import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';
import wrtc from 'wrtc';

import { loadConfig } from './config.js';
import type { RpcRequestV1, RpcResponseV1, RpcServiceAdvertisementV1, SignalMsg, WireMsg } from './types.js';
import { ensurePrivKeyHex, pubKeyFromPrivKeyHex, sha256Hex } from './crypto.js';
import { TapeStore } from './tape.js';
import { PeerSession, broadcastTapeEntry, dcMessageBytes } from './peerSession.js';
import { fetchBoundedJson } from './boundedFetch.js';
import { attachRequestDeadlines } from './httpDeadlines.js';
import { isWireMsg } from './validate.js';
import { ConcurrencyCounter, KeyedTokenBuckets, MinIntervalGate, TokenBucket } from './ratelimit.js';
import { clientKeyForIp, createClientIpResolver } from './clientIp.js';
import { ClearlistClient } from './clearlist.js';
import { loadValidators } from './schema.js';
import { buildManifest } from './manifest.js';
import { IpIntelClient } from './ipIntel.js';
import { AuditLog } from './auditLog.js';
import { buildBitvmStatusFromArtifacts } from './bitvmStatus.js';
import { admitOrder } from './orderAdmission.js';
import { logInternalError } from './log.js';

const PUBLIC_RPC_METHODS = new Set([
  'tl_getstatesnapshot',
  'tl_watchonly_register',
  'tl_watchonly_utxos',
  'tl_getsyncstatus',
  'tl_getallbalancesforaddress',
  'tl_getchannel',
  'tl_getchannelcolumn',
  'tl_getcontractinfo',
  'tl_getattestations',
  'tl_gettransaction',
  'tl_getclearlistbyid',
  'tl_listcontractseries',
  'tl_getinitmargin',
  'tl_channelbalanceforcommiter',
  'tl_getmaxsynth',
  'tl_contractposition',
  'tl_tokentradehistoryforaddress',
  'tl_contracttradehistoryforaddress',
  'tl_totaltradehistoryforaddress',
  'tl_getinfo',
  'tl_getbalance',
  'tl_getproperty',
  'tl_listproperties',
  'tl_createpayload_attestation',
  'tl_createpayload_commit_tochannel',
  'tl_bitvmstatus',
  // Read-only bitcoin-family RPCs backing the documented HTTP compat routes
  // (/chain/info, /address/validate/*, /address/utxo/*, /tx/decode). These fall
  // through to the WebRTC-routed path when the legacy proxy is disabled (H2),
  // so they must stay on the allowlist (advertised providers may serve them).
  'getblockchaininfo',
  'validateaddress',
  'listunspent',
  'decoderawtransaction',
]);

function normalizeRpcMethod(method: unknown): string {
  return String(method || '').trim().toLowerCase();
}

// Minimum interval between full TAPE_SUB tape re-reads per session (H3).
const TAPE_SUB_MIN_INTERVAL_MS = 1000;
// Bound on tracked per-client HTTP buckets (see KeyedTokenBuckets).
const HTTP_BUCKET_TABLE_MAX = 5000;
// Round 8: deadline and body cap for calls to the legacy relayer (its routes can answer large
// balance and UTXO lists, so the cap is larger than the intel and clearlist caps).
const LEGACY_PROXY_TIMEOUT_MS = 20_000;
const LEGACY_PROXY_MAX_BYTES = 8 * 1024 * 1024;

function isPublicRpcMethod(method: unknown): boolean {
  return PUBLIC_RPC_METHODS.has(normalizeRpcMethod(method));
}

function publicRpcError(id: string, code: string, message: string): RpcResponseV1 {
  return { id, ok: false, error: { code, message } };
}

function configuredCorsOrigins(): string[] {
  return String(process.env.TL_COLLATOR_CORS_ORIGINS || '')
    .split(/[\n,]+/)
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function randId(): string {
  return crypto.randomBytes(8).toString('hex');
}

function safeJsonParse(s: string): any | null {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

class RequestBodyTooLarge extends Error {}

function readHttpJson(req: http.IncomingMessage, maxBytes: number): Promise<any> {
  return new Promise((resolve, reject) => {
    // Round 8: the size is a running byte count. Re-measuring the accumulated text on every chunk
    // was quadratic for a body sent in small pieces.
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;
    req.on('data', (chunk: Buffer) => {
      // Stop buffering once over the limit; the caller answers 413 and closes.
      if (tooLarge) return;
      total += chunk.length;
      if (total > maxBytes) {
        tooLarge = true;
        chunks.length = 0;
        reject(new RequestBodyTooLarge('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) return;
      const raw = Buffer.concat(chunks).toString('utf8');
      resolve(raw ? safeJsonParse(raw) : null);
    });
    req.on('error', reject);
  });
}

function normalizeCompatParams(body: any): unknown[] {
  if (Array.isArray(body?.params)) return body.params;
  if (body?.params == null) return [];
  return [body.params];
}

function writeJson(res: http.ServerResponse, statusCode: number, body: unknown): void {
  res.setHeader('content-type', 'application/json');
  res.statusCode = statusCode;
  res.end(JSON.stringify(body));
}

function logPortfolioHeartbeat(scope: string, event: string, details: Record<string, unknown>): void {
  console.log(`[portfolio-heartbeat][collator][${scope}] ${event}`, details);
}

function normalizeRpcRequest(raw: any): RpcRequestV1 | null {
  if (!raw || typeof raw !== 'object') return null;
  const service = typeof raw.service === 'string' ? raw.service.trim() : '';
  const method = typeof raw.method === 'string' ? raw.method.trim() : '';
  if (!service || !method) return null;
  return {
    id: typeof raw.id === 'string' && raw.id ? raw.id : `rpc-${randId()}`,
    service,
    ...(typeof raw.network === 'string' && raw.network.trim() ? { network: raw.network.trim() } : {}),
    method,
    params: raw.params,
    ...(Number.isFinite(Number(raw.timeoutMs)) ? { timeoutMs: Number(raw.timeoutMs) } : {}),
    ...(typeof raw.sourceEndpoint === 'string' && raw.sourceEndpoint.trim() ? { sourceEndpoint: raw.sourceEndpoint.trim() } : {}),
  };
}

function summarizeRpcMethod(method: string, params: unknown): Record<string, unknown> {
  const normalized = String(method || '').trim().toLowerCase();
  const values = Array.isArray(params) ? params : [];
  const first = values[0] as any;
  const second = values[1] as any;
  const third = values[2] as any;

  if (normalized === 'listunspent' && third && typeof third === 'object') {
    return {
      mappedEndpoint: '/address/utxo',
      address: String(third.address || '').trim(),
      hasPubkey: !!third.pubkey,
      minconf: first,
      maxconf: second,
    };
  }

  if (normalized === 'tl_getallbalancesforaddress') {
    return {
      mappedEndpoint: '/address/balance',
      address: String(first || '').trim(),
    };
  }

  if (normalized === 'tl_listproperties') {
    return { mappedEndpoint: '/token/list' };
  }

  if (normalized === 'tl_getproperty') {
    return {
      mappedEndpoint: '/token/:propid',
      propid: Number(first),
    };
  }

  return { paramsCount: values.length };
}

async function main() {
  const cfg = loadConfig();
  const schemas = loadValidators();
  const startedAt = Date.now();
  const compatRpcService = process.env.TL_COLLATOR_RPC_SERVICE || 'tradelayer.rpc';
  const compatRpcNetwork = process.env.TL_COLLATOR_RPC_NETWORK || '';
  const rpcAdvertTtlMs = cfg.rpcAdvertTtlMs;
  const corsOrigins = configuredCorsOrigins();
  const isProduction = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  const legacyTlProxyEnabled = !isProduction && String(process.env.TL_COLLATOR_ENABLE_LEGACY_TL_PROXY || '').trim() === '1';
  // Master switch for all legacy relayer proxy routes (H2). Disabled by default:
  // these paths bypass the public RPC allowlist and some can move funds.
  const legacyProxyEnabled = String(process.env.LEGACY_PROXY_ENABLED || '').trim() === '1';
  // Faucet proxying additionally requires an explicit opt-in (H2).
  const legacyProxyFaucetEnabled = String(process.env.LEGACY_PROXY_FAUCET || '').trim() === '1';
  // The only place client IPs are derived. Headers are believed solely from
  // TRUST_PROXY_CIDRS hops (validated at startup in config.ts).
  const clientIpResolver = createClientIpResolver(cfg.trustedProxy);
  // Hard cap on concurrent in-flight routed RPC requests (C2d/H3).
  const pendingRpcMax = cfg.pendingRpcMax;
  const legacyRelayerBaseUrl = String(
    process.env.TL_RELAY_COMPAT_UPSTREAM_URL ||
    process.env.TL_WALLET_LISTENER_URL ||
    'http://127.0.0.1:3000'
  ).replace(/\/+$/, '');

  // Load/generate collator key.
  let privHex: string;
  if (fs.existsSync(cfg.collatorKeyPath)) privHex = ensurePrivKeyHex(fs.readFileSync(cfg.collatorKeyPath, 'utf8'));
  else {
    privHex = ensurePrivKeyHex(null);
    fs.mkdirSync(path.dirname(cfg.collatorKeyPath), { recursive: true });
    // L1: private key must not be world-readable.
    fs.writeFileSync(cfg.collatorKeyPath, privHex, { encoding: 'utf8', mode: 0o600 });
  }
  const pubHex = pubKeyFromPrivKeyHex(privHex);
  const collatorId = sha256Hex(pubHex);

  const manifest = buildManifest(cfg, { collatorId, collatorPubKey: pubHex, collatorPrivKeyHex: privHex });

  const tape = new TapeStore({
    tapePath: cfg.tapePath,
    idxPath: cfg.idxPath,
    idxStride: cfg.idxStride,
    replayBatch: cfg.replayBatch,
    maxReplayEntries: cfg.tapeResyncMaxEntries,
    collatorId,
    collatorPrivKeyHex: privHex,
  });
  const clearlist = cfg.clearlistEnforce && cfg.clearlistUrl ? new ClearlistClient({ baseUrl: cfg.clearlistUrl }) : null;
  const ipIntel = cfg.ipIntelUrl ? new IpIntelClient({ url: cfg.ipIntelUrl, ttlSec: cfg.ipIntelTtlSec, max: 5000 }) : null;
  const audit = new AuditLog(cfg.ipLogging === 'on' ? path.join(cfg.dataDir, 'audit.log') : null);

  const server = cfg.tlsKeyPath && cfg.tlsCertPath
    ? https.createServer({
        key: fs.readFileSync(cfg.tlsKeyPath),
        cert: fs.readFileSync(cfg.tlsCertPath),
        // Round 8: TLS handshake deadline (see httpDeadlines.ts); the Node default is 120 s.
        handshakeTimeout: 10_000,
      })
    : http.createServer();
  // Round 8: header, body and idle deadlines for every connection (slowloris). See httpDeadlines.ts.
  attachRequestDeadlines(server);

  const wss = new WebSocketServer({ server, path: cfg.wsPath, maxPayload: cfg.maxMsgBytes });
  const sessions = new Map<string, PeerSession>();
  const peers = new Set<PeerSession>();
  const rpcAdvertisements = new Map<PeerSession, { nodeId: string; services: RpcServiceAdvertisementV1[]; lastSeenTs: number }>();
  // Routed-RPC admission. A WebSocket request is charged to its session AND to
  // its client IP; an HTTP request only to its client IP. Sessions are cheap
  // (CONN_MAX_PER_IP of them per IP), so the session cap alone would let one IP
  // multiply its share; the IP cap closes that.
  const rpcAdmission = new ConcurrencyCounter();
  const sessionAdmissionKey = (sessionId: string): string => `sess:${sessionId}`;
  // The one limiter identity: every per-client budget, cap and aggregation below
  // keys on this (IPv6 collapsed to its prefix), never on the raw address.
  const clientKey = (ip: string): string => clientKeyForIp(ip, cfg.clientIpv6PrefixLen);
  // Per-client token buckets for HTTP entry points (bounded; see httpRpcAllowed).
  const httpRpcBuckets = new KeyedTokenBuckets({
    capacity: cfg.httpRpcPerIpBurst,
    refillPerSec: cfg.httpRpcPerIpRps,
    maxKeys: HTTP_BUCKET_TABLE_MAX,
  });
  // SUBMIT budget per client key, charged alongside each session's own bucket.
  const submitClientBuckets = new KeyedTokenBuckets({
    capacity: cfg.submitClientBurst,
    refillPerSec: cfg.submitClientRatePerSec,
    maxKeys: HTTP_BUCKET_TABLE_MAX,
  });
  // Optional all-clients backstop, charged only after the per-client bucket admits.
  const httpRpcGlobal = cfg.httpRpcGlobalRps > 0
    ? new TokenBucket({ capacity: cfg.httpRpcGlobalBurst, refillPerSec: cfg.httpRpcGlobalRps })
    : null;
  // Logs (at most once a minute) while the bucket table is full and new clients share the overflow bucket.
  const httpBucketOverflowGate = new MinIntervalGate(60 * 1000, 1);
  // Logs (at most once per 10 minutes) when a peer that is not a configured proxy hop
  // sends forwarding headers: the usual sign of a proxy missing from TRUST_PROXY_CIDRS,
  // which makes every client share that proxy's HTTP bucket.
  const forwardedHeaderHintGate = new MinIntervalGate(10 * 60 * 1000, 1);
  // One TAPE_SUB replay per client IP per second; sessions are cheap, so a
  // per-session limit alone would let one IP multiply its replay rate.
  const tapeResyncGate = new MinIntervalGate(TAPE_SUB_MIN_INTERVAL_MS, 5000);

  const pendingRpc = new Map<string, {
    wireId: string;
    requester?: PeerSession;
    admissionKeys: string[];
    provider: PeerSession;
    providerNodeId: string;
    timer: NodeJS.Timeout;
    resolve?: (res: RpcResponseV1) => void;
    reject?: (err: Error) => void;
  }>();

  // C2c: pending entries are namespaced by the assigned provider session, so a
  // wire-supplied req.id can never overwrite another session's pending entry.
  const pendingRpcKey = (providerSessionId: string, wireId: string): string => `${providerSessionId}:${wireId}`;

  // Single release path for pending entries: clears the timer, drops the entry
  // and keeps the client admission counter in sync.
  const releasePending = (pendingKey: string) => {
    const pending = pendingRpc.get(pendingKey);
    if (!pending) return null;
    clearTimeout(pending.timer);
    pendingRpc.delete(pendingKey);
    for (const key of pending.admissionKeys) rpcAdmission.release(key);
    return pending;
  };

  const pruneRpcAdvertisements = (): void => {
    const now = Date.now();
    for (const [sess, advert] of rpcAdvertisements.entries()) {
      const dcOpen = !!sess.dc && sess.dc.readyState === 'open';
      const fresh = now - Number(advert.lastSeenTs || 0) <= rpcAdvertTtlMs;
      if (!dcOpen || !fresh) {
        logPortfolioHeartbeat('rpc', 'provider-pruned', {
          providerNodeId: advert.nodeId,
          dcOpen,
          ageMs: now - Number(advert.lastSeenTs || 0),
          ttlMs: rpcAdvertTtlMs,
        });
        rpcAdvertisements.delete(sess);
      }
    }
  };

  const findRpcProvider = (rpcReq: RpcRequestV1, requester?: PeerSession): { session: PeerSession; nodeId: string } | null => {
    pruneRpcAdvertisements();
    const preferredProviderNodeId = String(rpcReq.preferredProviderNodeId || '').trim();
    for (const [sess, advert] of rpcAdvertisements.entries()) {
      if (sess === requester) continue;
      if (!sess.dc || sess.dc.readyState !== 'open') continue;
      if (preferredProviderNodeId && advert.nodeId !== preferredProviderNodeId) continue;
      for (const service of advert.services) {
        if (service.service !== rpcReq.service) continue;
        if (rpcReq.network && service.network && service.network !== rpcReq.network) continue;
        if (!Array.isArray(service.methods) || service.methods.length === 0) continue;
        const requestedMethod = normalizeRpcMethod(rpcReq.method);
        const advertised = service.methods.map((method) => normalizeRpcMethod(method));
        if (!advertised.includes(requestedMethod)) continue;
        return { session: sess, nodeId: advert.nodeId };
      }
    }
    return null;
  };

  // Local status routes that never reach upstream and are not charged.
  const HTTP_UNLIMITED_PATHS = new Set(['/health', '/manifest', '/rpc/providers']);
  const httpRateLimitedBody = (pathname: string): unknown => {
    const message = 'too many RPC requests from this client; retry later';
    return pathname === '/rpc/route'
      ? { ok: false, error: { code: 'RPC_RATE_LIMITED', message } }
      : { error: message, code: 'RPC_RATE_LIMITED' };
  };
  // Per-client token bucket for HTTP requests (HTTP_RPC_PER_IP_RPS / _BURST), then
  // the optional global backstop. Called only from the HTTP entry gate, once per request.
  const httpRpcAllowed = (ip: string): boolean => {
    const taken = httpRpcBuckets.take(clientKey(ip));
    if (taken.overflow && httpBucketOverflowGate.allow('overflow')) {
      console.warn(JSON.stringify({
        service: 'tl-collator',
        event: 'http-bucket-table-full',
        msg: 'HTTP client bucket table is full with no refilled entry; new clients share one overflow budget until entries go idle',
        maxKeys: HTTP_BUCKET_TABLE_MAX,
      }));
    }
    if (!taken.allowed) return false;
    return httpRpcGlobal ? httpRpcGlobal.allow(1) : true;
  };

  // The public-mesh allowlist, checked once for every route that can reach a provider (HTTP, WebRTC).
  const publicRouteRefusal = (service: string, method: string): { code: string; message: string } | null => {
    if (service !== compatRpcService) {
      return { code: 'RPC_SERVICE_FORBIDDEN', message: 'RPC service is not available on the public mesh' };
    }
    if (!isPublicRpcMethod(method)) {
      return { code: 'RPC_METHOD_FORBIDDEN', message: 'RPC method is not available on the public mesh' };
    }
    return null;
  };

  // Routed-RPC admission for one request. `caller.session` is set only for
  // WebSocket callers, who receive RPC_RES over their DataChannel. HTTP callers
  // are rate-limited per client IP by httpRpcAllowed at the HTTP entry point,
  // before this function is reached; this function only applies the concurrency caps.
  const routeRpcRequest = (rpcReq: RpcRequestV1, caller: { ip: string; session?: PeerSession }): Promise<RpcResponseV1> => {
    const requester = caller.session;
    const fail = (code: string, message: string): Promise<RpcResponseV1> => {
      const res = publicRpcError(rpcReq.id, code, message);
      if (requester) requester.sendDc({ t: 'RPC_RES', v: 1, res });
      return Promise.resolve(res);
    };
    logPortfolioHeartbeat('rpc', 'request', {
      service: rpcReq.service,
      method: rpcReq.method,
      network: rpcReq.network || null,
      preferredProviderNodeId: rpcReq.preferredProviderNodeId || null,
      requester: requester?.id || null,
      sourceEndpoint: rpcReq.sourceEndpoint || null,
    });
    const refusal = publicRouteRefusal(rpcReq.service, rpcReq.method);
    if (refusal) return fail(refusal.code, refusal.message);
    const provider = findRpcProvider(rpcReq, requester);
    if (!provider) {
      logPortfolioHeartbeat('rpc', 'no-provider', {
        service: rpcReq.service,
        method: rpcReq.method,
        network: rpcReq.network || null,
      });
      return fail('NO_RPC_PROVIDER', `no WebRTC RPC provider for ${rpcReq.service}${rpcReq.network ? ` on ${rpcReq.network}` : ''}`);
    }

    const timeoutMs = Math.max(1000, Math.min(120000, Number(rpcReq.timeoutMs || 12000)));
    // Admission: a WebSocket request is charged to its session and to its IP, an
    // HTTP request to its IP only. Each cap is checked before anything is charged.
    const ipKey = clientKey(caller.ip);
    const sessionKey = requester ? sessionAdmissionKey(requester.id) : null;
    const admissionKeys = sessionKey ? [sessionKey, ipKey] : [ipKey];
    if (sessionKey && cfg.pendingRpcMaxPerSession > 0 && rpcAdmission.get(sessionKey) >= cfg.pendingRpcMaxPerSession) {
      return fail('RPC_SESSION_OVERLOADED', 'too many outstanding routed RPC requests for this session');
    }
    if (cfg.pendingRpcMaxPerIp > 0 && rpcAdmission.get(ipKey) >= cfg.pendingRpcMaxPerIp) {
      return fail('RPC_IP_OVERLOADED', 'too many outstanding routed RPC requests for this client');
    }
    // C2d/H3: bound the number of concurrent in-flight routed requests.
    if (pendingRpc.size >= pendingRpcMax) {
      return fail('RPC_OVERLOADED', 'too many pending routed RPC requests');
    }
    // C2c: refuse client-chosen ids that collide with an in-flight request on
    // the same provider instead of overwriting (which would orphan the earlier
    // caller's promise until timeout).
    const pendingKey = pendingRpcKey(provider.session.id, rpcReq.id);
    if (pendingRpc.has(pendingKey)) {
      return fail('RPC_ID_COLLISION', 'request id already pending for this provider');
    }
    logPortfolioHeartbeat('rpc', 'provider-selected', {
      service: rpcReq.service,
      method: rpcReq.method,
      network: rpcReq.network || null,
      providerNodeId: provider.nodeId,
      timeoutMs,
    });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        releasePending(pendingKey);
        const advert = rpcAdvertisements.get(provider.session);
        if (advert && advert.nodeId === provider.nodeId) {
          rpcAdvertisements.delete(provider.session);
        }
        logPortfolioHeartbeat('rpc', 'timeout', {
          service: rpcReq.service,
          method: rpcReq.method,
          network: rpcReq.network || null,
          providerNodeId: provider.nodeId,
          timeoutMs,
          providerEvicted: !!advert,
        });
        const res: RpcResponseV1 = {
          id: rpcReq.id,
          ok: false,
          error: { code: 'RPC_TIMEOUT', message: `routed RPC timed out after ${timeoutMs}ms` },
        };
        if (requester) {
          requester.sendDc({ t: 'RPC_RES', v: 1, res });
          resolve(res);
          return;
        }
        reject(new Error(res.error?.message || 'routed RPC timed out'));
      }, timeoutMs);

      pendingRpc.set(pendingKey, {
        wireId: rpcReq.id,
        requester,
        admissionKeys,
        provider: provider.session,
        providerNodeId: provider.nodeId,
        timer,
        resolve,
        reject,
      });
      for (const key of admissionKeys) rpcAdmission.acquire(key);
      provider.session.sendDc({ t: 'RPC_REQ', v: 1, req: rpcReq });
    });
  };

  // HTTP status for a failed routed RPC: overload and rate limits are 429 so
  // callers back off, no provider is 503, anything else is 502.
  const httpStatusForRoutedError = (code: string | undefined): number => {
    if (code === 'NO_RPC_PROVIDER') return 503;
    if (code === 'RPC_RATE_LIMITED' || code === 'RPC_IP_OVERLOADED') return 429;
    return 502;
  };

  // H2: the legacy relayer proxy is disabled unless LEGACY_PROXY_ENABLED=1.
  // A 503 (>=500) makes every caller with a routed-RPC fallback fall through to
  // the allowlisted path; proxy-only routes end in 404, as before.
  const legacyProxyGate = (pathname: string): { statusCode: number; body: any } | null => {
    if (!legacyProxyEnabled) {
      return {
        statusCode: 503,
        body: { error: { code: 'LEGACY_PROXY_DISABLED', message: 'Legacy relayer proxy is disabled (set LEGACY_PROXY_ENABLED=1 to enable)' } },
      };
    }
    if (pathname.startsWith('/address/faucet') && !legacyProxyFaucetEnabled) {
      return {
        statusCode: 503,
        body: { error: { code: 'LEGACY_PROXY_FAUCET_DISABLED', message: 'Faucet proxying is disabled (requires LEGACY_PROXY_ENABLED=1 and LEGACY_PROXY_FAUCET=1)' } },
      };
    }
    return null;
  };

  const proxyLegacyJson = async (
    method: string,
    pathname: string,
    body?: any,
    query?: Record<string, string>,
    headers?: Record<string, string>,
  ): Promise<{ statusCode: number; body: any }> => {
    const gated = legacyProxyGate(pathname);
    if (gated) return gated;
    const url = new URL(`${legacyRelayerBaseUrl}${pathname}`);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v != null) url.searchParams.set(k, v);
      }
    }
    // Round 8: the legacy relayer answer has a deadline and a body cap, and redirects are refused.
    const res = await fetchBoundedJson(
      url,
      {
        method,
        headers: { 'content-type': 'application/json', ...(headers || {}) },
        body: method === 'GET' || method === 'HEAD' ? undefined : JSON.stringify(body ?? {}),
      },
      { timeoutMs: LEGACY_PROXY_TIMEOUT_MS, maxBytes: LEGACY_PROXY_MAX_BYTES },
    );
    return { statusCode: res.status, body: res.body };
  };

  const routeCompatRpcRequest = async (
    method: string,
    params: unknown[],
    replyPath: string,
    clientIp: string,
  ): Promise<{ statusCode: number; body: any }> => {
    const refusal = publicRouteRefusal(compatRpcService, method);
    if (refusal) return { statusCode: 403, body: { error: refusal } };
    const rpcReq: RpcRequestV1 = {
      id: `rpc-${randId()}`,
      service: compatRpcService,
      method,
      params,
      ...(compatRpcNetwork ? { network: compatRpcNetwork } : {}),
    };
    const routed = await routeRpcRequest(rpcReq, { ip: clientIp });
    if (routed.ok) {
      return { statusCode: 200, body: { data: routed.result } };
    }
    if (routed.error?.code === 'NO_RPC_PROVIDER') {
      try {
        const proxied = await proxyLegacyJson('POST', `/rpc/${method}`, { params });
        return proxied;
      } catch (e: any) {
        logInternalError('legacy-proxy-error', e);
        return {
          statusCode: 502,
          body: {
            error: `legacy relayer proxy failed on ${replyPath}`,
            code: 'LEGACY_PROXY_ERROR',
          },
        };
      }
    }
    return {
      statusCode: httpStatusForRoutedError(routed.error?.code),
      body: {
        error: routed.error?.message || `compat RPC failed on ${replyPath}`,
        code: routed.error?.code || 'RPC_ERROR',
      },
    };
  };

  const settleRpcResponse = (res: RpcResponseV1, sender: PeerSession): void => {
    // C2a: only accept RPC_RES from the session the request was routed to.
    const pendingKey = pendingRpcKey(sender.id, res.id);
    const pending = pendingRpc.get(pendingKey);
    if (!pending) return;
    if (pending.provider !== sender) return;
    const settled = releasePending(pendingKey);
    if (!settled) return;
    const routed = settled.providerNodeId ? { ...res, providerNodeId: settled.providerNodeId } : res;
    logPortfolioHeartbeat('rpc', 'response', {
      id: res.id,
      ok: !!res.ok,
      providerNodeId: pending.providerNodeId || null,
      hasResult: res.result != null,
    });
    if (pending.requester) pending.requester.sendDc({ t: 'RPC_RES', v: 1, res: routed });
    if (pending.resolve) pending.resolve(routed);
  };

  server.on('request', (req, res) => {
    void (async () => {
      const u = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);

      // Resolve the client IP once through the trust-gated resolver; per-IP
      // rate limits and routed-RPC admission are keyed on it.
      const clientIp = clientIpResolver.resolve(req);
      if ((req.headers['x-forwarded-for'] !== undefined || req.headers.forwarded !== undefined)
        && !clientIpResolver.headersTrusted(req)
        && forwardedHeaderHintGate.allow('hint')) {
        console.warn(JSON.stringify({
          service: 'tl-collator',
          event: 'untrusted-forwarding-header',
          msg: 'forwarding headers from a peer outside TRUST_PROXY_CIDRS were ignored; behind a reverse proxy set TRUST_PROXY=1 and TRUST_PROXY_CIDRS',
        }));
      }

      const requestOrigin = typeof req.headers.origin === 'string' ? req.headers.origin.trim() : '';
      const originAllowed = !!requestOrigin && corsOrigins.includes(requestOrigin);
      const allowDevelopmentWildcard = !isProduction && corsOrigins.length === 0;
      if (originAllowed) {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin);
        res.setHeader('Vary', 'Origin');
      } else if (allowDevelopmentWildcard) {
        res.setHeader('Access-Control-Allow-Origin', '*');
      }
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'content-type');
      if (req.method === 'OPTIONS') {
        if (requestOrigin && !originAllowed && !allowDevelopmentWildcard) {
          writeJson(res, 403, { error: { code: 'CORS_ORIGIN_DENIED', message: 'Origin is not approved for this API' } });
          return;
        }
        res.statusCode = 204;
        res.end();
        return;
      }

      // Single HTTP admission point. Every route except the local status ones
      // is charged here, once per request, before the body is read and before
      // any upstream (mesh or legacy relayer) is contacted.
      if (!HTTP_UNLIMITED_PATHS.has(u.pathname) && !httpRpcAllowed(clientIp)) {
        writeJson(res, 429, httpRateLimitedBody(u.pathname));
        return;
      }

      if (req.method === 'GET' && u.pathname === '/health') {
        pruneRpcAdvertisements();
        writeJson(res, 200, {
          ok: true,
          collatorId,
          uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
          rpcProviders: rpcAdvertisements.size,
        });
        return;
      }

      if (req.method === 'GET' && u.pathname === '/manifest') {
        writeJson(res, 200, manifest);
        return;
      }

      if (u.pathname === '/attestation/ip') {
        // H1: determine the client IP first and validate it before any use.
        const ip = clientIp;
        if (!ip || net.isIP(ip) === 0) {
          writeJson(res, 400, { success: false, error: 'Unable to determine client IP' });
          return;
        }
        try {
          // Forward only the headers the collator itself believes (X-Forwarded-For),
          // and only from a trusted hop; otherwise they are client-controlled and
          // would let callers spoof the attested IP.
          const proxyHeaders: Record<string, string> = {};
          if (clientIpResolver.headersTrusted(req)) {
            for (const name of ['x-forwarded-for', 'x-forwarded-proto']) {
              const value = req.headers[name];
              if (typeof value === 'string' && value.trim()) proxyHeaders[name] = value;
            }
          }
          const proxied = await proxyLegacyJson(req.method || 'GET', '/attestation/ip', undefined, undefined, proxyHeaders);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        try {
          const intel = ipIntel ? await ipIntel.lookup(ip) : null;
          const isVpn = !!intel?.vpn;
          const isBlocked = isVpn;
          writeJson(res, 200, {
            success: true,
            ip,
            countryCode: 'Unknown',
            isVpn,
            isProxy: false,
            isDarkweb: false,
            isAnonymousVpn: false,
            isBlocked,
            source: 'unknown',
            message: isBlocked ? 'Suspicious IP detected.' : 'IP is clean and trusted.',
          });
          return;
        } catch (e: any) {
          logInternalError('ip-intel-error', e);
          writeJson(res, 200, {
            success: false,
            ip,
            isBlocked: false,
            source: 'unknown',
            message: 'No IP reputation provider succeeded',
            error: 'Both primary and fallback IP reputation APIs failed or are not configured.',
          });
          return;
        }
      }

      if (req.method === 'GET' && u.pathname === '/rpc/providers') {
        pruneRpcAdvertisements();
        logPortfolioHeartbeat('http', '/rpc/providers request', {
          providerCount: rpcAdvertisements.size,
          sourceEndpoint: 'testnet-api',
        });
        writeJson(res, 200, {
          ok: true,
          providers: Array.from(rpcAdvertisements.values()).map((advert) => ({
            nodeId: advert.nodeId,
            services: advert.services,
            lastSeenTs: advert.lastSeenTs,
          })),
        });
        return;
      }

      if (u.pathname.startsWith('/tl_')) {
        if (req.method === 'POST' && u.pathname === '/tl_bitvmStatus') {
          const body = await readHttpJson(req, cfg.maxMsgBytes);
          writeJson(res, 200, buildBitvmStatusFromArtifacts(body || {}));
          return;
        }

        if (!legacyTlProxyEnabled || !legacyProxyEnabled) {
          writeJson(res, 404, { error: { code: 'LEGACY_TL_PROXY_DISABLED', message: 'Legacy /tl_* proxy is disabled' } });
          return;
        }

        const body = req.method === 'GET' ? undefined : await readHttpJson(req, cfg.maxMsgBytes);
        const proxied = await proxyLegacyJson(req.method || 'POST', u.pathname, body);
        writeJson(res, proxied.statusCode, proxied.body);
        return;
      }

      const compatRpcMatch =
        u.pathname !== '/rpc/route' &&
        u.pathname !== '/rpc/providers' &&
        u.pathname.match(/^\/(?:relayer\/)?rpc\/([^/]+)$/);
      if (req.method === 'POST' && compatRpcMatch) {
        const method = decodeURIComponent(compatRpcMatch[1] || '').trim();
        if (!method) {
          writeJson(res, 400, { error: { code: 'BAD_RPC_REQUEST', message: 'Missing RPC method' } });
          return;
        }
        const compatRefusal = publicRouteRefusal(compatRpcService, method);
        if (compatRefusal) {
          writeJson(res, 403, { error: compatRefusal });
          return;
        }
        const raw = await readHttpJson(req, cfg.maxMsgBytes);
        if (method.toLowerCase() === 'tl_bitvmstatus') {
          writeJson(res, 200, buildBitvmStatusFromArtifacts(raw || {}));
          return;
        }
        const params = normalizeCompatParams(raw);
        logPortfolioHeartbeat('http', '/rpc compat request', {
          method,
          pathname: u.pathname,
          paramsCount: params.length,
        });
        const compat = await routeCompatRpcRequest(method, params, u.pathname, clientIp);
        logPortfolioHeartbeat('http', '/rpc compat response', {
          method,
          pathname: u.pathname,
          statusCode: compat.statusCode,
          ok: !!compat.body?.data || !!compat.body?.result || !!compat.body?.ok,
        });
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'POST' && u.pathname === '/rpc/route') {
        const raw = await readHttpJson(req, cfg.maxMsgBytes);
        const rpcReq = normalizeRpcRequest(raw);
        if (!rpcReq) {
          writeJson(res, 400, { ok: false, error: { code: 'BAD_RPC_REQUEST', message: 'service and method are required' } });
          return;
        }
        const routeRefusal = publicRouteRefusal(rpcReq.service, rpcReq.method);
        if (routeRefusal) {
          writeJson(res, 403, { ok: false, error: routeRefusal });
          return;
        }
        logPortfolioHeartbeat('http', '/rpc/route request', {
          service: rpcReq.service,
          method: rpcReq.method,
          network: rpcReq.network || null,
          sourceEndpoint: rpcReq.sourceEndpoint || null,
          ...summarizeRpcMethod(rpcReq.method, rpcReq.params),
        });
        const routed = await routeRpcRequest(rpcReq, { ip: clientIp });
        logPortfolioHeartbeat('http', '/rpc/route response', {
          service: rpcReq.service,
          method: rpcReq.method,
          network: rpcReq.network || null,
          ok: routed.ok,
          errorCode: routed.error?.code || null,
          providerNodeId: routed.providerNodeId || null,
        });
        writeJson(res, routed.ok ? 200 : httpStatusForRoutedError(routed.error?.code), routed);
        return;
      }

      if (req.method === 'GET' && u.pathname === '/chain/info') {
        try {
          const proxied = await proxyLegacyJson('GET', '/chain/info');
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        logPortfolioHeartbeat('http', '/chain/info fallback', {});
        const compat = await routeCompatRpcRequest('getblockchaininfo', [], u.pathname, clientIp);
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'GET' && u.pathname.startsWith('/address/validate/')) {
        const address = decodeURIComponent(u.pathname.slice('/address/validate/'.length));
        if (!address) {
          writeJson(res, 400, { error: 'Missing address' });
          return;
        }
        try {
          const proxied = await proxyLegacyJson('GET', `/address/validate/${encodeURIComponent(address)}`);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const compat = await routeCompatRpcRequest('validateaddress', [address], u.pathname, clientIp);
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'GET' && u.pathname.startsWith('/address/balance/')) {
        const address = decodeURIComponent(u.pathname.slice('/address/balance/'.length));
        if (!address) {
          writeJson(res, 400, { error: 'Missing address' });
          return;
        }
        logPortfolioHeartbeat('http', '/address/balance request', {
          address,
          sourceEndpoint: 'testnet-api',
          mappedRpc: 'tl_getallbalancesforaddress',
        });
        try {
          const proxied = await proxyLegacyJson('GET', `/address/balance/${encodeURIComponent(address)}`);
          if (proxied.statusCode < 500) {
            logPortfolioHeartbeat('http', '/address/balance proxied', {
              address,
              statusCode: proxied.statusCode,
            });
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const compat = await routeCompatRpcRequest('tl_getallbalancesforaddress', [address], u.pathname, clientIp);
        logPortfolioHeartbeat('http', '/address/balance routed', {
          address,
          statusCode: compat.statusCode,
          mappedRpc: 'tl_getallbalancesforaddress',
        });
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'GET' && u.pathname.startsWith('/address/faucet/')) {
        const address = decodeURIComponent(u.pathname.slice('/address/faucet/'.length));
        if (!address) {
          writeJson(res, 400, { error: 'Missing address' });
          return;
        }
        try {
          const proxied = await proxyLegacyJson('GET', `/address/faucet/${encodeURIComponent(address)}`);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const compat = await routeCompatRpcRequest('sendtoaddress', [address, 1], u.pathname, clientIp);
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'POST' && u.pathname.startsWith('/address/utxo/')) {
        const address = decodeURIComponent(u.pathname.slice('/address/utxo/'.length));
        if (!address) {
          writeJson(res, 400, { error: 'Missing address' });
          return;
        }
        const raw = await readHttpJson(req, cfg.maxMsgBytes);
        const pubkey = typeof raw?.pubkey === 'string' && raw.pubkey.trim() ? raw.pubkey.trim() : undefined;
        logPortfolioHeartbeat('http', '/address/utxo request', {
          address,
          hasPubkey: !!pubkey,
          sourceEndpoint: 'testnet-api',
          mappedRpc: 'listunspent',
        });
        try {
          const proxied = await proxyLegacyJson('POST', `/address/utxo/${encodeURIComponent(address)}`, { pubkey });
          if (proxied.statusCode < 500) {
            logPortfolioHeartbeat('http', '/address/utxo proxied', {
              address,
              statusCode: proxied.statusCode,
            });
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const compat = await routeCompatRpcRequest('listunspent', [0, 99999999, { address, ...(pubkey ? { pubkey } : {}) }], u.pathname, clientIp);
        logPortfolioHeartbeat('http', '/address/utxo routed', {
          address,
          statusCode: compat.statusCode,
          mappedRpc: 'listunspent',
        });
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'GET' && u.pathname.startsWith('/tx/')) {
        const txid = decodeURIComponent(u.pathname.slice('/tx/'.length));
        if (!txid) {
          writeJson(res, 400, { error: 'Missing txid' });
          return;
        }
        try {
          const proxied = await proxyLegacyJson('GET', `/tx/${encodeURIComponent(txid)}`);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const compat = await routeCompatRpcRequest('tl_gettransaction', [txid], u.pathname, clientIp);
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'GET' && u.pathname === '/token/list') {
        try {
          const proxied = await proxyLegacyJson('GET', '/token/list');
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const compat = await routeCompatRpcRequest('tl_listproperties', [], u.pathname, clientIp);
        logPortfolioHeartbeat('http', '/token/list routed', {
          statusCode: compat.statusCode,
          mappedRpc: 'tl_listproperties',
          sourceEndpoint: 'testnet-api',
        });
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'POST' && u.pathname === '/tx/decode') {
        const raw = await readHttpJson(req, cfg.maxMsgBytes);
        try {
          const proxied = await proxyLegacyJson('POST', '/tx/decode', raw);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const rawtx = typeof raw?.rawtx === 'string' ? raw.rawtx : '';
        const compat = await routeCompatRpcRequest('decoderawtransaction', [rawtx], u.pathname, clientIp);
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      if (req.method === 'POST' && u.pathname === '/tx/sendTx') {
        const raw = await readHttpJson(req, cfg.maxMsgBytes);
        try {
          const proxied = await proxyLegacyJson('POST', '/tx/sendTx', raw);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const rawTx = typeof raw?.rawTx === 'string' ? raw.rawTx : '';
        const compat = await routeCompatRpcRequest('sendrawtransaction', [rawTx], u.pathname, clientIp);
        writeJson(res, compat.statusCode, { txid: compat.body?.data ?? compat.body?.result ?? compat.body });
        return;
      }

      if (
        req.method === 'POST'
        && ['/tx/buildTx', '/tx/buildUnsigned', '/tx/buildunsigned', '/tx/build-unsigned'].includes(u.pathname)
      ) {
        const body = await readHttpJson(req, cfg.maxMsgBytes);
        try {
          const proxied = await proxyLegacyJson('POST', u.pathname, body);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
      }

      if (req.method === 'POST' && u.pathname === '/tx/multisig') {
        const body = await readHttpJson(req, cfg.maxMsgBytes);
        try {
          const proxied = await proxyLegacyJson('POST', '/tx/multisig', body);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
      }

      if (req.method === 'POST' && u.pathname === '/tx/buildTradeTx') {
        const body = await readHttpJson(req, cfg.maxMsgBytes);
        try {
          const proxied = await proxyLegacyJson('POST', '/tx/buildTradeTx', body);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
      }

      if (req.method === 'POST' && u.pathname === '/tx/buildLTCTradeTx') {
        const body = await readHttpJson(req, cfg.maxMsgBytes);
        try {
          const proxied = await proxyLegacyJson('POST', '/tx/buildLTCTradeTx', body);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
      }

      if (req.method === 'POST' && u.pathname === '/tx/finalizePsbt') {
        const body = await readHttpJson(req, cfg.maxMsgBytes);
        try {
          const proxied = await proxyLegacyJson('POST', '/tx/finalizePsbt', body);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
      }

      if (req.method === 'GET' && u.pathname.startsWith('/token/')) {
        const propId = decodeURIComponent(u.pathname.slice('/token/'.length));
        if (!propId) {
          writeJson(res, 400, { error: 'Missing propid' });
          return;
        }
        try {
          const proxied = await proxyLegacyJson('GET', `/token/${encodeURIComponent(propId)}`);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        // Routed calls take a numeric property id; anything else is refused here
        // rather than sent upstream as NaN (JSON null).
        if (!/^\d+$/.test(propId) || !Number.isSafeInteger(Number(propId))) {
          writeJson(res, 400, { error: 'propid must be a non-negative safe integer' });
          return;
        }
        const compat = await routeCompatRpcRequest('tl_getproperty', [Number(propId)], u.pathname, clientIp);
        logPortfolioHeartbeat('http', '/token/:propid routed', {
          propId: Number(propId),
          statusCode: compat.statusCode,
          mappedRpc: 'tl_getproperty',
          sourceEndpoint: 'testnet-api',
        });
        writeJson(res, compat.statusCode, compat.body);
        return;
      }

      res.statusCode = 404;
      res.end('not found');
    })().catch((e: any) => {
      // Details go to the log only; the response must not expose internal errors.
      if (e instanceof RequestBodyTooLarge) {
        res.setHeader('Connection', 'close');
        writeJson(res, 413, { ok: false, error: { code: 'BODY_TOO_LARGE', message: 'request body too large' } });
        return;
      }
      logInternalError('http-internal-error', e);
      writeJson(res, 500, { ok: false, error: { code: 'INTERNAL', message: 'internal error' } });
    });
  });

  // ---- Connection fairness (adversarial review H3b follow-up) ------------
  // CONN_MAX alone is trivially turned into a global lockout: 256 keep-alive
  // sockets and every new client gets WS close 1013. Mitigations:
  //  - idle reaper: sessions with no open DataChannel and no traffic for
  //    CONN_IDLE_TIMEOUT_MS are swept every CONN_SWEEP_INTERVAL_MS.
  //  - per-IP sub-cap: at most CONN_MAX_PER_IP concurrent WS connections per
  //    remote IP (0 disables).
  //  - handshake reserve: when the pool is full, a fresh handshake displaces
  //    the oldest silent (unestablished) session; only a pool of fully
  //    established DataChannel sessions refuses new connections with 1013.
  const { connIdleTimeoutMs, connSweepIntervalMs, connHandshakeGraceMs } = cfg;
  const perIpCounts = new Map<string, number>();
  // Each session's cleanup, so a session can leave the pool at once when it is evicted.
  const teardowns = new Map<PeerSession, () => void>();

  const isSilentPeer = (p: PeerSession): boolean => !p.dc || p.dc.readyState !== 'open';

  // The pool slot is released now, not when the close event arrives: a close frame takes a round trip,
  // and until then a burst of handshakes would find the same full pool and displace the same victim.
  const evictPeer = (p: PeerSession, code: number, reason: string): void => {
    teardowns.get(p)?.();
    try {
      p.ws.close(code, reason);
    } catch {}
  };

  const reapIdleSilentSessions = (nowTs: number = Date.now()): number => {
    let reaped = 0;
    for (const p of Array.from(peers)) {
      if (!isSilentPeer(p)) continue;
      if (nowTs - p.meta.lastSeenTs < connIdleTimeoutMs) continue;
      logPortfolioHeartbeat('conn', 'idle-reaped', {
        peerId: p.id,
        ip: p.meta.remoteIp || null,
        idleMs: nowTs - p.meta.lastSeenTs,
      });
      evictPeer(p, 1013, 'idle connection reaped');
      reaped++;
    }
    return reaped;
  };

  const sweepTimer = setInterval(() => {
    try {
      reapIdleSilentSessions();
    } catch {}
  }, connSweepIntervalMs);
  if (typeof (sweepTimer as any)?.unref === 'function') (sweepTimer as any).unref();

  wss.on('connection', (ws, req) => {
    // Cap by the resolved client IP, not the raw socket peer: behind a proxy the
    // socket address is the proxy's and would give every client one shared budget.
    const remoteIp = clientIpResolver.resolve(req);
    const ipKey = clientKey(remoteIp);

    // Per-IP sub-cap first: a single source must not be able to hold a large
    // fraction of the pool (keep-alive socket floods).
    if (cfg.connMaxPerIp > 0 && (perIpCounts.get(ipKey) || 0) >= cfg.connMaxPerIp) {
      try {
        ws.close(1013, 'too many connections from your ip');
      } catch {}
      return;
    }

    if (cfg.connMax !== null && peers.size >= cfg.connMax) {
      // Handshake reserve: reclaim room for this handshake before refusing.
      reapIdleSilentSessions();
      let victim: PeerSession | null = null;
      for (const p of peers) {
        if (!isSilentPeer(p)) continue;
        if (Date.now() - p.meta.firstSeenTs < connHandshakeGraceMs) continue;
        if (!victim || p.meta.firstSeenTs < victim.meta.firstSeenTs) victim = p;
      }
      if (!victim) {
        try {
          ws.close(1013, 'server busy');
        } catch {}
        return;
      }
      logPortfolioHeartbeat('conn', 'handshake-displaced', {
        victim: victim.id,
        victimIp: victim.meta.remoteIp || null,
      });
      evictPeer(victim, 1013, 'displaced by new handshake');
    }

    const id = `peer-${randId()}`;
    const userAgent = req?.headers?.['user-agent'] ? String(req.headers['user-agent']) : undefined;
    const sess = new PeerSession({ id, ws, burst: cfg.submitBurst, ratePerSec: cfg.submitRatePerSec, remoteIp: remoteIp || undefined, userAgent });
    sessions.set(id, sess);
    peers.add(sess);
    perIpCounts.set(ipKey, (perIpCounts.get(ipKey) || 0) + 1);

    let pc: any = null;

    const sendSignal = (m: SignalMsg) => {
      if (ws.readyState !== ws.OPEN) return;
      ws.send(JSON.stringify(m));
    };

    const cleanup = async () => {
      // Single-run guard: 'error' is often followed by 'close'.
      if (!sessions.has(id)) return;
      teardowns.delete(sess);
      try {
        sess.dc?.close();
      } catch {}
      sess.dc = null;
      try {
        pc?.close?.();
      } catch {}
      pc = null;
      const remaining = (perIpCounts.get(ipKey) || 1) - 1;
      if (remaining > 0) perIpCounts.set(ipKey, remaining);
      else perIpCounts.delete(ipKey);
      sessions.delete(id);
      peers.delete(sess);
      rpcAdvertisements.delete(sess);
      for (const [pendingKey, pending] of Array.from(pendingRpc.entries())) {
        if (pending.requester !== sess && pending.provider !== sess) continue;
        releasePending(pendingKey);
        const res: RpcResponseV1 = {
          id: pending.wireId,
          ok: false,
          error: { code: 'RPC_PEER_CLOSED', message: 'routed RPC peer disconnected before response' },
        };
        if (pending.requester && pending.requester !== sess) pending.requester.sendDc({ t: 'RPC_RES', v: 1, res });
        if (pending.reject) pending.reject(new Error(res.error?.message || 'routed RPC peer closed'));
      }
    };

    teardowns.set(sess, () => void cleanup());
    ws.on('close', () => void cleanup());
    ws.on('error', () => void cleanup());

    ws.on('message', async (buf) => {
      if (typeof buf !== 'string' && !(buf instanceof Buffer)) return;
      const raw = typeof buf === 'string' ? buf : buf.toString('utf8');
      const msg = safeJsonParse(raw) as SignalMsg | null;
      if (!msg || typeof msg.t !== 'string') return;
      sess.meta.lastSeenTs = Date.now();
      if (!schemas.validateSignalMsg(msg)) return;

      try {
        if (msg.t === 'SIGNAL_HELLO') {
          // Wallet sends this before offer. No response required for current wallet client.
          return;
        }

        if (msg.t === 'SIGNAL_OFFER') {
          // Refused before anything is torn down, so a flood cannot close the live channel.
          if (!sess.offerBucket.allow(1)) {
            sendSignal({ t: 'SIGNAL_ERR', v: 1, code: 'rate_limited', msg: 'too many SIGNAL_OFFER' });
            return;
          }
          // Collator is the answerer.
          // H3a: close/replace any previous peer connection for this session;
          // otherwise a client looping offers leaks native WebRTC/ICE resources.
          if (pc || sess.dc) {
            try {
              sess.dc?.close();
            } catch {}
            sess.dc = null;
            try {
              pc?.close?.();
            } catch {}
            pc = null;
          }
          pc = new (wrtc as any).RTCPeerConnection({ iceServers: cfg.iceServers });

          pc.onicecandidate = (ev: any) => {
            if (!ev.candidate) return;
            const c = typeof ev.candidate.toJSON === 'function'
              ? ev.candidate.toJSON()
              : {
                  candidate: ev.candidate.candidate,
                  sdpMid: ev.candidate.sdpMid,
                  sdpMLineIndex: ev.candidate.sdpMLineIndex,
                  usernameFragment: ev.candidate.usernameFragment,
                };
            sendSignal({ t: 'SIGNAL_ICE', v: 1, candidate: c as any });
          };

          pc.ondatachannel = (ev: any) => {
            const dc: RTCDataChannel = ev.channel;
            // Round 8: one live channel per session; the one it replaces is closed.
            sess.attachDataChannel(dc);

            dc.onmessage = async (ev2: any) => {
              try {
                if (dcMessageBytes(ev2.data) > cfg.maxMsgBytes) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'msg_too_large', msg: 'message too large' });
                  try { dc.close(); } catch {}
                  return;
                }
                const txt = typeof ev2.data === 'string' ? ev2.data : Buffer.from(ev2.data).toString('utf8');
                const wm = safeJsonParse(txt) as WireMsg | null;
                if (!wm || !isWireMsg(wm)) return;
                sess.meta.lastSeenTs = Date.now();
                if (!schemas.validateWireMsg(wm)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'invalid WireMsg schema' });
                  return;
                }

                if (wm.t === 'PING') {
                  sess.sendDc({ t: 'PONG', v: 1, ts: wm.ts });
                  return;
                }

                if (wm.t === 'HELLO') {
                  // Treat as ready.
                  return;
                }

                if (wm.t === 'RPC_ADVERTISE') {
                  const services = wm.services.reduce<RpcServiceAdvertisementV1[]>((accepted, service) => {
                    if (service.service !== compatRpcService || !Array.isArray(service.methods) || service.methods.length === 0) {
                      return accepted;
                    }
                    const methods = Array.from(new Set(service.methods
                      .map((method) => normalizeRpcMethod(method))
                      .filter((method) => isPublicRpcMethod(method))));
                    if (methods.length === 0) return accepted;
                    accepted.push({ ...service, methods });
                    return accepted;
                  }, []);
                  logPortfolioHeartbeat('rpc', 'advertise', {
                    nodeId: wm.nodeId,
                    services: services.map((service) => ({
                      service: service.service,
                      network: service.network || null,
                      methods: Array.isArray(service.methods) ? service.methods.length : null,
                    })),
                  });
                  if (services.length === 0) {
                    rpcAdvertisements.delete(sess);
                    sess.sendDc({ t: 'ERR', v: 1, code: 'RPC_ADVERTISEMENT_REJECTED', msg: 'advertise at least one supported public RPC method' });
                    return;
                  }
                  rpcAdvertisements.set(sess, {
                    nodeId: wm.nodeId,
                    services,
                    lastSeenTs: Date.now(),
                  });
                  return;
                }

                if (wm.t === 'RPC_REQ') {
                  const rpcReq = normalizeRpcRequest(wm.req);
                  if (!rpcReq) {
                    sess.sendDc({
                      t: 'RPC_RES',
                      v: 1,
                      res: {
                        id: wm.req?.id || `rpc-${randId()}`,
                        ok: false,
                        error: { code: 'BAD_RPC_REQUEST', message: 'service and method are required' },
                      },
                    });
                    return;
                  }
                  logPortfolioHeartbeat('rpc', 'wire-request', {
                    service: rpcReq.service,
                    method: rpcReq.method,
                    network: rpcReq.network || null,
                    sourceEndpoint: rpcReq.sourceEndpoint || null,
                    ...summarizeRpcMethod(rpcReq.method, rpcReq.params),
                  });
                  void routeRpcRequest(rpcReq, { ip: remoteIp, session: sess }).catch((e: any) => {
                    logInternalError('rpc-route-error', e);
                    sess.sendDc({
                      t: 'RPC_RES',
                      v: 1,
                      res: {
                        id: rpcReq.id,
                        ok: false,
                        error: { code: 'RPC_ROUTE_ERROR', message: 'internal error' },
                      },
                    });
                  });
                  return;
                }

                if (wm.t === 'RPC_RES') {
                  settleRpcResponse(wm.res, sess);
                  return;
                }

                if (wm.t === 'TAPE_SUB') {
                  // Register the live subscription first: the rate limit below
                  // only guards the full tape *replay* — returning early must
                  // never silently drop the client's live feed.
                  sess.wantsTape = true;
                  // H3c: rate-limit full tape re-reads per client IP (not per session).
                  if (!tapeResyncGate.allow(ipKey)) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'rate_limited', msg: 'TAPE_SUB resync too frequent; live feed stays subscribed' });
                    return;
                  }
                  const fromSeq = typeof wm.fromSeq === 'number' ? wm.fromSeq : 1;
                  // Paced on this channel: the replay waits for the queue to drain and stops if the
                  // channel is replaced or closed (round 10).
                  let interrupted = false;
                  const replay = await tape.replayFromSeq(Math.max(1, fromSeq), async (e) => {
                    const sent = await sess.sendReplayEntry(dc, e);
                    if (!sent) interrupted = true;
                    return sent;
                  });
                  // An interrupted replay has no end marker: TAPE_END would claim a tip the peer never received.
                  if (interrupted) return;
                  // Optional end marker; wallets that don't understand it should ignore.
                  // `fromSeq` is the first seq actually replayed: it is greater than the
                  // requested one when the resync was clamped to TAPE_RESYNC_MAX_ENTRIES.
                  sess.sendDc({ t: 'TAPE_END', v: 1, lastSeq: replay.lastSeq, fromSeq: replay.fromSeq });
                  return;
                }

                if (wm.t === 'SUBMIT') {
                  if (!sess.admitSubmit(submitClientBuckets, ipKey)) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'rate_limited', msg: 'too many SUBMIT' });
                    return;
                  }
                  const order = (wm as any).order;
                  if (!schemas.validateOrderEnvelope(order)) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'invalid OrderEnvelopeV1 schema' });
                    return;
                  }
                  const refusal = await admitOrder(cfg, { tape, intel: ipIntel, clearlist }, sess.meta, order);
                  if (refusal) {
                    sess.sendDc({ t: 'ERR', v: 1, ...refusal });
                    return;
                  }

                  // Atomic duplicate check: the awaits above (IP intel, clearlist) mean
                  // an identical SUBMIT may have landed since the fast-path check.
                  const entry = tape.append(order);
                  if (!entry) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'DUPLICATE', msg: 'orderId already seen' });
                    return;
                  }
                  audit.write({
                    ts: Date.now(),
                    collatorId,
                    peerId: sess.id,
                    ip: sess.meta.remoteIp,
                    asn: sess.meta.asn,
                    vpn: sess.meta.vpn,
                    orderId: order.orderId,
                    traderPubKey: order.traderPubKey,
                    seq: entry.seq,
                  });

                  // Broadcast to all tape subscribers (MVP: if no explicit subscribers, still broadcast).
                  // The entry is committed at this point; the broadcast can not turn it into an error.
                  broadcastTapeEntry(peers, entry);
                  return;
                }
              } catch (e: any) {
                // A throw here (e.g. the tape refusing a write) must not become an
                // unhandled rejection, which would take the whole collator down.
                logInternalError('dc-internal-error', e);
                try { sess.sendDc({ t: 'ERR', v: 1, code: 'INTERNAL', msg: 'internal error' }); } catch {}
              }
            };

            dc.onopen = () => {
              // No-op. Wait for client HELLO/TAPE_SUB.
            };
            dc.onclose = () => {
              // Only the channel the session currently holds. A replaced channel closes after
              // its successor is attached, and must not detach the successor.
              if (sess.dc === dc) sess.dc = null;
            };
          };

          await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          sendSignal({ t: 'SIGNAL_ANSWER', v: 1, kind: 'answer', sdp: answer.sdp || '' });
          return;
        }

        if (msg.t === 'SIGNAL_ICE') {
          if (!pc) return;
          try {
            await pc.addIceCandidate(msg.candidate);
          } catch {}
          return;
        }
      } catch (e: any) {
        logInternalError('signal-error', e);
        sendSignal({ t: 'SIGNAL_ERR', v: 1, code: 'internal', msg: 'internal error' });
      }
    });
  });

  server.listen(cfg.port, '0.0.0.0', () => {
    // eslint-disable-next-line no-console
    const scheme = cfg.tlsKeyPath && cfg.tlsCertPath ? 'wss' : 'ws';
    const wsUrl = `${scheme}://0.0.0.0:${cfg.port}${cfg.wsPath}`;
    console.log(
      JSON.stringify(
        {
          service: 'tl-collator',
          port: cfg.port,
          ws_path: cfg.wsPath,
          ws_url: wsUrl,
          handshake_url: wsUrl,
          collator_id: collatorId,
          tape_path: cfg.tapePath,
          last_seq: tape.getLastSeq(),
          note: `Use the exact WS URL with path ${cfg.wsPath} for wallet handshakes.`,
        },
        null,
        2
      )
    );
  });
}

// Round 8: process-level error policy, the same as the relayer (round 7). Request and session
// failures are answered at their own boundary. An unhandled rejection is logged and the collator
// keeps serving, because a single missed catch must not be a remote crash. An uncaught exception
// exits, because synchronous state may be inconsistent and the supervisor restarts the process.
// Only the message is logged: errors can carry request config and provider URLs.
process.on('unhandledRejection', (reason: unknown) => {
  console.error(JSON.stringify({
    service: 'tl-collator',
    event: 'unhandled-rejection',
    msg: reason instanceof Error ? reason.message : String(reason),
  }));
});
process.on('uncaughtException', (error: Error) => {
  console.error(JSON.stringify({ service: 'tl-collator', event: 'uncaught-exception', msg: error?.message || 'unknown error' }));
  process.exit(1);
});

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
