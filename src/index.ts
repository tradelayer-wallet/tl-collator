import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { WebSocketServer } from 'ws';
import wrtc from 'wrtc';

import { loadConfig } from './config.js';
import type { RpcRequestV1, RpcResponseV1, RpcServiceAdvertisementV1, SignalMsg, WireMsg } from './types.js';
import { verifyTraderSig, ensurePrivKeyHex, pubKeyFromPrivKeyHex, sha256Hex } from './crypto.js';
import { TapeStore } from './tape.js';
import { PeerSession } from './peerSession.js';
import { isWireMsg } from './validate.js';
import { LruSet } from './lru.js';
import { ClearlistClient } from './clearlist.js';
import { loadValidators } from './schema.js';
import { buildManifest } from './manifest.js';
import { IpIntelClient } from './ipIntel.js';
import { AuditLog } from './auditLog.js';
import { buildBitvmStatusFromArtifacts } from './bitvmStatus.js';

function randId(): string {
  return Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2);
}

function safeJsonParse(s: string): any | null {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function readHttpJson(req: http.IncomingMessage, maxBytes: number): Promise<any> {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      raw += chunk;
      if (Buffer.byteLength(raw, 'utf8') > maxBytes) {
        reject(new Error('request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(raw ? safeJsonParse(raw) : null));
    req.on('error', reject);
  });
}

function normalizeCompatParams(body: any): unknown[] {
  if (Array.isArray(body?.params)) return body.params;
  if (body?.params == null) return [];
  return [body.params];
}

async function readResponseBody(res: Response): Promise<any> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
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
  const rpcAdvertTtlMs = Math.max(15000, Number(process.env.TL_COLLATOR_RPC_ADVERT_TTL_MS || 45000) || 45000);
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
    fs.writeFileSync(cfg.collatorKeyPath, privHex, 'utf8');
  }
  const pubHex = pubKeyFromPrivKeyHex(privHex);
  const collatorId = sha256Hex(pubHex);

  const manifest = buildManifest(cfg, { collatorId, collatorPubKey: pubHex, collatorPrivKeyHex: privHex });

  const tape = new TapeStore({
    tapePath: cfg.tapePath,
    idxPath: cfg.idxPath,
    idxStride: cfg.idxStride,
    replayBatch: cfg.replayBatch,
    collatorId,
    collatorPrivKeyHex: privHex,
  });
  const seen = new LruSet(Number(process.env.SEEN_ORDERIDS_MAX || 100000));
  const clearlist = cfg.clearlistEnforce && cfg.clearlistUrl ? new ClearlistClient({ baseUrl: cfg.clearlistUrl }) : null;
  const ipIntel = cfg.ipIntelUrl ? new IpIntelClient({ url: cfg.ipIntelUrl, ttlSec: cfg.ipIntelTtlSec, max: 5000 }) : null;
  const audit = new AuditLog(cfg.ipLogging === 'on' ? path.join(cfg.dataDir, 'audit.log') : null);

  const server = cfg.tlsKeyPath && cfg.tlsCertPath
    ? https.createServer({
        key: fs.readFileSync(cfg.tlsKeyPath),
        cert: fs.readFileSync(cfg.tlsCertPath),
      })
    : http.createServer();

  const wss = new WebSocketServer({ server, path: cfg.wsPath, maxPayload: cfg.maxMsgBytes });
  const sessions = new Map<string, PeerSession>();
  const peers = new Set<PeerSession>();
  const rpcAdvertisements = new Map<PeerSession, { nodeId: string; services: RpcServiceAdvertisementV1[]; lastSeenTs: number }>();
  const pendingRpc = new Map<string, {
    requester?: PeerSession;
    provider: PeerSession;
    providerNodeId: string;
    timer: NodeJS.Timeout;
    resolve?: (res: RpcResponseV1) => void;
    reject?: (err: Error) => void;
  }>();

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
        if (Array.isArray(service.methods) && service.methods.length) {
          const requestedMethod = String(rpcReq.method || '').trim().toLowerCase();
          const advertised = service.methods.map((method) => String(method || '').trim().toLowerCase());
          if (!advertised.includes(requestedMethod)) continue;
        }
        return { session: sess, nodeId: advert.nodeId };
      }
    }
    return null;
  };

  const routeRpcRequest = (rpcReq: RpcRequestV1, requester?: PeerSession): Promise<RpcResponseV1> => {
    logPortfolioHeartbeat('rpc', 'request', {
      service: rpcReq.service,
      method: rpcReq.method,
      network: rpcReq.network || null,
      preferredProviderNodeId: rpcReq.preferredProviderNodeId || null,
      requester: requester?.id || null,
      sourceEndpoint: rpcReq.sourceEndpoint || null,
    });
    const provider = findRpcProvider(rpcReq, requester);
    if (!provider) {
      logPortfolioHeartbeat('rpc', 'no-provider', {
        service: rpcReq.service,
        method: rpcReq.method,
        network: rpcReq.network || null,
      });
      const res: RpcResponseV1 = {
        id: rpcReq.id,
        ok: false,
        error: {
          code: 'NO_RPC_PROVIDER',
          message: `no WebRTC RPC provider for ${rpcReq.service}${rpcReq.network ? ` on ${rpcReq.network}` : ''}`,
        },
      };
      if (requester) requester.sendDc({ t: 'RPC_RES', v: 1, res });
      return Promise.resolve(res);
    }

    const timeoutMs = Math.max(1000, Math.min(120000, Number(rpcReq.timeoutMs || 12000)));
    logPortfolioHeartbeat('rpc', 'provider-selected', {
      service: rpcReq.service,
      method: rpcReq.method,
      network: rpcReq.network || null,
      providerNodeId: provider.nodeId,
      timeoutMs,
    });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingRpc.delete(rpcReq.id);
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

      pendingRpc.set(rpcReq.id, { requester, provider: provider.session, providerNodeId: provider.nodeId, timer, resolve, reject });
      provider.session.sendDc({ t: 'RPC_REQ', v: 1, req: rpcReq });
    });
  };

  const proxyLegacyJson = async (method: string, pathname: string, body?: any, query?: Record<string, string>): Promise<{ statusCode: number; body: any }> => {
    const url = new URL(`${legacyRelayerBaseUrl}${pathname}`);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v != null) url.searchParams.set(k, v);
      }
    }
    const res = await fetch(url, {
      method,
      headers: { 'content-type': 'application/json' },
      body: method === 'GET' || method === 'HEAD' ? undefined : JSON.stringify(body ?? {}),
    });
    return { statusCode: res.status, body: await readResponseBody(res) };
  };

  const getRequestIp = (req: http.IncomingMessage): string => {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) return cf.trim();
    const xreal = req.headers['x-real-ip'];
    if (typeof xreal === 'string' && xreal.trim()) return xreal.trim();
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) return xff.split(',')[0].trim();
    return String((req as any)?.socket?.remoteAddress || '127.0.0.1');
  };

  const routeCompatRpcRequest = async (method: string, params: unknown[], replyPath: string): Promise<{ statusCode: number; body: any }> => {
    const rpcReq: RpcRequestV1 = {
      id: `rpc-${randId()}`,
      service: compatRpcService,
      method,
      params,
      ...(compatRpcNetwork ? { network: compatRpcNetwork } : {}),
    };
    const routed = await routeRpcRequest(rpcReq);
    if (routed.ok) {
      return { statusCode: 200, body: { data: routed.result } };
    }
    if (routed.error?.code === 'NO_RPC_PROVIDER') {
      try {
        const proxied = await proxyLegacyJson('POST', `/rpc/${method}`, { params });
        return proxied;
      } catch (e: any) {
        return {
          statusCode: 502,
          body: {
            error: e?.message || `legacy relayer proxy failed on ${replyPath}`,
            code: 'LEGACY_PROXY_ERROR',
          },
        };
      }
    }
    return {
      statusCode: routed.error?.code === 'NO_RPC_PROVIDER' ? 503 : 502,
      body: {
        error: routed.error?.message || `compat RPC failed on ${replyPath}`,
        code: routed.error?.code || 'RPC_ERROR',
      },
    };
  };

  const settleRpcResponse = (res: RpcResponseV1): void => {
    const pending = pendingRpc.get(res.id);
    if (!pending) return;
    clearTimeout(pending.timer);
    pendingRpc.delete(res.id);
    const routed = pending.providerNodeId ? { ...res, providerNodeId: pending.providerNodeId } : res;
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

      // Basic CORS for web clients.
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'content-type');
      if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
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
        try {
          const proxied = await proxyLegacyJson(req.method || 'GET', '/attestation/ip');
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
        const ip = getRequestIp(req);
        if (!ip) {
          writeJson(res, 400, { success: false, error: 'Unable to determine client IP' });
          return;
        }
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
            source: ipIntel ? 'unknown' : 'unknown',
            message: isBlocked ? 'Suspicious IP detected.' : 'IP is clean and trusted.',
          });
          return;
        } catch (e: any) {
          writeJson(res, 200, {
            success: false,
            ip,
            isBlocked: false,
            source: 'unknown',
            message: e?.message || 'No IP reputation provider succeeded',
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

        try {
          const body = req.method === 'GET' ? undefined : await readHttpJson(req, cfg.maxMsgBytes);
          const proxied = await proxyLegacyJson(req.method || 'POST', u.pathname, body);
          if (proxied.statusCode < 500) {
            writeJson(res, proxied.statusCode, proxied.body);
            return;
          }
        } catch {}
      }

      const compatRpcMatch =
        u.pathname !== '/rpc/route' &&
        u.pathname !== '/rpc/providers' &&
        u.pathname.match(/^\/(?:relayer\/)?rpc\/([^/]+)$/);
      if (req.method === 'POST' && compatRpcMatch) {
        const method = decodeURIComponent(compatRpcMatch[1] || '').trim();
        if (!method) {
          writeJson(res, 400, { error: 'Missing RPC method' });
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
        const compat = await routeCompatRpcRequest(method, params, u.pathname);
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
        logPortfolioHeartbeat('http', '/rpc/route request', {
          service: rpcReq.service,
          method: rpcReq.method,
          network: rpcReq.network || null,
          sourceEndpoint: rpcReq.sourceEndpoint || null,
          ...summarizeRpcMethod(rpcReq.method, rpcReq.params),
        });
        const routed = await routeRpcRequest(rpcReq);
        logPortfolioHeartbeat('http', '/rpc/route response', {
          service: rpcReq.service,
          method: rpcReq.method,
          network: rpcReq.network || null,
          ok: routed.ok,
          errorCode: routed.error?.code || null,
          providerNodeId: routed.providerNodeId || null,
        });
        writeJson(res, routed.ok ? 200 : 502, routed);
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
        const compat = await routeCompatRpcRequest('getblockchaininfo', [], u.pathname);
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
        const compat = await routeCompatRpcRequest('validateaddress', [address], u.pathname);
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
        const compat = await routeCompatRpcRequest('tl_getallbalancesforaddress', [address], u.pathname);
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
        const compat = await routeCompatRpcRequest('sendtoaddress', [address, 1], u.pathname);
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
        const compat = await routeCompatRpcRequest('listunspent', [0, 99999999, { address, ...(pubkey ? { pubkey } : {}) }], u.pathname);
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
        const compat = await routeCompatRpcRequest('tl_gettransaction', [txid], u.pathname);
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
        const compat = await routeCompatRpcRequest('tl_listproperties', [], u.pathname);
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
        const compat = await routeCompatRpcRequest('decoderawtransaction', [rawtx], u.pathname);
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
        const compat = await routeCompatRpcRequest('sendrawtransaction', [rawTx], u.pathname);
        writeJson(res, compat.statusCode, { txid: compat.body?.data ?? compat.body?.result ?? compat.body });
        return;
      }

      if (req.method === 'POST' && u.pathname === '/tx/buildTx') {
        const body = await readHttpJson(req, cfg.maxMsgBytes);
        try {
          const proxied = await proxyLegacyJson('POST', '/tx/buildTx', body);
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
        const compat = await routeCompatRpcRequest('tl_getproperty', [Number(propId)], u.pathname);
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
      writeJson(res, 500, { ok: false, error: { code: 'INTERNAL', message: e?.message || String(e) } });
    });
  });

  wss.on('connection', (ws, req) => {
    if (typeof cfg.connMax === 'number' && cfg.connMax >= 0 && peers.size >= cfg.connMax) {
      try {
        ws.close(1013, 'server busy');
      } catch {}
      return;
    }

    const id = `peer-${randId()}`;
    const remoteIp = (req as any)?.socket?.remoteAddress ? String((req as any).socket.remoteAddress) : undefined;
    const userAgent = req?.headers?.['user-agent'] ? String(req.headers['user-agent']) : undefined;
    const sess = new PeerSession({ id, ws, burst: cfg.submitBurst, ratePerSec: cfg.submitRatePerSec, remoteIp, userAgent });
    sessions.set(id, sess);
    peers.add(sess);

    let pc: any = null;

    const sendSignal = (m: SignalMsg) => {
      if (ws.readyState !== ws.OPEN) return;
      ws.send(JSON.stringify(m));
    };

    const cleanup = async () => {
      try {
        sess.dc?.close();
      } catch {}
      sess.dc = null;
      try {
        pc?.close?.();
      } catch {}
      pc = null;
      sessions.delete(id);
      peers.delete(sess);
      rpcAdvertisements.delete(sess);
      for (const [reqId, pending] of Array.from(pendingRpc.entries())) {
        if (pending.requester !== sess && pending.provider !== sess) continue;
        clearTimeout(pending.timer);
        pendingRpc.delete(reqId);
        const res: RpcResponseV1 = {
          id: reqId,
          ok: false,
          error: { code: 'RPC_PEER_CLOSED', message: 'routed RPC peer disconnected before response' },
        };
        if (pending.requester && pending.requester !== sess) pending.requester.sendDc({ t: 'RPC_RES', v: 1, res });
        if (pending.reject) pending.reject(new Error(res.error?.message || 'routed RPC peer closed'));
      }
    };

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
          // Collator is the answerer.
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
            sess.dc = dc;

            dc.onmessage = async (ev2: any) => {
              const txt = typeof ev2.data === 'string' ? ev2.data : Buffer.from(ev2.data).toString('utf8');
              if (txt.length > cfg.maxMsgBytes) {
                sess.sendDc({ t: 'ERR', v: 1, code: 'msg_too_large', msg: 'message too large' });
                try { dc.close(); } catch {}
                return;
              }
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
                logPortfolioHeartbeat('rpc', 'advertise', {
                  nodeId: wm.nodeId,
                  services: Array.isArray(wm.services) ? wm.services.map((service) => ({
                    service: service.service,
                    network: service.network || null,
                    methods: Array.isArray(service.methods) ? service.methods.length : null,
                  })) : [],
                });
                rpcAdvertisements.set(sess, {
                  nodeId: wm.nodeId,
                  services: wm.services,
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
                void routeRpcRequest(rpcReq, sess).catch((e: any) => {
                  sess.sendDc({
                    t: 'RPC_RES',
                    v: 1,
                    res: {
                      id: rpcReq.id,
                      ok: false,
                      error: { code: 'RPC_ROUTE_ERROR', message: e?.message || String(e) },
                    },
                  });
                });
                return;
              }

              if (wm.t === 'RPC_RES') {
                settleRpcResponse(wm.res);
                return;
              }

              if (wm.t === 'TAPE_SUB') {
                sess.wantsTape = true;
                const fromSeq = typeof wm.fromSeq === 'number' ? wm.fromSeq : 1;
                const lastSeq = await tape.replayFromSeq(Math.max(1, fromSeq), (e) => sess.sendTapeEntry(e));
                // Optional end marker; wallets that don't understand it should ignore.
                sess.sendDc({ t: 'TAPE_END', v: 1, lastSeq });
                return;
              }

              if (wm.t === 'SUBMIT') {
                if (!sess.submitBucket.allow(1)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'rate_limited', msg: 'too many SUBMIT' });
                  return;
                }
                const order = (wm as any).order;
                if (!schemas.validateOrderEnvelope(order)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'invalid OrderEnvelopeV1 schema' });
                  return;
                }
                if (seen.has(order.orderId)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'DUPLICATE', msg: 'orderId already seen' });
                  return;
                }
                if (!verifyTraderSig(order.orderId, order.sigTrader, order.traderPubKey)) {
                  sess.sendDc({ t: 'ERR', v: 1, code: 'bad_sig', msg: 'sigTrader verify failed' });
                  return;
                }

                // Basic referential integrity: prevent third-party cancels/replaces.
                if (order.kind === 'CANCEL') {
                  const target = String(order.cancelsOrderId || '').trim();
                  if (!target) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'missing cancelsOrderId' });
                    return;
                  }
                  const owner = tape.getTraderForOrderId(target);
                  if (!owner) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'UNKNOWN_ORDER', msg: 'cancelsOrderId not found' });
                    return;
                  }
                  if (owner !== order.traderPubKey) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'NOT_OWNER', msg: 'cannot cancel other trader order' });
                    return;
                  }
                } else if (order.kind === 'REPLACE') {
                  const target = String(order.replacesOrderId || '').trim();
                  if (!target) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'SCHEMA_INVALID', msg: 'missing replacesOrderId' });
                    return;
                  }
                  const owner = tape.getTraderForOrderId(target);
                  if (!owner) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'UNKNOWN_ORDER', msg: 'replacesOrderId not found' });
                    return;
                  }
                  if (owner !== order.traderPubKey) {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'NOT_OWNER', msg: 'cannot replace other trader order' });
                    return;
                  }
                }

                // Optional IP intel policy enforcement.
                if (ipIntel && (cfg.vpnFilterMode !== 'off' || cfg.asnBlockMode !== 'off')) {
                  const ip = sess.meta.remoteIp;
                  if (ip) {
                    try {
                      const intel = await ipIntel.lookup(ip);
                      if (typeof intel.asn === 'number') sess.meta.asn = intel.asn;
                      if (typeof intel.vpn === 'boolean') sess.meta.vpn = intel.vpn;
                    } catch {
                      // ignore intel errors for now; manifest already disables enforcement if IP_INTEL_URL missing.
                    }
                  }
                }

                if (cfg.vpnFilterMode !== 'off' && sess.meta.vpn === true) {
                  if (cfg.vpnFilterMode === 'reject') {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'VPN_BLOCKED', msg: 'vpn traffic rejected' });
                    return;
                  }
                }
                if (cfg.asnBlockMode !== 'off' && typeof sess.meta.asn === 'number' && cfg.asnBlocklist.includes(sess.meta.asn)) {
                  if (cfg.asnBlockMode === 'reject') {
                    sess.sendDc({ t: 'ERR', v: 1, code: 'ASN_BLOCKED', msg: 'asn blocked' });
                    return;
                  }
                }

                // Optional clearlist enforcement.
                if (cfg.clearlistEnforce) {
                  const vis: any = order?.body?.visibility;
                  const kind = vis?.kind;
                  const groupId = vis?.groupId;
                  if ((kind === 'CLEARLIST' || kind === 'DARK') && typeof groupId === 'string' && groupId) {
                    if (!clearlist) {
                      sess.sendDc({ t: 'ERR', v: 1, code: 'CLEARLIST_CONFIG', msg: 'CLEARLIST_URL not configured' });
                      if (cfg.clearlistFailMode === 'closed') return;
                    } else {
                      try {
                        const res = await clearlist.check(groupId, order.traderPubKey);
                        if (!res.allowed) {
                          sess.sendDc({ t: 'ERR', v: 1, code: 'NOT_CLEARLISTED', msg: 'not clearlisted' });
                          return;
                        }
                      } catch (e: any) {
                        if (cfg.clearlistFailMode === 'closed') {
                          sess.sendDc({ t: 'ERR', v: 1, code: 'CLEARLIST_DOWN', msg: e?.message || String(e) });
                          return;
                        }
                      }
                    }
                  }
                }

                const entry = tape.append(order);
                seen.add(order.orderId);
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
                for (const p of peers) {
                  if (!p.dc || p.dc.readyState !== 'open') continue;
                  if (!p.wantsTape) continue;
                  p.sendTapeEntry(entry);
                }
                return;
              }
            };

            dc.onopen = () => {
              // No-op. Wait for client HELLO/TAPE_SUB.
            };
            dc.onclose = () => {
              sess.dc = null;
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
        sendSignal({ t: 'SIGNAL_ERR', v: 1, code: 'internal', msg: e?.message || String(e) });
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

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
