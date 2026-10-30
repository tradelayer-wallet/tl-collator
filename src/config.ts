import fs from 'node:fs';
import path from 'node:path';

import {
  CLIENT_IPV6_PREFIX_DEFAULT,
  CLIENT_IPV6_PREFIX_MAX,
  CLIENT_IPV6_PREFIX_MIN,
  parseTrustedProxyConfig,
  type TrustedProxyConfig,
} from './clientIp.js';

export interface Config {
  port: number;
  wsPath: string;
  dataDir: string;
  tapePath: string;
  idxPath: string;
  idxStride: number;
  replayBatch: number;
  collatorKeyPath: string;
  infraAttestationsPath: string | null;
  infraAttestationsJson: string | null;
  maxMsgBytes: number;
  submitBurst: number;
  submitRatePerSec: number;
  submitClientBurst: number;
  submitClientRatePerSec: number;
  openSessionBurst: number;
  openSessionRatePerSec: number;
  openIpBurst: number;
  openIpRatePerSec: number;
  tapeIpBurst: number;
  tapeIpRatePerSec: number;
  clearlistEnforce: boolean;
  clearlistUrl: string | null;
  clearlistFailMode: 'open' | 'closed';
  name: string | null;
  operator: string | null;
  region: string | null;
  ipLogging: 'off' | 'on';
  vpnFilterMode: 'off' | 'log' | 'reject';
  asnBlockMode: 'off' | 'log' | 'reject';
  asnBlocklist: number[];
  ipIntelUrl: string | null;
  ipIntelTtlSec: number;
  connMax: number | null;
  trustedProxy: TrustedProxyConfig;
  tapeResyncMaxEntries: number;
  httpRpcPerIpRps: number;
  httpRpcPerIpBurst: number;
  httpRpcGlobalRps: number;
  httpRpcGlobalBurst: number;
  clientIpv6PrefixLen: number;
  pendingRpcMax: number;
  rpcAdvertTtlMs: number;
  connIdleTimeoutMs: number;
  connSweepIntervalMs: number;
  connHandshakeGraceMs: number;
  connMaxPerIp: number;
  pendingRpcMaxPerSession: number;
  pendingRpcMaxPerIp: number;
  tlsKeyPath: string | null;
  tlsCertPath: string | null;
  iceServers: RTCIceServer[];
}

// Inclusive bounds for one integer env var. Every integer env var declares its
// own bounds; nothing is silently clamped to a floor or ceiling.
export interface IntBounds {
  min: number;
  max: number;
}

// ws reads maxPayload with `| 0`, so anything above 2^31-1 wraps negative and
// silently disables the WebSocket size check.
const INT32_MAX = 2147483647;
// setTimeout/setInterval treat anything above 2^31-1 ms as 1 ms (TimeoutOverflowWarning).
export const TIMER_MAX_MS = INT32_MAX;

export function atLeast(min: number, max: number = INT32_MAX): IntBounds {
  return { min, max };
}

// The single integer-env parser for the collator. Unset or empty means the
// default. Anything else must be a safe integer inside `bounds`: a typo such as
// CONN_MAX=25six, a negative cap that would disable it, or a zero that would
// silently become a different value all abort startup instead of running with
// something other than what was asked for. Every integer env var goes through
// here (no `Number(x) || default` and no Math.max/min clamps).
export function parseIntEnv(k: string, raw: string | undefined, d: number, bounds: IntBounds): number {
  const v = (raw ?? '').trim();
  if (v === '') return d;
  if (!/^[+-]?\d+$/.test(v)) {
    throw new Error(`${k} must be an integer (got "${raw}")`);
  }
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < bounds.min || n > bounds.max) {
    throw new Error(`${k} must be an integer from ${bounds.min} to ${bounds.max} (got "${raw}")`);
  }
  return n;
}

export function intEnv(k: string, d: number, bounds: IntBounds): number {
  return parseIntEnv(k, process.env[k], d, bounds);
}

// The single parser for enumerated policy switches. Unset or empty means the
// default; any other value must be spelled exactly as one of `choices`. A
// misspelled mode such as `rejct` must not read as `off`, and a case variant of
// `open` must not read as a different fail mode.
export function parseChoiceEnv<T extends string>(k: string, raw: string | undefined, d: T, choices: readonly T[]): T {
  const v = (raw ?? '').trim();
  if (v === '') return d;
  const hit = choices.find((c) => c === v);
  if (hit === undefined) {
    throw new Error(`${k} must be one of ${choices.join(', ')} (got "${raw}")`);
  }
  return hit;
}

export function loadConfig(): Config {
  const dataDir = process.env.DATA_DIR || './data';
  const tapePath = process.env.TAPE_PATH || path.join(dataDir, 'tape.log');
  const idxPath = process.env.TAPE_INDEX_PATH || path.join(dataDir, 'tape.idx');
  const collatorKeyPath = process.env.COLLATOR_KEY_PATH || path.join(dataDir, 'collator.key');
  const infraAttestationsPath = process.env.INFRA_ATTESTATIONS_PATH || path.join(dataDir, 'infra-attestations.json');
  const infraAttestationsJson = process.env.INFRA_ATTESTATIONS_JSON || null;
  const iceJson =
    process.env.ICE_SERVERS_JSON ||
    JSON.stringify([{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }]);
  // A value that is set but not a JSON array refuses startup (round 12 / F8); it is never replaced by the defaults.
  let iceParsed: unknown = null;
  try {
    iceParsed = JSON.parse(iceJson);
  } catch {}
  if (!Array.isArray(iceParsed)) throw new Error('ICE_SERVERS_JSON must be a JSON array of ICE server objects');
  const iceServers = iceParsed as RTCIceServer[];

  fs.mkdirSync(dataDir, { recursive: true });

  const clearlistEnforce = parseChoiceEnv('CLEARLIST_ENFORCE', process.env.CLEARLIST_ENFORCE, '0', ['0', '1']) === '1';
  const clearlistUrl = process.env.CLEARLIST_URL || null;
  if (clearlistEnforce && !clearlistUrl) {
    throw new Error('CLEARLIST_ENFORCE=1 requires CLEARLIST_URL (the clearlist oracle)');
  }
  const clearlistFailMode = parseChoiceEnv('CLEARLIST_FAIL_MODE', process.env.CLEARLIST_FAIL_MODE, 'closed', ['open', 'closed']);

  const name = process.env.NAME || null;
  const operator = process.env.OPERATOR || null;
  const region = process.env.REGION || null;

  const ipLoggingSwitch = parseChoiceEnv('IP_LOGGING', process.env.IP_LOGGING, 'off', ['off', 'on', '0', '1']);
  const ipLogging = ipLoggingSwitch === 'on' || ipLoggingSwitch === '1' ? 'on' : 'off';

  const ipIntelUrl = process.env.IP_INTEL_URL || null;
  const ipIntelTtlSec = intEnv('IP_INTEL_TTL_SEC', 300, atLeast(0));

  // A verdict-driven mode needs the intel source it reads from. Refusing the
  // combination keeps a configured block from being silently inert.
  const intelModes = ['off', 'log', 'reject'] as const;
  const vpnFilterMode = parseChoiceEnv('VPN_FILTER_MODE', (process.env.VPN_FILTER_MODE || '').toLowerCase(), 'off', intelModes);
  const asnBlockMode = parseChoiceEnv('ASN_BLOCK_MODE', (process.env.ASN_BLOCK_MODE || '').toLowerCase(), 'off', intelModes);
  if (!ipIntelUrl) {
    if (vpnFilterMode !== 'off') throw new Error(`VPN_FILTER_MODE=${vpnFilterMode} requires IP_INTEL_URL`);
    if (asnBlockMode !== 'off') throw new Error(`ASN_BLOCK_MODE=${asnBlockMode} requires IP_INTEL_URL`);
  }

  // Comma-separated ASNs; empty entries are skipped, anything else must be a positive integer.
  const asnBlocklist = String(process.env.ASN_BLOCKLIST || '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '')
    .map((s) => parseIntEnv('ASN_BLOCKLIST', s, 0, atLeast(1, 4294967295)));
  if (asnBlocklist.length > 0 && asnBlockMode === 'off') {
    throw new Error('ASN_BLOCKLIST is set but ASN_BLOCK_MODE is off; set ASN_BLOCK_MODE=log or reject, or unset ASN_BLOCKLIST');
  }

  // Support both new and old env var names.
  const submitBurst = intEnv('SUBMIT_BURST', 10, atLeast(1));
  const submitRatePerSec = intEnv('SUBMIT_RPS', intEnv('SUBMIT_RATE_PER_SEC', 2, atLeast(1)), atLeast(1));
  // Per client key (see clientIp.ts), shared by all of that client's sessions.
  const submitClientBurst = intEnv('SUBMIT_CLIENT_BURST', 40, atLeast(1));
  const submitClientRatePerSec = intEnv('SUBMIT_CLIENT_RPS', 8, atLeast(1));

  // H3b: sane default connection cap; CONN_MAX=0 explicitly disables the cap.
  const connMaxConfigured = intEnv('CONN_MAX', 256, atLeast(0));

  // Startup-validated: a malformed or ambiguous proxy configuration aborts the
  // process instead of silently trusting or ignoring client-IP headers.
  const trustedProxy = parseTrustedProxyConfig(process.env);

  // Upper bound on tape entries a single TAPE_SUB resync may replay.
  const tapeResyncMaxEntries = intEnv('TAPE_RESYNC_MAX_ENTRIES', 10000, atLeast(1));
  // Per-client-IP token bucket for the unauthenticated HTTP RPC entry points.
  const httpRpcPerIpRps = intEnv('HTTP_RPC_PER_IP_RPS', 20, atLeast(1));
  const httpRpcPerIpBurst = intEnv('HTTP_RPC_PER_IP_BURST', 40, atLeast(1));
  // Global backstop over all clients for the same HTTP entry points; 0 disables.
  const httpRpcGlobalRps = intEnv('HTTP_RPC_GLOBAL_RPS', 0, atLeast(0));
  const httpRpcGlobalBurst = intEnv('HTTP_RPC_GLOBAL_BURST', 200, atLeast(1));
  // Prefix length that defines one IPv6 client for every per-client limit.
  const clientIpv6PrefixLen = intEnv('CLIENT_IPV6_PREFIX_LEN', CLIENT_IPV6_PREFIX_DEFAULT, atLeast(CLIENT_IPV6_PREFIX_MIN, CLIENT_IPV6_PREFIX_MAX));
  // Concurrency caps: 0 disables. (Parsed here, not with `|| default`, which would
  // turn an explicit 0 back into the default.)
  const connMaxPerIp = intEnv('CONN_MAX_PER_IP', 16, atLeast(0));
  // Admission budget for opens (SIGNAL_OFFER and each channel open) and TAPE_SUB. Each costs one unit,
  // drawn from the session's bucket and then from its client IP's bucket. Refill is per second.
  // The IP scope is sized for N = 8 honest tabs behind one NAT: an honest reconnect is an offer, a
  // channel and a TAPE_SUB (3 units), so one session reconnecting once a second needs 3 per second,
  // and 8 such tabs need 8 x 3 = 24 per second with a burst of 8 x 4 = 32.
  //
  //   scope    burst (env, default)     refill per second (env, default)
  //   session  OPEN_SESSION_BURST (4)   OPEN_SESSION_RPS (3)
  //   client   OPEN_IP_BURST (32)       OPEN_IP_RPS (24)
  //
  // A second TAPE_SUB on one session inside 1 s is refused whatever the budget (TAPE_SUB_MIN_INTERVAL_MS).
  const openSessionBurst = intEnv('OPEN_SESSION_BURST', 4, atLeast(1));
  const openSessionRatePerSec = intEnv('OPEN_SESSION_RPS', 3, atLeast(1));
  const openIpBurst = intEnv('OPEN_IP_BURST', 32, atLeast(1));
  const openIpRatePerSec = intEnv('OPEN_IP_RPS', 24, atLeast(1));
  // A TAPE_SUB also starts a replay of up to the replay bound, so it draws on a second, smaller client bucket:
  // N = 8 honest tabs each resubscribing once a second need 8 per second.
  //
  //   client   TAPE_IP_BURST (16)       TAPE_IP_RPS (8)
  const tapeIpBurst = intEnv('TAPE_IP_BURST', 16, atLeast(1));
  const tapeIpRatePerSec = intEnv('TAPE_IP_RPS', 8, atLeast(1));
  // Hard cap on concurrent in-flight routed RPC requests.
  const pendingRpcMax = intEnv('PENDING_RPC_MAX', 1000, atLeast(1));
  const rpcAdvertTtlMs = intEnv('TL_COLLATOR_RPC_ADVERT_TTL_MS', 45000, atLeast(15000, TIMER_MAX_MS));
  const connIdleTimeoutMs = intEnv('CONN_IDLE_TIMEOUT_MS', 60000, atLeast(1000, TIMER_MAX_MS));
  const connSweepIntervalMs = intEnv('CONN_SWEEP_INTERVAL_MS', 15000, atLeast(1000, TIMER_MAX_MS));
  const connHandshakeGraceMs = intEnv('CONN_HANDSHAKE_GRACE_MS', 5000, atLeast(0, TIMER_MAX_MS));
  // Read again per status build (bitvmStatus.ts); validated here so a typo aborts startup, not every request.
  intEnv('BITVM_COLLATERAL_PROPERTY_ID', 1, atLeast(1));
  const pendingRpcMaxPerSession = intEnv('PENDING_RPC_MAX_PER_SESSION', 32, atLeast(0));
  const pendingRpcMaxPerIp = intEnv('PENDING_RPC_MAX_PER_IP', 256, atLeast(0));

  return {
    port: intEnv('PORT', intEnv('SERVER_PORT', 8787, atLeast(1, 65535)), atLeast(1, 65535)),
    wsPath: process.env.WS_PATH || '/ws',
    dataDir,
    tapePath,
    idxPath,
    idxStride: intEnv('TAPE_INDEX_STRIDE', 1000, atLeast(1)),
    replayBatch: intEnv('TAPE_REPLAY_BATCH', 500, atLeast(1)),
    collatorKeyPath,
    infraAttestationsPath: infraAttestationsPath || null,
    infraAttestationsJson,
    maxMsgBytes: intEnv('MAX_MSG_BYTES', 1048576, atLeast(1)),
    submitBurst,
    submitRatePerSec,
    submitClientBurst,
    submitClientRatePerSec,
    openSessionBurst,
    openSessionRatePerSec,
    openIpBurst,
    tapeIpBurst,
    tapeIpRatePerSec,
    openIpRatePerSec,
    clearlistEnforce,
    clearlistUrl,
    clearlistFailMode,
    name,
    operator,
    region,
    ipLogging,
    vpnFilterMode,
    asnBlockMode,
    asnBlocklist,
    ipIntelUrl,
    ipIntelTtlSec,
    connMax: connMaxConfigured > 0 ? connMaxConfigured : null,
    trustedProxy,
    tapeResyncMaxEntries,
    httpRpcPerIpRps,
    httpRpcPerIpBurst,
    httpRpcGlobalRps,
    httpRpcGlobalBurst,
    clientIpv6PrefixLen,
    pendingRpcMax,
    rpcAdvertTtlMs,
    connIdleTimeoutMs,
    connSweepIntervalMs,
    connHandshakeGraceMs,
    connMaxPerIp,
    pendingRpcMaxPerSession,
    pendingRpcMaxPerIp,
    tlsKeyPath: process.env.TLS_KEY_PATH || null,
    tlsCertPath: process.env.TLS_CERT_PATH || null,
    iceServers,
  };
}
