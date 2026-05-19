import fs from 'node:fs';
import path from 'node:path';

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
  tlsKeyPath: string | null;
  tlsCertPath: string | null;
  iceServers: RTCIceServer[];
}

function intEnv(k: string, d: number): number {
  const v = process.env[k];
  if (!v) return d;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : d;
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
  let iceServers: RTCIceServer[] = [];
  try {
    iceServers = JSON.parse(iceJson);
  } catch {
    iceServers = [{ urls: ['stun:stun.l.google.com:19302'] }];
  }

  fs.mkdirSync(dataDir, { recursive: true });

  const clearlistEnforce = String(process.env.CLEARLIST_ENFORCE || '') === '1';
  const clearlistUrl = process.env.CLEARLIST_URL || null;
  const clearlistFailMode = (process.env.CLEARLIST_FAIL_MODE === 'open' ? 'open' : 'closed') as 'open' | 'closed';

  const name = process.env.NAME || null;
  const operator = process.env.OPERATOR || null;
  const region = process.env.REGION || null;

  const ipLogging = (String(process.env.IP_LOGGING || '') === 'on' || String(process.env.IP_LOGGING || '') === '1')
    ? 'on'
    : 'off';

  const ipIntelUrl = process.env.IP_INTEL_URL || null;
  const ipIntelTtlSec = intEnv('IP_INTEL_TTL_SEC', 300);

  // If no IP intel configured, be honest: disable vpn/asn enforcement modes.
  const rawVpnMode = (process.env.VPN_FILTER_MODE || 'off').toLowerCase();
  const vpnFilterMode = (ipIntelUrl
    ? (rawVpnMode === 'reject' ? 'reject' : rawVpnMode === 'log' ? 'log' : 'off')
    : 'off') as 'off' | 'log' | 'reject';

  const rawAsnMode = (process.env.ASN_BLOCK_MODE || 'off').toLowerCase();
  const asnBlockMode = (ipIntelUrl
    ? (rawAsnMode === 'reject' ? 'reject' : rawAsnMode === 'log' ? 'log' : 'off')
    : 'off') as 'off' | 'log' | 'reject';

  const asnBlocklist = String(process.env.ASN_BLOCKLIST || '')
    .split(',')
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n) && n > 0);

  // Support both new and old env var names.
  const submitBurst = intEnv('SUBMIT_BURST', intEnv('SUBMIT_BURST', 10));
  const submitRatePerSec = intEnv('SUBMIT_RPS', intEnv('SUBMIT_RATE_PER_SEC', 2));

  return {
    port: intEnv('PORT', intEnv('SERVER_PORT', 8787)),
    wsPath: process.env.WS_PATH || '/ws',
    dataDir,
    tapePath,
    idxPath,
    idxStride: intEnv('TAPE_INDEX_STRIDE', 1000),
    replayBatch: intEnv('TAPE_REPLAY_BATCH', 500),
    collatorKeyPath,
    infraAttestationsPath: infraAttestationsPath || null,
    infraAttestationsJson,
    maxMsgBytes: intEnv('MAX_MSG_BYTES', 1048576),
    submitBurst,
    submitRatePerSec,
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
    connMax: process.env.CONN_MAX ? intEnv('CONN_MAX', 0) : null,
    tlsKeyPath: process.env.TLS_KEY_PATH || null,
    tlsCertPath: process.env.TLS_CERT_PATH || null,
    iceServers,
  };
}
