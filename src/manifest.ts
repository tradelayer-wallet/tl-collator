import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { stableStringify } from './canonical.js';
import { sha256Hex, signWithPrivKeyHex } from './crypto.js';
import type { Config } from './config.js';

export interface InfraAttestationBodyV1 {
  v: 1;
  kind: 'COLLATOR_APPROVAL' | 'BUNDLER_APPROVAL';
  clearlistId: number;
  infraPubKey: string; // compressed secp256k1 pubkey hex
  infraId: string; // derived (wallet will verify it matches infraPubKey)
  ws: string; // signaling URL the wallet connects to
  issuedAt: number; // unix seconds
  expiresAt: number; // unix seconds
  nonce: string; // random hex
  adminPubKey: string; // compressed secp256k1 pubkey hex (must correspond to protocol admin address)
}

export interface InfraAttestationV1 {
  body: InfraAttestationBodyV1;
  sigAdmin: string; // 64-byte compact sig over sha256(stableStringify(body))
}

export interface ManifestV1 {
  v: 1;
  collatorId: string;
  collatorPubKey: string;
  name?: string;
  operator?: string;
  region?: string;
  roles: Array<'collator' | 'bundler'>;
  protocol: {
    wireMsgVersion: 1;
    dataChannelLabel: string;
    maxMsgBytes: number;
  };
  tape: {
    format: 'ndjson';
    hash: 'sha256';
    indexStride: number;
    replayBatch: number;
  };
  policy: {
    clearlist: {
      enforce: boolean;
      failMode: 'open' | 'closed';
      oracleUrl?: string;
      cacheTtlSec: number;
    };
    network: {
      ipLogging: 'off' | 'on';
      vpnFilterMode: 'off' | 'log' | 'reject';
      asnBlockMode: 'off' | 'log' | 'reject';
    };
    rateLimit: {
      submitRps: number;
      submitBurst: number;
      connMax?: number;
    };
  };
  build: {
    version: string;
    gitSha?: string;
    builtAt?: string;
  };
  infraAttestations?: InfraAttestationV1[];
  sigCollator: string;
}

function readPkgVersion(): string {
  try {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const pj = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    return String(pj?.version || '0.0.0');
  } catch {
    return '0.0.0';
  }
}

function loadInfraAttestations(cfg: Config): InfraAttestationV1[] | undefined {
  try {
    let raw: any = null;

    if (cfg.infraAttestationsJson) {
      raw = JSON.parse(String(cfg.infraAttestationsJson));
    } else if (cfg.infraAttestationsPath && fs.existsSync(cfg.infraAttestationsPath)) {
      raw = JSON.parse(fs.readFileSync(cfg.infraAttestationsPath, 'utf8'));
    }

    if (!Array.isArray(raw)) return undefined;

    const out: InfraAttestationV1[] = [];
    for (const item of raw) {
      const body = item?.body;
      const sigAdmin = item?.sigAdmin;
      if (!body || typeof body !== 'object') continue;
      if (body.v !== 1) continue;
      if (body.kind !== 'COLLATOR_APPROVAL' && body.kind !== 'BUNDLER_APPROVAL') continue;
      if (!Number.isInteger(body.clearlistId) || body.clearlistId < 0) continue;
      if (typeof body.infraPubKey !== 'string' || !/^[0-9a-fA-F]+$/.test(body.infraPubKey)) continue;
      if (typeof body.infraId !== 'string' || body.infraId.length < 1) continue;
      if (typeof body.ws !== 'string' || body.ws.length < 1) continue;
      if (!Number.isFinite(Number(body.issuedAt)) || !Number.isFinite(Number(body.expiresAt))) continue;
      if (typeof body.nonce !== 'string' || body.nonce.length < 1) continue;
      if (typeof body.adminPubKey !== 'string' || !/^[0-9a-fA-F]+$/.test(body.adminPubKey)) continue;
      if (typeof sigAdmin !== 'string' || !/^[0-9a-fA-F]{128}$/.test(sigAdmin)) continue;

      out.push({ body, sigAdmin });
      if (out.length >= 128) break; // avoid manifest bloat
    }

    return out.length ? out : undefined;
  } catch {
    return undefined;
  }
}

export function buildManifest(cfg: Config, opts: { collatorId: string; collatorPubKey: string; collatorPrivKeyHex: string }): ManifestV1 {
  const version = readPkgVersion();
  const builtAt = new Date().toISOString();
  const gitSha = process.env.GIT_SHA || process.env.SOURCE_VERSION || undefined;
  const infraAttestations = loadInfraAttestations(cfg);

  const body: Omit<ManifestV1, 'sigCollator'> = {
    v: 1,
    collatorId: opts.collatorId,
    collatorPubKey: opts.collatorPubKey,
    ...(cfg.name ? { name: cfg.name } : {}),
    ...(cfg.operator ? { operator: cfg.operator } : {}),
    ...(cfg.region ? { region: cfg.region } : {}),
    roles: ['collator'],
    protocol: {
      wireMsgVersion: 1,
      dataChannelLabel: 'tl-bb',
      maxMsgBytes: cfg.maxMsgBytes,
    },
    tape: {
      format: 'ndjson',
      hash: 'sha256',
      indexStride: cfg.idxStride,
      replayBatch: cfg.replayBatch,
    },
    policy: {
      clearlist: {
        enforce: cfg.clearlistEnforce,
        failMode: cfg.clearlistFailMode,
        ...(cfg.clearlistUrl ? { oracleUrl: cfg.clearlistUrl } : {}),
        cacheTtlSec: 60,
      },
      network: {
        ipLogging: cfg.ipLogging,
        vpnFilterMode: cfg.vpnFilterMode,
        asnBlockMode: cfg.asnBlockMode,
      },
      rateLimit: {
        submitRps: cfg.submitRatePerSec,
        submitBurst: cfg.submitBurst,
        ...(typeof cfg.connMax === 'number' ? { connMax: cfg.connMax } : {}),
      },
    },
    build: {
      version,
      ...(gitSha ? { gitSha } : {}),
      builtAt,
    },
    ...(infraAttestations ? { infraAttestations } : {}),
  };

  const msg32 = sha256Hex(stableStringify(body));
  const sigCollator = signWithPrivKeyHex(msg32, opts.collatorPrivKeyHex);
  return { ...body, sigCollator };
}
