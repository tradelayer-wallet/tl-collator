#!/usr/bin/env node
/* eslint-disable no-console */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ecc = require('tiny-secp256k1');

function usage() {
  console.log(
    [
      'Usage:',
      '  node scripts/sign-infra-attestation.cjs \\',
      '    --ws ws://127.0.0.1:8787/ws \\',
      '    --clearlist-id 42 \\',
      '    --admin-pubkey <hex-compressed-pubkey> \\',
      '    --admin-privkey <hex-privkey> \\',
      '    [--collator-key ./data/collator.key] \\',
      '    [--issued-at 1760000000] \\',
      '    [--expires-at 1762592000] \\',
      '    [--expires-in-days 30] \\',
      '    [--nonce <hex>] \\',
      '    [--kind COLLATOR_APPROVAL|BUNDLER_APPROVAL] \\',
      '    [--out ./data/infra-attestations.json]',
      '',
      'Notes:',
      '  - If --out exists, the attestation is upserted by (ws, clearlistId, infraId).',
      '  - Signature is compact 64-byte hex over sha256(stableStringify(body)).',
    ].join('\n')
  );
}

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const k = a.slice(2);
    const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true;
    out[k] = v;
    if (v !== true) i += 1;
  }
  return out;
}

function isHex(s) {
  return typeof s === 'string' && /^[0-9a-fA-F]+$/.test(s);
}

function sha256HexUtf8(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function canonicalize(v) {
  if (v === null) return null;
  if (Array.isArray(v)) return v.map(canonicalize);
  if (v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = canonicalize(v[k]);
    return out;
  }
  return v;
}

function stableStringify(v) {
  return JSON.stringify(canonicalize(v));
}

function readPrivHex(rawOrPath) {
  const raw = String(rawOrPath || '').trim();
  if (!raw) throw new Error('missing private key');
  if (isHex(raw) && raw.length === 64) return raw.toLowerCase();
  const filePath = path.resolve(process.cwd(), raw);
  const fileData = fs.readFileSync(filePath, 'utf8').trim();
  if (!isHex(fileData) || fileData.length !== 64) throw new Error(`invalid private key in file: ${filePath}`);
  return fileData.toLowerCase();
}

function readPubHex(rawOrPath) {
  const raw = String(rawOrPath || '').trim();
  if (!raw) throw new Error('missing public key');
  if (isHex(raw) && (raw.length === 66 || raw.length === 130)) return raw.toLowerCase();
  const filePath = path.resolve(process.cwd(), raw);
  const fileData = fs.readFileSync(filePath, 'utf8').trim();
  if (!isHex(fileData) || (fileData.length !== 66 && fileData.length !== 130)) {
    throw new Error(`invalid public key in file: ${filePath}`);
  }
  return fileData.toLowerCase();
}

function main() {
  const args = parseArgs(process.argv);
  if (args.help || args.h) {
    usage();
    process.exit(0);
  }

  const ws = String(args.ws || '').trim();
  if (!ws) throw new Error('--ws is required');

  const clearlistId = Number(args['clearlist-id']);
  if (!Number.isInteger(clearlistId) || clearlistId < 0) throw new Error('--clearlist-id must be a non-negative integer');

  const kind = String(args.kind || 'COLLATOR_APPROVAL').trim();
  if (kind !== 'COLLATOR_APPROVAL' && kind !== 'BUNDLER_APPROVAL') throw new Error('--kind must be COLLATOR_APPROVAL or BUNDLER_APPROVAL');

  const collatorKeyPath = String(args['collator-key'] || './data/collator.key').trim();
  const collatorPriv = readPrivHex(collatorKeyPath);
  const collatorPubBytes = ecc.pointFromScalar(Buffer.from(collatorPriv, 'hex'), true);
  if (!collatorPubBytes) throw new Error('invalid collator private key');
  const infraPubKey = Buffer.from(collatorPubBytes).toString('hex');
  const infraId = sha256HexUtf8(infraPubKey);

  const adminPubKey = readPubHex(args['admin-pubkey']);
  const adminPrivKey = readPrivHex(args['admin-privkey']);

  const issuedAt = Number.isFinite(Number(args['issued-at']))
    ? Number(args['issued-at'])
    : Math.floor(Date.now() / 1000);
  let expiresAt = Number.isFinite(Number(args['expires-at'])) ? Number(args['expires-at']) : 0;
  if (!expiresAt) {
    const days = Number.isFinite(Number(args['expires-in-days'])) ? Number(args['expires-in-days']) : 30;
    expiresAt = issuedAt + Math.max(1, Math.floor(days)) * 24 * 60 * 60;
  }
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
    throw new Error('issued/expires values invalid');
  }

  const nonce = isHex(String(args.nonce || '')) ? String(args.nonce).toLowerCase() : crypto.randomBytes(16).toString('hex');

  const body = {
    v: 1,
    kind,
    clearlistId,
    infraPubKey,
    infraId,
    ws,
    issuedAt: Math.floor(issuedAt),
    expiresAt: Math.floor(expiresAt),
    nonce,
    adminPubKey,
  };

  const msg32 = sha256HexUtf8(stableStringify(body));
  const sig = ecc.sign(Buffer.from(msg32, 'hex'), Buffer.from(adminPrivKey, 'hex'));
  const sigAdmin = Buffer.from(sig).toString('hex');
  const entry = { body, sigAdmin };

  const outPath = path.resolve(process.cwd(), String(args.out || './data/infra-attestations.json'));
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  let arr = [];
  if (fs.existsSync(outPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(outPath, 'utf8'));
      if (Array.isArray(parsed)) arr = parsed;
    } catch {}
  }

  const key = `${body.ws}|${body.clearlistId}|${body.infraId}`;
  const filtered = arr.filter((x) => {
    const b = x && x.body ? x.body : {};
    const k = `${String(b.ws || '')}|${String(b.clearlistId || '')}|${String(b.infraId || '')}`;
    return k !== key;
  });
  filtered.push(entry);
  fs.writeFileSync(outPath, JSON.stringify(filtered, null, 2));

  console.log(JSON.stringify({ ok: true, out: outPath, entry }, null, 2));
}

try {
  main();
} catch (e) {
  console.error(String(e && e.message ? e.message : e));
  process.exit(1);
}
