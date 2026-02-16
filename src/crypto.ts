import crypto from 'node:crypto';
import * as ecc from 'tiny-secp256k1';

export function sha256Hex(s: string): string {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

export function verifyTraderSig(orderIdHex: string, sigHex: string, pubKeyHex: string): boolean {
  try {
    const msg = Buffer.from(orderIdHex, 'hex');
    const sig = Buffer.from(sigHex, 'hex');
    const pub = Buffer.from(pubKeyHex, 'hex');
    if (msg.length !== 32) return false;
    if (sig.length !== 64) return false;
    return ecc.verify(msg, pub, sig);
  } catch {
    return false;
  }
}

export function signWithPrivKeyHex(msg32Hex: string, privKeyHex: string): string {
  const msg = Buffer.from(msg32Hex, 'hex');
  const priv = Buffer.from(privKeyHex, 'hex');
  if (msg.length !== 32) throw new Error('msg must be 32-byte hex');
  if (priv.length !== 32) throw new Error('privkey must be 32 bytes');
  const sig = ecc.sign(msg, priv); // 64 bytes
  return Buffer.from(sig).toString('hex');
}

export function pubKeyFromPrivKeyHex(privKeyHex: string): string {
  const priv = Buffer.from(privKeyHex, 'hex');
  const pub = ecc.pointFromScalar(priv, true);
  if (!pub) throw new Error('invalid privkey');
  return Buffer.from(pub).toString('hex');
}

export function ensurePrivKeyHex(existing?: string | null): string {
  if (existing) {
    const s = existing.trim();
    if (/^[0-9a-fA-F]{64}$/.test(s)) return s.toLowerCase();
    throw new Error('invalid private key hex');
  }
  // Generate a random 32-byte scalar; retry until valid.
  while (true) {
    const b = crypto.randomBytes(32);
    // tiny-secp doesn't expose "isValidScalar", but pointFromScalar null indicates invalid.
    const pub = ecc.pointFromScalar(b, true);
    if (pub) return b.toString('hex');
  }
}

