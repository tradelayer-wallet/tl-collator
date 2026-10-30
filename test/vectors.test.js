import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeEnvelopeHash, computeOrderId, envelopeSignedFields, parseCanonicalJson, stableStringify } from '../dist/canonical.js';
import { sha256Hex } from '../dist/crypto.js';
import { TapeStore } from '../dist/tape.js';
import { loadValidators } from '../dist/schema.js';

const vectorsPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'spec', 'test-vectors.json');
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

// Independent re-implementation of the TL-Canon v1 convention used by the
// smoke clients (scripts/smoke-live-flow.cjs buildOrder): code-point key order,
// keys written by hand (JSON.stringify would hoist integer-like keys).
const codePoints = (str) => Array.from(str, (c) => c.codePointAt(0));
const compareCodePoints = (a, b) => {
  const x = codePoints(a);
  const y = codePoints(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
};
function canonicalText(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalText).join(',')}]`;
  if (v && typeof v === 'object') {
    // Own-key-safe: `__proto__` is an ordinary key, read as an own data property.
    const keys = Object.keys(v).sort(compareCodePoints);
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalText(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}
function smokeStyleOrderId(envelope) {
  const signed = {};
  for (const k of Object.keys(envelope)) {
    if (k === 'orderId' || k === 'sigTrader') continue;
    Object.defineProperty(signed, k, { value: envelope[k], enumerable: true, writable: true, configurable: true });
  }
  return crypto.createHash('sha256').update(canonicalText(signed), 'utf8').digest('hex');
}

test('C1: spec vector orderId matches the envelope-hash derivation', () => {
  const { envelopeNoSig, expectedOrderId } = vectors.orderTest;
  assert.equal(computeEnvelopeHash(envelopeNoSig), expectedOrderId);
  assert.equal(computeOrderId(envelopeNoSig), expectedOrderId);
});

test('C1: canonical.ts derivation matches the smoke-script convention', () => {
  const { envelopeNoSig } = vectors.orderTest;
  assert.equal(computeEnvelopeHash(envelopeNoSig), smokeStyleOrderId(envelopeNoSig));
});

test('C1: orderId is insensitive to key order but sensitive to any content change', () => {
  const { envelopeNoSig, expectedOrderId } = vectors.orderTest;
  const shuffled = {
    clientNonce: envelopeNoSig.clientNonce,
    traderPubKey: envelopeNoSig.traderPubKey,
    body: {
      clientTs: envelopeNoSig.body.clientTs,
      visibility: envelopeNoSig.body.visibility,
      qty: envelopeNoSig.body.qty,
      px: envelopeNoSig.body.px,
      side: envelopeNoSig.body.side,
      market: envelopeNoSig.body.market,
      v: envelopeNoSig.body.v,
    },
    kind: envelopeNoSig.kind,
    v: envelopeNoSig.v,
  };
  assert.equal(stableStringify(shuffled), stableStringify(envelopeSignedFields(envelopeNoSig)));
  assert.equal(computeEnvelopeHash(shuffled), expectedOrderId);

  // Signature-stripping attack: reuse the same orderId/sig with a tampered body.
  const tampered = { ...envelopeNoSig, body: { ...envelopeNoSig.body, px: '0.01' } };
  assert.notEqual(computeEnvelopeHash(tampered), expectedOrderId);
  const tamperedNonce = 'beef'.repeat(8);
  assert.notEqual(computeEnvelopeHash({ ...envelopeNoSig, clientNonce: tamperedNonce }), expectedOrderId);
});

test('C1: kind/cancelsOrderId/replacesOrderId are bound into orderId (CANCEL/REPLACE forgery)', () => {
  const { envelopeNoSig: newEnv, expectedOrderId: newOrderId } = vectors.orderTest;
  const { envelopeNoSig: cancelEnv, expectedOrderId: cancelOrderId } = vectors.orderCancelTest;

  // The spec CANCEL vector derives cleanly and differs from its NEW sibling.
  assert.equal(computeEnvelopeHash(cancelEnv), cancelOrderId);
  assert.notEqual(cancelOrderId, newOrderId);

  // Red-team exploit: harvest (orderId, sigTrader, traderPubKey, body) from a
  // NEW order on the tape, resubmit as CANCEL/REPLACE of a victim order. The
  // recomputed envelope hash no longer matches the harvested orderId.
  const victimOrderId = 'ab'.repeat(32);
  const forgedCancel = { ...newEnv, kind: 'CANCEL', cancelsOrderId: victimOrderId };
  const forgedReplace = { ...newEnv, kind: 'REPLACE', replacesOrderId: victimOrderId };
  assert.notEqual(computeEnvelopeHash(forgedCancel), newOrderId);
  assert.notEqual(computeEnvelopeHash(forgedReplace), newOrderId);

  // Even a same-kind envelope with a different target order is unforgeable.
  assert.notEqual(
    computeEnvelopeHash({ ...cancelEnv, cancelsOrderId: 'cd'.repeat(32) }),
    cancelOrderId
  );
});

test('canonical: __proto__ keys are ordinary own keys — no hash collision, no pollution', () => {
  const base = vectors.orderTest.envelopeNoSig;
  const withProto = JSON.parse(JSON.stringify(base));
  withProto.body = JSON.parse(JSON.stringify(base.body));
  withProto.body.visibility = JSON.parse('{"kind":"PUBLIC","__proto__":{"polluted":true}}');

  // Pre-fix stableStringify dropped the __proto__ key (prototype setter),
  // making these two collide while leaving the raw objects different.
  assert.notEqual(stableStringify(base), stableStringify(withProto));
  assert.notEqual(computeEnvelopeHash(base), computeEnvelopeHash(withProto));

  // canonicalize must not pollute Object.prototype.
  stableStringify(JSON.parse('{"__proto__":{"pwned":1}}'));
  assert.equal(({}).pwned, undefined);
  assert.equal(({}).polluted, undefined);
});

test('validation: __proto__/constructor/prototype keys are rejected anywhere in the envelope', () => {
  const { envelopeNoSig } = vectors.orderTest;
  const envelope = { ...envelopeNoSig, orderId: 'ab'.repeat(32), sigTrader: '11'.repeat(64) };
  const validators = loadValidators();

  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const badTop = JSON.parse(JSON.stringify(envelope));
    Object.defineProperty(badTop, key, { value: { pwned: 1 }, enumerable: true, writable: true, configurable: true });
    assert.equal(validators.validateOrderEnvelope(badTop), false, `top-level ${key} must be rejected`);

    const badNested = JSON.parse(JSON.stringify(envelope));
    badNested.body.visibility = JSON.parse(`{"kind":"PUBLIC","${key}":{"pwned":1}}`);
    assert.equal(validators.validateOrderEnvelope(badNested), false, `nested ${key} must be rejected`);
  }

  // Sanity: the clean envelope still validates.
  assert.equal(validators.validateOrderEnvelope(envelope), true);
});

test('validation: values TL-Canon cannot represent are rejected before hashing', () => {
  const validators = loadValidators();
  const base = { ...vectors.orderTest.envelopeNoSig, orderId: 'ab'.repeat(32), sigTrader: '11'.repeat(64) };
  const clone = () => JSON.parse(JSON.stringify(base));
  const cases = {
    'clientTs above 2^53-1': (e) => { e.body.clientTs = Number.MAX_SAFE_INTEGER + 1; },
    'clientTs fractional': (e) => { e.body.clientTs = 1.5; },
    'expiryTs out of range': (e) => { e.body.expiryTs = 1e300; },
    'nested fractional number in open body': (e) => { e.body.extra = { x: 0.5 }; },
    'nested out-of-range number in open body': (e) => { e.body.extra = [1, 1e300]; },
    'lone surrogate in a string value': (e) => { e.body.market = 'SPOT:\ud800'; },
    'lone surrogate in a key': (e) => { e.body.extra = JSON.parse('{"\\udc00":1}'); },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const env = clone();
    mutate(env);
    assert.equal(validators.validateOrderEnvelope(env), false, name);
  }
  assert.equal(validators.validateOrderEnvelope(clone()), true);
});

test('validation: deeply nested input is refused with a reason, never a stack overflow', () => {
  const validators = loadValidators();
  const base = { ...vectors.orderTest.envelopeNoSig, orderId: 'ab'.repeat(32), sigTrader: '11'.repeat(64) };
  for (const depth of [5000, 100000]) {
    const env = JSON.parse(JSON.stringify(base));
    env.body.extra = JSON.parse('['.repeat(depth) + ']'.repeat(depth));
    let accepted;
    assert.doesNotThrow(() => { accepted = validators.validateOrderEnvelope(env); }, `depth ${depth} must be a validation result`);
    assert.equal(accepted, false, `depth ${depth}`);
    assert.match(validators.errorsText(), /nesting/);
  }
});

test('TL-Canon: integer-like, astral and integral-number vectors match the spec', () => {
  const ik = vectors.integerKeyTest;
  assert.equal(stableStringify(ik.input), ik.expectedCanonical);
  assert.equal(sha256Hex(stableStringify(ik.input)), ik.expectedSha256);
  // The batch-1 JSON.stringify ordering produces a different digest for this vector.
  assert.notEqual(sha256Hex(JSON.stringify(ik.input)), ik.expectedSha256);
  assert.equal(computeEnvelopeHash(vectors.orderIntegerKeyTest.envelopeNoSig), vectors.orderIntegerKeyTest.expectedOrderId);

  const uk = vectors.unicodeKeyOrderTest;
  assert.equal(stableStringify(uk.input), uk.expectedCanonical);
  assert.equal(sha256Hex(stableStringify(uk.input)), uk.expectedSha256);

  assert.equal(stableStringify(vectors.integralNumberTest.input), vectors.integralNumberTest.expectedCanonical);
});

test('TL-Canon: every rejectTests input is refused, never serialized', () => {
  for (const c of vectors.rejectTests) {
    assert.throws(() => stableStringify(c.input), TypeError, c.name);
  }
});

test('TL-Canon text: a safe integer written as a fraction is refused at parse; the other numbers are left to the value rules', () => {
  for (const c of vectors.textRejectTests) {
    assert.equal(parseCanonicalJson(c.text), null, c.name);
  }
  for (const c of vectors.textAcceptTests) {
    assert.notEqual(parseCanonicalJson(c.text), null, c.name);
  }
});

test('TL-Canon text: a hostile text that opens a string and never closes it is refused in linear time', () => {
  // A string opener followed by escaped quotes made a pattern scan quadratic: 28 s at 256 KiB.
  const hostile = '"' + '\\"'.repeat(131072);
  const started = process.hrtime.bigint();
  assert.equal(parseCanonicalJson(hostile), null);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert(elapsedMs < 1000, `a 256 KiB unterminated string took ${elapsedMs.toFixed(0)} ms`);
  // The same bytes inside a closed string are valid JSON and still parse.
  assert.notEqual(parseCanonicalJson(JSON.stringify({ a: '\\"'.repeat(1000) })), null);
});

test('TL-Canon round trip: the canonical text parses back to the same value and re-encodes byte-identically', () => {
  for (const v of [vectors.integerKeyTest.input, vectors.unicodeKeyOrderTest.input, vectors.integralNumberTest.input, vectors.orderIntegerKeyTest.envelopeNoSig]) {
    const text = stableStringify(v);
    const back = JSON.parse(text);
    assert.equal(stableStringify(back), text);
    assert.deepStrictEqual(back, JSON.parse(JSON.stringify(v)));
    assert.equal(sha256Hex(stableStringify(back)), sha256Hex(text));
  }
});

test('tape vectors: entryHash and collator sig payload hash match spec', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-vectors-'));
  const base = vectors.tapeTest.entryNoSig;
  const t = new TapeStore({
    tapePath: path.join(dir, 'tape.log'),
    idxPath: path.join(dir, 'tape.idx'),
    idxStride: 10,
    replayBatch: 10,
    maxReplayEntries: 1000,
    collatorId: base.collatorId,
    collatorPrivKeyHex: '22'.repeat(32),
  });

  // The vector's order must itself satisfy the C1 envelope-hash derivation rule.
  assert.equal(computeEnvelopeHash(base.order), base.order.orderId);

  const entryHash = t.computeEntryHash({
    v: base.v,
    collatorId: base.collatorId,
    seq: base.seq,
    prevHash: base.prevHash,
    receivedTs: base.receivedTs,
    order: base.order,
  });
  assert.equal(entryHash, vectors.tapeTest.expectedEntryHash);

  const sigPayloadHash = sha256Hex(`${base.seq}|${base.prevHash}|${base.order.orderId}|${entryHash}`);
  assert.equal(sigPayloadHash, vectors.tapeTest.expectedSigPayloadHash);
});
