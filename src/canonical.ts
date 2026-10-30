import { sha256Hex } from './crypto.js';

// Keys rejected by the validation layer (schema.ts) wherever an OrderEnvelopeV1
// is accepted: assignment of `__proto__` on a plain object triggers the
// prototype setter, and `constructor`/`prototype` are the other classic
// pollution vectors. The serializer below does NOT interpret keys as accessors
// and serializes these as ordinary own keys (see spec/schemas/tl-canon-v1.md).
export const UNSAFE_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (!v || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

// TL-Canon v1 domain checks, shared by the serializer and the validation walker.
// Numbers must be safe integers; strings must be well-formed Unicode (no lone
// UTF-16 surrogates, which have no UTF-8 encoding).
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function scalarViolation(v: unknown): string | null {
  if (typeof v === 'number') return Number.isSafeInteger(v) ? null : 'number is not a safe integer';
  if (typeof v === 'string') return LONE_SURROGATE.test(v) ? 'string is not well-formed Unicode' : null;
  return null;
}

// Validation-layer bound on container nesting. Not a TL-Canon rule: it keeps
// validated input well inside the recursion depth of the serializer, so an
// accepted value can always be hashed and a hostile one is refused, never
// turned into a stack overflow.
export const MAX_NESTING_DEPTH = 64;

function violationAt(v: unknown, depth: number): string | null {
  const scalar = scalarViolation(v);
  if (scalar) return scalar;
  if (!Array.isArray(v) && !isPlainObject(v)) return null;
  if (depth >= MAX_NESTING_DEPTH) return `nesting deeper than ${MAX_NESTING_DEPTH} levels`;
  if (Array.isArray(v)) {
    for (const item of v) {
      const hit = violationAt(item, depth + 1);
      if (hit) return hit;
    }
    return null;
  }
  for (const k of Object.keys(v as object)) {
    if (UNSAFE_KEYS.has(k)) return `unsafe key not allowed: ${k}`;
    const keyProblem = scalarViolation(k);
    if (keyProblem) return `key ${keyProblem}`;
    // Data properties only, as in the serializer: accessors are never invoked.
    const desc = Object.getOwnPropertyDescriptor(v, k);
    if (!desc || !('value' in desc)) continue;
    const hit = violationAt(desc.value, depth + 1);
    if (hit) return hit;
  }
  return null;
}

/**
 * Validation walker: returns a reason for the first value or key that TL-Canon
 * v1 cannot represent (unsafe key, non-safe-integer number, lone surrogate,
 * nesting beyond MAX_NESTING_DEPTH), or null. Used by schema.ts and the manifest
 * loader to reject input before hashing or storing it.
 */
export function findCanonicalViolation(v: unknown): string | null {
  return violationAt(v, 0);
}

// JSON.parse keeps a number's value, not its text, and rounds: "9007199254740991.0000000000000001"
// parses to the integer 9007199254740991. So the number tokens are judged on their text before parsing,
// which needs no runtime support beyond JSON.parse. The pattern consumes whole strings first, so digits
// inside a string are never read as numbers.
const JSON_TOKEN = /"(?:[^"\\\u0000-\u001f]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;

/** The integer a JSON number token denotes, or null when its exact value is not an integer. */
function exactInteger(token: string): bigint | null {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
  if (!m) return null;
  const [, sign, whole, fraction = '', exponent = '0'] = m;
  let digits = (whole + fraction).replace(/^0+/, '');
  if (digits === '') return 0n;
  const shift = Number(exponent) - fraction.length;
  // Only safe integers are compared, and those have at most 16 digits: a longer value is not one of them.
  if (shift > 16) return null;
  if (shift >= 0) {
    digits += '0'.repeat(shift);
  } else {
    const cut = -shift;
    if (digits.length <= cut || /[1-9]/.test(digits.slice(-cut))) return null;
    digits = digits.slice(0, -cut);
  }
  return BigInt(sign + digits);
}

/** True when a number token's value is a safe integer that its text does not write as that integer. */
function hidesItsFraction(token: string): boolean {
  const value = Number(token);
  return Number.isSafeInteger(value) && exactInteger(token) !== BigInt(value);
}

/**
 * Parses JSON text as TL-Canon input. Returns null for text that is not JSON, or that holds a safe
 * integer not written as that integer (the value is 9007199254740991 but the text is a fraction).
 * Other numbers are left to findCanonicalViolation, which refuses any that is not a safe integer.
 */
export function parseCanonicalJson(text: string): unknown {
  // Parse first: JSON.parse is linear and refuses a text with an unterminated string, so the scan below
  // only ever sees complete strings and runs in linear time. Scanning first is quadratic on a hostile
  // text that opens a string and never closes it.
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  for (const [token] of text.matchAll(JSON_TOKEN)) {
    if (token[0] !== '"' && hidesItsFraction(token)) return null;
  }
  return value;
}

// TL-Canon v1 key order: ascending Unicode **code point** (shortest prefix
// first) — NOT `JSON.stringify` object order. JSON.stringify emits
// integer-like keys ("9", "10", ...) first in numeric order, which silently
// diverges from the spec and made non-JS clients derive different orderIds
// (`bad_order_id`). A plain `Array.prototype.sort()` (UTF-16 code-unit order)
// would also diverge for astral-plane keys, so we compare code points.
// Matches Python's `sorted(str)`.
function compareCodePoints(a: string, b: string): number {
  const ai = Array.from(a, (ch) => ch.codePointAt(0) as number);
  const bi = Array.from(b, (ch) => ch.codePointAt(0) as number);
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i++) {
    if (ai[i] !== bi[i]) return ai[i] - bi[i];
  }
  return ai.length - bi.length;
}

// Recursive TL-Canon v1 serialization. Returns `undefined` for values JSON
// omits (`undefined` / functions / symbols) so object keys carrying them are
// dropped (spec: "omit keys whose value is undefined").
function serializeCanonical(v: unknown): string | undefined {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'number' || t === 'string') {
    const problem = scalarViolation(v);
    if (problem) throw new TypeError(`TL-Canon: ${problem}`);
    return JSON.stringify(v);
  }
  if (t === 'boolean') return JSON.stringify(v);
  if (t === 'undefined' || t === 'function' || t === 'symbol') return undefined;
  if (Array.isArray(v)) return `[${Array.from(v, (item) => serializeCanonical(item) ?? 'null').join(',')}]`;
  if (isPlainObject(v)) {
    // Own enumerable keys only, in code-point order; values are read from
    // property descriptors so accessor properties are never invoked and a key
    // like `__proto__` is serialized as an ordinary own key.
    const parts: string[] = [];
    for (const k of Object.keys(v).sort(compareCodePoints)) {
      const problem = scalarViolation(k);
      if (problem) throw new TypeError(`TL-Canon: key ${problem}`);
      const desc = Object.getOwnPropertyDescriptor(v, k);
      if (!desc || !('value' in desc)) continue;
      const s = serializeCanonical(desc.value);
      if (s === undefined) continue;
      parts.push(`${JSON.stringify(k)}:${s}`);
    }
    return `{${parts.join(',')}}`;
  }
  return JSON.stringify(v);
}

export function stableStringify(v: unknown): string {
  return serializeCanonical(v) ?? 'null';
}

/**
 * Signed envelope fields (TL-Canon v1, see spec/schemas/tl-canon-v1.md):
 * every own field of the OrderEnvelopeV1 except `orderId` (the digest being
 * derived) and `sigTrader` (the signature over that digest). For a well-formed
 * envelope that is `v`, `kind`, `body`, `traderPubKey`, `clientNonce`, plus
 * `cancelsOrderId` / `replacesOrderId` when present.
 */
export function envelopeSignedFields(envelope: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null);
  if (!envelope || typeof envelope !== 'object') return out;
  for (const k of Object.keys(envelope as Record<string, unknown>)) {
    if (k === 'orderId' || k === 'sigTrader') continue;
    Object.defineProperty(out, k, {
      value: (envelope as Record<string, unknown>)[k],
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * Envelope hash (TL-Canon v1):
 *
 *   orderId = sha256(stableStringify(envelope minus {orderId, sigTrader}))
 *
 * `sigTrader` is a compact 64-byte secp256k1 signature over the 32 raw bytes of
 * `orderId`. Deriving the digest over the *whole* envelope (not just `body`)
 * binds `kind`, `cancelsOrderId` and `replacesOrderId` into the trader
 * signature, so a harvested `(orderId, sigTrader, traderPubKey, body)` from the
 * tape can never be re-submitted as a forged CANCEL/REPLACE. The digest is
 * lowercase hex. Throws if the envelope holds a value TL-Canon cannot
 * represent; callers validate with `findCanonicalViolation` first.
 *
 * NOTE (BREAKING): this supersedes the batch-1 body-only derivation
 * `sha256(stableStringify(body) + traderPubKey + clientNonce)`. Clients must
 * adopt this convention (identical to scripts/smoke-live-flow.cjs buildOrder).
 *
 * NOTE (BREAKING): object keys are emitted in Unicode code-point
 * order. Envelopes whose signed fields contain integer-like keys ("9", "10")
 * or astral-plane keys hash differently than under the batch-1 serializer.
 */
export function computeEnvelopeHash(envelope: unknown): string {
  return sha256Hex(stableStringify(envelopeSignedFields(envelope)));
}

/**
 * Order ID derivation: `orderId` is exactly the envelope hash. Kept under the
 * historical name so client code reads naturally; the argument is now the
 * envelope (any object exposing the signed fields), not `(body, pubKey, nonce)`.
 */
export function computeOrderId(envelope: unknown): string {
  return computeEnvelopeHash(envelope);
}
