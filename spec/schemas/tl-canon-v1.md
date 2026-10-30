# TL-Canon v1

Deterministic canonical JSON used for hashing/signing.

Rules:
- Objects: serialize the own enumerable string keys sorted by ascending
  **Unicode code point** (shortest prefix first; equivalently Python's
  `sorted(str)`). Keys are compared by code point, NOT by UTF-16 code unit
  (`Array.prototype.sort()` on JS strings) and NOT by `JSON.stringify` order.
  `JSON.stringify` emits integer-like keys (`"9"`, `"10"`, ...) first, in numeric
  order, so implementations MUST write the key order themselves (e.g. sort the
  keys with a code-point comparator and join `"<escaped key>":<value>` pairs).
  Vectors: `integerKeyTest`, `orderIntegerKeyTest` (integer-like keys) and
  `unicodeKeyOrderTest` (astral vs U+E000..U+FFFF keys).
  ⚠️ **BREAKING (key order):** envelopes whose signed fields contain integer-like
  or astral-plane keys derive a different `orderId` than under the earlier
  `JSON.stringify` / UTF-16 ordering; such envelopes are rejected with `bad_order_id`
  unless the client re-derives the id under this rule.
- No whitespace: canonical JSON has no spaces or newlines.
- Arrays: preserve order. Array holes and `undefined` elements serialize as `null`.
- Numbers: **safe integers only** (`-(2^53-1)` to `2^53-1`), decimal form. A
  number is judged by its value, so `1.0` is `1` (vector `integralNumberTest`).
  Any other number (fraction, NaN, Infinity, out of range) has no TL-Canon form
  and MUST be rejected, never serialized. Monetary values must be strings.
  The value is the one the number's text denotes, not the double a parser makes of it: a
  safe integer written with a non-zero fraction (`9007199254740991.0000000000000001`)
  MUST be rejected, since a parser that rounds it would accept a value the text does not state.
- Omit keys whose value is `undefined`, a function or a symbol.
- Accessor properties are never invoked; only data properties are serialized.
- Strings: must be well-formed Unicode. A lone UTF-16 surrogate has no UTF-8
  encoding and MUST be rejected (values and keys alike). Escaping is standard
  JSON: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00xx` (lowercase hex)
  for other code points below U+0020. Every other character, including U+007F
  and U+2028/U+2029, is emitted literally as UTF-8.
- Hex strings should be lowercase unless specified otherwise.
- Keys are always plain own property names. Canonicalization never interprets a
  key as an accessor or touches a prototype: `__proto__` is serialized as an
  ordinary key (e.g. `{"__proto__":{}}` canonicalizes with that key present).
- Independent executable form of this spec: `scripts/tl-canon-ref.py` (Python;
  shares no code with the TypeScript implementation). It and the TypeScript
  implementation both verify every entry of `spec/test-vectors.json`, including
  the `rejectTests` that must fail to serialize.
- Validation layer (not part of canonicalization): the keys `__proto__`,
  `constructor` and `prototype` are **rejected** wherever an `OrderEnvelopeV1`
  is accepted.

## Order ID derivation (OrderEnvelopeV1)

`orderId` MUST be derived from the canonical envelope — every own field of the
`OrderEnvelopeV1` except `orderId` (the digest being derived) and `sigTrader`
(the signature over that digest):

```
orderId = sha256(stableStringify(envelope minus {orderId, sigTrader}))
```

- For a well-formed envelope the signed fields are `v`, `kind`, `body`,
  `traderPubKey`, `clientNonce`, plus `cancelsOrderId` / `replacesOrderId`
  when present. All of them are bound into the digest, so `kind`, `cancelsOrderId`
  and `replacesOrderId` are covered by `sigTrader` just like `body` is.
- The digest is lowercase hex (32 bytes / 64 chars).
- `sigTrader` is a compact 64-byte secp256k1 signature over the 32 raw bytes
  of `orderId`.

The collator rejects any `SUBMIT` whose `orderId` does not exactly match this
derivation (`ERR` code `bad_order_id`). This binds `sigTrader` to the complete
order intent: a harvested `(orderId, sigTrader, traderPubKey)` triple can never
be re-submitted with an attacker-chosen `body`, `kind`, `cancelsOrderId` or
`replacesOrderId` — in particular a tape-harvested `NEW` order cannot be
replayed as a forged `CANCEL`/`REPLACE` of somebody else's order. Worked
examples: `spec/test-vectors.json` → `orderTest` and `orderCancelTest`.

⚠️ **BREAKING (supersedes the earlier body-only rule):** the previous draft of
this document derived `orderId` as
`sha256(stableStringify(body) + traderPubKey + clientNonce)`, which left `kind`
and the cancel/replace target ids outside the signature. Clients must adopt the
envelope-hash derivation above (identical to `scripts/smoke-live-flow.cjs`
`buildOrder`); envelopes computed the old way are rejected with `bad_order_id`.
