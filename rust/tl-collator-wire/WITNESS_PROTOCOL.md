# Independent signed witness v1 (RUST-17E)

This additive Rust module defines and verifies an independent, signed checkpoint
receipt and compares it to a fully reverified historical tape prefix.

It does not create, query, store or operate an external witness service.
It is not a complete anti-rollback system unless the independently operated
witness implements a trusted durable, monotonic compare-and-swap counter.

## Signed receipt wire format

The receipt is a JSON object with exactly these fields:

{
  "domain": "TradeLayer/collator/checkpoint/v1",
  "v": 1,
  "network": "LTCTEST",
  "collatorId": "collator-1",
  "stream": "orders",
  "epoch": 3,
  "seq": 2,
  "headHash": "<64 lowercase hex characters>",
  "seenOrders": 2,
  "challenge": "<64 lowercase hex characters>",
  "sigWitness": "<128 hex characters>"
}

The witness signs the 32 raw bytes of
SHA256(TL-Canon-v1(receipt with sigWitness removed))
using a 64-byte compact ECDSA secp256k1 signature. This is not a Bitcoin
message-prefix signature and not a signature made by the collator key.

The verifier pins the independent witness public key, collator ID, network,
stream and epoch from operator configuration. None is trusted from the receipt
alone. The verifier rejects unknown or missing fields, duplicate JSON keys,
unsafe precision conversions, a mismatched challenge, invalid signatures, a
malformed/noncanonical head hash and a witness signing key identical to the
configured collator signing key.

The caller MUST generate a cryptographically unpredictable, fresh, nonzero
32-byte challenge from its OS CSPRNG for each independent witness query. The
witness MUST sign the current committed head and that challenge, never a head
supplied by the collator caller. The outside service must enforce atomic
compare-and-swap advancement and durable monotonic state across restarts.

This crate neither generates the challenge nor attests its freshness. It only
checks that the signed challenge matches the one supplied by the caller. A
reused challenge combined with a stale signed receipt can fail to detect a
rollback; tests deliberately demonstrate that limitation.

## Tape comparison

WitnessScope::verify_tape recomputes signatures and hashes for every local
signed NDJSON entry, then requires an exact match at the externally witnessed
sequence. If the tape is shorter, the verifier reports Rollback. If the tape
contains an alternate fully signed branch at that sequence, it reports Fork.
If a signature, canonical entry or tape link is invalid, verification fails.

It intentionally does not modify the disk checkpoint, truncate a torn tail,
repair any file, or open the live writer. Integrating an independent witness
into writer startup requires an API that holds its OS lock, prevents races
between verification and mutation, and follows external CAS acknowledgment
semantics. That integration must be reviewed and tested separately.

Unit tests use deterministic synthetic independent keys and a fake witness
reply. A stale response with a repeated challenge is explicitly demonstrated
to be insufficient for freshness.

## Remaining security gates

- Independently hosted, authenticated monotonic witness with separate key
  custody, replay-resistant fresh challenge transport, and atomic CAS.
- A signed external witness head fetched while the tape's single-writer
  lock is held, before any local recovery or mutation.
- Error semantics for ambiguous remote acknowledgment and unavailable witness:
  fail closed for spends/settlement; never silently fall back to local-only.
- Cross-node identity binding, epoch/key rotation with overlap rules, and
  unambiguous operator recovery after a witness outage.
- Review of source versions, real filesystems, and regtest-only canaries.

This work does not move funds, sign real orders, deploy servers or enable a
production spending path.
