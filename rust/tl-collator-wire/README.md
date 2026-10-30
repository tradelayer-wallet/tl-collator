# TL-Canon v1 Rust reference (RUST-17)

This additive application crate implements canonical hashing for order intent
and tape entries. It does not use or move private keys, sign envelopes,
authorize network clients, execute trades or alter the TradeLayer protocol core.

Reference: tradelayer-wallet/tl-collator PR #2, external hardening branch head
cbc4f33a93da72e34eea3493e0ac62ca7ca65248, pinned on 2026-10-29.
The original spec/test-vectors.json is preserved in fixtures/upstream-pr2-vectors.json.
The curated fixture drops two unpaired-surrogate JSON values because Rust
serde_json rejects invalid UTF-16 escape pairs during parsing. Their rejection
is tested directly with raw JSON text. scripts/verify-fixture.cjs compares
the curated objects against the original pinned reference.

Supported rules:

* Objects use ascending Unicode code-point order, including integer-like and
  astral-plane keys. Valid UTF-8 byte order equals code-point order.
* Arrays retain order; scalar strings use compact JSON escaping. Numbers must
  be integers within JavaScript's exact 53-bit range, written canonically.
* Explicit text scanning refuses fractional literals rounded by a floating
  parser to safe integers. Duplicate object keys fail closed.
* Signed orderId hashes every envelope field except orderId and sigTrader,
  including kind and cancel/replace target. Unsafe keys are rejected throughout
  signed envelopes, matching the validation-layer policy.
* Tape entry and signature-payload hashes follow the pinned PR #2 vectors.
  Canonicalization and unsafe-key policy are distinct interfaces.
* Validation caps nesting to 64 containers and raw input to one MiB. These
  are implementation limits, not claimed equivalence for arbitrary JS input.

Current test vectors cover NEW/CANCEL, integer-like keys, astral Unicode,
tape hashes and tamper-sensitive fields, plus malformed inputs and decimal
precision traps. The Rust tests do not verify secp256k1 signatures or the
collator's actual live WebRTC/session authorization and replay persistence.

Commands after committing Cargo.lock:

    cd rust/tl-collator-wire
    cargo test --locked --offline
    node scripts/verify-fixture.cjs
    cargo clippy --locked --offline --all-targets -- -D warnings
    cargo fmt --all -- --check

The core consensus crate at patrickdugan/TradeLayer-Rust owns all ledger,
margin, replay and consensus logic. This crate is only an application message
and hash reference. PR #2 is independently reviewed, and this Rust branch
must be rechecked against the accepted final TS wire spec before integration.

## Lean verification

`lean/` (Lean 4 v4.34.1, core only, no Mathlib) models the chain rules of
`VerifiedReplay::prepare_entry`/`commit_prepared` (`src/verify.rs`), the receipt
comparison in `WitnessScope::verify_tape` (`src/witness.rs`) and
`compare_and_swap` in `rust/tl-witness-service/src/lib.rs`. Hashes, ids and owners
are `Nat`; signatures and schema checks are one boolean; the canonical entry hash
is taken from the entry. Durability, file locks and transport are not modelled.

| Theorem | Statement |
|---|---|
| `apply_spec` | an accepted entry has `seq = last+1`, `prevHash = last hash`, a fresh id, room under capacity and valid signatures |
| `apply_counts`, `replay_counts` | `seen_orders == last_seq` is invariant; replaying n entries advances the sequence by n |
| `apply_capacity` | the owner index never exceeds `max_entries` |
| `apply_fresh_id` | order ids are never reused |
| `apply_cancel_owner` | CANCEL/REPLACE are accepted only from the target's owner |
| `replay_linked` | every accepted entry names its predecessor's hash |
| `judge_ok`, `judge_fork`, `checkpoints_seq_bound`, `truncated_is_rollback` | a receipt is accepted only if its head is on the replayed history; a different head at that sequence is a fork; a truncated tape is a rollback |
| `cas_spec`, `cas_race`, `cas_monotone` | CAS appends only from the expected checkpoint, two writers from the same checkpoint cannot both succeed, the witnessed sequence only grows |

    cd lean && lake build && lake env lean AxiomCheck.lean

The `lean` job in `.github/workflows/rust-canon.yml` repeats this (not yet run).
