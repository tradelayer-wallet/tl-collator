# TradeLayer independent checkpoint witness (RUST-17F prototype)

The witness is a **separate Rust package**, deliberately not linked into the
live TypeScript collator server. Its persistence is a verified append-only copy
of signed collator entries using the already audited Rust DurableTape primitive.
It has a separate ECDSA private key, pinned collator public key, collator ID,
network, stream and epoch. Its signer **never signs caller-specified heads**:
it signs only the fully persisted current state under a fresh 32-byte challenge.

## Security contract

- compare_and_swap checks the expected exact previous (sequence, hash, owner
  count) against the local independently stored state under one OS writer lock.
  It persists only a complete next signed tape entry verified against the
  pinned collator key and the trader signature. No arbitrary hash updates.
- attest_latest signs TL-Canon-v1({domain,v,network,collatorId,stream,epoch,
  seq,headHash,seenOrders,challenge}) with a 64-byte compact secp256k1 ECDSA
  signature. The request controls **only the challenge**, not the signed head.
- The public key must be pinned independently by the client. The witness key
  may not equal the collator key. No private signing key is logged or exposed
  in a response, and the signing key must be provisioned by the independent
  operator, not the collator.
- A second process opening the same store fails to acquire the OS file lock.
  Restart replays and verifies all signed records. A complete valid entry
  ahead of the local checkpoint is re-anchored; corrupt or missing committed
  history refuses startup.

The package is **not an Internet-facing daemon**: no unauthenticated HTTP,
TLS proxy or SSH command handler is implemented yet. A distinct host/operator,
separate key custody, authenticated request transport, anti-rollback backup
or quorum, admission limits and a monotonic secure store are still required.
The service's local checkpoint can itself be rolled back by an attacker with
privileged access to its own disk; do not treat one co-located instance as
independent anti-rollback.

The collator must fetch a fresh independently signed latest head and verify its
history **under the existing collator tape lock and before any local repair**.
That integration is a separate gate. In production, an unreachable witness
must block writes; no local-only fallback. The collator and witness services
must not share file paths, filesystem snapshots, signing keys or administrators.

## Verification

With Rust 1.90 and the pinned Cargo.lock:

    cd rust/tl-witness-service
    cargo test --locked --offline
    cargo clippy --locked --offline --all-targets -- -D warnings
    cargo fmt --all -- --check

Synthetic-key tests prove authenticated receipt signatures, exact CAS,
duplicate/branch denial, restart state, lock contention, and schema scope.
They do **not** prove remote durability, network authorization or safe power-loss
behavior on a specific physical filesystem.
