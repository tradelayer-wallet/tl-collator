# Verified replay contract (RUST-17B)

This branch stacks on the offline Rust TL-Canon v1 reference in PR #3.
The TypeScript security PR #2 is an independent protocol source, pinned
for compatibility to commit cbc4f33a93da72e34eea3493e0ac62ca7ca65248.

The Rust module src/verify.rs checks 64-byte compact secp256k1 ECDSA
signatures. Trader signatures authenticate the SHA-256 of all canonical
envelope fields except orderId/sigTrader, including cancel/replace targets.
A separate *configured, pinned* collator public key authenticates the
SHA-256 of seq|prevHash|orderId|entryHash. Each entry is rehashed against
the exact TL-Canon v1 tape material, with a continuous sequence and
previous-entry hash. Order IDs and collator/tape hashes use lowercase hex.

The in-memory VerifiedReplay owner table supports duplicate refusal
and historical ownership checks on cancellation and replacement.
These match the bounded subset of the existing TapeStore index.
The verifier refuses malformed, double-key and ambiguous number tokens
before verifying signatures, and keeps its state unchanged on rejection.

VerifiedReplay::from_ndjson checks a bounded NDJSON stream and returns a
complete verified state only after the whole file passes. A torn final line,
damaged interior, broken link, replayed order, incorrect signature or wrong
collator identity fails the load. No disk writer or repair path is provided.
This models a restart verification gate, rather than implementing durable
append, fsync, rollback, or multi-process locking.

Tests use deterministic **synthetic** secp256k1 keys for fixture signing.
The production module has verification only. Real keys, network activity,
trade execution and deployed service changes are outside scope.

The next boundary is a durable single-writer append mechanism with
crash fault-injection, a verified startup index and authenticated RPC
provider selection. This draft is a component-level result, not proof of
end-to-end order privacy, execution, settlement, or full schema parity.
