# RUST-17C: single-writer durable verified tape

Status: **offline application-state component**, not a live collator replacement.
This draft stacks on RUST-17B, the pinned signed-replay verifier, and RUST-17,
the TL-Canon v1 hashing reference. It does not modify the TypeScript server.

## Ownership and trust

- The operator supplies an existing, access-controlled local directory, a
  sanitized tape stem, collator ID, pinned collator ECDSA public key and maximum
  entry count. No signing private key, HTTP service or node RPC is exposed.
- This implementation targets **local POSIX filesystems**. On other platforms
  the directory sync path returns UnsupportedFilesystem. Do not deploy the
  current version on NFS, SMB, a writable shared volume, or an untrusted
  directory. File locks may be advisory; all writers must obey them.
- The permanent `.lock` file is opened with the Rust 1.90 standard library
  native OS lock (`File::try_lock`, stable since 1.89). It is deliberately
  **never deleted**: removing/recreating the lock inode would permit two
  processes to hold locks on different files. A process exit/crash releases
  the OS lock without human stale-PID override.
- Existing tape/anchor/lock paths reject symlinks and non-regular files. The
  containing directory must be permission-restricted and immune to path
  replacement by other users. Checks alone cannot defeat a privileged race.

## Durable append protocol

1. Acquire the exclusive lock before inspecting or creating the tape.
2. Verify all complete NDJSON lines, *including signatures*, hashes, sequence,
   previous hash, order ownership and duplicate IDs. Compare the stored
   checkpoint anchor to the corresponding verified historical prefix.
3. On startup, an incomplete final line can be truncated **only after** all
   complete entries and the last anchored prefix validate. Its removal is
   synced to disk. Complete invalid lines fail startup with no repair.
4. Append a fully signed, already validated NDJSON entry to the tape under
   the same lock. Only validated input from the TL-Canon ECDSA verifier is
   eligible to mutate disk or memory.
5. `sync_all` the tape, write a checkpoint into a unique new temporary file,
   `sync_all` the temp, atomically rename over the checkpoint and sync the
   parent directory. Only then acknowledge the entry and swap the candidate
   verified in-memory state into the writer.
6. A write/sync failure before tape commit attempts a synced truncate back
   to the old size. If rollback fails, the writer refuses further appends.
   If anchor persistence fails *after* tape sync, the writer reports an
   **unknown commit outcome**, refuses further writes and must restart.
   This avoids an unsafe rollback past a possibly published anchor.
7. Restart scans the whole signed tape. A complete, verified entry which
   survived after a crash but ahead of the anchor is synced and anchored.
   Duplicate replay remains rejected. The checkpoint/tape pair must not
   lose any anchored sequence or alter its anchored hash.

An empty tape without an anchor is initialized with sequence zero. Nonempty
unanchored history requires the explicit `ExplicitVerifiedImport` option:
every record is verified under the pinned key before an initial anchor is
created. The default `RequireAnchor` mode refuses implicit migration.

## On-disk files

All paths sit in the operator-supplied directory:

- `<stem>.ndjson`: newline-terminated signed tape records
- `<stem>.lock`: persistent OS lock inode, never deleted by writer
- `<stem>.checkpoint`: version/sequence/entryHash/unique-order-count anchor
- `.<stem>.checkpoint.tmp.<pid>.<counter>`: temporary checkpoint written
  before atomic rename. An orphan temp after a crash is ignored.

An anchor file is an **integrity check within the local directory**, not
tamper-proof anti-rollback: a privileged attacker who can replace both tape
and checkpoint with a previously signed prefix may still roll back history.
Production deployment requires an independently stored or signed monotonic
checkpoint (or a remote observer) and guarded backups. File-level durability
also depends on actual hardware/fsync honesty and filesystem guarantees.

## Tests and fault boundaries

The Rust unit suite includes synthetic-key signed-order generation,
commit/restart, lock contention, kill-9-style child process termination,
partial write rollback, crash immediately after tape sync, crash after
checkpoint rename, recovery of a complete unanchored signed entry, torn-tail
repair, valid-history truncation rejection, corrupt complete lines and anchors,
unauthorized cancel after restart, duplicate replay, and size/path limits.

Commands (Rust 1.90):

    cd rust/tl-collator-wire
    cargo test --locked --offline
    cargo clippy --locked --offline --all-targets -- -D warnings
    cargo fmt --all -- --check
    node scripts/verify-fixture.cjs

This adds a **verified local writer**, not a collator service. Remaining gates
include actual order admission and signing-agent integration, replay indexing,
network authorization and session identity, bounded streaming responses,
cross-process/machine fault injection on the intended production filesystem,
an externally authenticated rollback anchor, signed release artefacts, and
review of the final accepted TypeScript wire contract. No live funds or keys.
