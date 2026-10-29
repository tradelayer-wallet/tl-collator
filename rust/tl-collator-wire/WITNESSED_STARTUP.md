# RUST-17F2: witnessed startup and remote-first signed CAS

The independent witness core in `rust/tl-witness-service` now implements the
`WitnessTransport` contract. A separate local tape writer is exposed as
`WitnessedTape<T>`, **not** as a raw `DurableTape` handle. This keeps all
witness-gated append paths behind an explicit signed remote acknowledgment.

## Startup under lock

1. Acquire the same permanent exclusive OS file lock as the original
   `DurableTape` writer.
2. Fetch the independently stored *latest* witness checkpoint using a new
   32-byte challenge read from the operating system CSPRNG.
3. Validate the signed receipt against a pinned independent witness key and
   scope (network, collator ID, stream, epoch); the witness key cannot equal the
   collator signing key.
4. Verify all complete local signed tape entries and require that the
   checkpoint at the witness sequence matches **exactly**.
5. Refuse startup on truncation (witness ahead), a signed fork at its sequence,
   a corrupt local anchor, a witness outage or a wrong scope. Also refuse a
   valid-looking local head *ahead* of the independently witnessed one.
6. Only after successful remote proof may a torn, unacknowledged trailing line
   be trimmed or a local checkpoint caught up. There is no local-only fallback.

The lock is held through all of these steps. The `open` call may create an
empty tape/lockfile but does not truncate or rewrite signed local tape content
until after the independent check.

## Remote-first append

1. Validate a candidate signed entry and its ownership/sequence locally,
   without changing the local index or tape.
2. Submit the entry and exact previous checkpoint to an independent,
   authenticated witness CAS operation. The witness verifies and durably writes
   the full signed entry to its own tape.
3. Require a **newly signed current-head receipt** matching a fresh challenge
   and the exact next checkpoint. Never trust unsigned CAS success messages.
4. Only then perform the local durable append and local checkpoint fsync.
5. Any ambiguous remote result, invalid signature, or failure of the local
   durability step poisons the handle. Further writes require restart and
   independent history reconciliation, not silent rollback.

This chooses remote-first ordering. A witness advance followed by local disk
failure produces a witnessed head ahead of local history. The next startup
correctly refuses that state and requires audited signed-history restoration
from the independent witness. That restoration mechanism is NOT included
in this prototype. It is safer to fail closed than to roll back a remote
commit or accidentally acknowledge a local-only append.

## Trust and limits

The `WitnessTransport` trait describes an **authenticated** external
read/CAS transport but does not implement remote SSH, TLS, key custody, or
a durable remote quorum itself. Unit tests use a separately keyed
`WitnessService` stored under an independent temporary directory.
The one-shot witnessctl CLI is available for operator-provisioned SSH
forced-command hosting, but production SSH transport and provisioning are
still out of scope.

The existing local-only `DurableTape::open` remains available for explicit
offline/recovery use. Production operator code MUST use `WitnessedTape`
for its authorization path; merely linking the crate does not enforce this
against callers that intentionally choose local-only APIs.

Tests exercise legitimate start/restart, remote CAS and signed receipt checks,
privileged local rollback of both tape and anchor, alternative fully signed
local fork, network mismatch, remote unavailability, lost CAS acknowledgment,
witness ahead of local, local ahead of witness, and torn-tail recovery after
a matching witness proof. All tests use synthetic keys; no network service,
production keys, real funds or deployment are involved.

Next gates: build an authenticated remote adapter to the independently hosted
witnessctl service, implement signed history fetch for operator-authorized
recovery after ambiguous remote commit, attest external quorum/store backups,
and test the actual production filesystem and network partitions. The
TypeScript collator still uses its existing production implementation.
