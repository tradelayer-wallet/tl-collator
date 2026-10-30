# Process-crash durability drills

These synthetic drills kill live writer processes with SIGKILL at observed
commit boundaries and replay the on-disk state afterward. They add no runtime
fault switches to the witness executables and do not reboot a machine, alter
accounts/networking, install a service or touch live wallet data.

## Tape commit matrix

The `tl-collator-wire` unit-test build includes private barriers at the actual
append/checkpoint operations. The barriers and their environment variables
exist only under `cfg(all(test, unix))`. They print a pipe marker and park;
coordination performs no additional filesystem sync. The parent confirms the
child is still alive and holds the OS lock, inspects the exact tape/checkpoint
state, kills the child, checks SIGKILL status, then verifies restart and append.

Each case starts from an acknowledged, signed record at sequence 1 and attempts
sequence 2. The expected state after the observed process death is:

| Interrupted operation | Tape after restart | Checkpoint before restart | Recovery |
| --- | --- | --- | --- |
| Before tape write | sequence 1 | sequence 1 | Retry the missing entry explicitly |
| Partial tape write | sequence 1, torn suffix removed | sequence 1 | Verify preserved prefix, then retry |
| After tape fsync | sequence 2 | sequence 1 | Verify and anchor the complete unacknowledged entry |
| After checkpoint temp-file fsync | sequence 2 | sequence 1 | Verify and anchor; preserve orphaned temp evidence |
| After checkpoint rename | sequence 2 | sequence 2 | Verify exact checkpoint/history agreement |
| After directory fsync | sequence 2 | sequence 2 | Verify exact checkpoint/history agreement |
| Before returning acknowledgment | sequence 2 | sequence 2 | Reconcile the durable but unacknowledged result |

Every case confirms the acknowledged prefix is unchanged, verifies both signed
records where present, rejects the recovered duplicate order, appends sequence
3 and reopens again. A timeout or child exit before the named barrier fails
the drill. No returned error is substituted for the process kill.

## Independent witness-process interruption

`tests/process_crash.rs` uses a separate process running the actual
`WitnessService` and a separately pinned synthetic witness key. It kills that
process in two cases:

1. Durable CAS has completed, before receipt signing.
2. The receipt has been signed and verified inside the witness process, but no
   signed acknowledgment has been delivered to the client.

The client transport returns an ambiguous/unavailable result. The witnessed
writer must block further appends without changing its old local tape or
checkpoint. A restarted witness must report the committed sequence 2, and the
old sequence-1 client store must refuse startup against that fresh head.
An independently authorized export and fresh receipt validate the recovery
candidate. The test models explicit operator approval of a **new** destination,
imports there, passes witness-gated startup and appends sequence 3. Original
failed-store bytes remain unchanged. No automated repair command is introduced.

## Reproduction and portable host verification

Use Rust 1.90.0 and the committed lockfiles:

```sh
cd rust/tl-witness-service
cargo test --locked --offline --test process_crash --no-run --message-format=json > /tmp/witness-process-artifacts.jsonl
cargo test --locked --offline --manifest-path ../tl-collator-wire/Cargo.toml --lib --no-run --message-format=json > /tmp/wire-process-artifacts.jsonl
python3 scripts/run-process-crash-tests.py --wire-artifacts /tmp/wire-process-artifacts.jsonl --witness-artifacts /tmp/witness-process-artifacts.jsonl
```

The launcher also accepts `--wire-test <verified-unit-test-executable>` and
`--witness-test <verified-process-crash-executable>` for relocated, hash-checked
artifacts. Keep the service binaries beside the test executable's `deps/`
directory, as in a Cargo debug build. The launcher verifies that normal service
executables contain none of the test-only fault-control marker strings, checks
that the exact required test names exist (zero selected tests cannot pass),
and bounds each subprocess group. It needs no root privileges or listener.

CI runs the ordinary suites and the portable launcher. Helper entrypoints are
explicitly ignored in the ordinary suite and invoked only by their parent tests
with private fixture paths. Existing signature/chain/owner replay semantics,
Cargo dependencies and application wire formats are unchanged.

## Evidence limits and remaining gates

SIGKILL loses process memory but leaves the operating system and its page cache
running. In particular, a visible rename after process death does not establish
what a storage device would retain after power loss before directory fsync.
These tests therefore prove process-crash/restart behavior at the named
boundaries, not physical power-loss durability, filesystem/controller ordering,
honest remote administration or monotonic backup/quorum operation.

Actual storage power interruption, externally controlled backup/restore and
partition drills, independent signing-key custody and security review remain
required before production enablement. Preserve ambiguous-commit and orphaned
temp-file evidence; do not delete it or replace old stores as an incidental test.
