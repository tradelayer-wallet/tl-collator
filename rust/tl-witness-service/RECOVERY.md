# Operator recovery export v1

This additive, offline component provides `recovery::export_history`, the
separate `witness-export` executable, and `recovery::verify_full_recovery`.
It does not install a service, restore files, or alter the TypeScript runtime.
Independent security review and a genuine independent-host recovery drill are
required before enabling it operationally.

Source baseline: collator master `a1842473124453cbbd2d697c067129342deb00ab`.
Contracts come from `../tl-collator-wire/src/verify.rs`, `src/durable.rs` and
`src/witness.rs`, plus this package's existing scope/CAS implementation. Existing
TypeScript consumers do not call this additive module or executable.

| Contract | Result |
| --- | --- |
| latest/CAS wire commands and signed tape entries | Preserved |
| Witness receipt and signature domains | Preserved |
| Recovery request/manifest | New explicitly versioned domains |
| Normal startup repairs versus recovery export | Export refuses all repair and preserves evidence |
| CRLF accepted by ordinary replay | Export intentionally accepts only exact LF records |
| Production routing, signing and consensus | Unchanged |

## Authorization and confidentiality

`witnessctl` still accepts only `latest` and `cas`. Recovery is a separate
capability, with a separate SSH identity/forced command **and** a compact
secp256k1 operator signature. The recovery operator public key is pinned in a
host-controlled policy file. It must differ from both collator and witness
signing identities. The operator private key never goes to the witness host.
This application authorization key is distinct from the SSH authentication key.

Signing authenticates bytes; it does not encrypt historic orders. Use pinned
SSH host keys and protected output storage. Neither the manifest nor ordinary
`latest` authentication grants permission to disclose history. A previously
authorized signed request may be replayed while its exact checkpoint remains
current: this protocol provides challenge-bound response freshness, not a
persistent one-use authorization ledger. The separate SSH authorization and
access policy must still apply to every invocation.

Provision the exporter behind a separate root-controlled launcher and SSH key
using `restrict,command="/operator-controlled/export-launcher"`. The launcher
must ignore `SSH_ORIGINAL_COMMAND`, clear the inherited environment, use a
private umask, and set every configuration path/value from operator policy.
Do not accept `AcceptEnv`/`PermitUserEnvironment` values for `TL_WITNESS_*`,
client-selected paths, shell commands or extra exporter arguments. The
latest/CAS principal must have no shell, forwarding, exporter-policy write
access, or ability to invoke the exporter launcher. Access audits must omit
request bodies, signing keys and signed historical orders. Supervise request
concurrency and apply service memory/CPU/process limits.

The CLI requires a real 0700 data directory, regular private key and export
policy files with no group/other permissions and ownership matching the store.
The policy's confidentiality does not replace a root-controlled launcher or
OS separation. Host administrators can change files and policy; this protocol
does not make a compromised witness administrator trustworthy.

## Exact request contract

Send one UTF-8 JSON object on stdin, then EOF. No command arguments are accepted.
Unknown or duplicate fields fail. Metadata is limited to 8192 bytes. The exact
fields, before adding the operator signature, are:

```json
{
  "domain": "TradeLayer/collator/recovery-request/v1",
  "v": 1,
  "collatorId": "operator-pinned-id",
  "network": "operator-pinned-network",
  "stream": "orders",
  "epoch": 3,
  "operatorId": "recovery-operator",
  "startSeq": 1,
  "count": 3,
  "checkpointSeq": 3,
  "checkpointHash": "<current committed 64-character lowercase hash>",
  "seenOrders": 3,
  "challenge": "<fresh nonzero 32-byte CSPRNG challenge, lowercase hex>"
}
```

Compute SHA-256 of TL-Canon v1 of that object, sign the digest using compact
64-byte secp256k1 ECDSA, and add its hex encoding as `sigOperator`. The signature
binds the exact range, expected committed checkpoint, scope and challenge.
Obtain the expected checkpoint through independently authenticated `latest`
first. The exporter refuses stale expected checkpoints; it never lets the
caller choose the checkpoint to attest. If CAS advanced meanwhile, obtain a
fresh receipt and explicitly authorize a new request.

The trusted launcher sets the existing `TL_WITNESS_DATA_DIR`,
`TL_WITNESS_KEY_FILE`, `TL_WITNESS_COLLATOR_ID`, `TL_WITNESS_COLLATOR_PUBKEY`,
`TL_WITNESS_NETWORK`, `TL_WITNESS_STREAM`, `TL_WITNESS_EPOCH` and
`TL_WITNESS_MAX_ENTRIES`, plus `TL_WITNESS_EXPORT_POLICY` pointing to a restricted
JSON file with exactly:

```json
{
  "operatorId": "recovery-operator",
  "operatorPubKey": "<independently provisioned compressed secp256k1 public key>",
  "maxRecords": 1000,
  "maxRecordBytes": 1048576,
  "maxExportBytes": 16777216,
  "maxScanBytes": 268435456,
  "timeoutMillis": 10000
}
```

Hard ceilings are 10,000 exported records, 1 MiB per record (excluding LF),
64 MiB total response (including manifest and LF), 1 GiB scanned tape and
60 seconds. The configured caps can be smaller. Existing replay capacity
remains independently bounded by `Config.max_entries` (at most 1,000,000).
The library checks elapsed time between reads/signature validations. Blocking
filesystem calls need process-level containment: the one-shot CLI watchdog
also bounds blocked stdin, reads and stdout after loading trusted policy.
An external supervisor must cover startup and uninterruptible kernel I/O.

## Snapshot and response

The exporter opens the **existing** `witness.lock` inode read-only and takes
the same exclusive OS lock as CAS. Contention refuses immediately. While
holding it, it checks pinned `witness.scope`, the existing committed
`witness.checkpoint`, and every signed record from genesis to EOF, including
records outside the requested range. The fully verified final state must equal
the exact checkpoint. Oversized records, invalid signatures, broken chains,
missing spans, torn tails and valid-but-unanchored suffixes all refuse.

No recovery-opening primitive is used: no files are created, truncated,
re-anchored or repaired. All output stays buffered until verification succeeds.
Paths must remain under the independent operator's control on a local POSIX
filesystem; concurrent privileged replacement and mutable ancestor symlinks
are outside the supported threat model. Final-component symlinks are refused.

Successful stdout is a signed JSON manifest, LF, then the exact selected signed
NDJSON records with LF terminators. The manifest domain is
`TradeLayer/collator/recovery-manifest/v1`. Its exact fields are:

`domain`, `v`, `collatorId`, `collatorPubKey`, `witnessPubKey`, `network`,
`stream`, `epoch`, `operatorId`, `startSeq`, `count`, `prevHash`, `finalHash`,
`checkpointSeq`, `checkpointHash`, `seenOrders`, `challenge`, `bytes`, `digest`,
`sigWitness`.

`prevHash` is the verified hash immediately before the selected range;
`finalHash` is its last entry hash. Checkpoint fields identify the full committed
snapshot, even for an interior range. `bytes` and `digest` describe the exact
NDJSON bytes including every LF. `digest` is SHA-256. `sigWitness` is compact
ECDSA over SHA-256 of TL-Canon of all manifest fields except `sigWitness`.

A process kill, closed pipe or timeout can truncate the transport. Successful
exit, a manifest alone, or the presence of some complete records is insufficient:
the complete byte count, digest, range, signatures and fresh receipt must all
verify. Failed commands return no authoritative partial bundle. Keep failed
transport captures as evidence, never append them to a tape.

## Explicit offline restoration procedure

1. Stop the affected collator writer under operator supervision. Preserve its
   old tape, checkpoint, ambiguous acknowledgment evidence and failure report
   as restricted, immutable copies. Do not open the damaged evidence with a
   repair-capable tape constructor.
2. Independently authenticate witness identity/scope. Obtain the latest head,
   authorize the exact full range with a new random challenge, and export to a
   new restricted artifact. Do not overwrite evidence or existing tape paths.
3. After export, query independent `latest` again using a **different new random
   challenge**. Record `Instant::now()` before starting that query and pass the
   raw reply, challenge and request start to `FreshReceipt`. The challenge and
   time are caller-controlled trusted inputs, not values read from a manifest
   or supplied by the remote party. `max_age` must be <=30 seconds and cover the
   entire query plus verification. Wall-clock timestamps or file modification
   dates do not establish freshness.
4. Call `verify_full_recovery` with independently pinned configuration, witness
   key, expected operator ID and the original export challenge. It checks the
   manifest, exact bytes and full trader/collator signature replay, then requires
   equality with the fresh independent receipt. A newer remote head requires a
   newly authorized export; stale, divergent or incomplete history refuses.
   The verifier writes nothing. Partial exports are diagnostic artifacts; this
   version accepts only a single complete genesis-to-checkpoint bundle within
   its caps as a restore candidate. Multi-bundle assembly and histories beyond
   those caps require a separately reviewed extension.
5. Obtain explicit human authorization for the verified checkpoint and a **new**
   destination directory. Only then may an offline operator tool import the
   verified NDJSON through `DurableTape`'s existing `ExplicitVerifiedImport`.
   This change supplies no automated importer, replacement or repair command.
6. Reopen the restored store through witness-gated startup using another fresh
   receipt, compare state, and retain the old evidence. Runtime enablement and
   production cutover require their own review and authorization.

## Verification and remaining operational gates

With the pinned Rust 1.90.0 toolchain:

```sh
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --all -- --check
```

Synthetic fixtures are generated by `tests/recovery.rs` from deterministic
non-production seeds 1 (trader), 3 (collator), 5 (witness), and 7 (operator),
using the established signed-order and tape contracts. Tests cover operator
denial, tampering, complete and interior ranges, scope/key changes, all resource
bounds, corrupt interior, torn/missing/unanchored history, stale checkpoint,
lock contention/CAS serialization, request schemas, symlinks, CLI policy,
watchdog, SIGKILL observed during the locked snapshot, full replay and fresh
receipt refusal. SSH tests cover inherited stdout/stdin descriptors and process
group cleanup. CI checks committed formatting before tests without rewriting
sources or dumping source encodings.

The lost-acknowledgment recovery drill commits remotely, loses the reply,
confirms the old local store refuses startup, exports and independently verifies
the missing signed history, models explicit approval into a new directory,
performs the existing offline import, and resumes a witnessed append. It checks
that the failed tape and checkpoint bytes remain unchanged. This models an
operator ceremony with synthetic data; it does not certify a human approval
workflow or physical durability.

These local tests do not establish independent administrator/key custody,
real forced-command separation, physical power-loss persistence, secure
anti-rollback backups, network partitions, or a safe production restore.
Those remain independent-host and human-review gates. New code uses the
existing pinned cryptography/JSON dependencies; Cargo manifests/lockfiles and
consensus behavior are unchanged.
