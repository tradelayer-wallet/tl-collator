# SSH forced-command boundary

`witness-ssh-gate` is a server-side, one-shot authorized-keys command. It adds
no listener or public RPC and does not install itself. Keep the gate, policy,
binary paths and all their parent directories under independent administrator
control. The witness account must not be able to replace them. Review this
boundary and complete isolated-host drills before enabling operational access.

Use separate SSH identities for the two fixed capabilities:

```text
restrict,command="/opt/witness/witness-ssh-gate witness /etc/witness/gate.json" <witness SSH public key>
restrict,command="/opt/witness/witness-ssh-gate recovery /etc/witness/gate.json" <operator SSH public key>
```

The ordinary witness identity can request `witnessctl latest <challenge>` and
`witnessctl cas <seq> <hash> <orders> <challenge>`. The recovery identity can
request only `witness-export`; its stdin must also contain the operator-signed
export request defined in [RECOVERY.md](RECOVERY.md). SSH keys, recovery-request
authorization keys and witness signing keys are separate capabilities.

The gate parses `SSH_ORIGINAL_COMMAND` against a bounded ASCII grammar without
executing it. The genesis hash is represented by the exact token `''`. No shell,
subsystem, additional program, quoting expression, substitution, redirection
or separator is accepted. Challenges, safe integers, hash lengths, sequence and
owner counts are validated before invoking the service. Latest/CAS can never
select the exporter or invoke an operator command.

The administrator supplies the fixed role and policy arguments in
`authorized_keys`; they are not received from the client. The exact policy
schema is:

```json
{
  "witnessctl": "/opt/witness/witnessctl",
  "exporter": "/opt/witness/witness-export",
  "dataDir": "/var/lib/witness/orders",
  "keyFile": "/var/lib/witness/witness-secret",
  "exportPolicyFile": "/var/lib/witness/export-policy.json",
  "collatorId": "operator-pinned-id",
  "collatorPubKey": "<pinned collator public key>",
  "network": "operator-pinned-network",
  "stream": "orders",
  "epoch": 3,
  "maxEntries": 1000000,
  "timeoutMillis": 10000
}
```

The policy and selected binary must be absolute, regular, root-owned files
without group/other write permissions. Unknown/duplicate fields, invalid
scope/capacity, relative data/key/policy paths and timeouts outside 100–60,000 ms
refuse. Public gate policy may be readable by the service account; it contains
paths and public configuration, never private key bytes. The exporter applies
its additional private-file ownership/permission checks.

The gate discards the inherited environment, then sets only the explicit
`TL_WITNESS_*` configuration derived from its trusted policy. It uses a fixed
`/bin/sh` program to set `umask 077` and `exec "$@"`; client command text is never
evaluated by that shell. Signed input travels on stdin. The child runs in its
own process group with a bounded deadline, including blocked stdin, and errors
are redacted. Use OS service/cgroup admission, memory and process limits for
concurrency, disconnects and stronger containment. A privileged filesystem
attacker or uninterruptible kernel I/O is outside this one-shot gate's guarantee.

Require protected ancestor directories, separate administrator and signing-key
custody, known host keys, no account shell access through another SSH key, no
forwarding/TTY/user-controlled environment, and independently verified backup
or quorum. A forced command alone cannot make a co-administered witness
independent. No actual host/account changes are performed by this package.

## Reproducible real-SSH test

The normal Rust suite includes parser tests and a shell-faithful fake transport.
The encrypted transport test is explicitly ignored by `cargo test` because it
requires Linux root privileges, OpenSSH and a private mount namespace. CI runs
it as a mandatory separate step:

```sh
cargo test --locked --offline --test openssh --no-run --message-format=json > /tmp/witness-ssh-artifacts.jsonl
sudo python3 scripts/run-openssh-test.py --sshd /usr/sbin/sshd --artifacts /tmp/witness-ssh-artifacts.jsonl
```

The launcher creates a private mount namespace with a disposable `/run` and a
copy of the public account database. It supplies an `sshd` privilege-separation
entry there if needed. It changes no host accounts, SSH configuration, password,
firewall or system service. The daemon listens only on `127.0.0.1` at a temporary
port. Host, witness, operator, lost-ack and unrecognized SSH credentials are
generated for the test and removed afterward. Root login exists only in that
loopback test configuration; it is not a deployment recommendation.

The test copies the actual service executables into protected fixture paths and
checks real encrypted SSH genesis CAS, exact host pinning (including paths with
spaces), unknown-key refusal, disjoint forced-command roles, invalid operator
signatures, injection denial, hostile environment refusal, policy permissions,
blocked-stdin timeout and unavailable-server refusal. It deliberately discards
a real remote CAS receipt, proves the local writer blocks, recovers signed
history through the separate operator identity, verifies a fresh receipt,
models explicit offline import into a new store and resumes witnessed append
without changing the failed store.

All collator/witness/operator signing seeds are deterministic synthetic fixtures
(1, 3, 5 and 7); none are live wallet or operator credentials. Source contracts
and dependencies remain the same as [RECOVERY.md](RECOVERY.md). Passing this test
demonstrates the encrypted SSH and capability boundary. Separate-host custody,
physical crash/power-loss persistence, independent backups and production
acceptance require additional evidence.
