# Authenticated SSH transport adapter (RUST-17G)

The Rust module rust/tl-witness-service/src/ssh.rs provides a bounded,
separately configured SSH process transport implementing WitnessTransport.
It does **not** bring up a network daemon or create keys/servers.

## Operator requirements

Use a dedicated independent host and user, a separate witness ECDSA signing
key in a 0600 file and a private 0700 witness data directory. Provision the
one-shot witnessctl command (latest and cas) behind an authenticated SSH
key/forced-command policy. Ensure the operator pins host keys in a protected
known_hosts file and the client uses a separate restricted SSH identity file.

The client requires an explicitly configured absolute SSH executable path,
restricted identity path, non-writable known_hosts path, validated user/host,
port and bounded timeout. It executes no local shell and uses SSH flags
including -F /dev/null, BatchMode, StrictHostKeyChecking, UserKnownHostsFile,
IdentitiesOnly, IdentityAgent=none, password/GSSAPI authentication disabled,
ProxyCommand=none, no port forwarding, and no SSH control master.
Only validated integer/hex values go in the remote command; the complete
signed entry travels over stdin.

OpenSSH sends the remote command through a shell, so the adapter explicitly
encodes the genesis predecessor hash as `''` rather than relying on an empty
local argv element. `UserKnownHostsFile` paths are quoted for the ssh_config
parser. Identity and host-key paths with control characters, quotes, backslash,
`$` or `%` are refused so OpenSSH expansion cannot select a different file from
the one validated locally. Whitespace in ordinary absolute paths is supported.

A whole subprocess deadline covers both process exit and completion of stdin
and stdout I/O. Each SSH command has its own POSIX process group; cleanup sends
SIGKILL to that group through the trusted `/bin/kill` utility on success or
failure, including descendants that inherited pipes after their leader exited.
Unfinished I/O threads are never joined on timeout. The configured executable
must be operator trusted and preserve group membership; a process supervisor
is required for containment of deliberately escaping descendants. Output is capped at
8192 bytes and decoded as UTF-8, never interpreted as a trustworthy checkpoint
without a separately verified WitnessScope signature. Subprocess errors and
stderr are redacted from the API; no private key bytes are passed as args.

## CI coverage and limits

The tests use a disposable fake-SSH executable which joins the remote command
and invokes a shell, matching OpenSSH's argument handling for a separate local
witnessctl process. It tests genesis CAS empty-hash preservation as well as the
argument policy, a real witnessctl-provided signed latest response, and
remote-first WitnessedTape append across independent test directories.
Timeout and bad-output cases demonstrate rejection.

**Fake SSH does not test real SSH encryption, authentication, host key
verification or remote CAS durability.** Those depend on OpenSSH, its runtime
configuration and the operator-controlled host. Real authorized-key
forced-command behavior, remote host identity, trusted monotonic storage,
network partitions and witnessed restart must be tested on a dedicated
regtest host before deployment. No production endpoint was configured here.

## Open service gates

- Remote witness operator and host with independent key custody
- Rate/size bounds at the forced-command boundary and monitored access logs
- Secure independent monotonic backups/quorum and key/epoch rotation
- Audited recovery of a remote-committed/local-missing signed record
- Regtest network fault injection, filesystem power-loss validation, and
  explicit production deployment permission
