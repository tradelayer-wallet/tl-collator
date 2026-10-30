//! Explicit SSH process adapter for a separately hosted witnessctl executable.
//! It neither stores signing keys nor authenticates receipts itself: the
//! WitnessedTape caller verifies the independently signed TL-Canon receipt.
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tl_collator_wire::{
    durable::{WitnessTransport, WitnessTransportError},
    verify::Checkpoint,
    MAX_INPUT_BYTES, MAX_SAFE_INTEGER,
};

const MAX_REPLY: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Invalid,
}

fn host_valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !s.contains("..")
}
fn user_valid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn challenge_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes().any(|b| b != b'0')
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn head_valid(seq: u64, hash: &str, orders: usize) -> bool {
    seq <= MAX_SAFE_INTEGER
        && orders as u64 == seq
        && if seq == 0 {
            hash.is_empty()
        } else {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
}
fn regular(path: &Path) -> bool {
    path.is_absolute() && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

// OpenSSH parses -o as ssh_config text and expands tokens in file paths.
// Quote whitespace and refuse expansion/escape syntax so the path inspected
// below names the same identity/host-key file that OpenSSH actually opens.
fn literal_ssh_path(path: &Path) -> bool {
    path.to_str().is_some_and(|s| {
        !s.chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '"' | '$' | '%'))
    })
}

/// The SSH *client* process uses the operator's private authentication key,
/// distinct from the witness service's ECDSA signing key and collator key.
pub struct SshConfig {
    ssh_binary: PathBuf,
    user: String,
    host: String,
    port: u16,
    identity: PathBuf,
    known_hosts: PathBuf,
    timeout: Duration,
}
impl SshConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ssh_binary: PathBuf,
        user: String,
        host: String,
        port: u16,
        identity: PathBuf,
        known_hosts: PathBuf,
        timeout: Duration,
    ) -> Result<Self, ConfigError> {
        if !host_valid(&host)
            || !user_valid(&user)
            || port == 0
            || !regular(&ssh_binary)
            || !regular(&identity)
            || !regular(&known_hosts)
            || !literal_ssh_path(&identity)
            || !literal_ssh_path(&known_hosts)
            || timeout < Duration::from_millis(250)
            || timeout > Duration::from_secs(60)
        {
            return Err(ConfigError::Invalid);
        }
        let ssh_meta = fs::metadata(&ssh_binary).map_err(|_| ConfigError::Invalid)?;
        let key_meta = fs::metadata(&identity).map_err(|_| ConfigError::Invalid)?;
        let known_meta = fs::metadata(&known_hosts).map_err(|_| ConfigError::Invalid)?;
        if ssh_meta.permissions().mode() & 0o111 == 0
            || key_meta.permissions().mode() & 0o077 != 0
            || known_meta.permissions().mode() & 0o022 != 0
            || known_meta.len() == 0
        {
            return Err(ConfigError::Invalid);
        }
        Ok(Self {
            ssh_binary,
            user,
            host,
            port,
            identity,
            known_hosts,
            timeout,
        })
    }
}

/// Launches exactly one operator-pinned SSH command at a time. No shell runs
/// locally. Only validated integer/hex arguments reach the remote shell, and
/// the full signed tape record is sent as *stdin*, never as a command argument.
/// Standard error is suppressed and never returned to the caller.
pub struct SshWitnessTransport {
    config: SshConfig,
}
impl SshWitnessTransport {
    pub fn new(config: SshConfig) -> Self {
        Self { config }
    }
    fn run(
        &mut self,
        action: &str,
        values: &[String],
        input: Option<&str>,
    ) -> Result<String, WitnessTransportError> {
        let mut command = Command::new(&self.config.ssh_binary);
        let connect_timeout = self.config.timeout.as_secs().clamp(1, 15);
        command.args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "GSSAPIAuthentication=no",
            "-o",
            "PreferredAuthentications=publickey",
        ]);
        command.arg("-o").arg(format!(
            "UserKnownHostsFile=\"{}\"",
            self.config.known_hosts.display()
        ));
        command.args(["-o", "GlobalKnownHostsFile=/dev/null"]);
        command
            .arg("-o")
            .arg(format!("ConnectTimeout={connect_timeout}"));
        command.args(["-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1"]);
        command.arg("-i").arg(&self.config.identity);
        command.arg("-p").arg(self.config.port.to_string());
        command.args(["-T", "--"]);
        command.arg(format!("{}@{}", self.config.user, self.config.host));
        command.args(["witnessctl", action]);
        // OpenSSH joins remote argv with spaces; the remote shell otherwise
        // discards the empty predecessor hash in the genesis CAS command.
        // Nonempty values are strictly validated decimal/hex before run().
        command.args(
            values
                .iter()
                .map(|v| if v.is_empty() { "''" } else { v.as_str() }),
        );
        command.stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        command
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("DISPLAY");
        // Isolate descendants so an inherited stdout/stdin pipe cannot keep
        // the caller blocked after the SSH leader exits or times out.
        command.process_group(0);
        let start = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|_| WitnessTransportError::Unavailable)?;
        let writer = if let Some(payload) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or(WitnessTransportError::Unavailable)?;
            let owned = payload.as_bytes().to_vec();
            Some(thread::spawn(move || stdin.write_all(&owned)))
        } else {
            None
        };
        let mut stdout = child
            .stdout
            .take()
            .ok_or(WitnessTransportError::Unavailable)?;
        let reader = thread::spawn(move || {
            let mut reply = Vec::new();
            let read = stdout
                .by_ref()
                .take((MAX_REPLY + 1) as u64)
                .read_to_end(&mut reply);
            (read, reply)
        });
        let mut exited = None;
        let status = loop {
            if exited.is_none() {
                match child.try_wait() {
                    Ok(Some(s)) => exited = Some(s),
                    Ok(None) => {}
                    Err(_) => break None,
                }
            }
            let pipes_done =
                reader.is_finished() && writer.as_ref().is_none_or(thread::JoinHandle::is_finished);
            if pipes_done && exited.is_some() {
                break exited;
            }
            if start.elapsed() >= self.config.timeout {
                break None;
            }
            thread::sleep(Duration::from_millis(10));
        };
        // /bin/kill receives a validated numeric process-group ID; no shell or
        // new dependency/unsafe syscall wrapper. Clean up descendants on both
        // success and failure. The pinned SSH executable must not escape its
        // process group. A service supervisor supplies stronger containment.
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if exited.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Never join unfinished I/O, including descendants deliberately
        // escaping the group. Failure returns within the request deadline.
        if status.is_none() {
            return Err(WitnessTransportError::Unavailable);
        }
        let write_ok = writer.is_none_or(|handle| handle.join().is_ok_and(|r| r.is_ok()));
        let (read_ok, output) = reader
            .join()
            .map_err(|_| WitnessTransportError::Unavailable)?;
        if !write_ok
            || read_ok.is_err()
            || output.len() > MAX_REPLY
            || !status.is_some_and(|s| s.success())
        {
            return Err(WitnessTransportError::Unavailable);
        }
        let response = String::from_utf8(output).map_err(|_| WitnessTransportError::Unavailable)?;
        if response.len() > MAX_REPLY || !response.ends_with('\n') {
            return Err(WitnessTransportError::Unavailable);
        }
        Ok(response.trim_end_matches('\n').to_owned())
    }
}
impl WitnessTransport for SshWitnessTransport {
    fn latest(&mut self, challenge: &str) -> Result<String, WitnessTransportError> {
        if !challenge_valid(challenge) {
            return Err(WitnessTransportError::Unavailable);
        }
        self.run("latest", &[challenge.to_owned()], None)
    }
    fn cas_signed(
        &mut self,
        expected: &Checkpoint,
        entry: &str,
        challenge: &str,
    ) -> Result<String, WitnessTransportError> {
        if !head_valid(expected.last_seq, &expected.last_hash, expected.seen_orders)
            || !challenge_valid(challenge)
            || entry.is_empty()
            || entry.len() > MAX_INPUT_BYTES
            || entry.as_bytes().contains(&b'\n')
            || entry.as_bytes().contains(&b'\r')
        {
            return Err(WitnessTransportError::Unavailable);
        }
        self.run(
            "cas",
            &[
                expected.last_seq.to_string(),
                expected.last_hash.clone(),
                expected.seen_orders.to_string(),
                challenge.to_owned(),
            ],
            Some(entry),
        )
    }
}
