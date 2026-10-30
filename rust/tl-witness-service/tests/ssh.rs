#![cfg(unix)]
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::json;
use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tl_collator_wire::{
    durable::{WitnessTransport, WitnessTransportError, WitnessedTape},
    order_id, tape_entry_hash, tape_signature_hash,
    verify::Checkpoint,
    witness::WitnessScope,
};
use tl_witness_service::ssh::{SshConfig, SshWitnessTransport};

static I: AtomicU64 = AtomicU64::new(0);
struct Env {
    root: PathBuf,
    local: PathBuf,
    ssh: PathBuf,
    known: PathBuf,
    auth: PathBuf,
    args: PathBuf,
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
impl Env {
    fn new(script_override: Option<&str>) -> Self {
        let n = I.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("tl-ssh-witness-{nanos}-{n}-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let remote = root.join("remote");
        let local = root.join("local");
        fs::create_dir(&remote).unwrap();
        fs::create_dir(&local).unwrap();
        fs::set_permissions(&remote, Permissions::from_mode(0o700)).unwrap();
        let witness_key = remote.join("witness-secret");
        fs::write(&witness_key, "05".repeat(32)).unwrap();
        fs::set_permissions(&witness_key, Permissions::from_mode(0o600)).unwrap();
        let auth = root.join("ssh-test-identity");
        fs::write(&auth, "synthetic SSH identity - not a credential").unwrap();
        fs::set_permissions(&auth, Permissions::from_mode(0o600)).unwrap();
        let known = root.join("known_hosts");
        fs::write(
            &known,
            "example.test ssh-ed25519 synthetic-test-host-pinning\n",
        )
        .unwrap();
        fs::set_permissions(&known, Permissions::from_mode(0o600)).unwrap();
        let args = root.join("ssh_args");
        let ssh = root.join("fake-ssh");
        let source = if let Some(contents) = script_override {
            contents.to_owned()
        } else {
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = witnessctl ]; then\n    shift\n    export TL_WITNESS_DATA_DIR={}\n    export TL_WITNESS_KEY_FILE={}\n    export TL_WITNESS_COLLATOR_ID=collator-test\n    export TL_WITNESS_COLLATOR_PUBKEY={}\n    export TL_WITNESS_NETWORK=LTCTEST\n    export TL_WITNESS_STREAM=orders\n    export TL_WITNESS_EPOCH=3\n    export TL_WITNESS_MAX_ENTRIES=100\n    exec /bin/sh -c \"{} $*\"\n  fi\n  shift\ndone\nexit 2\n",
                quote(&args.display().to_string()),
                quote(&remote.display().to_string()),
                quote(&witness_key.display().to_string()),
                quote(&key(&[3u8;32])),
                quote(env!("CARGO_BIN_EXE_witnessctl"))
            )
        };
        fs::write(&ssh, source).unwrap();
        fs::set_permissions(&ssh, Permissions::from_mode(0o700)).unwrap();
        Self {
            root,
            local,
            ssh,
            known,
            auth,
            args,
        }
    }
    fn config(&self, timeout: Duration) -> SshConfig {
        SshConfig::new(
            self.ssh.clone(),
            "witnessrunner".into(),
            "example.test".into(),
            2222,
            self.auth.clone(),
            self.known.clone(),
            timeout,
        )
        .unwrap()
    }
    fn client(&self) -> SshWitnessTransport {
        SshWitnessTransport::new(self.config(Duration::from_secs(4)))
    }
    fn args(&self) -> String {
        fs::read_to_string(&self.args).unwrap_or_default()
    }
}
impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn key(bytes: &[u8; 32]) -> String {
    let ctx = Secp256k1::new();
    PublicKey::from_secret_key(&ctx, &SecretKey::from_slice(bytes).unwrap())
        .serialize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn sign(message_hex: &str, private: &[u8; 32]) -> String {
    let mut hash = [0u8; 32];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = u8::from_str_radix(&message_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    Secp256k1::new()
        .sign_ecdsa(
            &Message::from_digest(hash),
            &SecretKey::from_slice(private).unwrap(),
        )
        .serialize_compact()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn entry() -> String {
    let mut order = json!({
        "v":1,"kind":"NEW","body":{
            "v":1,"market":"SPOT:LTC/USDT","side":"BUY","px":"72.50",
            "qty":"10.0","visibility":{"kind":"PUBLIC"},"clientTs":1700000000000_u64,
        },
        "traderPubKey":key(&[1u8;32]),"clientNonce":"aabbccddee001122"
    });
    let id = order_id(&order).unwrap();
    order["orderId"] = json!(id);
    order["sigTrader"] = json!(sign(&id, &[1u8; 32]));
    let mut event = json!({"v":1,"collatorId":"collator-test","seq":1,
        "prevHash":"","receivedTs":1700000000001_u64,"order":order});
    let hash = tape_entry_hash(&event).unwrap();
    event["entryHash"] = json!(hash);
    let digest = tape_signature_hash(&event, &hash).unwrap();
    event["sigCollator"] = json!(sign(&digest, &[3u8; 32]));
    event.to_string()
}
fn scope() -> WitnessScope {
    WitnessScope::new("collator-test", "LTCTEST", "orders", 3, &key(&[5u8; 32])).unwrap()
}
fn challenge() -> String {
    "ab".repeat(32)
}
#[test]
fn ssh_adapter_receives_independently_signed_latest_from_remote_process() {
    let env = Env::new(None);
    let mut client = env.client();
    let raw = client.latest(&challenge()).unwrap();
    let verified = scope().verify_receipt(&raw, &challenge()).unwrap();
    assert_eq!(verified.seq(), 0);
    let args = env.args();
    for flag in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "ProxyCommand=none",
        "ControlMaster=no",
        "ClearAllForwardings=yes",
        "PasswordAuthentication=no",
        "UserKnownHostsFile=",
        "UpdateHostKeys=no",
    ] {
        assert!(args.contains(flag), "missing pinned SSH flag: {flag}");
    }
}
#[test]
fn ssh_process_boundary_completes_witnessed_remote_first_cas() {
    let env = Env::new(None);
    let client = env.client();
    let mut writer = WitnessedTape::open(
        &env.local,
        "orders",
        "collator-test",
        &key(&[3u8; 32]),
        100,
        scope(),
        client,
    )
    .unwrap();
    assert_eq!(writer.checkpoint().last_seq, 0);
    let next = writer.append_signed(&entry()).unwrap();
    assert_eq!(next.last_seq, 1);
    drop(writer);
    let raw = env.client().latest(&challenge()).unwrap();
    let proof = scope().verify_receipt(&raw, &challenge()).unwrap();
    assert_eq!(proof.seq(), 1);
    assert_eq!(proof.head_hash(), next.last_hash);
    assert_eq!(
        fs::read_to_string(env.local.join("orders.ndjson"))
            .unwrap()
            .lines()
            .count(),
        1
    );
}
#[test]
fn invalid_hosts_paths_and_permissions_are_refused() {
    let env = Env::new(None);
    assert!(SshConfig::new(
        env.ssh.clone(),
        "bad;user".into(),
        "example.test".into(),
        2222,
        env.auth.clone(),
        env.known.clone(),
        Duration::from_secs(2)
    )
    .is_err());
    assert!(SshConfig::new(
        env.ssh.clone(),
        "witnessrunner".into(),
        "-malicious".into(),
        2222,
        env.auth.clone(),
        env.known.clone(),
        Duration::from_secs(2)
    )
    .is_err());
    fs::set_permissions(&env.auth, Permissions::from_mode(0o644)).unwrap();
    assert!(SshConfig::new(
        env.ssh.clone(),
        "witnessrunner".into(),
        "example.test".into(),
        2222,
        env.auth.clone(),
        env.known.clone(),
        Duration::from_secs(2)
    )
    .is_err());
}
#[test]
fn malformed_challenge_and_untrusted_cas_args_fail_before_spawning() {
    let env = Env::new(None);
    let mut client = env.client();
    assert!(matches!(
        client.latest("bad"),
        Err(WitnessTransportError::Unavailable)
    ));
    let bad = Checkpoint {
        last_seq: 1,
        last_hash: "invalid".into(),
        seen_orders: 1,
    };
    assert!(matches!(
        client.cas_signed(&bad, &entry(), &challenge()),
        Err(WitnessTransportError::Unavailable)
    ));
    assert!(matches!(
        client.cas_signed(
            &Checkpoint {
                last_seq: 0,
                last_hash: String::new(),
                seen_orders: 0
            },
            "malformed\nextra",
            &challenge()
        ),
        Err(WitnessTransportError::Unavailable)
    ));
    assert!(!env.args.exists());
}
#[test]
fn hung_local_ssh_command_is_killed_on_deadline() {
    let env = Env::new(Some("#!/bin/sh\nexec sleep 10\n"));
    let mut client = SshWitnessTransport::new(env.config(Duration::from_millis(300)));
    let started = std::time::Instant::now();
    assert!(matches!(
        client.latest(&challenge()),
        Err(WitnessTransportError::Unavailable)
    ));
    assert!(started.elapsed() < Duration::from_secs(3));
}
#[test]
fn attacker_output_not_consisting_of_signed_receipt_fails_at_verifier() {
    let env = Env::new(Some("#!/bin/sh\nprintf '%s\\n' '{\"seq\":0}'\n"));
    let mut client = env.client();
    let output = client.latest(&challenge()).unwrap();
    assert!(scope().verify_receipt(&output, &challenge()).is_err());
}

#[test]
fn exited_ssh_leader_with_descendant_holding_stdout_obeys_deadline() {
    let env = Env::new(Some("#!/bin/sh\nsleep 10 &\nexit 0\n"));
    let mut client = SshWitnessTransport::new(env.config(Duration::from_millis(300)));
    let started = std::time::Instant::now();
    assert!(client.latest(&challenge()).is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn descendant_holding_stdin_cannot_block_large_cas_write() {
    let env = Env::new(Some("#!/bin/sh\nsleep 10 &\nexit 0\n"));
    let mut client = SshWitnessTransport::new(env.config(Duration::from_millis(300)));
    let started = std::time::Instant::now();
    assert!(client
        .cas_signed(
            &Checkpoint {
                last_seq: 0,
                last_hash: String::new(),
                seen_orders: 0
            },
            &"x".repeat(512 * 1024),
            &challenge()
        )
        .is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn timed_out_process_group_cannot_leave_a_descendant_running() {
    let env = Env::new(Some("#!/bin/sh\nexit 2\n"));
    let marker = env.root.join("descendant-survived");
    fs::write(
        &env.ssh,
        format!(
            "#!/bin/sh\n(sleep 1; printf survived > {}) &\nwait\n",
            quote(&marker.display().to_string())
        ),
    )
    .unwrap();
    let mut client = SshWitnessTransport::new(env.config(Duration::from_millis(300)));
    assert!(client.latest(&challenge()).is_err());
    std::thread::sleep(Duration::from_millis(900));
    assert!(!marker.exists());
}

#[test]
fn genesis_cas_preserves_empty_hash_through_the_remote_shell() {
    let env = Env::new(None);
    let mut client = env.client();
    let genesis = Checkpoint {
        last_seq: 0,
        last_hash: String::new(),
        seen_orders: 0,
    };
    let receipt = client.cas_signed(&genesis, &entry(), &challenge()).unwrap();
    assert_eq!(
        scope()
            .verify_receipt(&receipt, &challenge())
            .unwrap()
            .seq(),
        1
    );
    assert!(env.args().contains("\n''\n"));
}

#[test]
fn ssh_config_paths_are_literal_and_whitespace_is_quoted() {
    let env = Env::new(None);
    let spaced = env.root.join("known hosts");
    fs::copy(&env.known, &spaced).unwrap();
    let config = SshConfig::new(
        env.ssh.clone(),
        "witnessrunner".into(),
        "example.test".into(),
        2222,
        env.auth.clone(),
        spaced.clone(),
        Duration::from_secs(4),
    )
    .unwrap();
    let mut client = SshWitnessTransport::new(config);
    client.latest(&challenge()).unwrap();
    assert!(env
        .args()
        .contains(&format!("UserKnownHostsFile=\"{}\"", spaced.display())));
    for name in [
        "known%h",
        "known${HOME}",
        "known\nhosts",
        "known\"hosts",
        "known\\hosts",
    ] {
        let expanded = env.root.join(name);
        fs::copy(&env.known, &expanded).unwrap();
        assert!(SshConfig::new(
            env.ssh.clone(),
            "witnessrunner".into(),
            "example.test".into(),
            2222,
            env.auth.clone(),
            expanded,
            Duration::from_secs(4)
        )
        .is_err());
    }
}
