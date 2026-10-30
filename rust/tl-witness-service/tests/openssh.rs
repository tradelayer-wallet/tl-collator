//! Real encrypted OpenSSH, generated credentials, private loopback server.
//! Explicitly run through scripts/run-openssh-test.py; never targets a VPS.
#![cfg(target_os = "linux")]
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use tl_collator_wire::{
    canonical_json,
    durable::{DurableError, DurableTape, ImportMode, WitnessTransport, WitnessedTape},
    order_id, sha256_hex, tape_entry_hash, tape_signature_hash,
    verify::Checkpoint,
    witness::WitnessScope,
};
use tl_witness_service::{
    recovery::{
        verify_full_recovery, FreshReceipt, PagedRecovery, RecoveryExport, RecoveryLimits,
        RecoverySessionLimits, REQUEST_DOMAIN,
    },
    ssh::{SshConfig, SshWitnessTransport},
    Config, WitnessService,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn public(seed: u8) -> String {
    hex(&PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[seed; 32]).unwrap(),
    )
    .serialize())
}
fn signature(digest: &str, seed: u8) -> String {
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16).unwrap();
    }
    hex(&Secp256k1::new()
        .sign_ecdsa(
            &Message::from_digest(bytes),
            &SecretKey::from_slice(&[seed; 32]).unwrap(),
        )
        .serialize_compact())
}
fn signed_entry(seq: u64, previous: &str) -> String {
    let mut order = json!({"v":1,"kind":"NEW","body":{"v":1,"market":"SPOT:LTC/USDT","side":"BUY",
        "px":"72.50","qty":"10.0","visibility":{"kind":"PUBLIC"},"clientTs":1700000000000_u64},
        "traderPubKey":public(1),"clientNonce":format!("{seq:016x}")});
    let id = order_id(&order).unwrap();
    order["orderId"] = json!(id);
    order["sigTrader"] = json!(signature(&id, 1));
    let mut entry = json!({"v":1,"collatorId":"collator-test","seq":seq,"prevHash":previous,
        "receivedTs":1700000000001_u64,"order":order});
    let hash = tape_entry_hash(&entry).unwrap();
    entry["entryHash"] = json!(hash);
    entry["sigCollator"] = json!(signature(&tape_signature_hash(&entry, &hash).unwrap(), 3));
    entry.to_string()
}
fn config() -> Config {
    Config {
        collator_id: "collator-test".into(),
        collator_pubkey: public(3),
        network: "LTCTEST".into(),
        stream: "orders".into(),
        epoch: 3,
        max_entries: 1000,
    }
}
fn scope() -> WitnessScope {
    WitnessScope::new("collator-test", "LTCTEST", "orders", 3, &public(5)).unwrap()
}
fn limits() -> RecoveryLimits {
    RecoveryLimits {
        max_records: 1000,
        max_record_bytes: 1_048_576,
        max_export_bytes: 1_048_576,
        max_scan_bytes: 2_097_152,
        timeout: Duration::from_secs(10),
    }
}
fn request(cp: &Checkpoint, seed: u8) -> String {
    request_range(cp, 1, cp.last_seq, &"ab".repeat(32), seed)
}
fn request_range(cp: &Checkpoint, start: u64, count: u64, nonce: &str, seed: u8) -> String {
    let mut value = json!({"domain":REQUEST_DOMAIN,"v":1,"collatorId":"collator-test","network":"LTCTEST",
        "stream":"orders","epoch":3,"operatorId":"test-operator","startSeq":start,"count":count,
        "checkpointSeq":cp.last_seq,"checkpointHash":cp.last_hash,"seenOrders":cp.seen_orders,"challenge":nonce});
    value["sigOperator"] = json!(signature(
        &sha256_hex(&canonical_json(&value).unwrap()),
        seed
    ));
    value.to_string()
}
fn restricted(path: &Path, contents: impl AsRef<[u8]>, mode: u32) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
struct Server {
    root: PathBuf,
    child: Option<Child>,
    port: u16,
    policy: Value,
    known: String,
}
impl Server {
    fn new() -> Self {
        let runtime = PathBuf::from(
            std::env::var_os("TL_TEST_RUNTIME").expect("use the namespace test launcher"),
        );
        assert!(runtime.starts_with("/run/"));
        let root = runtime.join(format!("witness-openssh-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut server = Self {
            root,
            child: None,
            port: 0,
            policy: Value::Null,
            known: String::new(),
        };
        for name in [
            "host",
            "writer key",
            "recovery key",
            "lost ack key",
            "unknown key",
        ] {
            let status = Command::new("/usr/bin/ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(server.root.join(name))
                .status()
                .unwrap();
            assert!(status.success());
        }
        fs::create_dir(server.root.join("bin")).unwrap();
        for (variable, name) in [
            ("TL_TEST_WITNESSCTL", "witnessctl"),
            ("TL_TEST_EXPORTER", "witness-export"),
            ("TL_TEST_GATE", "witness-ssh-gate"),
        ] {
            let source = std::env::var_os(variable).expect("missing test binary");
            let target = server.root.join("bin").join(name);
            fs::copy(source, &target).unwrap();
            fs::set_permissions(target, fs::Permissions::from_mode(0o555)).unwrap();
        }
        fs::create_dir(server.root.join("remote")).unwrap();
        fs::set_permissions(
            server.root.join("remote"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        restricted(&server.root.join("secret"), "05".repeat(32), 0o600);
        restricted(&server.root.join("export-policy"),json!({"operatorId":"test-operator","operatorPubKey":public(7),
            "maxRecords":1000,"maxRecordBytes":1_048_576,"maxExportBytes":1_048_576,"maxScanBytes":2_097_152,"timeoutMillis":5000}).to_string(),0o600);
        server.policy = json!({"witnessctl":server.root.join("bin/witnessctl"),"exporter":server.root.join("bin/witness-export"),
            "dataDir":server.root.join("remote"),"keyFile":server.root.join("secret"),"exportPolicyFile":server.root.join("export-policy"),
            "collatorId":"collator-test","collatorPubKey":public(3),"network":"LTCTEST","stream":"orders","epoch":3,"maxEntries":1000,"timeoutMillis":5000});
        server.save_policy();
        let gate = server.root.join("bin/witness-ssh-gate");
        let policy = server.root.join("gate-policy");
        let mut authorized = String::new();
        for (key, role) in [("writer key", "witness"), ("recovery key", "recovery")] {
            authorized.push_str(&format!(
                "restrict,command=\"{} {} {}\" {}\n",
                gate.display(),
                role,
                policy.display(),
                fs::read_to_string(server.root.join(format!("{key}.pub")))
                    .unwrap()
                    .trim()
            ));
        }
        let drop_ack = server.root.join("drop-ack");
        restricted(&drop_ack,format!("#!/bin/sh\ncase \"$SSH_ORIGINAL_COMMAND\" in\n 'witnessctl latest '*) exec {} witness {} ;;\n *) exec {} witness {} >/dev/null ;;\nesac\n",
            quote(&gate.display().to_string()),quote(&policy.display().to_string()),quote(&gate.display().to_string()),quote(&policy.display().to_string())),0o500);
        authorized.push_str(&format!(
            "restrict,command=\"{}\" {}\n",
            drop_ack.display(),
            fs::read_to_string(server.root.join("lost ack key.pub"))
                .unwrap()
                .trim()
        ));
        restricted(&server.root.join("authorized_keys"), authorized, 0o600);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        server.port = listener.local_addr().unwrap().port();
        drop(listener);
        let host = fs::read_to_string(server.root.join("host.pub")).unwrap();
        let parts: Vec<_> = host.split_whitespace().collect();
        server.known = format!("[127.0.0.1]:{} {} {}\n", server.port, parts[0], parts[1]);
        restricted(&server.root.join("known hosts"), &server.known, 0o600);
        restricted(&server.root.join("sshd_config"),format!("Port {}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes yes\nUsePAM yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin yes\nAllowUsers root\nPermitUserEnvironment no\nAllowAgentForwarding no\nAllowTcpForwarding no\nPermitTTY no\nX11Forwarding no\nAcceptEnv TL_WITNESS_*\nLogLevel VERBOSE\n",
            server.port,server.root.join("host").display(),server.root.join("sshd.pid").display(),server.root.join("authorized_keys").display()),0o600);
        let daemon = std::env::var_os("TL_TEST_SSHD").expect("missing test daemon");
        let child = Command::new(daemon)
            .args(["-D", "-e", "-f"])
            .arg(server.root.join("sshd_config"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(server.root.join("sshd.log")).unwrap())
            .spawn()
            .unwrap();
        server.child = Some(child);
        let started = Instant::now();
        loop {
            if server.child.as_mut().unwrap().try_wait().unwrap().is_some() {
                panic!(
                    "sshd startup: {}",
                    fs::read_to_string(server.root.join("sshd.log")).unwrap()
                );
            }
            if TcpStream::connect(("127.0.0.1", server.port)).is_ok() {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "sshd did not listen"
            );
            thread::sleep(Duration::from_millis(20));
        }
        server
    }
    fn save_policy(&self) {
        restricted(
            &self.root.join("gate-policy"),
            self.policy.to_string(),
            0o600,
        );
    }
    fn client(&self, key: &str) -> SshWitnessTransport {
        SshWitnessTransport::new(
            SshConfig::new(
                "/usr/bin/ssh".into(),
                "root".into(),
                "127.0.0.1".into(),
                self.port,
                self.root.join(key),
                self.root.join("known hosts"),
                Duration::from_secs(5),
            )
            .unwrap(),
        )
    }
    fn command(&self, key: &str, original: &str) -> Command {
        let mut command = Command::new("/usr/bin/ssh");
        command
            .args([
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
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=2",
            ])
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile=\"{}\"",
                self.root.join("known hosts").display()
            ))
            .arg("-o")
            .arg(format!(
                "SetEnv=TL_WITNESS_DATA_DIR={}",
                self.root.join("attacker-selected").display()
            ))
            .arg("-i")
            .arg(self.root.join(key))
            .arg("-p")
            .arg(self.port.to_string())
            .args(["-T", "root@127.0.0.1", original])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        command
    }
    fn raw(&self, key: &str, original: &str, input: &str) -> Output {
        let mut child = self.command(key, original).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                panic!("raw SSH deadline exceeded");
            }
            thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    }
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
#[ignore = "requires root, real sshd, synthetic keys and the private namespace launcher"]
fn real_openssh_recovery_and_authorization() {
    let mut server = Server::new();
    let nonce = "cd".repeat(32);
    let local = server.root.join("local");
    fs::create_dir(&local).unwrap();
    let mut writer = WitnessedTape::open(
        &local,
        "orders",
        "collator-test",
        &public(3),
        1000,
        scope(),
        server.client("writer key"),
    )
    .unwrap();
    let one = writer.append_signed(&signed_entry(1, "")).unwrap();
    assert_eq!(one.last_seq, 1);
    drop(writer);
    for name in [
        "witness.lock",
        "witness.ndjson",
        "witness.checkpoint",
        "witness.scope",
    ] {
        assert_eq!(
            fs::metadata(server.root.join("remote").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0,
            "gate must keep created witness files private"
        );
    }
    let mut ambiguous = WitnessedTape::open(
        &local,
        "orders",
        "collator-test",
        &public(3),
        1000,
        scope(),
        server.client("lost ack key"),
    )
    .unwrap();
    assert!(matches!(
        ambiguous.append_signed(&signed_entry(2, &one.last_hash)),
        Err(DurableError::RemoteUncertain)
    ));
    assert!(ambiguous.is_blocked());
    assert_eq!(ambiguous.checkpoint(), one);
    drop(ambiguous);
    let preserved = fs::read(local.join("orders.ndjson")).unwrap();
    let preserved_anchor = fs::read(local.join("orders.checkpoint")).unwrap();
    let latest = server.client("writer key").latest(&nonce).unwrap();
    let cp = scope().verify_receipt(&latest, &nonce).unwrap();
    assert_eq!(cp.seq(), 2);
    let checkpoint = Checkpoint {
        last_seq: cp.seq(),
        last_hash: cp.head_hash().into(),
        seen_orders: cp.seen_orders(),
    };
    for (key, command, input) in [
        (
            "writer key",
            "witness-export".into(),
            request(&checkpoint, 7),
        ),
        (
            "recovery key",
            format!("witnessctl latest {nonce}"),
            String::new(),
        ),
        (
            "writer key",
            format!(
                "witnessctl latest {nonce}; touch {}",
                server.root.join("injected").display()
            ),
            String::new(),
        ),
        ("writer key", "sh".into(), String::new()),
        (
            "recovery key",
            "witness-export".into(),
            request(&checkpoint, 3),
        ),
        (
            "unknown key",
            format!("witnessctl latest {nonce}"),
            String::new(),
        ),
    ] {
        let denied = server.raw(key, &command, &input);
        assert!(!denied.status.success(), "unexpected authorized command");
        assert!(denied.stdout.is_empty());
    }
    assert!(!server.root.join("injected").exists());
    assert!(!server.root.join("attacker-selected").exists());
    // Deliberately accepted hostile client environment is erased by the gate.
    let reply = server.raw("writer key", &format!("witnessctl latest {nonce}"), "");
    assert!(reply.status.success());
    assert_eq!(
        scope()
            .verify_receipt(std::str::from_utf8(&reply.stdout).unwrap().trim(), &nonce)
            .unwrap()
            .seq(),
        2
    );
    let exported = server.raw("recovery key", "witness-export", &request(&checkpoint, 7));
    assert!(exported.status.success());
    let raw = String::from_utf8(exported.stdout).unwrap();
    let (manifest, ndjson) = raw.split_once('\n').unwrap();
    let bundle = RecoveryExport {
        manifest: manifest.into(),
        ndjson: ndjson.into(),
    };
    let started = Instant::now();
    let fresh = server.client("writer key").latest(&nonce).unwrap();
    let verified = verify_full_recovery(
        &bundle,
        &config(),
        &public(5),
        "test-operator",
        &"ab".repeat(32),
        FreshReceipt {
            raw: &fresh,
            challenge: &nonce,
            requested_at: started,
            max_age: Duration::from_secs(10),
        },
        &limits(),
    )
    .unwrap();
    assert_eq!(verified, checkpoint);
    let configuration = config();
    let mut paged = PagedRecovery::new(
        &configuration,
        &public(5),
        "test-operator",
        checkpoint.clone(),
        RecoveryLimits {
            max_records: 1,
            ..limits()
        },
        RecoverySessionLimits {
            max_pages: 2,
            max_total_export_bytes: 8192,
            timeout: Duration::from_secs(20),
        },
    )
    .unwrap();
    let mut assembled = String::new();
    for n in 1..=2 {
        let challenge = format!("{n:064x}");
        let output = server.raw(
            "recovery key",
            "witness-export",
            &request_range(&checkpoint, n, 1, &challenge, 7),
        );
        assert!(output.status.success());
        let raw = String::from_utf8(output.stdout).unwrap();
        let (manifest, ndjson) = raw.split_once('\n').unwrap();
        let page = RecoveryExport {
            manifest: manifest.into(),
            ndjson: ndjson.into(),
        };
        paged.accept_page(&page, &challenge).unwrap();
        assembled.push_str(&page.ndjson);
    }
    let final_challenge = "ef".repeat(32);
    let started = Instant::now();
    let fresh = server
        .client("writer key")
        .latest(&final_challenge)
        .unwrap();
    let verified = paged
        .finish(FreshReceipt {
            raw: &fresh,
            challenge: &final_challenge,
            requested_at: started,
            max_age: Duration::from_secs(10),
        })
        .unwrap();
    assert_eq!(verified, checkpoint);
    assert_eq!(assembled, bundle.ndjson);
    let restored = server.root.join("restored");
    fs::create_dir(&restored).unwrap();
    restricted(&restored.join("orders.ndjson"), &assembled, 0o600);
    let imported = DurableTape::open(
        &restored,
        "orders",
        "collator-test",
        &public(3),
        1000,
        ImportMode::ExplicitVerifiedImport,
    )
    .unwrap();
    assert_eq!(imported.checkpoint(), verified);
    drop(imported);
    let mut resumed = WitnessedTape::open(
        &restored,
        "orders",
        "collator-test",
        &public(3),
        1000,
        scope(),
        server.client("writer key"),
    )
    .unwrap();
    let three = resumed
        .append_signed(&signed_entry(3, &verified.last_hash))
        .unwrap();
    assert_eq!(three.last_seq, 3);
    drop(resumed);
    assert_eq!(fs::read(local.join("orders.ndjson")).unwrap(), preserved);
    assert_eq!(
        fs::read(local.join("orders.checkpoint")).unwrap(),
        preserved_anchor
    );
    let wrong = fs::read_to_string(server.root.join("unknown key.pub")).unwrap();
    let fields: Vec<_> = wrong.split_whitespace().collect();
    restricted(
        &server.root.join("known hosts"),
        format!("[127.0.0.1]:{} {} {}\n", server.port, fields[0], fields[1]),
        0o600,
    );
    assert!(server.client("writer key").latest(&nonce).is_err());
    restricted(&server.root.join("known hosts"), &server.known, 0o600);
    fs::set_permissions(
        server.root.join("gate-policy"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(!server
        .raw("writer key", &format!("witnessctl latest {nonce}"), "")
        .status
        .success());
    server.save_policy();
    server.policy["timeoutMillis"] = json!(300);
    server.save_policy();
    let command = format!("witnessctl cas 3 {} 3 {nonce}", three.last_hash);
    let mut hung = server.command("writer key", &command).spawn().unwrap();
    let started = Instant::now();
    while hung.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(5) {
            let _ = hung.kill();
            panic!("gate did not bound blocked stdin");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!hung.wait_with_output().unwrap().status.success());
    assert_eq!(
        WitnessService::open(&server.root.join("remote"), config(), &[5; 32])
            .unwrap()
            .checkpoint(),
        three
    );
    server.stop();
    assert!(server.client("writer key").latest(&nonce).is_err());
    println!("Real OpenSSH: genesis CAS, paged lost-ack recovery, disjoint forced commands, operator signatures, hostile environment, unknown identity, host pinning, policy permissions, deadline and partition refusal passed.");
}
