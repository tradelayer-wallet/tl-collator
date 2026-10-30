//! Real witness-process SIGKILL after durable CAS and after receipt signing.
//! Synthetic data only; does not add fault switches to service executables.
#![cfg(unix)]
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tl_collator_wire::{
    canonical_json,
    durable::{
        DurableError, DurableTape, ImportMode, WitnessTransport, WitnessTransportError,
        WitnessedTape,
    },
    order_id, sha256_hex, tape_entry_hash, tape_signature_hash,
    verify::Checkpoint,
    witness::{WitnessError, WitnessScope},
    MAX_INPUT_BYTES,
};
use tl_witness_service::{
    recovery::{
        export_history, verify_full_recovery, FreshReceipt, RecoveryLimits, RecoveryPolicy,
        REQUEST_DOMAIN,
    },
    Config, WitnessService,
};

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "tl-witness-process-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
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
fn sign(digest: &str, seed: u8) -> String {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).unwrap();
    }
    hex(&Secp256k1::new()
        .sign_ecdsa(
            &Message::from_digest(bytes),
            &SecretKey::from_slice(&[seed; 32]).unwrap(),
        )
        .serialize_compact())
}
fn entry(seq: u64, previous: &str) -> String {
    let mut order = json!({"v":1,"kind":"NEW","body":{"v":1,"market":"SPOT:LTC/USDT","side":"BUY","px":"72.50",
        "qty":"10","visibility":{"kind":"PUBLIC"},"clientTs":1700000000000_u64},"traderPubKey":public(1),"clientNonce":format!("{seq:016x}")});
    let id = order_id(&order).unwrap();
    order["orderId"] = json!(id);
    order["sigTrader"] = json!(sign(&id, 1));
    let mut value = json!({"v":1,"collatorId":"collator-test","seq":seq,"prevHash":previous,"receivedTs":1700000000001_u64,"order":order});
    let hash = tape_entry_hash(&value).unwrap();
    value["entryHash"] = json!(hash);
    value["sigCollator"] = json!(sign(&tape_signature_hash(&value, &hash).unwrap(), 3));
    value.to_string()
}
fn config() -> Config {
    Config {
        collator_id: "collator-test".into(),
        collator_pubkey: public(3),
        network: "LTCTEST".into(),
        stream: "orders".into(),
        epoch: 3,
        max_entries: 100,
    }
}
fn service(path: &Path) -> WitnessService {
    WitnessService::open(path, config(), &[5; 32]).unwrap()
}
fn scope() -> WitnessScope {
    WitnessScope::new("collator-test", "LTCTEST", "orders", 3, &public(5)).unwrap()
}

#[test]
#[ignore = "entrypoint used only by the witness-process crash test"]
fn committed_witness_child() {
    let Some(path) = std::env::var_os("TL_TEST_WITNESS_PROCESS_PATH") else {
        return;
    };
    let mut input = String::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES as u64 + 8192)
        .read_to_string(&mut input)
        .unwrap();
    let message: Value = serde_json::from_str(&input).unwrap();
    let mut witness = service(Path::new(&path));
    let before = witness.checkpoint();
    witness
        .compare_and_swap(&before, message["entry"].as_str().unwrap())
        .unwrap();
    assert_eq!(witness.checkpoint().last_seq, 2);
    if message["afterSigning"] == true {
        let challenge = message["challenge"].as_str().unwrap();
        let signed = witness.attest_latest(challenge).unwrap();
        assert_eq!(scope().verify_receipt(&signed, challenge).unwrap().seq(), 2);
    }
    println!("TL_WITNESS_DURABLE_READY");
    std::io::stdout().flush().unwrap();
    loop {
        thread::park();
    }
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct CrashWitness {
    path: PathBuf,
    after_signing: bool,
}
impl WitnessTransport for CrashWitness {
    fn latest(&mut self, challenge: &str) -> Result<String, WitnessTransportError> {
        service(&self.path)
            .attest_latest(challenge)
            .map_err(|_| WitnessTransportError::Unavailable)
    }
    fn cas_signed(
        &mut self,
        _expected: &Checkpoint,
        signed_entry: &str,
        challenge: &str,
    ) -> Result<String, WitnessTransportError> {
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "committed_witness_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TL_TEST_WITNESS_PROCESS_PATH", &self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        child.0.stdin.take().unwrap().write_all(json!({"entry":signed_entry,"challenge":challenge,"afterSigning":self.after_signing}).to_string().as_bytes()).unwrap();
        let stdout = child.0.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut input = BufReader::new(stdout).take(16_384);
            let mut line = String::new();
            loop {
                line.clear();
                if input.read_line(&mut line).unwrap() == 0 {
                    let _ = sender.send(false);
                    return;
                }
                if line.contains("TL_WITNESS_DURABLE_READY") {
                    let _ = sender.send(true);
                    return;
                }
            }
        });
        assert!(receiver
            .recv_timeout(Duration::from_secs(6))
            .expect("witness crash barrier deadline"));
        reader.join().unwrap();
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(
            matches!(
                WitnessService::open(&self.path, config(), &[5; 32]),
                Err(tl_witness_service::Error::Durable(DurableError::LockBusy))
            ),
            "committed child must still own witness lock"
        );
        let anchor: Value =
            serde_json::from_slice(&fs::read(self.path.join("witness.checkpoint")).unwrap())
                .unwrap();
        assert_eq!(anchor["seq"], 2);
        child.0.kill().unwrap();
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));
        Err(WitnessTransportError::Unavailable) // No signed acknowledgment reaches the client.
    }
}

#[test]
fn sigkill_after_remote_commit_or_signing_requires_explicit_verified_recovery() {
    for after_signing in [false, true] {
        let remote = Directory::new("remote");
        let local = Directory::new("failed");
        let restored = Directory::new("restored");
        let first = entry(1, "");
        let mut witness = service(&remote.0);
        let one = witness
            .compare_and_swap(&witness.checkpoint(), &first)
            .unwrap();
        drop(witness);
        let mut initial = DurableTape::open(
            &local.0,
            "orders",
            "collator-test",
            &public(3),
            100,
            ImportMode::RequireAnchor,
        )
        .unwrap();
        initial.append_signed(&first).unwrap();
        drop(initial);
        let preserved = fs::read(local.0.join("orders.ndjson")).unwrap();
        let preserved_anchor = fs::read(local.0.join("orders.checkpoint")).unwrap();
        let mut writer = WitnessedTape::open(
            &local.0,
            "orders",
            "collator-test",
            &public(3),
            100,
            scope(),
            CrashWitness {
                path: remote.0.clone(),
                after_signing,
            },
        )
        .unwrap();
        assert!(matches!(
            writer.append_signed(&entry(2, &one.last_hash)),
            Err(DurableError::RemoteUncertain)
        ));
        assert!(writer.is_blocked());
        assert_eq!(writer.checkpoint(), one);
        assert!(matches!(
            writer.append_signed(&entry(2, &one.last_hash)),
            Err(DurableError::NeedsRecovery)
        ));
        drop(writer);
        let witness = service(&remote.0);
        let two = witness.checkpoint();
        assert_eq!(two.last_seq, 2);
        drop(witness);
        assert!(matches!(
            WitnessedTape::open(
                &local.0,
                "orders",
                "collator-test",
                &public(3),
                100,
                scope(),
                service(&remote.0)
            ),
            Err(DurableError::Witness(WitnessError::Rollback))
        ));
        let caps = RecoveryLimits {
            max_records: 100,
            max_record_bytes: MAX_INPUT_BYTES,
            max_export_bytes: 1_048_576,
            max_scan_bytes: 2_097_152,
            timeout: Duration::from_secs(10),
        };
        let mut request = json!({"domain":REQUEST_DOMAIN,"v":1,"collatorId":"collator-test","network":"LTCTEST","stream":"orders","epoch":3,
            "operatorId":"crash-operator","startSeq":1,"count":2,"checkpointSeq":two.last_seq,"checkpointHash":two.last_hash,"seenOrders":two.seen_orders,"challenge":"ab".repeat(32)});
        request["sigOperator"] = json!(sign(&sha256_hex(&canonical_json(&request).unwrap()), 7));
        let policy = RecoveryPolicy::new("crash-operator", &public(7), caps.clone()).unwrap();
        let bundle = export_history(
            &remote.0,
            &config(),
            &[5; 32],
            &policy,
            &request.to_string(),
        )
        .unwrap();
        let challenge = "cd".repeat(32);
        let started = Instant::now();
        let fresh = service(&remote.0).attest_latest(&challenge).unwrap();
        let approved = verify_full_recovery(
            &bundle,
            &config(),
            &public(5),
            "crash-operator",
            &"ab".repeat(32),
            FreshReceipt {
                raw: &fresh,
                challenge: &challenge,
                requested_at: started,
                max_age: Duration::from_secs(10),
            },
            &caps,
        )
        .unwrap();
        assert_eq!(approved, two);
        // Synthetic explicit approval into a NEW store; no automatic repair API.
        fs::write(restored.0.join("orders.ndjson"), &bundle.ndjson).unwrap();
        let imported = DurableTape::open(
            &restored.0,
            "orders",
            "collator-test",
            &public(3),
            100,
            ImportMode::ExplicitVerifiedImport,
        )
        .unwrap();
        assert_eq!(imported.checkpoint(), approved);
        drop(imported);
        let mut resumed = WitnessedTape::open(
            &restored.0,
            "orders",
            "collator-test",
            &public(3),
            100,
            scope(),
            service(&remote.0),
        )
        .unwrap();
        let three = resumed.append_signed(&entry(3, &two.last_hash)).unwrap();
        assert_eq!(three.last_seq, 3);
        drop(resumed);
        assert_eq!(service(&remote.0).checkpoint(), three);
        assert_eq!(fs::read(local.0.join("orders.ndjson")).unwrap(), preserved);
        assert_eq!(
            fs::read(local.0.join("orders.checkpoint")).unwrap(),
            preserved_anchor
        );
        println!(
            "Witness SIGKILL recovery verified: {}",
            if after_signing {
                "receipt signed but not delivered"
            } else {
                "CAS committed before receipt signing"
            }
        );
    }
}
