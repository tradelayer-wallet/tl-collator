#![cfg(unix)]
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tl_collator_wire::{order_id, tape_entry_hash, tape_signature_hash, verify::Checkpoint};
use tl_witness_service::{Config, WitnessService};

// fork/exec can briefly inherit another test's flock descriptor before exec
// closes it. Serialize this binary's subprocess/lock tests to avoid that race.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
static N: AtomicU64 = AtomicU64::new(0);
struct Tmp(PathBuf);
impl Tmp {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("tl-witness-cas-{}-{now}-{n}", std::process::id()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn tape(&self) -> PathBuf {
        self.0.join("witness.ndjson")
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn pubkey(k: &[u8; 32]) -> String {
    let ctx = Secp256k1::new();
    let sk = SecretKey::from_slice(k).unwrap();
    PublicKey::from_secret_key(&ctx, &sk)
        .serialize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn sign(message_hex: &str, key: &[u8; 32]) -> String {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = u8::from_str_radix(&message_hex[2 * i..2 * i + 2], 16).unwrap();
    }
    Secp256k1::new()
        .sign_ecdsa(
            &Message::from_digest(h),
            &SecretKey::from_slice(key).unwrap(),
        )
        .serialize_compact()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn order(n: u64) -> Value {
    let mut v = json!({
        "v":1,"kind":"NEW",
        "body":{"v":1,"market":"SPOT:LTC/USDT",
          "side":"BUY","px":"72.50","qty":"10.0",
          "visibility":{"kind":"PUBLIC"},"clientTs":1700000000000_u64},
        "traderPubKey":pubkey(&[1u8;32]),"clientNonce":format!("{n:016x}"),
    });
    let hash = order_id(&v).unwrap();
    v["orderId"] = json!(hash);
    v["sigTrader"] = json!(sign(&hash, &[1u8; 32]));
    v
}
fn entry(seq: u64, prev: &str, order: Value) -> String {
    let mut v = json!({"v":1,"collatorId":"collator-test","seq":seq,
        "prevHash":prev,"receivedTs":1700000000010_u64,"order":order});
    let hash = tape_entry_hash(&v).unwrap();
    v["entryHash"] = json!(hash);
    let payload = tape_signature_hash(&v, &hash).unwrap();
    v["sigCollator"] = json!(sign(&payload, &[3u8; 32]));
    v.to_string()
}
fn config(network: &str) -> Config {
    Config {
        collator_id: "collator-test".into(),
        collator_pubkey: pubkey(&[3u8; 32]),
        network: network.into(),
        stream: "orders".into(),
        epoch: 3,
        max_entries: 50,
    }
}
fn open(t: &Tmp) -> WitnessService {
    WitnessService::open(t.path(), config("LTCTEST"), &[5u8; 32]).unwrap()
}
fn challenge() -> String {
    "ab".repeat(32)
}

use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use tl_collator_wire::{canonical_json, sha256_hex};
use tl_witness_service::recovery::{
    export_history, verify_full_recovery, FreshReceipt, RecoveryError, RecoveryExport,
    RecoveryLimits, RecoveryPolicy, REQUEST_DOMAIN,
};
fn limits() -> RecoveryLimits {
    RecoveryLimits {
        max_records: 50,
        max_record_bytes: 1_048_576,
        max_export_bytes: 1_048_576,
        max_scan_bytes: 2_097_152,
        timeout: Duration::from_secs(10),
    }
}
fn policy() -> RecoveryPolicy {
    RecoveryPolicy::new("recovery-operator", &pubkey(&[7; 32]), limits()).unwrap()
}
fn signed_request(cp: &Checkpoint, start: u64, count: u64) -> Value {
    let mut v = json!({"domain":REQUEST_DOMAIN,"v":1,"collatorId":"collator-test",
        "network":"LTCTEST","stream":"orders","epoch":3,"operatorId":"recovery-operator",
        "startSeq":start,"count":count,"checkpointSeq":cp.last_seq,"checkpointHash":cp.last_hash,
        "seenOrders":cp.seen_orders,"challenge":challenge()});
    resign(&mut v, "sigOperator", &[7; 32]);
    v
}
fn resign(v: &mut Value, field: &str, key: &[u8; 32]) {
    v.as_object_mut().unwrap().remove(field);
    let digest = sha256_hex(&canonical_json(v).unwrap());
    v[field] = json!(sign(&digest, key));
}
fn populated(t: &Tmp) -> Checkpoint {
    let mut service = open(t);
    for n in 1..=3 {
        let cp = service.checkpoint();
        service
            .compare_and_swap(&cp, &entry(n, &cp.last_hash, order(n)))
            .unwrap();
    }
    service.checkpoint()
}
fn export(t: &Tmp, cp: &Checkpoint, start: u64, count: u64) -> RecoveryExport {
    export_history(
        t.path(),
        &config("LTCTEST"),
        &[5; 32],
        &policy(),
        &signed_request(cp, start, count).to_string(),
    )
    .unwrap()
}
fn receipt(t: &Tmp) -> String {
    open(t).attest_latest(&"cd".repeat(32)).unwrap()
}
fn verify(
    bundle: &RecoveryExport,
    raw: &str,
    started: Instant,
) -> Result<Checkpoint, RecoveryError> {
    verify_full_recovery(
        bundle,
        &config("LTCTEST"),
        &pubkey(&[5; 32]),
        "recovery-operator",
        &challenge(),
        FreshReceipt {
            raw,
            challenge: &"cd".repeat(32),
            requested_at: started,
            max_age: Duration::from_secs(10),
        },
        &limits(),
    )
}
fn evidence(t: &Tmp) -> Vec<Vec<u8>> {
    [
        "witness.ndjson",
        "witness.checkpoint",
        "witness.scope",
        "witness.lock",
    ]
    .iter()
    .map(|name| fs::read(t.path().join(name)).unwrap())
    .collect()
}
#[test]
fn full_export_and_fresh_independent_receipt_verify_without_writing() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let before = evidence(&t);
    let bundle = export(&t, &cp, 1, 3);
    let started = Instant::now();
    let raw = receipt(&t);
    assert_eq!(verify(&bundle, &raw, started).unwrap(), cp);
    assert_eq!(bundle.ndjson, String::from_utf8(before[0].clone()).unwrap());
    assert_eq!(evidence(&t), before);
}
#[test]
fn exact_partial_range_is_authenticated_but_never_a_full_restore() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let bundle = export(&t, &cp, 2, 1);
    assert_eq!(bundle.ndjson.lines().count(), 1);
    let manifest: Value = serde_json::from_str(&bundle.manifest).unwrap();
    let lines = fs::read_to_string(t.tape()).unwrap();
    let one: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
    assert_eq!(manifest["prevHash"], one["entryHash"]);
    assert!(verify(&bundle, &receipt(&t), Instant::now()).is_err());
}
#[test]
fn unauthorized_tampered_and_latest_capability_requests_cannot_export() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let before = evidence(&t);
    let mut request = signed_request(&cp, 1, 3);
    resign(&mut request, "sigOperator", &[3; 32]); // collator is not recovery operator
    assert!(matches!(
        export_history(
            t.path(),
            &config("LTCTEST"),
            &[5; 32],
            &policy(),
            &request.to_string()
        ),
        Err(RecoveryError::Unauthorized)
    ));
    request = signed_request(&cp, 1, 3);
    request["count"] = json!(1);
    assert!(export_history(
        t.path(),
        &config("LTCTEST"),
        &[5; 32],
        &policy(),
        &request.to_string()
    )
    .is_err());
    request.as_object_mut().unwrap().remove("sigOperator");
    assert!(export_history(
        t.path(),
        &config("LTCTEST"),
        &[5; 32],
        &policy(),
        &request.to_string()
    )
    .is_err());
    assert_eq!(evidence(&t), before);
    let result = Command::new(env!("CARGO_BIN_EXE_witnessctl"))
        .arg("export")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}
#[test]
fn all_request_and_scan_limits_are_enforced() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    for (start, count) in [(0, 1), (1, 0), (1, 51), (3, 2), (9_007_199_254_740_991, 2)] {
        assert!(export_history(
            t.path(),
            &config("LTCTEST"),
            &[5; 32],
            &policy(),
            &signed_request(&cp, start, count).to_string()
        )
        .is_err());
    }
    for caps in [
        RecoveryLimits {
            max_record_bytes: 50,
            ..limits()
        },
        RecoveryLimits {
            max_export_bytes: 200,
            ..limits()
        },
        RecoveryLimits {
            max_scan_bytes: 100,
            ..limits()
        },
        RecoveryLimits {
            timeout: Duration::from_nanos(1),
            ..limits()
        },
    ] {
        let pol = RecoveryPolicy::new("recovery-operator", &pubkey(&[7; 32]), caps).unwrap();
        assert!(export_history(
            t.path(),
            &config("LTCTEST"),
            &[5; 32],
            &pol,
            &signed_request(&cp, 1, 3).to_string()
        )
        .is_err());
    }
    assert!(RecoveryPolicy::new(
        "recovery-operator",
        &pubkey(&[7; 32]),
        RecoveryLimits {
            max_records: 10_001,
            ..limits()
        }
    )
    .is_err());
}
#[test]
fn corrupt_interior_and_torn_tail_refuse_even_an_unaffected_range() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for torn in [false, true] {
        let t = Tmp::new();
        let cp = populated(&t);
        if torn {
            fs::OpenOptions::new()
                .append(true)
                .open(t.tape())
                .unwrap()
                .write_all(b"{torn")
                .unwrap();
        } else {
            let raw = fs::read_to_string(t.tape()).unwrap();
            let mut lines: Vec<String> = raw.lines().map(str::to_owned).collect();
            let mut changed: Value = serde_json::from_str(&lines[1]).unwrap();
            changed["sigCollator"] = json!("11".repeat(64));
            lines[1] = changed.to_string();
            fs::write(t.tape(), format!("{}\n", lines.join("\n"))).unwrap();
        }
        let before = evidence(&t);
        assert!(export_history(
            t.path(),
            &config("LTCTEST"),
            &[5; 32],
            &policy(),
            &signed_request(&cp, 1, 1).to_string()
        )
        .is_err());
        assert_eq!(evidence(&t), before);
    }
}
#[test]
fn missing_span_stale_checkpoint_and_valid_unanchored_append_preserve_evidence() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for variant in 0..3 {
        let t = Tmp::new();
        let cp = populated(&t);
        let raw = fs::read_to_string(t.tape()).unwrap();
        match variant {
            0 => fs::write(
                t.tape(),
                format!("{}\n", raw.lines().take(2).collect::<Vec<_>>().join("\n")),
            )
            .unwrap(),
            1 => {
                let mut anchor: Value =
                    serde_json::from_slice(&fs::read(t.path().join("witness.checkpoint")).unwrap())
                        .unwrap();
                anchor["seq"] = json!(2);
                fs::write(t.path().join("witness.checkpoint"), anchor.to_string()).unwrap();
            }
            _ => {
                fs::OpenOptions::new()
                    .append(true)
                    .open(t.tape())
                    .unwrap()
                    .write_all(format!("{}\n", entry(4, &cp.last_hash, order(4))).as_bytes())
                    .unwrap();
            }
        }
        let before = evidence(&t);
        assert!(export_history(
            t.path(),
            &config("LTCTEST"),
            &[5; 32],
            &policy(),
            &signed_request(&cp, 1, 3).to_string()
        )
        .is_err());
        assert_eq!(evidence(&t), before);
    }
}
#[test]
fn pinned_scope_key_epoch_and_nonexistent_store_fail_without_initialization() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let empty = Tmp::new();
    let genesis = Checkpoint {
        last_seq: 1,
        last_hash: "ab".repeat(32),
        seen_orders: 1,
    };
    assert!(export_history(
        empty.path(),
        &config("LTCTEST"),
        &[5; 32],
        &policy(),
        &signed_request(&genesis, 1, 1).to_string()
    )
    .is_err());
    assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
    let t = Tmp::new();
    let cp = populated(&t);
    let before = evidence(&t);
    for c in [
        config("BTC"),
        Config {
            epoch: 4,
            ..config("LTCTEST")
        },
    ] {
        assert!(export_history(
            t.path(),
            &c,
            &[5; 32],
            &policy(),
            &signed_request(&cp, 1, 3).to_string()
        )
        .is_err());
    }
    assert!(export_history(
        t.path(),
        &config("LTCTEST"),
        &[9; 32],
        &policy(),
        &signed_request(&cp, 1, 3).to_string()
    )
    .is_err());
    assert_eq!(evidence(&t), before);
}
#[test]
fn concurrent_cas_writer_and_export_share_the_existing_os_lock() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let mut service = open(&t);
    assert!(matches!(
        export_history(
            t.path(),
            &config("LTCTEST"),
            &[5; 32],
            &policy(),
            &signed_request(&cp, 1, 3).to_string()
        ),
        Err(RecoveryError::Busy)
    ));
    let advanced = service
        .compare_and_swap(&cp, &entry(4, &cp.last_hash, order(4)))
        .unwrap();
    drop(service);
    assert!(export_history(
        t.path(),
        &config("LTCTEST"),
        &[5; 32],
        &policy(),
        &signed_request(&cp, 1, 3).to_string()
    )
    .is_err());
    assert_eq!(export(&t, &advanced, 1, 4).ndjson.lines().count(), 4);
}
#[test]
fn tampered_manifest_record_range_digest_and_signature_cannot_restore() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let bundle = export(&t, &cp, 1, 3);
    let raw = receipt(&t);
    for field in [
        "digest",
        "operatorId",
        "checkpointHash",
        "finalHash",
        "challenge",
        "sigWitness",
    ] {
        let mut m: Value = serde_json::from_str(&bundle.manifest).unwrap();
        m[field] = json!("ee".repeat(32));
        let changed = RecoveryExport {
            manifest: m.to_string(),
            ndjson: bundle.ndjson.clone(),
        };
        assert!(verify(&changed, &raw, Instant::now()).is_err());
    }
    for data in [
        bundle.ndjson.lines().take(2).collect::<Vec<_>>().join("\n"),
        format!("{}garbage\n", bundle.ndjson),
    ] {
        assert!(verify(
            &RecoveryExport {
                manifest: bundle.manifest.clone(),
                ndjson: data
            },
            &raw,
            Instant::now()
        )
        .is_err());
    }
}
#[test]
fn freshly_signed_bad_history_is_replayed_not_just_digest_checked() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let mut bundle = export(&t, &cp, 1, 3);
    let raw = receipt(&t);
    bundle.ndjson = bundle.ndjson.replace("72.50", "72.51");
    let mut m: Value = serde_json::from_str(&bundle.manifest).unwrap();
    m["digest"] = json!(sha256_hex(&bundle.ndjson));
    resign(&mut m, "sigWitness", &[5; 32]);
    bundle.manifest = m.to_string();
    assert!(verify(&bundle, &raw, Instant::now()).is_err());
}
#[test]
fn receipt_freshness_wrong_scope_prefix_fork_and_newer_head_are_rejected() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let bundle = export(&t, &cp, 1, 3);
    let raw = receipt(&t);
    assert_eq!(
        verify(&bundle, &raw, Instant::now() - Duration::from_secs(11)),
        Err(RecoveryError::Freshness)
    );
    assert_eq!(
        verify(&bundle, &raw, Instant::now() + Duration::from_secs(1)),
        Err(RecoveryError::Freshness)
    );
    for field in ["headHash", "network", "challenge"] {
        let mut r: Value = serde_json::from_str(&raw).unwrap();
        r[field] = json!("ee".repeat(32));
        resign(&mut r, "sigWitness", &[5; 32]);
        assert!(verify(&bundle, &r.to_string(), Instant::now()).is_err());
    }
    let mut service = open(&t);
    service
        .compare_and_swap(&cp, &entry(4, &cp.last_hash, order(4)))
        .unwrap();
    let advanced = service.attest_latest(&"cd".repeat(32)).unwrap();
    assert_eq!(
        verify(&bundle, &advanced, Instant::now()),
        Err(RecoveryError::Checkpoint)
    );
    let replayed = service.attest_latest(&challenge()).unwrap();
    assert!(verify(&bundle, &replayed, Instant::now()).is_err());
}

fn cli(t: &Tmp) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_witness-export"));
    c.env_clear()
        .env("TL_WITNESS_DATA_DIR", t.path())
        .env("TL_WITNESS_KEY_FILE", t.path().join("secret"))
        .env("TL_WITNESS_EXPORT_POLICY", t.path().join("export-policy"))
        .env("TL_WITNESS_COLLATOR_ID", "collator-test")
        .env("TL_WITNESS_COLLATOR_PUBKEY", pubkey(&[3; 32]))
        .env("TL_WITNESS_NETWORK", "LTCTEST")
        .env("TL_WITNESS_STREAM", "orders")
        .env("TL_WITNESS_EPOCH", "3")
        .env("TL_WITNESS_MAX_ENTRIES", "50");
    c
}
fn cli_files(t: &Tmp, timeout: u64) {
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(t.path().join("secret"), "05".repeat(32)).unwrap();
    fs::write(t.path().join("export-policy"),json!({"operatorId":"recovery-operator","operatorPubKey":pubkey(&[7;32]),
        "maxRecords":50,"maxRecordBytes":1_048_576,"maxExportBytes":1_048_576,"maxScanBytes":2_097_152,"timeoutMillis":timeout}).to_string()).unwrap();
    for name in ["secret", "export-policy"] {
        fs::set_permissions(t.path().join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
#[test]
fn separate_cli_requires_restricted_policy_and_signed_request() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    cli_files(&t, 10_000);
    let mut process = cli(&t)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    process
        .stdin
        .take()
        .unwrap()
        .write_all(signed_request(&cp, 1, 3).to_string().as_bytes())
        .unwrap();
    let output = process.wait_with_output().unwrap();
    assert!(output.status.success());
    let raw = String::from_utf8(output.stdout).unwrap();
    let (manifest, ndjson) = raw.split_once('\n').unwrap();
    assert_eq!(
        verify(
            &RecoveryExport {
                manifest: manifest.into(),
                ndjson: ndjson.into()
            },
            &receipt(&t),
            Instant::now()
        )
        .unwrap(),
        cp
    );
    fs::set_permissions(
        t.path().join("export-policy"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let denied = cli(&t).stdin(Stdio::null()).output().unwrap();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    fs::remove_file(t.path().join("export-policy")).unwrap();
    assert!(!cli(&t)
        .stdin(Stdio::null())
        .output()
        .unwrap()
        .status
        .success());
}
#[test]
fn export_watchdog_bounds_blocked_stdin_and_sigkill_preserves_store() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let _cp = populated(&t);
    cli_files(&t, 100);
    let before = evidence(&t);
    let mut process = cli(&t)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = process.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if started.elapsed() > Duration::from_secs(3) {
            let _ = process.kill();
            panic!("watchdog failed");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(evidence(&t), before);
    let mut process = cli(&t)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    process.kill().unwrap();
    process.wait().unwrap();
    assert_eq!(evidence(&t), before);
    assert!(open(&t).checkpoint().last_seq == 3);
}

#[test]
#[cfg(target_os = "linux")]
fn sigkill_during_locked_snapshot_releases_lock_and_never_repairs_evidence() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let mut service = WitnessService::open(
        t.path(),
        Config {
            max_entries: 1000,
            ..config("LTCTEST")
        },
        &[5; 32],
    )
    .unwrap();
    for n in 1..=500 {
        let cp = service.checkpoint();
        service
            .compare_and_swap(&cp, &entry(n, &cp.last_hash, order(n)))
            .unwrap();
    }
    let cp = service.checkpoint();
    drop(service);
    cli_files(&t, 10_000);
    let before = evidence(&t);
    let mut process = cli(&t)
        .env("TL_WITNESS_MAX_ENTRIES", "1000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    process
        .stdin
        .take()
        .unwrap()
        .write_all(signed_request(&cp, 1, 1).to_string().as_bytes())
        .unwrap();
    let started = Instant::now();
    let mut observed = false;
    while started.elapsed() < Duration::from_secs(3) {
        // Observe without acquiring a competing lock: probing with try_lock
        // can itself cause the fail-fast exporter to refuse the snapshot.
        let locks = fs::read_to_string("/proc/locks").unwrap();
        if locks.lines().any(|line| {
            line.split_whitespace()
                .nth(4)
                .and_then(|s| s.parse::<u32>().ok())
                == Some(process.id())
        }) {
            observed = true;
            break;
        }
        if process.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::yield_now();
    }
    let _ = process.kill();
    process.wait().unwrap();
    assert!(observed, "export never acquired the snapshot lock");
    assert_eq!(evidence(&t), before);
    assert_eq!(
        WitnessService::open(
            t.path(),
            Config {
                max_entries: 1000,
                ..config("LTCTEST")
            },
            &[5; 32]
        )
        .unwrap()
        .checkpoint(),
        cp
    );
}

#[test]
fn duplicate_fields_extra_fields_and_symlinks_are_refused() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let request = signed_request(&cp, 1, 3).to_string();
    for raw in [
        request.replacen('{', "{\"count\":3,", 1),
        request.replacen('{', "{\"extra\":1,", 1),
        "x".repeat(8193),
    ] {
        assert!(export_history(t.path(), &config("LTCTEST"), &[5; 32], &policy(), &raw).is_err());
    }
    let original = t.path().join("preserved.ndjson");
    fs::rename(t.tape(), &original).unwrap();
    std::os::unix::fs::symlink(&original, t.tape()).unwrap();
    assert!(export_history(t.path(), &config("LTCTEST"), &[5; 32], &policy(), &request).is_err());
}
