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
    export_history, verify_full_recovery, FreshReceipt, PagedRecovery, RecoveryError,
    RecoveryExport, RecoveryLimits, RecoveryPolicy, RecoverySessionLimits, REQUEST_DOMAIN,
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

#[test]
fn lost_ack_recovery_drill_preserves_failed_tape_and_resumes_only_a_new_verified_store() {
    use tl_collator_wire::{
        durable::{
            DurableError, DurableTape, ImportMode, WitnessTransport, WitnessTransportError,
            WitnessedTape,
        },
        witness::{WitnessError, WitnessScope},
    };
    struct LostAck(WitnessService);
    impl WitnessTransport for LostAck {
        fn latest(&mut self, challenge: &str) -> Result<String, WitnessTransportError> {
            self.0.latest(challenge)
        }
        fn cas_signed(
            &mut self,
            before: &Checkpoint,
            entry: &str,
            _challenge: &str,
        ) -> Result<String, WitnessTransportError> {
            self.0
                .compare_and_swap(before, entry)
                .map_err(|_| WitnessTransportError::Unavailable)?;
            Err(WitnessTransportError::Unavailable)
        }
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let failed = Tmp::new();
    let remote = Tmp::new();
    let restored = Tmp::new();
    let witness_scope =
        || WitnessScope::new("collator-test", "LTCTEST", "orders", 3, &pubkey(&[5; 32])).unwrap();
    let mut writer = WitnessedTape::open(
        failed.path(),
        "orders",
        "collator-test",
        &pubkey(&[3; 32]),
        50,
        witness_scope(),
        LostAck(open(&remote)),
    )
    .unwrap();
    assert!(matches!(
        writer.append_signed(&entry(1, "", order(101))),
        Err(DurableError::RemoteUncertain)
    ));
    assert!(writer.is_blocked());
    assert_eq!(writer.checkpoint().last_seq, 0);
    drop(writer);
    let old_tape = fs::read(failed.path().join("orders.ndjson")).unwrap();
    let old_anchor = fs::read(failed.path().join("orders.checkpoint")).unwrap();
    let committed = open(&remote).checkpoint();
    assert_eq!(committed.last_seq, 1);
    assert!(matches!(
        WitnessedTape::open(
            failed.path(),
            "orders",
            "collator-test",
            &pubkey(&[3; 32]),
            50,
            witness_scope(),
            open(&remote)
        ),
        Err(DurableError::Witness(WitnessError::Rollback))
    ));
    let bundle = export(&remote, &committed, 1, 1);
    let started = Instant::now();
    let fresh = receipt(&remote);
    let approved_checkpoint = verify(&bundle, &fresh, started).unwrap();
    assert_eq!(approved_checkpoint, committed);
    // Synthetic drill models the explicit operator's approval of this exact
    // checkpoint and NEW destination. No recovery API writes or repairs it.
    assert_eq!(fs::read_dir(restored.path()).unwrap().count(), 0);
    fs::set_permissions(restored.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let restored_tape = restored.path().join("orders.ndjson");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&restored_tape)
        .unwrap();
    fs::set_permissions(&restored_tape, fs::Permissions::from_mode(0o600)).unwrap();
    file.write_all(bundle.ndjson.as_bytes()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let imported = DurableTape::open(
        restored.path(),
        "orders",
        "collator-test",
        &pubkey(&[3; 32]),
        50,
        ImportMode::ExplicitVerifiedImport,
    )
    .unwrap();
    assert_eq!(imported.checkpoint(), approved_checkpoint);
    drop(imported);
    // Startup obtains another independently challenge-bound receipt under its
    // own lock before accepting the imported store or any resumed append.
    let mut resumed = WitnessedTape::open(
        restored.path(),
        "orders",
        "collator-test",
        &pubkey(&[3; 32]),
        50,
        witness_scope(),
        open(&remote),
    )
    .unwrap();
    assert_eq!(resumed.checkpoint(), approved_checkpoint);
    let next = resumed
        .append_signed(&entry(2, &approved_checkpoint.last_hash, order(102)))
        .unwrap();
    assert_eq!(next.last_seq, 2);
    drop(resumed);
    assert_eq!(open(&remote).checkpoint(), next);
    assert_eq!(
        fs::read(failed.path().join("orders.ndjson")).unwrap(),
        old_tape
    );
    assert_eq!(
        fs::read(failed.path().join("orders.checkpoint")).unwrap(),
        old_anchor
    );
}

fn session_limits() -> RecoverySessionLimits {
    RecoverySessionLimits {
        max_pages: 10,
        max_total_export_bytes: 2_097_152,
        timeout: Duration::from_secs(60),
    }
}
fn page(t: &Tmp, cp: &Checkpoint, start: u64, count: u64, nonce: u64) -> RecoveryExport {
    let mut request = signed_request(cp, start, count);
    request["challenge"] = json!(format!("{nonce:064x}"));
    resign(&mut request, "sigOperator", &[7; 32]);
    export_history(
        t.path(),
        &config("LTCTEST"),
        &[5; 32],
        &policy(),
        &request.to_string(),
    )
    .unwrap()
}
fn receipt_for(raw: &str) -> FreshReceipt<'_> {
    FreshReceipt {
        raw,
        challenge: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        requested_at: Instant::now(),
        max_age: Duration::from_secs(10),
    }
}
#[test]
fn paged_recovery_exceeds_one_response_without_relaxing_response_caps() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let before = evidence(&t);
    let pages: Vec<_> = (1..=3).map(|n| page(&t, &cp, n, 1, n)).collect();
    let maximum = pages
        .iter()
        .map(|p| p.manifest.len() + 1 + p.ndjson.len())
        .max()
        .unwrap();
    let total = pages
        .iter()
        .map(|p| (p.manifest.len() + 1 + p.ndjson.len()) as u64)
        .sum();
    let caps = RecoveryLimits {
        max_records: 1,
        max_export_bytes: maximum,
        ..limits()
    };
    let full = export(&t, &cp, 1, 3);
    assert!(full.manifest.len() + 1 + full.ndjson.len() > maximum);
    let configuration = config("LTCTEST");
    let mut verifier = PagedRecovery::new(
        &configuration,
        &pubkey(&[5; 32]),
        "recovery-operator",
        cp.clone(),
        caps,
        RecoverySessionLimits {
            max_pages: 3,
            max_total_export_bytes: total,
            ..session_limits()
        },
    )
    .unwrap();
    for (i, p) in pages.iter().enumerate() {
        verifier.accept_page(p, &format!("{:064x}", i + 1)).unwrap();
    }
    let raw = receipt(&t);
    assert_eq!(verifier.finish(receipt_for(&raw)).unwrap(), cp);
    assert_eq!(evidence(&t), before);
}
#[test]
fn paged_recovery_refuses_missing_reordered_overlapping_or_replayed_pages() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let configuration = config("LTCTEST");
    let first = page(&t, &cp, 1, 1, 1);
    let second = page(&t, &cp, 2, 1, 2);
    let third = page(&t, &cp, 3, 1, 3);
    let overlap = page(&t, &cp, 1, 1, 4);
    let reused = page(&t, &cp, 2, 1, 1);
    for sequence in [
        vec![(&second, 2)],
        vec![(&first, 1), (&third, 3)],
        vec![(&first, 1), (&overlap, 4)],
        vec![(&first, 1), (&reused, 1)],
    ] {
        let mut verifier = PagedRecovery::new(
            &configuration,
            &pubkey(&[5; 32]),
            "recovery-operator",
            cp.clone(),
            limits(),
            session_limits(),
        )
        .unwrap();
        let mut refused = false;
        for (p, n) in sequence {
            if verifier.accept_page(p, &format!("{n:064x}")).is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused);
        assert!(verifier.is_blocked());
        assert!(verifier
            .accept_page(&second, &format!("{:064x}", 2))
            .is_err());
        assert!(verifier.finish(receipt_for(&receipt(&t))).is_err());
    }
    for count in 0..=2 {
        let mut verifier = PagedRecovery::new(
            &configuration,
            &pubkey(&[5; 32]),
            "recovery-operator",
            cp.clone(),
            limits(),
            session_limits(),
        )
        .unwrap();
        for (p, n) in [(&first, 1), (&second, 2)].iter().take(count) {
            verifier.accept_page(p, &format!("{n:064x}")).unwrap();
        }
        assert_eq!(
            verifier.finish(receipt_for(&receipt(&t))),
            Err(RecoveryError::Checkpoint)
        );
    }
}
#[test]
fn partial_page_replay_failure_permanently_blocks_finalization() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let configuration = config("LTCTEST");
    let mut bad = page(&t, &cp, 2, 2, 2);
    let mut lines: Vec<_> = bad.ndjson.lines().map(str::to_owned).collect();
    lines[1] = lines[1].replace("72.50", "72.51");
    bad.ndjson = lines.join("\n") + "\n";
    let mut manifest: Value = serde_json::from_str(&bad.manifest).unwrap();
    manifest["digest"] = json!(sha256_hex(&bad.ndjson));
    resign(&mut manifest, "sigWitness", &[5; 32]);
    bad.manifest = manifest.to_string();
    let mut verifier = PagedRecovery::new(
        &configuration,
        &pubkey(&[5; 32]),
        "recovery-operator",
        cp.clone(),
        limits(),
        session_limits(),
    )
    .unwrap();
    verifier
        .accept_page(&page(&t, &cp, 1, 1, 1), &format!("{:064x}", 1))
        .unwrap();
    assert_eq!(
        verifier.accept_page(&bad, &format!("{:064x}", 2)),
        Err(RecoveryError::Corrupt)
    );
    assert!(verifier.is_blocked());
    assert!(verifier
        .accept_page(&page(&t, &cp, 2, 2, 3), &format!("{:064x}", 3))
        .is_err());
    assert!(verifier.finish(receipt_for(&receipt(&t))).is_err());
}
#[test]
fn paged_recovery_binds_one_checkpoint_and_requires_a_new_final_receipt() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let configuration = config("LTCTEST");
    let first = page(&t, &cp, 1, 1, 1);
    let rest = page(&t, &cp, 2, 2, 2);
    let make = || {
        PagedRecovery::new(
            &configuration,
            &pubkey(&[5; 32]),
            "recovery-operator",
            cp.clone(),
            limits(),
            session_limits(),
        )
        .unwrap()
    };
    let mut verifier = make();
    verifier
        .accept_page(&first, &format!("{:064x}", 1))
        .unwrap();
    verifier.accept_page(&rest, &format!("{:064x}", 2)).unwrap();
    let nonce = format!("{:064x}", 1);
    let raw = open(&t).attest_latest(&nonce).unwrap();
    assert_eq!(
        verifier.finish(FreshReceipt {
            raw: &raw,
            challenge: &nonce,
            requested_at: Instant::now(),
            max_age: Duration::from_secs(10)
        }),
        Err(RecoveryError::Freshness)
    );
    let mut old = make();
    old.accept_page(&first, &format!("{:064x}", 1)).unwrap();
    old.accept_page(&rest, &format!("{:064x}", 2)).unwrap();
    let mut service = open(&t);
    let advanced = service
        .compare_and_swap(&cp, &entry(4, &cp.last_hash, order(4)))
        .unwrap();
    drop(service);
    assert_eq!(
        old.finish(receipt_for(&receipt(&t))),
        Err(RecoveryError::Checkpoint)
    );
    let mut mixed = make();
    mixed.accept_page(&first, &format!("{:064x}", 1)).unwrap();
    assert_eq!(
        mixed.accept_page(&page(&t, &advanced, 2, 3, 3), &format!("{:064x}", 3)),
        Err(RecoveryError::Checkpoint)
    );
    assert!(mixed.is_blocked());
}
#[test]
fn paged_recovery_bounds_aggregate_bytes_pages_records_and_elapsed_time() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let cp = populated(&t);
    let configuration = config("LTCTEST");
    let pages: Vec<_> = (1..=3).map(|n| page(&t, &cp, n, 1, n)).collect();
    let total: u64 = pages
        .iter()
        .map(|p| (p.manifest.len() + 1 + p.ndjson.len()) as u64)
        .sum();
    for caps in [
        RecoverySessionLimits {
            max_pages: 2,
            ..session_limits()
        },
        RecoverySessionLimits {
            max_total_export_bytes: total - 1,
            ..session_limits()
        },
    ] {
        let mut verifier = PagedRecovery::new(
            &configuration,
            &pubkey(&[5; 32]),
            "recovery-operator",
            cp.clone(),
            limits(),
            caps,
        )
        .unwrap();
        for (i, p) in pages.iter().take(2).enumerate() {
            verifier.accept_page(p, &format!("{:064x}", i + 1)).unwrap();
        }
        assert_eq!(
            verifier.accept_page(&pages[2], &format!("{:064x}", 3)),
            Err(RecoveryError::Limit)
        );
        assert!(verifier.is_blocked());
    }
    let mut timed = PagedRecovery::new(
        &configuration,
        &pubkey(&[5; 32]),
        "recovery-operator",
        cp.clone(),
        limits(),
        RecoverySessionLimits {
            timeout: Duration::from_nanos(1),
            ..session_limits()
        },
    )
    .unwrap();
    assert_eq!(
        timed.accept_page(&pages[0], &format!("{:064x}", 1)),
        Err(RecoveryError::Deadline)
    );
    let mut record = PagedRecovery::new(
        &configuration,
        &pubkey(&[5; 32]),
        "recovery-operator",
        cp,
        RecoveryLimits {
            max_record_bytes: 32,
            ..limits()
        },
        session_limits(),
    )
    .unwrap();
    assert_eq!(
        record.accept_page(&pages[0], &format!("{:064x}", 1)),
        Err(RecoveryError::Limit)
    );
    for caps in [
        RecoverySessionLimits {
            max_pages: 10_001,
            ..session_limits()
        },
        RecoverySessionLimits {
            max_total_export_bytes: 1_073_741_825,
            ..session_limits()
        },
        RecoverySessionLimits {
            timeout: Duration::from_secs(86_401),
            ..session_limits()
        },
    ] {
        assert!(caps.validate().is_err());
    }
}

#[test]
fn complete_history_larger_than_ten_thousand_records_recovers_in_bounded_pages() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let configuration = Config {
        max_entries: 20_000,
        ..config("LTCTEST")
    };
    drop(
        WitnessService::open(
            t.path(),
            Config {
                max_entries: 20_000,
                ..config("LTCTEST")
            },
            &[5; 32],
        )
        .unwrap(),
    );
    let mut tape = String::new();
    let mut final_hash = String::new();
    for n in 1..=10_001 {
        let line = entry(n, &final_hash, order(n));
        let value: Value = serde_json::from_str(&line).unwrap();
        final_hash = value["entryHash"].as_str().unwrap().into();
        tape.push_str(&line);
        tape.push('\n');
    }
    fs::write(t.tape(), tape).unwrap();
    let target = Checkpoint {
        last_seq: 10_001,
        last_hash: final_hash,
        seen_orders: 10_001,
    };
    fs::write(t.path().join("witness.checkpoint"),json!({"version":1,"seq":target.last_seq,"hash":target.last_hash,"orders":target.seen_orders}).to_string()).unwrap();
    let caps = RecoveryLimits {
        max_records: 10_000,
        max_export_bytes: 16 * 1024 * 1024,
        max_scan_bytes: 32 * 1024 * 1024,
        timeout: Duration::from_secs(60),
        ..limits()
    };
    let policy = RecoveryPolicy::new("recovery-operator", &pubkey(&[7; 32]), caps.clone()).unwrap();
    assert!(matches!(
        export_history(
            t.path(),
            &configuration,
            &[5; 32],
            &policy,
            &signed_request(&target, 1, 10_001).to_string()
        ),
        Err(RecoveryError::Limit)
    ));
    let mut verifier = PagedRecovery::new(
        &configuration,
        &pubkey(&[5; 32]),
        "recovery-operator",
        target.clone(),
        caps,
        RecoverySessionLimits {
            max_pages: 2,
            max_total_export_bytes: 32 * 1024 * 1024,
            timeout: Duration::from_secs(120),
        },
    )
    .unwrap();
    for (start, count, nonce) in [(1, 5000, 1), (5001, 5001, 2)] {
        let mut request = signed_request(&target, start, count);
        request["challenge"] = json!(format!("{nonce:064x}"));
        resign(&mut request, "sigOperator", &[7; 32]);
        let bundle = export_history(
            t.path(),
            &configuration,
            &[5; 32],
            &policy,
            &request.to_string(),
        )
        .unwrap();
        verifier
            .accept_page(&bundle, &format!("{nonce:064x}"))
            .unwrap();
    }
    let started = Instant::now();
    let raw = WitnessService::open(
        t.path(),
        Config {
            max_entries: 20_000,
            ..config("LTCTEST")
        },
        &[5; 32],
    )
    .unwrap()
    .attest_latest(&"cd".repeat(32))
    .unwrap();
    assert_eq!(
        verifier
            .finish(FreshReceipt {
                raw: &raw,
                challenge: &"cd".repeat(32),
                requested_at: started,
                max_age: Duration::from_secs(30)
            })
            .unwrap(),
        target
    );
}

#[test]
fn paged_replay_keeps_order_ownership_across_page_boundaries() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let mut service = open(&t);
    let original = order(1);
    let target = original["orderId"].as_str().unwrap().to_owned();
    let one = service
        .compare_and_swap(&service.checkpoint(), &entry(1, "", original))
        .unwrap();
    let mut cancel = order(2);
    cancel["kind"] = json!("CANCEL");
    cancel["cancelsOrderId"] = json!(target);
    cancel.as_object_mut().unwrap().remove("orderId");
    cancel.as_object_mut().unwrap().remove("sigTrader");
    let digest = order_id(&cancel).unwrap();
    cancel["orderId"] = json!(digest);
    cancel["sigTrader"] = json!(sign(&digest, &[1; 32]));
    let cp = service
        .compare_and_swap(&one, &entry(2, &one.last_hash, cancel))
        .unwrap();
    drop(service);
    let configuration = config("LTCTEST");
    let mut verifier = PagedRecovery::new(
        &configuration,
        &pubkey(&[5; 32]),
        "recovery-operator",
        cp.clone(),
        limits(),
        session_limits(),
    )
    .unwrap();
    verifier
        .accept_page(&page(&t, &cp, 1, 1, 1), &format!("{:064x}", 1))
        .unwrap();
    verifier
        .accept_page(&page(&t, &cp, 2, 1, 2), &format!("{:064x}", 2))
        .unwrap();
    assert_eq!(verifier.finish(receipt_for(&receipt(&t))).unwrap(), cp);
}
