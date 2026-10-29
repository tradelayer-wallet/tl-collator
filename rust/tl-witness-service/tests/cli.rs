#![cfg(unix)]
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
static I: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let n = I.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tl-witnessctl-test-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
        let key = root.join("witness-secret");
        fs::write(&key, "05".repeat(32)).unwrap();
        fs::set_permissions(&key, Permissions::from_mode(0o600)).unwrap();
        Self(root)
    }
    fn public_key() -> String {
        let s = SecretKey::from_slice(&[3u8; 32]).unwrap();
        PublicKey::from_secret_key(&Secp256k1::new(), &s)
            .serialize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_witnessctl"))
            .args(args)
            .env("TL_WITNESS_DATA_DIR", &self.0)
            .env("TL_WITNESS_KEY_FILE", self.0.join("witness-secret"))
            .env("TL_WITNESS_COLLATOR_ID", "collator-test")
            .env("TL_WITNESS_COLLATOR_PUBKEY", Self::public_key())
            .env("TL_WITNESS_NETWORK", "LTCTEST")
            .env("TL_WITNESS_STREAM", "orders")
            .env("TL_WITNESS_EPOCH", "3")
            .env("TL_WITNESS_MAX_ENTRIES", "50")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn one_shot_cli_answers_signed_latest_from_owned_data_directory() {
    let t = Fixture::new();
    let challenge = "ab".repeat(32);
    let output = t.run(&["latest", &challenge]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["seq"], 0);
    assert_eq!(v["network"], "LTCTEST");
    assert_eq!(v["challenge"], challenge);
    assert_eq!(v["sigWitness"].as_str().unwrap().len(), 128);
    assert!(t.0.join("witness.scope").exists());
}
#[test]
fn unrestricted_private_key_file_causes_refusal() {
    let t = Fixture::new();
    fs::set_permissions(t.0.join("witness-secret"), Permissions::from_mode(0o644)).unwrap();
    let output = t.run(&["latest", &"ab".repeat(32)]);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("050505"));
}
#[test]
fn untrusted_directory_or_client_selected_head_cannot_open_witness() {
    let t = Fixture::new();
    fs::set_permissions(&t.0, Permissions::from_mode(0o755)).unwrap();
    assert!(!t.run(&["latest", &"ab".repeat(32)]).status.success());
    fs::set_permissions(&t.0, Permissions::from_mode(0o700)).unwrap();
    assert!(!t
        .run(&["latest", &"ab".repeat(32), "forged-head"])
        .status
        .success());
}
#[test]
fn cas_with_missing_signed_stdin_is_denied_without_advancing_head() {
    let t = Fixture::new();
    let fail = t.run(&["cas", "0", "", "0"]);
    assert!(!fail.status.success());
    let success = t.run(&["latest", &"ab".repeat(32)]);
    assert!(success.status.success());
    let v: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(v["seq"], 0);
}
