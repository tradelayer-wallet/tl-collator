use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tl_collator_wire::{
    durable::{DurableError, DurableTape, ImportMode, WitnessTransport, WitnessTransportError, WitnessedTape},
    order_id, tape_entry_hash, tape_signature_hash,
    verify::Checkpoint,
    witness::{WitnessError, WitnessScope},
};
use tl_witness_service::{Config, WitnessService};

static COUNTER: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "tl-witness-locked-{}-{time}-{n}",
            std::process::id()
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn tape(&self) -> PathBuf {
        self.0.join("orders.ndjson")
    }
    fn anchor(&self) -> PathBuf {
        self.0.join("orders.checkpoint")
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn hex(input: &[u8]) -> String {
    input.iter().map(|b| format!("{b:02x}")).collect()
}
fn key(bytes: &[u8; 32]) -> String {
    let ctx = Secp256k1::new();
    let s = SecretKey::from_slice(bytes).unwrap();
    hex(&PublicKey::from_secret_key(&ctx, &s).serialize())
}
fn signed(hash: &str, seed: &[u8; 32]) -> String {
    let mut digest = [0u8; 32];
    for (i, b) in digest.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hash[2 * i..2 * i + 2], 16).unwrap();
    }
    hex(&Secp256k1::new()
        .sign_ecdsa(
            &Message::from_digest(digest),
            &SecretKey::from_slice(seed).unwrap(),
        )
        .serialize_compact())
}
fn order(n: u64) -> Value {
    let mut v = json!({"v":1,"kind":"NEW","body":{
        "v":1,"market":"SPOT:LTC/USDT","side":"BUY","px":"72.50",
        "qty":"10.0","visibility":{"kind":"PUBLIC"},"clientTs":1700000000000_u64},
        "traderPubKey":key(&[1u8;32]),"clientNonce":format!("{n:016x}")});
    let digest = order_id(&v).unwrap();
    v["orderId"] = json!(digest);
    v["sigTrader"] = json!(signed(&digest, &[1u8; 32]));
    v
}
fn entry(seq: u64, prev: &str, n: u64) -> String {
    let mut v = json!({"v":1,"collatorId":"collator-test","seq":seq,
        "prevHash":prev,"receivedTs":1700000000001_u64,"order":order(n)});
    let hash = tape_entry_hash(&v).unwrap();
    v["entryHash"] = json!(hash);
    let digest = tape_signature_hash(&v, &hash).unwrap();
    v["sigCollator"] = json!(signed(&digest, &[3u8; 32]));
    v.to_string()
}
fn service(directory: &Dir) -> WitnessService {
    WitnessService::open(
        directory.path(),
        Config {
            collator_id: "collator-test".into(),
            network: "LTCTEST".into(),
            stream: "orders".into(),
            epoch: 3,
            collator_pubkey: key(&[3u8; 32]),
            max_entries: 100,
        },
        &[5u8; 32],
    )
    .unwrap()
}
fn scope() -> WitnessScope {
    WitnessScope::new("collator-test", "LTCTEST", "orders", 3, &key(&[5u8; 32])).unwrap()
}
fn open<T: WitnessTransport>(dir: &Dir, remote: T) -> Result<WitnessedTape<T>, DurableError> {
    WitnessedTape::open(
        dir.path(),
        "orders",
        "collator-test",
        &key(&[3u8; 32]),
        100,
        scope(),
        remote,
    )
}
fn local(dir: &Dir) -> DurableTape {
    DurableTape::open(
        dir.path(),
        "orders",
        "collator-test",
        &key(&[3u8; 32]),
        100,
        ImportMode::RequireAnchor,
    )
    .unwrap()
}
struct Unavailable;
impl WitnessTransport for Unavailable {
    fn latest(&mut self, _: &str) -> Result<String, WitnessTransportError> {
        Err(WitnessTransportError::Unavailable)
    }
    fn cas_signed(&mut self, _: &Checkpoint, _: &str, _: &str) -> Result<String, WitnessTransportError> {
        Err(WitnessTransportError::Unavailable)
    }
}
struct DropCas(WitnessService);
impl WitnessTransport for DropCas {
    fn latest(&mut self, c: &str) -> Result<String, WitnessTransportError> {
        self.0.attest_latest(c).map_err(|_| WitnessTransportError::Unavailable)
    }
    fn cas_signed(&mut self, _: &Checkpoint, _: &str, _: &str) -> Result<String, WitnessTransportError> {
        Err(WitnessTransportError::Unavailable)
    }
}
struct LostCasAck(WitnessService);
impl WitnessTransport for LostCasAck {
    fn latest(&mut self, c: &str) -> Result<String, WitnessTransportError> {
        self.0.attest_latest(c).map_err(|_| WitnessTransportError::Unavailable)
    }
    fn cas_signed(&mut self, cp: &Checkpoint, signed: &str, _: &str) -> Result<String, WitnessTransportError> {
        self.0.compare_and_swap(cp, signed).map_err(|_| WitnessTransportError::Unavailable)?;
        Err(WitnessTransportError::Unavailable) // Witness has committed; reply lost
    }
}
#[test]
fn locked_startup_fetches_fresh_head_and_acknowledges_both_stores() {
    let local = Dir::new();
    let remote = Dir::new();
    let mut writer = open(&local, service(&remote)).unwrap();
    let c = writer.append_signed(&entry(1, "", 1001)).unwrap();
    assert_eq!(c.last_seq, 1);
    let second = writer.append_signed(&entry(2, &c.last_hash, 1002)).unwrap();
    assert_eq!(second.last_seq, 2);
    drop(writer);
    let resumed = open(&local, service(&remote)).unwrap();
    assert_eq!(resumed.checkpoint(), second);
    assert_eq!(resumed.recovery().unanchored_records, 0);
}
#[test]
fn privileged_local_rewind_cannot_pass_independent_latest() {
    let localdir = Dir::new();
    let remotedir = Dir::new();
    let mut w = open(&localdir, service(&remotedir)).unwrap();
    let c1 = w.append_signed(&entry(1, "", 1101)).unwrap();
    let previous_tape = fs::read(localdir.tape()).unwrap();
    let previous_anchor = fs::read(localdir.anchor()).unwrap();
    w.append_signed(&entry(2, &c1.last_hash, 1102)).unwrap();
    drop(w);
    fs::write(localdir.tape(), &previous_tape).unwrap();
    fs::write(localdir.anchor(), &previous_anchor).unwrap();
    let before = fs::read(localdir.tape()).unwrap();
    assert!(matches!(
        open(&localdir, service(&remotedir)),
        Err(DurableError::Witness(WitnessError::Rollback))
    ));
    assert_eq!(fs::read(localdir.tape()).unwrap(), before);
}
#[test]
fn signed_fork_with_same_seq_fails_before_repair() {
    let localdir = Dir::new();
    let remotedir = Dir::new();
    let mut remote = service(&remotedir);
    let genesis = remote.checkpoint();
    remote
        .compare_and_swap(&genesis, &entry(1, "", 1201))
        .unwrap();
    drop(remote);
    let mut local = local(&localdir);
    local.append_signed(&entry(1, "", 1202)).unwrap();
    drop(local);
    let original = fs::read(localdir.tape()).unwrap();
    assert!(matches!(
        open(&localdir, service(&remotedir)),
        Err(DurableError::Witness(WitnessError::Fork))
    ));
    assert_eq!(fs::read(localdir.tape()).unwrap(), original);
}
#[test]
fn unreachable_witness_refuses_writes_at_startup() {
    let dir = Dir::new();
    assert!(matches!(
        open(&dir, Unavailable),
        Err(DurableError::RemoteUncertain)
    ));
    assert!(!dir.anchor().exists());
}
#[test]
fn lost_remote_ack_poisons_writer_without_local_append() {
    let localdir = Dir::new();
    let remotedir = Dir::new();
    let mut w = open(&localdir, LostCasAck(service(&remotedir))).unwrap();
    let first = entry(1, "", 1301);
    assert!(matches!(
        w.append_signed(&first),
        Err(DurableError::RemoteUncertain)
    ));
    assert!(w.is_blocked());
    assert!(matches!(
        w.append_signed(&first),
        Err(DurableError::NeedsRecovery)
    ));
    assert_eq!(w.checkpoint().last_seq, 0);
    drop(w);
    assert!(matches!(
        open(&localdir, service(&remotedir)),
        Err(DurableError::Witness(WitnessError::Rollback))
    ));
}
#[test]
fn failing_cas_cannot_fall_back_to_unwitnessed_append() {
    let localdir = Dir::new();
    let remotedir = Dir::new();
    let mut w = open(&localdir, DropCas(service(&remotedir))).unwrap();
    let first = entry(1, "", 1401);
    assert!(matches!(
        w.append_signed(&first),
        Err(DurableError::RemoteUncertain)
    ));
    assert_eq!(w.checkpoint().last_seq, 0);
    assert_eq!(fs::metadata(localdir.tape()).unwrap().len(), 0);
}
#[test]
fn honest_remote_ahead_is_required_even_for_torn_tail_repair() {
    let localdir = Dir::new();
    let remotedir = Dir::new();
    let mut w = open(&localdir, service(&remotedir)).unwrap();
    let cp = w.append_signed(&entry(1, "", 1501)).unwrap();
    drop(w);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(localdir.tape())
        .unwrap();
    file.write_all(b"{\"unacknowledged\":").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let resumed = open(&localdir, service(&remotedir)).unwrap();
    assert_eq!(resumed.checkpoint(), cp);
    assert!(resumed.recovery().torn_tail_bytes > 0);
}
#[test]
fn local_ahead_of_remote_cannot_start() {
    let localdir = Dir::new();
    let remotedir = Dir::new();
    let mut l = local(&localdir);
    l.append_signed(&entry(1, "", 1601)).unwrap();
    drop(l);
    assert!(matches!(
        open(&localdir, service(&remotedir)),
        Err(DurableError::AheadOfWitness)
    ));
}
#[test]
fn remote_wrong_network_scope_is_rejected_before_mutation() {
    let localdir = Dir::new();
    let remotedir = Dir::new();
    let remote = service(&remotedir);
    let wrong = WitnessScope::new("collator-test", "BTC", "orders", 3, &key(&[5u8; 32])).unwrap();
    assert!(matches!(
        WitnessedTape::open(
            localdir.path(),
            "orders",
            "collator-test",
            &key(&[3u8; 32]),
            100,
            wrong,
            remote
        ),
        Err(DurableError::Witness(WitnessError::WrongScope))
    ));
    assert!(!localdir.anchor().exists());
}
