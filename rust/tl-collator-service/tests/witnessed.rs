#![cfg(unix)]
//! `WitnessedSignedTape` against a real `WitnessService` (separate directory and key):
//! appends only after the durable commit, refusal on rollback/fork/outage, serve gate.
mod common;
use common::*;
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use tl_collator_service::signer::SecretKeySigner;
use tl_collator_service::tape::{DurableSignedTape, MemoryTape, TapeError, TapeStore};
use tl_collator_service::witnessed::{
    Judgement, OpenError, ServeState, WitnessPin, WitnessedOpen, WitnessedSignedTape,
};
use tl_collator_service::{HostSession, Out, Service, ServiceParts};
use tl_collator_wire::durable::{DurableTape, ImportMode, WitnessTransport, WitnessTransportError};
use tl_collator_wire::verify::Checkpoint;
use tl_witness_service::{Config as WitnessConfig, WitnessService};

const NETWORK_NAME: &str = "ltc-testnet";
const STREAM: &str = "orders";
const CH1: &str = "abababababababababababababababababababababababababababababababab";
const CH2: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("tl-witnessed-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Up,
    Down,
    /// The witness commits, the reply is lost.
    LoseAck,
}

struct Remote {
    svc: Rc<RefCell<WitnessService>>,
    mode: Rc<Cell<Mode>>,
}

impl WitnessTransport for Remote {
    fn latest(&mut self, challenge: &str) -> Result<String, WitnessTransportError> {
        if self.mode.get() == Mode::Down {
            return Err(WitnessTransportError::Unavailable);
        }
        self.svc
            .borrow()
            .attest_latest(challenge)
            .map_err(|_| WitnessTransportError::Unavailable)
    }
    fn cas_signed(
        &mut self,
        expected: &Checkpoint,
        signed_entry: &str,
        challenge: &str,
    ) -> Result<String, WitnessTransportError> {
        match self.mode.get() {
            Mode::Down => Err(WitnessTransportError::Unavailable),
            Mode::LoseAck => {
                let _ = self
                    .svc
                    .borrow_mut()
                    .compare_and_swap(expected, signed_entry);
                Err(WitnessTransportError::Unavailable)
            }
            Mode::Up => {
                self.svc
                    .borrow_mut()
                    .compare_and_swap(expected, signed_entry)
                    .map_err(|_| WitnessTransportError::Unavailable)?;
                self.svc
                    .borrow()
                    .attest_latest(challenge)
                    .map_err(|_| WitnessTransportError::Unavailable)
            }
        }
    }
}

type Tape = WitnessedSignedTape<SecretKeySigner, Remote>;

struct World {
    tdir: Dir,
    _wdir: Dir,
    svc: Rc<RefCell<WitnessService>>,
    mode: Rc<Cell<Mode>>,
    pin: WitnessPin,
}

fn witness_config() -> WitnessConfig {
    WitnessConfig {
        collator_id: COLLATOR.into(),
        collator_pubkey: secret(3).public_key_hex(),
        network: NETWORK_NAME.into(),
        stream: STREAM.into(),
        epoch: 1,
        max_entries: 256,
    }
}

impl World {
    fn new(tag: &str) -> World {
        let wdir = Dir::new(&format!("{tag}-w"));
        let svc = WitnessService::open(wdir.path(), witness_config(), &[9u8; 32]).unwrap();
        let pin = WitnessPin {
            collator_id: COLLATOR.into(),
            network: NETWORK_NAME.into(),
            stream: STREAM.into(),
            epoch: 1,
            witness_pubkey_hex: svc.public_key().to_owned(),
        };
        World {
            tdir: Dir::new(&format!("{tag}-t")),
            _wdir: wdir,
            svc: Rc::new(RefCell::new(svc)),
            mode: Rc::new(Cell::new(Mode::Up)),
            pin,
        }
    }

    fn remote(&self) -> Remote {
        Remote {
            svc: self.svc.clone(),
            mode: self.mode.clone(),
        }
    }

    fn open_with(&self, pin: &WitnessPin) -> Result<Tape, OpenError> {
        let pubkey = secret(3).public_key_hex();
        WitnessedSignedTape::open(
            &WitnessedOpen {
                directory: self.tdir.path(),
                stem: STREAM,
                collator_id: COLLATOR,
                collator_pubkey_hex: &pubkey,
                max_entries: 256,
                pin,
            },
            secret(3),
            self.remote(),
        )
    }

    fn open(&self) -> Tape {
        self.open_with(&self.pin).expect("open")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.tdir.path().join(name)
    }
}

fn refused(r: Result<Tape, OpenError>) -> Judgement {
    match r {
        Err(OpenError::Refused(j)) => j,
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("expected a refusal, but the tape opened"),
    }
}

fn fill(t: &mut Tape, n: std::ops::RangeInclusive<u64>) {
    for k in n {
        let e = t.append_order(&new_order(21, k), T0 + k).unwrap();
        assert_eq!(e.seq, k);
    }
}

/// The signed lines a `MemoryTape` produces for these orders (deterministic signatures, so
/// identical to the adapter's lines for identical orders and timestamps).
fn history(trader: u8, count: u64) -> Vec<String> {
    let mut m = MemoryTape::new(COLLATOR, &secret(3).public_key_hex(), secret(3), 256).unwrap();
    (1..=count)
        .map(|k| m.append_order(&new_order(trader, k), T0 + k).unwrap().line)
        .collect()
}

#[test]
fn appends_reads_checkpoint_and_restart() {
    let w = World::new("basic");
    {
        let mut t = w.open();
        assert!(t.is_serving());
        assert_eq!(t.judgement(), Judgement::Ok);
        fill(&mut t, 1..=4);
        assert_eq!(t.last_seq(), 4);
        let cp = t.checkpoint();
        assert_eq!(cp.last_seq, 4);
        assert_eq!(cp.seen_orders, 4);
        assert_eq!(w.svc.borrow().checkpoint(), cp, "witness and tape agree");
        assert!(t.contains_order(new_order(21, 2)["orderId"].as_str().unwrap()));
        let r = t.read_range(2, 2).unwrap();
        assert_eq!(r.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);
        assert!(t.read_range(9, 5).unwrap().is_empty());

        // Refusals do not touch the witness.
        assert_eq!(
            t.append_order(&new_order(21, 2), T0 + 9),
            Err(TapeError::Duplicate)
        );
        let target = new_order(21, 1)["orderId"].as_str().unwrap().to_owned();
        let theirs = order(22, 50, "CANCEL", Some(&target), json!({"kind":"PUBLIC"}));
        assert_eq!(t.precheck(&theirs), Err(TapeError::NotOwner));
        assert_eq!(t.append_order(&theirs, T0 + 10), Err(TapeError::NotOwner));
        let ghost = order(
            21,
            51,
            "CANCEL",
            Some(&"0".repeat(64)),
            json!({"kind":"PUBLIC"}),
        );
        assert_eq!(
            t.append_order(&ghost, T0 + 10),
            Err(TapeError::UnknownOrder)
        );
        assert_eq!(w.svc.borrow().checkpoint().last_seq, 4);
        assert!(t.is_serving());

        // A fresh receipt under a fresh challenge is judged Ok.
        let receipt = w.svc.borrow().attest_latest(CH1).unwrap();
        assert_eq!(t.recheck(&receipt, CH1), Judgement::Ok);
        assert!(t.is_serving());
    }
    let mut t = w.open();
    assert_eq!(t.last_seq(), 4);
    assert_eq!(t.append_order(&new_order(21, 5), T0 + 20).unwrap().seq, 5);
    assert_eq!(t.read_range(1, 100).unwrap().len(), 5);
    assert_eq!(w.svc.borrow().checkpoint().last_seq, 5);
}

#[test]
fn a_restored_older_tape_is_a_rollback_and_refuses_to_open() {
    let w = World::new("rollback");
    let tape_file = w.file("orders.ndjson");
    let anchor = w.file("orders.checkpoint");
    let (old_tape, old_anchor);
    {
        let mut t = w.open();
        fill(&mut t, 1..=2);
        old_tape = std::fs::read(&tape_file).unwrap();
        old_anchor = std::fs::read(&anchor).unwrap();
        fill(&mut t, 3..=4);
    }
    // A privileged rollback of both the tape and its local anchor: only the witness notices.
    std::fs::write(&tape_file, old_tape).unwrap();
    std::fs::write(&anchor, old_anchor).unwrap();
    assert_eq!(refused(w.open_with(&w.pin)), Judgement::Rollback);
    assert_eq!(
        w.svc.borrow().checkpoint().last_seq,
        4,
        "the witness never regresses"
    );
}

#[test]
fn an_alternative_signed_history_is_a_fork_and_refuses_to_open() {
    let w = World::new("fork");
    {
        let mut t = w.open();
        fill(&mut t, 1..=4);
    }
    // A complete, validly signed history of the same length by other traders.
    let alt = Dir::new("fork-alt");
    {
        let tape = DurableTape::open(
            alt.path(),
            STREAM,
            COLLATOR,
            &secret(3).public_key_hex(),
            256,
            ImportMode::RequireAnchor,
        )
        .unwrap();
        let mut plain =
            DurableSignedTape::new(COLLATOR, secret(3), tape, alt.path().join("orders.ndjson"));
        for k in 1..=4 {
            plain.append_order(&new_order(30, k), T0 + k).unwrap();
        }
    }
    std::fs::copy(alt.path().join("orders.ndjson"), w.file("orders.ndjson")).unwrap();
    std::fs::copy(
        alt.path().join("orders.checkpoint"),
        w.file("orders.checkpoint"),
    )
    .unwrap();
    assert_eq!(refused(w.open_with(&w.pin)), Judgement::Fork);
}

#[test]
fn an_unwitnessed_local_head_is_refused() {
    let w = World::new("ahead");
    {
        let mut t = w.open();
        fill(&mut t, 1..=2);
    }
    {
        // A local-only writer (the explicit offline API) extends the tape past the witness.
        let tape = DurableTape::open(
            w.tdir.path(),
            STREAM,
            COLLATOR,
            &secret(3).public_key_hex(),
            256,
            ImportMode::RequireAnchor,
        )
        .unwrap();
        let mut plain = DurableSignedTape::new(COLLATOR, secret(3), tape, w.file("orders.ndjson"));
        plain.append_order(&new_order(21, 3), T0 + 3).unwrap();
    }
    assert_eq!(refused(w.open_with(&w.pin)), Judgement::AheadOfWitness);
}

#[test]
fn wrong_pins_and_an_unreachable_witness_refuse_to_open() {
    let w = World::new("pins");
    {
        let mut t = w.open();
        fill(&mut t, 1..=1);
    }
    let mut epoch = w.pin.clone();
    epoch.epoch = 2;
    assert_eq!(refused(w.open_with(&epoch)), Judgement::WrongScope);

    let mut net = w.pin.clone();
    net.network = "ltc-mainnet".into();
    assert_eq!(refused(w.open_with(&net)), Judgement::WrongScope);

    let mut key = w.pin.clone();
    key.witness_pubkey_hex = secret(10).public_key_hex();
    assert_eq!(refused(w.open_with(&key)), Judgement::BadSignature);

    // The witness cannot be the collator's own key.
    let mut same = w.pin.clone();
    same.witness_pubkey_hex = secret(3).public_key_hex();
    assert_eq!(refused(w.open_with(&same)), Judgement::Invalid);

    let mut id = w.pin.clone();
    id.collator_id = "other".into();
    assert!(matches!(w.open_with(&id), Err(OpenError::Config(_))));

    w.mode.set(Mode::Down);
    assert_eq!(refused(w.open_with(&w.pin)), Judgement::Uncertain);
    w.mode.set(Mode::Up);
    assert_eq!(
        w.open().last_seq(),
        1,
        "no local-only fallback was taken, no damage done"
    );
}

#[test]
fn nothing_is_committed_or_visible_when_the_witness_is_down() {
    let w = World::new("down");
    let mut t = w.open();
    fill(&mut t, 1..=2);
    let before = std::fs::read(w.file("orders.ndjson")).unwrap();
    let cp = t.checkpoint();

    w.mode.set(Mode::Down);
    let o = new_order(21, 3);
    assert_eq!(t.append_order(&o, T0 + 3), Err(TapeError::Blocked));
    assert_eq!(std::fs::read(w.file("orders.ndjson")).unwrap(), before);
    assert_eq!(t.checkpoint(), cp);
    assert_eq!(t.last_seq(), 2);
    assert!(!t.contains_order(o["orderId"].as_str().unwrap()));
    assert_eq!(w.svc.borrow().checkpoint(), cp);

    // The handle is poisoned: it stays refused even when the witness returns.
    assert_eq!(t.state(), ServeState::Refused(Judgement::Uncertain));
    w.mode.set(Mode::Up);
    assert_eq!(t.append_order(&o, T0 + 4), Err(TapeError::Blocked));
    assert_eq!(t.read_range(1, 10), Err(TapeError::Blocked));
    assert_eq!(t.precheck(&o), Err(TapeError::Blocked));
}

#[test]
fn a_lost_acknowledgment_is_not_served_and_needs_a_restart() {
    let w = World::new("lostack");
    let mut t = w.open();
    fill(&mut t, 1..=2);
    w.mode.set(Mode::LoseAck);
    let o = new_order(21, 3);
    assert_eq!(t.append_order(&o, T0 + 3), Err(TapeError::Blocked));
    assert_eq!(t.last_seq(), 2, "the local tape did not advance");
    assert!(!t.contains_order(o["orderId"].as_str().unwrap()));
    assert_eq!(w.svc.borrow().checkpoint().last_seq, 3, "the witness did");
    assert_eq!(t.judgement(), Judgement::Uncertain);
    assert_eq!(t.read_range(1, 10), Err(TapeError::Blocked));
    drop(t);
    w.mode.set(Mode::Up);
    // Witness ahead of the local tape: restoring the history is an operator action.
    assert_eq!(refused(w.open_with(&w.pin)), Judgement::Rollback);
}

#[test]
fn recheck_latches_on_a_fork_a_rollback_a_stale_challenge_and_junk() {
    // Fork: a witness (same key and scope) that holds another history.
    let w = World::new("recheck-fork");
    let mut t = w.open();
    fill(&mut t, 1..=3);
    let alt_dir = Dir::new("recheck-fork-alt");
    let mut alt = WitnessService::open(alt_dir.path(), witness_config(), &[9u8; 32]).unwrap();
    for line in history(40, 3) {
        let cp = alt.checkpoint();
        alt.compare_and_swap(&cp, &line).unwrap();
    }
    let receipt = alt.attest_latest(CH1).unwrap();
    assert_eq!(t.recheck(&receipt, CH1), Judgement::Fork);
    assert_eq!(t.state(), ServeState::Refused(Judgement::Fork));
    assert_eq!(t.read_range(1, 5), Err(TapeError::Blocked));
    assert_eq!(
        t.append_order(&new_order(21, 9), T0 + 9),
        Err(TapeError::Blocked)
    );
    // A later good receipt does not lift the latch.
    let good = w.svc.borrow().attest_latest(CH2).unwrap();
    assert_eq!(t.recheck(&good, CH2), Judgement::Fork);
    drop(t);
    drop(alt);

    // Rollback: a witness that has seen more of the same history than the tape holds.
    let w = World::new("recheck-roll");
    let mut t = w.open();
    fill(&mut t, 1..=3);
    let alt_dir = Dir::new("recheck-roll-alt");
    let mut alt = WitnessService::open(alt_dir.path(), witness_config(), &[9u8; 32]).unwrap();
    for line in history(21, 4) {
        let cp = alt.checkpoint();
        alt.compare_and_swap(&cp, &line).unwrap();
    }
    let receipt = alt.attest_latest(CH1).unwrap();
    assert_eq!(t.recheck(&receipt, CH1), Judgement::Rollback);
    assert!(!t.is_serving());
    drop(t);

    // Stale challenge (replayed receipt), bad signature, junk.
    let w = World::new("recheck-stale");
    let mut t = w.open();
    fill(&mut t, 1..=2);
    let receipt = w.svc.borrow().attest_latest(CH1).unwrap();
    assert_eq!(t.recheck(&receipt, CH2), Judgement::StaleChallenge);
    drop(t);

    let w = World::new("recheck-sig");
    let mut t = w.open();
    fill(&mut t, 1..=2);
    let mut v: serde_json::Value =
        serde_json::from_str(&w.svc.borrow().attest_latest(CH1).unwrap()).unwrap();
    v["sigWitness"] = json!("0".repeat(127) + "1");
    assert_eq!(t.recheck(&v.to_string(), CH1), Judgement::BadSignature);
    drop(t);

    let w = World::new("recheck-junk");
    let mut t = w.open();
    fill(&mut t, 1..=2);
    assert_eq!(t.recheck("not json", CH1), Judgement::Invalid);
    assert!(!t.is_serving());
    drop(t);

    // A receipt for another scope.
    let w = World::new("recheck-scope");
    let mut t = w.open();
    fill(&mut t, 1..=2);
    let mut other = witness_config();
    other.epoch = 7;
    let alt_dir = Dir::new("recheck-scope-alt");
    let alt = WitnessService::open(alt_dir.path(), other, &[9u8; 32]).unwrap();
    assert_eq!(
        t.recheck(&alt.attest_latest(CH1).unwrap(), CH1),
        Judgement::WrongScope
    );
}

#[test]
fn a_tampered_tape_file_is_inconsistent_not_served() {
    let w = World::new("tamper");
    let mut t = w.open();
    fill(&mut t, 1..=3);
    // Someone appends an extra (unwitnessed) line behind the handle's back.
    let extra = history(21, 4).pop().unwrap();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(w.file("orders.ndjson"))
            .unwrap();
        writeln!(f, "{extra}").unwrap();
    }
    let receipt = w.svc.borrow().attest_latest(CH1).unwrap();
    let j = t.recheck(&receipt, CH1);
    assert_eq!(j, Judgement::Inconsistent);
    assert_eq!(t.read_range(1, 10), Err(TapeError::Blocked));
}

#[test]
fn the_sparse_index_follows_witnessed_appends_and_restarts() {
    let w = World::new("index");
    {
        let mut t = w.open().with_index(3, 64).unwrap();
        fill(&mut t, 1..=10);
        let idx = t.index().unwrap();
        assert_eq!(idx.last_seq(), Some(10));
        assert_eq!(
            idx.entries().iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![1, 4, 7, 10]
        );
        let r = t.read_range(8, 5).unwrap();
        assert_eq!(r.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![8, 9, 10]);
    }
    let mut t = w.open().with_index(3, 64).unwrap();
    assert_eq!(t.index().unwrap().len(), 4);
    t.append_order(&new_order(21, 11), T0 + 11).unwrap();
    assert_eq!(t.index().unwrap().last_seq(), Some(11));
    assert_eq!(t.read_range(11, 5).unwrap().len(), 1);
}

#[test]
fn the_reducer_serves_the_witnessed_tape() {
    let w = World::new("reducer");
    let cfg = config_with(&[]);
    let collator = secret(3);
    let parts = ServiceParts {
        collator_id: COLLATOR.into(),
        collator_pubkey: collator.public_key_hex(),
        build: tl_collator_service::manifest::BuildInfo {
            version: "0.1.0".into(),
            git_sha: None,
            built_at: "2026-10-30T00:00:00.000Z".into(),
        },
        signer: Box::new(secret(3)),
        tape: Box::new(w.open()),
        clearlist_oracle: None,
        ip_intel: None,
        audit: None,
        artifacts: Box::new(SharedArtifacts(Default::default())),
        bitvm_collateral_property_id: None,
        provider_pins: pins(),
        boot_secret: [4; 32],
        attestations: None,
    };
    let mut svc = Service::new(cfg, parts, T0).unwrap();
    let h = HostSession(1);
    svc.open_session(h, Some("203.0.113.1"), None, T0).unwrap();
    svc.channel_opened(h, T0).unwrap();
    let o = new_order(21, 1);
    assert!(svc.on_message(h, &submit_msg(&o), T0).is_empty());
    assert_eq!(
        w.svc.borrow().checkpoint().last_seq,
        1,
        "committed at the witness first"
    );
    let outs = svc.on_message(h, r#"{"t":"TAPE_SUB","v":1}"#, T0 + 1);
    let n = outs
        .iter()
        .filter(|o| matches!(o, Out::Send { msg, .. } if msg["t"] == "TAPE_ENTRY"))
        .count();
    assert_eq!(n, 1);
}
