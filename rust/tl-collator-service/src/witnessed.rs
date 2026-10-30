//! `WitnessedTape` adapter: a `TapeStore` over `tl_collator_wire::durable::WitnessedTape`
//! (see `tl-collator-wire/WITNESSED_STARTUP.md` and `WITNESS_PROTOCOL.md`).
//!
//! * Startup takes the wire crate's path: OS lock, fresh challenge, signed receipt under a
//!   pinned independent witness key and scope, exact checkpoint match. A rollback, a fork,
//!   a witness ahead of or behind the local tape, a wrong scope or an unreachable witness
//!   refuses to open (`OpenError::Refused`); there is no local-only fallback.
//! * Appends go remote-first through the wire crate (witness CAS + signed receipt, then the
//!   local fsync and anchor). The adapter updates its replay mirror, index and checkpoint
//!   only after `append_signed` returned `Ok`, i.e. after the durable commit.
//! * `recheck` judges a fresh witness receipt against the whole local tape. Any judgement
//!   other than `Judgement::Ok` latches the adapter into `Refused`: `read_range` and
//!   `append_order` fail with `TapeError::Blocked` until the process restarts (and passes
//!   the startup check again).
//!
//! The wire crate does not expose its ownership index, so the adapter keeps a
//! `VerifiedReplay` rebuilt from the tape file while the wire crate's lock is held.
use crate::signer::DigestSigner;
use crate::tape::{precheck_order, signed_line, TapeEntry, TapeError, TapeStore};
use crate::tapeindex::{read_range_at, TapeIndex};
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use tl_collator_wire::durable::{DurableError, Recovery, WitnessTransport, WitnessedTape};
use tl_collator_wire::verify::{Checkpoint, VerifiedReplay};
use tl_collator_wire::witness::{WitnessError, WitnessScope};

/// Verdict on the independent witness' view of this tape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgement {
    /// The receipt is valid under the pinned key and scope and matches the local tape exactly.
    Ok,
    /// The witness is ahead of the local tape (truncated or restored tape).
    Rollback,
    /// The witness saw a different history at the same sequence.
    Fork,
    /// The local tape is ahead of the witness (an unwitnessed head).
    AheadOfWitness,
    WrongScope,
    StaleChallenge,
    BadSignature,
    /// Malformed receipt or tape.
    Invalid,
    /// An ambiguous remote result (lost acknowledgment, outage) or an unconfirmed commit.
    Uncertain,
    /// The on-disk tape no longer matches what this process committed.
    Inconsistent,
}

impl Judgement {
    pub fn is_ok(self) -> bool {
        self == Judgement::Ok
    }
}

impl From<&WitnessError> for Judgement {
    fn from(e: &WitnessError) -> Self {
        match e {
            WitnessError::Rollback => Judgement::Rollback,
            WitnessError::Fork => Judgement::Fork,
            WitnessError::WrongScope => Judgement::WrongScope,
            WitnessError::StaleChallenge => Judgement::StaleChallenge,
            WitnessError::BadSignature => Judgement::BadSignature,
            _ => Judgement::Invalid,
        }
    }
}

/// Operator-pinned witness identity. Never taken from the tape or from a receipt.
#[derive(Clone, Debug)]
pub struct WitnessPin {
    pub collator_id: String,
    pub network: String,
    pub stream: String,
    pub epoch: u64,
    pub witness_pubkey_hex: String,
}

impl WitnessPin {
    fn scope(&self) -> Result<WitnessScope, WitnessError> {
        WitnessScope::new(
            &self.collator_id,
            &self.network,
            &self.stream,
            self.epoch,
            &self.witness_pubkey_hex,
        )
    }
}

#[derive(Debug)]
pub enum OpenError {
    /// The witness check failed: the service must not serve this tape.
    Refused(Judgement),
    /// Another startup failure (I/O, lock, corrupt anchor, ...).
    Durable(DurableError),
    Config(&'static str),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for OpenError {}

fn open_error(e: DurableError) -> OpenError {
    match e {
        DurableError::Witness(w) => OpenError::Refused(Judgement::from(&w)),
        DurableError::AheadOfWitness => OpenError::Refused(Judgement::AheadOfWitness),
        DurableError::RemoteUncertain => OpenError::Refused(Judgement::Uncertain),
        other => OpenError::Durable(other),
    }
}

/// The whole serving decision: serve iff the last judgement is `Ok`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServeState {
    Serving,
    Refused(Judgement),
}

pub struct WitnessedSignedTape<S: DigestSigner, T: WitnessTransport> {
    collator_id: String,
    collator_pubkey: String,
    max_entries: usize,
    signer: S,
    tape: WitnessedTape<T>,
    scope: WitnessScope,
    mirror: VerifiedReplay,
    file: PathBuf,
    index: Option<TapeIndex>,
    state: ServeState,
}

/// Everything `WitnessedSignedTape::open` needs from the operator.
pub struct WitnessedOpen<'a> {
    pub directory: &'a Path,
    pub stem: &'a str,
    pub collator_id: &'a str,
    pub collator_pubkey_hex: &'a str,
    pub max_entries: usize,
    pub pin: &'a WitnessPin,
}

impl<S: DigestSigner, T: WitnessTransport> WitnessedSignedTape<S, T> {
    /// Opens `<directory>/<stem>.ndjson` under the wire crate's lock and witness check.
    pub fn open(p: &WitnessedOpen<'_>, signer: S, remote: T) -> Result<Self, OpenError> {
        if p.pin.collator_id != p.collator_id {
            return Err(OpenError::Config("pin collator id"));
        }
        let startup_scope = p
            .pin
            .scope()
            .map_err(|_| OpenError::Config("witness pin"))?;
        let scope = p
            .pin
            .scope()
            .map_err(|_| OpenError::Config("witness pin"))?;
        scope
            .assert_collator_identity(p.collator_id, p.collator_pubkey_hex)
            .map_err(|e| OpenError::Refused(Judgement::from(&e)))?;
        let tape = WitnessedTape::open(
            p.directory,
            p.stem,
            p.collator_id,
            p.collator_pubkey_hex,
            p.max_entries,
            startup_scope,
            remote,
        )
        .map_err(open_error)?;
        let file = p.directory.join(format!("{}.ndjson", p.stem));
        let reader = File::open(&file).map_err(|e| OpenError::Durable(DurableError::Io(e)))?;
        let mirror = VerifiedReplay::from_ndjson(
            BufReader::new(reader),
            p.collator_id,
            p.collator_pubkey_hex,
            p.max_entries,
        )
        .map_err(|_| OpenError::Refused(Judgement::Inconsistent))?;
        if mirror.checkpoint() != tape.checkpoint() {
            return Err(OpenError::Refused(Judgement::Inconsistent));
        }
        Ok(Self {
            collator_id: p.collator_id.to_owned(),
            collator_pubkey: p.collator_pubkey_hex.to_owned(),
            max_entries: p.max_entries,
            signer,
            tape,
            scope,
            mirror,
            file,
            index: None,
            state: ServeState::Serving,
        })
    }

    /// Add the sparse replay index (see `tapeindex`).
    pub fn with_index(mut self, stride: u64, max_entries: usize) -> Result<Self, TapeError> {
        let f = File::open(&self.file).map_err(|_| TapeError::Io)?;
        self.index = Some(
            TapeIndex::build_from_reader(BufReader::new(f), stride, max_entries)
                .map_err(|_| TapeError::Invalid)?,
        );
        Ok(self)
    }

    /// The committed checkpoint (last sequence, head hash, order count).
    pub fn checkpoint(&self) -> Checkpoint {
        self.tape.checkpoint()
    }

    pub fn recovery(&self) -> Recovery {
        self.tape.recovery()
    }

    pub fn state(&self) -> ServeState {
        self.state
    }

    pub fn is_serving(&self) -> bool {
        self.state == ServeState::Serving
    }

    /// `Judgement::Ok` while serving, otherwise the latched reason.
    pub fn judgement(&self) -> Judgement {
        match self.state {
            ServeState::Serving => Judgement::Ok,
            ServeState::Refused(j) => j,
        }
    }

    pub fn index(&self) -> Option<&TapeIndex> {
        self.index.as_ref()
    }

    fn refuse(&mut self, j: Judgement) -> Judgement {
        if self.state == ServeState::Serving {
            self.state = ServeState::Refused(j);
        }
        self.judgement()
    }

    /// Judge a witness receipt (obtained by the host with a fresh 32-byte challenge, e.g. from
    /// `WitnessService::attest_latest`) against the entire local tape. Re-verifies every entry
    /// (cost linear in the tape). A failure latches `Refused`; success never lifts a latch.
    pub fn recheck(&mut self, receipt_json: &str, challenge: &str) -> Judgement {
        if !self.is_serving() {
            return self.judgement();
        }
        let receipt = match self.scope.verify_receipt(receipt_json, challenge) {
            Ok(r) => r,
            Err(e) => return self.refuse(Judgement::from(&e)),
        };
        let reader = match File::open(&self.file) {
            Ok(f) => BufReader::new(f),
            Err(_) => return self.refuse(Judgement::Inconsistent),
        };
        let cp =
            match self
                .scope
                .verify_tape(reader, &self.collator_pubkey, self.max_entries, &receipt)
            {
                Ok(cp) => cp,
                Err(e) => return self.refuse(Judgement::from(&e)),
            };
        if cp != self.tape.checkpoint() {
            return self.refuse(Judgement::Inconsistent);
        }
        if cp.last_seq > receipt.seq() {
            return self.refuse(Judgement::AheadOfWitness);
        }
        Judgement::Ok
    }
}

impl<S: DigestSigner, T: WitnessTransport> TapeStore for WitnessedSignedTape<S, T> {
    fn last_seq(&self) -> u64 {
        self.tape.checkpoint().last_seq
    }

    fn contains_order(&self, order_id: &str) -> bool {
        self.mirror.contains(order_id)
    }

    fn precheck(&self, order: &Value) -> Result<(), TapeError> {
        if !self.is_serving() {
            return Err(TapeError::Blocked);
        }
        precheck_order(&self.mirror, order)
    }

    fn append_order(&mut self, order: &Value, received_ts: u64) -> Result<TapeEntry, TapeError> {
        if !self.is_serving() {
            return Err(TapeError::Blocked);
        }
        precheck_order(&self.mirror, order)?;
        let cp = self.tape.checkpoint();
        let seq = cp.last_seq.checked_add(1).ok_or(TapeError::Capacity)?;
        let line = signed_line(
            &self.collator_id,
            seq,
            &cp.last_hash,
            received_ts,
            order,
            &self.signer,
        )?;
        let after = match self.tape.append_signed(&line) {
            Ok(after) => after,
            Err(e) => {
                if self.tape.is_blocked() {
                    self.refuse(Judgement::Uncertain);
                }
                return Err(match e {
                    DurableError::Witness(_) => TapeError::Blocked,
                    other => other.into(),
                });
            }
        };
        // Past the durable commit: only now do the mirror, the index and the result change.
        if self.mirror.apply_line(&line).is_err() {
            self.refuse(Judgement::Inconsistent);
        }
        if let Some(idx) = self.index.as_mut() {
            if idx
                .record_append(after.last_seq, line.len() as u64 + 1)
                .is_err()
            {
                self.index = None;
            }
        }
        Ok(TapeEntry {
            seq: after.last_seq,
            line,
        })
    }

    fn read_range(&self, from_seq: u64, max: usize) -> Result<Vec<TapeEntry>, TapeError> {
        if !self.is_serving() {
            return Err(TapeError::Blocked);
        }
        let mut file = File::open(&self.file).map_err(|_| TapeError::Io)?;
        Ok(read_range_at(&mut file, self.index.as_ref(), from_seq, max)?.entries)
    }
}
