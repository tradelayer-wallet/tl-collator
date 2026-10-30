//! Tape boundary. The reducer appends orders and reads replay ranges through
//! `TapeStore`. Both shipped adapters build the collator-signed entry (the signature is
//! supplied by a `DigestSigner`, so no key lives here) and commit it through
//! `tl-collator-wire`, which re-verifies the order id, both signatures, the hash chain,
//! duplicate order ids, the owner of CANCEL/REPLACE targets and capacity before any state
//! changes. Nothing is appended that the wire crate would refuse to replay.
use crate::signer::{DigestSigner, SignError};
use crate::tapeindex::{read_range_at, TapeIndex};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::BufReader;
use std::path::PathBuf;
use tl_collator_wire::durable::{DurableError, DurableTape};
use tl_collator_wire::verify::{VerifiedReplay, VerifyError};
use tl_collator_wire::{canonical_json, tape_entry_hash, tape_signature_hash};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TapeError {
    Duplicate,
    UnknownOrder,
    NotOwner,
    BadOrder,
    Capacity,
    Sign,
    Io,
    /// The durable handle refuses further writes until reopened.
    Blocked,
    Invalid,
}

impl std::fmt::Display for TapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TapeError {}

impl From<VerifyError> for TapeError {
    fn from(e: VerifyError) -> Self {
        match e {
            VerifyError::Duplicate => TapeError::Duplicate,
            VerifyError::UnknownOrder => TapeError::UnknownOrder,
            VerifyError::NotOwner => TapeError::NotOwner,
            VerifyError::Capacity => TapeError::Capacity,
            VerifyError::BadOrderId | VerifyError::BadSignature => TapeError::BadOrder,
            VerifyError::Io | VerifyError::TornTail => TapeError::Io,
            _ => TapeError::Invalid,
        }
    }
}

impl From<DurableError> for TapeError {
    fn from(e: DurableError) -> Self {
        match e {
            DurableError::Verify(v) => v.into(),
            DurableError::Io(_) | DurableError::TornTail => TapeError::Io,
            DurableError::NeedsRecovery
            | DurableError::CommitUnknown
            | DurableError::RemoteUncertain
            | DurableError::AheadOfWitness => TapeError::Blocked,
            _ => TapeError::Invalid,
        }
    }
}

impl From<SignError> for TapeError {
    fn from(_: SignError) -> Self {
        TapeError::Sign
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapeEntry {
    pub seq: u64,
    /// The NDJSON line exactly as committed (canonical JSON, no newline).
    pub line: String,
}

pub trait TapeStore {
    fn last_seq(&self) -> u64;
    /// Authoritative duplicate test. The service's LRU of recent ids is only a cache.
    fn contains_order(&self, order_id: &str) -> bool;
    /// Cheap, side-effect-free rejection before the collator signs anything. Adapters that
    /// cannot answer return `Ok(())`; `append_order` re-checks everything regardless.
    fn precheck(&self, _order: &Value) -> Result<(), TapeError> {
        Ok(())
    }
    fn append_order(&mut self, order: &Value, received_ts: u64) -> Result<TapeEntry, TapeError>;
    /// Entries with `seq >= from_seq`, ascending, contiguous, at most `max`.
    fn read_range(&self, from_seq: u64, max: usize) -> Result<Vec<TapeEntry>, TapeError>;
}

pub(crate) fn signed_line(
    collator_id: &str,
    seq: u64,
    prev_hash: &str,
    received_ts: u64,
    order: &Value,
    signer: &dyn DigestSigner,
) -> Result<String, TapeError> {
    let mut entry = json!({
        "v": 1,
        "collatorId": collator_id,
        "seq": seq,
        "prevHash": prev_hash,
        "receivedTs": received_ts,
        "order": order,
    });
    let hash = tape_entry_hash(&entry).map_err(|_| TapeError::Invalid)?;
    entry["entryHash"] = json!(hash);
    let digest = tape_signature_hash(&entry, &hash).map_err(|_| TapeError::Invalid)?;
    entry["sigCollator"] = json!(signer.sign_digest(&digest)?);
    canonical_json(&entry).map_err(|_| TapeError::Invalid)
}

fn owner_of_order(order: &Value) -> Option<&str> {
    order.get("traderPubKey").and_then(Value::as_str)
}

/// In-memory tape over `VerifiedReplay`; bounded by `max_entries`.
pub struct MemoryTape<S: DigestSigner> {
    collator_id: String,
    signer: S,
    replay: VerifiedReplay,
    lines: BTreeMap<u64, String>,
}

impl<S: DigestSigner> MemoryTape<S> {
    pub fn new(
        collator_id: &str,
        collator_pubkey_hex: &str,
        signer: S,
        max_entries: usize,
    ) -> Result<Self, TapeError> {
        let replay = VerifiedReplay::new(collator_id, collator_pubkey_hex, max_entries)?;
        Ok(Self {
            collator_id: collator_id.to_owned(),
            signer,
            replay,
            lines: BTreeMap::new(),
        })
    }
}

impl<S: DigestSigner> TapeStore for MemoryTape<S> {
    fn last_seq(&self) -> u64 {
        self.replay.checkpoint().last_seq
    }

    fn contains_order(&self, order_id: &str) -> bool {
        self.replay.contains(order_id)
    }

    fn precheck(&self, order: &Value) -> Result<(), TapeError> {
        precheck_order(&self.replay, order)
    }

    fn append_order(&mut self, order: &Value, received_ts: u64) -> Result<TapeEntry, TapeError> {
        let cp = self.replay.checkpoint();
        let seq = cp.last_seq.checked_add(1).ok_or(TapeError::Capacity)?;
        let line = signed_line(
            &self.collator_id,
            seq,
            &cp.last_hash,
            received_ts,
            order,
            &self.signer,
        )?;
        let after = self.replay.apply_line(&line)?;
        self.lines.insert(after.last_seq, line.clone());
        Ok(TapeEntry {
            seq: after.last_seq,
            line,
        })
    }

    fn read_range(&self, from_seq: u64, max: usize) -> Result<Vec<TapeEntry>, TapeError> {
        Ok(self
            .lines
            .range(from_seq..)
            .take(max)
            .map(|(seq, line)| TapeEntry {
                seq: *seq,
                line: line.clone(),
            })
            .collect())
    }
}

/// Crash-safe tape over `DurableTape` (fsync + anchored checkpoint). Replay reads the
/// tape file by a bounded forward scan; the legacy sparse index is not ported.
pub struct DurableSignedTape<S: DigestSigner> {
    collator_id: String,
    signer: S,
    tape: DurableTape,
    file: PathBuf,
    index: Option<TapeIndex>,
}

impl<S: DigestSigner> DurableSignedTape<S> {
    /// `file` is the tape file the `DurableTape` owns (`<directory>/<stem>.ndjson`).
    pub fn new(collator_id: &str, signer: S, tape: DurableTape, file: PathBuf) -> Self {
        Self {
            collator_id: collator_id.to_owned(),
            signer,
            tape,
            file,
            index: None,
        }
    }

    /// Build the sparse index (`stride`, at most `max_entries` entries) from the tape file.
    /// Replay then starts at the indexed offset; without it (or when the file no longer
    /// matches it) replay scans from the start. Appends extend the index.
    pub fn with_index(mut self, stride: u64, max_entries: usize) -> Result<Self, TapeError> {
        let f = std::fs::File::open(&self.file).map_err(|_| TapeError::Io)?;
        let idx = TapeIndex::build_from_reader(BufReader::new(f), stride, max_entries)
            .map_err(|_| TapeError::Invalid)?;
        self.index = Some(idx);
        Ok(self)
    }

    pub fn index(&self) -> Option<&TapeIndex> {
        self.index.as_ref()
    }
}

impl<S: DigestSigner> TapeStore for DurableSignedTape<S> {
    fn last_seq(&self) -> u64 {
        self.tape.checkpoint().last_seq
    }

    fn contains_order(&self, order_id: &str) -> bool {
        self.tape.has_order(order_id)
    }

    fn append_order(&mut self, order: &Value, received_ts: u64) -> Result<TapeEntry, TapeError> {
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
        let after = self.tape.append_signed(&line)?;
        if let Some(idx) = self.index.as_mut() {
            if idx
                .record_append(after.last_seq, line.len() as u64 + 1)
                .is_err()
            {
                self.index = None; // rebuilt by the host; reads fall back to a scan
            }
        }
        Ok(TapeEntry {
            seq: after.last_seq,
            line,
        })
    }

    fn read_range(&self, from_seq: u64, max: usize) -> Result<Vec<TapeEntry>, TapeError> {
        let mut file = std::fs::File::open(&self.file).map_err(|_| TapeError::Io)?;
        Ok(read_range_at(&mut file, self.index.as_ref(), from_seq, max)?.entries)
    }
}

/// CANCEL/REPLACE owner check against a verified replay (shared by the in-memory and the
/// witnessed adapters; the wire crate re-checks at commit regardless).
pub(crate) fn precheck_order(replay: &VerifiedReplay, order: &Value) -> Result<(), TapeError> {
    let kind = order.get("kind").and_then(Value::as_str).unwrap_or("");
    let field = match kind {
        "CANCEL" => "cancelsOrderId",
        "REPLACE" => "replacesOrderId",
        _ => return Ok(()),
    };
    let target = order
        .get(field)
        .and_then(Value::as_str)
        .ok_or(TapeError::Invalid)?;
    match replay.owner_of(target) {
        None => Err(TapeError::UnknownOrder),
        Some(owner) => {
            let me = owner_of_order(order).ok_or(TapeError::Invalid)?;
            if owner.eq_ignore_ascii_case(me) {
                Ok(())
            } else {
                Err(TapeError::NotOwner)
            }
        }
    }
}
