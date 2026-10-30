//! Operator-authorized, read-only recovery. Never opens DurableTape (which can
//! repair evidence on startup), creates files, or restores the collator store.
use crate::{hex, valid_challenge, visible, Config};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{
    fs::{self, File, TryLockError},
    io::{BufRead, BufReader, Read},
    path::Path,
    time::{Duration, Instant},
};
use tl_collator_wire::{
    canonical_json, parse_canonical_text, sha256_hex,
    verify::{verify_compact, Checkpoint, VerifiedReplay},
    witness::WitnessScope,
    MAX_INPUT_BYTES, MAX_SAFE_INTEGER,
};

pub const REQUEST_DOMAIN: &str = "TradeLayer/collator/recovery-request/v1";
pub const MANIFEST_DOMAIN: &str = "TradeLayer/collator/recovery-manifest/v1";
pub const MAX_METADATA_BYTES: usize = 8192;

mod paged;
pub use paged::{PagedRecovery, RecoverySessionLimits};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Invalid,
    Unauthorized,
    Busy,
    Io,
    Limit,
    Deadline,
    Corrupt,
    Checkpoint,
    Freshness,
}
impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recovery request refused: {self:?}")
    }
}
impl std::error::Error for RecoveryError {}
type Result<T> = std::result::Result<T, RecoveryError>;

/// Operator policy, never supplied by the remote caller. Byte caps include LF
/// terminators; max_export_bytes includes the manifest and its LF terminator.
#[derive(Clone, Debug)]
pub struct RecoveryLimits {
    pub max_records: usize,
    pub max_record_bytes: usize,
    pub max_export_bytes: usize,
    pub max_scan_bytes: u64,
    pub timeout: Duration,
}
impl RecoveryLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_records == 0
            || self.max_records > 10_000
            || self.max_record_bytes == 0
            || self.max_record_bytes > MAX_INPUT_BYTES
            || self.max_export_bytes == 0
            || self.max_export_bytes > 64 * 1024 * 1024
            || self.max_scan_bytes == 0
            || self.max_scan_bytes > 1024 * 1024 * 1024
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(60)
        {
            return Err(RecoveryError::Limit);
        }
        Ok(())
    }
}

pub struct RecoveryPolicy {
    operator_id: String,
    operator_key: PublicKey,
    pub limits: RecoveryLimits,
}
impl RecoveryPolicy {
    pub fn new(operator_id: &str, operator_pubkey: &str, limits: RecoveryLimits) -> Result<Self> {
        limits.validate()?;
        if !visible(operator_id) {
            return Err(RecoveryError::Invalid);
        }
        Ok(Self {
            operator_id: operator_id.into(),
            operator_key: key(operator_pubkey)?,
            limits,
        })
    }
}

fn key(text: &str) -> Result<PublicKey> {
    // from_str_radix would also accept a leading '+', so non-canonical key text could
    // name a valid point; require plain hex digits.
    if !matches!(text.len(), 66 | 130) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RecoveryError::Invalid);
    }
    let bytes = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(RecoveryError::Invalid)?;
    PublicKey::from_slice(&bytes).map_err(|_| RecoveryError::Invalid)
}
fn text<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or(RecoveryError::Invalid)
}
fn uint(v: &Value, name: &str) -> Result<u64> {
    v.get(name)
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SAFE_INTEGER)
        .ok_or(RecoveryError::Invalid)
}
fn fields(raw: &str, names: &[&str]) -> Result<Value> {
    if raw.len() > MAX_METADATA_BYTES {
        return Err(RecoveryError::Limit);
    }
    let v = parse_canonical_text(raw).map_err(|_| RecoveryError::Invalid)?;
    let map = v.as_object().ok_or(RecoveryError::Invalid)?;
    if map.len() != names.len() || names.iter().any(|n| !map.contains_key(*n)) {
        return Err(RecoveryError::Invalid);
    }
    Ok(v)
}
fn unsigned(v: &Value, signature: &str) -> Result<String> {
    let mut map = v.as_object().ok_or(RecoveryError::Invalid)?.clone();
    map.remove(signature);
    canonical_json(&Value::Object(map)).map_err(|_| RecoveryError::Invalid)
}
fn verify_signature(v: &Value, signature: &str, signer: &PublicKey) -> Result<()> {
    verify_compact(
        &sha256_hex(&unsigned(v, signature)?),
        text(v, signature)?,
        signer,
    )
    .map_err(|_| RecoveryError::Unauthorized)
}
fn sign(v: &mut Value, secret: &SecretKey) -> Result<()> {
    let digest = sha256_hex(&canonical_json(v).map_err(|_| RecoveryError::Invalid)?);
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16)
            .map_err(|_| RecoveryError::Invalid)?;
    }
    let sig = Secp256k1::signing_only().sign_ecdsa(&Message::from_digest(bytes), secret);
    v["sigWitness"] = json!(hex(&sig.serialize_compact()));
    Ok(())
}
fn scope(v: &Value, config: &Config) -> Result<()> {
    if text(v, "collatorId")? != config.collator_id
        || text(v, "network")? != config.network
        || text(v, "stream")? != config.stream
        || uint(v, "epoch")? != config.epoch
    {
        return Err(RecoveryError::Invalid);
    }
    Ok(())
}
fn checkpoint(v: &Value) -> Result<Checkpoint> {
    let seq = uint(v, "checkpointSeq")?;
    let hash = text(v, "checkpointHash")?;
    let orders = uint(v, "seenOrders")?;
    let hash_valid = hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if orders != seq || !(seq == 0 && hash.is_empty() || seq > 0 && hash_valid) {
        return Err(RecoveryError::Checkpoint);
    }
    Ok(Checkpoint {
        last_seq: seq,
        last_hash: hash.into(),
        seen_orders: usize::try_from(orders).map_err(|_| RecoveryError::Checkpoint)?,
    })
}
fn deadline(end: Instant) -> Result<()> {
    if Instant::now() >= end {
        Err(RecoveryError::Deadline)
    } else {
        Ok(())
    }
}
fn regular(path: &Path, cap: u64) -> Result<File> {
    let meta = fs::symlink_metadata(path).map_err(|_| RecoveryError::Io)?;
    if !meta.file_type().is_file() {
        return Err(RecoveryError::Invalid);
    }
    if meta.len() > cap {
        return Err(RecoveryError::Limit);
    }
    File::open(path).map_err(|_| RecoveryError::Io)
}
fn metadata(path: &Path) -> Result<String> {
    let file = regular(path, MAX_METADATA_BYTES as u64)?;
    let mut raw = String::new();
    file.take(MAX_METADATA_BYTES as u64 + 1)
        .read_to_string(&mut raw)
        .map_err(|_| RecoveryError::Io)?;
    if raw.len() > MAX_METADATA_BYTES {
        return Err(RecoveryError::Limit);
    }
    Ok(raw)
}

const REQUEST_FIELDS: &[&str] = &[
    "domain",
    "v",
    "collatorId",
    "network",
    "stream",
    "epoch",
    "operatorId",
    "startSeq",
    "count",
    "checkpointSeq",
    "checkpointHash",
    "seenOrders",
    "challenge",
    "sigOperator",
];
const MANIFEST_FIELDS: &[&str] = &[
    "domain",
    "v",
    "collatorId",
    "collatorPubKey",
    "witnessPubKey",
    "network",
    "stream",
    "epoch",
    "operatorId",
    "startSeq",
    "count",
    "prevHash",
    "finalHash",
    "checkpointSeq",
    "checkpointHash",
    "seenOrders",
    "challenge",
    "bytes",
    "digest",
    "sigWitness",
];

/// Output stays private to the call until full history and committed checkpoint
/// agree. CLI emits manifest + LF followed by exact signed NDJSON records.
pub struct RecoveryExport {
    pub manifest: String,
    pub ndjson: String,
}

/// Requires an operator-signed exact range and expected checkpoint. Separate
/// operator authentication is mandatory even when an SSH wrapper is deployed.
/// The filesystem must be operator controlled, local POSIX, with an existing
/// witness.lock inode. No repair, truncation, checkpoint catch-up or import.
pub fn export_history(
    directory: &Path,
    config: &Config,
    witness_secret: &[u8; 32],
    policy: &RecoveryPolicy,
    signed_request: &str,
) -> Result<RecoveryExport> {
    let end = Instant::now()
        .checked_add(policy.limits.timeout)
        .ok_or(RecoveryError::Limit)?;
    policy.limits.validate()?;
    config.validate().map_err(|_| RecoveryError::Invalid)?;
    let request = fields(signed_request, REQUEST_FIELDS)?;
    scope(&request, config)?;
    if text(&request, "domain")? != REQUEST_DOMAIN
        || uint(&request, "v")? != 1
        || text(&request, "operatorId")? != policy.operator_id
        || !valid_challenge(text(&request, "challenge")?)
    {
        return Err(RecoveryError::Unauthorized);
    }
    let secret = SecretKey::from_slice(witness_secret).map_err(|_| RecoveryError::Invalid)?;
    let witness_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
    let collator_key = key(&config.collator_pubkey)?;
    if witness_key == collator_key
        || policy.operator_key == witness_key
        || policy.operator_key == collator_key
    {
        return Err(RecoveryError::Unauthorized);
    }
    verify_signature(&request, "sigOperator", &policy.operator_key)?;
    let expected = checkpoint(&request)?;
    let start = uint(&request, "startSeq")?;
    let count = uint(&request, "count")?;
    let finish = start
        .checked_add(count)
        .and_then(|n| n.checked_sub(1))
        .ok_or(RecoveryError::Limit)?;
    if start == 0
        || count == 0
        || count > policy.limits.max_records as u64
        || finish > expected.last_seq
        || expected.last_seq > config.max_entries as u64
    {
        return Err(RecoveryError::Limit);
    }
    deadline(end)?;
    if !fs::symlink_metadata(directory)
        .map_err(|_| RecoveryError::Io)?
        .is_dir()
    {
        return Err(RecoveryError::Invalid);
    }
    let lock = regular(&directory.join("witness.lock"), 4096)?;
    lock.try_lock().map_err(|err| match err {
        TryLockError::WouldBlock => RecoveryError::Busy,
        _ => RecoveryError::Io,
    })?;
    let stored_scope = fields(
        &metadata(&directory.join("witness.scope"))?,
        &[
            "v",
            "collatorId",
            "collatorPubKey",
            "network",
            "stream",
            "epoch",
            "witnessPubKey",
        ],
    )?;
    scope(&stored_scope, config)?;
    if uint(&stored_scope, "v")? != 1
        || text(&stored_scope, "collatorPubKey")? != config.collator_pubkey
        || text(&stored_scope, "witnessPubKey")? != hex(&witness_key.serialize())
    {
        return Err(RecoveryError::Invalid);
    }
    let anchor = fields(
        &metadata(&directory.join("witness.checkpoint"))?,
        &["version", "seq", "hash", "orders"],
    )?;
    if uint(&anchor, "version")? != 1
        || uint(&anchor, "seq")? != expected.last_seq
        || text(&anchor, "hash")? != expected.last_hash
        || uint(&anchor, "orders")? != expected.seen_orders as u64
    {
        return Err(RecoveryError::Checkpoint);
    }
    let file = regular(
        &directory.join("witness.ndjson"),
        policy.limits.max_scan_bytes,
    )?;
    let mut input = BufReader::new(file);
    let mut replay = VerifiedReplay::new(
        &config.collator_id,
        &config.collator_pubkey,
        config.max_entries,
    )
    .map_err(|_| RecoveryError::Invalid)?;
    let mut ndjson = String::new();
    let mut previous = String::new();
    let mut final_hash = String::new();
    let mut scanned = 0u64;
    let mut selected = 0u64;
    loop {
        deadline(end)?;
        let mut bytes = Vec::new();
        (&mut input)
            .take(policy.limits.max_record_bytes as u64 + 2)
            .read_until(b'\n', &mut bytes)
            .map_err(|_| RecoveryError::Io)?;
        if bytes.is_empty() {
            break;
        }
        scanned = scanned
            .checked_add(bytes.len() as u64)
            .ok_or(RecoveryError::Limit)?;
        if scanned > policy.limits.max_scan_bytes
            || bytes.len() > policy.limits.max_record_bytes + 1
        {
            return Err(RecoveryError::Limit);
        }
        if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
            return Err(RecoveryError::Corrupt);
        }
        let line =
            std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| RecoveryError::Corrupt)?;
        let before = replay.checkpoint();
        let after = replay
            .apply_line(line)
            .map_err(|_| RecoveryError::Corrupt)?;
        deadline(end)?;
        if after.last_seq >= start && after.last_seq <= finish {
            if ndjson.len().saturating_add(bytes.len()) > policy.limits.max_export_bytes {
                return Err(RecoveryError::Limit);
            }
            if selected == 0 {
                previous = before.last_hash;
            }
            final_hash = after.last_hash;
            ndjson.push_str(line);
            ndjson.push('\n');
            selected += 1;
        }
    }
    if replay.checkpoint() != expected || selected != count {
        return Err(RecoveryError::Checkpoint);
    }
    let mut manifest = json!({
        "domain":MANIFEST_DOMAIN,"v":1,"collatorId":config.collator_id,
        "collatorPubKey":config.collator_pubkey,"witnessPubKey":hex(&witness_key.serialize()),
        "network":config.network,"stream":config.stream,"epoch":config.epoch,
        "operatorId":policy.operator_id,"startSeq":start,"count":count,
        "prevHash":previous,"finalHash":final_hash,"checkpointSeq":expected.last_seq,
        "checkpointHash":expected.last_hash,"seenOrders":expected.seen_orders,
        "challenge":text(&request,"challenge")?,"bytes":ndjson.len(),"digest":sha256_hex(&ndjson),
    });
    sign(&mut manifest, &secret)?;
    let manifest = canonical_json(&manifest).map_err(|_| RecoveryError::Invalid)?;
    if manifest.len() > MAX_METADATA_BYTES
        || manifest
            .len()
            .saturating_add(1)
            .saturating_add(ndjson.len())
            > policy.limits.max_export_bytes
    {
        return Err(RecoveryError::Limit);
    }
    deadline(end)?;
    Ok(RecoveryExport { manifest, ndjson })
}

/// Fresh independent latest query started AFTER export, using a distinct random
/// challenge. The caller measures request time; receipts contain no trusted clock.
pub struct FreshReceipt<'a> {
    pub raw: &'a str,
    pub challenge: &'a str,
    pub requested_at: Instant,
    pub max_age: Duration,
}

/// Offline validation only. Requires a full genesis-to-head export; partial
/// ranges are diagnostic artifacts, never an authoritative restore candidate.
/// Returns no file handle and performs no writes. Human authorization and
/// evidence preservation are separate prerequisites for an actual restoration.
#[allow(clippy::too_many_arguments)]
pub fn verify_full_recovery(
    bundle: &RecoveryExport,
    config: &Config,
    witness_pubkey: &str,
    operator_id: &str,
    export_challenge: &str,
    fresh: FreshReceipt<'_>,
    limits: &RecoveryLimits,
) -> Result<Checkpoint> {
    limits.validate()?;
    config.validate().map_err(|_| RecoveryError::Invalid)?;
    paged::validate_freshness(&fresh)?;
    if !valid_challenge(export_challenge) || fresh.challenge == export_challenge {
        return Err(RecoveryError::Freshness);
    }
    let manifest = fields(&bundle.manifest, MANIFEST_FIELDS)?;
    let target = checkpoint(&manifest)?;
    let mut replay = PagedRecovery::new(
        config,
        witness_pubkey,
        operator_id,
        target,
        limits.clone(),
        RecoverySessionLimits {
            max_pages: 1,
            max_total_export_bytes: limits.max_export_bytes as u64,
            timeout: limits.timeout,
        },
    )?;
    replay.accept_page(bundle, export_challenge)?;
    replay.finish(fresh)
}
