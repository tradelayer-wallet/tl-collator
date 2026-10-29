//! Independent witness *service core*: a separately hosted copy of the verified
//! signed tape, with monotonic compare-and-swap and a distinct signing key.
//! It opens no network sockets and accepts no unauthenticated RPC by itself.
#![forbid(unsafe_code)]

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{fmt, fs::{self, File, OpenOptions}, io::Write, path::Path};
use tl_collator_wire::{
    canonical_json,
    durable::{DurableError, DurableTape, ImportMode},
    sha256_hex,
    verify::Checkpoint,
    witness::{WitnessError, WitnessScope},
    MAX_SAFE_INTEGER,
};

const DOMAIN: &str = "TradeLayer/collator/checkpoint/v1";

#[derive(Debug)]
pub enum Error {
    InvalidScope,
    InvalidKey,
    InvalidChallenge,
    InvalidStoredScope,
    Conflict,
    Durable(DurableError),
    Witness(WitnessError),
    Canonical(tl_collator_wire::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not include secrets or untrusted data in errors.
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<DurableError> for Error {
    fn from(e: DurableError) -> Self { Self::Durable(e) }
}
impl From<WitnessError> for Error {
    fn from(e: WitnessError) -> Self { Self::Witness(e) }
}
impl From<tl_collator_wire::Error> for Error {
    fn from(e: tl_collator_wire::Error) -> Self { Self::Canonical(e) }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn valid_challenge(s: &str) -> bool {
    s.len() == 64
        && s.bytes().any(|b| b != b'0')
        && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn visible(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 &&
        s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// The operator must provision the collator public key and an entirely separate
/// witness signing private key on an independent machine and filesystem.
pub struct Config {
    pub collator_id: String,
    pub collator_pubkey: String,
    pub network: String,
    pub stream: String,
    pub epoch: u64,
    pub max_entries: usize,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if !visible(&self.collator_id) || !visible(&self.network) ||
            !visible(&self.stream) || self.epoch > MAX_SAFE_INTEGER ||
            self.max_entries == 0 || self.max_entries > 1_000_000 {
            return Err(Error::InvalidScope);
        }
        Ok(())
    }
}

/// Immutable scope metadata. The independent host filesystem must be
/// controlled by the witness operator. A missing scope alongside preexisting
/// signed tape history fails closed: do not silently reassign old entries
/// to a new network, stream, epoch, or signing key.
fn pin_scope(
    directory: &Path, config: &Config, witness_key: &str, state: &Checkpoint,
) -> Result<(), Error> {
    let directory=fs::canonicalize(directory).map_err(|_|Error::InvalidStoredScope)?;
    let path=directory.join("witness.scope");
    let expected=json!({
        "v":1, "collatorId":config.collator_id,
        "collatorPubKey":config.collator_pubkey,
        "network":config.network, "stream":config.stream,
        "epoch":config.epoch,"witnessPubKey":witness_key,
    });
    let encoded=serde_json::to_vec(&expected).map_err(|_|Error::InvalidStoredScope)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len()!=encoded.len() as u64 {
                return Err(Error::InvalidStoredScope);
            }
            let actual=fs::read(&path).map_err(|_|Error::InvalidStoredScope)?;
            if actual!=encoded {return Err(Error::InvalidStoredScope);}
        },
        Err(err) if err.kind()==std::io::ErrorKind::NotFound => {
            if state.last_seq!=0 {return Err(Error::InvalidStoredScope);}
            let mut file=OpenOptions::new()
                .write(true).create_new(true).open(&path)
                .map_err(|_|Error::InvalidStoredScope)?;
            file.write_all(&encoded).and_then(|_|file.sync_all())
                .map_err(|_|Error::InvalidStoredScope)?;
            File::open(&directory).and_then(|f|f.sync_all())
                .map_err(|_|Error::InvalidStoredScope)?;
        },
        Err(_) =>return Err(Error::InvalidStoredScope),
    }
    Ok(())
}

/// A signed checkpoint can be created only from the witness's own verified
/// durable current state. Never accept a caller-supplied head for this method.
pub struct WitnessService {
    tape: DurableTape,
    witness_private_key: SecretKey,
    witness_pubkey_hex: String,
    collator_id: String,
    network: String,
    stream: String,
    epoch: u64,
}
impl WitnessService {
    pub fn open(
        directory: &Path, config: Config, witness_private_key_bytes: &[u8; 32],
    ) -> Result<Self, Error> {
        config.validate()?;
        let secp = Secp256k1::new();
        let witness_private_key=SecretKey::from_slice(witness_private_key_bytes)
            .map_err(|_| Error::InvalidKey)?;
        let witness_pubkey=PublicKey::from_secret_key(&secp, &witness_private_key);
        let witness_pubkey_hex=hex(&witness_pubkey.serialize());
        // Witness must not have the same signing identity as collator.
        WitnessScope::new(
            &config.collator_id, &config.network, &config.stream,
            config.epoch, &witness_pubkey_hex,
        )?;
        if !matches!(config.collator_pubkey.len(), 66 | 130)
            || !config.collator_pubkey.bytes().all(|b|
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(Error::InvalidKey);
        }
        let collator_pubkey_bytes: Vec<u8> = config.collator_pubkey.as_bytes()
            .chunks_exact(2)
            .map(|p| std::str::from_utf8(p).ok().and_then(|s| u8::from_str_radix(s,16).ok()))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::InvalidKey)?;
        let collator_pubkey=PublicKey::from_slice(&collator_pubkey_bytes)
            .map_err(|_|Error::InvalidKey)?;
        if collator_pubkey == witness_pubkey { return Err(Error::InvalidKey); }
        let tape=DurableTape::open(
            directory, "witness", &config.collator_id,
            &config.collator_pubkey, config.max_entries,
            ImportMode::RequireAnchor,
        )?;
        // Bind persistent records to a single network/stream/epoch and the
        // collator + witness identities. This happens while the tape OS lock
        // is held, so competing service instances cannot race the first pin.
        pin_scope(directory, &config, &witness_pubkey_hex, &tape.checkpoint())?;
        Ok(Self {
            tape,witness_private_key,witness_pubkey_hex,
            collator_id:config.collator_id, network:config.network,
            stream:config.stream, epoch:config.epoch,
        })
    }
    pub fn public_key(&self)->&str { &self.witness_pubkey_hex }
    pub fn checkpoint(&self)->Checkpoint { self.tape.checkpoint() }

    /// Exact compare-and-swap of a signed *next* entry. The service validates
    /// both the trader signature and collator signature, the canonical hash,
    /// ownership, strict sequence and predecessor before any persistence.
    /// The OS file lock serializes any other attempted service instance.
    pub fn compare_and_swap(
        &mut self, expected: &Checkpoint, signed_entry: &str,
    ) -> Result<Checkpoint, Error> {
        if &self.tape.checkpoint() != expected { return Err(Error::Conflict); }
        self.tape.append_signed(signed_entry).map_err(Error::Durable)
    }

    /// Signs the current committed head and a fresh caller-provided challenge.
    /// Clients must generate a *new random* challenge for each call and verify
    /// against an independently pinned witness key using WitnessScope.
    pub fn attest_latest(&self, challenge: &str) -> Result<String, Error> {
        if !valid_challenge(challenge) { return Err(Error::InvalidChallenge); }
        let cp=self.tape.checkpoint();
        let unsigned=json!({
            "domain":DOMAIN, "v":1,
            "network":self.network,"collatorId":self.collator_id,
            "stream":self.stream,"epoch":self.epoch,
            "seq":cp.last_seq, "headHash":cp.last_hash,
            "seenOrders":cp.seen_orders, "challenge":challenge,
        });
        let payload=canonical_json(&unsigned)?;
        let digest=sha256_hex(&payload);
        let mut digest_bytes=[0u8;32];
        for (i,b) in digest_bytes.iter_mut().enumerate(){
            *b=u8::from_str_radix(&digest[i*2..i*2+2],16)
                .map_err(|_|Error::InvalidKey)?;
        }
        let signature=Secp256k1::signing_only().sign_ecdsa(
            &Message::from_digest(digest_bytes), &self.witness_private_key
        );
        let mut reply=unsigned;
        reply["sigWitness"]=Value::String(hex(&signature.serialize_compact()));
        serde_json::to_string(&reply).map_err(|_|Error::InvalidScope)
    }
}
