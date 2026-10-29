//! Offline verification of an independent challenge-bound signed checkpoint.
//! This module does not implement or contact a remote monotonic witness service.
use crate::{
    canonical_json, parse_canonical_text, sha256_hex,
    verify::{public_key, verify_compact, Checkpoint, VerifiedReplay, VerifyError},
    Error as CanonError, MAX_SAFE_INTEGER,
};
use secp256k1::PublicKey;
use serde_json::Value;
use std::{fmt, io::BufRead};

const DOMAIN: &str = "TradeLayer/collator/checkpoint/v1";
const KEYS: [&str; 11] = [
    "domain",
    "v",
    "network",
    "collatorId",
    "stream",
    "epoch",
    "seq",
    "headHash",
    "seenOrders",
    "challenge",
    "sigWitness",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessError {
    Canon(CanonError),
    Verify(VerifyError),
    Invalid(&'static str),
    WrongScope,
    StaleChallenge,
    BadSignature,
    Rollback,
    Fork,
}
impl From<CanonError> for WitnessError {
    fn from(e: CanonError) -> Self {
        Self::Canon(e)
    }
}
impl From<VerifyError> for WitnessError {
    fn from(e: VerifyError) -> Self {
        Self::Verify(e)
    }
}
impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WitnessError {}

fn visible(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}
fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn exact_unsigned(value: &Value) -> Result<u64, WitnessError> {
    let canonical = canonical_json(value)?;
    let amount = canonical
        .parse::<u64>()
        .map_err(|_| WitnessError::Invalid("number"))?;
    if amount > MAX_SAFE_INTEGER {
        return Err(WitnessError::Invalid("number"));
    }
    Ok(amount)
}
fn get_str<'a>(value: &'a Value, name: &'static str) -> Result<&'a str, WitnessError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or(WitnessError::Invalid(name))
}
fn get_uint(value: &Value, name: &'static str) -> Result<u64, WitnessError> {
    exact_unsigned(value.get(name).ok_or(WitnessError::Invalid(name))?)
}

/// The witness scope must be operator configured and pinned outside the tape.
/// The witness public key must be independent of the collator signing key.
pub struct WitnessScope {
    collator_id: String,
    network: String,
    stream: String,
    epoch: u64,
    witness_pubkey: PublicKey,
}
impl WitnessScope {
    pub fn new(
        collator_id: &str,
        network: &str,
        stream: &str,
        epoch: u64,
        trusted_witness_pubkey_hex: &str,
    ) -> Result<Self, WitnessError> {
        if !visible(collator_id)
            || !visible(network)
            || !visible(stream)
            || epoch > MAX_SAFE_INTEGER
        {
            return Err(WitnessError::Invalid("scope"));
        }
        let witness_pubkey = public_key(trusted_witness_pubkey_hex)?;
        Ok(Self {
            collator_id: collator_id.into(),
            network: network.into(),
            stream: stream.into(),
            epoch,
            witness_pubkey,
        })
    }

    /// Validate a signed receipt returned by an independently queried witness.
    /// The caller must supply a new 32-byte CSPRNG challenge per query.
    /// A signature only proves what the witness signed, not that its remote
    /// storage implements an honest monotonic compare-and-swap protocol.
    pub fn verify_receipt(
        &self,
        raw_json: &str,
        expected_challenge: &str,
    ) -> Result<VerifiedReceipt, WitnessError> {
        if !lower_hash(expected_challenge) || expected_challenge.bytes().all(|b| b == b'0') {
            return Err(WitnessError::Invalid("challenge"));
        }
        let value = parse_canonical_text(raw_json)?;
        let map = value.as_object().ok_or(WitnessError::Invalid("object"))?;
        if map.len() != KEYS.len() || KEYS.iter().any(|k| !map.contains_key(*k)) {
            return Err(WitnessError::Invalid("fields"));
        }
        if get_str(&value, "domain")? != DOMAIN || get_uint(&value, "v")? != 1 {
            return Err(WitnessError::Invalid("domain"));
        }
        if get_str(&value, "network")? != self.network
            || get_str(&value, "collatorId")? != self.collator_id
            || get_str(&value, "stream")? != self.stream
            || get_uint(&value, "epoch")? != self.epoch
        {
            return Err(WitnessError::WrongScope);
        }
        let challenge = get_str(&value, "challenge")?;
        if challenge != expected_challenge {
            return Err(WitnessError::StaleChallenge);
        }
        let seq = get_uint(&value, "seq")?;
        let seen_orders = usize::try_from(get_uint(&value, "seenOrders")?)
            .map_err(|_| WitnessError::Invalid("orders"))?;
        if seen_orders as u64 != seq {
            return Err(WitnessError::Invalid("orders"));
        }
        let head_hash = get_str(&value, "headHash")?;
        if !((seq == 0 && head_hash.is_empty()) || (seq > 0 && lower_hash(head_hash))) {
            return Err(WitnessError::Invalid("headHash"));
        }
        let sig = get_str(&value, "sigWitness")?;
        let mut payload = map.clone();
        payload.remove("sigWitness");
        let canonical = canonical_json(&Value::Object(payload))?;
        let digest = sha256_hex(&canonical);
        verify_compact(&digest, sig, &self.witness_pubkey)
            .map_err(|_| WitnessError::BadSignature)?;
        Ok(VerifiedReceipt {
            seq,
            head_hash: head_hash.to_owned(),
            seen_orders,
        })
    }

    /// Independently verify signed tape history and match the receipt at its
    /// exact witnessed sequence. A truncated or divergent prefix fails closed.
    /// This does not read or modify the local checkpoint, or repair any file.
    pub fn verify_tape<R: BufRead>(
        &self,
        input: R,
        collator_pubkey_hex: &str,
        max_entries: usize,
        receipt: &VerifiedReceipt,
    ) -> Result<Checkpoint, WitnessError> {
        // A collator must not also act as its own independent witness.
        if public_key(collator_pubkey_hex)? == self.witness_pubkey {
            return Err(WitnessError::Invalid("independence"));
        }
        let mut seen = receipt.seq == 0;
        let mut fork = false;
        let replay = VerifiedReplay::from_ndjson_with_hook(
            input,
            self.collator_id.as_str(),
            collator_pubkey_hex,
            max_entries,
            |checkpoint| {
                if checkpoint.last_seq == receipt.seq {
                    if checkpoint.last_hash == receipt.head_hash
                        && checkpoint.seen_orders == receipt.seen_orders
                    {
                        seen = true;
                    } else {
                        fork = true;
                    }
                }
            },
        )?;
        if fork {
            return Err(WitnessError::Fork);
        }
        if !seen {
            return Err(WitnessError::Rollback);
        }
        Ok(replay.checkpoint())
    }
}

/// Receipt proof validated under a pinned, independent witness key.
/// Cannot be manually constructed outside the module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReceipt {
    seq: u64,
    head_hash: String,
    seen_orders: usize,
}
impl VerifiedReceipt {
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn head_hash(&self) -> &str {
        &self.head_hash
    }
    pub fn seen_orders(&self) -> usize {
        self.seen_orders
    }
}
