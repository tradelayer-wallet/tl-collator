//! Offline verification of TL-Canon v1 signed orders and hash-chained tape entries.
//! This module reads untrusted serialized entries and never signs or writes to disk.
use crate::{
    canonical_json, order_id, parse_canonical_text, tape_entry_hash, tape_signature_hash,
    Error as CanonError, MAX_INPUT_BYTES, MAX_SAFE_INTEGER,
};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, io::BufRead};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Canon(CanonError),
    Missing(&'static str),
    Invalid(&'static str),
    WrongCollator,
    BadOrderId,
    BadEntryHash,
    BadSignature,
    BrokenChain,
    Duplicate,
    UnknownOrder,
    NotOwner,
    Capacity,
    TornTail,
    Io,
    TooLarge,
}
impl From<CanonError> for VerifyError {
    fn from(value: CanonError) -> Self {
        Self::Canon(value)
    }
}
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for VerifyError {}

fn field<'a>(v: &'a Value, name: &'static str) -> Result<&'a Value, VerifyError> {
    v.get(name).ok_or(VerifyError::Missing(name))
}
fn str_field<'a>(v: &'a Value, name: &'static str) -> Result<&'a str, VerifyError> {
    field(v, name)?.as_str().ok_or(VerifyError::Invalid(name))
}
fn max_safe_number(v: &Value) -> Result<(), VerifyError> {
    let encoded = canonical_json(v)?;
    if encoded.parse::<i64>().is_err() {
        return Err(VerifyError::Invalid("integer"));
    }
    Ok(())
}
fn u64_field(v: &Value, name: &'static str) -> Result<u64, VerifyError> {
    let n=field(v,name)?;
    max_safe_number(n)?;
    let encoded=canonical_json(n)?;
    let u=encoded.parse::<u64>().map_err(|_| VerifyError::Invalid(name))?;
    if u>MAX_SAFE_INTEGER {return Err(VerifyError::Invalid(name));}
    Ok(u)
}
fn lowercase_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex_bytes(s: &str, expected: usize) -> Result<Vec<u8>, VerifyError> {
    if s.len()!=expected*2 || !s.bytes().all(|b|b.is_ascii_hexdigit()) {
        return Err(VerifyError::Invalid("hex"));
    }
    let mut output=Vec::with_capacity(expected);
    for pair in s.as_bytes().chunks_exact(2) {
        let txt=std::str::from_utf8(pair).map_err(|_| VerifyError::Invalid("hex"))?;
        output.push(u8::from_str_radix(txt,16).map_err(|_| VerifyError::Invalid("hex"))?);
    }
    Ok(output)
}
fn public_key(s: &str) -> Result<PublicKey, VerifyError> {
    let size=match s.len(){66=>33,130=>65,_=>return Err(VerifyError::Invalid("publicKey"))};
    let bytes=hex_bytes(s,size)?;
    PublicKey::from_slice(&bytes).map_err(|_|VerifyError::Invalid("publicKey"))
}

/// Verifies a 64-byte compact ECDSA signature on a prehashed 32-byte message.
/// Neither DER nor Bitcoin-message-prefix signatures are accepted.
pub fn verify_compact(
    message_hex: &str,
    signature_hex: &str,
    key: &PublicKey,
) -> Result<(), VerifyError> {
    let message=hex_bytes(message_hex,32)?;
    let digest: [u8;32] = message.try_into().map_err(|_|VerifyError::Invalid("digest"))?;
    let signature=hex_bytes(signature_hex,64)?;
    let signature=Signature::from_compact(&signature).map_err(|_|VerifyError::BadSignature)?;
    Secp256k1::verification_only()
        .verify_ecdsa(Message::from_digest(digest),&signature,key)
        .map_err(|_|VerifyError::BadSignature)
}

/// A fingerprint for the verified prefix. The ledger only advances after both
/// trader and collator signatures and all references have been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub last_seq: u64,
    pub last_hash: String,
    pub seen_orders: usize,
}

pub struct VerifiedReplay {
    collator_id: String,
    collator_pubkey: PublicKey,
    max_entries: usize,
    checkpoint: Checkpoint,
    owners: BTreeMap<String,String>,
}
impl VerifiedReplay {
    /// The public key is a pinned operator-configured trust anchor, never read
    /// from the entry itself. max_entries bounds memory consumed by owner lookup.
    pub fn new(
        collator_id: impl Into<String>,
        collator_pubkey_hex: &str,
        max_entries: usize,
    ) -> Result<Self, VerifyError> {
        let collator_id=collator_id.into();
        if collator_id.is_empty() || collator_id.len()>128 || max_entries==0
            || max_entries>1_000_000 { return Err(VerifyError::Invalid("config")); }
        Ok(Self {
            collator_id,
            collator_pubkey:public_key(collator_pubkey_hex)?,
            max_entries,
            checkpoint:Checkpoint {last_seq:0,last_hash:String::new(),seen_orders:0},
            owners:BTreeMap::new(),
        })
    }
    pub fn checkpoint(&self)->Checkpoint {self.checkpoint.clone()}
    pub fn owner_of(&self, id:&str)->Option<&str> {
        self.owners.get(&id.to_ascii_lowercase()).map(String::as_str)
    }
    pub fn contains(&self,id:&str)->bool {self.owner_of(id).is_some()}

    /// Verification is atomic with respect to this in-memory state. The input
    /// must originate from serialized JSON, preserving duplicate-key and
    /// fractional-token checks. No entry is acknowledged before this returns.
    pub fn apply_line(&mut self, line:&str)->Result<Checkpoint,VerifyError> {
        let entry=parse_canonical_text(line)?;
        self.apply_entry(&entry)?;
        Ok(self.checkpoint())
    }
    fn apply_entry(&mut self, entry:&Value)->Result<(),VerifyError> {
        if u64_field(entry,"v")?!=1 { return Err(VerifyError::Invalid("v")); }
        if str_field(entry,"collatorId")?!=self.collator_id {return Err(VerifyError::WrongCollator);}
        let seq=u64_field(entry,"seq")?;
        let next=self.checkpoint.last_seq.checked_add(1).ok_or(VerifyError::BrokenChain)?;
        if seq!=next {return Err(VerifyError::BrokenChain);}
        max_safe_number(field(entry,"receivedTs")?)?;
        let prev=str_field(entry,"prevHash")?;
        if prev!=self.checkpoint.last_hash {return Err(VerifyError::BrokenChain);}
        let entry_hash=str_field(entry,"entryHash")?;
        if !lowercase_hash(entry_hash) {return Err(VerifyError::BadEntryHash);}
        let order=field(entry,"order")?;
        if u64_field(order,"v")?!=1 {return Err(VerifyError::Invalid("order.v"));}
        let kind=str_field(order,"kind")?;
        if !matches!(kind,"NEW"|"CANCEL"|"REPLACE"){return Err(VerifyError::Invalid("kind"));}
        let body=field(order,"body")?;
        if u64_field(body,"v")?!=1{return Err(VerifyError::Invalid("body.v"));}
        if str_field(body,"market")?.is_empty(){return Err(VerifyError::Invalid("market"));}
        if !matches!(str_field(body,"side")?,"BUY"|"SELL"){return Err(VerifyError::Invalid("side"));}
        for name in ["px","qty"] {
            if str_field(body,name)?.is_empty(){return Err(VerifyError::Invalid(name));}
        }
        max_safe_number(field(body,"clientTs")?)?;
        let visibility=str_field(field(body,"visibility")?,"kind")?;
        if !matches!(visibility,"PUBLIC"|"DARK"|"CLEARLIST") {
            return Err(VerifyError::Invalid("visibility"));
        }
        if matches!(visibility,"DARK"|"CLEARLIST") && str_field(field(body,"visibility")?,"groupId")?.is_empty() {
            return Err(VerifyError::Invalid("groupId"));
        }
        let nonce=str_field(order,"clientNonce")?;
        if nonce.is_empty() || nonce.len()>256 || !nonce.bytes().all(|b|b.is_ascii_hexdigit()){
            return Err(VerifyError::Invalid("clientNonce"));
        }
        let id=str_field(order,"orderId")?;
        if !lowercase_hash(id) || order_id(order)?!=id {return Err(VerifyError::BadOrderId);}
        if self.owners.contains_key(id) {return Err(VerifyError::Duplicate);}
        if self.owners.len()>=self.max_entries {return Err(VerifyError::Capacity);}
        let trader=str_field(order,"traderPubKey")?;
        let trader_pubkey=public_key(trader)?;
        verify_compact(id,str_field(order,"sigTrader")?,&trader_pubkey)?;
        let owner=trader.to_ascii_lowercase();
        if matches!(kind,"CANCEL"|"REPLACE") {
            let name=if kind=="CANCEL" {"cancelsOrderId"} else {"replacesOrderId"};
            let target=str_field(order,name)?;
            if !lowercase_hash(target){return Err(VerifyError::Invalid(name));}
            let previous=self.owners.get(target).ok_or(VerifyError::UnknownOrder)?;
            if previous!=&owner {return Err(VerifyError::NotOwner);}
        }
        if tape_entry_hash(entry)?!=entry_hash {return Err(VerifyError::BadEntryHash);}
        let signed_hash=tape_signature_hash(entry,entry_hash)?;
        verify_compact(&signed_hash,str_field(entry,"sigCollator")?,&self.collator_pubkey)?;
        // All failure paths return before state advances.
        self.owners.insert(id.to_owned(),owner);
        self.checkpoint=Checkpoint {
            last_seq:seq, last_hash:entry_hash.to_owned(),seen_orders:self.owners.len()
        };
        Ok(())
    }
    /// Reconstruct the entire trusted prefix from persisted NDJSON without a
    /// disk mutation. A truncated final record and damaged interior refuse
    /// startup. No checkpoint is returned on failure.
    pub fn from_ndjson<R:BufRead>(
        mut input:R,
        collator_id:impl Into<String>,
        collator_pubkey_hex:&str,
        max_entries:usize,
    )->Result<Self,VerifyError>{
        let mut replay=Self::new(collator_id,collator_pubkey_hex,max_entries)?;
        let mut line=Vec::new();
        loop {
            let available=input.fill_buf().map_err(|_|VerifyError::Io)?;
            if available.is_empty() {
                if !line.is_empty(){return Err(VerifyError::TornTail);}
                return Ok(replay);
            }
            let newline=available.iter().position(|b|*b==b'\n');
            let n=newline.map_or(available.len(),|idx|idx+1);
            if line.len().saturating_add(n)>MAX_INPUT_BYTES+2 {
                return Err(VerifyError::TooLarge);
            }
            line.extend_from_slice(&available[..n]);
            let complete=newline.is_some();
            input.consume(n);
            if complete {
                let mut end=line.len()-1;
                if end>0 && line[end-1]==b'\r'{end-=1;}
                let text=std::str::from_utf8(&line[..end])
                    .map_err(|_|VerifyError::Invalid("UTF-8"))?;
                replay.apply_line(text)?;
                line.clear();
            }
        }
    }
}
