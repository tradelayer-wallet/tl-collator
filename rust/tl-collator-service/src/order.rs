//! `OrderEnvelopeV1` admission checks that need no state: shape (the Ajv schema of
//! `spec/schemas/order-envelope.v1.schema.json` plus the stricter rules `tl-collator-wire`
//! applies when replaying), order-id binding and the trader signature
//! (`verifyTraderSig`, `src/crypto.ts`).
use crate::signer::hex_decode;
use secp256k1::PublicKey;
use serde_json::Value;
use tl_collator_wire::order_id;
use tl_collator_wire::verify::verify_compact;

const MAX_MARKET: usize = 128;
const MAX_DECIMAL: usize = 64;
const MAX_GROUP: usize = 128;
const MAX_NONCE: usize = 256;

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn text<'a>(v: &'a Value, key: &str, max: usize) -> Option<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| s.len() <= max)
}

fn safe_number(v: Option<&Value>) -> bool {
    v.is_some_and(|n| n.is_u64() || n.is_i64())
        && v.and_then(Value::as_i64)
            .is_some_and(|n| n.unsigned_abs() <= tl_collator_wire::MAX_SAFE_INTEGER)
}

/// `Err` carries the legacy `SCHEMA_INVALID` message to send.
pub fn validate_shape(order: &Value) -> Result<(), &'static str> {
    const BAD: &str = "invalid OrderEnvelopeV1 schema";
    if !order.is_object() || order.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(BAD);
    }
    let kind = order.get("kind").and_then(Value::as_str).ok_or(BAD)?;
    if !matches!(kind, "NEW" | "CANCEL" | "REPLACE") {
        return Err(BAD);
    }
    let body = order.get("body").filter(|b| b.is_object()).ok_or(BAD)?;
    if body.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(BAD);
    }
    if text(body, "market", MAX_MARKET).is_none_or(str::is_empty) {
        return Err(BAD);
    }
    if !matches!(
        body.get("side").and_then(Value::as_str),
        Some("BUY" | "SELL")
    ) {
        return Err(BAD);
    }
    for k in ["px", "qty"] {
        if text(body, k, MAX_DECIMAL).is_none_or(str::is_empty) {
            return Err(BAD);
        }
    }
    if let Some(t) = body.get("tif") {
        if !matches!(t.as_str(), Some("GTC" | "IOC" | "FOK")) {
            return Err(BAD);
        }
    }
    if let Some(e) = body.get("expiryTs") {
        if !safe_number(Some(e)) {
            return Err(BAD);
        }
    }
    if let Some(t) = body.get("clearlistTag") {
        if t.as_str().is_none_or(|s| s.len() > MAX_GROUP) {
            return Err(BAD);
        }
    }
    if !safe_number(body.get("clientTs")) {
        return Err(BAD);
    }
    let vis = body
        .get("visibility")
        .filter(|v| v.is_object())
        .ok_or(BAD)?;
    match vis.get("kind").and_then(Value::as_str) {
        Some("PUBLIC") => {}
        Some("CLEARLIST" | "DARK") => {
            if text(vis, "groupId", MAX_GROUP).is_none_or(str::is_empty) {
                return Err(BAD);
            }
        }
        _ => return Err(BAD),
    }
    let trader = text(order, "traderPubKey", 130).ok_or(BAD)?;
    if !(trader.len() == 66 || trader.len() == 130)
        || !trader.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(BAD);
    }
    let nonce = text(order, "clientNonce", MAX_NONCE).ok_or(BAD)?;
    if nonce.is_empty() || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BAD);
    }
    // Lowercase only: an uppercase spelling of the same id would defeat duplicate detection.
    if !text(order, "orderId", 64).is_some_and(|s| lower_hex(s, 64)) {
        return Err(BAD);
    }
    let sig = text(order, "sigTrader", 128).ok_or(BAD)?;
    if sig.len() != 128 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BAD);
    }
    for k in ["replacesOrderId", "cancelsOrderId"] {
        if let Some(t) = order.get(k) {
            if !t.as_str().is_some_and(|s| lower_hex(s, 64)) {
                return Err(BAD);
            }
        }
    }
    match kind {
        "CANCEL" if order.get("cancelsOrderId").is_none() => Err("missing cancelsOrderId"),
        "REPLACE" if order.get("replacesOrderId").is_none() => Err("missing replacesOrderId"),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderCheck {
    /// The claimed `orderId` is not the hash of the envelope.
    IdMismatch,
    /// `sigTrader` does not verify against `traderPubKey` over `orderId`.
    BadSignature,
}

/// The order id must be recomputed from the signed contents (legacy accepted any 32-byte
/// value and only checked that it was signed, leaving the order body unauthenticated), then
/// the compact ECDSA signature over that id must verify.
pub fn verify_binding(order: &Value) -> Result<String, OrderCheck> {
    let claimed = order.get("orderId").and_then(Value::as_str).unwrap_or("");
    let computed = order_id(order).map_err(|_| OrderCheck::IdMismatch)?;
    if computed != claimed {
        return Err(OrderCheck::IdMismatch);
    }
    let key_hex = order
        .get("traderPubKey")
        .and_then(Value::as_str)
        .unwrap_or("");
    let key_bytes = hex_decode(key_hex).ok_or(OrderCheck::BadSignature)?;
    let key = PublicKey::from_slice(&key_bytes).map_err(|_| OrderCheck::BadSignature)?;
    let sig = order.get("sigTrader").and_then(Value::as_str).unwrap_or("");
    verify_compact(&computed, sig, &key).map_err(|_| OrderCheck::BadSignature)?;
    Ok(computed)
}
