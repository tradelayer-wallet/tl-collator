//! TL-Canon v1 Rust reference contract.
//! This crate canonicalizes intent and verifies signed replay records.
//! It performs no signing, networking, or live order admission.
#![forbid(unsafe_code)]

pub mod durable;
pub mod verify;
pub mod witness;

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_DEPTH: usize = 64;
pub const MAX_INPUT_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidJson,
    DuplicateKey,
    InvalidNumber,
    UnsafeKey,
    TooDeep,
    TooLarge,
    NotAnObject,
    MissingField,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// A JSON visitor which rejects ambiguous duplicate object fields at any depth.
/// Ordinary JSON parser implementations may silently keep the last occurrence.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value with unique keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(Number::from(v))))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(Number::from(v))))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Number::from_f64(v)
                    .map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid finite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, UniqueValue(v))) = a.next_entry::<String, UniqueValue>()? {
                    if values.insert(key, v).is_some() {
                        return Err(de::Error::custom("duplicate JSON object field"));
                    }
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        d.deserialize_any(UniqueVisitor)
    }
}

/// Parse JSON without losing fractional mantissa digits that would round to
/// a safe integer under IEEE-754. Invalid surrogate escapes are rejected by serde.
pub fn parse_canonical_text(text: &str) -> Result<Value, Error> {
    if text.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    // Fully validate before scanning numbers, so strings and JSON escapes are
    // always well formed. An independent numeric-token scan follows.
    let UniqueValue(value) =
        serde_json::from_str::<UniqueValue>(text).map_err(|_| Error::InvalidJson)?;
    for token in number_tokens(text) {
        let approx: f64 = token.parse().map_err(|_| Error::InvalidNumber)?;
        if approx.is_finite() && approx.fract() == 0.0 && approx.abs() <= MAX_SAFE_INTEGER as f64 {
            let exact = exact_integer_token(token);
            if exact != Some(approx as i128) {
                return Err(Error::InvalidNumber);
            }
        }
    }
    Ok(value)
}

/// The text is already known to be valid JSON. Scan numeric tokens only outside
/// complete strings, skipping escaped bytes while retaining exact token text.
fn number_tokens(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                } else if b[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if b[i] == b'-' || b[i].is_ascii_digit() {
            let start = i;
            if b[i] == b'-' {
                i += 1;
            }
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i < b.len() && b[i] == b'.' {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
                i += 1;
                if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
                    i += 1;
                }
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            tokens.push(&text[start..i]);
        } else {
            i += 1;
        }
    }
    tokens
}

/// Exact decimal exponent arithmetic bounded to the JavaScript safe range.
/// None means the literal has a nonzero fractional component or is too large.
fn exact_integer_token(text: &str) -> Option<i128> {
    let negative = text.starts_with('-');
    let text = text.strip_prefix('-').unwrap_or(text);
    let (mantissa, exponent) = if let Some(i) = text.find(['e', 'E']) {
        (&text[..i], text[i + 1..].parse::<i64>().ok()?)
    } else {
        (text, 0)
    };
    let (whole, fractional) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = format!("{whole}{fractional}")
        .trim_start_matches('0')
        .to_string();
    if digits.is_empty() {
        return Some(0);
    }
    let shift = exponent.checked_sub(fractional.len() as i64)?;
    if shift >= 0 {
        let extra = usize::try_from(shift).ok()?;
        if digits.len().checked_add(extra)? > 16 {
            return None;
        }
        digits.push_str(&"0".repeat(extra));
    } else {
        let cut = usize::try_from(-shift).ok()?;
        if cut >= digits.len()
            || digits.as_bytes()[digits.len() - cut..]
                .iter()
                .any(|b| *b != b'0')
        {
            return None;
        }
        digits.truncate(digits.len() - cut);
    }
    let value = digits.parse::<u64>().ok()?;
    if value > MAX_SAFE_INTEGER {
        return None;
    }
    Some(if negative {
        -(value as i128)
    } else {
        value as i128
    })
}

fn json_string(s: &str) -> String {
    // Serde uses standard compact JSON escaping and preserves UTF-8.
    serde_json::to_string(s).expect("valid UTF-8 Rust string")
}
fn canon(value: &Value, depth: usize, out: &mut String) -> Result<(), Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(x) => out.push_str(if *x { "true" } else { "false" }),
        Value::String(s) => out.push_str(&json_string(s)),
        Value::Number(n) => {
            let signed = if let Some(i) = n.as_i64() {
                i as i128
            } else if let Some(u) = n.as_u64() {
                u as i128
            } else {
                let f = n.as_f64().ok_or(Error::InvalidNumber)?;
                if !f.is_finite() || f.fract() != 0.0 || f.abs() > MAX_SAFE_INTEGER as f64 {
                    return Err(Error::InvalidNumber);
                }
                f as i128
            };
            if signed.unsigned_abs() > MAX_SAFE_INTEGER as u128 {
                return Err(Error::InvalidNumber);
            }
            out.push_str(&signed.to_string());
        }
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return Err(Error::TooDeep);
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(items) => {
            if depth >= MAX_DEPTH {
                return Err(Error::TooDeep);
            }
            out.push('{');
            // serde_json default Map uses BTreeMap<String,_>. The UTF-8
            // lexicographic order of valid Rust String equals code-point order.
            for (i, (k, v)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(k));
                out.push(':');
                canon(v, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}
pub fn canonical_json(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    canon(value, 0, &mut out)?;
    if out.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(out)
}
pub fn sha256_hex(body: &str) -> String {
    let result = Sha256::digest(body.as_bytes());
    result.iter().map(|b| format!("{b:02x}")).collect()
}
fn unsafe_field(value: &Value, depth: usize) -> Result<(), Error> {
    if depth >= MAX_DEPTH && (value.is_array() || value.is_object()) {
        return Err(Error::TooDeep);
    }
    match value {
        Value::Array(a) => {
            for item in a {
                unsafe_field(item, depth + 1)?;
            }
        }
        Value::Object(m) => {
            for (k, v) in m {
                if matches!(k.as_str(), "__proto__" | "constructor" | "prototype") {
                    return Err(Error::UnsafeKey);
                }
                unsafe_field(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn order_id(envelope: &Value) -> Result<String, Error> {
    let obj = envelope.as_object().ok_or(Error::NotAnObject)?;
    unsafe_field(envelope, 0)?;
    let mut signed = Map::new();
    for (k, v) in obj {
        if k != "orderId" && k != "sigTrader" {
            signed.insert(k.clone(), v.clone());
        }
    }
    Ok(sha256_hex(&canonical_json(&Value::Object(signed))?))
}
pub fn tape_entry_hash(entry: &Value) -> Result<String, Error> {
    let obj = entry.as_object().ok_or(Error::NotAnObject)?;
    let mut selected = Map::new();
    for key in ["v", "collatorId", "seq", "prevHash", "receivedTs", "order"] {
        selected.insert(
            key.to_string(),
            obj.get(key).ok_or(Error::MissingField)?.clone(),
        );
    }
    Ok(sha256_hex(&canonical_json(&Value::Object(selected))?))
}
pub fn tape_signature_hash(entry: &Value, entry_hash: &str) -> Result<String, Error> {
    let obj = entry.as_object().ok_or(Error::NotAnObject)?;
    let seq = obj.get("seq").ok_or(Error::MissingField)?;
    let seq = canonical_json(seq)?;
    let prev = obj
        .get("prevHash")
        .and_then(Value::as_str)
        .ok_or(Error::MissingField)?;
    let order = obj
        .get("order")
        .and_then(Value::as_object)
        .ok_or(Error::MissingField)?;
    let order_id = order
        .get("orderId")
        .and_then(Value::as_str)
        .ok_or(Error::MissingField)?;
    Ok(sha256_hex(&format!("{seq}|{prev}|{order_id}|{entry_hash}")))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_tokens_do_not_hide_fraction() {
        assert!(parse_canonical_text(r#"{"qty":9007199254740991.0000000000000001}"#).is_err());
        assert!(parse_canonical_text(r#"{"qty":9007199254740990.9999999999999999}"#).is_err());
        assert!(parse_canonical_text(r#"[3.0000000000000000001]"#).is_err());
        assert!(parse_canonical_text(r#"{"qty":1.0}"#).is_ok());
        assert!(parse_canonical_text(r#"[1e3,-0,9007199254740991.000]"#).is_ok());
        assert!(parse_canonical_text(r#"["1.0000000000000000001"]"#).is_ok());
    }
    #[test]
    fn duplicate_keys_are_rejected() {
        assert!(parse_canonical_text(r#"{"body":{"a":1,"a":2}}"#).is_err());
    }
    #[test]
    fn unsafe_key_is_rejected_for_signed_envelope() {
        let v = parse_canonical_text(r#"{"body":{"__proto__":1},"v":1}"#).unwrap();
        assert!(canonical_json(&v).unwrap().contains("__proto__"));
        assert_eq!(order_id(&v), Err(Error::UnsafeKey));
    }
    #[test]
    fn depth_is_bounded() {
        let s = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        let v = parse_canonical_text(&s).unwrap();
        assert_eq!(canonical_json(&v), Err(Error::TooDeep));
    }
    #[test]
    fn signed_fields_include_order_kind_and_cancellation() {
        let first = parse_canonical_text(
            r#"{"v":1,"kind":"NEW","body":{},"traderPubKey":"key","clientNonce":"n"}"#,
        )
        .unwrap();
        let mut second = first.clone();
        second["kind"] = Value::String("CANCEL".into());
        second["cancelsOrderId"] = Value::String("target".into());
        assert_ne!(order_id(&first).unwrap(), order_id(&second).unwrap());
        second["sigTrader"] = Value::String("fake".into());
        second["orderId"] = Value::String("not-derived".into());
        assert_eq!(
            order_id(&second).unwrap(),
            order_id(&{
                let mut copy = second.clone();
                copy.as_object_mut().unwrap().remove("sigTrader");
                copy.as_object_mut().unwrap().remove("orderId");
                copy
            })
            .unwrap()
        );
    }
}
