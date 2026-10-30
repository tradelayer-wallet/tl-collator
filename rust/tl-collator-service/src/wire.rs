//! `WireMsg` v1 parsing and construction (port of `src/types.ts`, `src/validate.ts`
//! `isWireMsg`, and `spec/schemas/wiremsg.v1.schema.json`). Input is strict: duplicate
//! object keys, unsafe numeric tokens, over-deep nesting and over-long messages are
//! rejected by `tl_collator_wire::parse_canonical_text` before any field is read.
use serde_json::{json, Value};
use tl_collator_wire::{parse_canonical_text, MAX_SAFE_INTEGER};

/// Longest accepted RPC identifier/label field.
pub const MAX_FIELD_BYTES: usize = 512;
pub const MAX_ADVERTISED_SERVICES: usize = 16;
pub const MAX_ADVERTISED_METHODS: usize = 256;

#[derive(Clone, Debug, PartialEq)]
pub enum WireIn {
    Hello {
        client_id: String,
        want: Vec<String>,
    },
    Submit {
        order: Value,
    },
    TapeSub {
        /// Already clamped to `>= 1` like `Math.max(1, fromSeq)`; a fractional value
        /// rounds up (legacy compared `seq >= fromSeq`).
        from_seq: u64,
    },
    /// Valid frames the server never acts on (clients echo them); ignored like the legacy handler.
    Ignored(&'static str),
    RpcAdvertise {
        node_id: String,
        services: Vec<Value>,
        /// Versioned extension: canonical provider-auth proof (see `tl-rpc-router`).
        proof: Option<String>,
    },
    RpcReq {
        req: Value,
    },
    RpcRes {
        res: Value,
    },
    Ping {
        ts: Value,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Larger than the configured message limit: `ERR msg_too_large` and close.
    TooLarge,
    /// Not JSON / not an object with string `t` and numeric `v`: dropped silently (legacy).
    Drop,
    /// Well-formed envelope that fails the schema: `ERR SCHEMA_INVALID`.
    Schema(&'static str),
}

fn string_field<'a>(v: &'a Value, name: &'static str) -> Result<&'a str, WireError> {
    v.get(name)
        .and_then(Value::as_str)
        .filter(|s| s.len() <= MAX_FIELD_BYTES * 4)
        .ok_or(WireError::Schema(name))
}

fn is_number(v: &Value) -> bool {
    v.is_number()
}

fn services(v: &Value) -> Result<Vec<Value>, WireError> {
    let list = v
        .get("services")
        .and_then(Value::as_array)
        .ok_or(WireError::Schema("services"))?;
    if list.len() > MAX_ADVERTISED_SERVICES {
        return Err(WireError::Schema("services"));
    }
    for s in list {
        s.get("service")
            .and_then(Value::as_str)
            .ok_or(WireError::Schema("service"))?;
        if let Some(n) = s.get("network") {
            n.as_str().ok_or(WireError::Schema("network"))?;
        }
        if let Some(m) = s.get("methods") {
            let m = m.as_array().ok_or(WireError::Schema("methods"))?;
            if m.len() > MAX_ADVERTISED_METHODS || !m.iter().all(Value::is_string) {
                return Err(WireError::Schema("methods"));
            }
        }
        if let Some(l) = s.get("label") {
            l.as_str().ok_or(WireError::Schema("label"))?;
        }
    }
    Ok(list.clone())
}

fn from_seq(v: &Value) -> Result<u64, WireError> {
    match v.get("fromSeq") {
        None => Ok(1),
        Some(Value::Number(n)) => {
            let f = n.as_f64().ok_or(WireError::Schema("fromSeq"))?;
            if !f.is_finite() || f <= 1.0 {
                Ok(1)
            } else if f >= MAX_SAFE_INTEGER as f64 {
                Ok(MAX_SAFE_INTEGER)
            } else {
                Ok(f.ceil() as u64)
            }
        }
        Some(_) => Err(WireError::Schema("fromSeq")),
    }
}

pub fn parse_wire(text: &str, max_bytes: usize) -> Result<WireIn, WireError> {
    if text.len() > max_bytes {
        return Err(WireError::TooLarge);
    }
    let value = parse_canonical_text(text).map_err(|_| WireError::Drop)?;
    let t = value
        .get("t")
        .and_then(Value::as_str)
        .ok_or(WireError::Drop)?;
    if !value.get("v").is_some_and(is_number) {
        return Err(WireError::Drop);
    }
    if value.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(WireError::Schema("v"));
    }
    match t {
        "HELLO" => {
            let want = value
                .get("want")
                .and_then(Value::as_array)
                .ok_or(WireError::Schema("want"))?;
            if want.len() > 3
                || !want
                    .iter()
                    .all(|w| matches!(w.as_str(), Some("TAPE" | "SUBMIT" | "RPC")))
            {
                return Err(WireError::Schema("want"));
            }
            Ok(WireIn::Hello {
                client_id: string_field(&value, "clientId")?.to_owned(),
                want: want
                    .iter()
                    .filter_map(|w| w.as_str().map(str::to_owned))
                    .collect(),
            })
        }
        "SUBMIT" => {
            let order = value
                .get("order")
                .filter(|o| o.is_object())
                .ok_or(WireError::Schema("order"))?;
            Ok(WireIn::Submit {
                order: order.clone(),
            })
        }
        "TAPE_SUB" => Ok(WireIn::TapeSub {
            from_seq: from_seq(&value)?,
        }),
        "TAPE_ENTRY" => {
            value
                .get("entry")
                .filter(|e| e.is_object())
                .ok_or(WireError::Schema("entry"))?;
            Ok(WireIn::Ignored("TAPE_ENTRY"))
        }
        "TAPE_END" => {
            value
                .get("lastSeq")
                .filter(|n| is_number(n))
                .ok_or(WireError::Schema("lastSeq"))?;
            Ok(WireIn::Ignored("TAPE_END"))
        }
        "RPC_ADVERTISE" => {
            let proof = match value.get("proof") {
                None | Some(Value::Null) => None,
                Some(Value::String(p)) => Some(p.clone()),
                Some(_) => return Err(WireError::Schema("proof")),
            };
            Ok(WireIn::RpcAdvertise {
                node_id: string_field(&value, "nodeId")?.to_owned(),
                services: services(&value)?,
                proof,
            })
        }
        "RPC_REQ" => {
            let req = value
                .get("req")
                .filter(|r| r.is_object())
                .ok_or(WireError::Schema("req"))?;
            for name in ["id", "service", "method"] {
                string_field(req, name)?;
            }
            if let Some(n) = req.get("network") {
                n.as_str().ok_or(WireError::Schema("network"))?;
            }
            if let Some(t) = req.get("timeoutMs") {
                if !is_number(t) {
                    return Err(WireError::Schema("timeoutMs"));
                }
            }
            Ok(WireIn::RpcReq { req: req.clone() })
        }
        "RPC_RES" => {
            let res = value
                .get("res")
                .filter(|r| r.is_object())
                .ok_or(WireError::Schema("res"))?;
            string_field(res, "id")?;
            res.get("ok")
                .and_then(Value::as_bool)
                .ok_or(WireError::Schema("ok"))?;
            if let Some(e) = res.get("error") {
                string_field(e, "message")?;
            }
            Ok(WireIn::RpcRes { res: res.clone() })
        }
        "PING" | "PONG" => {
            let ts = value
                .get("ts")
                .filter(|n| is_number(n))
                .ok_or(WireError::Schema("ts"))?;
            if t == "PING" {
                Ok(WireIn::Ping { ts: ts.clone() })
            } else {
                Ok(WireIn::Ignored("PONG"))
            }
        }
        "ERR" => {
            string_field(&value, "code")?;
            string_field(&value, "msg")?;
            Ok(WireIn::Ignored("ERR"))
        }
        _ => Err(WireError::Schema("t")),
    }
}

/// Outbound constructors. All return the JSON object to serialize with `to_string`.
pub fn err(code: &str, msg: &str) -> Value {
    json!({"t": "ERR", "v": 1, "code": code, "msg": msg})
}

pub fn pong(ts: &Value) -> Value {
    json!({"t": "PONG", "v": 1, "ts": ts})
}

pub fn tape_end(last_seq: u64) -> Value {
    json!({"t": "TAPE_END", "v": 1, "lastSeq": last_seq})
}

pub fn tape_entry(entry: Value) -> Value {
    json!({"t": "TAPE_ENTRY", "v": 1, "entry": entry})
}

pub fn rpc_res(res: Value) -> Value {
    json!({"t": "RPC_RES", "v": 1, "res": res})
}

pub fn rpc_req(req: Value) -> Value {
    json!({"t": "RPC_REQ", "v": 1, "req": req})
}

/// Versioned extension answering a proof-less `RPC_ADVERTISE`.
pub fn rpc_challenge(nonce: &str, domain: &str) -> Value {
    json!({"t": "RPC_CHALLENGE", "v": 1, "challenge": nonce, "domain": domain})
}
