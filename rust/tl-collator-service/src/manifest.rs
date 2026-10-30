//! Signed manifest (port of `src/manifest.ts`). The body is a pure function of the
//! validated `Config`, the collator identity and build info supplied by the host; the
//! signature comes from a `DigestSigner` over `sha256(canonical_json(body))`, matching
//! `sha256Hex(stableStringify(body))` for the integer/string-only body.
use crate::config::Config;
use crate::signer::{DigestSigner, SignError};
use serde_json::{json, Map, Value};
use tl_collator_wire::{canonical_json, sha256_hex};

pub const MAX_ATTESTATIONS: usize = 128;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug)]
pub struct BuildInfo {
    pub version: String,
    pub git_sha: Option<String>,
    /// ISO-8601 text supplied by the host (the reducer has no wall clock).
    pub built_at: String,
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn text(v: &Value, key: &str, max: usize) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .map(str::to_owned)
}

fn safe_int(v: &Value, key: &str) -> Option<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SAFE)
}

/// Validate and rebuild one attestation; `None` drops it. The admin signature is passed
/// through for the wallet to verify (the collator holds no admin key), but only well-formed
/// 128-hex signatures, 33-byte hex keys and unexpired time windows are published.
fn attestation(item: &Value, now_s: u64) -> Option<Value> {
    let body = item.get("body").filter(|b| b.is_object())?;
    let sig = item.get("sigAdmin").and_then(Value::as_str)?;
    if !is_hex(sig, 128) {
        return None;
    }
    if body.get("v").and_then(Value::as_u64) != Some(1) {
        return None;
    }
    let kind = body.get("kind").and_then(Value::as_str)?;
    if kind != "COLLATOR_APPROVAL" && kind != "BUNDLER_APPROVAL" {
        return None;
    }
    let clearlist_id = safe_int(body, "clearlistId")?;
    let infra_pub = text(body, "infraPubKey", 66).filter(|k| is_hex(k, 66))?;
    let admin_pub = text(body, "adminPubKey", 66).filter(|k| is_hex(k, 66))?;
    let infra_id = text(body, "infraId", 128)?;
    let ws = text(body, "ws", 512)?;
    let issued = safe_int(body, "issuedAt")?;
    let expires = safe_int(body, "expiresAt")?;
    let nonce = text(body, "nonce", 128).filter(|n| n.bytes().all(|b| b.is_ascii_hexdigit()))?;
    if expires <= issued || expires <= now_s {
        return None;
    }
    Some(json!({
        "body": {
            "v": 1,
            "kind": kind,
            "clearlistId": clearlist_id,
            "infraPubKey": infra_pub,
            "infraId": infra_id,
            "ws": ws,
            "issuedAt": issued,
            "expiresAt": expires,
            "nonce": nonce,
            "adminPubKey": admin_pub,
        },
        "sigAdmin": sig,
    }))
}

/// `now_s` is unix seconds. Returns `None` when the input is not an array or nothing survives.
pub fn load_infra_attestations(raw: &Value, now_s: u64) -> Option<Vec<Value>> {
    let list = raw.as_array()?;
    let mut out = Vec::new();
    for item in list {
        if let Some(a) = attestation(item, now_s) {
            out.push(a);
            if out.len() >= MAX_ATTESTATIONS {
                break;
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

pub fn manifest_body(
    cfg: &Config,
    collator_id: &str,
    collator_pubkey: &str,
    build: &BuildInfo,
    attestations: Option<Vec<Value>>,
) -> Value {
    let mut m = Map::new();
    m.insert("v".into(), json!(1));
    m.insert("collatorId".into(), json!(collator_id));
    m.insert("collatorPubKey".into(), json!(collator_pubkey));
    for (key, value) in [
        ("name", &cfg.name),
        ("operator", &cfg.operator),
        ("region", &cfg.region),
    ] {
        if let Some(v) = value {
            m.insert(key.into(), json!(v));
        }
    }
    m.insert("roles".into(), json!(["collator"]));
    m.insert(
        "protocol".into(),
        json!({"wireMsgVersion": 1, "dataChannelLabel": "tl-bb", "maxMsgBytes": cfg.max_msg_bytes}),
    );
    m.insert(
        "tape".into(),
        json!({
            "format": "ndjson",
            "hash": "sha256",
            "indexStride": cfg.idx_stride,
            "replayBatch": cfg.replay_batch,
        }),
    );
    let mut clearlist = Map::new();
    clearlist.insert("enforce".into(), json!(cfg.clearlist_enforce));
    clearlist.insert("failMode".into(), json!(cfg.clearlist_fail_mode.as_str()));
    if let Some(url) = &cfg.clearlist_url {
        clearlist.insert("oracleUrl".into(), json!(url));
    }
    clearlist.insert("cacheTtlSec".into(), json!(cfg.clearlist_ttl_sec));
    m.insert(
        "policy".into(),
        json!({
            "clearlist": Value::Object(clearlist),
            "network": {
                "ipLogging": if cfg.ip_logging { "on" } else { "off" },
                "vpnFilterMode": cfg.vpn_filter_mode.as_str(),
                "asnBlockMode": cfg.asn_block_mode.as_str(),
            },
            "rateLimit": {
                "submitRps": cfg.submit_rate_per_sec,
                "submitBurst": cfg.submit_burst,
                "connMax": cfg.conn_max,
            },
        }),
    );
    let mut b = Map::new();
    b.insert("version".into(), json!(build.version));
    if let Some(sha) = &build.git_sha {
        b.insert("gitSha".into(), json!(sha));
    }
    b.insert("builtAt".into(), json!(build.built_at));
    m.insert("build".into(), Value::Object(b));
    if let Some(list) = attestations {
        m.insert("infraAttestations".into(), Value::Array(list));
    }
    Value::Object(m)
}

pub fn sign_manifest(body: Value, signer: &dyn DigestSigner) -> Result<Value, SignError> {
    let canonical = canonical_json(&body).map_err(|_| SignError::BadDigest)?;
    let digest = sha256_hex(&canonical);
    let sig = signer.sign_digest(&digest)?;
    let mut signed = body;
    if let Some(m) = signed.as_object_mut() {
        m.insert("sigCollator".into(), json!(sig));
    }
    Ok(signed)
}
