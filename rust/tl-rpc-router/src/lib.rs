//! In-memory routing contract for collator-mediated RPC. The host owns
//! authenticated transport/session lifetimes, a fresh boot secret, monotonic
//! time, byte-bounded I/O and delivery. This crate opens no network service,
//! loads no private key, builds no transaction and performs no runtime cutover.
//!
//! The provider challenge/proof exchange is an unreviewed v1 proposal. It is not
//! active in the TypeScript collator, whose RPC_ADVERTISE remains unauthenticated.
#![forbid(unsafe_code)]

use secp256k1::PublicKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tl_collator_wire::{canonical_json, parse_canonical_text, sha256_hex, verify::verify_compact};

pub const DOMAIN: &str = "TradeLayer/collator/rpc-provider/v1";
pub const MAX_BODY_BYTES: usize = 65_536;
pub const MAX_PROOF_BYTES: usize = 16_384;
pub const MAX_LABEL_BYTES: usize = 128;
pub const MAX_METHODS: usize = 64;
pub const MAX_PINS: usize = 256;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
/// Upper bound of every configurable duration; keeps `now + duration` below MAX_SAFE.
const MAX_DURATION_MS: u64 = 120_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    UnknownSession,
    Capacity,
    Clock,
    Unauthorized,
    Expired,
    WrongProvider,
    UnknownRequest,
    NoProvider,
    Overloaded,
}

impl Error {
    /// Error code for an RpcResponseV1 sent back to the requester.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Invalid(_) => "BAD_RPC_REQUEST",
            Error::NoProvider => "NO_RPC_PROVIDER",
            Error::Overloaded | Error::Capacity => "RPC_OVERLOADED",
            Error::Clock => "RPC_CLOCK_FAILED",
            Error::UnknownSession => "RPC_UNKNOWN_SESSION",
            Error::Unauthorized | Error::Expired => "RPC_UNAUTHORIZED",
            Error::WrongProvider | Error::UnknownRequest => "RPC_ROUTE_ERROR",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

fn label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_LABEL_BYTES
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn method(text: &str) -> bool {
    label(text) && !text.bytes().any(|b| b.is_ascii_uppercase())
}

/// Sorted, unique, canonical lowercase method names.
fn methods(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_METHODS
        && values.iter().all(|s| method(s))
        && values.windows(2).all(|w| w[0] < w[1])
}

/// Legacy `normalizeRpcMethod`: `String(method).trim().toLowerCase()`.
/// Only ASCII is accepted afterwards, so ASCII lowercasing is exact.
pub fn normalize_method(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn key(hex: &str) -> Result<PublicKey, Error> {
    if hex.len() != 66
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid("compressed public key"));
    }
    let mut bytes = [0u8; 33];
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| Error::Invalid("public key"))?;
        bytes[i] = u8::from_str_radix(text, 16).map_err(|_| Error::Invalid("public key"))?;
    }
    PublicKey::from_slice(&bytes).map_err(|_| Error::Invalid("public key"))
}

/// Operator-configured authority, never derived from an untrusted advertisement.
#[derive(Clone, Debug)]
pub struct ProviderPin {
    pub node_id: String,
    /// Lowercase hex compressed secp256k1 key.
    pub public_key: String,
    /// Sorted unique canonical lowercase names, already approved by the operator.
    pub methods: Vec<String>,
}

#[derive(Debug)]
pub struct Policy {
    collator_id: String,
    service: String,
    network: String,
    pins: BTreeMap<String, ProviderPin>,
}

impl Policy {
    pub fn new(
        collator_id: &str,
        service: &str,
        network: &str,
        pins: Vec<ProviderPin>,
    ) -> Result<Self, Error> {
        if !label(collator_id)
            || !label(service)
            || !label(network)
            || pins.is_empty()
            || pins.len() > MAX_PINS
        {
            return Err(Error::Invalid("policy"));
        }
        let mut map = BTreeMap::new();
        let mut keys = BTreeSet::new();
        for pin in pins {
            let serialized = key(&pin.public_key)?.serialize();
            if !label(&pin.node_id)
                || !methods(&pin.methods)
                || !keys.insert(serialized)
                || map.contains_key(&pin.node_id)
            {
                return Err(Error::Invalid("provider pin"));
            }
            map.insert(pin.node_id.clone(), pin);
        }
        Ok(Self {
            collator_id: collator_id.into(),
            service: service.into(),
            network: network.into(),
            pins: map,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub sessions: usize,
    pub pending: usize,
    pub per_requester: usize,
    pub per_provider: usize,
    pub challenge_ms: u64,
    pub advertisement_ms: u64,
    pub request_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sessions: 256,
            pending: 1000,
            per_requester: 32,
            per_provider: 64,
            challenge_ms: 10_000,
            advertisement_ms: 45_000,
            request_ms: 12_000,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<(), Error> {
        let ok = (1..=4096).contains(&self.sessions)
            && (1..=4096).contains(&self.pending)
            && (1..=self.pending).contains(&self.per_requester)
            && (1..=self.pending).contains(&self.per_provider)
            && (1..=30_000).contains(&self.challenge_ms)
            && (1..=60_000).contains(&self.advertisement_ms)
            && (1..=MAX_DURATION_MS).contains(&self.request_ms);
        if ok {
            Ok(())
        } else {
            Err(Error::Invalid("limits"))
        }
    }
}

/// Opaque server-side handle; transport identifiers and caller IDs cannot mint it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

struct Challenge {
    nonce: String,
    expires: u64,
}

struct Advertisement {
    node: String,
    methods: Vec<String>,
    expires: u64,
}

struct Session {
    challenge: Option<Challenge>,
    advert: Option<Advertisement>,
}

struct Pending {
    requester: SessionId,
    provider: SessionId,
    node: String,
    caller_id: String,
    deadline: u64,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub id: String,
    pub service: String,
    pub network: String,
    /// Normalized like the legacy collator (trim, lowercase) before checks.
    pub method: String,
    /// Opaque JSON parameters, forwarded byte-for-byte; not signed with TL-Canon.
    pub params_json: String,
    pub preferred_provider: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug)]
pub struct Dispatch {
    pub provider: SessionId,
    pub provider_node_id: String,
    /// Forward this server token in RPC_REQ.id, never the caller-selected ID.
    pub token: String,
    /// Normalized method name.
    pub method: String,
    pub params_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Timeout,
    PeerClosed,
}

#[derive(Debug)]
pub struct Completion {
    pub requester: SessionId,
    pub caller_id: String,
    pub provider_node_id: String,
    /// Validated response with caller ID and pinned provider identity restored.
    pub result: Result<Value, Failure>,
}

impl Completion {
    /// The RpcResponseV1 object to deliver to the requester.
    pub fn response(&self) -> Value {
        match &self.result {
            Ok(value) => value.clone(),
            Err(Failure::Timeout) => json!({
                "id": self.caller_id,
                "ok": false,
                "providerNodeId": self.provider_node_id,
                "error": {"code": "RPC_TIMEOUT", "message": "routed RPC timed out"},
            }),
            Err(Failure::PeerClosed) => json!({
                "id": self.caller_id,
                "ok": false,
                "providerNodeId": self.provider_node_id,
                "error": {
                    "code": "RPC_PEER_CLOSED",
                    "message": "routed RPC peer disconnected before response",
                },
            }),
        }
    }
}

/// RpcResponseV1 for a request the router refused before dispatch.
pub fn refusal(caller_id: &str, error: &Error) -> Value {
    json!({
        "id": caller_id,
        "ok": false,
        "error": {"code": error.code(), "message": error.to_string()},
    })
}

/// All `now_ms` values come from one trusted monotonic host clock. A backwards
/// clock permanently closes admission. Call `expire` periodically and deliver its
/// completions; no timer, HTTP socket or native channel is owned by this library.
pub struct Router {
    policy: Policy,
    limits: Limits,
    boot_secret: [u8; 32],
    counter: u64,
    last_now: u64,
    clock_failed: bool,
    sessions: BTreeMap<SessionId, Session>,
    pending: BTreeMap<String, Pending>,
    last_provider: Option<String>,
}

impl Router {
    /// Supply 32 fresh CSPRNG bytes on every process start. Never persist/reuse
    /// this secret or take it from a network peer. This crate does not load keys.
    pub fn new(policy: Policy, limits: Limits, boot_secret: [u8; 32]) -> Result<Self, Error> {
        limits.validate()?;
        if boot_secret == [0; 32] {
            return Err(Error::Invalid("boot secret"));
        }
        Ok(Self {
            policy,
            limits,
            boot_secret,
            counter: 0,
            last_now: 0,
            clock_failed: false,
            sessions: BTreeMap::new(),
            pending: BTreeMap::new(),
            last_provider: None,
        })
    }

    fn clock(&mut self, now: u64) -> Result<(), Error> {
        if self.clock_failed || now < self.last_now || now > MAX_SAFE - MAX_DURATION_MS {
            self.clock_failed = true;
            return Err(Error::Clock);
        }
        self.last_now = now;
        Ok(())
    }

    /// Unpredictable handle: SHA-256(boot secret || purpose length || purpose || counter).
    fn token(&mut self, purpose: &str) -> Result<String, Error> {
        self.counter = self.counter.checked_add(1).ok_or(Error::Capacity)?;
        let mut hasher = Sha256::new();
        hasher.update(self.boot_secret);
        hasher.update((purpose.len() as u64).to_be_bytes());
        hasher.update(purpose.as_bytes());
        hasher.update(self.counter.to_be_bytes());
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    pub fn open_session(&mut self, now_ms: u64) -> Result<SessionId, Error> {
        self.clock(now_ms)?;
        if self.sessions.len() >= self.limits.sessions {
            return Err(Error::Capacity);
        }
        let id = SessionId(self.token("session")?);
        self.sessions.insert(
            id.clone(),
            Session {
                challenge: None,
                advert: None,
            },
        );
        Ok(id)
    }

    /// New challenges invalidate older outstanding challenges on this session.
    /// Existing authenticated advertisements keep only their original expiry.
    pub fn challenge(&mut self, session: &SessionId, now_ms: u64) -> Result<String, Error> {
        self.clock(now_ms)?;
        if !self.sessions.contains_key(session) {
            return Err(Error::UnknownSession);
        }
        let nonce = self.token("provider-challenge")?;
        let expires = now_ms + self.limits.challenge_ms;
        let state = self
            .sessions
            .get_mut(session)
            .ok_or(Error::UnknownSession)?;
        state.challenge = Some(Challenge {
            nonce: nonce.clone(),
            expires,
        });
        Ok(nonce)
    }

    /// A proof attempt consumes its challenge, including malformed/bad signatures.
    /// Any failure revokes the session's advertisement. Reauthentication is explicit.
    pub fn authenticate(
        &mut self,
        session: &SessionId,
        proof: &str,
        now_ms: u64,
    ) -> Result<(), Error> {
        self.clock(now_ms)?;
        let state = self
            .sessions
            .get_mut(session)
            .ok_or(Error::UnknownSession)?;
        let old_node = state.advert.take().map(|a| a.node);
        let challenge = state.challenge.take().ok_or(Error::Unauthorized)?;
        if now_ms >= challenge.expires {
            return Err(Error::Expired);
        }
        let (node, accepted) = self.verify_proof(proof, &challenge.nonce)?;
        if old_node.as_ref().is_some_and(|n| n != &node) {
            return Err(Error::Unauthorized);
        }
        let duplicate = self.sessions.iter().any(|(id, s)| {
            id != session
                && s.advert
                    .as_ref()
                    .is_some_and(|a| a.node == node && now_ms < a.expires)
        });
        if duplicate {
            return Err(Error::Unauthorized);
        }
        let expires = now_ms + self.limits.advertisement_ms;
        let state = self
            .sessions
            .get_mut(session)
            .ok_or(Error::UnknownSession)?;
        state.advert = Some(Advertisement {
            node,
            methods: accepted,
            expires,
        });
        Ok(())
    }

    fn verify_proof(&self, proof: &str, nonce: &str) -> Result<(String, Vec<String>), Error> {
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::Invalid("proof bytes"));
        }
        let value = parse_canonical_text(proof).map_err(|_| Error::Invalid("proof JSON"))?;
        let map = value.as_object().ok_or(Error::Invalid("proof object"))?;
        let fields = [
            "domain",
            "v",
            "collatorId",
            "service",
            "network",
            "nodeId",
            "challenge",
            "methods",
            "sigProvider",
        ];
        if map.len() != fields.len()
            || fields.iter().any(|f| !map.contains_key(*f))
            || value["v"] != json!(1)
            || value["domain"] != DOMAIN
            || value["collatorId"] != self.policy.collator_id
            || value["service"] != self.policy.service
            || value["network"] != self.policy.network
            || value["challenge"] != nonce
        {
            return Err(Error::Unauthorized);
        }
        let node = value["nodeId"].as_str().ok_or(Error::Unauthorized)?;
        let pin = self.policy.pins.get(node).ok_or(Error::Unauthorized)?;
        let accepted: Vec<String> = value["methods"]
            .as_array()
            .ok_or(Error::Unauthorized)?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Unauthorized))
            .collect::<Result<_, _>>()?;
        if !methods(&accepted)
            || accepted
                .iter()
                .any(|m| pin.methods.binary_search(m).is_err())
        {
            return Err(Error::Unauthorized);
        }
        let sig = value["sigProvider"].as_str().ok_or(Error::Unauthorized)?;
        let mut payload = map.clone();
        payload.remove("sigProvider");
        let canonical = canonical_json(&Value::Object(payload)).map_err(|_| Error::Unauthorized)?;
        verify_compact(&sha256_hex(&canonical), sig, &key(&pin.public_key)?)
            .map_err(|_| Error::Unauthorized)?;
        Ok((node.into(), accepted))
    }

    fn pending_for_provider(&self, provider: &SessionId) -> usize {
        self.pending
            .values()
            .filter(|p| &p.provider == provider)
            .count()
    }

    pub fn route(
        &mut self,
        requester: &SessionId,
        request: Request,
        now_ms: u64,
    ) -> Result<Dispatch, Error> {
        self.clock(now_ms)?;
        if !self.sessions.contains_key(requester) {
            return Err(Error::UnknownSession);
        }
        let method_name = normalize_method(&request.method);
        let bad = request.id.is_empty()
            || request.id.len() > MAX_LABEL_BYTES
            || request.id.chars().any(char::is_control)
            || request.service != self.policy.service
            || request.network != self.policy.network
            || !method(&method_name)
            || request.params_json.len() > MAX_BODY_BYTES
            || serde_json::from_str::<Value>(&request.params_json).is_err()
            || request.timeout_ms == 0
            || request.timeout_ms > self.limits.request_ms
            || request
                .preferred_provider
                .as_ref()
                .is_some_and(|n| !label(n));
        if bad {
            return Err(Error::Invalid("request"));
        }
        let mine = self
            .pending
            .values()
            .filter(|p| &p.requester == requester)
            .count();
        if self.pending.len() >= self.limits.pending || mine >= self.limits.per_requester {
            return Err(Error::Overloaded);
        }
        let mut candidates: Vec<(String, SessionId)> = self
            .sessions
            .iter()
            .filter_map(|(id, s)| {
                let a = s.advert.as_ref()?;
                let eligible = id != requester
                    && now_ms < a.expires
                    && a.methods.binary_search(&method_name).is_ok()
                    && request
                        .preferred_provider
                        .as_ref()
                        .is_none_or(|n| n == &a.node)
                    && self.pending_for_provider(id) < self.limits.per_provider;
                eligible.then(|| (a.node.clone(), id.clone()))
            })
            .collect();
        candidates.sort();
        // Round robin over node ids: the first node after the previous choice.
        let selected = candidates
            .iter()
            .find(|(node, _)| self.last_provider.as_ref().is_none_or(|last| node > last))
            .or(candidates.first())
            .cloned()
            .ok_or(Error::NoProvider)?;
        let token = self.token("rpc-request")?;
        self.pending.insert(
            token.clone(),
            Pending {
                requester: requester.clone(),
                provider: selected.1.clone(),
                node: selected.0.clone(),
                caller_id: request.id,
                deadline: now_ms + request.timeout_ms,
            },
        );
        self.last_provider = Some(selected.0.clone());
        Ok(Dispatch {
            provider: selected.1,
            provider_node_id: selected.0,
            token,
            method: method_name,
            params_json: request.params_json,
        })
    }

    /// The sender handle comes from the receiving channel, never a JSON field.
    /// A wrong sender cannot remove the pending request, even at its deadline.
    pub fn settle(
        &mut self,
        sender: &SessionId,
        token: &str,
        response: &str,
        now_ms: u64,
    ) -> Result<Completion, Error> {
        self.clock(now_ms)?;
        let pending = self.pending.get(token).ok_or(Error::UnknownRequest)?;
        if &pending.provider != sender {
            return Err(Error::WrongProvider);
        }
        if now_ms >= pending.deadline {
            return self.finish(token, Err(Failure::Timeout));
        }
        let advert = self
            .sessions
            .get(sender)
            .and_then(|s| s.advert.as_ref())
            .ok_or(Error::Unauthorized)?;
        if advert.node != pending.node || now_ms >= advert.expires {
            return Err(Error::Unauthorized);
        }
        if response.len() > MAX_BODY_BYTES {
            return Err(Error::Invalid("response bytes"));
        }
        let mut value: Value =
            serde_json::from_str(response).map_err(|_| Error::Invalid("response JSON"))?;
        let map = value.as_object_mut().ok_or(Error::Invalid("response"))?;
        if !response_shape(map, token) {
            return Err(Error::Invalid("response shape"));
        }
        let caller_id = pending.caller_id.clone();
        let node = pending.node.clone();
        map.insert("id".into(), json!(caller_id));
        map.insert("providerNodeId".into(), json!(node));
        self.finish(token, Ok(value))
    }

    fn finish(&mut self, token: &str, result: Result<Value, Failure>) -> Result<Completion, Error> {
        let p = self.pending.remove(token).ok_or(Error::UnknownRequest)?;
        Ok(Self::complete(p, result))
    }

    pub fn expire(&mut self, now_ms: u64) -> Result<Vec<Completion>, Error> {
        self.clock(now_ms)?;
        let tokens: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| now_ms >= p.deadline)
            .map(|(t, _)| t.clone())
            .collect();
        Ok(self.drain(tokens, Failure::Timeout))
    }

    /// The host must call this for every DC replacement/close or signaling close.
    pub fn close_session(
        &mut self,
        session: &SessionId,
        now_ms: u64,
    ) -> Result<Vec<Completion>, Error> {
        self.clock(now_ms)?;
        self.sessions.remove(session).ok_or(Error::UnknownSession)?;
        let tokens: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| &p.provider == session || &p.requester == session)
            .map(|(t, _)| t.clone())
            .collect();
        Ok(self.drain(tokens, Failure::PeerClosed))
    }

    fn drain(&mut self, tokens: Vec<String>, failure: Failure) -> Vec<Completion> {
        tokens
            .into_iter()
            .filter_map(|t| self.pending.remove(&t))
            .map(|p| Self::complete(p, Err(failure.clone())))
            .collect()
    }

    fn complete(p: Pending, result: Result<Value, Failure>) -> Completion {
        Completion {
            requester: p.requester,
            caller_id: p.caller_id,
            provider_node_id: p.node,
            result,
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Node id of a live authenticated advertisement on `session`, if any.
    pub fn advertised_node(&self, session: &SessionId, now_ms: u64) -> Option<&str> {
        self.sessions
            .get(session)?
            .advert
            .as_ref()
            .filter(|a| now_ms < a.expires)
            .map(|a| a.node.as_str())
    }
}

/// RpcResponseV1 shape bound to the server token: only known keys, `ok` boolean,
/// success carries `result` and no `error`, failure carries `error.message` and no `result`.
fn response_shape(map: &Map<String, Value>, token: &str) -> bool {
    const KEYS: [&str; 5] = ["id", "ok", "result", "error", "providerNodeId"];
    let Some(success) = map.get("ok").and_then(Value::as_bool) else {
        return false;
    };
    if map.keys().any(|k| !KEYS.contains(&k.as_str())) {
        return false;
    }
    if map.get("id").and_then(Value::as_str) != Some(token) {
        return false;
    }
    if success {
        map.contains_key("result") && !map.contains_key("error")
    } else {
        !map.contains_key("result")
            && map
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .is_some()
    }
}
