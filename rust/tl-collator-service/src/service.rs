//! The service reducer: WireMsg and HTTP dispatch as a pure state machine.
//!
//! Inputs are host session ids, already-received message text or parsed HTTP requests and a
//! millisecond clock (`now_ms`, unix time, never decreasing: the RPC router latches a
//! permanent failure on a backwards clock). Outputs are `Out` values the host performs.
//! The only effects the reducer performs itself go through the injected traits: the tape,
//! the clearlist oracle, the IP-intel source, the audit sink and the BitVM artifact source.
//! RPC routing is delegated to `tl_rpc_router::Router`.
use crate::audit::{AuditRecord, AuditSink};
use crate::bitvm::{build_status, ArtifactSource, BitvmQuery};
use crate::clearlist::{
    decide, ClearlistClient, ClearlistDecision, ClearlistOracle, OracleView, Visibility,
};
use crate::config::Config;
use crate::http::{
    client_ip, compat_params, cors, route, HttpRequest, HttpResponse, HttpTicket, ProxyRequest,
    Route, RouteError,
};
use crate::ipintel::{evaluate, IntelPolicy, IpIntel, IpIntelClient, IpIntelSource};
use crate::lru::LruSet;
use crate::manifest::{load_infra_attestations, manifest_body, sign_manifest, BuildInfo};
use crate::order::{validate_shape, verify_binding, OrderCheck};
use crate::peer::{HostSession, PeerSession, SessionMeta};
use crate::ratelimit::{KeyedLimiter, TokenBucket};
use crate::signer::{DigestSigner, SignError};
use crate::tape::{TapeError, TapeStore};
use crate::wire::{self, parse_wire, WireError, WireIn};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tl_collator_wire::parse_canonical_text;
use tl_rpc_router::{
    normalize_method, refusal, Completion, Dispatch, Error as RouterError, Limits, Policy,
    ProviderPin, Request as RouterRequest, Router, SessionId, DOMAIN,
};

/// Router sessions reserved for HTTP-originated RPC (requests are spread over them so one
/// shared requester does not hit the per-requester cap for everybody).
pub const HTTP_SHARDS: usize = 8;
/// Open HTTP exchanges awaiting a provider or an upstream reply.
pub const MAX_HTTP_INFLIGHT: usize = 512;
pub const DEFAULT_RPC_TIMEOUT_MS: u64 = 12_000;
pub const MIN_RPC_TIMEOUT_MS: u64 = 1_000;
pub const MAX_RPC_TIMEOUT_MS: u64 = 120_000;
/// Cached entries for the IP-intel and clearlist clients (legacy: 5000 and unbounded).
const INTEL_CACHE: usize = 5_000;
const CLEARLIST_CACHE: usize = 20_000;

/// Methods served on the public mesh (`PUBLIC_RPC_METHODS`, `src/index.ts` 22-49).
pub const PUBLIC_RPC_METHODS: [&str; 25] = [
    "tl_getstatesnapshot",
    "tl_watchonly_register",
    "tl_watchonly_utxos",
    "tl_getsyncstatus",
    "tl_getallbalancesforaddress",
    "tl_getchannel",
    "tl_getchannelcolumn",
    "tl_getcontractinfo",
    "tl_getattestations",
    "tl_gettransaction",
    "tl_getclearlistbyid",
    "tl_listcontractseries",
    "tl_getinitmargin",
    "tl_channelbalanceforcommiter",
    "tl_getmaxsynth",
    "tl_contractposition",
    "tl_tokentradehistoryforaddress",
    "tl_contracttradehistoryforaddress",
    "tl_totaltradehistoryforaddress",
    "tl_getinfo",
    "tl_getbalance",
    "tl_getproperty",
    "tl_listproperties",
    "tl_createpayload_attestation",
    "tl_createpayload_commit_tochannel",
];

/// `tl_bitvmstatus` is also public but is answered locally from artifacts, never routed.
pub const LOCAL_PUBLIC_METHOD: &str = "tl_bitvmstatus";

pub fn is_public_rpc_method(method: &str) -> bool {
    let m = normalize_method(method);
    m == LOCAL_PUBLIC_METHOD || PUBLIC_RPC_METHODS.contains(&m.as_str())
}

#[derive(Debug)]
pub enum Out {
    /// One WireMsg (as JSON) for a session's data channel.
    Send { to: HostSession, msg: Value },
    /// Close the data channel (`reason` is for the host log).
    CloseChannel {
        session: HostSession,
        reason: &'static str,
    },
    HttpReply {
        ticket: HttpTicket,
        response: HttpResponse,
    },
    /// Perform this upstream request and report with `Service::proxy_done`.
    Proxy {
        ticket: HttpTicket,
        request: ProxyRequest,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Total or per-address connection cap reached (legacy: close 1013 `server busy`).
    Busy,
    Duplicate,
}

#[derive(Debug)]
pub enum ServiceError {
    Config(&'static str),
    Router(RouterError),
    Sign(SignError),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ServiceError {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub orders_accepted: u64,
    pub orders_rejected: u64,
    pub audit_failures: u64,
    pub intel_logged: u64,
    pub malformed_dropped: u64,
    pub rate_limited: u64,
}

pub struct ServiceParts {
    pub collator_id: String,
    pub collator_pubkey: String,
    pub build: BuildInfo,
    pub signer: Box<dyn DigestSigner>,
    pub tape: Box<dyn TapeStore>,
    pub clearlist_oracle: Option<Box<dyn ClearlistOracle>>,
    pub ip_intel: Option<Box<dyn IpIntelSource>>,
    pub audit: Option<Box<dyn AuditSink>>,
    pub artifacts: Box<dyn ArtifactSource>,
    /// Raw `BITVM_COLLATERAL_PROPERTY_ID`.
    pub bitvm_collateral_property_id: Option<String>,
    /// Operator-pinned RPC providers (the router's authentication anchors).
    pub provider_pins: Vec<ProviderPin>,
    /// 32 fresh CSPRNG bytes per process start.
    pub boot_secret: [u8; 32],
    /// Parsed infra attestation array, if any.
    pub attestations: Option<Value>,
}

struct Advert {
    node_id: String,
    methods: Vec<String>,
    since_ms: u64,
}

enum Fallback {
    /// Upstream failure ends in the legacy fall-through `404 not found`.
    NotFound,
    Rpc {
        method: String,
        params: Vec<Value>,
    },
    Attestation {
        ip: String,
    },
}

enum RpcKind {
    Compat {
        method: String,
    },
    /// `/rpc/route`: the caller's own request id is echoed back.
    Route {
        caller_id: String,
    },
}

enum Stage {
    Upstream(Fallback),
    Rpc { caller_id: String, kind: RpcKind },
    CompatUpstream,
}

struct HttpPlan {
    cors: Vec<(String, String)>,
    stage: Stage,
}

pub struct Service {
    cfg: Config,
    collator_id: String,
    started_ms: u64,
    manifest: Value,
    tape: Box<dyn TapeStore>,
    seen: LruSet,
    clearlist: Option<ClearlistClient<Box<dyn ClearlistOracle>>>,
    intel: Option<IpIntelClient<Box<dyn IpIntelSource>>>,
    intel_policy: IntelPolicy,
    audit: Option<Box<dyn AuditSink>>,
    artifacts: Box<dyn ArtifactSource>,
    bitvm_collateral: Option<String>,
    router: Router,
    http_sessions: Vec<SessionId>,
    sessions: BTreeMap<HostSession, PeerSession>,
    router_to_host: BTreeMap<SessionId, HostSession>,
    adverts: BTreeMap<HostSession, Advert>,
    ip_conns: BTreeMap<String, usize>,
    ip_limiter: KeyedLimiter,
    http_plans: BTreeMap<HttpTicket, HttpPlan>,
    http_waiters: BTreeMap<String, HttpTicket>,
    next_ticket: u64,
    next_rpc_id: u64,
    stats: Stats,
}

fn send(to: HostSession, msg: Value) -> Out {
    Out::Send { to, msg }
}

fn reply(ticket: HttpTicket, response: HttpResponse) -> Out {
    Out::HttpReply { ticket, response }
}

impl Service {
    pub fn new(cfg: Config, parts: ServiceParts, now_ms: u64) -> Result<Service, ServiceError> {
        let policy = Policy::new(
            &parts.collator_id,
            &cfg.rpc_service,
            &cfg.rpc_network,
            parts.provider_pins,
        )
        .map_err(ServiceError::Router)?;
        let limits = Limits {
            sessions: cfg.conn_max + HTTP_SHARDS,
            advertisement_ms: cfg.rpc_advert_ttl_ms,
            request_ms: MAX_RPC_TIMEOUT_MS,
            ..Limits::default()
        };
        let mut router =
            Router::new(policy, limits, parts.boot_secret).map_err(ServiceError::Router)?;
        let mut http_sessions = Vec::new();
        for _ in 0..HTTP_SHARDS {
            http_sessions.push(router.open_session(now_ms).map_err(ServiceError::Router)?);
        }
        let attestations = parts
            .attestations
            .as_ref()
            .and_then(|raw| load_infra_attestations(raw, now_ms / 1000));
        let body = manifest_body(
            &cfg,
            &parts.collator_id,
            &parts.collator_pubkey,
            &parts.build,
            attestations,
        );
        let manifest = sign_manifest(body, parts.signer.as_ref()).map_err(ServiceError::Sign)?;
        let clearlist = if cfg.clearlist_enforce && cfg.clearlist_url.is_some() {
            parts.clearlist_oracle.map(|o| {
                ClearlistClient::new(o, u64::from(cfg.clearlist_ttl_sec) * 1000, CLEARLIST_CACHE)
            })
        } else {
            None
        };
        let intel_policy = IntelPolicy {
            vpn_mode: cfg.vpn_filter_mode,
            asn_mode: cfg.asn_block_mode,
            blocklist: cfg.asn_blocklist.clone(),
            fail_mode: cfg.ip_intel_fail_mode,
        };
        let intel = parts
            .ip_intel
            .map(|s| IpIntelClient::new(s, cfg.ip_intel_ttl_sec, INTEL_CACHE));
        Ok(Service {
            started_ms: now_ms,
            seen: LruSet::new(cfg.seen_orderids_max),
            ip_limiter: KeyedLimiter::new(10_000, cfg.ip_burst, cfg.ip_rate_per_sec),
            collator_id: parts.collator_id,
            manifest,
            tape: parts.tape,
            clearlist,
            intel,
            intel_policy,
            audit: if cfg.ip_logging { parts.audit } else { None },
            artifacts: parts.artifacts,
            bitvm_collateral: parts.bitvm_collateral_property_id,
            router,
            http_sessions,
            sessions: BTreeMap::new(),
            router_to_host: BTreeMap::new(),
            adverts: BTreeMap::new(),
            ip_conns: BTreeMap::new(),
            http_plans: BTreeMap::new(),
            http_waiters: BTreeMap::new(),
            next_ticket: 1,
            next_rpc_id: 1,
            stats: Stats::default(),
            cfg,
        })
    }

    pub fn manifest(&self) -> &Value {
        &self.manifest
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn pending_rpc(&self) -> usize {
        self.router.pending_count()
    }

    pub fn http_inflight(&self) -> usize {
        self.http_plans.len()
    }

    pub fn is_replaying(&self, host: HostSession) -> bool {
        self.sessions
            .get(&host)
            .is_some_and(|s| s.replay_cursor.is_some())
    }

    pub fn is_live(&self, host: HostSession) -> bool {
        self.sessions.get(&host).is_some_and(PeerSession::is_live)
    }

    // ---- sessions -------------------------------------------------------------------

    /// Register a signaling connection. Enforces the total and per-address caps.
    pub fn open_session(
        &mut self,
        host: HostSession,
        remote_ip: Option<&str>,
        user_agent: Option<&str>,
        now_ms: u64,
    ) -> Result<(), Reject> {
        if self.sessions.contains_key(&host) {
            return Err(Reject::Duplicate);
        }
        if self.sessions.len() >= self.cfg.conn_max {
            return Err(Reject::Busy);
        }
        let ip = remote_ip.map(|s| s.chars().take(64).collect::<String>());
        if let Some(ip) = &ip {
            if self.ip_conns.get(ip).copied().unwrap_or(0) >= self.cfg.conn_max_per_ip {
                return Err(Reject::Busy);
            }
            *self.ip_conns.entry(ip.clone()).or_insert(0) += 1;
        }
        let c = &self.cfg;
        let session = PeerSession {
            id: host,
            peer_id: format!("peer-{}", host.0),
            meta: SessionMeta {
                remote_ip: ip,
                user_agent: user_agent.map(|s| s.chars().take(256).collect()),
                asn: None,
                vpn: None,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
            },
            wants_tape: false,
            replay_cursor: None,
            channel_open: false,
            router: None,
            submit_bucket: TokenBucket::new(c.submit_burst, c.submit_rate_per_sec, now_ms),
            msg_bucket: TokenBucket::new(c.msg_burst, c.msg_rate_per_sec, now_ms),
            heavy_bucket: TokenBucket::new(c.heavy_burst, c.heavy_rate_per_sec, now_ms),
        };
        self.sessions.insert(host, session);
        Ok(())
    }

    /// The data channel opened. Creates the session's router identity; a replacement
    /// channel first goes through `channel_closed`.
    pub fn channel_opened(&mut self, host: HostSession, now_ms: u64) -> Result<(), RouterError> {
        let Some(s) = self.sessions.get(&host) else {
            return Err(RouterError::UnknownSession);
        };
        if s.channel_open {
            return Err(RouterError::Invalid("channel already open"));
        }
        let rsid = self.router.open_session(now_ms)?;
        self.router_to_host.insert(rsid.clone(), host);
        if let Some(s) = self.sessions.get_mut(&host) {
            s.router = Some(rsid);
            s.channel_open = true;
        }
        Ok(())
    }

    /// The data channel closed (the signaling connection may live on). Everything pending on
    /// the old router identity completes with `RPC_PEER_CLOSED`.
    pub fn channel_closed(&mut self, host: HostSession, now_ms: u64) -> Vec<Out> {
        let mut out = Vec::new();
        self.adverts.remove(&host);
        let rsid = match self.sessions.get_mut(&host) {
            Some(s) => {
                s.channel_open = false;
                s.wants_tape = false;
                s.replay_cursor = None;
                s.router.take()
            }
            None => None,
        };
        if let Some(rsid) = rsid {
            self.router_to_host.remove(&rsid);
            if let Ok(done) = self.router.close_session(&rsid, now_ms) {
                for c in done {
                    out.extend(self.deliver(c, now_ms));
                }
            }
        }
        out
    }

    /// The signaling connection closed: drop all session state.
    pub fn close_session(&mut self, host: HostSession, now_ms: u64) -> Vec<Out> {
        let out = self.channel_closed(host, now_ms);
        if let Some(s) = self.sessions.remove(&host) {
            if let Some(ip) = s.meta.remote_ip {
                if let Some(n) = self.ip_conns.get_mut(&ip) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.ip_conns.remove(&ip);
                    }
                }
            }
        }
        out
    }

    /// Complete overdue RPC requests. The host calls this periodically.
    pub fn expire(&mut self, now_ms: u64) -> Vec<Out> {
        match self.router.expire(now_ms) {
            Ok(done) => done
                .into_iter()
                .flat_map(|c| self.deliver(c, now_ms))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    // ---- WireMsg ----------------------------------------------------------------------

    fn err_to(&self, host: HostSession, code: &str, msg: &str) -> Out {
        send(host, wire::err(code, msg))
    }

    /// One data-channel text frame from `host`.
    pub fn on_message(&mut self, host: HostSession, text: &str, now_ms: u64) -> Vec<Out> {
        let Some(s) = self.sessions.get_mut(&host) else {
            return Vec::new();
        };
        if !s.channel_open {
            return Vec::new();
        }
        if text.len() > self.cfg.max_msg_bytes {
            return vec![
                self.err_to(host, "msg_too_large", "message too large"),
                Out::CloseChannel {
                    session: host,
                    reason: "msg_too_large",
                },
            ];
        }
        s.meta.last_seen_ms = now_ms;
        if !s.msg_bucket.allow(1, now_ms) {
            self.stats.rate_limited += 1;
            return vec![self.err_to(host, "rate_limited", "too many messages")];
        }
        let msg = match parse_wire(text, self.cfg.max_msg_bytes) {
            Ok(m) => m,
            Err(WireError::Drop) => {
                self.stats.malformed_dropped += 1;
                return Vec::new();
            }
            Err(WireError::TooLarge) => {
                return vec![
                    self.err_to(host, "msg_too_large", "message too large"),
                    Out::CloseChannel {
                        session: host,
                        reason: "msg_too_large",
                    },
                ]
            }
            Err(WireError::Schema(_)) => {
                return vec![self.err_to(host, "SCHEMA_INVALID", "invalid WireMsg schema")]
            }
        };
        match msg {
            WireIn::Ping { ts } => vec![send(host, wire::pong(&ts))],
            WireIn::Hello { .. } | WireIn::Ignored(_) => Vec::new(),
            WireIn::TapeSub { from_seq } => self.tape_sub(host, from_seq, now_ms),
            WireIn::Submit { order } => self.submit(host, &order, now_ms),
            WireIn::RpcAdvertise { proof, .. } => self.rpc_advertise(host, proof, now_ms),
            WireIn::RpcReq { req } => self.rpc_req(host, &req, now_ms),
            WireIn::RpcRes { res } => self.rpc_res(host, &res, now_ms),
        }
    }

    fn heavy_ok(&mut self, host: HostSession, now_ms: u64) -> bool {
        let ok = self
            .sessions
            .get_mut(&host)
            .is_some_and(|s| s.heavy_bucket.allow(1, now_ms));
        if !ok {
            self.stats.rate_limited += 1;
        }
        ok
    }

    fn tape_sub(&mut self, host: HostSession, from_seq: u64, now_ms: u64) -> Vec<Out> {
        if !self.heavy_ok(host, now_ms) {
            return vec![self.err_to(host, "rate_limited", "too many requests")];
        }
        if let Some(s) = self.sessions.get_mut(&host) {
            s.wants_tape = true;
            s.replay_cursor = Some(from_seq.max(1));
        }
        self.pump_replay(host)
    }

    /// Send the next batch (at most `replay_batch` entries) of a TAPE_SUB replay. The batch is
    /// the contiguous range starting at the session's cursor; after the entry numbered
    /// `tape.last_seq()` has been sent, TAPE_END follows and the session turns live. Entries
    /// appended during the replay are not pushed live (the replay reaches them), so the
    /// stream a peer sees has no duplicates and no gaps. The host calls this again while
    /// `is_replaying(host)` (that is the legacy per-batch `await sleep0()` backpressure).
    pub fn pump_replay(&mut self, host: HostSession) -> Vec<Out> {
        let Some(s) = self.sessions.get(&host) else {
            return Vec::new();
        };
        let Some(cursor) = s.replay_cursor else {
            return Vec::new();
        };
        if !s.channel_open {
            return Vec::new();
        }
        let abort = |this: &mut Service| {
            if let Some(s) = this.sessions.get_mut(&host) {
                s.replay_cursor = None;
                s.wants_tape = false;
            }
            vec![this.err_to(host, "tape_unavailable", "tape replay failed")]
        };
        let batch = self.cfg.replay_batch as usize;
        let entries = match self.tape.read_range(cursor, batch) {
            Ok(e) => e,
            Err(_) => return abort(self),
        };
        let mut out = Vec::new();
        let mut next = cursor;
        for e in &entries {
            let parsed: Option<Value> = (e.seq == next)
                .then(|| serde_json::from_str(&e.line).ok())
                .flatten();
            let Some(entry) = parsed else {
                return abort(self);
            };
            out.push(send(host, wire::tape_entry(entry)));
            next = match e.seq.checked_add(1) {
                Some(n) => n,
                None => return abort(self),
            };
        }
        let last = self.tape.last_seq();
        if entries.is_empty() && cursor <= last {
            return abort(self);
        }
        if let Some(s) = self.sessions.get_mut(&host) {
            if next > last {
                s.replay_cursor = None;
                out.push(send(host, wire::tape_end(last)));
            } else {
                s.replay_cursor = Some(next);
            }
        }
        out
    }

    fn reject_order(&mut self, host: HostSession, code: &str, msg: &str) -> Vec<Out> {
        self.stats.orders_rejected += 1;
        vec![self.err_to(host, code, msg)]
    }

    fn tape_error(&mut self, host: HostSession, e: &TapeError, order: &Value) -> Vec<Out> {
        let is_cancel = order.get("kind").and_then(Value::as_str) == Some("CANCEL");
        match e {
            TapeError::Duplicate => self.reject_order(host, "DUPLICATE", "orderId already seen"),
            TapeError::BadOrder => self.reject_order(host, "bad_sig", "sigTrader verify failed"),
            TapeError::UnknownOrder => {
                let msg = if is_cancel {
                    "cancelsOrderId not found"
                } else {
                    "replacesOrderId not found"
                };
                self.reject_order(host, "UNKNOWN_ORDER", msg)
            }
            TapeError::NotOwner => {
                let msg = if is_cancel {
                    "cannot cancel other trader order"
                } else {
                    "cannot replace other trader order"
                };
                self.reject_order(host, "NOT_OWNER", msg)
            }
            TapeError::Capacity => self.reject_order(host, "tape_full", "tape capacity reached"),
            _ => self.reject_order(host, "tape_unavailable", "tape append failed"),
        }
    }

    /// SUBMIT. An order reaches the tape only after, in order: the session and address rate
    /// limits, shape validation, order-id recomputation, the duplicate check against the
    /// tape, the trader signature, CANCEL/REPLACE ownership, IP policy, clearlist policy,
    /// and the wire crate's own re-verification inside `TapeStore::append_order`.
    fn submit(&mut self, host: HostSession, order: &Value, now_ms: u64) -> Vec<Out> {
        let Some(s) = self.sessions.get_mut(&host) else {
            return Vec::new();
        };
        let session_ok = s.submit_bucket.allow(1, now_ms);
        let ip = s.meta.remote_ip.clone();
        let ip_ok = match (session_ok, &ip) {
            (true, Some(ip)) => self.ip_limiter.allow(&format!("submit:{ip}"), 1, now_ms),
            (ok, _) => ok,
        };
        if !(session_ok && ip_ok) {
            self.stats.rate_limited += 1;
            return vec![self.err_to(host, "rate_limited", "too many SUBMIT")];
        }
        if let Err(msg) = validate_shape(order) {
            return self.reject_order(host, "SCHEMA_INVALID", msg);
        }
        let order_id = match order.get("orderId").and_then(Value::as_str) {
            Some(id) => id.to_owned(),
            None => {
                return self.reject_order(host, "SCHEMA_INVALID", "invalid OrderEnvelopeV1 schema")
            }
        };
        if self.seen.has(&order_id) || self.tape.contains_order(&order_id) {
            return self.reject_order(host, "DUPLICATE", "orderId already seen");
        }
        match verify_binding(order) {
            Ok(_) => {}
            Err(OrderCheck::IdMismatch) => {
                return self.reject_order(
                    host,
                    "BAD_ORDER_ID",
                    "orderId does not match order contents",
                )
            }
            Err(OrderCheck::BadSignature) => {
                return self.reject_order(host, "bad_sig", "sigTrader verify failed")
            }
        }
        if let Err(e) = self.tape.precheck(order) {
            return self.tape_error(host, &e, order);
        }
        // IP policy.
        if self.intel_policy.active() {
            let mut failed = false;
            if let (Some(client), Some(ip)) = (self.intel.as_mut(), ip.as_deref()) {
                match client.lookup(ip, now_ms) {
                    Ok(IpIntel { asn, vpn }) => {
                        if let Some(s) = self.sessions.get_mut(&host) {
                            if asn.is_some() {
                                s.meta.asn = asn;
                            }
                            if vpn.is_some() {
                                s.meta.vpn = vpn;
                            }
                        }
                    }
                    Err(_) => failed = true,
                }
            } else {
                failed = true;
            }
            let meta = self
                .sessions
                .get(&host)
                .map(|s| IpIntel {
                    asn: s.meta.asn,
                    vpn: s.meta.vpn,
                })
                .unwrap_or_default();
            let verdict = evaluate(&self.intel_policy, meta, failed);
            self.stats.intel_logged += verdict.logged.len() as u64;
            if let Some((code, msg)) = verdict.reject {
                return self.reject_order(host, code, msg);
            }
        }
        // Clearlist policy.
        if self.cfg.clearlist_enforce {
            let Some(visibility) = Visibility::from_order(order) else {
                return self.reject_order(host, "SCHEMA_INVALID", "invalid OrderEnvelopeV1 schema");
            };
            let view = match (&mut self.clearlist, visibility.group()) {
                (_, None) => OracleView::Answer(true),
                (None, Some(_)) => OracleView::NotConfigured,
                (Some(client), Some(group)) => {
                    let trader = order
                        .get("traderPubKey")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    match client.check(group, trader, now_ms) {
                        Ok(r) => OracleView::Answer(r.allowed),
                        Err(_) => OracleView::Down,
                    }
                }
            };
            if let ClearlistDecision::Deny { code, msg } =
                decide(true, self.cfg.clearlist_fail_mode, &visibility, &view)
            {
                return self.reject_order(host, code, msg);
            }
        }
        let entry = match self.tape.append_order(order, now_ms) {
            Ok(e) => e,
            Err(e) => return self.tape_error(host, &e, order),
        };
        self.seen.add(&order_id);
        self.stats.orders_accepted += 1;
        if let Some(audit) = self.audit.as_mut() {
            let (peer_id, ip, asn, vpn) = self
                .sessions
                .get(&host)
                .map(|s| {
                    (
                        s.peer_id.clone(),
                        s.meta.remote_ip.clone(),
                        s.meta.asn,
                        s.meta.vpn,
                    )
                })
                .unwrap_or_default();
            let record = AuditRecord {
                ts: now_ms,
                collator_id: self.collator_id.clone(),
                peer_id,
                ip,
                asn,
                vpn,
                order_id: order_id.clone(),
                trader_pub_key: order
                    .get("traderPubKey")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                seq: entry.seq,
            };
            if audit.write(&record.to_line()).is_err() {
                self.stats.audit_failures += 1;
            }
        }
        let Ok(entry_value) = serde_json::from_str::<Value>(&entry.line) else {
            return Vec::new();
        };
        self.sessions
            .values()
            .filter(|s| s.is_live())
            .map(|s| send(s.id, wire::tape_entry(entry_value.clone())))
            .collect()
    }

    fn rpc_advertise(&mut self, host: HostSession, proof: Option<String>, now_ms: u64) -> Vec<Out> {
        if !self.heavy_ok(host, now_ms) {
            return vec![self.err_to(host, "rate_limited", "too many requests")];
        }
        let Some(rsid) = self.sessions.get(&host).and_then(|s| s.router.clone()) else {
            return Vec::new();
        };
        match proof {
            None => match self.router.challenge(&rsid, now_ms) {
                Ok(nonce) => vec![send(host, wire::rpc_challenge(&nonce, DOMAIN))],
                Err(_) => vec![self.err_to(
                    host,
                    "RPC_ADVERTISEMENT_REJECTED",
                    "provider authentication unavailable",
                )],
            },
            Some(proof) => match self.router.authenticate(&rsid, &proof, now_ms) {
                Ok(()) => {
                    let parsed = serde_json::from_str::<Value>(&proof).unwrap_or(Value::Null);
                    let node_id = parsed
                        .get("nodeId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    let methods = parsed
                        .get("methods")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|m| m.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    self.adverts.insert(
                        host,
                        Advert {
                            node_id,
                            methods,
                            since_ms: now_ms,
                        },
                    );
                    Vec::new()
                }
                Err(_) => {
                    self.adverts.remove(&host);
                    vec![self.err_to(
                        host,
                        "RPC_ADVERTISEMENT_REJECTED",
                        "provider authentication failed",
                    )]
                }
            },
        }
    }

    fn next_rpc_id(&mut self) -> String {
        let n = self.next_rpc_id;
        self.next_rpc_id = self.next_rpc_id.saturating_add(1);
        format!("rpc-{n:x}")
    }

    /// Legacy `normalizeRpcRequest` over a wire/JSON object. `None` means service or method
    /// was empty. `timeoutMs` follows `Math.max(1000, Math.min(120000, Number(t || 12000)))`.
    fn normalize_request(&mut self, raw: &Value) -> Option<RouterRequest> {
        let trimmed = |k: &str| {
            raw.get(k)
                .and_then(Value::as_str)
                .map(|s| s.trim().to_owned())
                .unwrap_or_default()
        };
        let service = trimmed("service");
        let method = trimmed("method");
        if service.is_empty() || method.is_empty() {
            return None;
        }
        let id = match raw.get("id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => id.to_owned(),
            _ => self.next_rpc_id(),
        };
        let network = Some(trimmed("network"))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| self.cfg.rpc_network.clone());
        let t = raw
            .get("timeoutMs")
            .and_then(Value::as_f64)
            .filter(|t| t.is_finite() && *t != 0.0)
            .unwrap_or(DEFAULT_RPC_TIMEOUT_MS as f64);
        let timeout_ms = t.clamp(MIN_RPC_TIMEOUT_MS as f64, MAX_RPC_TIMEOUT_MS as f64) as u64;
        let params = raw.get("params").cloned().unwrap_or(Value::Null);
        Some(RouterRequest {
            id,
            service,
            network,
            method,
            params_json: params.to_string(),
            preferred_provider: None,
            timeout_ms,
        })
    }

    fn no_provider(&self, req: &RouterRequest, caller_id: &str) -> Value {
        let net = if req.network.is_empty() {
            String::new()
        } else {
            format!(" on {}", req.network)
        };
        json!({
            "id": caller_id,
            "ok": false,
            "error": {
                "code": "NO_RPC_PROVIDER",
                "message": format!("no WebRTC RPC provider for {}{}", req.service, net),
            },
        })
    }

    fn refusal_value(&self, req: &RouterRequest, e: &RouterError) -> Value {
        if *e == RouterError::NoProvider {
            self.no_provider(req, &req.id)
        } else {
            refusal(&req.id, e)
        }
    }

    fn dispatch_out(&self, d: &Dispatch, req: &RouterRequest) -> Option<Out> {
        let to = *self.router_to_host.get(&d.provider)?;
        let params = serde_json::from_str::<Value>(&d.params_json).unwrap_or(Value::Null);
        Some(send(
            to,
            wire::rpc_req(json!({
                "id": d.token,
                "service": req.service,
                "network": req.network,
                "method": d.method,
                "params": params,
            })),
        ))
    }

    fn rpc_req(&mut self, host: HostSession, raw: &Value, now_ms: u64) -> Vec<Out> {
        if !self.heavy_ok(host, now_ms) {
            return vec![self.err_to(host, "rate_limited", "too many requests")];
        }
        let Some(req) = self.normalize_request(raw) else {
            let id = raw
                .get("id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| self.next_rpc_id());
            return vec![send(
                host,
                wire::rpc_res(json!({
                    "id": id,
                    "ok": false,
                    "error": {"code": "BAD_RPC_REQUEST", "message": "service and method are required"},
                })),
            )];
        };
        if req.service != self.cfg.rpc_service {
            return vec![send(
                host,
                wire::rpc_res(json!({
                    "id": req.id, "ok": false,
                    "error": {"code": "RPC_SERVICE_FORBIDDEN", "message": "RPC service is not available on the public mesh"},
                })),
            )];
        }
        if !is_public_rpc_method(&req.method) {
            return vec![send(
                host,
                wire::rpc_res(json!({
                    "id": req.id, "ok": false,
                    "error": {"code": "RPC_METHOD_FORBIDDEN", "message": "RPC method is not available on the public mesh"},
                })),
            )];
        }
        let Some(rsid) = self.sessions.get(&host).and_then(|s| s.router.clone()) else {
            return Vec::new();
        };
        match self.router.route(&rsid, req.clone(), now_ms) {
            Ok(d) => self.dispatch_out(&d, &req).into_iter().collect(),
            Err(e) => vec![send(host, wire::rpc_res(self.refusal_value(&req, &e)))],
        }
    }

    fn rpc_res(&mut self, host: HostSession, res: &Value, now_ms: u64) -> Vec<Out> {
        let Some(rsid) = self.sessions.get(&host).and_then(|s| s.router.clone()) else {
            return Vec::new();
        };
        let token = res.get("id").and_then(Value::as_str).unwrap_or("");
        match self.router.settle(&rsid, token, &res.to_string(), now_ms) {
            Ok(done) => self.deliver(done, now_ms),
            // Unknown token: a late or duplicate response, ignored like the legacy handler.
            Err(RouterError::UnknownRequest) => Vec::new(),
            Err(_) => vec![self.err_to(host, "RPC_RES_REJECTED", "response not accepted")],
        }
    }

    /// Hand a finished request to whoever is waiting for it.
    fn deliver(&mut self, c: Completion, _now_ms: u64) -> Vec<Out> {
        if let Some(host) = self.router_to_host.get(&c.requester).copied() {
            return vec![send(host, wire::rpc_res(c.response()))];
        }
        if let Some(ticket) = self.http_waiters.remove(&c.caller_id) {
            return self.finish_http_rpc(ticket, &c.response());
        }
        Vec::new()
    }

    // ---- HTTP -------------------------------------------------------------------------

    fn new_ticket(&mut self) -> HttpTicket {
        let t = HttpTicket(self.next_ticket);
        self.next_ticket = self.next_ticket.saturating_add(1);
        t
    }

    fn status_for(code: Option<&str>, ok: bool) -> u16 {
        if ok {
            200
        } else if code == Some("NO_RPC_PROVIDER") {
            503
        } else {
            502
        }
    }

    fn finish_http_rpc(&mut self, ticket: HttpTicket, resp: &Value) -> Vec<Out> {
        let Some(plan) = self.http_plans.remove(&ticket) else {
            return Vec::new();
        };
        let Stage::Rpc { kind, .. } = &plan.stage else {
            return Vec::new();
        };
        let ok = resp.get("ok").and_then(Value::as_bool) == Some(true);
        let code = resp.pointer("/error/code").and_then(Value::as_str);
        let status = Self::status_for(code, ok);
        let response = match kind {
            RpcKind::Route { caller_id } => {
                let mut body = resp.clone();
                body["id"] = json!(caller_id);
                HttpResponse::json(status, &plan.cors, &body)
            }
            RpcKind::Compat { .. } if ok => HttpResponse::json(
                200,
                &plan.cors,
                &json!({"data": resp.get("result").cloned().unwrap_or(Value::Null)}),
            ),
            RpcKind::Compat { .. } => HttpResponse::json(
                status,
                &plan.cors,
                &json!({
                    "error": resp.pointer("/error/message").cloned().unwrap_or_else(|| json!("compat RPC failed")),
                    "code": code.unwrap_or("RPC_ERROR"),
                }),
            ),
        };
        vec![reply(ticket, response)]
    }

    /// Route one request through the router on a shard session and register the waiter.
    /// `None` result: nothing dispatched, the caller replies.
    fn http_route(
        &mut self,
        ticket: HttpTicket,
        req: RouterRequest,
        kind: RpcKind,
        cors_headers: Vec<(String, String)>,
        now_ms: u64,
    ) -> Vec<Out> {
        let shard = (ticket.0 as usize) % self.http_sessions.len().max(1);
        let Some(rsid) = self.http_sessions.get(shard).cloned() else {
            return vec![reply(
                ticket,
                HttpResponse::error(503, &cors_headers, "BUSY", "no routing session"),
            )];
        };
        let caller_id = req.id.clone();
        let compat_method = match &kind {
            RpcKind::Compat { method } => Some(method.clone()),
            RpcKind::Route { .. } => None,
        };
        match self.router.route(&rsid, req.clone(), now_ms) {
            Ok(d) => {
                let Some(out) = self.dispatch_out(&d, &req) else {
                    return vec![reply(
                        ticket,
                        HttpResponse::error(
                            502,
                            &cors_headers,
                            "RPC_ROUTE_ERROR",
                            "provider unreachable",
                        ),
                    )];
                };
                self.http_waiters.insert(caller_id.clone(), ticket);
                self.http_plans.insert(
                    ticket,
                    HttpPlan {
                        cors: cors_headers,
                        stage: Stage::Rpc { caller_id, kind },
                    },
                );
                vec![out]
            }
            Err(RouterError::NoProvider) if compat_method.is_some() => {
                // Legacy: no WebRTC provider -> try the compat relayer.
                let method = compat_method.unwrap_or_default();
                let params = serde_json::from_str::<Value>(&req.params_json).unwrap_or(Value::Null);
                self.http_plans.insert(
                    ticket,
                    HttpPlan {
                        cors: cors_headers,
                        stage: Stage::CompatUpstream,
                    },
                );
                vec![Out::Proxy {
                    ticket,
                    request: ProxyRequest {
                        method: "POST".into(),
                        path: format!("/rpc/{method}"),
                        body: Some(json!({"params": params})),
                        headers: Vec::new(),
                    },
                }]
            }
            Err(e) => {
                let v = self.refusal_value(&req, &e);
                let status = match e {
                    RouterError::Invalid(_) => 400,
                    RouterError::Overloaded | RouterError::Capacity => 503,
                    RouterError::NoProvider => 503,
                    _ => 502,
                };
                let body = match kind {
                    RpcKind::Route { caller_id } => {
                        let mut v = v;
                        v["id"] = json!(caller_id);
                        v
                    }
                    RpcKind::Compat { .. } => json!({
                        "error": v.pointer("/error/message").cloned().unwrap_or(Value::Null),
                        "code": v.pointer("/error/code").cloned().unwrap_or(Value::Null),
                    }),
                };
                vec![reply(
                    ticket,
                    HttpResponse::json(status, &cors_headers, &body),
                )]
            }
        }
    }

    fn start_compat(
        &mut self,
        ticket: HttpTicket,
        method: &str,
        params: Vec<Value>,
        cors_headers: Vec<(String, String)>,
        now_ms: u64,
    ) -> Vec<Out> {
        if !is_public_rpc_method(method) {
            return vec![reply(
                ticket,
                HttpResponse::error(
                    403,
                    &cors_headers,
                    "RPC_METHOD_FORBIDDEN",
                    "RPC method is not available on the public mesh",
                ),
            )];
        }
        let req = RouterRequest {
            id: format!("http-{}", ticket.0),
            service: self.cfg.rpc_service.clone(),
            network: self.cfg.rpc_network.clone(),
            method: method.to_owned(),
            params_json: Value::Array(params).to_string(),
            preferred_provider: None,
            timeout_ms: DEFAULT_RPC_TIMEOUT_MS,
        };
        self.http_route(
            ticket,
            req,
            RpcKind::Compat {
                method: normalize_method(method),
            },
            cors_headers,
            now_ms,
        )
    }

    fn upstream(
        &mut self,
        ticket: HttpTicket,
        request: ProxyRequest,
        fallback: Fallback,
        cors_headers: Vec<(String, String)>,
    ) -> Vec<Out> {
        self.http_plans.insert(
            ticket,
            HttpPlan {
                cors: cors_headers,
                stage: Stage::Upstream(fallback),
            },
        );
        vec![Out::Proxy { ticket, request }]
    }

    fn local_bitvm(&mut self, body: Option<&Value>, now_ms: u64) -> Value {
        let artifacts = self.artifacts.load();
        let query = BitvmQuery::from_body(body);
        build_status(&artifacts, &query, self.bitvm_collateral.as_deref(), now_ms)
    }

    fn attestation(&mut self, ip: &str, now_ms: u64) -> Value {
        let failed = |msg: &str| {
            json!({
                "success": false,
                "ip": ip,
                "isBlocked": false,
                "source": "unknown",
                "message": msg,
                "error": "Both primary and fallback IP reputation APIs failed or are not configured.",
            })
        };
        match self.intel.as_mut() {
            None => failed("No IP reputation provider configured"),
            Some(client) => match client.lookup(ip, now_ms) {
                Ok(IpIntel { vpn: None, .. }) => {
                    failed("IP reputation provider returned no verdict")
                }
                Ok(intel) => {
                    let vpn = intel.vpn == Some(true);
                    json!({
                        "success": true,
                        "ip": ip,
                        "countryCode": "Unknown",
                        "isVpn": vpn,
                        "isProxy": false,
                        "isDarkweb": false,
                        "isAnonymousVpn": false,
                        "isBlocked": vpn,
                        "source": "unknown",
                        "message": if vpn { "Suspicious IP detected." } else { "IP is clean and trusted." },
                    })
                }
                Err(_) => failed("No IP reputation provider succeeded"),
            },
        }
    }

    fn proxy_headers(&self, req: &HttpRequest) -> Vec<(String, String)> {
        let mut h = Vec::new();
        if self.cfg.trust_proxy_headers {
            let f = &req.forwarded;
            for (name, value) in [
                ("cf-connecting-ip", &f.cf_connecting_ip),
                ("x-real-ip", &f.x_real_ip),
                ("x-forwarded-for", &f.x_forwarded_for),
                ("x-forwarded-proto", &f.x_forwarded_proto),
            ] {
                if let Some(v) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                    h.push((name.to_owned(), v.chars().take(256).collect()));
                }
            }
        } else {
            h.push((
                "x-forwarded-for".to_owned(),
                req.peer_ip.chars().take(64).collect(),
            ));
        }
        h
    }

    /// One HTTP request. Returns immediately-final replies, upstream work for the host, or
    /// dispatches to RPC providers (the reply then arrives from a later `on_message`,
    /// `expire` or `close_session` call as `Out::HttpReply`).
    pub fn handle_http(&mut self, req: &HttpRequest, now_ms: u64) -> (HttpTicket, Vec<Out>) {
        let ticket = self.new_ticket();
        let outcome = cors(req.origin.as_deref(), &self.cfg);
        let c = outcome.headers;
        let done = |r: HttpResponse| (ticket, vec![reply(ticket, r)]);
        if req.method == "OPTIONS" {
            return if outcome.denied {
                done(HttpResponse::error(
                    403,
                    &c,
                    "CORS_ORIGIN_DENIED",
                    "Origin is not approved for this API",
                ))
            } else {
                done(HttpResponse::text(204, &c, ""))
            };
        }
        if outcome.denied && req.method == "POST" {
            return done(HttpResponse::error(
                403,
                &c,
                "CORS_ORIGIN_DENIED",
                "Origin is not approved for this API",
            ));
        }
        if req.body.len() > self.cfg.max_msg_bytes {
            return done(HttpResponse::error(
                413,
                &c,
                "BODY_TOO_LARGE",
                "request body too large",
            ));
        }
        let ip = client_ip(req, self.cfg.trust_proxy_headers);
        if !self.ip_limiter.allow(&format!("http:{ip}"), 1, now_ms) {
            self.stats.rate_limited += 1;
            return done(HttpResponse::error(
                429,
                &c,
                "RATE_LIMITED",
                "too many requests",
            ));
        }
        if self.http_plans.len() >= MAX_HTTP_INFLIGHT {
            return done(HttpResponse::error(
                503,
                &c,
                "BUSY",
                "too many requests in flight",
            ));
        }
        let parsed_route = match route(&req.method, &req.path) {
            Ok(r) => r,
            Err(RouteError::Missing(what)) => {
                return done(HttpResponse::json(400, &c, &json!({"error": what})))
            }
            Err(RouteError::Invalid(what)) => {
                return done(HttpResponse::json(400, &c, &json!({"error": what})))
            }
            Err(RouteError::BadPath) => {
                return done(HttpResponse::error(
                    400,
                    &c,
                    "BAD_PATH",
                    "malformed request path",
                ))
            }
        };
        let body: Result<Option<Value>, ()> = if req.body.is_empty() {
            Ok(None)
        } else {
            std::str::from_utf8(&req.body)
                .ok()
                .and_then(|t| parse_canonical_text(t).ok())
                .map(Some)
                .ok_or(())
        };
        let needs_body = matches!(
            parsed_route,
            Route::TlBitvmStatus
                | Route::RpcCompat(_)
                | Route::RpcRoute
                | Route::AddressUtxo(_)
                | Route::TxDecode
                | Route::TxSend
                | Route::ProxyOnly(_)
                | Route::TlOther(_)
        ) && req.method != "GET";
        let body = match (needs_body, body) {
            (true, Err(())) => {
                return done(HttpResponse::error(
                    400,
                    &c,
                    "BAD_JSON",
                    "request body is not valid JSON",
                ))
            }
            (_, Ok(b)) => b,
            (false, Err(())) => None,
        };
        let out = self.dispatch_route(ticket, req, parsed_route, body, c, &ip, now_ms);
        (ticket, out)
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_route(
        &mut self,
        ticket: HttpTicket,
        req: &HttpRequest,
        parsed: Route,
        body: Option<Value>,
        c: Vec<(String, String)>,
        ip: &str,
        now_ms: u64,
    ) -> Vec<Out> {
        let proxy = |method: &str, path: String, body: Option<Value>| ProxyRequest {
            method: method.to_owned(),
            path,
            body,
            headers: Vec::new(),
        };
        match parsed {
            Route::Health => {
                let providers = self
                    .sessions
                    .iter()
                    .filter(|(h, s)| {
                        self.adverts.contains_key(h)
                            && s.router
                                .as_ref()
                                .is_some_and(|r| self.router.advertised_node(r, now_ms).is_some())
                    })
                    .count();
                vec![reply(
                    ticket,
                    HttpResponse::json(
                        200,
                        &c,
                        &json!({
                            "ok": true,
                            "collatorId": self.collator_id,
                            "uptimeSec": now_ms.saturating_sub(self.started_ms) / 1000,
                            "rpcProviders": providers,
                        }),
                    ),
                )]
            }
            Route::Manifest => vec![reply(ticket, HttpResponse::json(200, &c, &self.manifest))],
            Route::AttestationIp => {
                let request = ProxyRequest {
                    method: req.method.clone(),
                    path: "/attestation/ip".into(),
                    body: None,
                    headers: self.proxy_headers(req),
                };
                self.upstream(
                    ticket,
                    request,
                    Fallback::Attestation { ip: ip.to_owned() },
                    c,
                )
            }
            Route::RpcProviders => {
                let providers: Vec<Value> = self
                    .sessions
                    .iter()
                    .filter_map(|(h, s)| {
                        let a = self.adverts.get(h)?;
                        self.router.advertised_node(s.router.as_ref()?, now_ms)?;
                        Some(json!({
                            "nodeId": a.node_id,
                            "services": [{
                                "service": self.cfg.rpc_service,
                                "network": self.cfg.rpc_network,
                                "methods": a.methods,
                            }],
                            "lastSeenTs": a.since_ms,
                        }))
                    })
                    .collect();
                vec![reply(
                    ticket,
                    HttpResponse::json(200, &c, &json!({"ok": true, "providers": providers})),
                )]
            }
            Route::TlBitvmStatus => {
                let status = self.local_bitvm(body.as_ref(), now_ms);
                vec![reply(ticket, HttpResponse::json(200, &c, &status))]
            }
            Route::TlOther(path) => {
                if !self.cfg.legacy_proxy_enabled {
                    return vec![reply(
                        ticket,
                        HttpResponse::json(
                            404,
                            &c,
                            &json!({"error": {"code": "LEGACY_TL_PROXY_DISABLED", "message": "Legacy /tl_* proxy is disabled"}}),
                        ),
                    )];
                }
                let method = if req.method == "GET" { "GET" } else { "POST" };
                let request = proxy(method, path, if method == "GET" { None } else { body });
                self.upstream(ticket, request, Fallback::NotFound, c)
            }
            Route::RpcCompat(method) => {
                if method.is_empty() {
                    return vec![reply(
                        ticket,
                        HttpResponse::error(400, &c, "BAD_RPC_REQUEST", "Missing RPC method"),
                    )];
                }
                if !is_public_rpc_method(&method) {
                    return vec![reply(
                        ticket,
                        HttpResponse::error(
                            403,
                            &c,
                            "RPC_METHOD_FORBIDDEN",
                            "RPC method is not available on the public mesh",
                        ),
                    )];
                }
                if normalize_method(&method) == LOCAL_PUBLIC_METHOD {
                    let status = self.local_bitvm(body.as_ref(), now_ms);
                    return vec![reply(ticket, HttpResponse::json(200, &c, &status))];
                }
                let params = compat_params(body.as_ref());
                self.start_compat(ticket, &method, params, c, now_ms)
            }
            Route::RpcRoute => {
                let raw = body.unwrap_or(Value::Null);
                let Some(rpc) = self.normalize_request(&raw) else {
                    return vec![reply(
                        ticket,
                        HttpResponse::json(
                            400,
                            &c,
                            &json!({"ok": false, "error": {"code": "BAD_RPC_REQUEST", "message": "service and method are required"}}),
                        ),
                    )];
                };
                if rpc.service != self.cfg.rpc_service {
                    return vec![reply(
                        ticket,
                        HttpResponse::json(
                            403,
                            &c,
                            &json!({"ok": false, "error": {"code": "RPC_SERVICE_FORBIDDEN", "message": "RPC service is not available on the public mesh"}}),
                        ),
                    )];
                }
                if !is_public_rpc_method(&rpc.method) {
                    return vec![reply(
                        ticket,
                        HttpResponse::json(
                            403,
                            &c,
                            &json!({"ok": false, "error": {"code": "RPC_METHOD_FORBIDDEN", "message": "RPC method is not available on the public mesh"}}),
                        ),
                    )];
                }
                // The caller id is untrusted and only echoed back; routing uses a ticket id.
                let mut rpc = rpc;
                let caller_id = rpc.id.clone();
                rpc.id = format!("http-{}", ticket.0);
                self.http_route(ticket, rpc, RpcKind::Route { caller_id }, c, now_ms)
            }
            Route::ChainInfo => {
                let request = proxy("GET", "/chain/info".into(), None);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "getblockchaininfo".into(),
                        params: Vec::new(),
                    },
                    c,
                )
            }
            Route::AddressValidate(a) => {
                let request = proxy("GET", format!("/address/validate/{a}"), None);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "validateaddress".into(),
                        params: vec![json!(a)],
                    },
                    c,
                )
            }
            Route::AddressBalance(a) => {
                let request = proxy("GET", format!("/address/balance/{a}"), None);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "tl_getallbalancesforaddress".into(),
                        params: vec![json!(a)],
                    },
                    c,
                )
            }
            Route::AddressFaucet(a) => {
                let request = proxy("GET", format!("/address/faucet/{a}"), None);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "sendtoaddress".into(),
                        params: vec![json!(a), json!(1)],
                    },
                    c,
                )
            }
            Route::AddressUtxo(a) => {
                let pubkey = body
                    .as_ref()
                    .and_then(|b| b.get("pubkey"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|p| {
                        !p.is_empty() && p.len() <= 130 && p.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                    .map(str::to_owned);
                let request = proxy(
                    "POST",
                    format!("/address/utxo/{a}"),
                    Some(json!({"pubkey": pubkey})),
                );
                let mut filter = json!({"address": a});
                if let Some(p) = &pubkey {
                    filter["pubkey"] = json!(p);
                }
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "listunspent".into(),
                        params: vec![json!(0), json!(99_999_999), filter],
                    },
                    c,
                )
            }
            Route::TxGet(id) => {
                let request = proxy("GET", format!("/tx/{id}"), None);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "tl_gettransaction".into(),
                        params: vec![json!(id)],
                    },
                    c,
                )
            }
            Route::TokenList => {
                let request = proxy("GET", "/token/list".into(), None);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "tl_listproperties".into(),
                        params: Vec::new(),
                    },
                    c,
                )
            }
            Route::TxDecode => {
                let rawtx = body
                    .as_ref()
                    .and_then(|b| b.get("rawtx"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let request = proxy("POST", "/tx/decode".into(), body);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "decoderawtransaction".into(),
                        params: vec![json!(rawtx)],
                    },
                    c,
                )
            }
            Route::TxSend => {
                let raw_tx = body
                    .as_ref()
                    .and_then(|b| b.get("rawTx"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let request = proxy("POST", "/tx/sendTx".into(), body);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "sendrawtransaction".into(),
                        params: vec![json!(raw_tx)],
                    },
                    c,
                )
            }
            Route::ProxyOnly(path) => {
                let request = proxy("POST", path, body);
                self.upstream(ticket, request, Fallback::NotFound, c)
            }
            Route::TokenGet(id) => {
                let n: u64 = id.parse().unwrap_or(0);
                let request = proxy("GET", format!("/token/{id}"), None);
                self.upstream(
                    ticket,
                    request,
                    Fallback::Rpc {
                        method: "tl_getproperty".into(),
                        params: vec![json!(n)],
                    },
                    c,
                )
            }
            Route::NotFound => vec![reply(ticket, HttpResponse::text(404, &c, "not found"))],
        }
    }

    /// The host's answer to an `Out::Proxy`: `Some((status, body))` or `None` when the
    /// upstream failed or timed out. Must be called exactly once per `Out::Proxy`.
    pub fn proxy_done(
        &mut self,
        ticket: HttpTicket,
        result: Option<(u16, Value)>,
        now_ms: u64,
    ) -> Vec<Out> {
        let Some(plan) = self.http_plans.remove(&ticket) else {
            return Vec::new();
        };
        let c = plan.cors;
        match plan.stage {
            Stage::Upstream(fallback) => {
                if let Some((status, body)) = result.filter(|(s, _)| *s < 500) {
                    return vec![reply(ticket, HttpResponse::json(status, &c, &body))];
                }
                match fallback {
                    Fallback::NotFound => {
                        vec![reply(ticket, HttpResponse::text(404, &c, "not found"))]
                    }
                    Fallback::Rpc { method, params } => {
                        self.start_compat(ticket, &method, params, c, now_ms)
                    }
                    Fallback::Attestation { ip } => {
                        let body = self.attestation(&ip, now_ms);
                        vec![reply(ticket, HttpResponse::json(200, &c, &body))]
                    }
                }
            }
            Stage::CompatUpstream => match result {
                Some((status, body)) => vec![reply(ticket, HttpResponse::json(status, &c, &body))],
                None => vec![reply(
                    ticket,
                    HttpResponse::json(
                        502,
                        &c,
                        &json!({"error": "legacy relayer unavailable", "code": "LEGACY_PROXY_ERROR"}),
                    ),
                )],
            },
            Stage::Rpc { caller_id, kind } => {
                // Not an upstream exchange; put the plan back untouched.
                self.http_plans.insert(
                    ticket,
                    HttpPlan {
                        cors: c,
                        stage: Stage::Rpc { caller_id, kind },
                    },
                );
                Vec::new()
            }
        }
    }

    /// The host gave up on an HTTP exchange (client gone). Frees the plan; a still-pending
    /// router request completes (and is discarded) by timeout.
    pub fn http_abort(&mut self, ticket: HttpTicket) {
        if let Some(plan) = self.http_plans.remove(&ticket) {
            if let Stage::Rpc { caller_id, .. } = plan.stage {
                self.http_waiters.remove(&caller_id);
            }
        }
    }
}

// Re-exported for hosts building a `ServiceParts`.
pub use crate::signer::SecretKeySigner;
