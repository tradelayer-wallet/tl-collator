//! WebRTC signaling state machine (port of the `SIGNAL_*` handlers in `src/index.ts`
//! 971-1259, `src/peerSession.ts`, `src/wrtc.d.ts`, `spec/schemas/signalmsg.v1.schema.json`).
//!
//! A pure reducer: no socket, timer, SDP engine or peer connection lives here. The host
//! feeds it signaling-socket text frames, peer-connection events and an injected clock
//! (`now_ms`), and performs the returned `Action`s. The collator is always the answerer.
//!
//! ```text
//!            HELLO              OFFER                AnswerReady        DataChannelOpen
//!   Idle ───────────► Greeted ───────────► Offering ──────────────► Answered ──────────► Established
//!    └─────────────────────────OFFER───────────▲
//!   (any state) ──── close / timeout / PeerFailed / violation budget ───► Closed
//! ```
//!
//! Legacy behaviour that is not reproduced (see the README table): a second OFFER replaced
//! `pc` and leaked the previous peer connection; ICE candidates were handed unchecked to the
//! SDP stack; `e.message` of internal failures was sent to the peer; local ICE could precede
//! the ANSWER; nothing bounded message counts, SDP size, candidate counts or connection time.
use serde_json::{json, Value};
use tl_collator_wire::parse_canonical_text;

pub const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;
pub const CLOSE_POLICY: u16 = 1008;
pub const CLOSE_INTERNAL: u16 = 1011;
pub const CLOSE_TIMEOUT: u16 = 4408;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalState {
    /// Socket accepted, nothing received yet.
    Idle,
    /// `SIGNAL_HELLO` received (the wallet sends it before the offer; legacy ignored it).
    Greeted,
    /// An offer is pending: the host is building the answer. At most one per session.
    Offering,
    /// The answer was sent; waiting for the data channel to open.
    Answered,
    /// Data channel open. The signaling socket stays up (legacy closes the channel with it).
    Established,
    Closed,
}

impl SignalState {
    pub fn as_str(self) -> &'static str {
        match self {
            SignalState::Idle => "idle",
            SignalState::Greeted => "greeted",
            SignalState::Offering => "offering",
            SignalState::Answered => "answered",
            SignalState::Established => "established",
            SignalState::Closed => "closed",
        }
    }
}

/// The complete set of state changes the reducer may ever make.
pub fn edge_allowed(from: SignalState, to: SignalState) -> bool {
    use SignalState::*;
    from == to
        || matches!(
            (from, to),
            (Idle, Greeted)
                | (Idle, Offering)
                | (Greeted, Offering)
                | (Offering, Answered)
                | (Answered, Established)
                | (Idle | Greeted | Offering | Answered | Established, Closed)
        )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalLimits {
    /// Longest accepted signaling frame (bytes); larger closes the socket with 1009.
    pub max_frame_bytes: usize,
    pub max_sdp_bytes: usize,
    pub max_candidate_bytes: usize,
    /// Remote candidates handed to the peer connection over the whole session.
    pub max_remote_candidates: usize,
    /// Remote candidates held while the offer is being answered.
    pub max_buffered_candidates: usize,
    /// Local candidates relayed to the peer over the whole session.
    pub max_local_candidates: usize,
    /// Protocol errors tolerated before the socket is closed.
    pub max_violations: u32,
    /// Frames accepted over the whole session.
    pub max_messages: u32,
    /// No offer within this long after opening.
    pub idle_timeout_ms: u64,
    /// The host must produce the answer within this long after the offer.
    pub offer_timeout_ms: u64,
    /// The data channel must open within this long after the answer.
    pub connect_timeout_ms: u64,
}

impl Default for SignalLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 128 * 1024,
            max_sdp_bytes: 64 * 1024,
            max_candidate_bytes: 1024,
            max_remote_candidates: 128,
            max_buffered_candidates: 64,
            max_local_candidates: 128,
            max_violations: 8,
            max_messages: 512,
            idle_timeout_ms: 30_000,
            offer_timeout_ms: 15_000,
            connect_timeout_ms: 60_000,
        }
    }
}

impl SignalLimits {
    /// Frame limit follows the configured WebSocket payload limit when that is smaller.
    pub fn from_max_msg_bytes(max_msg_bytes: usize) -> Self {
        let d = Self::default();
        Self {
            max_frame_bytes: d.max_frame_bytes.min(max_msg_bytes),
            ..d
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_frame_bytes < 1024 || self.max_frame_bytes > 1 << 20 {
            return Err("max_frame_bytes");
        }
        if self.max_sdp_bytes < 256 || self.max_sdp_bytes + 1024 > self.max_frame_bytes {
            return Err("max_sdp_bytes");
        }
        if self.max_candidate_bytes < 64 || self.max_candidate_bytes + 1024 > self.max_frame_bytes {
            return Err("max_candidate_bytes");
        }
        if self.max_remote_candidates == 0
            || self.max_remote_candidates > 1024
            || self.max_buffered_candidates > self.max_remote_candidates
            || self.max_local_candidates == 0
            || self.max_local_candidates > 1024
        {
            return Err("candidate limits");
        }
        if self.max_violations == 0 || self.max_messages == 0 || self.max_messages > 100_000 {
            return Err("message budget");
        }
        if self.idle_timeout_ms == 0 || self.offer_timeout_ms == 0 || self.connect_timeout_ms == 0 {
            return Err("timeouts");
        }
        Ok(())
    }
}

/// `RTCIceCandidateInit` rebuilt from the four known fields; anything else is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceCandidate {
    /// Empty string is the end-of-candidates marker.
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
}

impl IceCandidate {
    pub fn to_json(&self) -> Value {
        json!({
            "candidate": self.candidate,
            "sdpMid": self.sdp_mid,
            "sdpMLineIndex": self.sdp_mline_index,
            "usernameFragment": self.username_fragment,
        })
    }
}

/// What the host must do. Order matters; perform them in sequence.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Send this JSON value as a text frame on the signaling socket.
    Send(Value),
    /// Create a peer connection (with `Config::ice_servers`), set this remote offer, create
    /// and set the local answer, then report `HostEvent::AnswerReady` or `PeerFailed`.
    /// Local ICE candidates must be reported as `HostEvent::LocalCandidate`.
    ApplyOffer {
        sdp: String,
    },
    AddRemoteCandidate(IceCandidate),
    /// Close the peer connection and its data channel (idempotent).
    ClosePeer,
    /// Close the signaling socket, then call `Service::close_session` for the session.
    CloseSocket {
        code: u16,
        reason: &'static str,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEvent {
    AnswerReady {
        sdp: String,
    },
    LocalCandidate(IceCandidate),
    /// setRemoteDescription/createAnswer/setLocalDescription (or the peer connection) failed.
    PeerFailed,
    DataChannelOpen,
    /// The signaling socket closed or errored (legacy `ws.on('close'|'error')`).
    SocketClosed,
}

fn err_msg(code: &str, msg: &str) -> Value {
    json!({"t": "SIGNAL_ERR", "v": 1, "code": code, "msg": msg})
}

fn printable_token(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn digits_in(s: &str, max: u64) -> bool {
    !s.is_empty()
        && s.len() <= 10
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u64>().is_ok_and(|n| n <= max)
}

/// `candidate:<foundation> <component> <udp|tcp> <priority> <address> <port> typ <type> ...`
fn valid_candidate_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("candidate:") else {
        return false;
    };
    if !rest.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return false;
    }
    let t: Vec<&str> = rest.split(' ').collect();
    t.len() >= 8
        && printable_token(t[0], 32)
        && digits_in(t[1], 255)
        && (t[2].eq_ignore_ascii_case("udp") || t[2].eq_ignore_ascii_case("tcp"))
        && digits_in(t[3], u64::from(u32::MAX))
        && printable_token(t[4], 255)
        && digits_in(t[5], 65_535)
        && t[6] == "typ"
        && matches!(t[7], "host" | "srflx" | "prflx" | "relay")
}

/// Bounds and shape for an SDP blob. Not a full RFC 4566 parser: the SDP engine remains the
/// authority, this keeps junk, control bytes and non-data-channel media away from it.
pub fn check_sdp(sdp: &str, max_bytes: usize) -> Result<(), &'static str> {
    if sdp.is_empty() || sdp.len() > max_bytes {
        return Err("sdp size");
    }
    if !sdp.starts_with("v=0") {
        return Err("sdp version");
    }
    if sdp
        .chars()
        .any(|c| c.is_control() && c != '\r' && c != '\n')
    {
        return Err("sdp control character");
    }
    let mut lines = 0usize;
    let mut media = 0usize;
    for raw in sdp.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        lines += 1;
        let b = line.as_bytes();
        if lines > 1024
            || line.len() > 4096
            || b.len() < 2
            || !b[0].is_ascii_lowercase()
            || b[1] != b'='
        {
            return Err("sdp line");
        }
        if line.starts_with("m=") {
            media += 1;
            // The collator only negotiates a data channel.
            if !line.starts_with("m=application ") || media > 4 {
                return Err("sdp media");
            }
        }
    }
    if media == 0 {
        return Err("sdp media");
    }
    Ok(())
}

fn candidate_from(v: &Value, limits: &SignalLimits) -> Result<IceCandidate, &'static str> {
    let obj = v.as_object().ok_or("candidate")?;
    let candidate = obj
        .get("candidate")
        .and_then(Value::as_str)
        .ok_or("candidate")?;
    if candidate.len() > limits.max_candidate_bytes {
        return Err("candidate size");
    }
    let opt_str = |name: &'static str, max: usize| -> Result<Option<String>, &'static str> {
        match obj.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if printable_token(s, max) => Ok(Some(s.clone())),
            _ => Err(name),
        }
    };
    let sdp_mid = opt_str("sdpMid", 64)?;
    let username_fragment = opt_str("usernameFragment", 256)?;
    let sdp_mline_index = match obj.get("sdpMLineIndex") {
        None | Some(Value::Null) => None,
        Some(n) => Some(
            n.as_u64()
                .filter(|n| *n <= 255)
                .map(|n| n as u16)
                .ok_or("sdpMLineIndex")?,
        ),
    };
    if !candidate.is_empty() {
        if !valid_candidate_line(candidate) {
            return Err("candidate shape");
        }
        if sdp_mid.is_none() && sdp_mline_index.is_none() {
            return Err("candidate target");
        }
    }
    Ok(IceCandidate {
        candidate: candidate.to_owned(),
        sdp_mid,
        sdp_mline_index,
        username_fragment,
    })
}

enum Parsed {
    Hello,
    Offer(String),
    Answer,
    Ice(IceCandidate),
    PeerErr,
}

enum ParseFail {
    /// Not JSON, no string `t`, or an unknown type: dropped (legacy: silent).
    Drop,
    /// Known type, bad fields.
    Schema(&'static str),
    TooLarge,
}

fn parse_signal(text: &str, limits: &SignalLimits) -> Result<Parsed, ParseFail> {
    if text.len() > limits.max_frame_bytes {
        return Err(ParseFail::TooLarge);
    }
    let value = parse_canonical_text(text).map_err(|_| ParseFail::Drop)?;
    let t = value
        .get("t")
        .and_then(Value::as_str)
        .ok_or(ParseFail::Drop)?;
    if !matches!(
        t,
        "SIGNAL_HELLO" | "SIGNAL_OFFER" | "SIGNAL_ANSWER" | "SIGNAL_ICE" | "SIGNAL_ERR"
    ) {
        return Err(ParseFail::Drop);
    }
    if value.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(ParseFail::Schema("v"));
    }
    let sdp_of = |kind: &'static str| -> Result<String, ParseFail> {
        if value.get("kind").and_then(Value::as_str) != Some(kind) {
            return Err(ParseFail::Schema("kind"));
        }
        let sdp = value
            .get("sdp")
            .and_then(Value::as_str)
            .ok_or(ParseFail::Schema("sdp"))?;
        check_sdp(sdp, limits.max_sdp_bytes).map_err(ParseFail::Schema)?;
        Ok(sdp.to_owned())
    };
    match t {
        "SIGNAL_HELLO" => {
            let id = value
                .get("clientId")
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 128 && !s.chars().any(char::is_control))
                .ok_or(ParseFail::Schema("clientId"))?;
            let _ = id;
            Ok(Parsed::Hello)
        }
        "SIGNAL_OFFER" => Ok(Parsed::Offer(sdp_of("offer")?)),
        "SIGNAL_ANSWER" => {
            sdp_of("answer")?;
            Ok(Parsed::Answer)
        }
        "SIGNAL_ICE" => {
            let c = value
                .get("candidate")
                .ok_or(ParseFail::Schema("candidate"))?;
            Ok(Parsed::Ice(
                candidate_from(c, limits).map_err(ParseFail::Schema)?,
            ))
        }
        _ => {
            for name in ["code", "msg"] {
                value
                    .get(name)
                    .and_then(Value::as_str)
                    .filter(|s| s.len() <= 1024)
                    .ok_or(ParseFail::Schema("err"))?;
            }
            Ok(Parsed::PeerErr)
        }
    }
}

pub struct SignalSession {
    limits: SignalLimits,
    state: SignalState,
    opened_ms: u64,
    last_now: u64,
    offer_started_ms: u64,
    answered_ms: u64,
    messages: u32,
    violations: u32,
    last_reject: Option<&'static str>,
    offers_accepted: u8,
    remote_sent: usize,
    remote_buffer: Vec<IceCandidate>,
    local_sent: usize,
    local_buffer: Vec<IceCandidate>,
}

impl SignalSession {
    pub fn new(limits: SignalLimits, now_ms: u64) -> Result<Self, &'static str> {
        limits.validate()?;
        Ok(Self {
            limits,
            state: SignalState::Idle,
            opened_ms: now_ms,
            last_now: now_ms,
            offer_started_ms: 0,
            answered_ms: 0,
            messages: 0,
            violations: 0,
            last_reject: None,
            offers_accepted: 0,
            remote_sent: 0,
            remote_buffer: Vec::new(),
            local_sent: 0,
            local_buffer: Vec::new(),
        })
    }

    pub fn state(&self) -> SignalState {
        self.state
    }

    /// Offers awaiting an answer: 0 or 1, never more.
    pub fn pending_offers(&self) -> usize {
        usize::from(self.state == SignalState::Offering)
    }

    /// Offers accepted over the session lifetime: 0 or 1.
    pub fn offers_accepted(&self) -> u8 {
        self.offers_accepted
    }

    /// Why the last schema-invalid frame was refused (for host logs; never sent to the peer).
    pub fn last_reject(&self) -> Option<&'static str> {
        self.last_reject
    }

    pub fn has_peer(&self) -> bool {
        matches!(
            self.state,
            SignalState::Offering | SignalState::Answered | SignalState::Established
        )
    }

    /// Buffered candidates (remote + local), always within the configured limits.
    pub fn buffered_candidates(&self) -> usize {
        self.remote_buffer.len() + self.local_buffer.len()
    }

    /// Absolute time at which `expire` will close the session, if any.
    pub fn deadline_ms(&self) -> Option<u64> {
        match self.state {
            SignalState::Idle | SignalState::Greeted => {
                Some(self.opened_ms.saturating_add(self.limits.idle_timeout_ms))
            }
            SignalState::Offering => Some(
                self.offer_started_ms
                    .saturating_add(self.limits.offer_timeout_ms),
            ),
            SignalState::Answered => Some(
                self.answered_ms
                    .saturating_add(self.limits.connect_timeout_ms),
            ),
            SignalState::Established | SignalState::Closed => None,
        }
    }

    fn tick(&mut self, now_ms: u64) -> u64 {
        // The clock is injected; never let a backwards step shorten a deadline.
        self.last_now = self.last_now.max(now_ms);
        self.last_now
    }

    fn goto(&mut self, to: SignalState) {
        debug_assert!(edge_allowed(self.state, to));
        if edge_allowed(self.state, to) {
            self.state = to;
        }
    }

    fn shutdown(&mut self, code: u16, reason: &'static str, err: Option<Value>) -> Vec<Action> {
        let mut out = Vec::new();
        if let Some(e) = err {
            out.push(Action::Send(e));
        }
        if self.has_peer() {
            out.push(Action::ClosePeer);
        }
        out.push(Action::CloseSocket { code, reason });
        self.remote_buffer.clear();
        self.local_buffer.clear();
        self.goto(SignalState::Closed);
        out
    }

    /// A refused message: tell the peer, keep the state, count against the budget.
    fn violation(&mut self, code: &str, msg: &str) -> Vec<Action> {
        self.violations = self.violations.saturating_add(1);
        if self.violations > self.limits.max_violations {
            return self.shutdown(
                CLOSE_POLICY,
                "too many protocol errors",
                Some(err_msg("too_many_errors", "too many protocol errors")),
            );
        }
        vec![Action::Send(err_msg(code, msg))]
    }

    fn silent_violation(&mut self) -> Vec<Action> {
        self.violations = self.violations.saturating_add(1);
        if self.violations > self.limits.max_violations {
            return self.shutdown(
                CLOSE_POLICY,
                "too many protocol errors",
                Some(err_msg("too_many_errors", "too many protocol errors")),
            );
        }
        Vec::new()
    }

    /// One text frame from the signaling socket.
    pub fn on_frame(&mut self, text: &str, now_ms: u64) -> Vec<Action> {
        let now = self.tick(now_ms);
        if self.state == SignalState::Closed {
            return Vec::new();
        }
        self.messages = self.messages.saturating_add(1);
        if self.messages > self.limits.max_messages {
            return self.shutdown(
                CLOSE_POLICY,
                "message budget exhausted",
                Some(err_msg("rate_limited", "too many signaling messages")),
            );
        }
        let parsed = match parse_signal(text, &self.limits) {
            Ok(p) => p,
            Err(ParseFail::TooLarge) => {
                return self.shutdown(CLOSE_MESSAGE_TOO_BIG, "message too big", None)
            }
            Err(ParseFail::Drop) => return self.silent_violation(),
            Err(ParseFail::Schema(why)) => {
                self.last_reject = Some(why);
                return self.violation("bad_message", "invalid signaling message");
            }
        };
        use SignalState::*;
        match (parsed, self.state) {
            (Parsed::PeerErr, _) => Vec::new(),
            (Parsed::Hello, Idle) => {
                self.goto(Greeted);
                Vec::new()
            }
            (Parsed::Offer(sdp), Idle | Greeted) => {
                self.goto(Offering);
                self.offers_accepted = self.offers_accepted.saturating_add(1);
                self.offer_started_ms = now;
                vec![Action::ApplyOffer { sdp }]
            }
            (Parsed::Ice(c), Offering) => {
                if self.remote_buffer.len() >= self.limits.max_buffered_candidates
                    || self.remote_sent + self.remote_buffer.len()
                        >= self.limits.max_remote_candidates
                {
                    return self.violation("too_many_candidates", "too many candidates");
                }
                self.remote_buffer.push(c);
                Vec::new()
            }
            (Parsed::Ice(c), Answered | Established) => {
                if self.remote_sent >= self.limits.max_remote_candidates {
                    return self.violation("too_many_candidates", "too many candidates");
                }
                self.remote_sent += 1;
                vec![Action::AddRemoteCandidate(c)]
            }
            (Parsed::Hello, _) => self.violation("unexpected", "duplicate hello"),
            (Parsed::Offer(_), _) => self.violation("unexpected", "an offer was already made"),
            (Parsed::Answer, _) => self.violation("unexpected", "the collator is the answerer"),
            (Parsed::Ice(_), _) => self.violation("unexpected", "no offer yet"),
        }
    }

    /// Something that happened on the host side.
    pub fn on_event(&mut self, ev: HostEvent, now_ms: u64) -> Vec<Action> {
        let now = self.tick(now_ms);
        use SignalState::*;
        if self.state == Closed {
            return Vec::new();
        }
        match (ev, self.state) {
            (HostEvent::SocketClosed, _) => {
                let mut out = Vec::new();
                if self.has_peer() {
                    out.push(Action::ClosePeer);
                }
                self.remote_buffer.clear();
                self.local_buffer.clear();
                self.goto(Closed);
                out
            }
            (HostEvent::AnswerReady { sdp }, Offering) => {
                if check_sdp(&sdp, self.limits.max_sdp_bytes).is_err() {
                    return self.shutdown(
                        CLOSE_INTERNAL,
                        "internal error",
                        Some(err_msg("internal", "internal error")),
                    );
                }
                self.goto(Answered);
                self.answered_ms = now;
                let mut out = vec![Action::Send(
                    json!({"t": "SIGNAL_ANSWER", "v": 1, "kind": "answer", "sdp": sdp}),
                )];
                // ANSWER always precedes this session's ICE in both directions.
                for c in std::mem::take(&mut self.local_buffer) {
                    out.push(Action::Send(
                        json!({"t": "SIGNAL_ICE", "v": 1, "candidate": c.to_json()}),
                    ));
                }
                for c in std::mem::take(&mut self.remote_buffer) {
                    self.remote_sent += 1;
                    out.push(Action::AddRemoteCandidate(c));
                }
                out
            }
            (HostEvent::LocalCandidate(c), Offering) => {
                if self.local_sent < self.limits.max_local_candidates {
                    self.local_buffer.push(c);
                    self.local_sent += 1;
                }
                Vec::new()
            }
            (HostEvent::LocalCandidate(c), Answered | Established) => {
                if self.local_sent >= self.limits.max_local_candidates {
                    return Vec::new();
                }
                self.local_sent += 1;
                vec![Action::Send(
                    json!({"t": "SIGNAL_ICE", "v": 1, "candidate": c.to_json()}),
                )]
            }
            (HostEvent::PeerFailed, Offering | Answered | Established) => self.shutdown(
                CLOSE_INTERNAL,
                "internal error",
                // Legacy sent `e.message` of the failure; the text is fixed here.
                Some(err_msg("internal", "internal error")),
            ),
            (HostEvent::DataChannelOpen, Answered) => {
                self.goto(Established);
                Vec::new()
            }
            // Stale or impossible host events change nothing.
            _ => Vec::new(),
        }
    }

    /// Timeouts; the host calls this at or after `deadline_ms`.
    pub fn expire(&mut self, now_ms: u64) -> Vec<Action> {
        let now = self.tick(now_ms);
        match self.deadline_ms() {
            Some(d) if now >= d => self.shutdown(
                CLOSE_TIMEOUT,
                "signaling timeout",
                Some(err_msg("timeout", "signaling timed out")),
            ),
            _ => Vec::new(),
        }
    }
}
