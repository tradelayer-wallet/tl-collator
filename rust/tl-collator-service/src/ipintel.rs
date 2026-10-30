//! IP intelligence decision logic (port of `src/ipIntel.ts` and the policy block of
//! the SUBMIT handler, `src/index.ts` 1156-1181). No network: lookups go through a trait.
use crate::config::{FailMode, Mode};
use crate::lru::LruMap;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpIntel {
    pub asn: Option<u32>,
    pub vpn: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntelError(pub String);

pub trait IpIntelSource {
    fn lookup(&mut self, ip: &str) -> Result<IpIntel, IntelError>;
}

/// `asn` must be a JSON integer (or a decimal string) in `1..=u32::MAX`; `vpn` a JSON
/// boolean. The legacy coercion `Number(j.asn)` turned `null`, `""` and `false` into 0.
pub fn parse_reply(reply: &Value) -> IpIntel {
    let asn = match reply.get("asn") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s))
            if !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse().ok()
        }
        _ => None,
    }
    .filter(|n| (1..=u64::from(u32::MAX)).contains(n))
    .map(|n| n as u32);
    IpIntel {
        asn,
        vpn: reply.get("vpn").and_then(Value::as_bool),
    }
}

/// TTL cache in front of a source, bounded in entries, driven by an injected clock.
pub struct IpIntelClient<S: IpIntelSource> {
    source: S,
    ttl_ms: u64,
    cache: LruMap<(u64, IpIntel)>,
}

impl<S: IpIntelSource> IpIntelClient<S> {
    pub fn new(source: S, ttl_sec: u32, max_entries: usize) -> Self {
        Self {
            source,
            ttl_ms: u64::from(ttl_sec) * 1000,
            cache: LruMap::new(max_entries),
        }
    }

    pub fn lookup(&mut self, ip: &str, now_ms: u64) -> Result<IpIntel, IntelError> {
        if let Some((exp, v)) = self.cache.get(ip) {
            if *exp > now_ms {
                return Ok(*v);
            }
        }
        let fresh = self.source.lookup(ip)?;
        let _ = self
            .cache
            .insert(ip, (now_ms.saturating_add(self.ttl_ms), fresh));
        Ok(fresh)
    }
}

#[derive(Clone, Debug)]
pub struct IntelPolicy {
    pub vpn_mode: Mode,
    pub asn_mode: Mode,
    pub blocklist: Vec<u32>,
    pub fail_mode: FailMode,
}

impl IntelPolicy {
    pub fn active(&self) -> bool {
        self.vpn_mode != Mode::Off || self.asn_mode != Mode::Off
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// First enforcing rule that matched: `(code, message)`.
    pub reject: Option<(&'static str, &'static str)>,
    /// Rules in `log` mode that matched; the caller records them in the audit log.
    pub logged: Vec<&'static str>,
}

/// Evaluate a session's known intel. `lookup_failed` with no usable metadata rejects in
/// closed mode when any enforcing rule is configured (legacy: ignored lookup errors,
/// so an unreachable intel service disabled `reject` mode).
pub fn evaluate(policy: &IntelPolicy, meta: IpIntel, lookup_failed: bool) -> Verdict {
    let mut verdict = Verdict {
        reject: None,
        logged: Vec::new(),
    };
    if meta.vpn == Some(true) {
        match policy.vpn_mode {
            Mode::Reject => verdict.reject = Some(("VPN_BLOCKED", "vpn traffic rejected")),
            Mode::Log => verdict.logged.push("VPN_BLOCKED"),
            Mode::Off => {}
        }
    }
    if let Some(asn) = meta.asn {
        if policy.blocklist.contains(&asn) {
            match policy.asn_mode {
                Mode::Reject => {
                    if verdict.reject.is_none() {
                        verdict.reject = Some(("ASN_BLOCKED", "asn blocked"));
                    }
                }
                Mode::Log => verdict.logged.push("ASN_BLOCKED"),
                Mode::Off => {}
            }
        }
    }
    let enforcing = policy.vpn_mode == Mode::Reject || policy.asn_mode == Mode::Reject;
    let unknown = meta.vpn.is_none() && meta.asn.is_none();
    if lookup_failed
        && unknown
        && enforcing
        && policy.fail_mode == FailMode::Closed
        && verdict.reject.is_none()
    {
        verdict.reject = Some(("IP_INTEL_DOWN", "ip reputation unavailable"));
    }
    verdict
}

impl<T: IpIntelSource + ?Sized> IpIntelSource for Box<T> {
    fn lookup(&mut self, ip: &str) -> Result<IpIntel, IntelError> {
        (**self).lookup(ip)
    }
}
