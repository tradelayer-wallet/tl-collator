//! Clearlist authorization (port of `src/clearlist.ts` and the enforcement block of
//! the SUBMIT handler, `src/index.ts` 1183-1207). No network: the oracle is a trait.
use crate::config::FailMode;
use crate::lru::LruMap;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearlistResult {
    pub allowed: bool,
    pub snapshot_id: Option<String>,
    pub exp_ts: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleError(pub String);

pub trait ClearlistOracle {
    fn check(&mut self, group_id: &str, pubkey_hex: &str) -> Result<ClearlistResult, OracleError>;
}

/// Parse an oracle reply. `allowed` must be the JSON boolean `true`; the legacy
/// `!!j.allowed` accepted any truthy value such as the string `"false"`.
pub fn parse_oracle_reply(reply: &Value) -> ClearlistResult {
    ClearlistResult {
        allowed: reply.get("allowed").and_then(Value::as_bool) == Some(true),
        snapshot_id: reply
            .get("snapshotId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .map(str::to_owned),
        exp_ts: reply.get("expTs").and_then(Value::as_u64),
    }
}

/// Length-prefixed so that `("a|b","c")` and `("a","b|c")` are different keys
/// (the legacy key was `groupId + "|" + pubkey`).
pub fn cache_key(group_id: &str, pubkey_hex: &str) -> String {
    format!(
        "{}:{}:{}",
        group_id.len(),
        group_id,
        pubkey_hex.to_ascii_lowercase()
    )
}

/// Caching client. The cache is bounded (legacy: unbounded `Map`) and keyed on the
/// lowercase public key.
pub struct ClearlistClient<O: ClearlistOracle> {
    oracle: O,
    ttl_ms: u64,
    cache: LruMap<(u64, ClearlistResult)>,
}

impl<O: ClearlistOracle> ClearlistClient<O> {
    pub fn new(oracle: O, ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            oracle,
            ttl_ms: ttl_ms.max(1000),
            cache: LruMap::new(max_entries),
        }
    }

    pub fn check(
        &mut self,
        group_id: &str,
        pubkey_hex: &str,
        now_ms: u64,
    ) -> Result<ClearlistResult, OracleError> {
        let key = cache_key(group_id, pubkey_hex);
        if let Some((exp, v)) = self.cache.get(&key) {
            if *exp > now_ms {
                return Ok(v.clone());
            }
        }
        let fresh = self.oracle.check(group_id, pubkey_hex)?;
        let _ = self
            .cache
            .insert(&key, (now_ms.saturating_add(self.ttl_ms), fresh.clone()));
        Ok(fresh)
    }

    pub fn cached(&self) -> usize {
        self.cache.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Clearlist(String),
    Dark(String),
}

impl Visibility {
    /// From `order.body.visibility`. A CLEARLIST or DARK order without a non-empty
    /// string `groupId` is `None` (malformed), never treated as unrestricted: the
    /// legacy block skipped enforcement when `groupId` was absent.
    pub fn from_order(order: &Value) -> Option<Visibility> {
        let vis = order.get("body")?.get("visibility")?;
        let group = || {
            vis.get("groupId")
                .and_then(Value::as_str)
                .filter(|g| !g.is_empty())
                .map(str::to_owned)
        };
        match vis.get("kind")?.as_str()? {
            "PUBLIC" => Some(Visibility::Public),
            "CLEARLIST" => group().map(Visibility::Clearlist),
            "DARK" => group().map(Visibility::Dark),
            _ => None,
        }
    }

    pub fn group(&self) -> Option<&str> {
        match self {
            Visibility::Public => None,
            Visibility::Clearlist(g) | Visibility::Dark(g) => Some(g),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClearlistDecision {
    Allow,
    Deny {
        code: &'static str,
        msg: &'static str,
    },
}

/// What the oracle said, as seen by the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OracleView {
    /// No client configured (enforce set without a URL).
    NotConfigured,
    Answer(bool),
    Down,
}

/// Pure authorization predicate. Public orders and `enforce = false` always pass;
/// a restricted order passes only on an affirmative answer, or when the operator chose
/// `open` and the oracle was missing or down. A negative answer is never overridden.
pub fn decide(
    enforce: bool,
    fail: FailMode,
    visibility: &Visibility,
    oracle: &OracleView,
) -> ClearlistDecision {
    if !enforce || visibility.group().is_none() {
        return ClearlistDecision::Allow;
    }
    match oracle {
        OracleView::Answer(true) => ClearlistDecision::Allow,
        OracleView::Answer(false) => ClearlistDecision::Deny {
            code: "NOT_CLEARLISTED",
            msg: "not clearlisted",
        },
        OracleView::NotConfigured => match fail {
            FailMode::Open => ClearlistDecision::Allow,
            FailMode::Closed => ClearlistDecision::Deny {
                code: "CLEARLIST_CONFIG",
                msg: "CLEARLIST_URL not configured",
            },
        },
        OracleView::Down => match fail {
            FailMode::Open => ClearlistDecision::Allow,
            FailMode::Closed => ClearlistDecision::Deny {
                code: "CLEARLIST_DOWN",
                msg: "clearlist oracle unavailable",
            },
        },
    }
}

impl<T: ClearlistOracle + ?Sized> ClearlistOracle for Box<T> {
    fn check(&mut self, group_id: &str, pubkey_hex: &str) -> Result<ClearlistResult, OracleError> {
        (**self).check(group_id, pubkey_hex)
    }
}
