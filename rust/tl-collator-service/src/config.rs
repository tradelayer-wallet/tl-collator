//! Validated service configuration (port of `src/config.ts` plus the env reads in
//! `src/index.ts`). The host passes the environment as a map; nothing here touches
//! the process environment or the file system. Every malformed value is an error:
//! the legacy loader silently replaced garbage with defaults (`parseInt` prefixes,
//! `NaN` fall-through, unknown modes mapped to `off`).
use serde_json::Value;
use std::collections::BTreeMap;
use tl_collator_wire::MAX_INPUT_BYTES;

pub type Env = BTreeMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub key: String,
    pub reason: &'static str,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.key, self.reason)
    }
}
impl std::error::Error for ConfigError {}

fn bad(key: &str, reason: &'static str) -> ConfigError {
    ConfigError {
        key: key.to_owned(),
        reason,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Log,
    Reject,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Log => "log",
            Mode::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailMode {
    Open,
    Closed,
}

impl FailMode {
    pub fn as_str(self) -> &'static str {
        match self {
            FailMode::Open => "open",
            FailMode::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Production,
    Development,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub ws_path: String,
    pub data_dir: String,
    pub tape_path: String,
    pub idx_path: String,
    pub idx_stride: u32,
    pub replay_batch: u32,
    pub collator_key_path: String,
    pub infra_attestations_path: Option<String>,
    pub infra_attestations_json: Option<String>,
    pub max_msg_bytes: usize,
    pub submit_burst: u32,
    pub submit_rate_per_sec: u32,
    /// Per-session budget for every message (new: the legacy limiter covered SUBMIT only).
    pub msg_burst: u32,
    pub msg_rate_per_sec: u32,
    /// Per-session budget for expensive requests: TAPE_SUB, RPC_REQ, RPC_ADVERTISE.
    pub heavy_burst: u32,
    pub heavy_rate_per_sec: u32,
    /// Per remote address, shared by reconnects (SUBMIT) and by HTTP requests.
    pub ip_burst: u32,
    pub ip_rate_per_sec: u32,
    pub clearlist_enforce: bool,
    pub clearlist_url: Option<String>,
    pub clearlist_fail_mode: FailMode,
    pub clearlist_ttl_sec: u32,
    pub name: Option<String>,
    pub operator: Option<String>,
    pub region: Option<String>,
    pub ip_logging: bool,
    pub vpn_filter_mode: Mode,
    pub asn_block_mode: Mode,
    pub asn_blocklist: Vec<u32>,
    pub ip_intel_url: Option<String>,
    pub ip_intel_ttl_sec: u32,
    pub ip_intel_fail_mode: FailMode,
    pub conn_max: usize,
    pub conn_max_per_ip: usize,
    pub tls_key_path: Option<String>,
    pub tls_cert_path: Option<String>,
    pub ice_servers: Value,
    pub seen_orderids_max: usize,
    pub rpc_service: String,
    pub rpc_network: String,
    pub rpc_advert_ttl_ms: u64,
    pub cors_origins: Vec<String>,
    pub environment: Environment,
    pub legacy_proxy_enabled: bool,
    pub legacy_upstream_url: String,
    pub trust_proxy_headers: bool,
}

const MAX_PATH_BYTES: usize = 1024;
const MAX_URL_BYTES: usize = 2048;
const MAX_LABEL: usize = 128;

fn get<'a>(env: &'a Env, key: &str) -> Option<&'a str> {
    env.get(key).map(String::as_str).filter(|v| !v.is_empty())
}

/// First of `keys` that is set (the legacy loader read `SUBMIT_RPS` then `SUBMIT_RATE_PER_SEC`).
fn get_any<'a>(env: &'a Env, keys: &[&'static str]) -> Option<(&'static str, &'a str)> {
    keys.iter().find_map(|k| get(env, k).map(|v| (*k, v)))
}

fn uint(key: &str, text: &str, min: u64, max: u64) -> Result<u64, ConfigError> {
    let t = text.trim();
    if t.is_empty() || t.len() > 18 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(key, "expected a plain non-negative integer"));
    }
    let n: u64 = t
        .parse()
        .map_err(|_| bad(key, "expected a plain non-negative integer"))?;
    if n < min || n > max {
        return Err(bad(key, "integer out of range"));
    }
    Ok(n)
}

fn num_or(
    env: &Env,
    keys: &[&'static str],
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    match get_any(env, keys) {
        None => Ok(default),
        Some((k, v)) => uint(k, v, min, max),
    }
}

fn flag(env: &Env, key: &str) -> Result<bool, ConfigError> {
    match get(env, key) {
        None => Ok(false),
        Some("1") | Some("true") | Some("on") => Ok(true),
        Some("0") | Some("false") | Some("off") => Ok(false),
        Some(_) => Err(bad(key, "expected 1/0, true/false or on/off")),
    }
}

fn mode(env: &Env, key: &str) -> Result<Mode, ConfigError> {
    match get(env, key).map(str::to_ascii_lowercase).as_deref() {
        None | Some("off") => Ok(Mode::Off),
        Some("log") => Ok(Mode::Log),
        Some("reject") => Ok(Mode::Reject),
        Some(_) => Err(bad(key, "expected off, log or reject")),
    }
}

fn fail_mode(env: &Env, key: &str) -> Result<FailMode, ConfigError> {
    match get(env, key) {
        None | Some("closed") => Ok(FailMode::Closed),
        Some("open") => Ok(FailMode::Open),
        Some(_) => Err(bad(key, "expected open or closed")),
    }
}

fn clean_text(key: &str, value: &str, max: usize) -> Result<String, ConfigError> {
    if value.len() > max || value.chars().any(char::is_control) {
        return Err(bad(key, "too long or contains control characters"));
    }
    Ok(value.to_owned())
}

fn opt_text(env: &Env, key: &str, max: usize) -> Result<Option<String>, ConfigError> {
    get(env, key).map(|v| clean_text(key, v, max)).transpose()
}

fn path_text(env: &Env, key: &str) -> Result<Option<String>, ConfigError> {
    get(env, key)
        .map(|v| {
            if v.contains('\0') {
                Err(bad(key, "NUL in path"))
            } else {
                clean_text(key, v, MAX_PATH_BYTES)
            }
        })
        .transpose()
}

/// `http(s)://host[:port][/path]` without credentials, whitespace or control bytes.
pub fn valid_http_url(url: &str) -> bool {
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        r
    } else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    url.len() <= MAX_URL_BYTES
        && !authority.is_empty()
        && !authority.contains('@')
        && !url.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn url_opt(env: &Env, key: &str) -> Result<Option<String>, ConfigError> {
    match get(env, key) {
        None => Ok(None),
        Some(v) if valid_http_url(v) => Ok(Some(v.trim_end_matches('/').to_owned())),
        Some(_) => Err(bad(key, "expected an http(s) URL without credentials")),
    }
}

/// A CORS origin is `scheme://host[:port]` exactly: no path, no wildcard.
pub fn valid_origin(origin: &str) -> bool {
    valid_http_url(origin)
        && !origin.contains('*')
        && !origin
            .split_once("://")
            .map(|(_, rest)| rest.contains(['/', '?', '#']))
            .unwrap_or(true)
}

fn ice(env: &Env) -> Result<Value, ConfigError> {
    let default = r#"[{"urls":["stun:stun.l.google.com:19302","stun:stun1.l.google.com:19302"]}]"#;
    let text = get(env, "ICE_SERVERS_JSON").unwrap_or(default);
    if text.len() > 16 * 1024 {
        return Err(bad("ICE_SERVERS_JSON", "too large"));
    }
    let value: Value =
        serde_json::from_str(text).map_err(|_| bad("ICE_SERVERS_JSON", "invalid JSON"))?;
    let list = value
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 16)
        .ok_or_else(|| bad("ICE_SERVERS_JSON", "expected 1 to 16 servers"))?;
    for server in list {
        let urls_ok = match server.get("urls") {
            Some(Value::String(s)) => !s.is_empty(),
            Some(Value::Array(a)) => {
                !a.is_empty()
                    && a.len() <= 16
                    && a.iter().all(|u| u.as_str().is_some_and(|s| !s.is_empty()))
            }
            _ => false,
        };
        if !urls_ok {
            return Err(bad("ICE_SERVERS_JSON", "each server needs urls"));
        }
    }
    Ok(value)
}

fn ws_path(env: &Env) -> Result<String, ConfigError> {
    let p = get(env, "WS_PATH").unwrap_or("/ws");
    if !p.starts_with('/')
        || p.len() > 256
        || p.chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '?' || c == '#')
    {
        return Err(bad("WS_PATH", "expected an absolute URL path"));
    }
    Ok(p.to_owned())
}

impl Config {
    /// Fails closed. The deployment must name the RPC network (`TL_COLLATOR_RPC_NETWORK`);
    /// `NODE_ENV` must be exactly `development` to relax CORS or enable the legacy proxy.
    pub fn from_env(env: &Env) -> Result<Config, ConfigError> {
        let data_dir = path_text(env, "DATA_DIR")?.unwrap_or_else(|| "./data".to_owned());
        let join = |name: &str| format!("{}/{}", data_dir.trim_end_matches('/'), name);
        let tape_path = path_text(env, "TAPE_PATH")?.unwrap_or_else(|| join("tape.log"));
        let idx_path = path_text(env, "TAPE_INDEX_PATH")?.unwrap_or_else(|| join("tape.idx"));
        let collator_key_path =
            path_text(env, "COLLATOR_KEY_PATH")?.unwrap_or_else(|| join("collator.key"));
        let infra_attestations_path = Some(
            path_text(env, "INFRA_ATTESTATIONS_PATH")?
                .unwrap_or_else(|| join("infra-attestations.json")),
        );
        let infra_attestations_json = match get(env, "INFRA_ATTESTATIONS_JSON") {
            None => None,
            Some(v) if v.len() <= 1 << 20 => Some(v.to_owned()),
            Some(_) => return Err(bad("INFRA_ATTESTATIONS_JSON", "too large")),
        };

        let ip_intel_url = url_opt(env, "IP_INTEL_URL")?;
        let vpn_filter_mode = mode(env, "VPN_FILTER_MODE")?;
        let asn_block_mode = mode(env, "ASN_BLOCK_MODE")?;
        if ip_intel_url.is_none() && (vpn_filter_mode != Mode::Off || asn_block_mode != Mode::Off) {
            // Legacy silently downgraded these to `off`, hiding a disabled filter.
            return Err(bad(
                "VPN_FILTER_MODE/ASN_BLOCK_MODE",
                "enforcement modes need IP_INTEL_URL",
            ));
        }
        let mut asn_blocklist = Vec::new();
        if let Some(list) = get(env, "ASN_BLOCKLIST") {
            for part in list.split(',') {
                let n = uint("ASN_BLOCKLIST", part, 1, u64::from(u32::MAX))?;
                asn_blocklist.push(n as u32);
                if asn_blocklist.len() > 1024 {
                    return Err(bad("ASN_BLOCKLIST", "too many entries"));
                }
            }
        }

        let clearlist_enforce = flag(env, "CLEARLIST_ENFORCE")?;
        let clearlist_url = url_opt(env, "CLEARLIST_URL")?;

        let tls_key_path = path_text(env, "TLS_KEY_PATH")?;
        let tls_cert_path = path_text(env, "TLS_CERT_PATH")?;
        if tls_key_path.is_some() != tls_cert_path.is_some() {
            return Err(bad("TLS_KEY_PATH/TLS_CERT_PATH", "set both or neither"));
        }

        let environment = match get(env, "NODE_ENV").map(str::to_ascii_lowercase).as_deref() {
            Some("development") => Environment::Development,
            _ => Environment::Production,
        };

        let mut cors_origins = Vec::new();
        if let Some(list) = get(env, "TL_COLLATOR_CORS_ORIGINS") {
            for part in list.split(['\n', ',']) {
                let origin = part.trim();
                if origin.is_empty() {
                    continue;
                }
                if !valid_origin(origin) {
                    return Err(bad(
                        "TL_COLLATOR_CORS_ORIGINS",
                        "expected scheme://host[:port] origins without wildcards",
                    ));
                }
                cors_origins.push(origin.to_owned());
                if cors_origins.len() > 64 {
                    return Err(bad("TL_COLLATOR_CORS_ORIGINS", "too many origins"));
                }
            }
        }

        let rpc_service = get(env, "TL_COLLATOR_RPC_SERVICE").unwrap_or("tradelayer.rpc");
        let rpc_service = clean_text("TL_COLLATOR_RPC_SERVICE", rpc_service, MAX_LABEL)?;
        let rpc_network = get(env, "TL_COLLATOR_RPC_NETWORK")
            .ok_or_else(|| bad("TL_COLLATOR_RPC_NETWORK", "required"))?;
        let rpc_network = clean_text("TL_COLLATOR_RPC_NETWORK", rpc_network, MAX_LABEL)?;

        let legacy_proxy_enabled = environment == Environment::Development
            && get(env, "TL_COLLATOR_ENABLE_LEGACY_TL_PROXY") == Some("1");
        let legacy_upstream_url = match get_any(
            env,
            &["TL_RELAY_COMPAT_UPSTREAM_URL", "TL_WALLET_LISTENER_URL"],
        ) {
            None => "http://127.0.0.1:3000".to_owned(),
            Some((k, v)) if valid_http_url(v) => {
                let _ = k;
                v.trim_end_matches('/').to_owned()
            }
            Some((k, _)) => return Err(bad(k, "expected an http(s) URL without credentials")),
        };

        Ok(Config {
            port: num_or(env, &["PORT", "SERVER_PORT"], 8787, 1, 65_535)? as u16,
            ws_path: ws_path(env)?,
            data_dir,
            tape_path,
            idx_path,
            idx_stride: num_or(env, &["TAPE_INDEX_STRIDE"], 1000, 1, 1_000_000)? as u32,
            replay_batch: num_or(env, &["TAPE_REPLAY_BATCH"], 500, 1, 10_000)? as u32,
            collator_key_path,
            infra_attestations_path,
            infra_attestations_json,
            max_msg_bytes: num_or(
                env,
                &["MAX_MSG_BYTES"],
                1_048_576,
                1024,
                MAX_INPUT_BYTES as u64,
            )? as usize,
            submit_burst: num_or(env, &["SUBMIT_BURST"], 10, 1, 10_000)? as u32,
            submit_rate_per_sec: num_or(env, &["SUBMIT_RPS", "SUBMIT_RATE_PER_SEC"], 2, 0, 10_000)?
                as u32,
            msg_burst: num_or(env, &["MSG_BURST"], 200, 1, 100_000)? as u32,
            msg_rate_per_sec: num_or(env, &["MSG_RPS"], 100, 0, 100_000)? as u32,
            heavy_burst: num_or(env, &["HEAVY_BURST"], 20, 1, 10_000)? as u32,
            heavy_rate_per_sec: num_or(env, &["HEAVY_RPS"], 5, 0, 10_000)? as u32,
            ip_burst: num_or(env, &["IP_BURST"], 60, 1, 100_000)? as u32,
            ip_rate_per_sec: num_or(env, &["IP_RPS"], 20, 0, 100_000)? as u32,
            clearlist_enforce,
            clearlist_url,
            clearlist_fail_mode: fail_mode(env, "CLEARLIST_FAIL_MODE")?,
            clearlist_ttl_sec: num_or(env, &["CLEARLIST_TTL_SEC"], 60, 1, 86_400)? as u32,
            name: opt_text(env, "NAME", MAX_LABEL)?,
            operator: opt_text(env, "OPERATOR", MAX_LABEL)?,
            region: opt_text(env, "REGION", MAX_LABEL)?,
            ip_logging: flag(env, "IP_LOGGING")?,
            vpn_filter_mode,
            asn_block_mode,
            asn_blocklist,
            ip_intel_url,
            ip_intel_ttl_sec: num_or(env, &["IP_INTEL_TTL_SEC"], 300, 0, 86_400)? as u32,
            ip_intel_fail_mode: fail_mode(env, "IP_INTEL_FAIL_MODE")?,
            conn_max: num_or(env, &["CONN_MAX"], 1024, 1, 4000)? as usize,
            conn_max_per_ip: num_or(env, &["CONN_MAX_PER_IP"], 16, 1, 100_000)? as usize,
            tls_key_path,
            tls_cert_path,
            ice_servers: ice(env)?,
            seen_orderids_max: num_or(env, &["SEEN_ORDERIDS_MAX"], 100_000, 1, 1_000_000)? as usize,
            rpc_service,
            rpc_network,
            rpc_advert_ttl_ms: num_or(
                env,
                &["TL_COLLATOR_RPC_ADVERT_TTL_MS"],
                45_000,
                15_000,
                60_000,
            )?,
            cors_origins,
            environment,
            legacy_proxy_enabled,
            legacy_upstream_url,
            trust_proxy_headers: flag(env, "TL_COLLATOR_TRUST_PROXY_HEADERS")?,
        })
    }
}
