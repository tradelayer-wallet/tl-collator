//! HTTP-facing types, CORS policy and routing table (port of the `server.on('request')`
//! handler, `src/index.ts` 444-909). Pure: the host reads the socket, enforces its own
//! header/body timeouts, calls the reducer and writes the response.
use crate::config::{Config, Environment};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HttpTicket(pub u64);

#[derive(Clone, Debug, Default)]
pub struct Forwarded {
    pub cf_connecting_ip: Option<String>,
    pub x_real_ip: Option<String>,
    pub x_forwarded_for: Option<String>,
    pub x_forwarded_proto: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    /// URL pathname exactly as received (percent-encoded), without query string.
    pub path: String,
    pub origin: Option<String>,
    /// Socket peer address as seen by the host.
    pub peer_ip: String,
    pub forwarded: Forwarded,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    pub fn json(status: u16, cors: &[(String, String)], body: &Value) -> Self {
        let mut headers = cors.to_vec();
        headers.push(("content-type".into(), "application/json".into()));
        Self {
            status,
            headers,
            body: body.to_string(),
        }
    }

    pub fn text(status: u16, cors: &[(String, String)], body: &str) -> Self {
        Self {
            status,
            headers: cors.to_vec(),
            body: body.to_owned(),
        }
    }

    pub fn error(status: u16, cors: &[(String, String)], code: &str, message: &str) -> Self {
        Self::json(
            status,
            cors,
            &json!({"error": {"code": code, "message": message}}),
        )
    }
}

/// An upstream request the host performs against the configured legacy relayer.
#[derive(Clone, Debug, PartialEq)]
pub struct ProxyRequest {
    pub method: String,
    /// Path (already restricted to a safe charset); the host prepends the configured base URL.
    pub path: String,
    pub body: Option<Value>,
    pub headers: Vec<(String, String)>,
}

pub const CORS_METHODS: &str = "GET,POST,OPTIONS";
pub const CORS_HEADERS: &str = "content-type";

pub struct CorsOutcome {
    pub headers: Vec<(String, String)>,
    /// A request whose `Origin` is neither approved nor covered by the development wildcard.
    pub denied: bool,
}

/// Production by default: no `Access-Control-Allow-Origin` unless the origin is listed. The
/// wildcard exists only when `NODE_ENV=development` and the list is empty (the legacy
/// default treated an unset `NODE_ENV` as development).
pub fn cors(origin: Option<&str>, cfg: &Config) -> CorsOutcome {
    let origin = origin.map(str::trim).filter(|o| !o.is_empty());
    let allowed = origin.is_some_and(|o| cfg.cors_origins.iter().any(|c| c == o));
    let wildcard = cfg.environment == Environment::Development && cfg.cors_origins.is_empty();
    let mut headers = Vec::new();
    if allowed {
        if let Some(o) = origin {
            headers.push(("Access-Control-Allow-Origin".to_owned(), o.to_owned()));
            headers.push(("Vary".to_owned(), "Origin".to_owned()));
        }
    } else if wildcard {
        headers.push(("Access-Control-Allow-Origin".to_owned(), "*".to_owned()));
    }
    headers.push((
        "Access-Control-Allow-Methods".to_owned(),
        CORS_METHODS.to_owned(),
    ));
    headers.push((
        "Access-Control-Allow-Headers".to_owned(),
        CORS_HEADERS.to_owned(),
    ));
    CorsOutcome {
        headers,
        denied: origin.is_some() && !allowed && !wildcard,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Health,
    Manifest,
    AttestationIp,
    RpcProviders,
    TlBitvmStatus,
    TlOther(String),
    RpcCompat(String),
    RpcRoute,
    ChainInfo,
    AddressValidate(String),
    AddressBalance(String),
    AddressFaucet(String),
    AddressUtxo(String),
    TxGet(String),
    TokenList,
    TxDecode,
    TxSend,
    ProxyOnly(String),
    TokenGet(String),
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// Malformed percent-encoding or unsafe path text.
    BadPath,
    /// The parameter segment was empty (`what` names it like the legacy 400 text).
    Missing(&'static str),
    /// The parameter is present but not in the accepted charset or length.
    Invalid(&'static str),
}

/// Strict `decodeURIComponent`: `%XX` escapes that form valid UTF-8, nothing else rewritten.
pub fn percent_decode(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}

fn param(
    rest: &str,
    missing: &'static str,
    invalid: &'static str,
    numeric: bool,
) -> Result<String, RouteError> {
    let decoded = percent_decode(rest).ok_or(RouteError::BadPath)?;
    if decoded.is_empty() {
        return Err(RouteError::Missing(missing));
    }
    let ok = token(&decoded, 128)
        && (!numeric || decoded.bytes().all(|b| b.is_ascii_digit()) && decoded.len() <= 15);
    if ok {
        Ok(decoded)
    } else {
        Err(RouteError::Invalid(invalid))
    }
}

/// `^/(?:relayer/)?rpc/([^/]+)$`
fn rpc_segment(path: &str) -> Option<&str> {
    let rest = path
        .strip_prefix("/relayer/rpc/")
        .or_else(|| path.strip_prefix("/rpc/"))?;
    (!rest.is_empty() && !rest.contains('/')).then_some(rest)
}

/// First matching rule wins, in the legacy order.
pub fn route(method: &str, path: &str) -> Result<Route, RouteError> {
    let get = method == "GET";
    let post = method == "POST";
    if get && path == "/health" {
        return Ok(Route::Health);
    }
    if get && path == "/manifest" {
        return Ok(Route::Manifest);
    }
    if path == "/attestation/ip" {
        return Ok(Route::AttestationIp);
    }
    if get && path == "/rpc/providers" {
        return Ok(Route::RpcProviders);
    }
    if path.starts_with("/tl_") {
        if post && path == "/tl_bitvmStatus" {
            return Ok(Route::TlBitvmStatus);
        }
        let safe = path.len() <= 128
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
            && !path.split('/').any(|s| s == ".." || s == ".");
        return if safe {
            Ok(Route::TlOther(path.to_owned()))
        } else {
            Err(RouteError::BadPath)
        };
    }
    if post && path != "/rpc/route" && path != "/rpc/providers" {
        if let Some(seg) = rpc_segment(path) {
            let decoded = percent_decode(seg).ok_or(RouteError::BadPath)?;
            return Ok(Route::RpcCompat(decoded.trim().to_owned()));
        }
    }
    if post && path == "/rpc/route" {
        return Ok(Route::RpcRoute);
    }
    if get && path == "/chain/info" {
        return Ok(Route::ChainInfo);
    }
    if get {
        if let Some(rest) = path.strip_prefix("/address/validate/") {
            return param(rest, "Missing address", "Invalid address", false)
                .map(Route::AddressValidate);
        }
        if let Some(rest) = path.strip_prefix("/address/balance/") {
            return param(rest, "Missing address", "Invalid address", false)
                .map(Route::AddressBalance);
        }
        if let Some(rest) = path.strip_prefix("/address/faucet/") {
            return param(rest, "Missing address", "Invalid address", false)
                .map(Route::AddressFaucet);
        }
    }
    if post {
        if let Some(rest) = path.strip_prefix("/address/utxo/") {
            return param(rest, "Missing address", "Invalid address", false)
                .map(Route::AddressUtxo);
        }
    }
    if get {
        if let Some(rest) = path.strip_prefix("/tx/") {
            return param(rest, "Missing txid", "Invalid txid", false).map(Route::TxGet);
        }
        if path == "/token/list" {
            return Ok(Route::TokenList);
        }
    }
    if post {
        match path {
            "/tx/decode" => return Ok(Route::TxDecode),
            "/tx/sendTx" => return Ok(Route::TxSend),
            "/tx/buildTx"
            | "/tx/buildUnsigned"
            | "/tx/buildunsigned"
            | "/tx/build-unsigned"
            | "/tx/multisig"
            | "/tx/buildTradeTx"
            | "/tx/buildLTCTradeTx"
            | "/tx/finalizePsbt" => return Ok(Route::ProxyOnly(path.to_owned())),
            _ => {}
        }
    }
    if get {
        if let Some(rest) = path.strip_prefix("/token/") {
            return param(rest, "Missing propid", "Invalid propid", true).map(Route::TokenGet);
        }
    }
    Ok(Route::NotFound)
}

/// The caller's address: the socket peer, or (only when the operator declared a trusted
/// reverse proxy) the first of `cf-connecting-ip`, `x-real-ip`, `x-forwarded-for`.
/// The legacy server always trusted those client-controlled headers.
pub fn client_ip(req: &HttpRequest, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers {
        let f = &req.forwarded;
        let pick = |v: &Option<String>| {
            v.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        if let Some(ip) = pick(&f.cf_connecting_ip).or_else(|| pick(&f.x_real_ip)) {
            return ip.chars().take(64).collect();
        }
        if let Some(first) = f
            .x_forwarded_for
            .as_deref()
            .and_then(|x| x.split(',').next())
        {
            let first = first.trim();
            if !first.is_empty() {
                return first.chars().take(64).collect();
            }
        }
    }
    req.peer_ip.chars().take(64).collect()
}

/// Legacy `normalizeCompatParams`: arrays pass through, null/absent is `[]`, otherwise a
/// one-element array.
pub fn compat_params(body: Option<&Value>) -> Vec<Value> {
    match body.and_then(|b| b.get("params")) {
        Some(Value::Array(a)) => a.clone(),
        None | Some(Value::Null) => Vec::new(),
        Some(other) => vec![other.clone()],
    }
}
