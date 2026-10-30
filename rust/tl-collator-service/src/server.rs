//! Listener / TLS option validation (port of the server setup in `src/index.ts` 220-227 and
//! 1261-1281, and the TLS fields of `src/config.ts`).
//!
//! This crate opens no socket and reads no key or certificate file: **sockets, TLS and the
//! WebSocket upgrade are host-owned.** `ServerConfig` only decides, fail-closed, whether the
//! options the host is about to use are acceptable, and says exactly what to bind:
//!
//! * `tls_key_path` and `tls_cert_path` are both set (HTTPS/WSS) or both absent (plain
//!   HTTP/WS), and name different files. Legacy served plaintext when only one was set.
//! * The bind address is an explicit IP (default `127.0.0.1`; legacy always `0.0.0.0`).
//!   A non-loopback address without TLS needs `TL_COLLATOR_ALLOW_PLAINTEXT=1`, the operator's
//!   statement that a TLS-terminating proxy or a private network protects the listener.
//! * `ws_path` is a plain path (`[A-Za-z0-9/_.~-]`, no `//`, no `.`/`..` segments) that does
//!   not shadow an HTTP route of the dispatcher.
//! * `max_msg_bytes` (the WebSocket `maxPayload`) is within `1024..=1 MiB`.
use crate::config::{Config, ConfigError, Env};
use serde_json::Value;
use std::net::IpAddr;
use tl_collator_wire::MAX_INPUT_BYTES;

/// HTTP routes served by `Service::handle_http`; the WebSocket path must not shadow them.
pub const RESERVED_PATH_PREFIXES: [&str; 9] = [
    "/health",
    "/manifest",
    "/attestation",
    "/relayer",
    "/rpc",
    "/chain",
    "/address",
    "/tx",
    "/token",
];

/// Open-ended prefixes: `/tl_getinfo`, `/tl_bitvmStatus`, ...
pub const RESERVED_OPEN_PREFIXES: [&str; 1] = ["/tl_"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Plain,
    Tls,
}

impl Scheme {
    pub fn http(self) -> &'static str {
        match self {
            Scheme::Plain => "http",
            Scheme::Tls => "https",
        }
    }
    pub fn ws(self) -> &'static str {
        match self {
            Scheme::Plain => "ws",
            Scheme::Tls => "wss",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsFiles {
    pub key_path: String,
    pub cert_path: String,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub ws_path: String,
    pub max_msg_bytes: usize,
    pub tls: Option<TlsFiles>,
    pub allow_plaintext_public: bool,
    /// Validated `ICE_SERVERS_JSON`, handed to the host's WebRTC stack.
    pub ice_servers: Value,
}

fn bad(key: &str, reason: &'static str) -> ConfigError {
    ConfigError {
        key: key.to_owned(),
        reason,
    }
}

fn plain_path(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= 256
        && !p.contains("//")
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'.' | b'~' | b'-'))
        && !p.split('/').any(|s| s == "." || s == "..")
}

fn file_path(key: &str, p: &str) -> Result<(), ConfigError> {
    if p.is_empty() || p.len() > 1024 || p.contains('\0') || p.chars().any(char::is_control) {
        return Err(bad(key, "expected a file path"));
    }
    Ok(())
}

fn reserved(path: &str) -> bool {
    RESERVED_OPEN_PREFIXES.iter().any(|r| path.starts_with(r))
        || RESERVED_PATH_PREFIXES.iter().any(|r| {
            path == *r
                || path
                    .strip_prefix(r)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

fn env_flag(env: &Env, key: &str) -> Result<bool, ConfigError> {
    match env.get(key).map(String::as_str).filter(|v| !v.is_empty()) {
        None | Some("0") | Some("false") | Some("off") => Ok(false),
        Some("1") | Some("true") | Some("on") => Ok(true),
        Some(_) => Err(bad(key, "expected 1/0, true/false or on/off")),
    }
}

impl ServerConfig {
    /// Build from the validated service `Config` plus the two listener keys
    /// `TL_COLLATOR_BIND` (an IP literal) and `TL_COLLATOR_ALLOW_PLAINTEXT`.
    pub fn from_config(cfg: &Config, env: &Env) -> Result<ServerConfig, ConfigError> {
        let bind: IpAddr = match env
            .get("TL_COLLATOR_BIND")
            .map(String::as_str)
            .filter(|v| !v.is_empty())
        {
            None => IpAddr::from([127, 0, 0, 1]),
            Some(text) => text
                .parse()
                .map_err(|_| bad("TL_COLLATOR_BIND", "expected an IP address literal"))?,
        };
        let tls = match (&cfg.tls_key_path, &cfg.tls_cert_path) {
            (Some(k), Some(c)) => Some(TlsFiles {
                key_path: k.clone(),
                cert_path: c.clone(),
            }),
            (None, None) => None,
            _ => return Err(bad("TLS_KEY_PATH/TLS_CERT_PATH", "set both or neither")),
        };
        let sc = ServerConfig {
            bind,
            port: cfg.port,
            ws_path: cfg.ws_path.clone(),
            max_msg_bytes: cfg.max_msg_bytes,
            tls,
            allow_plaintext_public: env_flag(env, "TL_COLLATOR_ALLOW_PLAINTEXT")?,
            ice_servers: cfg.ice_servers.clone(),
        };
        sc.validate()?;
        Ok(sc)
    }

    /// The checks, also usable on a hand-built value.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(bad("PORT", "port 0 is not a fixed listener"));
        }
        if self.bind.is_multicast() || self.bind == IpAddr::from([255, 255, 255, 255]) {
            return Err(bad(
                "TL_COLLATOR_BIND",
                "multicast/broadcast cannot be bound",
            ));
        }
        if !plain_path(&self.ws_path) {
            return Err(bad(
                "WS_PATH",
                "expected a plain path of [A-Za-z0-9/_.~-] without // or dot segments",
            ));
        }
        if self.ws_path == "/" || reserved(&self.ws_path) {
            return Err(bad("WS_PATH", "shadows an HTTP route"));
        }
        if self.max_msg_bytes < 1024 || self.max_msg_bytes > MAX_INPUT_BYTES {
            return Err(bad("MAX_MSG_BYTES", "outside 1024..=1048576"));
        }
        if let Some(t) = &self.tls {
            file_path("TLS_KEY_PATH", &t.key_path)?;
            file_path("TLS_CERT_PATH", &t.cert_path)?;
            if t.key_path == t.cert_path {
                return Err(bad(
                    "TLS_KEY_PATH/TLS_CERT_PATH",
                    "key and certificate must differ",
                ));
            }
        }
        if self.tls.is_none() && !self.bind.is_loopback() && !self.allow_plaintext_public {
            return Err(bad(
                "TL_COLLATOR_BIND",
                "plaintext on a non-loopback address needs TLS or TL_COLLATOR_ALLOW_PLAINTEXT=1",
            ));
        }
        if self.ice_servers.as_array().is_none_or(|a| a.is_empty()) {
            return Err(bad("ICE_SERVERS_JSON", "expected a non-empty list"));
        }
        Ok(())
    }

    pub fn scheme(&self) -> Scheme {
        if self.tls.is_some() {
            Scheme::Tls
        } else {
            Scheme::Plain
        }
    }

    /// `host:port` the host must bind (IPv6 in brackets).
    pub fn bind_addr(&self) -> String {
        match self.bind {
            IpAddr::V4(a) => format!("{a}:{}", self.port),
            IpAddr::V6(a) => format!("[{a}]:{}", self.port),
        }
    }

    /// The WebSocket URL the legacy startup banner printed (`ws_url`).
    pub fn ws_url(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme().ws(),
            self.bind_addr(),
            self.ws_path
        )
    }
}
