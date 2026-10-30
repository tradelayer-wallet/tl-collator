//! `ServerConfig`: listener / TLS / ws path validation, fail-closed.
mod common;
use common::*;
use std::net::IpAddr;
use tl_collator_service::config::{Config, Env};
use tl_collator_service::server::*;

fn env(extra: &[(&str, &str)]) -> Env {
    env_with(extra)
}

fn from(extra: &[(&str, &str)]) -> Result<ServerConfig, String> {
    let e = env(extra);
    let cfg = Config::from_env(&e).map_err(|x| x.to_string())?;
    ServerConfig::from_config(&cfg, &e).map_err(|x| x.to_string())
}

fn base() -> (Config, Env) {
    let e = env(&[]);
    (Config::from_env(&e).unwrap(), e)
}

#[test]
fn defaults_are_loopback_plain_and_describe_the_listener() {
    let s = from(&[]).unwrap();
    assert_eq!(s.bind, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(s.port, 8787);
    assert_eq!(s.scheme(), Scheme::Plain);
    assert_eq!(s.bind_addr(), "127.0.0.1:8787");
    assert_eq!(s.ws_url(), "ws://127.0.0.1:8787/ws");
    assert_eq!(s.scheme().http(), "http");
    assert_eq!(s.max_msg_bytes, 1_048_576);
    assert!(s.tls.is_none());
    assert!(s.ice_servers.is_array());
}

#[test]
fn tls_needs_both_files_and_enables_https_and_wss() {
    let s = from(&[
        ("TLS_KEY_PATH", "/etc/tl/key.pem"),
        ("TLS_CERT_PATH", "/etc/tl/cert.pem"),
        ("TL_COLLATOR_BIND", "203.0.113.7"),
        ("PORT", "8443"),
        ("WS_PATH", "/signal"),
    ])
    .unwrap();
    assert_eq!(s.scheme(), Scheme::Tls);
    assert_eq!(s.scheme().http(), "https");
    assert_eq!(s.ws_url(), "wss://203.0.113.7:8443/signal");
    assert_eq!(s.tls.as_ref().unwrap().cert_path, "/etc/tl/cert.pem");

    // The env loader already refuses half a pair; a hand-built Config is refused here too.
    assert!(from(&[("TLS_KEY_PATH", "/k")]).is_err());
    let (mut cfg, e) = base();
    cfg.tls_key_path = Some("/k".into());
    assert!(ServerConfig::from_config(&cfg, &e).is_err());
    cfg.tls_key_path = None;
    cfg.tls_cert_path = Some("/c".into());
    assert!(ServerConfig::from_config(&cfg, &e).is_err());
    // key == cert, empty and control-character paths
    for (k, c) in [
        ("/same", "/same"),
        ("", "/c"),
        ("/k", "/c\n"),
        ("/k\u{0}", "/c"),
    ] {
        let (mut cfg, e) = base();
        cfg.tls_key_path = Some(k.into());
        cfg.tls_cert_path = Some(c.into());
        assert!(ServerConfig::from_config(&cfg, &e).is_err(), "{k:?} {c:?}");
    }
}

#[test]
fn bind_policy_is_fail_closed() {
    // Legacy bound 0.0.0.0 plaintext unconditionally.
    assert!(from(&[("TL_COLLATOR_BIND", "0.0.0.0")]).is_err());
    assert!(from(&[("TL_COLLATOR_BIND", "203.0.113.7")]).is_err());
    assert!(from(&[("TL_COLLATOR_BIND", "::")]).is_err());
    let s = from(&[
        ("TL_COLLATOR_BIND", "0.0.0.0"),
        ("TL_COLLATOR_ALLOW_PLAINTEXT", "1"),
    ])
    .unwrap();
    assert_eq!(s.bind_addr(), "0.0.0.0:8787");
    assert!(s.allow_plaintext_public);
    // TLS makes a public bind acceptable without the acknowledgment.
    assert!(from(&[
        ("TL_COLLATOR_BIND", "0.0.0.0"),
        ("TLS_KEY_PATH", "/k"),
        ("TLS_CERT_PATH", "/c"),
    ])
    .is_ok());
    // IPv6 loopback and brackets.
    let s = from(&[("TL_COLLATOR_BIND", "::1")]).unwrap();
    assert_eq!(s.bind_addr(), "[::1]:8787");
    assert_eq!(s.ws_url(), "ws://[::1]:8787/ws");
    // Garbage, hostnames, octal-looking octets, multicast, broadcast.
    for bad in [
        "localhost",
        "999.1.1.1",
        "127.0.0.01",
        "127.0.0.1:80",
        "1.2.3",
        " 127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "ff02::1",
    ] {
        assert!(from(&[("TL_COLLATOR_BIND", bad)]).is_err(), "{bad}");
    }
    // The acknowledgment is a strict flag.
    assert!(from(&[("TL_COLLATOR_ALLOW_PLAINTEXT", "yes")]).is_err());
    assert!(from(&[("TL_COLLATOR_ALLOW_PLAINTEXT", "0")]).is_ok());
}

#[test]
fn ws_path_is_plain_and_does_not_shadow_http_routes() {
    for ok in [
        "/ws",
        "/signal/v1",
        "/a-b_c.d~e",
        "/rpcx",
        "/healthz",
        "/tlx",
    ] {
        let (mut cfg, e) = base();
        cfg.ws_path = ok.into();
        assert!(ServerConfig::from_config(&cfg, &e).is_ok(), "{ok}");
    }
    for bad in [
        "/",
        "",
        "ws",
        "/a//b",
        "/a/../b",
        "/a/./b",
        "/a b",
        "/%2e%2e",
        "/ws?x=1",
        "/ws#f",
        "/ü",
        "/health",
        "/health/x",
        "/manifest",
        "/rpc",
        "/rpc/route",
        "/attestation/ip",
        "/relayer/rpc/x",
        "/tl_getinfo",
        "/chain/info",
        "/address/balance/x",
        "/tx/sendTx",
        "/token/list",
    ] {
        let (mut cfg, e) = base();
        cfg.ws_path = bad.into();
        assert!(ServerConfig::from_config(&cfg, &e).is_err(), "{bad:?}");
    }
    let (mut cfg, e) = base();
    cfg.ws_path = format!("/{}", "a".repeat(300));
    assert!(ServerConfig::from_config(&cfg, &e).is_err());
}

#[test]
fn port_message_limit_and_ice_servers_are_rechecked() {
    let (cfg0, e) = base();
    let mut cfg = cfg0.clone();
    cfg.port = 0;
    assert!(ServerConfig::from_config(&cfg, &e).is_err());
    for bad in [0usize, 1023, 1_048_577, usize::MAX] {
        let mut cfg = cfg0.clone();
        cfg.max_msg_bytes = bad;
        assert!(ServerConfig::from_config(&cfg, &e).is_err(), "{bad}");
    }
    for ok in [1024usize, 1_048_576] {
        let mut cfg = cfg0.clone();
        cfg.max_msg_bytes = ok;
        assert!(ServerConfig::from_config(&cfg, &e).is_ok(), "{ok}");
    }
    let mut cfg = cfg0.clone();
    cfg.ice_servers = serde_json::json!([]);
    assert!(ServerConfig::from_config(&cfg, &e).is_err());
    cfg.ice_servers = serde_json::json!("stun:x");
    assert!(ServerConfig::from_config(&cfg, &e).is_err());
    // Values the env loader refuses never reach the server layer.
    assert!(from(&[("PORT", "0")]).is_err());
    assert!(from(&[("PORT", "70000")]).is_err());
    assert!(from(&[("MAX_MSG_BYTES", "5")]).is_err());
}

#[test]
fn hand_built_values_are_validated_too() {
    let mut s = from(&[]).unwrap();
    s.validate().unwrap();
    s.bind = "239.1.1.1".parse().unwrap();
    assert!(s.validate().is_err());
    s.bind = "127.0.0.1".parse().unwrap();
    s.tls = Some(TlsFiles {
        key_path: "/k".into(),
        cert_path: "/k".into(),
    });
    assert!(s.validate().is_err());
}
