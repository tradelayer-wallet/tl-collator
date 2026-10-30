use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use tl_collator_wire::{canonical_json, sha256_hex};
use tl_rpc_router::{
    normalize_method, refusal, Error, Failure, Limits, Policy, ProviderPin, Request, Router,
    SessionId, DOMAIN,
};

const COLLATOR: &str = "collator-test";
const SERVICE: &str = "tl";
const NETWORK: &str = "ltc-testnet";

fn secret(n: u8) -> SecretKey {
    SecretKey::from_slice(&[n; 32]).expect("synthetic key")
}

fn pubhex(n: u8) -> String {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &secret(n))
        .serialize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn pin(node: &str, n: u8, methods: &[&str]) -> ProviderPin {
    ProviderPin {
        node_id: node.into(),
        public_key: pubhex(n),
        methods: methods.iter().map(|m| m.to_string()).collect(),
    }
}

fn policy() -> Policy {
    Policy::new(
        COLLATOR,
        SERVICE,
        NETWORK,
        vec![
            pin("node-a", 1, &["getblockcount", "tl_getbalance"]),
            pin("node-b", 2, &["getblockcount"]),
        ],
    )
    .expect("policy")
}

fn router() -> Router {
    Router::new(policy(), Limits::default(), [7; 32]).expect("router")
}

fn proof_with(fields: Value, n: u8) -> String {
    let canonical = canonical_json(&fields).expect("canonical");
    let digest = sha256_hex(&canonical);
    let mut bytes = [0u8; 32];
    for (i, pair) in digest.as_bytes().chunks_exact(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa(&Message::from_digest(bytes), &secret(n));
    let sig_hex: String = sig
        .serialize_compact()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut full = fields;
    full["sigProvider"] = json!(sig_hex);
    canonical_json(&full).expect("canonical proof")
}

fn proof(node: &str, n: u8, nonce: &str, methods: &[&str]) -> String {
    proof_with(
        json!({
            "domain": DOMAIN,
            "v": 1,
            "collatorId": COLLATOR,
            "service": SERVICE,
            "network": NETWORK,
            "nodeId": node,
            "challenge": nonce,
            "methods": methods,
        }),
        n,
    )
}

fn provider(r: &mut Router, node: &str, n: u8, methods: &[&str], now: u64) -> SessionId {
    let s = r.open_session(now).unwrap();
    let nonce = r.challenge(&s, now).unwrap();
    r.authenticate(&s, &proof(node, n, &nonce, methods), now)
        .unwrap();
    s
}

fn request(id: &str, method: &str) -> Request {
    Request {
        id: id.into(),
        service: SERVICE.into(),
        network: NETWORK.into(),
        method: method.into(),
        params_json: "[]".into(),
        preferred_provider: None,
        timeout_ms: 5_000,
    }
}

fn ok_body(token: &str) -> String {
    json!({"id": token, "ok": true, "result": 42}).to_string()
}

#[test]
fn routes_and_restores_caller_id_and_pinned_provider() {
    let mut r = router();
    let p = provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    let d = r
        .route(&q, request("caller-1", "getblockcount"), 11)
        .unwrap();
    assert_eq!(d.provider, p);
    assert_eq!(d.provider_node_id, "node-a");
    assert_ne!(d.token, "caller-1");
    let body = json!({"id": d.token, "ok": true, "result": 7, "providerNodeId": "spoofed"});
    let c = r.settle(&p, &d.token, &body.to_string(), 12).unwrap();
    assert_eq!(c.requester, q);
    let v = c.result.unwrap();
    assert_eq!(v["id"], "caller-1");
    assert_eq!(v["providerNodeId"], "node-a");
    assert_eq!(v["result"], 7);
    assert_eq!(r.pending_count(), 0);
}

#[test]
fn response_from_non_provider_session_is_refused_and_kept_pending() {
    // Legacy collator settled RPC_RES by id from any session (src/index.ts settleRpcResponse).
    let mut r = router();
    let p = provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    let attacker = r.open_session(10).unwrap();
    let d = r.route(&q, request("c", "getblockcount"), 11).unwrap();
    assert_eq!(
        r.settle(&attacker, &d.token, &ok_body(&d.token), 12)
            .unwrap_err(),
        Error::WrongProvider
    );
    assert_eq!(
        r.settle(&q, &d.token, &ok_body(&d.token), 12).unwrap_err(),
        Error::WrongProvider
    );
    // A wrong sender cannot even force the timeout path.
    assert_eq!(
        r.settle(&attacker, &d.token, &ok_body(&d.token), 1_000_000)
            .unwrap_err(),
        Error::WrongProvider
    );
    assert_eq!(r.pending_count(), 1);
    assert!(r
        .settle(&p, &d.token, &ok_body(&d.token), 1_000_000)
        .is_ok());
}

#[test]
fn method_is_normalized_like_legacy_collator() {
    assert_eq!(normalize_method("  GetBlockCount \n"), "getblockcount");
    let mut r = router();
    provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    let d = r.route(&q, request("c", " GETBLOCKCOUNT "), 11).unwrap();
    assert_eq!(d.method, "getblockcount");
}

#[test]
fn unadvertised_or_unpinned_methods_are_refused() {
    let mut r = router();
    provider(&mut r, "node-b", 2, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    assert_eq!(
        r.route(&q, request("c", "tl_getbalance"), 11).unwrap_err(),
        Error::NoProvider
    );
    // node-b's pin does not approve tl_getbalance.
    let s = r.open_session(12).unwrap();
    let nonce = r.challenge(&s, 12).unwrap();
    assert_eq!(
        r.authenticate(
            &s,
            &proof("node-b", 2, &nonce, &["getblockcount", "tl_getbalance"]),
            12
        )
        .unwrap_err(),
        Error::Unauthorized
    );
}

#[test]
fn bad_signature_consumes_the_challenge() {
    let mut r = router();
    let s = r.open_session(10).unwrap();
    let nonce = r.challenge(&s, 10).unwrap();
    // Signed with node-b's key but claims node-a.
    let forged = proof("node-a", 2, &nonce, &["getblockcount"]);
    assert_eq!(
        r.authenticate(&s, &forged, 11).unwrap_err(),
        Error::Unauthorized
    );
    let good = proof("node-a", 1, &nonce, &["getblockcount"]);
    assert_eq!(
        r.authenticate(&s, &good, 11).unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(r.advertised_node(&s, 11), None);
}

#[test]
fn proofs_bound_to_other_contexts_are_refused() {
    let base = |nonce: &str| {
        json!({
            "domain": DOMAIN, "v": 1, "collatorId": COLLATOR, "service": SERVICE,
            "network": NETWORK, "nodeId": "node-a", "challenge": nonce, "methods": ["getblockcount"],
        })
    };
    for (field, value) in [
        ("collatorId", json!("other-collator")),
        ("network", json!("ltc-mainnet")),
        ("domain", json!("TradeLayer/other/v1")),
        ("v", json!(2)),
        ("service", json!("btc")),
    ] {
        let mut r = router();
        let s = r.open_session(10).unwrap();
        let nonce = r.challenge(&s, 10).unwrap();
        let mut f = base(&nonce);
        f[field] = value;
        assert_eq!(
            r.authenticate(&s, &proof_with(f, 1), 11).unwrap_err(),
            Error::Unauthorized,
            "{field}"
        );
    }
    // A proof for another session's challenge (replay) is refused.
    let mut r = router();
    let s1 = r.open_session(10).unwrap();
    let s2 = r.open_session(10).unwrap();
    let n1 = r.challenge(&s1, 10).unwrap();
    r.challenge(&s2, 10).unwrap();
    let p = proof("node-a", 1, &n1, &["getblockcount"]);
    assert_eq!(
        r.authenticate(&s2, &p, 11).unwrap_err(),
        Error::Unauthorized
    );
    // Extra field is refused even if signed.
    let mut r = router();
    let s = r.open_session(10).unwrap();
    let nonce = r.challenge(&s, 10).unwrap();
    let mut f = base(&nonce);
    f["extra"] = json!(1);
    assert_eq!(
        r.authenticate(&s, &proof_with(f, 1), 11).unwrap_err(),
        Error::Unauthorized
    );
}

#[test]
fn expired_challenge_is_refused() {
    let mut r = router();
    let s = r.open_session(10).unwrap();
    let nonce = r.challenge(&s, 10).unwrap();
    let p = proof("node-a", 1, &nonce, &["getblockcount"]);
    assert_eq!(
        r.authenticate(&s, &p, 10 + Limits::default().challenge_ms)
            .unwrap_err(),
        Error::Expired
    );
}

#[test]
fn one_live_session_per_node() {
    let mut r = router();
    provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let s = r.open_session(11).unwrap();
    let nonce = r.challenge(&s, 11).unwrap();
    assert_eq!(
        r.authenticate(&s, &proof("node-a", 1, &nonce, &["getblockcount"]), 11)
            .unwrap_err(),
        Error::Unauthorized
    );
}

#[test]
fn reauthentication_cannot_switch_node_identity() {
    let mut r = router();
    let s = provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let nonce = r.challenge(&s, 11).unwrap();
    assert_eq!(
        r.authenticate(&s, &proof("node-b", 2, &nonce, &["getblockcount"]), 11)
            .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(r.advertised_node(&s, 11), None);
}

#[test]
fn timeouts_and_peer_close_complete_with_legacy_codes() {
    let mut r = router();
    let p = provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    r.route(&q, request("t1", "getblockcount"), 11).unwrap();
    assert!(r.expire(5_010).unwrap().is_empty());
    let done = r.expire(5_011).unwrap();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].result, Err(Failure::Timeout));
    assert_eq!(done[0].response()["error"]["code"], "RPC_TIMEOUT");
    assert_eq!(done[0].response()["id"], "t1");

    r.route(&q, request("t2", "getblockcount"), 6_000).unwrap();
    let closed = r.close_session(&p, 6_001).unwrap();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].response()["error"]["code"], "RPC_PEER_CLOSED");
    assert_eq!(r.pending_count(), 0);
    assert_eq!(
        r.route(&q, request("t3", "getblockcount"), 6_002)
            .unwrap_err(),
        Error::NoProvider
    );
    assert_eq!(
        refusal("t3", &Error::NoProvider)["error"]["code"],
        "NO_RPC_PROVIDER"
    );
}

#[test]
fn settle_at_deadline_is_a_timeout() {
    let mut r = router();
    let p = provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    let d = r.route(&q, request("c", "getblockcount"), 10).unwrap();
    let c = r.settle(&p, &d.token, &ok_body(&d.token), 5_010).unwrap();
    assert_eq!(c.result, Err(Failure::Timeout));
}

#[test]
fn per_requester_per_provider_and_global_caps() {
    let limits = Limits {
        pending: 3,
        per_requester: 2,
        per_provider: 3,
        ..Limits::default()
    };
    let mut r = Router::new(policy(), limits, [9; 32]).unwrap();
    provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q1 = r.open_session(10).unwrap();
    let q2 = r.open_session(10).unwrap();
    r.route(&q1, request("a", "getblockcount"), 11).unwrap();
    r.route(&q1, request("b", "getblockcount"), 11).unwrap();
    assert_eq!(
        r.route(&q1, request("c", "getblockcount"), 11).unwrap_err(),
        Error::Overloaded
    );
    r.route(&q2, request("d", "getblockcount"), 11).unwrap();
    assert_eq!(
        r.route(&q2, request("e", "getblockcount"), 11).unwrap_err(),
        Error::Overloaded
    );

    let limits = Limits {
        per_provider: 1,
        ..Limits::default()
    };
    let mut r = Router::new(policy(), limits, [9; 32]).unwrap();
    provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    r.route(&q, request("a", "getblockcount"), 11).unwrap();
    assert_eq!(
        r.route(&q, request("b", "getblockcount"), 11).unwrap_err(),
        Error::NoProvider
    );
}

#[test]
fn session_capacity_is_bounded() {
    let limits = Limits {
        sessions: 2,
        ..Limits::default()
    };
    let mut r = Router::new(policy(), limits, [9; 32]).unwrap();
    r.open_session(1).unwrap();
    let s = r.open_session(1).unwrap();
    assert_eq!(r.open_session(1).unwrap_err(), Error::Capacity);
    r.close_session(&s, 2).unwrap();
    assert!(r.open_session(3).is_ok());
}

#[test]
fn backwards_clock_closes_admission_permanently() {
    let mut r = router();
    r.open_session(100).unwrap();
    assert_eq!(r.open_session(99).unwrap_err(), Error::Clock);
    assert_eq!(r.open_session(200).unwrap_err(), Error::Clock);
    let mut r = router();
    assert_eq!(r.open_session(u64::MAX).unwrap_err(), Error::Clock);
}

#[test]
fn malformed_responses_do_not_settle() {
    let mut r = router();
    let p = provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    let d = r.route(&q, request("c", "getblockcount"), 11).unwrap();
    let t = d.token.clone();
    let cases = [
        json!({"id": "c", "ok": true, "result": 1}).to_string(),
        json!({"id": t, "ok": true}).to_string(),
        json!({"id": t, "ok": true, "result": 1, "error": {"message": "x"}}).to_string(),
        json!({"id": t, "ok": false, "error": {"code": "x"}}).to_string(),
        json!({"id": t, "ok": false, "result": 1, "error": {"message": "x"}}).to_string(),
        json!({"id": t, "ok": "true", "result": 1}).to_string(),
        json!({"id": t, "ok": true, "result": 1, "extra": 1}).to_string(),
        json!([1, 2]).to_string(),
        "{not json".to_string(),
        json!({"id": t, "ok": true, "result": "x".repeat(70_000)}).to_string(),
    ];
    for body in cases {
        assert!(r.settle(&p, &t, &body, 12).is_err(), "{body:.80}");
        assert_eq!(r.pending_count(), 1);
    }
    let failure = json!({"id": t, "ok": false, "error": {"code": "E", "message": "boom"}});
    let c = r.settle(&p, &t, &failure.to_string(), 12).unwrap();
    assert_eq!(c.result.unwrap()["error"]["message"], "boom");
}

#[test]
fn round_robin_between_providers_and_preference() {
    let mut r = router();
    provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    provider(&mut r, "node-b", 2, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    let nodes: Vec<String> = (0..4)
        .map(|i| {
            r.route(&q, request(&format!("c{i}"), "getblockcount"), 11)
                .unwrap()
                .provider_node_id
        })
        .collect();
    assert_eq!(nodes, ["node-a", "node-b", "node-a", "node-b"]);
    let mut pref = request("p", "getblockcount");
    pref.preferred_provider = Some("node-b".into());
    assert_eq!(r.route(&q, pref, 11).unwrap().provider_node_id, "node-b");
    let mut bad = request("p2", "getblockcount");
    bad.preferred_provider = Some("node c".into());
    assert_eq!(r.route(&q, bad, 11).unwrap_err(), Error::Invalid("request"));
}

#[test]
fn requester_never_serves_itself_and_expired_adverts_are_skipped() {
    let mut r = router();
    let p = provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    assert_eq!(
        r.route(&p, request("self", "getblockcount"), 11)
            .unwrap_err(),
        Error::NoProvider
    );
    let q = r.open_session(11).unwrap();
    let expiry = 10 + Limits::default().advertisement_ms;
    assert_eq!(
        r.route(&q, request("late", "getblockcount"), expiry)
            .unwrap_err(),
        Error::NoProvider
    );
}

#[test]
fn malformed_requests_are_refused() {
    let mut r = router();
    provider(&mut r, "node-a", 1, &["getblockcount"], 10);
    let q = r.open_session(10).unwrap();
    let mut cases = Vec::new();
    let mut x = request("", "getblockcount");
    cases.push(x.clone());
    x = request("a\nb", "getblockcount");
    cases.push(x.clone());
    x = request("ok", "getblockcount");
    x.network = "ltc-mainnet".into();
    cases.push(x.clone());
    x = request("ok", "getblockcount");
    x.params_json = "{bad".into();
    cases.push(x.clone());
    x = request("ok", "getblockcount");
    x.timeout_ms = 0;
    cases.push(x.clone());
    x = request("ok", "getblockcount");
    x.timeout_ms = 12_001;
    cases.push(x.clone());
    x = request("ok", "get block");
    cases.push(x.clone());
    x = request("ok", "getblockcount");
    x.params_json = format!("\"{}\"", "a".repeat(70_000));
    cases.push(x);
    for c in cases {
        assert_eq!(r.route(&q, c, 11).unwrap_err(), Error::Invalid("request"));
    }
    let ghost = {
        // Same counter, different boot secret: a handle never minted here.
        let mut other = Router::new(policy(), Limits::default(), [3; 32]).unwrap();
        other.open_session(1).unwrap()
    };
    assert_eq!(
        r.route(&ghost, request("ok", "getblockcount"), 11)
            .unwrap_err(),
        Error::UnknownSession
    );
}

#[test]
fn configuration_is_validated() {
    assert!(Policy::new(COLLATOR, SERVICE, NETWORK, vec![]).is_err());
    assert!(Policy::new(
        COLLATOR,
        SERVICE,
        NETWORK,
        vec![pin("a", 1, &["x"]), pin("b", 1, &["x"])]
    )
    .is_err());
    assert!(Policy::new(COLLATOR, SERVICE, NETWORK, vec![pin("a", 1, &["b", "a"])]).is_err());
    assert!(Policy::new(COLLATOR, SERVICE, NETWORK, vec![pin("a", 1, &["A"])]).is_err());
    assert!(Policy::new("bad id", SERVICE, NETWORK, vec![pin("a", 1, &["x"])]).is_err());
    let mut p = pin("a", 1, &["x"]);
    p.public_key = p.public_key.to_uppercase();
    assert!(Policy::new(COLLATOR, SERVICE, NETWORK, vec![p]).is_err());
    assert!(Router::new(policy(), Limits::default(), [0; 32]).is_err());
    for limits in [
        Limits {
            sessions: 0,
            ..Limits::default()
        },
        Limits {
            per_requester: 2000,
            ..Limits::default()
        },
        Limits {
            request_ms: 120_001,
            ..Limits::default()
        },
        Limits {
            challenge_ms: 0,
            ..Limits::default()
        },
    ] {
        assert!(Router::new(policy(), limits, [1; 32]).is_err());
    }
}

#[test]
fn tokens_are_distinct_per_boot_secret() {
    let mut a = router();
    let mut b = Router::new(policy(), Limits::default(), [8; 32]).unwrap();
    let sa = a.open_session(1).unwrap();
    let sb = b.open_session(1).unwrap();
    assert_ne!(sa, sb);
    assert_eq!(sa.as_str().len(), 64);
    let sa2 = a.open_session(1).unwrap();
    assert_ne!(sa, sa2);
}
