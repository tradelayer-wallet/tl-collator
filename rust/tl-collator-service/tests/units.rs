#![allow(clippy::type_complexity)]
mod common;
use common::*;
use serde_json::{json, Value};
use tl_collator_service::audit::{AuditRecord, AuditSink, MemoryAudit};
use tl_collator_service::bitvm::{build_status, Artifacts, BitvmQuery};
use tl_collator_service::clearlist::{
    cache_key, decide, parse_oracle_reply, ClearlistClient, ClearlistDecision, OracleView,
    Visibility,
};
use tl_collator_service::config::{Config, Env, Environment, FailMode, Mode};
use tl_collator_service::http::{
    client_ip, cors, percent_decode, route, Forwarded, Route, RouteError,
};
use tl_collator_service::ipintel::{evaluate, parse_reply, IntelPolicy, IpIntel};
use tl_collator_service::lru::{LruMap, LruSet};
use tl_collator_service::manifest::load_infra_attestations;
use tl_collator_service::ratelimit::{KeyedLimiter, TokenBucket};
use tl_collator_service::wire::{parse_wire, WireError, WireIn};

// ---- ratelimit --------------------------------------------------------------------------

#[test]
fn bucket_burst_refill_and_cap() {
    let mut b = TokenBucket::new(3, 2, 1_000);
    assert!(b.allow(1, 1_000) && b.allow(1, 1_000) && b.allow(1, 1_000));
    assert!(!b.allow(1, 1_000));
    // Two tokens per second: after 500 ms exactly one token.
    assert!(!b.allow(1, 1_499));
    assert!(b.allow(1, 1_500));
    assert!(!b.allow(1, 1_500));
    // A long idle period never exceeds capacity.
    assert_eq!(b.available(), 0);
    assert!(b.allow(1, 10_000_000) && b.allow(1, 10_000_000) && b.allow(1, 10_000_000));
    assert!(!b.allow(1, 10_000_000));
}

#[test]
fn bucket_cost_zero_and_over_capacity_and_backwards_clock() {
    let mut b = TokenBucket::new(2, 1, 5_000);
    assert!(b.allow(0, 5_000));
    assert!(!b.allow(3, 5_000));
    assert!(b.allow(2, 5_000));
    // A clock that goes backwards neither refills nor panics, and does not rewind time.
    assert!(!b.allow(1, 1_000));
    assert!(!b.allow(1, 5_999));
    assert!(b.allow(1, 6_000));
    // Capacity is clamped to at least 1 (legacy Math.max(1, ..)).
    let mut one = TokenBucket::new(0, 0, 0);
    assert!(one.allow(1, 0));
    assert!(!one.allow(1, 1_000_000));
}

#[test]
fn bucket_never_grants_more_than_burst_plus_rate_times_elapsed() {
    // Deterministic pseudo-random schedule; the Lean model proves this bound for all inputs.
    let (cap, rate, t0) = (5_u32, 3_u32, 10_000_u64);
    let mut granted = 0_u64;
    let mut b = TokenBucket::new(cap, rate, t0);
    let (mut now, mut x) = (t0, 777_u64);
    for _ in 0..5_000 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        now += (x >> 33) % 400;
        let cost = 1 + ((x >> 20) % 3) as u32;
        if b.allow(cost, now) {
            granted += u64::from(cost);
        }
        assert!(granted * 1000 <= u64::from(cap) * 1000 + (now - t0) * u64::from(rate));
    }
}

#[test]
fn keyed_limiter_is_bounded_and_per_key() {
    let mut l = KeyedLimiter::new(2, 1, 0);
    assert!(l.allow("a", 1, 0));
    assert!(!l.allow("a", 1, 0));
    assert!(l.allow("b", 1, 0));
    assert!(l.allow("c", 1, 0)); // evicts the oldest key ("a")
    assert_eq!(l.tracked(), 2);
    assert!(l.allow("a", 1, 0)); // evicted keys start over: the memory bound is the cost
}

// ---- lru ----------------------------------------------------------------------------------

#[test]
fn lru_set_evicts_oldest_and_refreshes_on_add() {
    let mut s = LruSet::new(2);
    s.add("a");
    s.add("b");
    assert!(s.has("a")); // has() does not refresh
    s.add("c");
    assert!(!s.has("a") && s.has("b") && s.has("c"));
    s.add("b"); // refresh
    s.add("d");
    assert!(s.has("b") && s.has("d") && !s.has("c"));
    assert_eq!(s.len(), 2);
}

#[test]
fn lru_map_get_refreshes_and_the_empty_key_is_evictable() {
    let mut m: LruMap<u32> = LruMap::new(2);
    m.insert("", 0); // legacy `if (oldest)` skipped eviction when the oldest key was ""
    m.insert("x", 1);
    m.insert("y", 2);
    assert!(!m.contains(""));
    assert_eq!(m.len(), 2);
    assert_eq!(m.get("x"), Some(&1)); // refresh x
    m.insert("z", 3);
    assert_eq!(m.keys_oldest_first(), vec!["x".to_owned(), "z".to_owned()]);
    assert_eq!(m.remove("x"), Some(1));
    assert_eq!(m.peek("z"), Some(&3));
    // Capacity 0 clamps to 1; a replaced value keeps size.
    let mut one: LruMap<u8> = LruMap::new(0);
    one.insert("a", 1);
    one.insert("a", 2);
    assert_eq!((one.len(), one.capacity(), one.peek("a")), (1, 1, Some(&2)));
}

#[test]
fn lru_never_exceeds_capacity() {
    let mut m: LruMap<()> = LruMap::new(7);
    for i in 0..1000 {
        m.insert(&format!("k{}", i % 23), ());
        assert!(m.len() <= 7);
    }
}

// ---- config -------------------------------------------------------------------------------

fn cfg_err(extra: &[(&str, &str)]) -> String {
    Config::from_env(&env_with(extra)).unwrap_err().key
}

#[test]
fn config_defaults_match_the_legacy_loader() {
    let c = Config::from_env(&env_with(&[])).unwrap();
    assert_eq!((c.port, c.ws_path.as_str()), (8787, "/ws"));
    assert_eq!((c.submit_burst, c.submit_rate_per_sec), (10, 2));
    assert_eq!(
        (c.idx_stride, c.replay_batch, c.max_msg_bytes),
        (1000, 500, 1_048_576)
    );
    assert_eq!(c.tape_path, "./data/tape.log");
    assert_eq!(c.seen_orderids_max, 100_000);
    assert_eq!(c.rpc_advert_ttl_ms, 45_000);
    assert_eq!(c.clearlist_fail_mode, FailMode::Closed);
    assert_eq!(
        (c.vpn_filter_mode, c.asn_block_mode),
        (Mode::Off, Mode::Off)
    );
    assert_eq!(c.environment, Environment::Production);
    assert!(!c.legacy_proxy_enabled && !c.ip_logging && !c.clearlist_enforce);
    assert_eq!(c.legacy_upstream_url, "http://127.0.0.1:3000");
    assert!(c.ice_servers[0]["urls"].as_array().unwrap().len() == 2);
}

#[test]
fn config_accepts_legacy_aliases_and_rejects_garbage() {
    let c = Config::from_env(&env_with(&[
        ("SERVER_PORT", "9000"),
        ("SUBMIT_RATE_PER_SEC", "7"),
    ]))
    .unwrap();
    assert_eq!((c.port, c.submit_rate_per_sec), (9000, 7));
    // `SUBMIT_RPS` wins over the old name.
    let c = Config::from_env(&env_with(&[
        ("SUBMIT_RPS", "3"),
        ("SUBMIT_RATE_PER_SEC", "7"),
    ]))
    .unwrap();
    assert_eq!(c.submit_rate_per_sec, 3);
    // Empty means unset (legacy `!v`).
    assert_eq!(
        Config::from_env(&env_with(&[("PORT", "")])).unwrap().port,
        8787
    );

    for (k, v) in [
        ("PORT", "80abc"), // parseInt would have returned 80
        ("PORT", "-1"),
        ("PORT", "0"),
        ("PORT", "70000"),
        ("PORT", "1e3"),
        ("SUBMIT_BURST", "NaN"), // legacy fell back to the default silently
        ("SUBMIT_BURST", "0"),
        ("SEEN_ORDERIDS_MAX", "abc"), // legacy: NaN capacity = unbounded set
        ("MAX_MSG_BYTES", "99999999"),
        ("TAPE_REPLAY_BATCH", "0"),
        ("CONN_MAX", "-5"),
        ("CLEARLIST_ENFORCE", "yes"),
        ("CLEARLIST_FAIL_MODE", "maybe"),
        ("IP_LOGGING", "enabled"),
        ("ASN_BLOCKLIST", "123,abc"),
        ("ASN_BLOCKLIST", "0"),
        ("CLEARLIST_URL", "ftp://oracle"),
        ("CLEARLIST_URL", "https://user:pw@oracle.example"),
        ("WS_PATH", "ws"),
        ("WS_PATH", "/a b"),
        ("ICE_SERVERS_JSON", "not json"),
        ("ICE_SERVERS_JSON", "[]"),
        ("ICE_SERVERS_JSON", r#"[{"nourls":1}]"#),
        ("TL_COLLATOR_CORS_ORIGINS", "*"),
        ("TL_COLLATOR_CORS_ORIGINS", "https://a.example/path"),
        ("TL_COLLATOR_RPC_ADVERT_TTL_MS", "100"),
        ("NAME", "bad\nname"),
    ] {
        assert!(!cfg_err(&[(k, v)]).is_empty(), "{k}={v}");
        assert!(
            Config::from_env(&env_with(&[(k, v)])).is_err(),
            "{k}={v} must fail"
        );
    }
}

#[test]
fn config_fails_closed_on_inconsistent_enforcement_settings() {
    // Enforcement modes need an intel URL: legacy silently set them to `off`.
    assert!(Config::from_env(&env_with(&[("VPN_FILTER_MODE", "reject")])).is_err());
    assert!(Config::from_env(&env_with(&[("ASN_BLOCK_MODE", "log")])).is_err());
    let c = Config::from_env(&env_with(&[
        ("IP_INTEL_URL", "https://intel.example/"),
        ("VPN_FILTER_MODE", "REJECT"),
        ("ASN_BLOCKLIST", "64500, 64501"),
    ]))
    .unwrap();
    assert_eq!(c.vpn_filter_mode, Mode::Reject);
    assert_eq!(c.asn_blocklist, vec![64500, 64501]);
    assert_eq!(c.ip_intel_url.as_deref(), Some("https://intel.example"));
    // Half a TLS pair would have served plaintext.
    assert!(Config::from_env(&env_with(&[("TLS_KEY_PATH", "/k")])).is_err());
    assert!(Config::from_env(&env_with(&[
        ("TLS_KEY_PATH", "/k"),
        ("TLS_CERT_PATH", "/c")
    ]))
    .is_ok());
    // The RPC network must be named.
    assert!(Config::from_env(&Env::new()).is_err());
    // NODE_ENV only relaxes things when exactly `development`.
    let dev = Config::from_env(&env_with(&[
        ("NODE_ENV", "Development"),
        ("TL_COLLATOR_ENABLE_LEGACY_TL_PROXY", "1"),
    ]))
    .unwrap();
    assert!(dev.legacy_proxy_enabled);
    let prod = Config::from_env(&env_with(&[
        ("NODE_ENV", "production"),
        ("TL_COLLATOR_ENABLE_LEGACY_TL_PROXY", "1"),
    ]))
    .unwrap();
    assert!(!prod.legacy_proxy_enabled);
}

// ---- clearlist ------------------------------------------------------------------------------

#[test]
fn clearlist_cache_key_cannot_be_confused_by_separators() {
    // Legacy key: `${groupId}|${pubkey}`.
    assert_ne!(cache_key("a|b", "c"), cache_key("a", "b|c"));
    assert_eq!(cache_key("g", "ABCD"), cache_key("g", "abcd"));
}

#[test]
fn clearlist_reply_requires_a_real_boolean() {
    assert!(parse_oracle_reply(&json!({"allowed": true, "snapshotId": "s1", "expTs": 5})).allowed);
    assert!(!parse_oracle_reply(&json!({"allowed": "false"})).allowed); // legacy `!!"false"` was true
    assert!(!parse_oracle_reply(&json!({"allowed": 1})).allowed);
    assert!(!parse_oracle_reply(&json!({})).allowed);
    let r = parse_oracle_reply(&json!({"allowed": true, "snapshotId": "s1", "expTs": 5}));
    assert_eq!((r.snapshot_id.as_deref(), r.exp_ts), (Some("s1"), Some(5)));
}

#[test]
fn clearlist_client_caches_for_the_ttl_and_is_bounded() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let script = Rc::new(RefCell::new(OracleScript {
        answer: Ok(true),
        calls: vec![],
    }));
    let mut c = ClearlistClient::new(SharedOracle(script.clone()), 60_000, 2);
    assert!(c.check("g", "02aa", 0).unwrap().allowed);
    assert!(c.check("g", "02AA", 59_999).unwrap().allowed);
    assert_eq!(script.borrow().calls.len(), 1);
    assert!(c.check("g", "02aa", 60_000).unwrap().allowed);
    assert_eq!(script.borrow().calls.len(), 2);
    for i in 0..10 {
        let _ = c.check("g", &format!("02{i:02}"), 70_000);
    }
    assert_eq!(c.cached(), 2);
    script.borrow_mut().answer = Err(());
    assert!(c.check("new", "02ff", 70_000).is_err());
}

#[test]
fn clearlist_decision_table() {
    let restricted = Visibility::Clearlist("g".into());
    let public = Visibility::Public;
    use FailMode::{Closed, Open};
    let allow = ClearlistDecision::Allow;
    // Not enforcing or public: always allowed, whatever the oracle says.
    for v in [
        OracleView::Answer(false),
        OracleView::Down,
        OracleView::NotConfigured,
    ] {
        assert_eq!(decide(false, Closed, &restricted, &v), allow);
        assert_eq!(decide(true, Closed, &public, &v), allow);
    }
    assert_eq!(
        decide(true, Closed, &restricted, &OracleView::Answer(true)),
        allow
    );
    for fail in [Open, Closed] {
        assert!(matches!(
            decide(true, fail, &restricted, &OracleView::Answer(false)),
            ClearlistDecision::Deny {
                code: "NOT_CLEARLISTED",
                ..
            }
        ));
    }
    assert_eq!(decide(true, Open, &restricted, &OracleView::Down), allow);
    assert_eq!(
        decide(true, Open, &restricted, &OracleView::NotConfigured),
        allow
    );
    assert!(matches!(
        decide(true, Closed, &restricted, &OracleView::Down),
        ClearlistDecision::Deny {
            code: "CLEARLIST_DOWN",
            ..
        }
    ));
    assert!(matches!(
        decide(true, Closed, &restricted, &OracleView::NotConfigured),
        ClearlistDecision::Deny {
            code: "CLEARLIST_CONFIG",
            ..
        }
    ));
}

#[test]
fn visibility_without_a_group_is_malformed_not_unrestricted() {
    let o = |v: Value| json!({"body": {"visibility": v}});
    assert_eq!(
        Visibility::from_order(&o(json!({"kind":"PUBLIC"}))),
        Some(Visibility::Public)
    );
    assert_eq!(
        Visibility::from_order(&o(json!({"kind":"DARK","groupId":"g"}))),
        Some(Visibility::Dark("g".into()))
    );
    assert_eq!(Visibility::from_order(&o(json!({"kind":"DARK"}))), None);
    assert_eq!(
        Visibility::from_order(&o(json!({"kind":"CLEARLIST","groupId":7}))),
        None
    );
    assert_eq!(Visibility::from_order(&o(json!({"kind":"OTHER"}))), None);
}

// ---- ip intel -------------------------------------------------------------------------------

#[test]
fn ip_intel_reply_parsing_is_strict() {
    assert_eq!(
        parse_reply(&json!({"asn": 64500, "vpn": true})),
        IpIntel {
            asn: Some(64500),
            vpn: Some(true)
        }
    );
    assert_eq!(parse_reply(&json!({"asn": "64500"})).asn, Some(64500));
    for bad in [
        json!(null),
        json!(""),
        json!(false),
        json!(0),
        json!(-4),
        json!(1.5),
        json!("AS12"),
        json!(4294967296_u64),
    ] {
        assert_eq!(parse_reply(&json!({ "asn": bad })).asn, None, "{bad}");
    }
    assert_eq!(parse_reply(&json!({"vpn": "true"})).vpn, None);
}

#[test]
fn ip_intel_verdicts() {
    let policy = |vpn, asn, fail| IntelPolicy {
        vpn_mode: vpn,
        asn_mode: asn,
        blocklist: vec![64500],
        fail_mode: fail,
    };
    let vpn = IpIntel {
        asn: None,
        vpn: Some(true),
    };
    let blocked = IpIntel {
        asn: Some(64500),
        vpn: Some(false),
    };
    let v = evaluate(
        &policy(Mode::Reject, Mode::Off, FailMode::Closed),
        vpn,
        false,
    );
    assert_eq!(v.reject, Some(("VPN_BLOCKED", "vpn traffic rejected")));
    let v = evaluate(&policy(Mode::Log, Mode::Off, FailMode::Closed), vpn, false);
    assert_eq!((v.reject, v.logged), (None, vec!["VPN_BLOCKED"]));
    let v = evaluate(
        &policy(Mode::Off, Mode::Reject, FailMode::Closed),
        blocked,
        false,
    );
    assert_eq!(v.reject, Some(("ASN_BLOCKED", "asn blocked")));
    // The vpn rule is checked first, like the legacy order.
    let both = IpIntel {
        asn: Some(64500),
        vpn: Some(true),
    };
    assert_eq!(
        evaluate(
            &policy(Mode::Reject, Mode::Reject, FailMode::Closed),
            both,
            false
        )
        .reject
        .unwrap()
        .0,
        "VPN_BLOCKED"
    );
    // Off modes never reject; an allowed asn passes.
    assert!(
        evaluate(&policy(Mode::Off, Mode::Off, FailMode::Closed), both, false)
            .reject
            .is_none()
    );
    assert!(evaluate(
        &policy(Mode::Reject, Mode::Reject, FailMode::Closed),
        IpIntel {
            asn: Some(1),
            vpn: Some(false)
        },
        false
    )
    .reject
    .is_none());
    // Lookup failure: closed rejects only with no usable metadata and an enforcing mode.
    let down = |p: &IntelPolicy, m| evaluate(p, m, true).reject;
    assert_eq!(
        down(
            &policy(Mode::Reject, Mode::Off, FailMode::Closed),
            IpIntel::default()
        )
        .unwrap()
        .0,
        "IP_INTEL_DOWN"
    );
    assert!(down(
        &policy(Mode::Reject, Mode::Off, FailMode::Open),
        IpIntel::default()
    )
    .is_none());
    assert!(down(
        &policy(Mode::Log, Mode::Log, FailMode::Closed),
        IpIntel::default()
    )
    .is_none());
    assert!(down(
        &policy(Mode::Reject, Mode::Off, FailMode::Closed),
        IpIntel {
            asn: Some(5),
            vpn: Some(false)
        }
    )
    .is_none());
}

// ---- audit ------------------------------------------------------------------------------------

#[test]
fn audit_line_key_order_and_optional_fields() {
    let mut rec = AuditRecord {
        ts: 5,
        collator_id: "c\"1".into(),
        peer_id: "peer-1".into(),
        ip: None,
        asn: None,
        vpn: None,
        order_id: "o".into(),
        trader_pub_key: "t".into(),
        seq: 9,
    };
    assert_eq!(
        rec.to_line(),
        r#"{"ts":5,"collatorId":"c\"1","peerId":"peer-1","orderId":"o","traderPubKey":"t","seq":9}"#
    );
    rec.ip = Some("::1".into());
    rec.asn = Some(64500);
    rec.vpn = Some(false);
    assert_eq!(
        rec.to_line(),
        r#"{"ts":5,"collatorId":"c\"1","peerId":"peer-1","ip":"::1","asn":64500,"vpn":false,"orderId":"o","traderPubKey":"t","seq":9}"#
    );
    assert!(serde_json::from_str::<Value>(&rec.to_line()).is_ok());
    let mut sink = MemoryAudit::new(2);
    for i in 0..3 {
        sink.write(&format!("l{i}")).unwrap();
    }
    assert_eq!(sink.lines, vec!["l1", "l2"]);
}

// ---- manifest -----------------------------------------------------------------------------------

fn attestation(mutate: impl Fn(&mut Value)) -> Value {
    let mut a = json!({"body": {
        "v": 1, "kind": "COLLATOR_APPROVAL", "clearlistId": 3,
        "infraPubKey": format!("02{}", "11".repeat(32)), "infraId": "infra-1", "ws": "wss://c.example/ws",
        "issuedAt": 1_700_000_000_u64, "expiresAt": 1_800_000_000_u64, "nonce": "deadbeef",
        "adminPubKey": format!("03{}", "22".repeat(32)), "extra": "dropped"},
        "sigAdmin": "ab".repeat(64)});
    mutate(&mut a);
    a
}

#[test]
fn infra_attestations_are_validated_and_normalised() {
    let now = 1_750_000_000;
    let good = attestation(|_| {});
    let list = load_infra_attestations(&json!([good.clone()]), now).unwrap();
    assert!(list[0]["body"].get("extra").is_none());
    assert_eq!(list[0]["body"]["infraId"], "infra-1");

    let rejects: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|a| a["body"]["v"] = json!(2)),
        Box::new(|a| a["body"]["kind"] = json!("OTHER")),
        Box::new(|a| a["body"]["clearlistId"] = json!(-1)),
        Box::new(|a| a["body"]["clearlistId"] = json!("3")),
        Box::new(|a| a["body"]["infraPubKey"] = json!("0211")), // not 33 bytes
        Box::new(|a| a["body"]["adminPubKey"] = json!("zz")),
        Box::new(|a| a["body"]["infraId"] = json!("")),
        Box::new(|a| a["body"]["ws"] = json!("")),
        Box::new(|a| a["body"]["issuedAt"] = json!("")), // Number("") === 0 in the legacy check
        Box::new(|a| a["body"]["expiresAt"] = json!(1_000_u64)), // expired
        Box::new(|a| a["body"]["expiresAt"] = json!(1_699_999_999_u64)), // before issuedAt
        Box::new(|a| a["body"]["nonce"] = json!("not hex")),
        Box::new(|a| a["sigAdmin"] = json!("ab")),
        Box::new(|a| a["body"] = json!(null)),
    ];
    for m in rejects {
        let bad = attestation(&m);
        assert!(
            load_infra_attestations(&json!([bad.clone()]), now).is_none(),
            "{bad}"
        );
    }
    assert!(load_infra_attestations(&json!({"not": "array"}), now).is_none());
    // Bounded at 128 entries.
    let many: Vec<Value> = (0..200).map(|_| good.clone()).collect();
    assert_eq!(
        load_infra_attestations(&Value::Array(many), now)
            .unwrap()
            .len(),
        128
    );
}

#[test]
fn service_publishes_only_unexpired_attestations() {
    let h = Harness::new(&[]);
    assert!(h.svc.manifest().get("infraAttestations").is_none());
}

// ---- bitvm ---------------------------------------------------------------------------------------

fn full_artifacts() -> Artifacts {
    Artifacts {
        procedural_sync: Some(json!({
            "propertyId": "380", "templateId": " tpl ", "templateHash": "AB", "contractId": "c",
            "fundingTxid": "AB".repeat(32), "fundingOutpoint": {"vout": "1"}, "operatorAddress": "op",
            "holderAddress": "h", "state": "FUNDED", "fundedAmountLtc": "0.25",
            "settlement": {"route": "roll", "settlementKind": "k"}})),
        pipeline: Some(
            json!({"status": "done", "steps": [{"id": "settlementValidation", "status": "pending"}]}),
        ),
        parallel_utxo_index: Some(
            json!({"chain": {"chainId": "bitcoin-regtest"}, "transactions": [
            {"txRole": "other", "outputs": [{"role": "x", "address": "no"}]},
            {"txRole": "roll", "txid": format!("{}", "EF".repeat(32)), "outputs": [{"role": "funding-output", "address": " fa "}]}]}),
        ),
        challenge_bundle: None,
        draft: None,
    }
}

#[test]
fn bitvm_status_applies_the_javascript_coercions_of_the_source() {
    let status = build_status(
        &full_artifacts(),
        &BitvmQuery::from_body(Some(&json!({"propertyId": 380}))),
        None,
        77,
    );
    let p = &status["procedural"];
    assert_eq!(p["ready"], true, "{p}");
    assert_eq!(p["templateId"], "tpl"); // trimmed
    assert_eq!(p["templateHash"], "ab"); // lowercased
    assert_eq!(p["fundingTxid"], "ab".repeat(32));
    assert_eq!(p["fundingVout"], 1); // Number("1")
    assert_eq!(p["fundingOutpoint"], format!("{}:1", "ab".repeat(32)));
    assert_eq!(p["chainId"], "bitcoin-regtest");
    assert_eq!(p["chainTicker"], "BTC");
    assert_eq!(p["receiptTicker"], "rBTC-SAT");
    assert_eq!(p["receiptPropertyId"], 380);
    assert_eq!(p["fundedAmountLtc"], 0.25);
    assert_eq!(p["fundingAddress"], "fa");
    assert_eq!(p["selectedPathId"], "roll"); // from settlement.route
    assert_eq!(p["selectedPathTxid"], "ef".repeat(32));
    assert_eq!(p["collateralPropertyId"], 1);
    assert_eq!(p["validationReady"], false);
    assert_eq!(
        p["contextWarnings"],
        json!(["Settlement validation is pending; artifact chain is not fully validated."])
    );
    assert_eq!(status["pipeline"]["settlementValidation"], "pending");
    assert_eq!(status["updatedAt"], 77);
    assert_eq!(p["sourceArtifacts"]["challengeBundle"], Value::Null);
    assert_eq!(
        p["sourceArtifacts"]["pipeline"],
        json!({"kind": null, "createdAt": null})
    );
    let ctx = format!("bitcoin-regtest:{}:1:roll", "ab".repeat(32));
    assert_eq!(p["executionContextId"], ctx);
    // Pin the hash: sha256 of the legacy JSON.stringify payload, key order as in the source.
    let payload = format!(
        r#"{{"chainId":"bitcoin-regtest","templateId":"tpl","contractId":"c","fundingTxid":"{}","fundingVout":1,"selectedPathId":"roll","selectedPathTxid":"{}","receiptPropertyId":380,"settlementRoute":"roll"}}"#,
        "ab".repeat(32),
        "ef".repeat(32)
    );
    assert_eq!(
        p["executionContextHash"],
        tl_collator_wire::sha256_hex(&payload)
    );
}

#[test]
fn bitvm_status_reports_each_missing_input() {
    let missing = build_status(&Artifacts::default(), &BitvmQuery::default(), None, 1);
    assert_eq!(missing["featureEnabled"], false);
    assert_eq!(
        missing["procedural"]["contextErrors"],
        json!(["Missing bitvm_procedural_sync_latest.json"])
    );

    let bare = Artifacts {
        procedural_sync: Some(json!({"propertyId": 5})),
        ..Artifacts::default()
    };
    let s = build_status(&bare, &BitvmQuery::default(), Some("7"), 1);
    assert_eq!(s["featureEnabled"], false);
    let errors: Vec<&str> = s["procedural"]["contextErrors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap())
        .collect();
    assert_eq!(errors.len(), 8);
    assert!(errors.contains(&"Missing templateId in procedural sync artifact."));
    assert!(errors.contains(&"Missing selectedPathTxid for the selected BitVM path."));
    assert_eq!(s["procedural"]["collateralPropertyId"], 7);
    assert_eq!(s["procedural"]["executionContextId"], Value::Null);
    assert_eq!(s["procedural"]["executionContextHash"], Value::Null);

    // Garbage collateral id serialises like JSON.stringify(NaN).
    let g = build_status(&bare, &BitvmQuery::default(), Some("abc"), 1);
    assert_eq!(g["procedural"]["collateralPropertyId"], Value::Null);
}

#[test]
fn bitvm_status_draft_mismatches_and_property_filter() {
    let mut a = full_artifacts();
    a.draft = Some(json!({"template": {"templateId": "other", "templateHash": "ZZ"}}));
    let s = build_status(&a, &BitvmQuery::default(), None, 1);
    assert_eq!(s["procedural"]["ready"], false);
    let errs = s["procedural"]["contextErrors"].to_string();
    assert!(errs
        .contains("DLC draft templateId (other) does not match procedural sync templateId (tpl)."));
    assert!(errs
        .contains("DLC draft templateHash (zz) does not match procedural sync templateHash (ab)."));
    // propertyId 0 / absent is falsy and does not filter; a different truthy id does.
    let zero = build_status(
        &full_artifacts(),
        &BitvmQuery::from_body(Some(&json!({"propertyId": 0}))),
        None,
        1,
    );
    assert_eq!(zero["procedural"]["ready"], true);
    let other = build_status(
        &full_artifacts(),
        &BitvmQuery::from_body(Some(&json!({"propertyId": "381"}))),
        None,
        1,
    );
    assert_eq!(other["procedural"]["ready"], false);
}

#[test]
fn bitvm_status_nullish_chain_quirk_is_preserved() {
    // `a ?? b ?? c ?? d` with an explicit trailing null yields Number(null) === 0 in the source.
    let mut a = full_artifacts();
    a.procedural_sync
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("fundingOutpoint");
    a.challenge_bundle = Some(json!({"binding": {"fundingOutpoint": {"vout": null}}}));
    let s = build_status(&a, &BitvmQuery::default(), None, 1);
    assert_eq!(s["procedural"]["fundingVout"], 0);
    // With every candidate undefined the vout is missing.
    a.challenge_bundle = None;
    let s = build_status(&a, &BitvmQuery::default(), None, 1);
    assert_eq!(s["procedural"]["fundingVout"], Value::Null);
}

#[test]
fn bitvm_query_keeps_only_bounded_known_fields() {
    let q = BitvmQuery::from_body(Some(
        &json!({"propertyId": ["x"], "dlcRef": "r", "other": 1}),
    ));
    assert_eq!((q.property_id, q.dlc_ref.as_deref()), (None, Some("r")));
    let long = "x".repeat(300);
    assert_eq!(
        BitvmQuery::from_body(Some(&json!({"dlcRef": long}))).dlc_ref,
        None
    );
    assert_eq!(
        BitvmQuery::from_body(Some(&json!([1, 2]))),
        BitvmQuery::default()
    );
    assert_eq!(BitvmQuery::from_body(None), BitvmQuery::default());
}

// ---- wire --------------------------------------------------------------------------------------

#[test]
fn wire_messages_parse_into_typed_inputs() {
    let max = 1 << 20;
    assert_eq!(
        parse_wire(r#"{"t":"TAPE_SUB","v":1}"#, max),
        Ok(WireIn::TapeSub { from_seq: 1 })
    );
    assert!(matches!(
        parse_wire(
            r#"{"t":"HELLO","v":1,"clientId":"c","want":["TAPE","RPC"]}"#,
            max
        ),
        Ok(WireIn::Hello { .. })
    ));
    assert!(matches!(
        parse_wire(
            r#"{"t":"RPC_ADVERTISE","v":1,"nodeId":"n","services":[{"service":"s","methods":["a"]}],"proof":"p"}"#,
            max
        ),
        Ok(WireIn::RpcAdvertise { proof: Some(_), .. })
    ));
    assert_eq!(parse_wire("x", 0), Err(WireError::TooLarge));
    assert_eq!(
        parse_wire(r#"{"t":"TAPE_SUB","v":1,"fromSeq":true}"#, max),
        Err(WireError::Schema("fromSeq"))
    );
    assert_eq!(
        parse_wire(
            r#"{"t":"RPC_ADVERTISE","v":1,"nodeId":"n","services":[{"service":"s","methods":[1]}]}"#,
            max
        ),
        Err(WireError::Schema("methods"))
    );
    let many = format!(
        r#"{{"t":"RPC_ADVERTISE","v":1,"nodeId":"n","services":[{}]}}"#,
        vec![r#"{"service":"s"}"#; 17].join(",")
    );
    assert_eq!(parse_wire(&many, max), Err(WireError::Schema("services")));
    // Deeply nested input is refused by the strict parser rather than overflowing the stack.
    let deep = format!(
        r#"{{"t":"PING","v":1,"ts":1,"x":{}0{}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    assert!(parse_wire(&deep, max).is_err());
}

// ---- http helpers ----------------------------------------------------------------------------------

#[test]
fn routing_table_follows_the_legacy_precedence() {
    let r = |m: &str, p: &str| route(m, p).unwrap();
    assert_eq!(r("GET", "/health"), Route::Health);
    assert_eq!(r("DELETE", "/attestation/ip"), Route::AttestationIp);
    assert_eq!(r("GET", "/rpc/providers"), Route::RpcProviders);
    assert_eq!(r("POST", "/rpc/route"), Route::RpcRoute);
    assert_eq!(
        r("POST", "/relayer/rpc/tl_getinfo"),
        Route::RpcCompat("tl_getinfo".into())
    );
    assert_eq!(
        r("POST", "/rpc/%20tl_getinfo%20"),
        Route::RpcCompat("tl_getinfo".into())
    );
    assert_eq!(r("POST", "/rpc/providers"), Route::NotFound);
    assert_eq!(r("GET", "/rpc/tl_getinfo"), Route::NotFound);
    assert_eq!(r("POST", "/tl_bitvmStatus"), Route::TlBitvmStatus);
    assert_eq!(
        r("GET", "/tl_bitvmStatus"),
        Route::TlOther("/tl_bitvmStatus".into())
    );
    assert_eq!(r("GET", "/tx/decode"), Route::TxGet("decode".into())); // legacy prefix quirk
    assert_eq!(r("POST", "/tx/decode"), Route::TxDecode);
    assert_eq!(r("GET", "/token/list"), Route::TokenList);
    assert_eq!(r("GET", "/token/12"), Route::TokenGet("12".into()));
    assert_eq!(
        r("POST", "/tx/build-unsigned"),
        Route::ProxyOnly("/tx/build-unsigned".into())
    );
    assert_eq!(
        route("GET", "/address/balance/"),
        Err(RouteError::Missing("Missing address"))
    );
    assert_eq!(
        route("GET", "/token/x"),
        Err(RouteError::Invalid("Invalid propid"))
    );
    assert_eq!(route("POST", "/rpc/%ff"), Err(RouteError::BadPath));
}

#[test]
fn percent_decoding_is_strict() {
    assert_eq!(percent_decode("a%20b"), Some("a b".into()));
    assert_eq!(percent_decode("%C3%A9"), Some("é".into()));
    assert_eq!(percent_decode("%"), None);
    assert_eq!(percent_decode("%4"), None);
    assert_eq!(percent_decode("%zz"), None);
    assert_eq!(percent_decode("%ff"), None);
    assert_eq!(percent_decode("a+b"), Some("a+b".into()));
}

#[test]
fn client_ip_prefers_the_socket_unless_a_proxy_is_trusted() {
    let mut req = http("GET", "/health", None);
    req.forwarded = Forwarded {
        cf_connecting_ip: Some(" 198.51.100.1 ".into()),
        x_real_ip: Some("198.51.100.2".into()),
        x_forwarded_for: Some("198.51.100.3, 10.0.0.1".into()),
        x_forwarded_proto: None,
    };
    assert_eq!(client_ip(&req, false), "192.0.2.10");
    assert_eq!(client_ip(&req, true), "198.51.100.1");
    req.forwarded.cf_connecting_ip = None;
    assert_eq!(client_ip(&req, true), "198.51.100.2");
    req.forwarded.x_real_ip = Some("   ".into());
    assert_eq!(client_ip(&req, true), "198.51.100.3");
    req.forwarded.x_forwarded_for = None;
    assert_eq!(client_ip(&req, true), "192.0.2.10");
}

#[test]
fn cors_outcomes() {
    let prod = config_with(&[("TL_COLLATOR_CORS_ORIGINS", "https://a.example")]);
    assert!(cors(None, &prod)
        .headers
        .iter()
        .all(|(k, _)| k != "Access-Control-Allow-Origin"));
    assert!(!cors(None, &prod).denied);
    assert!(!cors(Some("https://a.example"), &prod).denied);
    assert!(cors(Some("https://b.example"), &prod).denied);
    assert!(cors(Some("https://a.example "), &prod)
        .headers
        .iter()
        .any(|(k, v)| k == "Access-Control-Allow-Origin" && v == "https://a.example"));
}
