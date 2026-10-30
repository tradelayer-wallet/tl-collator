#![allow(clippy::type_complexity)]
mod common;
use common::*;
use serde_json::{json, Value};
use tl_collator_service::ipintel::IpIntel;
use tl_collator_service::{HostSession, Out};
use tl_collator_wire::verify::VerifiedReplay;

fn tape_entries(outs: &[Out], h: HostSession) -> Vec<Value> {
    sent(outs, h)
        .into_iter()
        .filter(|m| m["t"] == "TAPE_ENTRY")
        .map(|m| m["entry"].clone())
        .collect()
}

fn subscribe(t: &mut Harness, h: HostSession) -> Vec<Out> {
    t.msg(h, r#"{"t":"TAPE_SUB","v":1}"#)
}

// ---- admission --------------------------------------------------------------------

#[test]
fn submit_appends_broadcasts_and_tape_verifies_independently() {
    let mut t = Harness::new(&[]);
    let sub = t.connect("198.51.100.1");
    let trader = t.connect("198.51.100.2");
    let late = t.connect("198.51.100.3");
    let first = subscribe(&mut t, sub);
    assert_eq!(
        sent(&first, sub),
        vec![json!({"t":"TAPE_END","v":1,"lastSeq":0})]
    );
    assert!(t.svc.is_live(sub));

    let o1 = new_order(21, 1);
    let outs = t.msg(trader, &submit_msg(&o1));
    // No ack to the submitter (legacy), one TAPE_ENTRY to the live subscriber.
    assert!(sent(&outs, trader).is_empty());
    let pushed = tape_entries(&outs, sub);
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0]["seq"], 1);
    assert_eq!(pushed[0]["order"]["orderId"], o1["orderId"]);
    assert_eq!(t.svc.stats().orders_accepted, 1);

    t.tick(5);
    t.msg(trader, &submit_msg(&new_order(21, 2)));
    let replay = subscribe(&mut t, late);
    let entries = tape_entries(&replay, late);
    assert_eq!(
        entries
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        sent(&replay, late).last().unwrap(),
        &json!({"t":"TAPE_END","v":1,"lastSeq":2})
    );

    // The replayed bytes verify under an independent VerifiedReplay pinned to the collator key.
    let mut verifier = VerifiedReplay::new(COLLATOR, &secret(3).public_key_hex(), 100).unwrap();
    for e in &entries {
        verifier.apply_line(&e.to_string()).expect("entry verifies");
    }
    assert_eq!(verifier.checkpoint().last_seq, 2);
}

#[test]
fn duplicate_is_refused_even_after_the_recent_id_cache_forgot_it() {
    // Regression for src/index.ts:1114 + tape.ts:110: the legacy `seen` LRU evicted old ids and
    // the tape never checked, so an old signed order could be appended again.
    let mut t = Harness::new(&[("SEEN_ORDERIDS_MAX", "1")]);
    let h = t.connect("198.51.100.1");
    let a = new_order(21, 1);
    let b = new_order(21, 2);
    assert!(err_codes(&t.msg(h, &submit_msg(&a)), h).is_empty());
    assert!(err_codes(&t.msg(h, &submit_msg(&b)), h).is_empty());
    // `a` is no longer in the 1-entry cache; the tape still refuses it.
    assert_eq!(err_codes(&t.msg(h, &submit_msg(&a)), h), vec!["DUPLICATE"]);
    assert_eq!(err_codes(&t.msg(h, &submit_msg(&b)), h), vec!["DUPLICATE"]);
}

#[test]
fn order_id_is_bound_to_the_order_contents() {
    // Regression for src/index.ts:1118: the legacy check verified a signature over whatever
    // 32-byte `orderId` the client supplied, so the body was unauthenticated.
    let mut t = Harness::new(&[]);
    let h = t.connect("198.51.100.1");
    let mut tampered = new_order(21, 1);
    tampered["body"]["px"] = json!("1.00");
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&tampered)), h),
        vec!["BAD_ORDER_ID"]
    );

    // Attacker signs an arbitrary id with their own key and attaches an arbitrary body.
    let attacker = secret(77);
    let mut forged = new_order(21, 2);
    let arbitrary_id = "ab".repeat(32);
    forged["traderPubKey"] = json!(attacker.public_key_hex());
    forged["orderId"] = json!(arbitrary_id.clone());
    forged["sigTrader"] = json!(tl_collator_service::signer::DigestSigner::sign_digest(
        &attacker,
        &arbitrary_id
    )
    .unwrap());
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&forged)), h),
        vec!["BAD_ORDER_ID"]
    );
    assert_eq!(t.svc.stats().orders_accepted, 0);
}

#[test]
fn bad_signature_is_refused() {
    let mut t = Harness::new(&[]);
    let h = t.connect("198.51.100.1");
    let mut o = new_order(21, 1);
    // Sign with a different trader's key.
    let other = secret(22);
    o["sigTrader"] = json!(tl_collator_service::signer::DigestSigner::sign_digest(
        &other,
        o["orderId"].as_str().unwrap()
    )
    .unwrap());
    assert_eq!(err_codes(&t.msg(h, &submit_msg(&o)), h), vec!["bad_sig"]);
}

#[test]
fn uppercase_order_id_cannot_slip_past_duplicate_detection() {
    let mut t = Harness::new(&[]);
    let h = t.connect("198.51.100.1");
    let mut o = new_order(21, 1);
    assert!(err_codes(&t.msg(h, &submit_msg(&o)), h).is_empty());
    let upper = o["orderId"].as_str().unwrap().to_uppercase();
    o["orderId"] = json!(upper);
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&o)), h),
        vec!["SCHEMA_INVALID"]
    );
}

#[test]
fn cancel_and_replace_are_owner_only() {
    let mut t = Harness::new(&[]);
    let h = t.connect("198.51.100.1");
    let base = new_order(21, 1);
    let id = base["orderId"].as_str().unwrap().to_owned();
    assert!(err_codes(&t.msg(h, &submit_msg(&base)), h).is_empty());

    let theirs = order(22, 2, "CANCEL", Some(&id), json!({"kind":"PUBLIC"}));
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&theirs)), h),
        vec!["NOT_OWNER"]
    );
    let theirs_replace = order(22, 3, "REPLACE", Some(&id), json!({"kind":"PUBLIC"}));
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&theirs_replace)), h),
        vec!["NOT_OWNER"]
    );
    let unknown = order(
        21,
        4,
        "CANCEL",
        Some(&"cd".repeat(32)),
        json!({"kind":"PUBLIC"}),
    );
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&unknown)), h),
        vec!["UNKNOWN_ORDER"]
    );

    let mut missing = order(21, 5, "CANCEL", Some(&id), json!({"kind":"PUBLIC"}));
    missing.as_object_mut().unwrap().remove("cancelsOrderId");
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&missing)), h),
        vec!["SCHEMA_INVALID"]
    );

    let mine = order(21, 6, "CANCEL", Some(&id), json!({"kind":"PUBLIC"}));
    assert!(err_codes(&t.msg(h, &submit_msg(&mine)), h).is_empty());
    let replace = order(21, 7, "REPLACE", Some(&id), json!({"kind":"PUBLIC"}));
    assert!(err_codes(&t.msg(h, &submit_msg(&replace)), h).is_empty());
    assert_eq!(t.svc.stats().orders_accepted, 3);
}

#[test]
fn shape_violations_are_schema_invalid() {
    let mut t = Harness::new(&[]);
    let h = t.connect("198.51.100.1");
    let good = new_order(21, 1);
    let mutations: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|o| o["v"] = json!(2)),
        Box::new(|o| o["kind"] = json!("MODIFY")),
        Box::new(|o| o["body"]["side"] = json!("HOLD")),
        Box::new(|o| o["body"]["market"] = json!("")),
        Box::new(|o| o["body"]["px"] = json!(72.5)),
        Box::new(|o| o["body"]["clientTs"] = json!(1.5)),
        Box::new(|o| o["body"]["visibility"] = json!({"kind":"DARK"})),
        Box::new(|o| o["body"]["visibility"] = json!({"kind":"CLEARLIST","groupId":""})),
        Box::new(|o| o["traderPubKey"] = json!("02zz")),
        Box::new(|o| o["clientNonce"] = json!("")),
        Box::new(|o| o["sigTrader"] = json!("00")),
        Box::new(|o| o["orderId"] = json!("00")),
        Box::new(|o| o["body"]["market"] = json!("m".repeat(200))),
    ];
    for m in mutations {
        let mut o = good.clone();
        m(&mut o);
        assert_eq!(
            err_codes(&t.msg(h, &submit_msg(&o)), h),
            vec!["SCHEMA_INVALID"],
            "{o}"
        );
        t.tick(2_000);
    }
    assert_eq!(t.svc.stats().orders_accepted, 0);
}

// ---- rate limits ---------------------------------------------------------------------

#[test]
fn submit_rate_limit_applies_per_session_and_survives_reconnect() {
    let mut t = Harness::new(&[
        ("SUBMIT_BURST", "2"),
        ("SUBMIT_RPS", "0"),
        ("IP_BURST", "3"),
        ("IP_RPS", "0"),
    ]);
    let h = t.connect("203.0.113.9");
    let mut n = 0;
    let mut next = |t: &mut Harness, h| {
        n += 1;
        err_codes(&t.msg(h, &submit_msg(&new_order(21, n))), h)
    };
    assert!(next(&mut t, h).is_empty());
    assert!(next(&mut t, h).is_empty());
    assert_eq!(next(&mut t, h), vec!["rate_limited"]);

    // Reconnecting gives a fresh session bucket, but the per-address budget (3) is shared:
    // the legacy limiter lived in the session, so reconnecting reset it.
    t.svc.close_session(h, t.now);
    let h2 = t.connect("203.0.113.9");
    assert!(next(&mut t, h2).is_empty()); // third use of the address
    assert_eq!(next(&mut t, h2), vec!["rate_limited"]);
    // A different address is unaffected.
    let h3 = t.connect("203.0.113.10");
    assert!(next(&mut t, h3).is_empty());
}

#[test]
fn every_message_type_is_rate_limited() {
    let mut t = Harness::new(&[("MSG_BURST", "3"), ("MSG_RPS", "0")]);
    let h = t.connect("203.0.113.9");
    for _ in 0..3 {
        assert!(!sent(&t.msg(h, r#"{"t":"PING","v":1,"ts":1}"#), h).is_empty());
    }
    assert_eq!(
        err_codes(&t.msg(h, r#"{"t":"PING","v":1,"ts":1}"#), h),
        vec!["rate_limited"]
    );
    t.tick(1000);
    assert_eq!(
        err_codes(&t.msg(h, r#"{"t":"PING","v":1,"ts":1}"#), h),
        vec!["rate_limited"]
    );
}

#[test]
fn tape_sub_and_rpc_requests_share_the_heavy_budget() {
    let mut t = Harness::new(&[("HEAVY_BURST", "2"), ("HEAVY_RPS", "0")]);
    let h = t.connect("203.0.113.9");
    assert!(err_codes(&subscribe(&mut t, h), h).is_empty());
    assert!(err_codes(&subscribe(&mut t, h), h).is_empty());
    assert_eq!(err_codes(&subscribe(&mut t, h), h), vec!["rate_limited"]);
    let req = json!({"t":"RPC_REQ","v":1,"req":{"id":"1","service":SERVICE,"method":"tl_getinfo"}});
    assert_eq!(err_codes(&t.msg_json(h, &req), h), vec!["rate_limited"]);
}

// ---- framing ---------------------------------------------------------------------------

#[test]
fn malformed_frames_follow_the_legacy_reply_rules() {
    let mut t = Harness::new(&[]);
    let h = t.connect("203.0.113.9");
    // Not JSON, not an object, missing t/v: dropped silently.
    for text in [
        "{",
        "[]",
        "null",
        r#"{"v":1}"#,
        r#"{"t":"PING"}"#,
        r#"{"t":"PING","v":"1"}"#,
    ] {
        assert!(t.msg(h, text).is_empty(), "{text}");
    }
    // Duplicate keys are ambiguous: dropped.
    assert!(t.msg(h, r#"{"t":"PING","v":1,"ts":1,"ts":2}"#).is_empty());
    assert_eq!(t.svc.stats().malformed_dropped, 7);
    // Well-formed envelope, bad schema: ERR.
    for text in [
        r#"{"t":"PING","v":2,"ts":1}"#,
        r#"{"t":"PING","v":1,"ts":"x"}"#,
        r#"{"t":"NOPE","v":1}"#,
        r#"{"t":"SUBMIT","v":1}"#,
        r#"{"t":"TAPE_SUB","v":1,"fromSeq":"1"}"#,
        r#"{"t":"RPC_REQ","v":1,"req":{"id":"a"}}"#,
        r#"{"t":"HELLO","v":1,"clientId":"c","want":["BOGUS"]}"#,
    ] {
        assert_eq!(
            err_codes(&t.msg(h, text), h),
            vec!["SCHEMA_INVALID"],
            "{text}"
        );
    }
    // Frames the server never acts on.
    for text in [
        r#"{"t":"HELLO","v":1,"clientId":"c","want":["TAPE"]}"#,
        r#"{"t":"PONG","v":1,"ts":1}"#,
        r#"{"t":"TAPE_END","v":1,"lastSeq":3}"#,
        r#"{"t":"ERR","v":1,"code":"x","msg":"y"}"#,
    ] {
        assert!(t.msg(h, text).is_empty(), "{text}");
    }
    assert_eq!(
        sent(&t.msg(h, r#"{"t":"PING","v":1,"ts":42}"#), h),
        vec![json!({"t":"PONG","v":1,"ts":42})]
    );
}

#[test]
fn oversized_frame_gets_an_error_and_closes_the_channel() {
    let mut t = Harness::new(&[("MAX_MSG_BYTES", "2048")]);
    let h = t.connect("203.0.113.9");
    let big = format!(
        r#"{{"t":"PING","v":1,"ts":1,"pad":"{}"}}"#,
        "x".repeat(4000)
    );
    let outs = t.msg(h, &big);
    assert_eq!(err_codes(&outs, h), vec!["msg_too_large"]);
    assert!(outs
        .iter()
        .any(|o| matches!(o, Out::CloseChannel { session, .. } if *session == h)));
    // Multi-byte text is measured in bytes, not UTF-16 units (legacy used `.length`).
    let wide = format!(
        r#"{{"t":"PING","v":1,"ts":1,"pad":"{}"}}"#,
        "é".repeat(1100)
    );
    assert!(wide.len() > 2048 && wide.chars().count() < 2048);
    assert_eq!(err_codes(&t.msg(h, &wide), h), vec!["msg_too_large"]);
}

#[test]
fn messages_before_the_channel_opens_or_from_unknown_sessions_are_ignored() {
    let mut t = Harness::new(&[]);
    let h = HostSession(500);
    t.svc
        .open_session(h, Some("203.0.113.9"), None, t.now)
        .unwrap();
    assert!(t.msg(h, r#"{"t":"PING","v":1,"ts":1}"#).is_empty());
    assert!(t
        .msg(HostSession(999), r#"{"t":"PING","v":1,"ts":1}"#)
        .is_empty());
}

#[test]
fn connection_caps_total_and_per_address() {
    let mut t = Harness::new(&[("CONN_MAX", "3"), ("CONN_MAX_PER_IP", "2")]);
    let a = t.connect("203.0.113.1");
    let _b = t.connect("203.0.113.1");
    assert!(t
        .svc
        .open_session(HostSession(90), Some("203.0.113.1"), None, t.now)
        .is_err());
    let _c = t.connect("203.0.113.2");
    assert!(t
        .svc
        .open_session(HostSession(91), Some("203.0.113.3"), None, t.now)
        .is_err());
    t.svc.close_session(a, t.now);
    assert!(t
        .svc
        .open_session(HostSession(92), Some("203.0.113.3"), None, t.now)
        .is_ok());
    assert_eq!(t.svc.session_count(), 3);
}

// ---- replay -------------------------------------------------------------------------------

#[test]
fn replay_is_contiguous_batched_and_does_not_double_deliver_live_entries() {
    let mut t = Harness::new(&[("TAPE_REPLAY_BATCH", "2")]);
    let writer = t.connect("203.0.113.1");
    let reader = t.connect("203.0.113.2");
    for n in 1..=5 {
        t.msg(writer, &submit_msg(&new_order(21, n)));
        t.tick(10);
    }
    let first = t.msg(reader, r#"{"t":"TAPE_SUB","v":1,"fromSeq":2}"#);
    let seqs = |o: &[Out]| {
        tape_entries(o, reader)
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(seqs(&first), vec![2, 3]);
    assert!(t.svc.is_replaying(reader));
    assert!(!t.svc.is_live(reader));

    // An order appended mid-replay is not pushed live to the replaying session.
    let mid = t.msg(writer, &submit_msg(&new_order(21, 6)));
    assert!(tape_entries(&mid, reader).is_empty());

    let second = t.svc.pump_replay(reader);
    assert_eq!(seqs(&second), vec![4, 5]);
    assert!(t.svc.is_replaying(reader));
    let third = t.svc.pump_replay(reader);
    assert_eq!(seqs(&third), vec![6]);
    assert_eq!(
        sent(&third, reader).last().unwrap(),
        &json!({"t":"TAPE_END","v":1,"lastSeq":6})
    );
    assert!(t.svc.is_live(reader));
    assert!(t.svc.pump_replay(reader).is_empty());

    // From now on it receives live entries exactly once.
    let live = t.msg(writer, &submit_msg(&new_order(21, 7)));
    assert_eq!(seqs(&live), vec![7]);
}

#[test]
fn replay_start_is_clamped_and_rounded_like_the_legacy_comparison() {
    let mut t = Harness::new(&[]);
    let w = t.connect("203.0.113.1");
    for n in 1..=3 {
        t.msg(w, &submit_msg(&new_order(21, n)));
        t.tick(10);
    }
    let r = t.connect("203.0.113.2");
    let seqs = |o: &[Out], h| {
        tape_entries(o, h)
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        seqs(&t.msg(r, r#"{"t":"TAPE_SUB","v":1,"fromSeq":-5}"#), r),
        vec![1, 2, 3]
    );
    assert_eq!(
        seqs(&t.msg(r, r#"{"t":"TAPE_SUB","v":1,"fromSeq":0}"#), r),
        vec![1, 2, 3]
    );
    assert_eq!(
        seqs(&t.msg(r, r#"{"t":"TAPE_SUB","v":1,"fromSeq":2.5}"#), r),
        vec![3]
    );
    let beyond = t.msg(r, r#"{"t":"TAPE_SUB","v":1,"fromSeq":99}"#);
    assert!(seqs(&beyond, r).is_empty());
    assert_eq!(
        sent(&beyond, r),
        vec![json!({"t":"TAPE_END","v":1,"lastSeq":3})]
    );
}

#[test]
fn a_closed_channel_stops_replay_and_live_delivery() {
    let mut t = Harness::new(&[("TAPE_REPLAY_BATCH", "1")]);
    let w = t.connect("203.0.113.1");
    for n in 1..=3 {
        t.msg(w, &submit_msg(&new_order(21, n)));
        t.tick(10);
    }
    let r = t.connect("203.0.113.2");
    t.msg(r, r#"{"t":"TAPE_SUB","v":1}"#);
    assert!(t.svc.is_replaying(r));
    t.svc.channel_closed(r, t.now);
    assert!(t.svc.pump_replay(r).is_empty());
    let outs = t.msg(w, &submit_msg(&new_order(21, 4)));
    assert!(sent(&outs, r).is_empty());
}

// ---- policy: clearlist / ip intel / audit ---------------------------------------------------

fn restricted(n: u64, kind: &str) -> Value {
    order(21, n, "NEW", None, json!({"kind": kind, "groupId": "g1"}))
}

#[test]
fn clearlist_enforcement_modes() {
    // Allowed.
    let mut t = Harness::new(&[
        ("CLEARLIST_ENFORCE", "1"),
        ("CLEARLIST_URL", "https://oracle.example"),
    ]);
    let h = t.connect("203.0.113.1");
    assert!(err_codes(&t.msg(h, &submit_msg(&restricted(1, "CLEARLIST"))), h).is_empty());
    assert_eq!(t.fakes.oracle.borrow().calls.len(), 1);
    // Public orders never call the oracle.
    assert!(err_codes(&t.msg(h, &submit_msg(&new_order(21, 2))), h).is_empty());
    assert_eq!(t.fakes.oracle.borrow().calls.len(), 1);
    // Cached for the TTL, then re-asked.
    assert!(err_codes(&t.msg(h, &submit_msg(&restricted(3, "DARK"))), h).is_empty());
    assert_eq!(t.fakes.oracle.borrow().calls.len(), 1); // same (group, trader): served from the cache
    t.fakes.oracle.borrow_mut().answer = Ok(false);
    t.tick(61_000);
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&restricted(4, "CLEARLIST"))), h),
        vec!["NOT_CLEARLISTED"]
    );

    // Oracle down: closed rejects, open admits.
    t.fakes.oracle.borrow_mut().answer = Err(());
    t.tick(61_000);
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&restricted(5, "CLEARLIST"))), h),
        vec!["CLEARLIST_DOWN"]
    );

    let mut open = Harness::new(&[
        ("CLEARLIST_ENFORCE", "1"),
        ("CLEARLIST_URL", "https://oracle.example"),
        ("CLEARLIST_FAIL_MODE", "open"),
    ]);
    open.fakes.oracle.borrow_mut().answer = Err(());
    let o = open.connect("203.0.113.1");
    assert!(err_codes(&open.msg(o, &submit_msg(&restricted(1, "DARK"))), o).is_empty());
    // A negative answer is never overridden by fail-open.
    open.fakes.oracle.borrow_mut().answer = Ok(false);
    open.tick(61_000);
    assert_eq!(
        err_codes(&open.msg(o, &submit_msg(&restricted(2, "DARK"))), o),
        vec!["NOT_CLEARLISTED"]
    );
}

#[test]
fn clearlist_enforced_without_an_oracle_fails_closed_by_default() {
    // enforce=1 and no CLEARLIST_URL -> no oracle client is built.
    let mut t = Harness::new(&[("CLEARLIST_ENFORCE", "1")]);
    let h = t.connect("203.0.113.1");
    assert_eq!(
        err_codes(&t.msg(h, &submit_msg(&restricted(1, "CLEARLIST"))), h),
        vec!["CLEARLIST_CONFIG"]
    );
    assert!(err_codes(&t.msg(h, &submit_msg(&new_order(21, 2))), h).is_empty());
}

#[test]
fn clearlist_off_ignores_restricted_visibility() {
    let mut t = Harness::new(&[]);
    let h = t.connect("203.0.113.1");
    assert!(err_codes(&t.msg(h, &submit_msg(&restricted(1, "CLEARLIST"))), h).is_empty());
    assert!(t.fakes.oracle.borrow().calls.is_empty());
}

#[test]
fn ip_intel_policy() {
    let env = [
        ("IP_INTEL_URL", "https://intel.example"),
        ("VPN_FILTER_MODE", "reject"),
        ("ASN_BLOCK_MODE", "reject"),
        ("ASN_BLOCKLIST", "64500,64501"),
        ("SUBMIT_BURST", "50"),
    ];
    let mut t = Harness::new(&env);
    let h = t.connect("203.0.113.1");
    let mut n = 0;
    let mut go = |t: &mut Harness, h| {
        n += 1;
        t.tick(1);
        err_codes(&t.msg(h, &submit_msg(&new_order(21, n))), h)
    };
    t.fakes.intel.borrow_mut().answer = Ok(IpIntel {
        asn: Some(64496),
        vpn: Some(false),
    });
    assert!(go(&mut t, h).is_empty());
    t.tick(301_000); // cache expiry
    t.fakes.intel.borrow_mut().answer = Ok(IpIntel {
        asn: Some(64496),
        vpn: Some(true),
    });
    assert_eq!(go(&mut t, h), vec!["VPN_BLOCKED"]);
    t.tick(301_000);
    t.fakes.intel.borrow_mut().answer = Ok(IpIntel {
        asn: Some(64501),
        vpn: Some(false),
    });
    assert_eq!(go(&mut t, h), vec!["ASN_BLOCKED"]);

    // Regression for src/index.ts:1164: an unreachable intel service no longer disables
    // enforcement for a session with no known metadata (default fail mode: closed).
    let fresh = t.connect("203.0.113.2");
    t.tick(301_000);
    t.fakes.intel.borrow_mut().answer = Err(());
    assert_eq!(go(&mut t, fresh), vec!["IP_INTEL_DOWN"]);

    // Fail-open operators keep the legacy behaviour.
    let mut o = Harness::new(&[
        ("IP_INTEL_URL", "https://intel.example"),
        ("VPN_FILTER_MODE", "reject"),
        ("IP_INTEL_FAIL_MODE", "open"),
    ]);
    o.fakes.intel.borrow_mut().answer = Err(());
    let oh = o.connect("203.0.113.3");
    assert!(err_codes(&o.msg(oh, &submit_msg(&new_order(21, 1))), oh).is_empty());
}

#[test]
fn log_mode_admits_and_counts() {
    let mut t = Harness::new(&[
        ("IP_INTEL_URL", "https://intel.example"),
        ("VPN_FILTER_MODE", "log"),
    ]);
    t.fakes.intel.borrow_mut().answer = Ok(IpIntel {
        asn: None,
        vpn: Some(true),
    });
    let h = t.connect("203.0.113.1");
    assert!(err_codes(&t.msg(h, &submit_msg(&new_order(21, 1))), h).is_empty());
    assert_eq!(t.svc.stats().intel_logged, 1);
    assert_eq!(t.svc.stats().orders_accepted, 1);
}

#[test]
fn audit_log_records_accepted_orders_only_when_enabled() {
    let mut t = Harness::new(&[("IP_LOGGING", "on")]);
    let h = t.connect("203.0.113.1");
    let o = new_order(21, 1);
    t.msg(h, &submit_msg(&o));
    t.msg(h, &submit_msg(&o)); // duplicate: not logged
    let lines = t.fakes.audit.borrow().clone();
    assert_eq!(lines.len(), 1);
    let expected = format!(
        r#"{{"ts":{},"collatorId":"collator-test","peerId":"peer-{}","ip":"203.0.113.1","orderId":"{}","traderPubKey":"{}","seq":1}}"#,
        T0,
        h.0,
        o["orderId"].as_str().unwrap(),
        o["traderPubKey"].as_str().unwrap()
    );
    assert_eq!(lines[0], expected);

    let mut off = Harness::new(&[]);
    let oh = off.connect("203.0.113.1");
    off.msg(oh, &submit_msg(&new_order(21, 1)));
    assert!(off.fakes.audit.borrow().is_empty());
}

// ---- RPC --------------------------------------------------------------------------------

fn rpc_req(id: &str, method: &str) -> Value {
    json!({"t":"RPC_REQ","v":1,"req":{"id":id,"service":SERVICE,"network":NETWORK,"method":method,"params":[1]}})
}

fn first_rpc_req(outs: &[Out], to: HostSession) -> Value {
    sent(outs, to)
        .into_iter()
        .find(|m| m["t"] == "RPC_REQ")
        .expect("RPC_REQ")["req"]
        .clone()
}

#[test]
fn routed_rpc_round_trip_with_server_token_and_pinned_identity() {
    let mut t = Harness::new(&[]);
    let provider = t.connect("203.0.113.1");
    let caller = t.connect("203.0.113.2");
    t.authenticate(provider, "node-a", 11, &["tl_getinfo", "tl_getproperty"]);

    let outs = t.msg_json(caller, &rpc_req("caller-id-1", "  TL_GETINFO "));
    let fwd = first_rpc_req(&outs, provider);
    let token = fwd["id"].as_str().unwrap().to_owned();
    assert_ne!(token, "caller-id-1");
    assert_eq!(fwd["method"], "tl_getinfo");
    assert_eq!(fwd["params"], json!([1]));
    assert_eq!(fwd["service"], SERVICE);
    assert!(sent(&outs, caller).is_empty());

    // Spoofed provider identity in the response is overwritten.
    let res = json!({"t":"RPC_RES","v":1,"res":{"id":token,"ok":true,"result":{"blocks":7},"providerNodeId":"node-evil"}});
    let done = t.msg_json(provider, &res);
    assert_eq!(
        sent(&done, caller),
        vec![
            json!({"t":"RPC_RES","v":1,"res":{"id":"caller-id-1","ok":true,"result":{"blocks":7},"providerNodeId":"node-a"}})
        ]
    );
    assert_eq!(t.svc.pending_rpc(), 0);
    // A replayed response is ignored.
    assert!(t.msg_json(provider, &res).is_empty());
}

#[test]
fn rpc_response_from_the_wrong_session_or_by_caller_id_is_refused() {
    // Regression for src/index.ts:429/1090: any session could settle any request by id.
    let mut t = Harness::new(&[]);
    let provider = t.connect("203.0.113.1");
    let caller = t.connect("203.0.113.2");
    let attacker = t.connect("203.0.113.3");
    t.authenticate(provider, "node-a", 11, &["tl_getinfo"]);
    let outs = t.msg_json(caller, &rpc_req("victim-1", "tl_getinfo"));
    let token = first_rpc_req(&outs, provider)["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Attacker guesses the caller id (legacy key) and the real token.
    let by_caller = json!({"t":"RPC_RES","v":1,"res":{"id":"victim-1","ok":true,"result":"pwn"}});
    assert!(t.msg_json(attacker, &by_caller).is_empty());
    let by_token = json!({"t":"RPC_RES","v":1,"res":{"id":token,"ok":true,"result":"pwn"}});
    assert_eq!(
        err_codes(&t.msg_json(attacker, &by_token), attacker),
        vec!["RPC_RES_REJECTED"]
    );
    // The caller itself cannot answer its own request either.
    assert_eq!(
        err_codes(&t.msg_json(caller, &by_token), caller),
        vec!["RPC_RES_REJECTED"]
    );
    assert_eq!(t.svc.pending_rpc(), 1);

    // Malformed provider response keeps the request pending, then the real answer works.
    let junk = json!({"t":"RPC_RES","v":1,"res":{"id":token,"ok":true,"surplus":1}});
    assert_eq!(
        err_codes(&t.msg_json(provider, &junk), provider),
        vec!["RPC_RES_REJECTED"]
    );
    assert_eq!(t.svc.pending_rpc(), 1);
    let good = json!({"t":"RPC_RES","v":1,"res":{"id":token,"ok":false,"error":{"code":"X","message":"boom"}}});
    let done = t.msg_json(provider, &good);
    assert_eq!(sent(&done, caller)[0]["res"]["id"], "victim-1");
    assert_eq!(sent(&done, caller)[0]["res"]["ok"], false);
}

#[test]
fn legacy_unauthenticated_advertise_does_not_register_a_provider() {
    let mut t = Harness::new(&[]);
    let evil = t.connect("203.0.113.1");
    let caller = t.connect("203.0.113.2");
    let advert = json!({"t":"RPC_ADVERTISE","v":1,"nodeId":"node-a",
        "services":[{"service":SERVICE,"network":NETWORK,"methods":["tl_getinfo"]}]});
    let outs = t.msg_json(evil, &advert);
    assert_eq!(sent(&outs, evil)[0]["t"], "RPC_CHALLENGE");
    let outs = t.msg_json(caller, &rpc_req("1", "tl_getinfo"));
    assert_eq!(
        sent(&outs, caller)[0]["res"]["error"]["code"],
        "NO_RPC_PROVIDER"
    );
    assert_eq!(
        sent(&outs, caller)[0]["res"]["error"]["message"],
        format!("no WebRTC RPC provider for {SERVICE} on {NETWORK}")
    );
    // A forged proof is rejected with the legacy advertisement error code.
    let bad = json!({"t":"RPC_ADVERTISE","v":1,"nodeId":"node-a","services":[],"proof":"{}"});
    assert_eq!(
        err_codes(&t.msg_json(evil, &bad), evil),
        vec!["RPC_ADVERTISEMENT_REJECTED"]
    );
    // A proof for a node pinned to another key is rejected too.
    let outs = t.msg_json(evil, &advert);
    let nonce = sent(&outs, evil)[0]["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let proof = provider_proof("node-a", 99, &nonce, &["tl_getinfo"]);
    let forged = json!({"t":"RPC_ADVERTISE","v":1,"nodeId":"node-a","services":[],"proof":proof});
    assert_eq!(
        err_codes(&t.msg_json(evil, &forged), evil),
        vec!["RPC_ADVERTISEMENT_REJECTED"]
    );
}

#[test]
fn rpc_policy_and_validation_errors() {
    let mut t = Harness::new(&[]);
    let caller = t.connect("203.0.113.2");
    let res = |t: &mut Harness, v: Value| sent(&t.msg_json(caller, &v), caller)[0]["res"].clone();

    let forbidden = res(&mut t, rpc_req("1", "sendtoaddress"));
    assert_eq!(forbidden["error"]["code"], "RPC_METHOD_FORBIDDEN");
    let other_service = res(
        &mut t,
        json!({"t":"RPC_REQ","v":1,"req":{"id":"2","service":"other","method":"tl_getinfo"}}),
    );
    assert_eq!(other_service["error"]["code"], "RPC_SERVICE_FORBIDDEN");
    let empty = res(
        &mut t,
        json!({"t":"RPC_REQ","v":1,"req":{"id":"3","service":SERVICE,"method":"   "}}),
    );
    assert_eq!(empty["error"]["code"], "BAD_RPC_REQUEST");
    assert_eq!(empty["id"], "3");
    let wrong_net = res(
        &mut t,
        json!({"t":"RPC_REQ","v":1,"req":{"id":"4","service":SERVICE,"network":"btc-mainnet","method":"tl_getinfo"}}),
    );
    assert_eq!(wrong_net["error"]["code"], "BAD_RPC_REQUEST");
    let ctl = res(&mut t, rpc_req("bad\nid", "tl_getinfo"));
    assert_eq!(ctl["error"]["code"], "BAD_RPC_REQUEST");
}

#[test]
fn rpc_timeout_and_peer_closure_complete_the_caller() {
    let mut t = Harness::new(&[]);
    let provider = t.connect("203.0.113.1");
    let caller = t.connect("203.0.113.2");
    t.authenticate(provider, "node-a", 11, &["tl_getinfo"]);

    let mut req = rpc_req("slow", "tl_getinfo");
    req["req"]["timeoutMs"] = json!(5000);
    t.msg_json(caller, &req);
    t.tick(4_999);
    assert!(t.svc.expire(t.now).is_empty());
    t.tick(1);
    let outs = t.svc.expire(t.now);
    let m = &sent(&outs, caller)[0]["res"];
    assert_eq!(m["error"]["code"], "RPC_TIMEOUT");
    assert_eq!(m["id"], "slow");
    assert_eq!(m["providerNodeId"], "node-a");

    // Provider disconnects with work in flight.
    t.msg_json(caller, &rpc_req("orphan", "tl_getinfo"));
    let outs = t.svc.close_session(provider, t.now);
    assert_eq!(
        sent(&outs, caller)[0]["res"]["error"]["code"],
        "RPC_PEER_CLOSED"
    );
    assert_eq!(t.svc.pending_rpc(), 0);
}

#[test]
fn pending_work_is_bounded_per_requester() {
    let mut t = Harness::new(&[("HEAVY_BURST", "1000"), ("MSG_BURST", "1000")]);
    let provider = t.connect("203.0.113.1");
    let caller = t.connect("203.0.113.2");
    t.authenticate(provider, "node-a", 11, &["tl_getinfo"]);
    let mut overloaded = 0;
    for i in 0..40 {
        let outs = t.msg_json(caller, &rpc_req(&format!("r{i}"), "tl_getinfo"));
        if sent(&outs, caller)
            .iter()
            .any(|m| m["res"]["error"]["code"] == "RPC_OVERLOADED")
        {
            overloaded += 1;
        }
    }
    assert_eq!(t.svc.pending_rpc(), 32);
    assert_eq!(overloaded, 8);
}

#[test]
fn colliding_caller_ids_do_not_overwrite_each_other() {
    // Regression for src/index.ts:351: `pendingRpc.set(rpcReq.id, ...)` let a second caller
    // reuse an id and displace (or later steal) the first caller's pending entry.
    let mut t = Harness::new(&[]);
    let provider = t.connect("203.0.113.1");
    let a = t.connect("203.0.113.2");
    let b = t.connect("203.0.113.3");
    t.authenticate(provider, "node-a", 11, &["tl_getinfo"]);
    let ta = first_rpc_req(&t.msg_json(a, &rpc_req("same", "tl_getinfo")), provider)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let tb = first_rpc_req(&t.msg_json(b, &rpc_req("same", "tl_getinfo")), provider)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(ta, tb);
    let done_b = t.msg_json(
        provider,
        &json!({"t":"RPC_RES","v":1,"res":{"id":tb,"ok":true,"result":"b"}}),
    );
    assert_eq!(sent(&done_b, b)[0]["res"]["result"], "b");
    assert!(sent(&done_b, a).is_empty());
    let done_a = t.msg_json(
        provider,
        &json!({"t":"RPC_RES","v":1,"res":{"id":ta,"ok":true,"result":"a"}}),
    );
    assert_eq!(sent(&done_a, a)[0]["res"]["result"], "a");
}

#[test]
fn channel_replacement_drops_the_old_identity() {
    let mut t = Harness::new(&[]);
    let provider = t.connect("203.0.113.1");
    let caller = t.connect("203.0.113.2");
    t.authenticate(provider, "node-a", 11, &["tl_getinfo"]);
    t.svc.channel_closed(provider, t.now);
    // The reopened channel has no advertisement until it authenticates again.
    t.svc.channel_opened(provider, t.now).unwrap();
    let outs = t.msg_json(caller, &rpc_req("1", "tl_getinfo"));
    assert_eq!(
        sent(&outs, caller)[0]["res"]["error"]["code"],
        "NO_RPC_PROVIDER"
    );
}
