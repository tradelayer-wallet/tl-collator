#![allow(clippy::type_complexity)]
mod common;
use common::*;
use serde_json::{json, Value};
use tl_collator_service::bitvm::Artifacts;
use tl_collator_service::http::HttpTicket;
use tl_collator_service::ipintel::IpIntel;
use tl_collator_service::signer::{DigestSigner, SecretKeySigner};
use tl_collator_service::{HostSession, Out};
use tl_collator_wire::{canonical_json, sha256_hex};

fn reply_of(outs: &[Out], ticket: HttpTicket) -> Option<(u16, Value, Vec<(String, String)>)> {
    outs.iter().find_map(|o| match o {
        Out::HttpReply {
            ticket: t,
            response,
        } if *t == ticket => Some((
            response.status,
            serde_json::from_str(&response.body).unwrap_or(Value::String(response.body.clone())),
            response.headers.clone(),
        )),
        _ => None,
    })
}

fn proxy_of(outs: &[Out], ticket: HttpTicket) -> Option<tl_collator_service::http::ProxyRequest> {
    outs.iter().find_map(|o| match o {
        Out::Proxy { ticket: t, request } if *t == ticket => Some(request.clone()),
        _ => None,
    })
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn get(t: &mut Harness, path: &str) -> (u16, Value, Vec<(String, String)>) {
    let (ticket, outs) = t.svc.handle_http(&http("GET", path, None), t.now);
    t.tick(100);
    reply_of(&outs, ticket).expect("immediate reply")
}

// ---- basic endpoints ----------------------------------------------------------------

#[test]
fn health_manifest_and_unknown_paths() {
    let mut t = Harness::new(&[]);
    t.tick(5_000);
    let (s, body, _) = get(&mut t, "/health");
    assert_eq!(s, 200);
    assert_eq!(body["ok"], true);
    assert_eq!(body["collatorId"], COLLATOR);
    assert_eq!(body["uptimeSec"], 5);
    assert_eq!(body["rpcProviders"], 0);

    let (s, manifest, _) = get(&mut t, "/manifest");
    assert_eq!(s, 200);
    assert_eq!(manifest["roles"], json!(["collator"]));
    assert_eq!(manifest["protocol"]["dataChannelLabel"], "tl-bb");
    assert_eq!(manifest["policy"]["rateLimit"]["submitBurst"], 10);
    // The signature covers the canonical body and verifies under the collator key.
    let mut body = manifest.clone();
    let sig = body.as_object_mut().unwrap().remove("sigCollator").unwrap();
    let digest = sha256_hex(&canonical_json(&body).unwrap());
    let expected = secret(3).sign_digest(&digest).unwrap();
    assert_eq!(sig, json!(expected));

    let (s, body, _) = get(&mut t, "/nope");
    assert_eq!((s, body), (404, Value::String("not found".into())));
    // POST to a GET-only path falls through to 404 like the legacy handler.
    let (ticket, outs) = t.svc.handle_http(&http("POST", "/health", None), t.now);
    assert_eq!(reply_of(&outs, ticket).unwrap().0, 404);
}

#[test]
fn rpc_providers_lists_only_authenticated_live_providers() {
    let mut t = Harness::new(&[]);
    let p = t.connect("203.0.113.1");
    assert_eq!(get(&mut t, "/rpc/providers").1["providers"], json!([]));
    t.authenticate(p, "node-a", 11, &["tl_getinfo"]);
    let (_, body, _) = get(&mut t, "/rpc/providers");
    assert_eq!(body["ok"], true);
    assert_eq!(body["providers"][0]["nodeId"], "node-a");
    assert_eq!(
        body["providers"][0]["services"][0]["methods"],
        json!(["tl_getinfo"])
    );
    assert_eq!(get(&mut t, "/health").1["rpcProviders"], 1);
    // The advertisement expires with its TTL (45 s default).
    t.tick(46_000);
    assert_eq!(get(&mut t, "/rpc/providers").1["providers"], json!([]));
}

// ---- CORS -----------------------------------------------------------------------------

#[test]
fn cors_is_closed_by_default_and_exact_when_configured() {
    let mut t = Harness::new(&[]);
    let mut req = http("GET", "/health", None);
    req.origin = Some("https://evil.example".into());
    let (ticket, outs) = t.svc.handle_http(&req, t.now);
    let (s, _, h) = reply_of(&outs, ticket).unwrap();
    assert_eq!(s, 200);
    assert!(header(&h, "Access-Control-Allow-Origin").is_none());

    let mut pre = http("OPTIONS", "/rpc/tl_getinfo", None);
    pre.origin = Some("https://evil.example".into());
    let (ticket, outs) = t.svc.handle_http(&pre, t.now);
    assert_eq!(reply_of(&outs, ticket).unwrap().0, 403);

    // Cross-origin POST from an unapproved origin is refused, not just unreadable.
    let mut post = http("POST", "/rpc/tl_getinfo", Some(&json!({})));
    post.origin = Some("https://evil.example".into());
    let (ticket, outs) = t.svc.handle_http(&post, t.now);
    assert_eq!(reply_of(&outs, ticket).unwrap().0, 403);

    let mut ok = Harness::new(&[(
        "TL_COLLATOR_CORS_ORIGINS",
        "https://app.example, https://wallet.example",
    )]);
    let mut pre = http("OPTIONS", "/rpc/tl_getinfo", None);
    pre.origin = Some("https://wallet.example".into());
    let (ticket, outs) = ok.svc.handle_http(&pre, ok.now);
    let (s, _, h) = reply_of(&outs, ticket).unwrap();
    assert_eq!(s, 204);
    assert_eq!(
        header(&h, "Access-Control-Allow-Origin"),
        Some("https://wallet.example")
    );
    assert_eq!(header(&h, "Vary"), Some("Origin"));
    assert_eq!(
        header(&h, "Access-Control-Allow-Methods"),
        Some("GET,POST,OPTIONS")
    );
    // A listed list means no wildcard even in development.
    let mut pre = http("OPTIONS", "/health", None);
    pre.origin = Some("https://other.example".into());
    let (ticket, outs) = ok.svc.handle_http(&pre, ok.now);
    assert_eq!(reply_of(&outs, ticket).unwrap().0, 403);
}

#[test]
fn development_wildcard_needs_an_explicit_node_env() {
    let mut dev = Harness::new(&[("NODE_ENV", "development")]);
    let mut req = http("GET", "/health", None);
    req.origin = Some("http://localhost:5173".into());
    let (ticket, outs) = dev.svc.handle_http(&req, dev.now);
    let (_, _, h) = reply_of(&outs, ticket).unwrap();
    assert_eq!(header(&h, "Access-Control-Allow-Origin"), Some("*"));
    // Unset NODE_ENV used to behave like development; it now means production.
    let mut prod = Harness::new(&[]);
    let (ticket, outs) = prod.svc.handle_http(&req, prod.now);
    let (_, _, h) = reply_of(&outs, ticket).unwrap();
    assert!(header(&h, "Access-Control-Allow-Origin").is_none());
}

// ---- compat RPC ---------------------------------------------------------------------------

#[test]
fn compat_rpc_routes_to_a_provider_and_wraps_data() {
    let mut t = Harness::new(&[]);
    let provider = t.connect("203.0.113.1");
    t.authenticate(provider, "node-a", 11, &["tl_getinfo"]);
    let (ticket, outs) = t.svc.handle_http(
        &http("POST", "/rpc/tl_getInfo", Some(&json!({"params": 5}))),
        t.now,
    );
    assert!(reply_of(&outs, ticket).is_none());
    let fwd = sent(&outs, provider)[0]["req"].clone();
    assert_eq!(fwd["method"], "tl_getinfo");
    assert_eq!(fwd["params"], json!([5]));
    assert_ne!(fwd["id"], format!("http-{}", ticket.0));
    assert_eq!(t.svc.http_inflight(), 1);

    let done = t.msg_json(
        provider,
        &json!({"t":"RPC_RES","v":1,"res":{"id":fwd["id"],"ok":true,"result":{"height":9}}}),
    );
    let (s, body, _) = reply_of(&done, ticket).expect("http reply");
    assert_eq!(s, 200);
    assert_eq!(body, json!({"data":{"height":9}}));
    assert_eq!(t.svc.http_inflight(), 0);

    // Provider-supplied failure -> 502 with code and message.
    let (ticket, outs) = t.svc.handle_http(
        &http("POST", "/relayer/rpc/tl_getinfo", Some(&json!({}))),
        t.now,
    );
    let fwd = sent(&outs, provider)[0]["req"].clone();
    let done = t.msg_json(
        provider,
        &json!({"t":"RPC_RES","v":1,"res":{"id":fwd["id"],"ok":false,"error":{"code":"E1","message":"bad"}}}),
    );
    let (s, body, _) = reply_of(&done, ticket).unwrap();
    assert_eq!((s, body), (502, json!({"error":"bad","code":"E1"})));
}

#[test]
fn compat_rpc_without_a_provider_uses_the_legacy_relayer() {
    let mut t = Harness::new(&[]);
    let (ticket, outs) = t.svc.handle_http(
        &http("POST", "/rpc/tl_getinfo", Some(&json!({"params":[1,2]}))),
        t.now,
    );
    let p = proxy_of(&outs, ticket).expect("upstream");
    assert_eq!(
        (p.method.as_str(), p.path.as_str()),
        ("POST", "/rpc/tl_getinfo")
    );
    assert_eq!(p.body, Some(json!({"params":[1,2]})));
    let done = t
        .svc
        .proxy_done(ticket, Some((200, json!({"data":"legacy"}))), t.now);
    assert_eq!(
        reply_of(&done, ticket).unwrap(),
        (200, json!({"data":"legacy"}), done_headers(&done, ticket))
    );

    let (ticket, _) = t
        .svc
        .handle_http(&http("POST", "/rpc/tl_getinfo", Some(&json!({}))), t.now);
    let done = t.svc.proxy_done(ticket, None, t.now);
    let (s, body, _) = reply_of(&done, ticket).unwrap();
    assert_eq!(
        (s, body["code"].clone()),
        (502, json!("LEGACY_PROXY_ERROR"))
    );
    assert_eq!(t.svc.http_inflight(), 0);
}

fn done_headers(outs: &[Out], ticket: HttpTicket) -> Vec<(String, String)> {
    reply_of(outs, ticket).unwrap().2
}

#[test]
fn compat_rpc_policy_errors() {
    let mut t = Harness::new(&[]);
    let post = |t: &mut Harness, path: &str, body: Option<Value>| {
        let (ticket, outs) = t.svc.handle_http(&http("POST", path, body.as_ref()), t.now);
        t.tick(100);
        reply_of(&outs, ticket).unwrap_or((0, Value::Null, vec![]))
    };
    assert_eq!(post(&mut t, "/rpc/sendtoaddress", Some(json!({}))).0, 403);
    assert_eq!(post(&mut t, "/rpc/%20", Some(json!({}))).0, 400);
    assert_eq!(post(&mut t, "/rpc/%zz", Some(json!({}))).0, 400);
    assert_eq!(
        post(&mut t, "/rpc/tl_getinfo/extra", Some(json!({}))).0,
        404
    );
    assert_eq!(post(&mut t, "/rpc/providers", Some(json!({}))).0, 404);
    // Invalid JSON is a 400, not silently treated as an empty body.
    let mut bad = http("POST", "/rpc/tl_getinfo", None);
    bad.body = b"{not json".to_vec();
    let (ticket, outs) = t.svc.handle_http(&bad, t.now);
    assert_eq!(reply_of(&outs, ticket).unwrap().0, 400);
    // Duplicate keys are ambiguous and refused.
    let mut dup = http("POST", "/rpc/tl_getinfo", None);
    dup.body = br#"{"params":[1],"params":[2]}"#.to_vec();
    t.tick(100);
    let (ticket, outs) = t.svc.handle_http(&dup, t.now);
    assert_eq!(reply_of(&outs, ticket).unwrap().0, 400);
}

#[test]
fn rpc_route_endpoint_statuses() {
    let mut t = Harness::new(&[]);
    let provider = t.connect("203.0.113.1");
    let route = |t: &mut Harness, body: Value| {
        let (ticket, outs) = t
            .svc
            .handle_http(&http("POST", "/rpc/route", Some(&body)), t.now);
        t.tick(100);
        (ticket, outs)
    };
    let (tk, outs) = route(&mut t, json!({"service":"other","method":"tl_getinfo"}));
    assert_eq!(reply_of(&outs, tk).unwrap().0, 403);
    let (tk, outs) = route(&mut t, json!({"service":SERVICE}));
    assert_eq!(reply_of(&outs, tk).unwrap().0, 400);
    let (tk, outs) = route(&mut t, json!({"service":SERVICE,"method":"getblockcount"}));
    assert_eq!(reply_of(&outs, tk).unwrap().0, 403);
    let (tk, outs) = route(
        &mut t,
        json!({"id":"c1","service":SERVICE,"method":"tl_getinfo"}),
    );
    let (s, body, _) = reply_of(&outs, tk).unwrap();
    assert_eq!(
        (s, body["error"]["code"].clone(), body["id"].clone()),
        (503, json!("NO_RPC_PROVIDER"), json!("c1"))
    );

    t.authenticate(provider, "node-a", 11, &["tl_getinfo"]);
    let (tk, outs) = route(
        &mut t,
        json!({"id":"c2","service":SERVICE,"method":"tl_getinfo","params":[]}),
    );
    let fwd = sent(&outs, provider)[0]["req"].clone();
    let done = t.msg_json(
        provider,
        &json!({"t":"RPC_RES","v":1,"res":{"id":fwd["id"],"ok":true,"result":1}}),
    );
    let (s, body, _) = reply_of(&done, tk).unwrap();
    assert_eq!(s, 200);
    assert_eq!(body["id"], "c2");
    assert_eq!(body["providerNodeId"], "node-a");
    // Timeout path.
    let (tk, outs) = route(
        &mut t,
        json!({"id":"c3","service":SERVICE,"method":"tl_getinfo","timeoutMs":1000}),
    );
    assert!(sent(&outs, provider)[0]["t"] == "RPC_REQ");
    t.tick(1_000);
    let (s, body, _) = reply_of(&t.svc.expire(t.now), tk).unwrap();
    assert_eq!(
        (s, body["error"]["code"].clone()),
        (502, json!("RPC_TIMEOUT"))
    );
}

// ---- proxied routes -----------------------------------------------------------------------

#[test]
fn proxied_routes_try_upstream_then_fall_back() {
    let mut t = Harness::new(&[]);
    // Success below 500 is returned verbatim.
    let (tk, outs) = t
        .svc
        .handle_http(&http("GET", "/address/balance/ltc1qexample", None), t.now);
    let p = proxy_of(&outs, tk).unwrap();
    assert_eq!(
        (p.method.as_str(), p.path.as_str()),
        ("GET", "/address/balance/ltc1qexample")
    );
    let done = t
        .svc
        .proxy_done(tk, Some((404, json!({"error":"unknown"}))), t.now);
    assert_eq!(reply_of(&done, tk).unwrap().0, 404);

    // Upstream 5xx falls back to the routed public method; no provider -> relayer rpc proxy.
    t.tick(100);
    let (tk, _) = t
        .svc
        .handle_http(&http("GET", "/address/balance/ltc1qexample", None), t.now);
    let next = t.svc.proxy_done(tk, Some((502, json!({}))), t.now);
    let p = proxy_of(&next, tk).expect("second stage: compat relayer");
    assert_eq!(p.path, "/rpc/tl_getallbalancesforaddress");
    assert_eq!(p.body, Some(json!({"params":["ltc1qexample"]})));
    let end = t
        .svc
        .proxy_done(tk, Some((200, json!({"data":{"balances":[]}}))), t.now);
    assert_eq!(
        reply_of(&end, tk).unwrap().1,
        json!({"data":{"balances":[]}})
    );

    // Fallbacks to non-public methods are refused (faucet, chain info, decode, sendTx).
    for (method, path) in [
        ("GET", "/chain/info"),
        ("GET", "/address/faucet/ltc1qexample"),
    ] {
        t.tick(100);
        let (tk, _) = t.svc.handle_http(&http(method, path, None), t.now);
        let done = t.svc.proxy_done(tk, None, t.now);
        assert_eq!(reply_of(&done, tk).unwrap().0, 403, "{path}");
    }
    t.tick(100);
    let (tk, _) = t.svc.handle_http(
        &http("POST", "/tx/sendTx", Some(&json!({"rawTx":"00"}))),
        t.now,
    );
    let done = t.svc.proxy_done(tk, Some((503, json!({}))), t.now);
    assert_eq!(reply_of(&done, tk).unwrap().0, 403);

    // Pure proxy routes end in the legacy 404 when upstream fails.
    t.tick(100);
    let (tk, outs) = t
        .svc
        .handle_http(&http("POST", "/tx/buildTx", Some(&json!({"a":1}))), t.now);
    assert_eq!(proxy_of(&outs, tk).unwrap().body, Some(json!({"a":1})));
    let done = t.svc.proxy_done(tk, None, t.now);
    assert_eq!(reply_of(&done, tk).unwrap().0, 404);
    assert_eq!(t.svc.http_inflight(), 0);
}

#[test]
fn path_parameters_are_validated_before_they_reach_upstream() {
    let mut t = Harness::new(&[]);
    for (path, status) in [
        ("/address/validate/", 400),
        ("/address/balance/..%2F..%2Fadmin", 400),
        ("/address/balance/a%00b", 400),
        ("/address/balance/a%2Fb", 400),
        ("/address/balance/%E0%A4", 400),
        ("/tx/", 400),
        ("/token/abc", 400),
        ("/token/", 400),
        ("/token/99999999999999999", 400),
    ] {
        t.tick(100);
        assert_eq!(get(&mut t, path).0, status, "{path}");
    }
    let (_, body, _) = get(&mut t, "/address/validate/");
    assert_eq!(body, json!({"error":"Missing address"}));
    // A numeric property id becomes a number in the fallback params.
    t.tick(100);
    let (tk, _) = t.svc.handle_http(&http("GET", "/token/380", None), t.now);
    let next = t.svc.proxy_done(tk, None, t.now);
    assert_eq!(
        proxy_of(&next, tk).unwrap().body,
        Some(json!({"params":[380]}))
    );
    t.svc.http_abort(tk);
}

#[test]
fn utxo_route_forwards_only_a_hex_pubkey() {
    let mut t = Harness::new(&[]);
    let (tk, outs) = t.svc.handle_http(
        &http(
            "POST",
            "/address/utxo/ltc1qexample",
            Some(&json!({"pubkey":"02ab","extra":{"x":1}})),
        ),
        t.now,
    );
    assert_eq!(
        proxy_of(&outs, tk).unwrap().body,
        Some(json!({"pubkey":"02ab"}))
    );
    t.tick(100);
    let (tk, outs) = t.svc.handle_http(
        &http(
            "POST",
            "/address/utxo/ltc1qexample",
            Some(&json!({"pubkey":"not hex"})),
        ),
        t.now,
    );
    assert_eq!(
        proxy_of(&outs, tk).unwrap().body,
        Some(json!({"pubkey":null}))
    );
}

// ---- legacy /tl_* ------------------------------------------------------------------------

#[test]
fn legacy_tl_proxy_is_closed_unless_development_flag_is_set() {
    let mut t = Harness::new(&[("TL_COLLATOR_ENABLE_LEGACY_TL_PROXY", "1")]);
    // Production (default) ignores the flag.
    let (tk, outs) = t
        .svc
        .handle_http(&http("POST", "/tl_listproperties", Some(&json!({}))), t.now);
    let (s, body, _) = reply_of(&outs, tk).unwrap();
    assert_eq!(
        (s, body["error"]["code"].clone()),
        (404, json!("LEGACY_TL_PROXY_DISABLED"))
    );

    let mut dev = Harness::new(&[
        ("NODE_ENV", "development"),
        ("TL_COLLATOR_ENABLE_LEGACY_TL_PROXY", "1"),
    ]);
    let (tk, outs) = dev.svc.handle_http(
        &http("POST", "/tl_listproperties", Some(&json!({"a":1}))),
        dev.now,
    );
    let p = proxy_of(&outs, tk).unwrap();
    assert_eq!(
        (p.method.as_str(), p.path.as_str()),
        ("POST", "/tl_listproperties")
    );
    // Traversal and odd characters never reach the upstream path.
    for path in ["/tl_/../admin", "/tl_x/../../y", "/tl_a%2fb", "/tl_a b"] {
        dev.tick(100);
        let (tk, outs) = dev
            .svc
            .handle_http(&http("POST", path, Some(&json!({}))), dev.now);
        assert!(proxy_of(&outs, tk).is_none(), "{path}");
        assert_eq!(reply_of(&outs, tk).unwrap().0, 400, "{path}");
    }
}

// ---- local endpoints --------------------------------------------------------------------

fn bitvm_fixture() -> Artifacts {
    let txid = "ab".repeat(32);
    Artifacts {
        procedural_sync: Some(json!({
            "kind": "sync", "createdAt": "2026-10-01T00:00:00Z",
            "propertyId": 380, "templateId": "tpl-1", "templateHash": "AA11",
            "contractId": "c-1", "fundingTxid": txid, "funding": {"fundingOutpoint": {"vout": 0}},
            "operatorAddress": "tltc1operator", "state": "FUNDED", "fundedAmountLtc": 0.5,
            "settlement": {"route": "roll", "settlementKind": "route"},
            "parallelUtxoIndex": {"chainId": "Litecoin-Testnet"},
        })),
        pipeline: Some(
            json!({"status": "ok", "options": {"mode": "replay", "selectedPath": "roll"},
            "summary": {"settlementValidation": {"status": "ok"}}}),
        ),
        parallel_utxo_index: Some(json!({"transactions": [
            {"txRole": "roll", "txid": "cd".repeat(32), "outputs": [{"role": "funding-output", "address": "tltc1fund"}]},
        ]})),
        challenge_bundle: Some(json!({"selectedPathId": "roll"})),
        draft: Some(json!({"template": {"templateId": "tpl-1", "templateHash": "aa11"}})),
    }
}

#[test]
fn bitvm_status_over_post_tl_bitvmstatus_and_rpc_compat() {
    let mut t = Harness::new(&[]);
    *t.fakes.artifacts.borrow_mut() = bitvm_fixture();
    let (tk, outs) = t.svc.handle_http(
        &http("POST", "/tl_bitvmStatus", Some(&json!({"propertyId":380}))),
        t.now,
    );
    let (s, body, _) = reply_of(&outs, tk).unwrap();
    assert_eq!(s, 200);
    let p = &body["procedural"];
    assert_eq!(p["ready"], true, "{p}");
    assert_eq!(p["chainId"], "litecoin-testnet");
    assert_eq!(p["receiptTicker"], "rLTC-SAT");
    assert_eq!(p["fundingVout"], 0);
    assert_eq!(p["selectedPathTxid"], "cd".repeat(32));
    assert_eq!(body["query"], json!({"propertyId":380}));
    assert!(
        p.get("artifactDir").is_none(),
        "server paths are not disclosed"
    );

    t.tick(100);
    let (tk, outs) = t.svc.handle_http(
        &http(
            "POST",
            "/rpc/TL_BitvmStatus",
            Some(&json!({"propertyId":999})),
        ),
        t.now,
    );
    let (_, body, _) = reply_of(&outs, tk).unwrap();
    assert_eq!(body["procedural"]["ready"], false);
    assert!(body["procedural"]["contextErrors"][0]
        .as_str()
        .unwrap()
        .contains("propertyId 999"));
    // The request body is not echoed back wholesale.
    t.tick(100);
    let (tk, outs) = t.svc.handle_http(
        &http(
            "POST",
            "/tl_bitvmStatus",
            Some(&json!({"propertyId":380,"junk":"x"})),
        ),
        t.now,
    );
    assert_eq!(
        reply_of(&outs, tk).unwrap().1["query"],
        json!({"propertyId":380})
    );
}

#[test]
fn attestation_ip_uses_trusted_addresses_only() {
    let mut t = Harness::new(&[("IP_INTEL_URL", "https://intel.example")]);
    t.fakes.intel.borrow_mut().answer = Ok(IpIntel {
        asn: Some(64500),
        vpn: Some(true),
    });
    let mut req = http("GET", "/attestation/ip", None);
    req.forwarded.x_forwarded_for = Some("198.51.100.77, 10.0.0.1".into());
    req.forwarded.cf_connecting_ip = Some("198.51.100.88".into());
    let (tk, outs) = t.svc.handle_http(&req, t.now);
    let p = proxy_of(&outs, tk).unwrap();
    // Spoofable headers are replaced by the socket address.
    assert_eq!(
        p.headers,
        vec![("x-forwarded-for".to_owned(), "192.0.2.10".to_owned())]
    );
    let done = t.svc.proxy_done(tk, None, t.now);
    let (_, body, _) = reply_of(&done, tk).unwrap();
    assert_eq!(body["ip"], "192.0.2.10");
    assert_eq!(body["isVpn"], true);
    assert_eq!(body["isBlocked"], true);
    assert_eq!(t.fakes.intel.borrow().calls, vec!["192.0.2.10".to_owned()]);

    // Behind an operator-declared proxy the headers are honoured, in legacy precedence order.
    let mut trusted = Harness::new(&[
        ("IP_INTEL_URL", "https://intel.example"),
        ("TL_COLLATOR_TRUST_PROXY_HEADERS", "1"),
    ]);
    let (tk, outs) = trusted.svc.handle_http(&req, trusted.now);
    let p = proxy_of(&outs, tk).unwrap();
    assert!(p
        .headers
        .contains(&("cf-connecting-ip".to_owned(), "198.51.100.88".to_owned())));
    let done = trusted.svc.proxy_done(tk, None, trusted.now);
    assert_eq!(reply_of(&done, tk).unwrap().1["ip"], "198.51.100.88");
}

#[test]
fn attestation_does_not_claim_clean_without_data() {
    let mut t = Harness::new(&[]);
    let (tk, _) = t
        .svc
        .handle_http(&http("GET", "/attestation/ip", None), t.now);
    let done = t.svc.proxy_done(tk, None, t.now);
    let (_, body, _) = reply_of(&done, tk).unwrap();
    assert_eq!(body["success"], false);
    assert_eq!(body["isBlocked"], false);
}

// ---- limits ---------------------------------------------------------------------------------

#[test]
fn http_requests_are_rate_limited_per_address_and_bounded_in_size() {
    let mut t = Harness::new(&[("IP_BURST", "3"), ("IP_RPS", "0")]);
    for _ in 0..3 {
        assert_eq!(get(&mut t, "/health").0, 200);
    }
    assert_eq!(get(&mut t, "/health").0, 429);
    // Spoofed forwarding headers do not mint a new bucket by default.
    let mut spoof = http("GET", "/health", None);
    spoof.forwarded.x_forwarded_for = Some("203.0.113.200".into());
    let (tk, outs) = t.svc.handle_http(&spoof, t.now);
    assert_eq!(reply_of(&outs, tk).unwrap().0, 429);

    let mut small = Harness::new(&[("MAX_MSG_BYTES", "2048")]);
    let mut big = http("POST", "/rpc/tl_getinfo", None);
    big.body = vec![b' '; 5000];
    let (tk, outs) = small.svc.handle_http(&big, small.now);
    assert_eq!(reply_of(&outs, tk).unwrap().0, 413);
}

#[test]
fn inflight_http_work_is_bounded_and_abortable() {
    let mut t = Harness::new(&[("IP_BURST", "10000"), ("IP_RPS", "10000")]);
    let mut tickets = Vec::new();
    for _ in 0..512 {
        let (tk, outs) = t.svc.handle_http(&http("GET", "/token/list", None), t.now);
        assert!(proxy_of(&outs, tk).is_some());
        tickets.push(tk);
        t.tick(1);
    }
    let (tk, outs) = t.svc.handle_http(&http("GET", "/token/list", None), t.now);
    assert_eq!(reply_of(&outs, tk).unwrap().0, 503);
    t.svc.http_abort(tickets[0]);
    assert_eq!(t.svc.http_inflight(), 511);
    assert!(t.svc.proxy_done(tickets[0], None, t.now).is_empty());
}

#[test]
fn closing_the_provider_answers_a_waiting_http_caller() {
    let mut t = Harness::new(&[]);
    let provider = t.connect("203.0.113.1");
    t.authenticate(provider, "node-a", 11, &["tl_getinfo"]);
    let (tk, _) = t
        .svc
        .handle_http(&http("POST", "/rpc/tl_getinfo", Some(&json!({}))), t.now);
    let outs = t.svc.close_session(HostSession(provider.0), t.now);
    let (s, body, _) = reply_of(&outs, tk).unwrap();
    assert_eq!((s, body["code"].clone()), (502, json!("RPC_PEER_CLOSED")));
    assert_eq!(t.svc.http_inflight(), 0);
}

#[allow(dead_code)]
fn unused(_: &SecretKeySigner) {}
