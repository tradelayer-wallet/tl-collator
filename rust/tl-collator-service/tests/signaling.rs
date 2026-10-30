//! Signaling reducer: success paths, malformed input, bounds, timeouts, cleanup and a
//! deterministic random walk that checks the transition invariants the Lean model proves.
use serde_json::{json, Value};
use tl_collator_service::signaling::*;

const T0: u64 = 1_700_000_000_000;

const SDP: &str = "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
a=group:BUNDLE 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n\
a=mid:0\r\na=sctp-port:5000\r\n";
const CAND: &str = "candidate:842163049 1 udp 1677729535 192.0.2.1 46154 typ srflx raddr 10.0.0.1 rport 46154 generation 0 ufrag abcd network-cost 999";

fn session() -> SignalSession {
    SignalSession::new(SignalLimits::default(), T0).unwrap()
}

fn hello() -> String {
    json!({"t":"SIGNAL_HELLO","v":1,"clientId":"wallet-1"}).to_string()
}
fn offer() -> String {
    json!({"t":"SIGNAL_OFFER","v":1,"kind":"offer","sdp":SDP}).to_string()
}
fn ice(c: &str) -> String {
    json!({"t":"SIGNAL_ICE","v":1,"candidate":{"candidate":c,"sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"abcd"}}).to_string()
}
fn cand() -> IceCandidate {
    IceCandidate {
        candidate: CAND.into(),
        sdp_mid: Some("0".into()),
        sdp_mline_index: Some(0),
        username_fragment: None,
    }
}
fn answer_ready() -> HostEvent {
    HostEvent::AnswerReady { sdp: SDP.into() }
}
fn errs(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(v) if v["t"] == "SIGNAL_ERR" => v["code"].as_str().map(str::to_owned),
            _ => None,
        })
        .collect()
}
fn closed_with(actions: &[Action]) -> Option<u16> {
    actions.iter().find_map(|a| match a {
        Action::CloseSocket { code, .. } => Some(*code),
        _ => None,
    })
}

fn to_answered(s: &mut SignalSession) {
    s.on_frame(&hello(), T0);
    assert!(matches!(
        s.on_frame(&offer(), T0 + 1)[..],
        [Action::ApplyOffer { .. }]
    ));
    s.on_event(answer_ready(), T0 + 2);
    assert_eq!(s.state(), SignalState::Answered);
}

#[test]
fn full_handshake_hello_offer_answer_ice_open() {
    let mut s = session();
    assert_eq!(s.state(), SignalState::Idle);
    assert!(s.on_frame(&hello(), T0).is_empty());
    assert_eq!(s.state(), SignalState::Greeted);

    let a = s.on_frame(&offer(), T0 + 1);
    assert_eq!(a, vec![Action::ApplyOffer { sdp: SDP.into() }]);
    assert_eq!(s.state(), SignalState::Offering);
    assert_eq!(s.pending_offers(), 1);

    let a = s.on_event(answer_ready(), T0 + 2);
    assert_eq!(
        a,
        vec![Action::Send(
            json!({"t":"SIGNAL_ANSWER","v":1,"kind":"answer","sdp":SDP})
        )]
    );
    assert_eq!(s.state(), SignalState::Answered);
    assert_eq!(s.pending_offers(), 0);

    let a = s.on_frame(&ice(CAND), T0 + 3);
    assert_eq!(
        a,
        vec![Action::AddRemoteCandidate(IceCandidate {
            candidate: CAND.into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some("abcd".into()),
        })]
    );
    let a = s.on_event(HostEvent::LocalCandidate(cand()), T0 + 4);
    assert_eq!(a.len(), 1);
    match &a[0] {
        Action::Send(v) => {
            assert_eq!(v["t"], "SIGNAL_ICE");
            assert_eq!(v["candidate"]["candidate"], CAND);
            assert_eq!(v["candidate"]["sdpMid"], "0");
        }
        other => panic!("{other:?}"),
    }
    assert!(s.on_event(HostEvent::DataChannelOpen, T0 + 5).is_empty());
    assert_eq!(s.state(), SignalState::Established);
    // Late trickle candidates are still accepted once established.
    assert_eq!(s.on_frame(&ice(CAND), T0 + 6).len(), 1);
    assert_eq!(s.deadline_ms(), None);
}

#[test]
fn offer_without_hello_is_accepted_like_the_legacy_handler() {
    let mut s = session();
    assert_eq!(s.on_frame(&offer(), T0).len(), 1);
    assert_eq!(s.state(), SignalState::Offering);
}

#[test]
fn at_most_one_pending_offer_and_one_offer_per_session() {
    let mut s = session();
    s.on_frame(&offer(), T0);
    // Legacy replaced `pc` here and leaked the first peer connection.
    let a = s.on_frame(&offer(), T0 + 1);
    assert_eq!(errs(&a), vec!["unexpected"]);
    assert!(!a.iter().any(|x| matches!(x, Action::ApplyOffer { .. })));
    assert_eq!(s.pending_offers(), 1);
    assert_eq!(s.state(), SignalState::Offering);
    s.on_event(answer_ready(), T0 + 2);
    let a = s.on_frame(&offer(), T0 + 3);
    assert_eq!(errs(&a), vec!["unexpected"]);
    assert_eq!(s.state(), SignalState::Answered);
    assert_eq!(s.offers_accepted(), 1);
    assert_eq!(s.pending_offers(), 0);
}

#[test]
fn repeated_hello_and_client_answers_are_refused() {
    let mut s = session();
    s.on_frame(&hello(), T0);
    assert_eq!(errs(&s.on_frame(&hello(), T0 + 1)), vec!["unexpected"]);
    let answer = json!({"t":"SIGNAL_ANSWER","v":1,"kind":"answer","sdp":SDP}).to_string();
    assert_eq!(errs(&s.on_frame(&answer, T0 + 2)), vec!["unexpected"]);
    assert_eq!(s.state(), SignalState::Greeted);
}

#[test]
fn peer_signal_err_is_ignored_and_free() {
    let mut s = session();
    let m = json!({"t":"SIGNAL_ERR","v":1,"code":"x","msg":"y"}).to_string();
    for _ in 0..20 {
        assert!(s.on_frame(&m, T0).is_empty());
    }
    assert_eq!(s.state(), SignalState::Idle);
    let bad = json!({"t":"SIGNAL_ERR","v":1,"code":1,"msg":"y"}).to_string();
    assert_eq!(errs(&s.on_frame(&bad, T0)), vec!["bad_message"]);
}

#[test]
fn ice_before_the_offer_is_refused() {
    let mut s = session();
    assert_eq!(errs(&s.on_frame(&ice(CAND), T0)), vec!["unexpected"]);
    s.on_frame(&hello(), T0);
    assert_eq!(errs(&s.on_frame(&ice(CAND), T0)), vec!["unexpected"]);
}

#[test]
fn candidates_during_the_offer_are_buffered_and_ordered_after_the_answer() {
    let mut s = session();
    s.on_frame(&offer(), T0);
    assert!(s.on_frame(&ice(CAND), T0 + 1).is_empty());
    assert!(s.on_frame(&ice(""), T0 + 1).is_empty());
    // Local ICE gathered while the answer is still being applied (legacy sent it before the answer).
    assert!(s
        .on_event(HostEvent::LocalCandidate(cand()), T0 + 2)
        .is_empty());
    assert_eq!(s.buffered_candidates(), 3);
    let a = s.on_event(answer_ready(), T0 + 3);
    assert_eq!(a.len(), 4);
    assert!(matches!(&a[0], Action::Send(v) if v["t"] == "SIGNAL_ANSWER"));
    assert!(matches!(&a[1], Action::Send(v) if v["t"] == "SIGNAL_ICE"));
    assert!(matches!(&a[2], Action::AddRemoteCandidate(c) if c.candidate == CAND));
    assert!(matches!(&a[3], Action::AddRemoteCandidate(c) if c.candidate.is_empty()));
    assert_eq!(s.buffered_candidates(), 0);
}

#[test]
fn candidate_budgets_are_enforced() {
    let limits = SignalLimits {
        max_remote_candidates: 4,
        max_buffered_candidates: 2,
        max_local_candidates: 3,
        ..SignalLimits::default()
    };
    let mut s = SignalSession::new(limits, T0).unwrap();
    s.on_frame(&offer(), T0);
    assert!(s.on_frame(&ice(CAND), T0).is_empty());
    assert!(s.on_frame(&ice(CAND), T0).is_empty());
    assert_eq!(
        errs(&s.on_frame(&ice(CAND), T0)),
        vec!["too_many_candidates"]
    );
    assert_eq!(s.buffered_candidates(), 2);
    s.on_event(answer_ready(), T0);
    // 2 flushed, 2 more allowed, then refused.
    assert_eq!(s.on_frame(&ice(CAND), T0).len(), 1);
    assert_eq!(s.on_frame(&ice(CAND), T0).len(), 1);
    assert_eq!(
        errs(&s.on_frame(&ice(CAND), T0)),
        vec!["too_many_candidates"]
    );
    // Local candidates beyond the cap are dropped silently.
    let sent: usize = (0..10)
        .map(|_| s.on_event(HostEvent::LocalCandidate(cand()), T0).len())
        .sum();
    assert_eq!(sent, 3);
}

#[test]
fn malformed_frames_are_dropped_or_refused_without_state_change() {
    for junk in [
        "",
        "not json",
        "[]",
        "null",
        "{}",
        r#"{"t":5,"v":1}"#,
        r#"{"t":"SIGNAL_NOPE","v":1}"#,
        r#"{"t":"SIGNAL_HELLO","v":1,"v":1,"clientId":"a"}"#, // duplicate key
        r#"{"t":"SIGNAL_OFFER","v":1,"kind":"offer","sdp":"x","sdp":"y"}"#,
    ] {
        let mut s = session();
        let a = s.on_frame(junk, T0);
        assert!(errs(&a).is_empty(), "silent drop for {junk:?}");
        assert_eq!(s.state(), SignalState::Idle);
    }
    for bad in [
        json!({"t":"SIGNAL_HELLO","v":2,"clientId":"a"}),
        json!({"t":"SIGNAL_HELLO","v":1}),
        json!({"t":"SIGNAL_HELLO","v":1,"clientId":7}),
        json!({"t":"SIGNAL_HELLO","v":1,"clientId":"x".repeat(129)}),
        json!({"t":"SIGNAL_HELLO","v":1,"clientId":"a\nb"}),
        json!({"t":"SIGNAL_OFFER","v":1,"kind":"answer","sdp":SDP}),
        json!({"t":"SIGNAL_OFFER","v":1,"sdp":SDP}),
        json!({"t":"SIGNAL_OFFER","v":1,"kind":"offer"}),
        json!({"t":"SIGNAL_OFFER","v":1,"kind":"offer","sdp":5}),
    ] {
        let mut s = session();
        let a = s.on_frame(&bad.to_string(), T0);
        assert_eq!(errs(&a), vec!["bad_message"], "{bad}");
        assert_eq!(s.state(), SignalState::Idle);
        assert!(s.last_reject().is_some());
    }
}

#[test]
fn sdp_bounds_and_shape() {
    let limits = SignalLimits::default();
    assert_eq!(check_sdp(SDP, limits.max_sdp_bytes), Ok(()));
    assert!(check_sdp("", 1000).is_err());
    assert!(check_sdp("v=1\r\nm=application 9 x\r\n", 1000).is_err());
    assert!(check_sdp(&format!("{SDP}a=pad:{}\r\n", "x".repeat(70_000)), 65_536).is_err());
    assert!(check_sdp("v=0\r\nm=video 9 RTP/AVP 96\r\n", 1000).is_err());
    assert!(check_sdp("v=0\r\nm=audio 9 RTP/AVP 0\r\n", 1000).is_err());
    assert!(
        check_sdp("v=0\r\ns=-\r\n", 1000).is_err(),
        "needs a data m-line"
    );
    assert!(check_sdp("v=0\r\nm=application 9 x\r\nnonsense\r\n", 1000).is_err());
    assert!(check_sdp("v=0\r\nm=application 9 x\r\na=\u{0}\r\n", 1000).is_err());
    assert!(check_sdp("v=0\r\nm=application 9 x\r\nA=bad\r\n", 1000).is_err());
    let long = format!("v=0\r\nm=application 9 x\r\na={}\r\n", "y".repeat(5000));
    assert!(check_sdp(&long, 20_000).is_err());
    let many = format!("v=0\r\nm=application 9 x\r\n{}", "a=k\r\n".repeat(1100));
    assert!(check_sdp(&many, 20_000).is_err());
    // Oversized SDP in an offer is refused before the host sees it.
    let mut s = session();
    let big = json!({"t":"SIGNAL_OFFER","v":1,"kind":"offer",
        "sdp": format!("{SDP}a=pad:{}\r\n", "x".repeat(70_000))})
    .to_string();
    let a = s.on_frame(&big, T0);
    assert_eq!(errs(&a), vec!["bad_message"]);
    assert_eq!(s.state(), SignalState::Idle);
}

#[test]
fn candidate_shape_is_checked_and_fields_are_rebuilt() {
    let answered = || {
        let mut s = session();
        s.on_frame(&offer(), T0);
        s.on_event(answer_ready(), T0);
        s
    };
    let wrap = |c: Value| json!({"t":"SIGNAL_ICE","v":1,"candidate":c}).to_string();
    for bad in [
        json!({"candidate":"bogus","sdpMid":"0"}),
        json!({"candidate":"candidate:1 1 udp 2 192.0.2.1 5 typ host"}), // too few tokens? has 8
        json!({"candidate":"candidate:1 1 sctp 2 192.0.2.1 5 typ host","sdpMid":"0"}),
        json!({"candidate":"candidate:1 1 udp 2 192.0.2.1 70000 typ host","sdpMid":"0"}),
        json!({"candidate":"candidate:1 1 udp 2 192.0.2.1 5 typ evil","sdpMid":"0"}),
        json!({"candidate":"candidate:1 1 udp 2 192.0.2.1 5 typ host\r\nm=video","sdpMid":"0"}),
        json!({"candidate":CAND}), // no mid and no index
        json!({"candidate":CAND,"sdpMid":"0","sdpMLineIndex":256}),
        json!({"candidate":CAND,"sdpMid":"0","sdpMLineIndex":-1}),
        json!({"candidate":CAND,"sdpMid":"0","sdpMLineIndex":1.5}),
        json!({"candidate":CAND,"sdpMid":"a b"}),
        json!({"candidate":CAND,"sdpMid":"0","usernameFragment":"x".repeat(300)}),
        json!({"candidate":format!("candidate:{}", "1".repeat(2000)),"sdpMid":"0"}),
        json!({"candidate":5}),
        json!("string"),
        json!(null),
    ] {
        let mut s = answered();
        let a = s.on_frame(&wrap(bad.clone()), T0);
        assert!(
            !a.iter().any(|x| matches!(x, Action::AddRemoteCandidate(_))),
            "{bad}"
        );
        assert_eq!(s.state(), SignalState::Answered);
        assert!(errs(&a) == vec!["bad_message"] || a.is_empty(), "{bad}");
    }
    let mut s = answered();
    let a = s.on_frame(
        &wrap(json!({"candidate":CAND,"sdpMLineIndex":1,"sdpMid":null,"evil":"drop me"})),
        T0,
    );
    assert_eq!(
        a,
        vec![Action::AddRemoteCandidate(IceCandidate {
            candidate: CAND.into(),
            sdp_mid: None,
            sdp_mline_index: Some(1),
            username_fragment: None,
        })]
    );
}

#[test]
fn violation_budget_closes_the_socket() {
    let mut s = session();
    let max = SignalLimits::default().max_violations;
    for _ in 0..max {
        assert!(s.on_frame("garbage", T0).is_empty());
    }
    assert_eq!(s.state(), SignalState::Idle);
    let a = s.on_frame("garbage", T0);
    assert_eq!(closed_with(&a), Some(CLOSE_POLICY));
    assert_eq!(errs(&a), vec!["too_many_errors"]);
    assert_eq!(s.state(), SignalState::Closed);
    assert!(s.on_frame(&hello(), T0).is_empty());
}

#[test]
fn oversized_frames_close_with_1009() {
    let limits = SignalLimits::from_max_msg_bytes(4096);
    assert_eq!(limits.max_frame_bytes, 4096);
    assert!(
        limits.validate().is_err(),
        "sdp bound must fit the frame bound"
    );
    let limits = SignalLimits {
        max_sdp_bytes: 2048,
        max_candidate_bytes: 512,
        ..limits
    };
    let mut s = SignalSession::new(limits, T0).unwrap();
    let a = s.on_frame(&" ".repeat(5000), T0);
    assert_eq!(closed_with(&a), Some(CLOSE_MESSAGE_TOO_BIG));
    assert_eq!(s.state(), SignalState::Closed);
}

#[test]
fn message_budget_is_bounded() {
    let limits = SignalLimits {
        max_messages: 5,
        ..SignalLimits::default()
    };
    let mut s = SignalSession::new(limits, T0).unwrap();
    let m = json!({"t":"SIGNAL_ERR","v":1,"code":"x","msg":"y"}).to_string();
    for _ in 0..5 {
        assert!(s.on_frame(&m, T0).is_empty());
    }
    let a = s.on_frame(&m, T0);
    assert_eq!(errs(&a), vec!["rate_limited"]);
    assert_eq!(closed_with(&a), Some(CLOSE_POLICY));
}

#[test]
fn idle_session_times_out() {
    let mut s = session();
    let d = s.deadline_ms().unwrap();
    assert_eq!(d, T0 + 30_000);
    assert!(s.expire(d - 1).is_empty());
    let a = s.expire(d);
    assert_eq!(errs(&a), vec!["timeout"]);
    assert_eq!(closed_with(&a), Some(CLOSE_TIMEOUT));
    assert!(!a.contains(&Action::ClosePeer), "no peer was created");
    assert_eq!(s.state(), SignalState::Closed);
    assert!(s.expire(d + 1).is_empty());
}

#[test]
fn unanswered_offer_times_out_and_closes_the_peer() {
    let mut s = session();
    s.on_frame(&offer(), T0 + 100);
    assert_eq!(s.deadline_ms(), Some(T0 + 100 + 15_000));
    assert!(s.expire(T0 + 14_999).is_empty());
    let a = s.expire(T0 + 15_100);
    assert!(a.contains(&Action::ClosePeer));
    assert_eq!(closed_with(&a), Some(CLOSE_TIMEOUT));
    assert_eq!(s.pending_offers(), 0);
    // A late answer from the host after the timeout changes nothing.
    assert!(s.on_event(answer_ready(), T0 + 16_000).is_empty());
    assert_eq!(s.state(), SignalState::Closed);
}

#[test]
fn data_channel_must_open_in_time_and_established_has_no_deadline() {
    let mut s = session();
    to_answered(&mut s);
    assert_eq!(s.deadline_ms(), Some(T0 + 2 + 60_000));
    let a = s.expire(T0 + 2 + 60_000);
    assert!(a.contains(&Action::ClosePeer));
    assert_eq!(closed_with(&a), Some(CLOSE_TIMEOUT));

    let mut s = session();
    to_answered(&mut s);
    s.on_event(HostEvent::DataChannelOpen, T0 + 10);
    assert!(s.expire(T0 + 10_000_000).is_empty());
    assert_eq!(s.state(), SignalState::Established);
}

#[test]
fn backwards_clock_never_shortens_a_deadline() {
    let mut s = session();
    s.on_frame(&offer(), T0 + 1000);
    // The clock steps back before the offer began; the deadline stays anchored to the
    // clamped time, and going back cannot trigger an early or underflowing expiry.
    assert!(s.expire(5).is_empty());
    assert_eq!(s.deadline_ms(), Some(T0 + 1000 + 15_000));
}

#[test]
fn host_failure_sends_fixed_text_closes_peer_and_ignores_the_rest() {
    let mut s = session();
    s.on_frame(&offer(), T0);
    let a = s.on_event(HostEvent::PeerFailed, T0 + 1);
    match &a[0] {
        Action::Send(v) => {
            assert_eq!(v["code"], "internal");
            assert_eq!(v["msg"], "internal error"); // legacy leaked e.message
        }
        other => panic!("{other:?}"),
    }
    assert!(a.contains(&Action::ClosePeer));
    assert_eq!(closed_with(&a), Some(CLOSE_INTERNAL));
    assert_eq!(s.state(), SignalState::Closed);
    for ev in [
        HostEvent::PeerFailed,
        HostEvent::SocketClosed,
        answer_ready(),
        HostEvent::DataChannelOpen,
        HostEvent::LocalCandidate(cand()),
    ] {
        assert!(s.on_event(ev, T0 + 2).is_empty(), "cleanup is idempotent");
    }
    assert!(s.on_frame(&offer(), T0 + 3).is_empty());
}

#[test]
fn an_invalid_answer_from_the_host_is_an_internal_failure() {
    let mut s = session();
    s.on_frame(&offer(), T0);
    let a = s.on_event(HostEvent::AnswerReady { sdp: "junk".into() }, T0);
    assert_eq!(errs(&a), vec!["internal"]);
    assert_eq!(s.state(), SignalState::Closed);
    assert!(!a
        .iter()
        .any(|x| matches!(x, Action::Send(v) if v["t"] == "SIGNAL_ANSWER")));
}

#[test]
fn socket_close_cleans_up_by_state() {
    let mut s = session();
    assert!(s.on_event(HostEvent::SocketClosed, T0).is_empty());
    assert_eq!(s.state(), SignalState::Closed);

    for target in [
        SignalState::Offering,
        SignalState::Answered,
        SignalState::Established,
    ] {
        let mut s = session();
        s.on_frame(&offer(), T0);
        s.on_frame(&ice(CAND), T0);
        if target != SignalState::Offering {
            s.on_event(answer_ready(), T0);
        }
        if target == SignalState::Established {
            s.on_event(HostEvent::DataChannelOpen, T0);
        }
        assert_eq!(s.state(), target);
        let a = s.on_event(HostEvent::SocketClosed, T0 + 1);
        assert_eq!(a, vec![Action::ClosePeer]);
        assert_eq!(s.state(), SignalState::Closed);
        assert_eq!(s.buffered_candidates(), 0);
        assert!(s.on_event(HostEvent::SocketClosed, T0 + 2).is_empty());
    }
}

#[test]
fn stale_or_impossible_host_events_change_nothing() {
    let mut s = session();
    assert!(s.on_event(answer_ready(), T0).is_empty());
    assert!(s.on_event(HostEvent::DataChannelOpen, T0).is_empty());
    assert!(s.on_event(HostEvent::PeerFailed, T0).is_empty());
    assert!(s.on_event(HostEvent::LocalCandidate(cand()), T0).is_empty());
    assert_eq!(s.state(), SignalState::Idle);
    s.on_frame(&offer(), T0);
    assert!(s.on_event(HostEvent::DataChannelOpen, T0).is_empty());
    assert_eq!(s.state(), SignalState::Offering);
}

#[test]
fn limits_are_validated() {
    let d = SignalLimits::default();
    assert!(d.validate().is_ok());
    for bad in [
        SignalLimits {
            max_frame_bytes: 10,
            ..d.clone()
        },
        SignalLimits {
            max_sdp_bytes: d.max_frame_bytes,
            ..d.clone()
        },
        SignalLimits {
            max_candidate_bytes: 8,
            ..d.clone()
        },
        SignalLimits {
            max_remote_candidates: 0,
            ..d.clone()
        },
        SignalLimits {
            max_buffered_candidates: 9999,
            ..d.clone()
        },
        SignalLimits {
            max_violations: 0,
            ..d.clone()
        },
        SignalLimits {
            max_messages: 0,
            ..d.clone()
        },
        SignalLimits {
            idle_timeout_ms: 0,
            ..d.clone()
        },
        SignalLimits {
            offer_timeout_ms: 0,
            ..d.clone()
        },
        SignalLimits {
            connect_timeout_ms: 0,
            ..d.clone()
        },
    ] {
        assert!(SignalSession::new(bad, T0).is_err());
    }
}

#[test]
fn edge_table_matches_the_documented_diagram() {
    use SignalState::*;
    let all = [Idle, Greeted, Offering, Answered, Established, Closed];
    let allowed: Vec<(SignalState, SignalState)> = all
        .iter()
        .flat_map(|a| all.iter().map(move |b| (*a, *b)))
        .filter(|(a, b)| a != b && edge_allowed(*a, *b))
        .collect();
    assert_eq!(
        allowed,
        vec![
            (Idle, Greeted),
            (Idle, Offering),
            (Idle, Closed),
            (Greeted, Offering),
            (Greeted, Closed),
            (Offering, Answered),
            (Offering, Closed),
            (Answered, Established),
            (Answered, Closed),
            (Established, Closed),
        ]
    );
    assert!(!edge_allowed(Closed, Idle));
    assert!(!edge_allowed(Established, Offering));
    assert!(!edge_allowed(Answered, Offering));
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn random_walk_only_follows_allowed_edges_and_keeps_every_bound() {
    let limits = SignalLimits {
        max_remote_candidates: 6,
        max_buffered_candidates: 3,
        max_local_candidates: 5,
        max_violations: 4,
        max_messages: 60,
        ..SignalLimits::default()
    };
    let frames = [
        hello(),
        offer(),
        ice(CAND),
        ice(""),
        "garbage".to_string(),
        json!({"t":"SIGNAL_ANSWER","v":1,"kind":"answer","sdp":SDP}).to_string(),
        json!({"t":"SIGNAL_ERR","v":1,"code":"x","msg":"y"}).to_string(),
        json!({"t":"SIGNAL_OFFER","v":1,"kind":"offer","sdp":"nope"}).to_string(),
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut transitions = 0usize;
    for _ in 0..400 {
        let mut s = SignalSession::new(limits.clone(), T0).unwrap();
        let mut now = T0;
        for _ in 0..80 {
            now += rng.next() % 600;
            let before = s.state();
            let actions = match rng.pick(8) {
                0..=3 => s.on_frame(&frames[rng.pick(frames.len())], now),
                4 => s.on_event(answer_ready(), now),
                5 => s.on_event(HostEvent::LocalCandidate(cand()), now),
                6 => match rng.pick(3) {
                    0 => s.on_event(HostEvent::DataChannelOpen, now),
                    1 => s.on_event(HostEvent::PeerFailed, now),
                    _ => s.on_event(HostEvent::SocketClosed, now),
                },
                _ => s.expire(now),
            };
            let after = s.state();
            assert!(edge_allowed(before, after), "{before:?} -> {after:?}");
            if before != after {
                transitions += 1;
            }
            assert!(s.pending_offers() <= 1);
            assert!(s.offers_accepted() <= 1);
            assert!(s.buffered_candidates() <= 3 + 5);
            let applies = actions
                .iter()
                .filter(|a| matches!(a, Action::ApplyOffer { .. }))
                .count();
            assert!(applies <= 1);
            if before == SignalState::Closed {
                assert!(actions.is_empty(), "nothing after close");
            }
            if after == SignalState::Closed && before != SignalState::Closed {
                let socket_closed = actions
                    .iter()
                    .filter(|a| matches!(a, Action::CloseSocket { .. }))
                    .count();
                assert!(socket_closed <= 1);
            }
        }
    }
    assert!(
        transitions > 600,
        "the walk must exercise the machine: {transitions}"
    );
}
