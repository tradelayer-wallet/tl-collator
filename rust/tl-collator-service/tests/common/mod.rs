#![allow(dead_code)]
//! Shared fixtures: synthetic keys only, regtest-style names, deterministic clock.
use serde_json::{json, Value};
use std::cell::RefCell;
use std::rc::Rc;
use tl_collator_service::audit::{AuditError, AuditSink};
use tl_collator_service::bitvm::{ArtifactSource, Artifacts};
use tl_collator_service::clearlist::{ClearlistOracle, ClearlistResult, OracleError};
use tl_collator_service::config::{Config, Env};
use tl_collator_service::http::{Forwarded, HttpRequest};
use tl_collator_service::ipintel::{IntelError, IpIntel, IpIntelSource};
use tl_collator_service::manifest::BuildInfo;
use tl_collator_service::signer::{DigestSigner, SecretKeySigner};
use tl_collator_service::tape::MemoryTape;
use tl_collator_service::{HostSession, Out, Service, ServiceParts};
use tl_collator_wire::{canonical_json, order_id, sha256_hex};
use tl_rpc_router::{ProviderPin, DOMAIN};

pub const COLLATOR: &str = "collator-test";
pub const SERVICE: &str = "tradelayer.rpc";
pub const NETWORK: &str = "ltc-testnet";
pub const T0: u64 = 1_700_000_000_000;

pub fn secret(n: u8) -> SecretKeySigner {
    SecretKeySigner::from_bytes(&[n; 32]).expect("synthetic key")
}

pub fn env_with(extra: &[(&str, &str)]) -> Env {
    let mut env = Env::new();
    env.insert("TL_COLLATOR_RPC_NETWORK".into(), NETWORK.into());
    for (k, v) in extra {
        env.insert((*k).into(), (*v).into());
    }
    env
}

pub fn config_with(extra: &[(&str, &str)]) -> Config {
    Config::from_env(&env_with(extra)).expect("config")
}

/// A signed order from the synthetic trader `n`.
pub fn order(n: u8, nonce: u64, kind: &str, target: Option<&str>, visibility: Value) -> Value {
    let trader = secret(n);
    let mut v = json!({
        "v": 1, "kind": kind,
        "body": {"v": 1, "market": "SPOT:LTC/USDT", "side": "BUY", "px": "72.50", "qty": "10",
                 "visibility": visibility, "clientTs": 1_700_000_000_000_u64},
        "traderPubKey": trader.public_key_hex(),
        "clientNonce": format!("{nonce:016x}"),
    });
    if let Some(t) = target {
        let name = if kind == "CANCEL" {
            "cancelsOrderId"
        } else {
            "replacesOrderId"
        };
        v[name] = json!(t);
    }
    let id = order_id(&v).expect("order id");
    v["sigTrader"] = json!(trader.sign_digest(&id).expect("sign"));
    v["orderId"] = json!(id);
    v
}

pub fn new_order(n: u8, nonce: u64) -> Value {
    order(n, nonce, "NEW", None, json!({"kind": "PUBLIC"}))
}

pub fn submit_msg(order: &Value) -> String {
    json!({"t": "SUBMIT", "v": 1, "order": order}).to_string()
}

// ---- fakes ----------------------------------------------------------------------------

pub struct OracleScript {
    pub answer: Result<bool, ()>,
    pub calls: Vec<(String, String)>,
}
pub struct SharedOracle(pub Rc<RefCell<OracleScript>>);
impl ClearlistOracle for SharedOracle {
    fn check(&mut self, g: &str, p: &str) -> Result<ClearlistResult, OracleError> {
        let mut s = self.0.borrow_mut();
        s.calls.push((g.to_owned(), p.to_owned()));
        match s.answer {
            Ok(allowed) => Ok(ClearlistResult {
                allowed,
                snapshot_id: None,
                exp_ts: None,
            }),
            Err(()) => Err(OracleError("down".into())),
        }
    }
}

pub struct IntelScript {
    pub answer: Result<IpIntel, ()>,
    pub calls: Vec<String>,
}
pub struct SharedIntel(pub Rc<RefCell<IntelScript>>);
impl IpIntelSource for SharedIntel {
    fn lookup(&mut self, ip: &str) -> Result<IpIntel, IntelError> {
        let mut s = self.0.borrow_mut();
        s.calls.push(ip.to_owned());
        s.answer.map_err(|()| IntelError("down".into()))
    }
}

pub struct SharedAudit(pub Rc<RefCell<Vec<String>>>);
impl AuditSink for SharedAudit {
    fn write(&mut self, line: &str) -> Result<(), AuditError> {
        self.0.borrow_mut().push(line.to_owned());
        Ok(())
    }
}

pub struct SharedArtifacts(pub Rc<RefCell<Artifacts>>);
impl ArtifactSource for SharedArtifacts {
    fn load(&mut self) -> Artifacts {
        self.0.borrow().clone()
    }
}

pub struct Fakes {
    pub oracle: Rc<RefCell<OracleScript>>,
    pub intel: Rc<RefCell<IntelScript>>,
    pub audit: Rc<RefCell<Vec<String>>>,
    pub artifacts: Rc<RefCell<Artifacts>>,
}

pub struct Harness {
    pub svc: Service,
    pub fakes: Fakes,
    pub now: u64,
    next_session: u64,
}

pub fn pins() -> Vec<ProviderPin> {
    vec![
        ProviderPin {
            node_id: "node-a".into(),
            public_key: secret(11).public_key_hex(),
            methods: vec![
                "tl_getinfo".into(),
                "tl_getproperty".into(),
                "tl_gettransaction".into(),
            ],
        },
        ProviderPin {
            node_id: "node-b".into(),
            public_key: secret(12).public_key_hex(),
            methods: vec!["tl_getinfo".into()],
        },
    ]
}

impl Harness {
    pub fn new(extra: &[(&str, &str)]) -> Harness {
        Self::with_config(config_with(extra))
    }

    pub fn with_config(cfg: Config) -> Harness {
        let collator = secret(3);
        let fakes = Fakes {
            oracle: Rc::new(RefCell::new(OracleScript {
                answer: Ok(true),
                calls: vec![],
            })),
            intel: Rc::new(RefCell::new(IntelScript {
                answer: Ok(IpIntel::default()),
                calls: vec![],
            })),
            audit: Rc::new(RefCell::new(vec![])),
            artifacts: Rc::new(RefCell::new(Artifacts::default())),
        };
        let tape =
            MemoryTape::new(COLLATOR, &collator.public_key_hex(), secret(3), 10_000).expect("tape");
        let parts = ServiceParts {
            collator_id: COLLATOR.into(),
            collator_pubkey: collator.public_key_hex(),
            build: BuildInfo {
                version: "0.1.0".into(),
                git_sha: Some("abc123".into()),
                built_at: "2026-10-30T00:00:00.000Z".into(),
            },
            signer: Box::new(secret(3)),
            tape: Box::new(tape),
            clearlist_oracle: Some(Box::new(SharedOracle(fakes.oracle.clone()))),
            ip_intel: Some(Box::new(SharedIntel(fakes.intel.clone()))),
            audit: Some(Box::new(SharedAudit(fakes.audit.clone()))),
            artifacts: Box::new(SharedArtifacts(fakes.artifacts.clone())),
            bitvm_collateral_property_id: None,
            provider_pins: pins(),
            boot_secret: [9; 32],
            attestations: None,
        };
        let svc = Service::new(cfg, parts, T0).expect("service");
        Harness {
            svc,
            fakes,
            now: T0,
            next_session: 1,
        }
    }

    pub fn connect(&mut self, ip: &str) -> HostSession {
        let h = HostSession(self.next_session);
        self.next_session += 1;
        self.svc
            .open_session(h, Some(ip), Some("test-agent"), self.now)
            .expect("open");
        self.svc.channel_opened(h, self.now).expect("channel");
        h
    }

    pub fn tick(&mut self, ms: u64) {
        self.now += ms;
    }

    pub fn msg(&mut self, h: HostSession, text: &str) -> Vec<Out> {
        self.svc.on_message(h, text, self.now)
    }

    pub fn msg_json(&mut self, h: HostSession, v: &Value) -> Vec<Out> {
        let text = v.to_string();
        self.msg(h, &text)
    }

    /// Authenticate `h` as provider `node` (key byte `key`), advertising `methods`.
    pub fn authenticate(&mut self, h: HostSession, node: &str, key: u8, methods: &[&str]) {
        let outs = self.msg_json(
            h,
            &json!({"t":"RPC_ADVERTISE","v":1,"nodeId":node,"services":[]}),
        );
        let nonce = sent(&outs, h)
            .iter()
            .find(|m| m["t"] == "RPC_CHALLENGE")
            .and_then(|m| m["challenge"].as_str().map(str::to_owned))
            .expect("challenge");
        let proof = provider_proof(node, key, &nonce, methods);
        let outs = self.msg_json(
            h,
            &json!({"t":"RPC_ADVERTISE","v":1,"nodeId":node,"services":[],"proof":proof}),
        );
        assert!(
            sent(&outs, h).is_empty(),
            "authentication must succeed silently"
        );
    }
}

pub fn provider_proof(node: &str, key: u8, nonce: &str, methods: &[&str]) -> String {
    let fields = json!({
        "domain": DOMAIN, "v": 1, "collatorId": COLLATOR, "service": SERVICE,
        "network": NETWORK, "nodeId": node, "challenge": nonce, "methods": methods,
    });
    let digest = sha256_hex(&canonical_json(&fields).expect("canonical"));
    let mut full = fields;
    full["sigProvider"] = json!(secret(key).sign_digest(&digest).expect("sign"));
    canonical_json(&full).expect("canonical proof")
}

pub fn sent(outs: &[Out], to: HostSession) -> Vec<Value> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Send { to: t, msg } if *t == to => Some(msg.clone()),
            _ => None,
        })
        .collect()
}

pub fn err_codes(outs: &[Out], to: HostSession) -> Vec<String> {
    sent(outs, to)
        .iter()
        .filter(|m| m["t"] == "ERR")
        .filter_map(|m| m["code"].as_str().map(str::to_owned))
        .collect()
}

pub fn http(method: &str, path: &str, body: Option<&Value>) -> HttpRequest {
    HttpRequest {
        method: method.into(),
        path: path.into(),
        origin: None,
        peer_ip: "192.0.2.10".into(),
        forwarded: Forwarded::default(),
        body: body.map(|b| b.to_string().into_bytes()).unwrap_or_default(),
    }
}
