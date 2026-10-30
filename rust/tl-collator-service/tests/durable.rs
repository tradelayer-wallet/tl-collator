#![cfg(unix)]
mod common;
use common::*;
use serde_json::json;
use std::path::PathBuf;
use tl_collator_service::config::Config;
use tl_collator_service::manifest::BuildInfo;
use tl_collator_service::tape::{DurableSignedTape, TapeError, TapeStore};
use tl_collator_service::{HostSession, Out, Service, ServiceParts};
use tl_collator_wire::durable::{DurableTape, ImportMode};

struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("tl-service-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open(dir: &Dir) -> DurableSignedTape<tl_collator_service::signer::SecretKeySigner> {
    let tape = DurableTape::open(
        &dir.0,
        "orders",
        COLLATOR,
        &secret(3).public_key_hex(),
        256,
        ImportMode::RequireAnchor,
    )
    .expect("open durable tape");
    DurableSignedTape::new(COLLATOR, secret(3), tape, dir.0.join("orders.ndjson"))
}

#[test]
fn durable_adapter_appends_reads_ranges_and_survives_reopen() {
    let dir = Dir::new("adapter");
    {
        let mut t = open(&dir);
        for n in 1..=4 {
            let e = t.append_order(&new_order(21, n), T0 + n).unwrap();
            assert_eq!(e.seq, n);
        }
        assert_eq!(t.last_seq(), 4);
        assert!(t.contains_order(new_order(21, 2)["orderId"].as_str().unwrap()));
        let range = t.read_range(2, 2).unwrap();
        assert_eq!(range.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);
        assert!(t.read_range(9, 5).unwrap().is_empty());
        // The wire crate's duplicate rule is the authority.
        assert_eq!(
            t.append_order(&new_order(21, 2), T0 + 9),
            Err(TapeError::Duplicate)
        );
        // Ownership is enforced at commit even though the adapter has no precheck.
        let target = new_order(21, 1)["orderId"].as_str().unwrap().to_owned();
        let theirs = order(22, 50, "CANCEL", Some(&target), json!({"kind":"PUBLIC"}));
        assert_eq!(t.append_order(&theirs, T0 + 10), Err(TapeError::NotOwner));
        assert_eq!(t.last_seq(), 4);
    }
    // Reopen: state recovered from disk, appends continue the chain.
    let mut t = open(&dir);
    assert_eq!(t.last_seq(), 4);
    assert_eq!(t.append_order(&new_order(21, 5), T0 + 20).unwrap().seq, 5);
    assert_eq!(t.read_range(1, 100).unwrap().len(), 5);
}

#[test]
fn reducer_runs_on_the_durable_tape() {
    let dir = Dir::new("reducer");
    let cfg: Config = config_with(&[]);
    let collator = secret(3);
    let parts = ServiceParts {
        collator_id: COLLATOR.into(),
        collator_pubkey: collator.public_key_hex(),
        build: BuildInfo {
            version: "0.1.0".into(),
            git_sha: None,
            built_at: "2026-10-30T00:00:00.000Z".into(),
        },
        signer: Box::new(secret(3)),
        tape: Box::new(open(&dir)),
        clearlist_oracle: None,
        ip_intel: None,
        audit: None,
        artifacts: Box::new(SharedArtifacts(Default::default())),
        bitvm_collateral_property_id: None,
        provider_pins: pins(),
        boot_secret: [4; 32],
        attestations: None,
    };
    let mut svc = Service::new(cfg, parts, T0).unwrap();
    let h = HostSession(1);
    svc.open_session(h, Some("203.0.113.1"), None, T0).unwrap();
    svc.channel_opened(h, T0).unwrap();
    let o = new_order(21, 1);
    assert!(svc.on_message(h, &submit_msg(&o), T0).is_empty());
    let outs = svc.on_message(h, r#"{"t":"TAPE_SUB","v":1}"#, T0 + 1);
    let entries: Vec<_> = outs
        .iter()
        .filter_map(|o| match o {
            Out::Send { msg, .. } if msg["t"] == "TAPE_ENTRY" => Some(msg["entry"].clone()),
            _ => None,
        })
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["order"]["orderId"], o["orderId"]);
}
