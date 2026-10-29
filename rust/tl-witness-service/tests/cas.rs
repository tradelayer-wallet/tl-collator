use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::{
    fs, io::Cursor, path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tl_collator_wire::{
    order_id, tape_entry_hash, tape_signature_hash,
    verify::Checkpoint, witness::{WitnessError, WitnessScope},
};
use tl_witness_service::{Config, Error, WitnessService};

static N: AtomicU64=AtomicU64::new(0);
struct Tmp(PathBuf);
impl Tmp {
    fn new()->Self {
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let n=N.fetch_add(1,Ordering::Relaxed);
        let p=std::env::temp_dir().join(format!("tl-witness-cas-{}-{now}-{n}",std::process::id()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self)->&Path{&self.0}
    fn tape(&self)->PathBuf {self.0.join("witness.ndjson")}
}
impl Drop for Tmp {
    fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}
}
fn pubkey(k:&[u8;32])->String {
    let ctx=Secp256k1::new();
    let sk=SecretKey::from_slice(k).unwrap();
    PublicKey::from_secret_key(&ctx,&sk).serialize()
        .iter().map(|b|format!("{b:02x}")).collect()
}
fn sign(message_hex:&str,key:&[u8;32])->String {
    let mut h=[0u8;32];
    for (i,b) in h.iter_mut().enumerate(){
        *b=u8::from_str_radix(&message_hex[2*i..2*i+2],16).unwrap();
    }
    Secp256k1::new().sign_ecdsa(
        &Message::from_digest(h),&SecretKey::from_slice(key).unwrap()
    ).serialize_compact().iter().map(|b|format!("{b:02x}")).collect()
}
fn order(n:u64)->Value {
    let mut v=json!({
        "v":1,"kind":"NEW",
        "body":{"v":1,"market":"SPOT:LTC/USDT",
          "side":"BUY","px":"72.50","qty":"10.0",
          "visibility":{"kind":"PUBLIC"},"clientTs":1700000000000_u64},
        "traderPubKey":pubkey(&[1u8;32]),"clientNonce":format!("{n:016x}"),
    });
    let hash=order_id(&v).unwrap();
    v["orderId"]=json!(hash);
    v["sigTrader"]=json!(sign(&hash,&[1u8;32]));
    v
}
fn entry(seq:u64, prev:&str, order:Value)->String {
    let mut v=json!({"v":1,"collatorId":"collator-test","seq":seq,
        "prevHash":prev,"receivedTs":1700000000010_u64,"order":order});
    let hash=tape_entry_hash(&v).unwrap();
    v["entryHash"]=json!(hash);
    let payload=tape_signature_hash(&v,&hash).unwrap();
    v["sigCollator"]=json!(sign(&payload,&[3u8;32]));
    v.to_string()
}
fn config(network:&str)->Config {
    Config {collator_id:"collator-test".into(),collator_pubkey:pubkey(&[3u8;32]),
        network:network.into(),stream:"orders".into(),epoch:3,max_entries:50}
}
fn open(t:&Tmp)->WitnessService {
    WitnessService::open(t.path(),config("LTCTEST"),&[5u8;32]).unwrap()
}
fn challenge()->String {"ab".repeat(32)}
fn scope()->WitnessScope {
    WitnessScope::new("collator-test","LTCTEST","orders",3,&pubkey(&[5u8;32])).unwrap()
}

#[test]
fn genesis_latest_is_signed_and_bound_to_challenge() {
    let t=Tmp::new();
    let svc=open(&t);
    assert_eq!(svc.checkpoint().last_seq,0);
    assert_eq!(svc.public_key(),pubkey(&[5u8;32]));
    let raw=svc.attest_latest(&challenge()).unwrap();
    let proof=scope().verify_receipt(&raw,&challenge()).unwrap();
    assert_eq!(proof.seq(),0);
    assert_eq!(proof.head_hash(),"");
    assert!(svc.attest_latest(&"0".repeat(64)).is_err());
    assert!(svc.attest_latest("not a challenge").is_err());
    assert_eq!(scope().verify_receipt(&raw,&"cd".repeat(32)),Err(WitnessError::StaleChallenge));
}
#[test]
fn cas_advances_only_on_fully_signed_next_entry() {
    let t=Tmp::new();
    let mut svc=open(&t);
    let before=svc.checkpoint();
    let one=entry(1,"",order(1));
    let after=svc.compare_and_swap(&before,&one).unwrap();
    assert_eq!(after.last_seq,1);
    assert_eq!(after.seen_orders,1);
    let receipt=svc.attest_latest(&challenge()).unwrap();
    let verified=scope().verify_receipt(&receipt,&challenge()).unwrap();
    assert_eq!(verified.seq(),1);
    assert_eq!(verified.head_hash(),after.last_hash);
    assert_eq!(scope().verify_tape(
        Cursor::new(fs::read(t.tape()).unwrap()),&pubkey(&[3u8;32]),50,&verified
    ).unwrap(),after);
}
#[test]
fn stale_cas_and_duplicate_signed_orders_are_rejected() {
    let t=Tmp::new();
    let mut svc=open(&t);
    let start=svc.checkpoint();
    let first=entry(1,"",order(2));
    let after=svc.compare_and_swap(&start,&first).unwrap();
    assert!(matches!(svc.compare_and_swap(&start,&first),Err(Error::Conflict)));
    let duplicated=entry(2,&after.last_hash,order(2));
    assert!(matches!(svc.compare_and_swap(&after,&duplicated),Err(Error::Durable(_))));
    assert_eq!(svc.checkpoint(),after);
}
#[test]
fn invalid_signatures_and_branches_never_advance_cas() {
    let t=Tmp::new();
    let mut svc=open(&t);
    let start=svc.checkpoint();
    let mut changed:Value=serde_json::from_str(&entry(1,"",order(3))).unwrap();
    changed["sigCollator"]=json!("11".repeat(64));
    assert!(svc.compare_and_swap(&start,&changed.to_string()).is_err());
    let wrong=entry(3,"",order(4));
    assert!(svc.compare_and_swap(&start,&wrong).is_err());
    let nonmatching=entry(1,&"a".repeat(64),order(5));
    assert!(svc.compare_and_swap(&start,&nonmatching).is_err());
    assert_eq!(svc.checkpoint(),start);
    assert_eq!(fs::read(t.tape()).unwrap(),b"");
}
#[test]
fn witness_restart_rejects_rollback_and_recovers_signed_head() {
    let t=Tmp::new();
    let mut service=open(&t);
    let a=service.compare_and_swap(&service.checkpoint(),&entry(1,"",order(6))).unwrap();
    service.compare_and_swap(&a,&entry(2,&a.last_hash,order(7))).unwrap();
    let final_head=service.checkpoint();
    assert!(WitnessService::open(t.path(),config("LTCTEST"),&[5u8;32]).is_err());
    drop(service);
    let resumed=open(&t);
    assert_eq!(resumed.checkpoint(),final_head);
    assert_eq!(scope().verify_receipt(&resumed.attest_latest(&challenge()).unwrap(),&challenge()).unwrap().seq(),2);
}
#[test]
fn persistent_scope_cannot_change_network_epoch_or_signing_key() {
    let t=Tmp::new();
    let mut service=open(&t);
    let before=service.checkpoint();
    service.compare_and_swap(&before,&entry(1,"",order(101))).unwrap();
    let written=fs::read(t.tape()).unwrap();
    drop(service);
    assert!(matches!(
        WitnessService::open(t.path(),config("BTC"),&[5u8;32]),
        Err(Error::InvalidStoredScope)
    ));
    let mut new_epoch=config("LTCTEST");
    new_epoch.epoch=4;
    assert!(matches!(
        WitnessService::open(t.path(),new_epoch,&[5u8;32]),
        Err(Error::InvalidStoredScope)
    ));
    assert!(matches!(
        WitnessService::open(t.path(),config("LTCTEST"),&[4u8;32]),
        Err(Error::InvalidStoredScope)
    ));
    assert_eq!(fs::read(t.tape()).unwrap(),written);
}
#[test]
fn missing_or_corrupt_persistent_scope_with_history_fails_closed() {
    let t=Tmp::new();
    let mut svc=open(&t);
    svc.compare_and_swap(&svc.checkpoint(),&entry(1,"",order(201))).unwrap();
    drop(svc);
    let stored=fs::read(t.tape()).unwrap();
    fs::remove_file(t.path().join("witness.scope")).unwrap();
    assert!(matches!(WitnessService::open(t.path(),config("LTCTEST"),&[5u8;32]),
        Err(Error::InvalidStoredScope)));
    assert_eq!(fs::read(t.tape()).unwrap(),stored);
}
#[test]
fn foreign_scope_or_witness_key_cannot_authenticate() {
    let t=Tmp::new();
    assert!(WitnessService::open(t.path(),config("LTCTEST"),&[3u8;32]).is_err());
    let service=open(&t);
    let raw=service.attest_latest(&challenge()).unwrap();
    let wrong=WitnessScope::new("collator-test","BTC","orders",3,&pubkey(&[5u8;32])).unwrap();
    assert_eq!(wrong.verify_receipt(&raw,&challenge()),Err(WitnessError::WrongScope));
    let wrong_key=WitnessScope::new("collator-test","LTCTEST","orders",3,&pubkey(&[4u8;32])).unwrap();
    assert_eq!(wrong_key.verify_receipt(&raw,&challenge()),Err(WitnessError::BadSignature));
}
#[test]
fn witness_signs_only_latest_even_if_caller_expects_old_head() {
    let t=Tmp::new();
    let mut service=open(&t);
    let earlier=service.checkpoint();
    let advanced=service.compare_and_swap(&earlier,&entry(1,"",order(8))).unwrap();
    assert_eq!(service.checkpoint(),advanced);
    let v:Value=serde_json::from_str(&service.attest_latest(&challenge()).unwrap()).unwrap();
    assert_eq!(v["seq"],1);
    assert_eq!(v["headHash"],advanced.last_hash);
}
#[test]
fn exact_cas_checks_prev_hash_and_owner_count() {
    let t=Tmp::new();
    let mut service=open(&t);
    let mut bogus=service.checkpoint();
    bogus.seen_orders+=1;
    assert!(matches!(service.compare_and_swap(&bogus,&entry(1,"",order(9))),Err(Error::Conflict)));
    bogus.seen_orders=0;
    bogus.last_hash="ab".repeat(32);
    assert!(matches!(service.compare_and_swap(&bogus,&entry(1,"",order(10))),Err(Error::Conflict)));
    assert_eq!(service.checkpoint(),Checkpoint{last_seq:0,last_hash:String::new(),seen_orders:0});
}
