use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::io::Cursor;
use tl_collator_wire::{
    order_id, sha256_hex, tape_entry_hash, tape_signature_hash,
    verify::{verify_compact, VerifyError, VerifiedReplay},
};

fn encode_hex(data:&[u8])->String {
    data.iter().map(|b|format!("{b:02x}")).collect()
}
fn decode_hex(s:&str)->[u8;32]{
    assert_eq!(s.len(),64);
    let mut out=[0u8;32];
    for (i,b) in out.iter_mut().enumerate(){
        *b=u8::from_str_radix(&s[2*i..2*i+2],16).unwrap();
    }
    out
}
struct Synthetic {
    secp: Secp256k1<secp256k1::All>,
    trader: SecretKey,
    other: SecretKey,
    collator: SecretKey,
}
impl Synthetic {
    fn new()->Self {
        Self {
            secp:Secp256k1::new(),
            trader:SecretKey::from_slice(&[0x11;32]).unwrap(),
            other:SecretKey::from_slice(&[0x22;32]).unwrap(),
            collator:SecretKey::from_slice(&[0x33;32]).unwrap(),
        }
    }
    fn public(&self,secret:&SecretKey)->String {
        encode_hex(&PublicKey::from_secret_key(&self.secp,secret).serialize())
    }
    fn sign(&self,hash:&str,key:&SecretKey)->String {
        let msg=Message::from_digest(decode_hex(hash));
        encode_hex(&self.secp.sign_ecdsa(msg,key).serialize_compact())
    }
    fn verifier(&self,cap:usize)->VerifiedReplay {
        VerifiedReplay::new("collator-test",&self.public(&self.collator),cap).unwrap()
    }
    fn order(&self,kind:&str,key:&SecretKey,target:Option<&str>,nonce:&str)->Value {
        let mut v=json!({
            "v":1,
            "kind":kind,
            "body":{
                "v":1,"market":"SPOT:LTC/USDT",
                "side":"BUY","px":"72.50","qty":"10.0",
                "visibility":{"kind":"PUBLIC"},
                "clientTs":1700000000000_u64
            },
            "traderPubKey":self.public(key),
            "clientNonce":nonce,
        });
        if let Some(id)=target {
            let field=if kind=="CANCEL"{"cancelsOrderId"}else{"replacesOrderId"};
            v[field]=json!(id);
        }
        let id=order_id(&v).unwrap();
        v["orderId"]=json!(id);
        v["sigTrader"]=json!(self.sign(&id,key));
        v
    }
    fn tape(&self,seq:u64,prev:&str,order:Value)->Value {
        let mut v=json!({
            "v":1,"collatorId":"collator-test","seq":seq,
            "prevHash":prev,"receivedTs":1700000000001_u64,"order":order,
        });
        let hash=tape_entry_hash(&v).unwrap();
        v["entryHash"]=json!(hash);
        let payload=tape_signature_hash(&v,&hash).unwrap();
        v["sigCollator"]=json!(self.sign(&payload,&self.collator));
        v
    }
}
fn feed(verifier:&mut VerifiedReplay,v:&Value)->Result<tl_collator_wire::verify::Checkpoint,VerifyError>{
    verifier.apply_line(&serde_json::to_string(v).unwrap())
}
#[test]
fn actual_compact_ecdsa_is_verified_and_tampering_fails() {
    let s=Synthetic::new();
    let k=PublicKey::from_secret_key(&s.secp,&s.trader);
    let digest=sha256_hex("fixture-message");
    let sig=s.sign(&digest,&s.trader);
    assert_eq!(verify_compact(&digest,&sig,&k),Ok(()));
    assert_eq!(verify_compact(&sha256_hex("changed"),&sig,&k),Err(VerifyError::BadSignature));
    assert!(verify_compact(&digest,"deadbeef",&k).is_err());
}
#[test]
fn authentic_new_order_advances_only_after_both_signatures() {
    let s=Synthetic::new();
    let mut v=s.verifier(8);
    let order=s.order("NEW",&s.trader,None,"0001");
    let entry=s.tape(1,"",order.clone());
    let checkpoint=feed(&mut v,&entry).unwrap();
    assert_eq!(checkpoint.last_seq,1);
    assert_eq!(checkpoint.seen_orders,1);
    assert_eq!(checkpoint.last_hash,entry["entryHash"]);
    assert_eq!(v.owner_of(order["orderId"].as_str().unwrap()),Some(s.public(&s.trader).as_str()));
}
#[test]
fn forged_cancel_is_refused_even_with_attacker_valid_signature() {
    let s=Synthetic::new();
    let mut v=s.verifier(8);
    let first=s.order("NEW",&s.trader,None,"0101");
    let entry=s.tape(1,"",first.clone());
    let head=feed(&mut v,&entry).unwrap();
    let target=first["orderId"].as_str().unwrap();
    let cancel=s.order("CANCEL",&s.other,Some(target),"0102");
    let e=s.tape(2,&head.last_hash,cancel);
    assert_eq!(feed(&mut v,&e),Err(VerifyError::NotOwner));
    assert_eq!(v.checkpoint(),head);
    let authorized=s.order("CANCEL",&s.trader,Some(target),"0103");
    let approved=s.tape(2,&head.last_hash,authorized);
    assert_eq!(feed(&mut v,&approved).unwrap().last_seq,2);
}
#[test]
fn replace_requires_the_original_trader() {
    let s=Synthetic::new();
    let mut v=s.verifier(8);
    let first=s.order("NEW",&s.trader,None,"0201");
    let h=feed(&mut v,&s.tape(1,"",first.clone())).unwrap();
    let target=first["orderId"].as_str().unwrap();
    let forged=s.order("REPLACE",&s.other,Some(target),"0202");
    assert_eq!(feed(&mut v,&s.tape(2,&h.last_hash,forged)),Err(VerifyError::NotOwner));
    let honest=s.order("REPLACE",&s.trader,Some(target),"0203");
    assert!(feed(&mut v,&s.tape(2,&h.last_hash,honest)).is_ok());
}
#[test]
fn cancel_target_changes_signature_domain() {
    let s=Synthetic::new();
    let a=s.order("NEW",&s.trader,None,"0301");
    let b=s.order("NEW",&s.trader,None,"0302");
    let mut v=s.verifier(8);
    let h=feed(&mut v,&s.tape(1,"",a.clone())).unwrap();
    let h2=feed(&mut v,&s.tape(2,&h.last_hash,b.clone())).unwrap();
    let mut forged=s.order("CANCEL",&s.trader,Some(a["orderId"].as_str().unwrap()),"0303");
    forged["cancelsOrderId"]=b["orderId"].clone();
    let e=s.tape(3,&h2.last_hash,forged);
    assert_eq!(feed(&mut v,&e),Err(VerifyError::BadOrderId));
    assert_eq!(v.checkpoint(),h2);
}
#[test]
fn collator_signature_and_tape_hash_are_checked() {
    let s=Synthetic::new();
    let original=s.tape(1,"",s.order("NEW",&s.trader,None,"0401"));
    let mut bad_sig=original.clone();
    bad_sig["sigCollator"]=json!("11".repeat(64));
    let mut v=s.verifier(8);
    assert_eq!(feed(&mut v,&bad_sig),Err(VerifyError::BadSignature));
    let mut bad_hash=original.clone();
    bad_hash["receivedTs"]=json!(1700000000088_u64);
    assert_eq!(feed(&mut v,&bad_hash),Err(VerifyError::BadEntryHash));
    let mut wrong=original.clone();
    wrong["collatorId"]=json!("impostor");
    assert_eq!(feed(&mut v,&wrong),Err(VerifyError::WrongCollator));
    assert_eq!(v.checkpoint().last_seq,0);
}
#[test]
fn continuous_sequence_and_previous_hash_are_mandatory() {
    let s=Synthetic::new();
    let mut v=s.verifier(8);
    let first=s.tape(1,"",s.order("NEW",&s.trader,None,"0501"));
    let h=feed(&mut v,&first).unwrap();
    let wrong_seq=s.tape(3,&h.last_hash,s.order("NEW",&s.trader,None,"0502"));
    assert_eq!(feed(&mut v,&wrong_seq),Err(VerifyError::BrokenChain));
    let wrong_prev=s.tape(2,&"a".repeat(64),s.order("NEW",&s.trader,None,"0503"));
    assert_eq!(feed(&mut v,&wrong_prev),Err(VerifyError::BrokenChain));
    assert_eq!(v.checkpoint(),h);
}
#[test]
fn duplicate_order_is_refused_after_restart_replay() {
    let s=Synthetic::new();
    let first=s.tape(1,"",s.order("NEW",&s.trader,None,"0601"));
    let raw=format!("{}\n",serde_json::to_string(&first).unwrap());
    let mut a=VerifiedReplay::from_ndjson(Cursor::new(raw.as_bytes()),"collator-test",&s.public(&s.collator),8).unwrap();
    let b=VerifiedReplay::from_ndjson(Cursor::new(raw.as_bytes()),"collator-test",&s.public(&s.collator),8).unwrap();
    assert_eq!(a.checkpoint(),b.checkpoint());
    assert_eq!(feed(&mut a,&first),Err(VerifyError::BrokenChain));
    let extra=s.tape(2,&a.checkpoint().last_hash,first["order"].clone());
    assert_eq!(feed(&mut a,&extra),Err(VerifyError::Duplicate));
    assert_eq!(a.checkpoint(),b.checkpoint());
}
#[test]
fn damaged_interior_or_torn_tail_fails_closed() {
    let s=Synthetic::new();
    let e=s.tape(1,"",s.order("NEW",&s.trader,None,"0701"));
    let raw=serde_json::to_string(&e).unwrap();
    let torn=format!("{raw}\n{{\"seq\":2");
    assert!(matches!(
        VerifiedReplay::from_ndjson(Cursor::new(torn), "collator-test",&s.public(&s.collator),8),
        Err(VerifyError::TornTail)
    ));
    let damaged=format!("{raw}\n{{bad json}}\n");
    assert!(matches!(
        VerifiedReplay::from_ndjson(Cursor::new(damaged),"collator-test",&s.public(&s.collator),8),
        Err(VerifyError::Canon(_))
    ));
}
#[test]
fn strict_duplicate_key_and_fractional_tokens_fail_closed() {
    let s=Synthetic::new();
    let mut replay=s.verifier(8);
    let e=s.tape(1,"",s.order("NEW",&s.trader,None,"0801"));
    let raw=serde_json::to_string(&e).unwrap();
    let doubled=raw.replacen("\"seq\":1,","\"seq\":1,\"seq\":1,",1);
    assert!(matches!(replay.apply_line(&doubled),Err(VerifyError::Canon(_))));
    let hidden=raw.replacen("\"seq\":1,","\"seq\":1.00000000000000001,",1);
    assert!(matches!(replay.apply_line(&hidden),Err(VerifyError::Canon(_))));
    assert_eq!(replay.checkpoint().last_seq,0);
}
#[test]
fn capacity_is_bounded_and_safe_on_rejection() {
    let s=Synthetic::new();
    let mut v=s.verifier(1);
    let h=feed(&mut v,&s.tape(1,"",s.order("NEW",&s.trader,None,"0901"))).unwrap();
    let second=s.tape(2,&h.last_hash,s.order("NEW",&s.trader,None,"0902"));
    assert_eq!(feed(&mut v,&second),Err(VerifyError::Capacity));
    assert_eq!(v.checkpoint(),h);
}
#[test]
fn torn_line_over_size_limit_fails_before_allocation() {
    let s=Synthetic::new();
    let huge=format!("{}\n","x".repeat(tl_collator_wire::MAX_INPUT_BYTES+6));
    assert!(matches!(
        VerifiedReplay::from_ndjson(Cursor::new(huge),"collator-test",&s.public(&s.collator),8),
        Err(VerifyError::TooLarge)
    ));
}
