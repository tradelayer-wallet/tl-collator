use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::io::Cursor;
use tl_collator_wire::{
    canonical_json, order_id, sha256_hex, tape_entry_hash, tape_signature_hash,
    witness::{WitnessError, WitnessScope},
};
fn pk(private: &[u8;32]) -> String {
    let secp=Secp256k1::new();
    let private=SecretKey::from_slice(private).unwrap();
    PublicKey::from_secret_key(&secp,&private).serialize()
        .iter().map(|b|format!("{b:02x}")).collect()
}
fn sign(hash: &str, private: &[u8;32]) -> String {
    let mut digest=[0u8;32];
    for (i,x) in digest.iter_mut().enumerate(){
        *x=u8::from_str_radix(&hash[i*2..i*2+2],16).unwrap();
    }
    let secp=Secp256k1::new();
    let private=SecretKey::from_slice(private).unwrap();
    secp.sign_ecdsa(&Message::from_digest(digest),&private).serialize_compact()
        .iter().map(|b|format!("{b:02x}")).collect()
}
fn order(index:u64)->Value {
    let mut data=json!({
        "v":1, "kind":"NEW",
        "body":{"v":1,"market":"SPOT:LTC/USDT","side":"BUY",
            "px":"72.50","qty":"10.0","visibility":{"kind":"PUBLIC"},
            "clientTs":1700000000000_u64},
        "traderPubKey":pk(&[1u8;32]),
        "clientNonce":format!("{index:016x}")
    });
    let hash=order_id(&data).unwrap();
    data["orderId"]=json!(hash);
    data["sigTrader"]=json!(sign(&hash,&[1u8;32]));
    data
}
fn tape(seq:u64,previous:&str,order:Value)->(String,String){
    let mut v=json!({
        "v":1,"collatorId":"collator-1","seq":seq,
        "prevHash":previous,"receivedTs":1700000000001_u64,"order":order
    });
    let hash=tape_entry_hash(&v).unwrap();
    v["entryHash"]=json!(hash);
    let sig_hash=tape_signature_hash(&v,&hash).unwrap();
    v["sigCollator"]=json!(sign(&sig_hash,&[3u8;32]));
    (serde_json::to_string(&v).unwrap(),hash)
}
fn receipt(
    network:&str, stream:&str, epoch:u64, seq:u64, head_hash:&str,
    challenge:&str, signer:&[u8;32],
)->String{
    let mut v=json!({
        "domain":"TradeLayer/collator/checkpoint/v1",
        "v":1,"network":network,"collatorId":"collator-1",
        "stream":stream,"epoch":epoch,"seq":seq,
        "headHash":head_hash,"seenOrders":seq,"challenge":challenge,
    });
    let digest=sha256_hex(&canonical_json(&v).unwrap());
    v["sigWitness"]=json!(sign(&digest,signer));
    serde_json::to_string(&v).unwrap()
}
fn scope()->WitnessScope {
    WitnessScope::new("collator-1","LTCTEST","orders",3,&pk(&[5u8;32])).unwrap()
}
fn challenge()->String {"ab".repeat(32)}
fn history()->(String,String,String,String,String){
    let (a,hash_a)=tape(1,"",order(101));
    let (b,hash_b)=tape(2,&hash_a,order(102));
    let (c,hash_c)=tape(3,&hash_b,order(103));
    (a,b,c,hash_b,hash_c)
}
#[test]
fn independent_witness_receipt_matches_middle_prefix_of_longer_history(){
    let (a,b,c,hash2,hash3)=history();
    let raw=receipt("LTCTEST","orders",3,2,&hash2,&challenge(),&[5u8;32]);
    let verified=scope().verify_receipt(&raw,&challenge()).unwrap();
    assert_eq!(verified.seq(),2);
    assert_eq!(verified.head_hash(),hash2);
    let cp=scope().verify_tape(
        Cursor::new(format!("{a}\n{b}\n{c}\n")),&pk(&[3u8;32]),20,&verified
    ).unwrap();
    assert_eq!(cp.last_seq,3);
    assert_eq!(cp.last_hash,hash3);
}
#[test]
fn truncated_local_history_below_fresh_witness_is_refused(){
    let (a,_,_,hash2,_)=history();
    let r=receipt("LTCTEST","orders",3,2,&hash2,&challenge(),&[5u8;32]);
    let w=scope().verify_receipt(&r,&challenge()).unwrap();
    assert_eq!(
        scope().verify_tape(Cursor::new(format!("{a}\n")),&pk(&[3u8;32]),20,&w),
        Err(WitnessError::Rollback)
    );
}
#[test]
fn fully_signed_but_forked_tape_is_refused(){
    let (a,_,_,_,_)=history();
    let a_hash:Value=serde_json::from_str(&a).unwrap();
    let hash_a=a_hash["entryHash"].as_str().unwrap();
    let valid=receipt("LTCTEST","orders",3,1,hash_a,&challenge(),&[5u8;32]);
    let w=scope().verify_receipt(&valid,&challenge()).unwrap();
    let (fork,_)=tape(1,"",order(998));
    assert_eq!(
        scope().verify_tape(Cursor::new(format!("{fork}\n")),&pk(&[3u8;32]),20,&w),
        Err(WitnessError::Fork)
    );
}
#[test]
fn replayed_witness_receipt_cannot_answer_fresh_challenge(){
    let (_,_,_,hash2,_)=history();
    let stale=receipt("LTCTEST","orders",3,2,&hash2,&challenge(),&[5u8;32]);
    assert_eq!(scope().verify_receipt(&stale,&"cd".repeat(32)),Err(WitnessError::StaleChallenge));
    assert_eq!(scope().verify_receipt(&stale,&"0".repeat(64)),Err(WitnessError::Invalid("challenge")));
}
#[test]
fn valid_signature_under_wrong_network_or_epoch_is_refused(){
    let (_,_,_,hash2,_)=history();
    let wrong_network=receipt("BTC","orders",3,2,&hash2,&challenge(),&[5u8;32]);
    assert_eq!(scope().verify_receipt(&wrong_network,&challenge()),Err(WitnessError::WrongScope));
    let wrong_epoch=receipt("LTCTEST","orders",4,2,&hash2,&challenge(),&[5u8;32]);
    assert_eq!(scope().verify_receipt(&wrong_epoch,&challenge()),Err(WitnessError::WrongScope));
    let wrong_stream=receipt("LTCTEST","other",3,2,&hash2,&challenge(),&[5u8;32]);
    assert_eq!(scope().verify_receipt(&wrong_stream,&challenge()),Err(WitnessError::WrongScope));
}
#[test]
fn witness_requires_independent_pinned_signing_key(){
    let (_,_,_,hash2,_)=history();
    let forged=receipt("LTCTEST","orders",3,2,&hash2,&challenge(),&[3u8;32]);
    assert_eq!(scope().verify_receipt(&forged,&challenge()),Err(WitnessError::BadSignature));
    let mut mutated:Value=serde_json::from_str(
        &receipt("LTCTEST","orders",3,2,&hash2,&challenge(),&[5u8;32])
    ).unwrap();
    mutated["headHash"]=json!("f".repeat(64));
    assert_eq!(scope().verify_receipt(&mutated.to_string(),&challenge()),Err(WitnessError::BadSignature));
}
#[test]
fn duplicate_and_rounding_traps_in_receipt_are_rejected(){
    let (_,_,_,hash2,_)=history();
    let raw=receipt("LTCTEST","orders",3,2,&hash2,&challenge(),&[5u8;32]);
    let extra=raw.replacen("\"seq\":2","\"seq\":2,\"seq\":2",1);
    assert!(matches!(scope().verify_receipt(&extra,&challenge()),Err(WitnessError::Canon(_))));
    let decimal=raw.replacen("\"seq\":2","\"seq\":2.00000000000000001",1);
    assert!(matches!(scope().verify_receipt(&decimal,&challenge()),Err(WitnessError::Canon(_))));
    let missing=raw.replacen("\"sigWitness\":","\"unexpected\":null,\"sigWitness\":",1);
    assert_eq!(scope().verify_receipt(&missing,&challenge()),Err(WitnessError::Invalid("fields")));
}
#[test]
fn witness_at_genesis_matches_empty_history(){
    let r=receipt("LTCTEST","orders",3,0,"",&challenge(),&[5u8;32]);
    let proof=scope().verify_receipt(&r,&challenge()).unwrap();
    let cp=scope().verify_tape(Cursor::new(b"".as_slice()),&pk(&[3u8;32]),20,&proof).unwrap();
    assert_eq!(cp.last_seq,0);
    assert!(cp.last_hash.is_empty());
}
#[test]
fn bad_tape_signature_fails_even_with_valid_external_receipt(){
    let (a,_,_,_,_)=history();
    let v:Value=serde_json::from_str(&a).unwrap();
    let hash=v["entryHash"].as_str().unwrap();
    let r=receipt("LTCTEST","orders",3,1,hash,&challenge(),&[5u8;32]);
    let proof=scope().verify_receipt(&r,&challenge()).unwrap();
    let mut broken=v.clone();
    broken["sigCollator"]=json!("11".repeat(64));
    assert!(matches!(
        scope().verify_tape(Cursor::new(format!("{}\n",broken)),&pk(&[3u8;32]),20,&proof),
        Err(WitnessError::Verify(_))
    ));
}
#[test]
fn signed_receipt_not_an_independent_monotonic_store(){
    // This is a limitation test: a previously signed receipt with a *reused*
    // challenge cannot detect rollback beyond its seq. Production must supply
    // fresh challenge and a separately maintained monotonic witness service.
    let (a,_,_,_,_)=history();
    let v:Value=serde_json::from_str(&a).unwrap();
    let hash=v["entryHash"].as_str().unwrap();
    let r=receipt("LTCTEST","orders",3,1,hash,&challenge(),&[5u8;32]);
    let old=scope().verify_receipt(&r,&challenge()).unwrap();
    assert_eq!(
        scope().verify_tape(Cursor::new(format!("{a}\n")),&pk(&[3u8;32]),20,&old)
            .unwrap().last_seq,1
    );
}

#[test]
fn collator_key_cannot_double_as_independent_witness(){
    let trusted_collator_key=pk(&[3u8;32]);
    let scope=WitnessScope::new("collator-1","LTCTEST","orders",3,&trusted_collator_key).unwrap();
    let record=receipt("LTCTEST","orders",3,0,"",&challenge(),&[3u8;32]);
    let signed=scope.verify_receipt(&record,&challenge()).unwrap();
    assert_eq!(
        scope.verify_tape(Cursor::new(b"".as_slice()),&trusted_collator_key,20,&signed),
        Err(WitnessError::Invalid("independence"))
    );
}
