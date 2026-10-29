use tl_collator_wire::{canonical_json,order_id,tape_entry_hash,tape_signature_hash,parse_canonical_text,sha256_hex};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/curated-vectors.json")).unwrap()
}
#[test]
fn order_and_cancel_hashes_match_upstream() {
    let v=fixture();
    for name in ["orderTest","orderCancelTest","orderIntegerKeyTest"] {
        assert_eq!(
            order_id(&v[name]["envelopeNoSig"]).unwrap(),
            v[name]["expectedOrderId"].as_str().unwrap(),
            "hash mismatch {name}"
        );
    }
}
#[test]
fn unicode_codepoint_and_integer_key_order() {
    let v=fixture();
    for name in ["integerKeyTest","unicodeKeyOrderTest"] {
        let bytes=canonical_json(&v[name]["input"]).unwrap();
        assert_eq!(bytes,v[name]["expectedCanonical"].as_str().unwrap());
        assert_eq!(sha256_hex(&bytes),v[name]["expectedSha256"].as_str().unwrap());
    }
    assert_eq!(
        canonical_json(&v["integralNumberTest"]["input"]).unwrap(),
        v["integralNumberTest"]["expectedCanonical"].as_str().unwrap()
    );
}
#[test]
fn tape_hash_and_signature_payload_match_upstream() {
    let v=fixture();
    let t=&v["tapeTest"];
    let entry=&t["entryNoSig"];
    let hash=tape_entry_hash(entry).unwrap();
    assert_eq!(hash,t["expectedEntryHash"].as_str().unwrap());
    assert_eq!(tape_signature_hash(entry,&hash).unwrap(),t["expectedSigPayloadHash"].as_str().unwrap());
}
#[test]
fn bad_inputs_fail_closed() {
    let v=fixture();
    for case in v["rejectTests"].as_array().unwrap() {
        assert!(canonical_json(&case["input"]).is_err(),"{}",case["name"]);
    }
    for case in v["textRejectTests"].as_array().unwrap() {
        assert!(parse_canonical_text(case["text"].as_str().unwrap()).is_err(),"{}",case["name"]);
    }
    assert!(parse_canonical_text("\"\\ud800\"").is_err());
    assert!(parse_canonical_text("{\"\\udc00\":1}").is_err());
}
#[test]
fn acceptable_text_tokens_preserve_original_precision() {
    let v=fixture();
    for case in v["textAcceptTests"].as_array().unwrap() {
        assert!(parse_canonical_text(case["text"].as_str().unwrap()).is_ok(),"{}",case["name"]);
    }
    let val=parse_canonical_text(r#"{"qty":1.0}"#).unwrap();
    assert_eq!(canonical_json(&val).unwrap(),r#"{"qty":1}"#);
    // Parsing 0.5 is allowed, but canonicalization rejects fractional values.
    assert!(canonical_json(&parse_canonical_text("[0.5]").unwrap()).is_err());
}
