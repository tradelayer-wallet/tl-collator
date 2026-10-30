
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{order_id, tape_entry_hash, tape_signature_hash};
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use serde_json::{json, Value};
    use std::{
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    static TEST_SEQUENCE: AtomicU64=AtomicU64::new(0);

    pub(super) struct TestDir(pub(super) PathBuf);
    impl TestDir {
        pub(super) fn new()->Self {
            let nanos=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let id=TEST_SEQUENCE.fetch_add(1,Ordering::Relaxed);
            let path=std::env::temp_dir().join(
                format!("tl-collator-durable-{}-{nanos}-{id}",std::process::id())
            );
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        pub(super) fn tape(&self)->PathBuf{self.0.join("orders.ndjson")}
        pub(super) fn anchor(&self)->PathBuf{self.0.join("orders.checkpoint")}
        pub(super) fn open(&self,mode:ImportMode)->Result<DurableTape,DurableError>{
            DurableTape::open(&self.0,"orders","collator-1",&key_hex(&[3u8;32]),256,mode)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}
    }
    fn hex(bytes:&[u8])->String{
        bytes.iter().map(|b|format!("{b:02x}")).collect()
    }
    fn secret(bytes:&[u8;32])->SecretKey{
        SecretKey::from_slice(bytes).unwrap()
    }
    pub(super) fn key_hex(secret_bytes:&[u8;32])->String{
        let ctx=Secp256k1::new();
        hex(&PublicKey::from_secret_key(&ctx,&secret(secret_bytes)).serialize())
    }
    pub(super) fn sign(hash:&str,secret_bytes:&[u8;32])->String{
        let ctx=Secp256k1::new();
        let mut digest=[0u8;32];
        for (i,byte) in digest.iter_mut().enumerate(){
            *byte=u8::from_str_radix(&hash[2*i..2*i+2],16).unwrap();
        }
        let signature=ctx.sign_ecdsa(&Message::from_digest(digest),&secret(secret_bytes));
        hex(&signature.serialize_compact())
    }
    fn order(n:u64,owner:&[u8;32],kind:&str,target:Option<&str>)->Value{
        let mut value=json!({
            "v":1,"kind":kind,
            "body":{"v":1,"market":"SPOT:LTC/USDT","side":"BUY",
                "px":"72.50","qty":"10","visibility":{"kind":"PUBLIC"},
                "clientTs":1700000000000_u64},
            "traderPubKey":key_hex(owner),
            "clientNonce":format!("{n:016x}"),
        });
        if let Some(id)=target{
            let name=if kind=="CANCEL"{"cancelsOrderId"}else{"replacesOrderId"};
            value[name]=json!(id);
        }
        let hash=order_id(&value).unwrap();
        value["orderId"]=json!(hash);
        value["sigTrader"]=json!(sign(&hash,owner));
        value
    }
    fn entry(seq:u64,previous:&str,order:Value)->String{
        let mut value=json!({
            "v":1,"collatorId":"collator-1","seq":seq,
            "prevHash":previous,"receivedTs":1700000000000_u64,
            "order":order,
        });
        let hash=tape_entry_hash(&value).unwrap();
        value["entryHash"]=json!(hash);
        let payload=tape_signature_hash(&value,&hash).unwrap();
        value["sigCollator"]=json!(sign(&payload,&[3u8;32]));
        serde_json::to_string(&value).unwrap()
    }
    pub(super) fn new_line(n:u64,seq:u64,previous:&str)->String{
        entry(seq,previous,order(n,&[1u8;32],"NEW",None))
    }
    fn write_unanchored_line(dir:&TestDir,line:&str){
        let mut file=OpenOptions::new().append(true).open(dir.tape()).unwrap();
        file.write_all(line.as_bytes()).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn commit_ack_requires_synced_tape_and_anchor_and_survives_restart(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        assert_eq!(w.checkpoint().last_seq,0);
        let first=new_line(1,1,"");
        let c1=w.append_signed(&first).unwrap();
        assert_eq!(c1.last_seq,1);
        let c2=w.append_signed(&new_line(2,2,&c1.last_hash)).unwrap();
        assert_eq!(c2.last_seq,2);
        assert_eq!(w.recovery(),Recovery{torn_tail_bytes:0,unanchored_records:0});
        assert!(w.has_order(serde_json::from_str::<Value>(&first).unwrap()["order"]["orderId"].as_str().unwrap()));
        assert_eq!(read_anchor(&dir.anchor()).unwrap().unwrap().seq,2);
        drop(w);
        let r=dir.open(ImportMode::RequireAnchor).unwrap();
        assert_eq!(r.checkpoint(),c2);
        assert_eq!(r.recovery(),Recovery{torn_tail_bytes:0,unanchored_records:0});
        assert_eq!(fs::read_to_string(dir.tape()).unwrap().lines().count(),2);
        // Do not remove the lockfile on close: a new lock refers to this inode.
        assert!(dir.0.join("orders.lock").exists());
    }
    #[test]
    fn second_writer_cannot_acquire_same_os_lock(){
        let dir=TestDir::new();
        let first=dir.open(ImportMode::RequireAnchor).unwrap();
        assert!(matches!(dir.open(ImportMode::RequireAnchor),Err(DurableError::LockBusy)));
        drop(first);
        assert!(dir.open(ImportMode::RequireAnchor).is_ok());
    }
    #[test]
    fn failed_partial_write_rolls_back_and_keeps_same_order_admissible(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        let first=new_line(3,1,"");
        assert!(matches!(w.append_inner(&first,FaultPoint::PartialWrite),Err(DurableError::InjectedWriteFailure)));
        assert_eq!(w.checkpoint().last_seq,0);
        assert!(fs::read(dir.tape()).unwrap().is_empty());
        assert_eq!(w.append_signed(&first).unwrap().last_seq,1);
    }
    #[test]
    fn crash_after_data_sync_is_reconciled_on_next_open(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        let first=new_line(4,1,"");
        assert!(matches!(w.append_inner(&first,FaultPoint::AfterDataSync),Err(DurableError::CommitUnknown)));
        assert!(matches!(w.append_signed(&first),Err(DurableError::NeedsRecovery)));
        assert_eq!(w.checkpoint().last_seq,0);
        drop(w);
        let mut next=dir.open(ImportMode::RequireAnchor).unwrap();
        assert_eq!(next.recovery().unanchored_records,1);
        assert_eq!(next.checkpoint().last_seq,1);
        assert_eq!(read_anchor(&dir.anchor()).unwrap().unwrap().seq,1);
        let cp=next.checkpoint();
        let second=new_line(5,2,&cp.last_hash);
        assert_eq!(next.append_signed(&second).unwrap().last_seq,2);
    }
    #[test]
    fn anchor_rename_uncertainty_requires_reopen(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        let first=new_line(6,1,"");
        assert!(matches!(w.append_inner(&first,FaultPoint::AfterAnchorRename),Err(DurableError::CommitUnknown)));
        assert!(matches!(w.append_signed(&first),Err(DurableError::NeedsRecovery)));
        drop(w);
        let mut next=dir.open(ImportMode::RequireAnchor).unwrap();
        assert_eq!(next.checkpoint().last_seq,1);
        assert_eq!(next.recovery().unanchored_records,0);
        let previous=next.checkpoint().last_hash;
        assert_eq!(next.append_signed(&new_line(7,2,&previous)).unwrap().last_seq,2);
    }
    #[test]
    fn fully_verified_unacknowledged_line_is_recovered_and_anchored(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        let c1=w.append_signed(&new_line(8,1,"")).unwrap();
        drop(w);
        write_unanchored_line(&dir,&new_line(9,2,&c1.last_hash));
        let next=dir.open(ImportMode::RequireAnchor).unwrap();
        assert_eq!(next.checkpoint().last_seq,2);
        assert_eq!(next.recovery().unanchored_records,1);
        assert_eq!(read_anchor(&dir.anchor()).unwrap().unwrap().seq,2);
    }
    #[test]
    fn torn_trailing_suffix_is_safely_removed(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        let c1=w.append_signed(&new_line(10,1,"")).unwrap();
        drop(w);
        let mut file=OpenOptions::new().append(true).open(dir.tape()).unwrap();
        file.write_all(b"{\"seq\":2,\"pre").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut next=dir.open(ImportMode::RequireAnchor).unwrap();
        assert_eq!(next.recovery().torn_tail_bytes,13);
        assert_eq!(next.checkpoint(),c1);
        assert!(fs::read_to_string(dir.tape()).unwrap().ends_with("}\n"));
        assert_eq!(next.append_signed(&new_line(11,2,&c1.last_hash)).unwrap().last_seq,2);
    }
    #[test]
    fn anchored_truncation_or_corrupted_complete_line_fails_closed(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        let c1=w.append_signed(&new_line(12,1,"")).unwrap();
        w.append_signed(&new_line(13,2,&c1.last_hash)).unwrap();
        drop(w);
        let all=fs::read_to_string(dir.tape()).unwrap();
        let first=all.lines().next().unwrap();
        fs::write(dir.tape(),format!("{first}\n")).unwrap();
        assert!(matches!(dir.open(ImportMode::RequireAnchor),Err(DurableError::AnchorMismatch)));
        fs::write(dir.tape(),all.replace("collator-1","collator-evil")).unwrap();
        assert!(matches!(dir.open(ImportMode::RequireAnchor),Err(DurableError::Verify(_))));
    }
    #[test]
    fn invalid_signature_and_duplicate_never_write_to_disk(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        let valid=new_line(14,1,"");
        let mut bad:Value=serde_json::from_str(&valid).unwrap();
        bad["sigCollator"]=json!("11".repeat(64));
        assert!(matches!(w.append_signed(&bad.to_string()),Err(DurableError::Verify(_))));
        assert!(fs::read(dir.tape()).unwrap().is_empty());
        let cp=w.append_signed(&valid).unwrap();
        let second=entry(2,&cp.last_hash,bad["order"].clone());
        assert!(matches!(w.append_signed(&second),Err(DurableError::Verify(VerifyError::Duplicate))));
        assert_eq!(w.checkpoint(),cp);
        assert_eq!(fs::read_to_string(dir.tape()).unwrap().lines().count(),1);
    }
    #[test]
    fn missing_anchor_for_nonempty_history_requires_explicit_import(){
        let dir=TestDir::new();
        fs::write(dir.tape(),format!("{}\n",new_line(15,1,""))).unwrap();
        assert!(matches!(dir.open(ImportMode::RequireAnchor),Err(DurableError::UnanchoredHistory)));
        let imported=dir.open(ImportMode::ExplicitVerifiedImport).unwrap();
        assert_eq!(imported.checkpoint().last_seq,1);
        assert_eq!(imported.recovery().unanchored_records,1);
        assert_eq!(read_anchor(&dir.anchor()).unwrap().unwrap().seq,1);
    }
    #[test]
    fn corrupt_anchor_is_rejected_without_rewriting_it(){
        let dir=TestDir::new();
        let w=dir.open(ImportMode::RequireAnchor).unwrap();
        drop(w);
        fs::write(dir.anchor(),b"{bad").unwrap();
        assert!(matches!(dir.open(ImportMode::RequireAnchor),Err(DurableError::CorruptAnchor)));
        assert_eq!(fs::read(dir.anchor()).unwrap(),b"{bad");
    }
    #[test]
    fn full_bad_record_is_not_silently_truncated(){
        let dir=TestDir::new();
        let w=dir.open(ImportMode::RequireAnchor).unwrap();
        drop(w);
        fs::write(dir.tape(),b"{not valid json}\n").unwrap();
        assert!(matches!(dir.open(ImportMode::RequireAnchor),Err(DurableError::Verify(_))));
        assert_eq!(fs::read(dir.tape()).unwrap(),b"{not valid json}\n");
    }
    #[test]
    fn records_and_names_have_bounded_memory(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        assert!(matches!(w.append_signed("a\nb"),Err(DurableError::TooLarge)));
        let giant="x".repeat(MAX_INPUT_BYTES+100);
        assert!(matches!(w.append_signed(&giant),Err(DurableError::TooLarge)));
        drop(w);
        fs::write(dir.tape(),giant).unwrap();
        assert!(matches!(dir.open(ImportMode::RequireAnchor),Err(DurableError::TooLarge)));
        assert!(matches!(
            DurableTape::open(&dir.0,"../unsafe","collator-1",&key_hex(&[3u8;32]),10,ImportMode::RequireAnchor),
            Err(DurableError::InvalidPath)
        ));
    }
    #[test]
    fn owner_checks_survive_valid_restart(){
        let dir=TestDir::new();
        let mut w=dir.open(ImportMode::RequireAnchor).unwrap();
        let new=order(16,&[1u8;32],"NEW",None);
        let id=new["orderId"].as_str().unwrap().to_string();
        let c1=w.append_signed(&entry(1,"",new)).unwrap();
        drop(w);
        let mut next=dir.open(ImportMode::RequireAnchor).unwrap();
        let forged=entry(2,&c1.last_hash,order(17,&[2u8;32],"CANCEL",Some(&id)));
        assert!(matches!(next.append_signed(&forged),Err(DurableError::Verify(VerifyError::NotOwner))));
        let good=entry(2,&c1.last_hash,order(18,&[1u8;32],"CANCEL",Some(&id)));
        assert_eq!(next.append_signed(&good).unwrap().last_seq,2);
    }
    #[test]
    fn lock_child_helper(){
        let path=match std::env::var_os("TL_DURABLE_CHILD_PATH"){Some(v)=>PathBuf::from(v),None=>return};
        let lock=DurableTape::open(&path,"orders","collator-1",&key_hex(&[3u8;32]),100,ImportMode::RequireAnchor).unwrap();
        println!("CHILD_LOCKED");
        io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_secs(30));
        drop(lock);
    }
    #[test]
    #[cfg(unix)]
    fn killed_writer_releases_os_lock_for_restart(){
        use std::process::{Command,Stdio};
        let dir=TestDir::new();
        let mut child=Command::new(std::env::current_exe().unwrap())
            .args(["--exact","durable::tests::lock_child_helper","--nocapture"])
            .env("TL_DURABLE_CHILD_PATH",&dir.0)
            .stdout(Stdio::piped()).spawn().unwrap();
        let stdout=child.stdout.take().unwrap();
        let mut stdout=BufReader::new(stdout);
        let mut result=String::new();
        loop{
            result.clear();
            assert!(stdout.read_line(&mut result).unwrap()>0,"child exited before lock");
            if result.contains("CHILD_LOCKED"){break;}
        }
        assert!(matches!(dir.open(ImportMode::RequireAnchor),Err(DurableError::LockBusy)));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(dir.open(ImportMode::RequireAnchor).is_ok());
    }

    #[test]
    fn preparation_is_inert_until_the_durable_commit() {
        let dir = TestDir::new();
        let mut writer = dir.open(ImportMode::RequireAnchor).unwrap();
        let first = new_line(31, 1, "");
        let prepared = writer.verified.prepare_line(&first).unwrap();
        assert_eq!(prepared.checkpoint().last_seq, 1);
        assert_eq!(writer.checkpoint().last_seq, 0);
        assert_eq!(writer.verified.checkpoint().seen_orders, 0);
        assert_eq!(fs::metadata(dir.tape()).unwrap().len(), 0);
        let committed = writer.append_signed(&first).unwrap();
        assert_eq!(committed.last_seq, 1);
        assert!(matches!(
            writer.verified.commit_prepared(prepared),
            Err(VerifyError::BrokenChain)
        ));
        assert_eq!(writer.checkpoint(), committed);
        assert_eq!(fs::read_to_string(dir.tape()).unwrap().lines().count(), 1);
    }

    #[test]
    fn stale_prepared_cannot_be_committed_after_another_entry() {
        let dir = TestDir::new();
        let mut writer = dir.open(ImportMode::RequireAnchor).unwrap();
        let line_a = new_line(32, 1, "");
        let line_b = new_line(33, 1, "");
        let prepared_a = writer.verified.prepare_line(&line_a).unwrap();
        let checkpoint = writer.append_signed(&line_b).unwrap();
        assert_eq!(checkpoint.last_seq, 1);
        assert!(matches!(
            writer.verified.commit_prepared(prepared_a),
            Err(VerifyError::BrokenChain)
        ));
        assert_eq!(writer.checkpoint(), checkpoint);
        assert_eq!(fs::read_to_string(dir.tape()).unwrap().lines().count(), 1);
    }

    #[test]
    fn bounded_history_remains_consistent_across_many_appends_and_restart() {
        let dir = TestDir::new();
        let mut writer = dir.open(ImportMode::RequireAnchor).unwrap();
        let mut prev = String::new();
        for n in 1..=150u64 {
            let item = new_line(1000 + n, n, &prev);
            let cp = writer.append_signed(&item).unwrap();
            assert_eq!(cp.last_seq, n);
            assert_eq!(cp.seen_orders, n as usize);
            prev = cp.last_hash;
        }
        drop(writer);
        let again = dir.open(ImportMode::RequireAnchor).unwrap();
        assert_eq!(again.checkpoint().last_seq, 150);
        assert_eq!(again.checkpoint().seen_orders, 150);
        assert_eq!(again.recovery().unanchored_records, 0);
    }

}
