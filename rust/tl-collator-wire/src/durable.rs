//! Durable local-fs append for already-signed, independently verified tape entries.
//! This module does not sign or broadcast. The operator must supply trusted paths,
//! a pinned collator pubkey and local POSIX filesystem semantics.
use crate::verify::{Checkpoint, VerifiedReplay, VerifyError};
use crate::MAX_INPUT_BYTES;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, BufRead, BufReader, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const ANCHOR_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportMode {
    /// Refuse a nonempty historical tape without a checkpoint anchor.
    RequireAnchor,
    /// One-time operator-authorized import. Every entry must have valid signatures.
    ExplicitVerifiedImport,
}

#[derive(Debug)]
pub enum DurableError {
    InvalidPath,
    UnsupportedFilesystem,
    LockBusy,
    Io(io::Error),
    Verify(VerifyError),
    TooLarge,
    TornTail,
    CorruptAnchor,
    AnchorMismatch,
    UnanchoredHistory,
    NeedsRecovery,
    CommitUnknown,
    InjectedWriteFailure,
}
impl fmt::Display for DurableError {
    fn fmt(&self, f:&mut fmt::Formatter<'_>)->fmt::Result {write!(f,"{self:?}")}
}
impl std::error::Error for DurableError {}
impl From<io::Error> for DurableError {
    fn from(err: io::Error)->Self {Self::Io(err)}
}
impl From<VerifyError> for DurableError {
    fn from(err: VerifyError)->Self {Self::Verify(err)}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// Bytes removed from an incomplete, unacknowledged trailing record.
    pub torn_tail_bytes: u64,
    /// Verified complete records found after the last anchored checkpoint.
    pub unanchored_records: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    version: u8,
    seq: u64,
    hash: String,
    orders: usize,
}
impl Anchor {
    fn from_checkpoint(c:&Checkpoint)->Self {
        Self {version:1,seq:c.last_seq,hash:c.last_hash.clone(),orders:c.seen_orders}
    }
    fn valid(&self)->bool {
        self.version==1 && self.seq<=crate::MAX_SAFE_INTEGER
            && self.orders as u64==self.seq
            && if self.seq==0 {self.hash.is_empty()} else {is_lower_hash(&self.hash)}
    }
}
fn is_lower_hash(s:&str)->bool {
    s.len()==64 && s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}

fn require_regular_or_absent(path:&Path)->Result<(),DurableError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => Ok(()),
        Ok(_) => Err(DurableError::InvalidPath),
        Err(e) if e.kind()==io::ErrorKind::NotFound =>Ok(()),
        Err(e)=>Err(DurableError::Io(e)),
    }
}
fn sync_directory(dir:&Path)->Result<(),DurableError>{
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _=dir;
        Err(DurableError::UnsupportedFilesystem)
    }
}
fn read_anchor(path:&Path)->Result<Option<Anchor>,DurableError>{
    require_regular_or_absent(path)?;
    if !path.exists(){return Ok(None);}
    let metadata=fs::metadata(path)?;
    if metadata.len()>ANCHOR_LIMIT as u64 {return Err(DurableError::CorruptAnchor);}
    let bytes=fs::read(path)?;
    let anchor:Anchor=serde_json::from_slice(&bytes)
        .map_err(|_|DurableError::CorruptAnchor)?;
    if !anchor.valid(){return Err(DurableError::CorruptAnchor);}
    Ok(Some(anchor))
}
fn unique_temp(path:&Path)->PathBuf {
    let number=TEMP_SEQUENCE.fetch_add(1,Ordering::Relaxed);
    let name=path.file_name().and_then(|s|s.to_str()).unwrap_or("anchor");
    path.with_file_name(format!(".{name}.tmp.{}.{}",std::process::id(),number))
}
fn write_anchor(dir:&Path,path:&Path,checkpoint:&Checkpoint,inject:bool)
    ->Result<(),DurableError>{
    let temp=unique_temp(path);
    let mut file=OpenOptions::new().write(true).create_new(true).open(&temp)?;
    let bytes=serde_json::to_vec(&Anchor::from_checkpoint(checkpoint))
        .map_err(|_|DurableError::CorruptAnchor)?;
    if let Err(error)=file.write_all(&bytes).and_then(|_|file.sync_all()){
        let _=fs::remove_file(&temp);
        return Err(DurableError::Io(error));
    }
    drop(file);
    fs::rename(&temp,path)?;
    if inject {return Err(DurableError::InjectedWriteFailure);}
    sync_directory(dir)
}

/// Reads at most MAX_INPUT_BYTES+2 bytes per record; never allocates an entire
/// untrusted NDJSON file, even if one record has no newline.
fn next_record<R:BufRead>(reader:&mut R,buffer:&mut Vec<u8>)
    ->Result<Option<bool>,DurableError>{
    buffer.clear();
    loop {
        let bytes=reader.fill_buf()?;
        if bytes.is_empty(){
            return if buffer.is_empty(){Ok(None)}else{Ok(Some(false))};
        }
        let newline=bytes.iter().position(|b|*b==b'\n');
        let n=newline.map_or(bytes.len(),|idx|idx+1);
        if buffer.len().saturating_add(n)>MAX_INPUT_BYTES+2 {
            return Err(DurableError::TooLarge);
        }
        buffer.extend_from_slice(&bytes[..n]);
        reader.consume(n);
        if newline.is_some(){return Ok(Some(true));}
    }
}
fn scan(
    tape:&mut File,collator_id:&str,key:&str,max_entries:usize,
    anchor:Option<&Anchor>,
)->Result<(VerifiedReplay,u64,u64),DurableError>{
    tape.seek(SeekFrom::Start(0))?;
    let mut reader=BufReader::new(tape.try_clone()?);
    let mut verified=VerifiedReplay::new(collator_id,key,max_entries)?;
    let mut line=Vec::new();
    let mut full_bytes=0u64;
    let mut torn_bytes=0u64;
    let mut anchor_seen=anchor.is_some_and(|a|a.seq==0&&a.hash.is_empty()&&a.orders==0);
    while let Some(complete)=next_record(&mut reader,&mut line)? {
        if !complete {
            torn_bytes=line.len() as u64;
            break;
        }
        let mut end=line.len()-1;
        if end>0 && line[end-1]==b'\r' {end-=1;}
        let text=std::str::from_utf8(&line[..end])
            .map_err(|_|DurableError::Verify(VerifyError::Invalid("UTF-8")))?;
        verified.apply_line(text)?;
        full_bytes=full_bytes.checked_add(line.len() as u64)
            .ok_or(DurableError::TooLarge)?;
        if let Some(a)=anchor {
            let cp=verified.checkpoint();
            if cp.last_seq==a.seq {
                if cp.last_hash!=a.hash || cp.seen_orders!=a.orders {
                    return Err(DurableError::AnchorMismatch);
                }
                anchor_seen=true;
            }
        }
    }
    if anchor.is_some() && !anchor_seen {return Err(DurableError::AnchorMismatch);}
    Ok((verified,full_bytes,torn_bytes))
}

/// Holds an OS-level exclusive file lock for its whole lifetime. Never deletes
/// the lockfile: removal/recreation would permit split-brain locks on two inodes.
pub struct DurableTape {
    _lock: File,
    tape: File,
    directory: PathBuf,
    anchor_path: PathBuf,
    bytes: u64,
    verified: VerifiedReplay,
    poisoned: bool,
    recovery: Recovery,
}
impl DurableTape {
    /// Directory must be an operator-controlled local POSIX filesystem;
    /// network filesystems and mutable symlinks are not an accepted deployment.
    pub fn open(
        directory:&Path,
        stem:&str,
        collator_id:&str,
        trusted_collator_pubkey:&str,
        max_entries:usize,
        import:ImportMode,
    )->Result<Self,DurableError>{
        #[cfg(not(unix))]
        return Err(DurableError::UnsupportedFilesystem);
        if stem.is_empty() || stem.len()>64
            || !stem.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-') {
            return Err(DurableError::InvalidPath);
        }
        let directory=fs::canonicalize(directory)?;
        if !directory.is_dir(){return Err(DurableError::InvalidPath);}
        let lock_path=directory.join(format!("{stem}.lock"));
        let tape_path=directory.join(format!("{stem}.ndjson"));
        let anchor_path=directory.join(format!("{stem}.checkpoint"));
        for path in [&lock_path,&tape_path,&anchor_path] {
            require_regular_or_absent(path)?;
        }
        // Keep the same inode and OS lock until drop; locks are released if
        // the process is killed or exits, no PID or stale-file override needed.
        let lock=OpenOptions::new().read(true).write(true).create(true).open(&lock_path)?;
        match lock.try_lock(){
            Ok(())=>{},
            Err(TryLockError::WouldBlock)=>return Err(DurableError::LockBusy),
            Err(TryLockError::Error(e))=>return Err(DurableError::Io(e)),
        }
        let mut tape=OpenOptions::new().read(true).write(true).create(true).open(&tape_path)?;
        // Persist initial directory entries before any successful append ack.
        sync_directory(&directory)?;
        let previous=read_anchor(&anchor_path)?;
        let (verified,valid_bytes,torn_tail)=scan(
            &mut tape,collator_id,trusted_collator_pubkey,max_entries,previous.as_ref()
        )?;
        if previous.is_none() && valid_bytes!=0 && import==ImportMode::RequireAnchor {
            return Err(DurableError::UnanchoredHistory);
        }
        if torn_tail>0 {
            // Only the unterminated suffix is removed. Full invalid lines and
            // acknowledged anchored records are NEVER silently truncated.
            tape.set_len(valid_bytes)?;
            tape.sync_all()?;
        }
        let current=verified.checkpoint();
        let anchored_seq=previous.as_ref().map_or(0,|a|a.seq);
        if previous.is_none() || current.last_seq>anchored_seq {
            // A valid, fully signed line can survive a crash before anchor
            // update. Sync it, then atomically catch the anchor up to its tip.
            tape.sync_all()?;
            write_anchor(&directory,&anchor_path,&current,false)?;
        }
        tape.seek(SeekFrom::Start(valid_bytes))?;
        Ok(Self {
            _lock:lock,tape,directory,anchor_path,bytes:valid_bytes,
            verified,poisoned:false,
            recovery:Recovery {
                torn_tail_bytes:torn_tail,
                unanchored_records:current.last_seq-anchored_seq
            },
        })
    }
    pub fn checkpoint(&self)->Checkpoint{self.verified.checkpoint()}
    pub fn recovery(&self)->Recovery{self.recovery.clone()}
    pub fn has_order(&self,order_id:&str)->bool{self.verified.contains(order_id)}

    pub fn append_signed(&mut self,line:&str)->Result<Checkpoint,DurableError>{
        self.append_inner(line,FaultPoint::None)
    }
    fn abort_partial(&mut self,old_len:u64)->Result<(),DurableError>{
        // A failure after an incomplete write must not poison future appends.
        // If rollback itself fails, prohibit any further writes in this handle.
        if let Err(e)=self.tape.set_len(old_len).and_then(|_|self.tape.sync_all()){
            self.poisoned=true;
            return Err(DurableError::Io(e));
        }
        self.tape.seek(SeekFrom::Start(old_len))?;
        Ok(())
    }
    fn append_inner(&mut self,line:&str,point:FaultPoint)->Result<Checkpoint,DurableError>{
        if self.poisoned{return Err(DurableError::NeedsRecovery);}
        if line.as_bytes().contains(&b'\n') || line.as_bytes().contains(&b'\r')
            || line.len()>MAX_INPUT_BYTES {
            return Err(DurableError::TooLarge);
        }
        let mut candidate=self.verified.clone();
        let next=candidate.apply_line(line)?;
        let mut bytes=line.as_bytes().to_vec();
        bytes.push(b'\n');
        self.tape.seek(SeekFrom::Start(self.bytes))?;
        if point==FaultPoint::PartialWrite {
            if let Err(error)=self.tape.write_all(&bytes[..bytes.len()/2]){
                self.abort_partial(self.bytes)?;
                return Err(DurableError::Io(error));
            }
            self.abort_partial(self.bytes)?;
            return Err(DurableError::InjectedWriteFailure);
        }
        if let Err(error)=self.tape.write_all(&bytes).and_then(|_|self.tape.sync_all()){
            self.abort_partial(self.bytes)?;
            return Err(DurableError::Io(error));
        }
        if point==FaultPoint::AfterDataSync {
            // The complete signed entry is durable, but no success was
            // acknowledged. Reopen must verify and reconcile its anchor.
            self.poisoned=true;
            return Err(DurableError::CommitUnknown);
        }
        let anchor_result=write_anchor(
            &self.directory,&self.anchor_path,&next,
            point==FaultPoint::AfterAnchorRename,
        );
        if anchor_result.is_err() {
            // The checkpoint may already have been renamed: never attempt an
            // in-place rollback that could leave an anchor pointing past tape.
            self.poisoned=true;
            return Err(DurableError::CommitUnknown);
        }
        self.bytes=self.bytes.checked_add(bytes.len() as u64)
            .ok_or(DurableError::TooLarge)?;
        self.verified=candidate;
        Ok(next)
    }
}

/// Only used to inject crash-like boundaries into unit tests.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum FaultPoint {None,PartialWrite,AfterDataSync,AfterAnchorRename}

#[cfg(test)]
include!("durable_tests.rs");
