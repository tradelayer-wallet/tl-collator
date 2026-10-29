//! Operator-restricted one-shot CLI for an independently hosted witness.
//! No HTTP listener. Authentication is provided by the operator's SSH/OS policy.
#[cfg(unix)]
mod unix_cli {
    use std::{
        env,
        error::Error,
        fs,
        io::{self, Read},
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };
    use tl_collator_wire::{verify::Checkpoint, MAX_INPUT_BYTES};
    use tl_witness_service::{Config, WitnessService};

    type Result<T> = std::result::Result<T, Box<dyn Error>>;
    fn required(name: &str) -> Result<String> {
        let value=env::var(name).map_err(|_| format!("missing configured {name}"))?;
        if value.is_empty(){return Err(format!("empty configured {name}").into());}
        Ok(value)
    }
    fn restricted_dir(path:&Path)->Result<()> {
        let metadata=fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("witness directory must be a restricted real directory (0700)".into());
        }
        Ok(())
    }
    fn load_private_key(path:&Path, dir:&Path)->Result<[u8;32]> {
        let metadata=fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 ||
            metadata.len()>128 {
            return Err("witness key file must be regular, restricted (0600), <=128 bytes".into());
        }
        if metadata.uid() != fs::symlink_metadata(dir)?.uid() {
            return Err("witness key owner does not match store owner".into());
        }
        let mut raw=fs::read(path)?;
        let mut secret=[0u8;32];
        let decode=(||->Result<()>{
            let text=std::str::from_utf8(&raw)?;
            let hex=text.trim();
            if hex.len()!=64 || !hex.bytes().all(|b|b.is_ascii_hexdigit()){
                return Err("witness key is not 32-byte hex".into());
            }
            for (i,b) in secret.iter_mut().enumerate() {
                *b=u8::from_str_radix(&hex[2*i..2*i+2],16)?;
            }
            Ok(())
        })();
        raw.fill(0);
        decode?;
        Ok(secret)
    }
    trait OwnerId { fn uid(&self)->u32; }
    impl OwnerId for fs::Metadata {
        fn uid(&self)->u32 {
            use std::os::unix::fs::MetadataExt;
            MetadataExt::uid(self)
        }
    }

    pub fn run() -> Result<String> {
        let args:Vec<String>=env::args().skip(1).collect();
        let mode=args.first().ok_or("expected latest or cas command")?;
        if !(mode=="latest" && args.len()==2 || mode=="cas" && args.len()==4) {
            return Err("usage: witnessctl latest <challenge> OR witnessctl cas <seq> <hash> <orders>".into());
        }
        let directory=PathBuf::from(required("TL_WITNESS_DATA_DIR")?);
        restricted_dir(&directory)?;
        let keypath=PathBuf::from(required("TL_WITNESS_KEY_FILE")?);
        let mut private=load_private_key(&keypath,&directory)?;
        let config=Config{
            collator_id:required("TL_WITNESS_COLLATOR_ID")?,
            collator_pubkey:required("TL_WITNESS_COLLATOR_PUBKEY")?,
            network:required("TL_WITNESS_NETWORK")?,
            stream:required("TL_WITNESS_STREAM")?,
            epoch:required("TL_WITNESS_EPOCH")?.parse()?,
            max_entries:required("TL_WITNESS_MAX_ENTRIES")?.parse()?,
        };
        let service=WitnessService::open(&directory,config,&private);
        private.fill(0);
        let mut service=service?;
        if mode=="latest" {
            return Ok(service.attest_latest(&args[1])?);
        }
        let expected=Checkpoint{
            last_seq:args[1].parse()?,
            last_hash:args[2].clone(),
            seen_orders:args[3].parse()?,
        };
        // Only a single size-bounded complete signed entry is accepted from
        // authenticated stdin. No unbounded read_to_string / split lines.
        let mut bytes=Vec::new();
        io::stdin().take(MAX_INPUT_BYTES as u64 + 2).read_to_end(&mut bytes)?;
        if bytes.len()>MAX_INPUT_BYTES+1{return Err("entry too long".into());}
        if bytes.last()==Some(&b'\n'){bytes.pop();}
        let entry=std::str::from_utf8(&bytes)?;
        if entry.is_empty() || entry.as_bytes().contains(&b'\n') || entry.as_bytes().contains(&b'\r') {
            return Err("invalid signed entry".into());
        }
        let head=service.compare_and_swap(&expected,entry)?;
        Ok(serde_json::json!({
            "seq":head.last_seq,"headHash":head.last_hash,"seenOrders":head.seen_orders
        }).to_string())
    }
}
#[cfg(unix)]
fn main() {
    match unix_cli::run() {
        Ok(output)=>println!("{output}"),
        Err(_)=>{eprintln!("witnessctl: request refused");std::process::exit(1);}
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("witnessctl: unsupported platform");
    std::process::exit(1);
}
