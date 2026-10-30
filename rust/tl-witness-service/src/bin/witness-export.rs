//! Separate operator recovery capability. Never exposed by witnessctl latest/CAS.
#![forbid(unsafe_code)]
#[cfg(unix)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        env, fs,
        io::{self, Read, Write},
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        time::Duration,
    };
    use tl_collator_wire::parse_canonical_text;
    use tl_witness_service::{
        recovery::{export_history, RecoveryLimits, RecoveryPolicy, MAX_METADATA_BYTES},
        Config,
    };
    fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let value = env::var(name)?;
        if value.is_empty() {
            return Err("missing configuration".into());
        }
        Ok(value)
    }
    fn restricted(path: &Path, owner: u32, cap: u64) -> Result<String, Box<dyn std::error::Error>> {
        let meta = fs::symlink_metadata(path)?;
        if !meta.file_type().is_file()
            || meta.permissions().mode() & 0o077 != 0
            || meta.uid() != owner
            || meta.len() > cap
        {
            return Err("restricted file required".into());
        }
        let mut raw = String::new();
        fs::File::open(path)?
            .take(cap + 1)
            .read_to_string(&mut raw)?;
        if raw.len() as u64 > cap {
            return Err("file too large".into());
        }
        Ok(raw)
    }
    if env::args_os().len() != 1 {
        return Err("no command arguments accepted".into());
    }
    let dir = PathBuf::from(required("TL_WITNESS_DATA_DIR")?);
    let meta = fs::symlink_metadata(&dir)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err("restricted real directory required".into());
    }
    let raw_policy = restricted(
        Path::new(&required("TL_WITNESS_EXPORT_POLICY")?),
        meta.uid(),
        4096,
    )?;
    let value = parse_canonical_text(&raw_policy)?;
    let names = [
        "operatorId",
        "operatorPubKey",
        "maxRecords",
        "maxRecordBytes",
        "maxExportBytes",
        "maxScanBytes",
        "timeoutMillis",
    ];
    let map = value.as_object().ok_or("policy object required")?;
    if map.len() != names.len() || names.iter().any(|n| !map.contains_key(*n)) {
        return Err("invalid policy".into());
    }
    let number = |name: &str| -> Result<u64, Box<dyn std::error::Error>> {
        value[name]
            .as_u64()
            .ok_or_else(|| "invalid policy number".into())
    };
    let policy = RecoveryPolicy::new(
        value["operatorId"].as_str().ok_or("operator required")?,
        value["operatorPubKey"]
            .as_str()
            .ok_or("operator key required")?,
        RecoveryLimits {
            max_records: usize::try_from(number("maxRecords")?)?,
            max_record_bytes: usize::try_from(number("maxRecordBytes")?)?,
            max_export_bytes: usize::try_from(number("maxExportBytes")?)?,
            max_scan_bytes: number("maxScanBytes")?,
            timeout: Duration::from_millis(number("timeoutMillis")?),
        },
    )?;
    // Process-wide watchdog covers blocked stdin, filesystem I/O and stdout.
    // A killed/truncated response must never pass manifest/digest verification.
    let timeout = policy.limits.timeout;
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        std::process::exit(1);
    });
    let mut request = String::new();
    io::stdin()
        .take(MAX_METADATA_BYTES as u64 + 1)
        .read_to_string(&mut request)?;
    if request.len() > MAX_METADATA_BYTES {
        return Err("request too large".into());
    }
    let config = Config {
        collator_id: required("TL_WITNESS_COLLATOR_ID")?,
        collator_pubkey: required("TL_WITNESS_COLLATOR_PUBKEY")?,
        network: required("TL_WITNESS_NETWORK")?,
        stream: required("TL_WITNESS_STREAM")?,
        epoch: required("TL_WITNESS_EPOCH")?.parse()?,
        max_entries: required("TL_WITNESS_MAX_ENTRIES")?.parse()?,
    };
    let mut raw_key = restricted(
        Path::new(&required("TL_WITNESS_KEY_FILE")?),
        meta.uid(),
        128,
    )?;
    let mut private = [0u8; 32];
    let decoded = (|| -> Result<(), Box<dyn std::error::Error>> {
        let text = raw_key.trim();
        if text.len() != 64 {
            return Err("invalid key".into());
        }
        for (i, b) in private.iter_mut().enumerate() {
            let pair = text.get(i * 2..i * 2 + 2).ok_or("invalid key")?;
            *b = u8::from_str_radix(pair, 16)?;
        }
        Ok(())
    })();
    // clear() does not zero memory; overwrite the owned byte buffer safely.
    let mut bytes = std::mem::take(&mut raw_key).into_bytes();
    bytes.fill(0);
    decoded?;
    let result = export_history(
        &dir,
        &config,
        &private,
        &policy,
        request.trim_end_matches('\n'),
    );
    private.fill(0);
    let bundle = result?;
    let mut out = io::stdout().lock();
    out.write_all(bundle.manifest.as_bytes())?;
    out.write_all(b"\n")?;
    out.write_all(bundle.ndjson.as_bytes())?;
    out.flush()?;
    Ok(())
}
fn main() {
    #[cfg(unix)]
    if run().is_ok() {
        return;
    }
    eprintln!("witness-export: request refused");
    std::process::exit(1);
}
