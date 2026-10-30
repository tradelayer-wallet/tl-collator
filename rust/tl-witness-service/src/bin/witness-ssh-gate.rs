//! Fixed authorized_keys command; arguments/policy are administrator controlled.
#![forbid(unsafe_code)]

#[cfg(unix)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        env, fs,
        io::Read,
        os::unix::{fs::MetadataExt, process::CommandExt},
        path::Path,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use tl_collator_wire::parse_canonical_text;
    use tl_witness_service::{
        forced_command::{self, Capability, ForcedCommand},
        Config,
    };
    fn pinned_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let meta = fs::symlink_metadata(path)?;
        if !path.is_absolute()
            || !meta.file_type().is_file()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
        {
            return Err("administrator-controlled absolute file required".into());
        }
        Ok(())
    }
    let args: Vec<_> = env::args().skip(1).take(4).collect();
    if args.len() != 2 {
        return Err("fixed role and policy required".into());
    }
    let role = match args[0].as_str() {
        "witness" => Capability::Witness,
        "recovery" => Capability::Recovery,
        _ => return Err("invalid role".into()),
    };
    let original = env::var("SSH_ORIGINAL_COMMAND").map_err(|_| "missing original command")?;
    let parsed = forced_command::parse(role, &original).map_err(|_| "unauthorized command")?;
    let policy_path = Path::new(&args[1]);
    pinned_file(policy_path)?;
    let mut raw = String::new();
    fs::File::open(policy_path)?
        .take(16_385)
        .read_to_string(&mut raw)?;
    if raw.len() > 16_384 {
        return Err("policy too large".into());
    }
    let policy = parse_canonical_text(&raw)?;
    let fields = [
        "witnessctl",
        "exporter",
        "dataDir",
        "keyFile",
        "exportPolicyFile",
        "collatorId",
        "collatorPubKey",
        "network",
        "stream",
        "epoch",
        "maxEntries",
        "timeoutMillis",
    ];
    let map = policy.as_object().ok_or("policy object required")?;
    if map.len() != fields.len() || fields.iter().any(|n| !map.contains_key(*n)) {
        return Err("invalid policy fields".into());
    }
    let string = |name: &str| policy[name].as_str().ok_or("invalid policy string");
    let number = |name: &str| policy[name].as_u64().ok_or("invalid policy number");
    let timeout = Duration::from_millis(number("timeoutMillis")?);
    if timeout < Duration::from_millis(100) || timeout > Duration::from_secs(60) {
        return Err("invalid deadline".into());
    }
    let config = Config {
        collator_id: string("collatorId")?.into(),
        collator_pubkey: string("collatorPubKey")?.into(),
        network: string("network")?.into(),
        stream: string("stream")?.into(),
        epoch: number("epoch")?,
        max_entries: usize::try_from(number("maxEntries")?)?,
    };
    config.validate()?;
    for name in ["dataDir", "keyFile", "exportPolicyFile"] {
        if !Path::new(string(name)?).is_absolute() {
            return Err("absolute configured paths required".into());
        }
    }
    let binary = if role == Capability::Witness {
        string("witnessctl")?
    } else {
        string("exporter")?
    };
    pinned_file(Path::new(binary))?;
    // Fixed program text only: original command text is never evaluated.
    // POSIX umask is set before exec without an unsafe pre_exec callback.
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "umask 077; exec \"$@\"", "witness-ssh-gate", binary]);
    command
        .env_clear()
        .env("TL_WITNESS_DATA_DIR", string("dataDir")?)
        .env("TL_WITNESS_KEY_FILE", string("keyFile")?)
        .env("TL_WITNESS_EXPORT_POLICY", string("exportPolicyFile")?)
        .env("TL_WITNESS_COLLATOR_ID", &config.collator_id)
        .env("TL_WITNESS_COLLATOR_PUBKEY", &config.collator_pubkey)
        .env("TL_WITNESS_NETWORK", &config.network)
        .env("TL_WITNESS_STREAM", &config.stream)
        .env("TL_WITNESS_EPOCH", config.epoch.to_string())
        .env("TL_WITNESS_MAX_ENTRIES", config.max_entries.to_string());
    match parsed {
        ForcedCommand::Latest { challenge } => {
            command.args(["latest", &challenge]);
        }
        ForcedCommand::Cas {
            seq,
            hash,
            orders,
            challenge,
        } => {
            command.args([
                "cas",
                &seq.to_string(),
                &hash,
                &orders.to_string(),
                &challenge,
            ]);
        }
        ForcedCommand::Export => {}
    }
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .process_group(0);
    let start = Instant::now();
    let mut child = command.spawn()?;
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    if result {
        Ok(())
    } else {
        Err("command refused".into())
    }
}

fn main() {
    #[cfg(unix)]
    if run().is_ok() {
        return;
    }
    eprintln!("witness-ssh-gate: request refused");
    std::process::exit(1);
}
