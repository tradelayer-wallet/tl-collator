//! Test-only barriers and SIGKILL matrix. None of this module or its environment
//! variables exists in production libraries, executables or normal consumers.
use super::{
    tests::{key_hex, new_line, TestDir},
    *,
};
use serde_json::Value;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CrashStage {
    BeforeTapeWrite,
    PartialTapeWrite,
    AfterTapeSync,
    AfterCheckpointTempSync,
    AfterCheckpointRename,
    AfterDirectorySync,
    BeforeAcknowledgment,
}
impl CrashStage {
    fn name(self) -> &'static str {
        match self {
            Self::BeforeTapeWrite => "before-tape-write",
            Self::PartialTapeWrite => "partial-tape-write",
            Self::AfterTapeSync => "after-tape-sync",
            Self::AfterCheckpointTempSync => "after-checkpoint-temp-sync",
            Self::AfterCheckpointRename => "after-checkpoint-rename",
            Self::AfterDirectorySync => "after-directory-sync",
            Self::BeforeAcknowledgment => "before-acknowledgment",
        }
    }
    fn tape_complete(self) -> bool {
        !matches!(self, Self::BeforeTapeWrite | Self::PartialTapeWrite)
    }
    fn checkpoint_current(self) -> bool {
        matches!(
            self,
            Self::AfterCheckpointRename | Self::AfterDirectorySync | Self::BeforeAcknowledgment
        )
    }
}

pub(super) fn pause_at(stage: CrashStage) {
    if std::env::var("TL_TEST_TAPE_CRASH_STAGE").ok().as_deref() != Some(stage.name()) {
        return;
    }
    // Pipe coordination performs no extra filesystem sync at the crash point.
    println!("TL_TAPE_CRASH_READY|{}", stage.name());
    io::stdout().flush().unwrap();
    loop {
        thread::park();
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "entrypoint used only by the parent SIGKILL matrix"]
fn crash_child_helper() {
    let Some(path) = std::env::var_os("TL_TEST_TAPE_CRASH_PATH") else {
        return;
    };
    let stage = std::env::var("TL_TEST_TAPE_CRASH_STAGE").unwrap();
    let directory = PathBuf::from(path);
    let start = Instant::now();
    let mut writer = loop {
        match DurableTape::open(
            &directory,
            "orders",
            "collator-1",
            &key_hex(&[3; 32]),
            256,
            ImportMode::RequireAnchor,
        ) {
            Ok(writer) => break writer,
            // Concurrent test fork/exec can briefly inherit a CLOEXEC flock.
            Err(DurableError::LockBusy) if start.elapsed() < Duration::from_secs(2) => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => panic!("child startup: {error:?}"),
        }
    };
    assert_eq!(writer.checkpoint().last_seq, 1);
    let second = new_line(22, 2, &writer.checkpoint().last_hash);
    let point = if stage == CrashStage::PartialTapeWrite.name() {
        FaultPoint::PartialWrite
    } else {
        FaultPoint::None
    };
    writer.append_inner(&second, point).unwrap();
    panic!("writer returned an acknowledgment without reaching the requested barrier");
}

#[test]
fn sigkill_at_each_durable_boundary_recovers_the_exact_signed_prefix() {
    for stage in [
        CrashStage::BeforeTapeWrite,
        CrashStage::PartialTapeWrite,
        CrashStage::AfterTapeSync,
        CrashStage::AfterCheckpointTempSync,
        CrashStage::AfterCheckpointRename,
        CrashStage::AfterDirectorySync,
        CrashStage::BeforeAcknowledgment,
    ] {
        let directory = TestDir::new();
        let mut initial = directory.open(ImportMode::RequireAnchor).unwrap();
        let first = new_line(11, 1, "");
        let before = initial.append_signed(&first).unwrap();
        let second = new_line(22, 2, &before.last_hash);
        let value: Value = serde_json::from_str(&second).unwrap();
        let planned = Checkpoint {
            last_seq: 2,
            last_hash: value["entryHash"].as_str().unwrap().into(),
            seen_orders: 2,
        };
        let prior_bytes = fs::read(directory.tape()).unwrap();
        drop(initial);
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "durable::crash_tests::crash_child_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TL_TEST_TAPE_CRASH_PATH", &directory.0)
            .env("TL_TEST_TAPE_CRASH_STAGE", stage.name())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().unwrap();
        let marker = format!("TL_TAPE_CRASH_READY|{}", stage.name());
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                let mut input = BufReader::new(stdout).take(16_384);
                let mut line = String::new();
                loop {
                    line.clear();
                    if input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                        return Err("child exited before barrier".into());
                    }
                    if line.contains(&marker) {
                        return Ok(());
                    }
                }
            })();
            let _ = sender.send(result);
        });
        receiver
            .recv_timeout(Duration::from_secs(6))
            .expect("crash barrier deadline")
            .expect("child barrier");
        reader.join().unwrap();
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child must be live at {stage:?}"
        );
        assert!(matches!(
            directory.open(ImportMode::RequireAnchor),
            Err(DurableError::LockBusy)
        ));
        let anchored = read_anchor(&directory.anchor()).unwrap().unwrap();
        assert_eq!(
            anchored.seq,
            if stage.checkpoint_current() { 2 } else { 1 },
            "{stage:?}"
        );
        let interrupted = fs::read(directory.tape()).unwrap();
        assert!(interrupted.starts_with(&prior_bytes));
        if stage == CrashStage::BeforeTapeWrite {
            assert_eq!(interrupted, prior_bytes);
        } else if stage == CrashStage::PartialTapeWrite {
            assert!(interrupted.len() > prior_bytes.len());
            assert!(interrupted.len() < prior_bytes.len() + second.len() + 1);
        } else {
            assert_eq!(interrupted, format!("{first}\n{second}\n").as_bytes());
        }
        let orphan_evidence = if stage == CrashStage::AfterCheckpointTempSync {
            let temps: Vec<_> = fs::read_dir(&directory.0)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".orders.checkpoint.tmp.")
                })
                .collect();
            assert_eq!(temps.len(), 1);
            assert_eq!(read_anchor(&temps[0]).unwrap().unwrap().seq, 2);
            Some((temps[0].clone(), fs::read(&temps[0]).unwrap()))
        } else {
            None
        };
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        assert_eq!(status.signal(), Some(9));
        let mut restarted = directory.open(ImportMode::RequireAnchor).unwrap();
        if let Some((path, bytes)) = orphan_evidence {
            assert_eq!(
                fs::read(path).unwrap(),
                bytes,
                "restart must preserve orphaned checkpoint evidence"
            );
        }
        assert_eq!(
            restarted.checkpoint(),
            if stage.tape_complete() {
                planned.clone()
            } else {
                before.clone()
            },
            "{stage:?}"
        );
        let recovery = restarted.recovery();
        assert_eq!(
            recovery.torn_tail_bytes > 0,
            stage == CrashStage::PartialTapeWrite
        );
        assert_eq!(
            recovery.unanchored_records,
            if stage.tape_complete() && !stage.checkpoint_current() {
                1
            } else {
                0
            }
        );
        if !stage.tape_complete() {
            assert_eq!(restarted.append_signed(&second).unwrap(), planned);
        }
        assert!(matches!(
            restarted.append_signed(&new_line(22, 3, &planned.last_hash)),
            Err(DurableError::Verify(VerifyError::Duplicate))
        ));
        let after = restarted
            .append_signed(&new_line(33, 3, &planned.last_hash))
            .unwrap();
        assert_eq!(after.last_seq, 3);
        drop(restarted);
        assert_eq!(
            directory
                .open(ImportMode::RequireAnchor)
                .unwrap()
                .checkpoint(),
            after
        );
        println!("SIGKILL boundary verified: {}", stage.name());
    }
}
