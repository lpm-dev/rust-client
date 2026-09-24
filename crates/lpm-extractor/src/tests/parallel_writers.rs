use crate::writers::{TestEvent, TestHooks, WriterPool};
use crate::{
    DEFAULT_EXTRACTION_LIMITS, ExtractedFileDigest, InspectionMode,
    extract_tar_archive_with_writers,
};
use flate2::read::GzDecoder;
use std::io;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

#[derive(Default)]
struct Gate(Mutex<bool>, Condvar);

impl Gate {
    fn wait(&self) {
        self.wait_for(Duration::from_secs(10));
    }

    fn wait_for(&self, timeout: Duration) {
        let (ready, timeout) = self
            .1
            .wait_timeout_while(self.0.lock().unwrap(), timeout, |ready| !*ready)
            .unwrap();
        let released = *ready;
        drop(ready);
        assert!(
            released && !timeout.timed_out(),
            "writer gate was not released"
        );
    }

    fn release(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.1.notify_all();
    }
}

#[test]
fn a_timed_out_test_gate_can_be_released_without_a_second_panic() {
    let gate = Gate::default();
    assert!(std::panic::catch_unwind(|| gate.wait_for(Duration::ZERO)).is_err());
    assert!(std::panic::catch_unwind(|| gate.release()).is_ok());
}

struct ReleaseOnDrop(Arc<Gate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn extract_with_pool(
    archive: &[u8],
    target: &Path,
    pool: WriterPool,
    compute_blake3: bool,
) -> Result<Vec<ExtractedFileDigest>, lpm_common::LpmError> {
    extract_tar_archive_with_writers(
        GzDecoder::new(archive),
        target,
        DEFAULT_EXTRACTION_LIMITS,
        compute_blake3,
        |_, _| false,
        |_| {},
        InspectionMode::WithoutCallback,
        |mut reader| {
            io::copy(&mut reader, &mut io::sink())
                .map(|_| ())
                .map_err(Into::into)
        },
        crate::writers::WriterSetup::Ready(pool),
    )
}

fn extract(
    archive: &[u8],
    target: &Path,
    count: usize,
) -> Result<Vec<ExtractedFileDigest>, lpm_common::LpmError> {
    extract_tar_archive_with_writers(
        GzDecoder::new(archive),
        target,
        DEFAULT_EXTRACTION_LIMITS,
        true,
        |_, _| false,
        |_| {},
        InspectionMode::WithoutCallback,
        |mut reader| {
            io::copy(&mut reader, &mut io::sink())
                .map(|_| ())
                .map_err(Into::into)
        },
        if count == 0 {
            crate::writers::WriterSetup::Disabled
        } else {
            crate::writers::WriterSetup::Ready(WriterPool::new(count)?)
        },
    )
}

#[test]
fn ineligible_tails_do_not_start_writer_pools() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for duplicate in [false, true] {
        let large = vec![0; crate::writers::MAX_ENTRY_BYTES + 1];
        let tail = if duplicate {
            ("prefix", b"replacement".as_slice())
        } else {
            ("large", large.as_slice())
        };
        let archive = super::create_test_tarball_with_entries(&[("prefix", b"first"), tail]);
        let root = tempfile::tempdir().unwrap();
        let exits = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&exits);
        let result: Vec<ExtractedFileDigest> = extract_tar_archive_with_writers(
            GzDecoder::new(archive.as_slice()),
            root.path(),
            DEFAULT_EXTRACTION_LIMITS,
            true,
            |_, _| false,
            |_| {},
            InspectionMode::WithoutCallback,
            |_| Ok(()),
            crate::writers::WriterSetup::AfterFiles {
                count: 2,
                failure: None,
                minimum: 1,
                hooks: TestHooks {
                    on_exit: Some(Arc::new(move || {
                        observed.fetch_add(1, Ordering::Relaxed);
                    })),
                    ..TestHooks::default()
                },
            },
        )
        .unwrap();
        assert!(!result.is_empty());
        assert_eq!(exits.load(Ordering::Relaxed), 0, "duplicate={duplicate}");
    }
}

#[test]
fn worker_spawn_failure_preserves_serial_extraction() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const CHILD: &str = "LPM_TEST_WRITER_SPAWN_FAILURE";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::parallel_writers::worker_spawn_failure_preserves_serial_extraction",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success()
                && String::from_utf8_lossy(&result.stdout).contains("1 passed;"),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    for fail_at in [0, 1] {
        let archive = super::create_test_tarball_with_entries(&[("file", b"content")]);
        let root = tempfile::tempdir().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed_attempts = Arc::clone(&attempts);
        let exits = Arc::new(AtomicUsize::new(0));
        let observed_exits = Arc::clone(&exits);
        let result: Vec<ExtractedFileDigest> = extract_tar_archive_with_writers(
            GzDecoder::new(archive.as_slice()),
            root.path(),
            DEFAULT_EXTRACTION_LIMITS,
            true,
            |_, _| false,
            |_| {},
            InspectionMode::WithoutCallback,
            |_| Ok(()),
            crate::writers::WriterSetup::AfterFiles {
                count: 2,
                failure: None,
                minimum: 0,
                hooks: TestHooks {
                    before_spawn: Some(Arc::new(move |index| {
                        observed_attempts.fetch_add(1, Ordering::Relaxed);
                        if index == fail_at {
                            Err(io::Error::other("injected thread exhaustion"))
                        } else {
                            Ok(())
                        }
                    })),
                    on_exit: Some(Arc::new(move || {
                        observed_exits.fetch_add(1, Ordering::Relaxed);
                    })),
                    ..TestHooks::default()
                },
            },
        )
        .unwrap();
        if crate::writers::writer_pool_capacity() > 0 {
            assert_eq!(attempts.load(Ordering::Relaxed), fail_at + 1);
            assert_eq!(exits.load(Ordering::Relaxed), fail_at);
        }
        assert_eq!(result.len(), 1);
        assert_eq!(std::fs::read(root.path().join("file")).unwrap(), b"content");
    }
}

#[test]
fn parallel_files_preserve_archive_order_and_final_duplicate_digests() {
    let names: Vec<_> = (0..140)
        .map(|i| format!("dir-{}/file-{i}", i % 5))
        .collect();
    let payloads: Vec<_> = (0..140).map(|i| vec![i as u8; 100 + i * 3]).collect();
    let mut entries: Vec<_> = names
        .iter()
        .zip(&payloads)
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    entries.push((names[0].as_str(), b"replacement"));
    let archive = super::create_test_tarball_with_entries(&entries);
    let reference = tempfile::tempdir().unwrap();
    let expected = extract(&archive, reference.path(), 0).unwrap();
    for count in [1, 2, 4, 8] {
        let target = tempfile::tempdir().unwrap();
        let actual = extract(&archive, target.path(), count).unwrap();
        assert_eq!(actual, expected);
        for file in actual {
            assert_eq!(
                *blake3::hash(&std::fs::read(target.path().join(file.relative_path)).unwrap())
                    .as_bytes(),
                file.blake3_digest
            );
        }
    }
}

#[test]
fn pending_paths_reject_case_and_ancestor_conflicts_and_roll_back() {
    for paths in [["lib/Foo.js", "lib/foo.js"], ["a", "a/b"], ["a/b", "a"]] {
        let archive =
            super::create_test_tarball_with_entries(&[(paths[0], b"first"), (paths[1], b"second")]);
        for count in [1, 2, 4, 8] {
            let target = tempfile::tempdir().unwrap();
            assert!(extract(&archive, target.path(), count).is_err());
            assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
        }
    }
}

#[test]
fn large_entries_stream_between_bounded_small_file_batches() {
    let large = vec![17; crate::writers::MAX_ENTRY_BYTES + 1];
    let small = vec![23; crate::writers::MAX_ENTRY_BYTES];
    let names: Vec<_> = (0..36).map(|i| format!("file-{i}")).collect();
    let mut entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), small.as_slice()))
        .collect();
    entries.insert(19, ("large", large.as_slice()));
    let archive = super::create_test_tarball_with_entries(&entries);
    let reference = tempfile::tempdir().unwrap();
    let expected = extract(&archive, reference.path(), 0).unwrap();
    for count in [1, 2, 4, 8] {
        let target = tempfile::tempdir().unwrap();
        assert_eq!(extract(&archive, target.path(), count).unwrap(), expected);
        assert_eq!(std::fs::read(target.path().join("large")).unwrap(), large);
    }
}

#[test]
fn blocked_writers_observe_entry_and_owned_byte_limits_before_admission_continues() {
    for (size, count, expected_entries, expected_bytes) in [
        (1, 65, 64, 64),
        (
            crate::writers::MAX_ENTRY_BYTES,
            17,
            16,
            crate::writers::MAX_PENDING_BYTES,
        ),
    ] {
        let target = tempfile::tempdir().unwrap();
        let names: Vec<_> = (0..count).map(|i| format!("file-{i}")).collect();
        let payload = vec![7; size];
        let entries: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), payload.as_slice()))
            .collect();
        let archive = super::create_test_tarball_with_entries(&entries);
        let gate = Arc::new(Gate::default());
        let _release = ReleaseOnDrop(Arc::clone(&gate));
        let events = Arc::new(Mutex::new(Vec::new()));
        let hooks = TestHooks {
            before_write: Some(Arc::new({
                let gate = Arc::clone(&gate);
                move |_| {
                    gate.wait();
                    Ok(())
                }
            })),
            observer: Some(Arc::new({
                let gate = Arc::clone(&gate);
                let events = Arc::clone(&events);
                move |event| {
                    events.lock().unwrap().push(event);
                    if matches!(event, TestEvent::DrainStarted) {
                        gate.release();
                    }
                }
            })),
            ..TestHooks::default()
        };
        let records = extract_with_pool(
            &archive,
            target.path(),
            WriterPool::new_with_hooks(2, hooks, None).unwrap(),
            true,
        )
        .unwrap();
        assert_eq!(records.len(), count);
        let events = events.lock().unwrap();
        let first_drain = events
            .iter()
            .position(|e| matches!(e, TestEvent::DrainStarted))
            .unwrap();
        assert!(
            matches!(events[first_drain-1], TestEvent::Admitted {entries, bytes} if entries == expected_entries && bytes == expected_bytes)
        );
        for event in events.iter() {
            if let TestEvent::Admitted { entries, bytes } = event {
                assert!(*entries <= crate::writers::MAX_PENDING_ENTRIES);
                assert!(*bytes <= crate::writers::MAX_PENDING_BYTES);
            }
        }
    }
}

#[test]
fn worker_errors_and_panics_roll_back_partial_and_completed_files() {
    use std::io::Write;
    for mode in 0..4 {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("keep"), b"sentinel").unwrap();
        let archive = super::create_test_tarball_with_entries(&[("lib/a", b"a"), ("lib/b", b"b")]);
        let first_path = target.path().join("lib/a");
        let hooks = TestHooks {
            before_write: Some(Arc::new(move |job| {
                if job.sequence == 0 && mode != 2 {
                    job.output.file.write_all(b"partial")?;
                    if mode == 3 {
                        job.output.file = std::fs::File::open(&first_path)?;
                        return Ok(());
                    }
                    if mode == 1 {
                        panic!("injected before completion");
                    }
                    return Err(io::Error::other("injected partial write failure").into());
                }
                Ok(())
            })),
            after_write: (mode == 2).then(|| {
                Arc::new(
                    |_: &crate::writers::Written| -> Result<(), lpm_common::LpmError> {
                        panic!("injected after completion");
                    },
                ) as _
            }),
            ..TestHooks::default()
        };
        let error = extract_with_pool(
            &archive,
            target.path(),
            WriterPool::new_with_hooks(2, hooks, None).unwrap(),
            true,
        )
        .unwrap_err();
        if mode == 3 {
            assert!(matches!(error, lpm_common::LpmError::Io(_)), "{error}");
        } else {
            assert!(error.to_string().contains(if mode == 0 {
                "injected partial write failure"
            } else {
                "file writer panicked"
            }));
        }
        assert_eq!(
            std::fs::read(target.path().join("keep")).unwrap(),
            b"sentinel"
        );
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 1);
    }
}

#[test]
fn earlier_worker_error_wins_even_when_later_error_completes_first() {
    let target = tempfile::tempdir().unwrap();
    let archive =
        super::create_test_tarball_with_entries(&[("a", b"a"), ("b", b"b"), ("B", b"conflict")]);
    let gate = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(Arc::clone(&gate));
    let hooks = TestHooks {
        before_write: Some(Arc::new({
            let gate = Arc::clone(&gate);
            move |job| {
                if job.sequence == 0 {
                    gate.wait();
                }
                Err(io::Error::other(format!("failure {}", job.sequence)).into())
            }
        })),
        observer: Some(Arc::new({
            let gate = Arc::clone(&gate);
            move |event| {
                if matches!(event, TestEvent::Completed { sequence: 1 }) {
                    gate.release();
                }
            }
        })),
        ..TestHooks::default()
    };
    let error = extract_with_pool(
        &archive,
        target.path(),
        WriterPool::new_with_hooks(2, hooks, None).unwrap(),
        true,
    )
    .unwrap_err();
    assert!(error.to_string().contains("failure 0"), "{error}");
    assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
}

#[test]
fn cleanup_waits_for_worker_exit_after_completion_delivery() {
    let target = tempfile::tempdir().unwrap();
    let archive = super::create_test_tarball_with_entries(&[("a", b"a"), ("A", b"conflict")]);
    let gate = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(Arc::clone(&gate));
    let (exiting, observed) = mpsc::channel();
    let (done, result) = mpsc::channel();
    let hooks = TestHooks {
        on_exit: Some(Arc::new({
            let gate = Arc::clone(&gate);
            move || {
                exiting.send(()).unwrap();
                gate.wait();
            }
        })),
        ..TestHooks::default()
    };
    let path = target.path().to_path_buf();
    let worker = std::thread::spawn(move || {
        let extracted = extract_with_pool(
            &archive,
            &path,
            WriterPool::new_with_hooks(1, hooks, None).unwrap(),
            true,
        );
        done.send(extracted).unwrap();
    });
    observed.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(std::fs::read(target.path().join("a")).unwrap(), b"a");
    assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
    gate.release();
    assert!(
        result
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .is_err()
    );
    worker.join().unwrap();
    assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
}

#[test]
fn record_failure_rolls_back_completed_files() {
    let target = tempfile::tempdir().unwrap();
    let archive = super::create_test_tarball_with_entries(&[("lib/a", b"a"), ("lib/b", b"b")]);
    let error =
        extract_with_pool(&archive, target.path(), WriterPool::new(2).unwrap(), false).unwrap_err();
    assert!(error.to_string().contains("digest"), "{error}");
    assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
}

#[test]
fn replacement_after_worker_completion_is_rejected_without_deleting_the_replacement() {
    let target = tempfile::tempdir().unwrap();
    let archive = super::create_test_tarball_with_entries(&[("file", b"original")]);
    let root = target.path().to_path_buf();
    let hooks = TestHooks {
        after_write: Some(Arc::new(move |_| {
            std::fs::rename(root.join("file"), root.join("moved"))?;
            std::fs::write(root.join("file"), b"replacement")?;
            Ok(())
        })),
        ..TestHooks::default()
    };
    let result = extract_with_pool(
        &archive,
        target.path(),
        WriterPool::new_with_hooks(1, hooks, None).unwrap(),
        true,
    );
    assert!(result.is_err(), "replacement was accepted: {result:?}");
    assert_eq!(
        std::fs::read(target.path().join("file")).unwrap(),
        b"replacement"
    );
    assert_eq!(
        std::fs::read(target.path().join("moved")).unwrap(),
        b"original"
    );
}

#[test]
fn terminal_input_failure_rolls_back_committed_worker_files() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("keep"), b"sentinel").unwrap();
    let archive = super::create_test_tarball_with_entries(&[("lib/a", b"a"), ("lib/b", b"b")]);
    let result: Result<Vec<ExtractedFileDigest>, _> = extract_tar_archive_with_writers(
        GzDecoder::new(archive.as_slice()),
        target.path(),
        DEFAULT_EXTRACTION_LIMITS,
        true,
        |_, _| false,
        |_| {},
        InspectionMode::WithoutCallback,
        |_| {
            assert_eq!(std::fs::read(target.path().join("lib/a")).unwrap(), b"a");
            assert_eq!(std::fs::read(target.path().join("lib/b")).unwrap(), b"b");
            Err(io::Error::other("injected terminal input failure").into())
        },
        crate::writers::WriterSetup::Ready(WriterPool::new(2).unwrap()),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("terminal input failure")
    );
    assert_eq!(
        std::fs::read(target.path().join("keep")).unwrap(),
        b"sentinel"
    );
    assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 1);
}

#[test]
fn many_file_archives_start_writers_after_the_serial_prefix() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let names: Vec<_> = (0..270).map(|i| format!("file-{i}")).collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), b"data".as_slice()))
        .collect();
    let archive = super::create_test_tarball_with_entries(&entries);
    let reference = tempfile::tempdir().unwrap();
    let expected = extract(&archive, reference.path(), 0).unwrap();
    for inspection in [
        InspectionMode::WithoutCallback,
        InspectionMode::WithCallback,
    ] {
        let target = tempfile::tempdir().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let hooks = TestHooks {
            before_write: Some(Arc::new({
                let writes = Arc::clone(&writes);
                move |_| {
                    writes.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            })),
            ..TestHooks::default()
        };
        let actual: Vec<ExtractedFileDigest> = extract_tar_archive_with_writers(
            GzDecoder::new(archive.as_slice()),
            target.path(),
            DEFAULT_EXTRACTION_LIMITS,
            true,
            |_, _| false,
            |_| {},
            inspection,
            |mut reader| {
                io::copy(&mut reader, &mut io::sink())
                    .map(|_| ())
                    .map_err(Into::into)
            },
            crate::writers::WriterSetup::AfterFiles {
                count: 2,
                failure: None,
                minimum: 256,
                hooks,
            },
        )
        .unwrap();
        assert_eq!(actual, expected);
        let expected_writes = if matches!(inspection, InspectionMode::WithoutCallback) {
            14
        } else {
            0
        };
        assert_eq!(writes.load(Ordering::Relaxed), expected_writes);
    }
}
