use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{Event, Metadata, Subscriber, span};

struct WriterProbe(Arc<AtomicUsize>);

#[cfg(unix)]
#[test]
fn public_digest_routes_complete_with_a_low_descriptor_limit() {
    const CHILD: &str = "LPM_TEST_LOW_DESCRIPTOR_WRITERS";
    if std::env::var_os(CHILD).is_none() {
        use std::os::unix::process::CommandExt;
        for writers in ["0", "2"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "tests::public_writer_activation::public_digest_routes_complete_with_a_low_descriptor_limit",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("LPM_INTERNAL_EXTRACT_WRITERS", writers);
            // SAFETY: The child hook only invokes async-signal-safe resource-limit calls.
            unsafe {
                command.pre_exec(|| {
                    let mut limit = std::mem::zeroed();
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    limit.rlim_cur = 96;
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let result = command.output().unwrap();
            assert!(
                result.status.success()
                    && String::from_utf8_lossy(&result.stdout).contains("1 passed;"),
                "writers={writers}: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        return;
    }
    let names: Vec<_> = (0..460).map(|index| format!("dir-{index}/file")).collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), b"data".as_slice()))
        .collect();
    let archive = super::create_test_tarball_with_entries(&entries);
    for route in ["buffered", "streaming", "hybrid-file", "pipelined-file"] {
        let target = tempfile::tempdir().unwrap();
        let files = match route {
            "buffered" => crate::extract_tarball_digests(&archive, target.path()),
            "streaming" => crate::extract_tarball_from_reader_streaming_digests(
                archive.as_slice(),
                target.path(),
            ),
            "hybrid-file" => {
                crate::extract_tarball_from_reader_hybrid_digests(archive.as_slice(), target.path())
            }
            "pipelined-file" => crate::extract_tarball_from_reader_pipelined_digests(
                archive.as_slice(),
                target.path(),
                || {},
            ),
            _ => unreachable!(),
        }
        .unwrap_or_else(|error| panic!("{route}: {error}"));
        assert_eq!(files.len(), entries.len(), "{route}");
        for file in files {
            assert_eq!(
                std::fs::read(target.path().join(file.relative_path)).unwrap(),
                b"data"
            );
        }
    }
}

impl Subscriber for WriterProbe {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_span() && metadata.name() == "tar_entry_writer_pool"
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(self.0.fetch_add(1, Ordering::Relaxed) as u64 + 1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

#[test]
fn public_digest_routes_preserve_contents_with_supported_writer_activation() {
    const CHILD: &str = "LPM_TEST_PUBLIC_WRITER_ACTIVATION";
    if std::env::var_os(CHILD).is_none() {
        for writers in [None, Some("0"), Some("1")] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "tests::public_writer_activation::public_digest_routes_preserve_contents_with_supported_writer_activation",
                "--nocapture",
            ]).env(CHILD, "1");
            if let Some(writers) = writers {
                command.env("LPM_INTERNAL_EXTRACT_WRITERS", writers);
            } else {
                command.env_remove("LPM_INTERNAL_EXTRACT_WRITERS");
            }
            let result = command.output().unwrap();
            assert!(
                result.status.success()
                    && String::from_utf8_lossy(&result.stdout).contains("1 passed;"),
                "writers={writers:?}: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        return;
    }

    for file_count in [100, 270] {
        let names: Vec<_> = (0..file_count)
            .map(|index| format!("file-{index}"))
            .collect();
        let entries: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), b"content".as_slice()))
            .collect();
        let archive = super::create_test_tarball_with_entries(&entries);
        let input = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(input.path(), &archive).unwrap();
        let _other_dispatcher =
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        for route in ["buffered", "streaming", "hybrid-file", "pipelined-file"] {
            let target = tempfile::tempdir().unwrap();
            let activations = Arc::new(AtomicUsize::new(0));
            let files =
                tracing::subscriber::with_default(WriterProbe(Arc::clone(&activations)), || {
                    match route {
                        "buffered" => crate::extract_tarball_digests(&archive, target.path()),
                        "streaming" => crate::extract_tarball_from_reader_streaming_digests(
                            archive.as_slice(),
                            target.path(),
                        ),
                        "hybrid-file" => crate::extract_tarball_from_reader_hybrid_digests(
                            std::fs::File::open(input.path()).unwrap(),
                            target.path(),
                        ),
                        "pipelined-file" => crate::extract_tarball_from_reader_pipelined_digests(
                            std::fs::File::open(input.path()).unwrap(),
                            target.path(),
                            || {},
                        ),
                        _ => unreachable!(),
                    }
                })
                .unwrap();
            assert_eq!(
                activations.load(Ordering::Relaxed),
                usize::from(
                    route != "streaming"
                        && file_count > 256
                        && std::env::var("LPM_INTERNAL_EXTRACT_WRITERS").as_deref() != Ok("0")
                        && crate::writers::writer_pool_capacity() > 0
                ),
                "{route}"
            );
            assert_eq!(files.len(), entries.len(), "{route}");
            for (file, name) in files.iter().zip(&names) {
                assert_eq!(&file.relative_path, std::path::Path::new(name), "{route}");
                let bytes = std::fs::read(target.path().join(&file.relative_path)).unwrap();
                assert_eq!(bytes, b"content", "{route}");
                assert_eq!(
                    *blake3::hash(&bytes).as_bytes(),
                    file.blake3_digest,
                    "{route}"
                );
            }
        }
    }
}
