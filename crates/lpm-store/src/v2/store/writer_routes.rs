use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{Event, Metadata, Subscriber, span};

struct WriterProbe(Arc<AtomicUsize>);

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

fn has_writer_capacity() -> bool {
    #[cfg(unix)]
    {
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: getrlimit initializes the valid out pointer on success.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
            return false;
        }
        // SAFETY: getrlimit succeeded.
        unsafe { limit.assume_init().rlim_cur >= 2 * (2 * 64 + 8) }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn many_file_archive() -> Vec<u8> {
    use std::io::Read;
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    let mut archive = tar::Builder::new(gzip);
    let size = lpm_extractor::MAX_HYBRID_BUFFERED_COMPRESSED_SIZE + 1024;
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(
            &mut header,
            "package/large",
            std::io::repeat(0x5a).take(size),
        )
        .unwrap();
    for index in 0..270 {
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o755);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                format!("package/file-{index}"),
                b"data".as_slice(),
            )
            .unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap()
}

#[test]
fn downloaded_file_routes_activate_writers_only_without_inspection() {
    const CHILD: &str = "LPM_TEST_STORE_FILE_WRITERS";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "v2::store::tests::writer_routes::downloaded_file_routes_activate_writers_only_without_inspection", "--nocapture"])
            .env(CHILD, "1").env("LPM_INTERNAL_EXTRACT_WRITERS", "2")
            .output().unwrap();
        assert!(
            result.status.success()
                && String::from_utf8_lossy(&result.stdout).contains("1 passed;"),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let bytes = many_file_archive();
    let sri = crate::compute_sri_hash(&bytes);
    let _other_dispatcher = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    for policy in [
        SecurityAnalysisPolicy::Disabled,
        SecurityAnalysisPolicy::Enabled,
    ] {
        for known in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let archive = root.path().join("archive.tgz");
            std::fs::write(&archive, &bytes).unwrap();
            let store = Store::at_with_policies(
                root.path().join("store"),
                ObjectIntegrityPolicy::Source,
                policy,
            );
            let activations = Arc::new(AtomicUsize::new(0));
            let object =
                tracing::subscriber::with_default(WriterProbe(Arc::clone(&activations)), || {
                    if known {
                        store
                            .extract_object_from_file_with_known_sha512(
                                std::fs::File::open(&archive).unwrap(),
                                &sri,
                                Some(&sri),
                                bytes.len() as u64,
                            )
                            .map(|(object, _, _)| object.path)
                    } else {
                        store
                            .extract_object_from_file(&archive, &sri)
                            .map(|(path, _)| path)
                    }
                })
                .unwrap();
            assert_eq!(
                activations.load(Ordering::Relaxed),
                usize::from(!policy.is_enabled() && has_writer_capacity())
            );
            for index in 0..270 {
                let file = object.join(format!("file-{index}"));
                assert_eq!(std::fs::read(&file).unwrap(), b"data");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    assert_eq!(
                        std::fs::metadata(&file).unwrap().permissions().mode() & 0o111,
                        0o111
                    );
                }
            }
            assert_eq!(
                std::fs::read_to_string(object.join(".integrity")).unwrap(),
                sri
            );
        }
    }
}
