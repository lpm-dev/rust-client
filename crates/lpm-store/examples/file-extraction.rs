//! Measure file extraction with an existing archive and its declared SRI.
use std::{path::PathBuf, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let archive = PathBuf::from(args.next().ok_or("expected archive path")?);
    let integrity = args.next().ok_or("expected declared SRI")?;
    let integrity = integrity.to_str().ok_or("SRI must be UTF-8")?;
    let directory = tempfile::tempdir()?;
    let store = lpm_store::v2::Store::at_with_policies(
        directory.path(),
        lpm_store::v2::ObjectIntegrityPolicy::Source,
        lpm_store::SecurityAnalysisPolicy::Disabled,
    );
    let started = Instant::now();
    let (_, timings) = store.extract_object_from_file(&archive, integrity)?;
    println!(
        "{}",
        serde_json::json!({
            "elapsed_ns": started.elapsed().as_nanos(),
            "file_count": timings.file_count,
            "dir_count": timings.dir_count,
            "unpacked_bytes": timings.unpacked_bytes,
        })
    );
    Ok(())
}
