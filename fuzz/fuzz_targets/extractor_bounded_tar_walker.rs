#![no_main]

use std::ops::ControlFlow;

use libfuzzer_sys::fuzz_target;
use lpm_extractor::{TarArchiveLimits, visit_tar_archive};

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }

    let limits = TarArchiveLimits {
        max_entries: 32,
        max_metadata_entries: 32,
        max_entry_bytes: 64 * 1024,
        max_total_entry_bytes: 256 * 1024,
        max_path_depth: 32,
        max_path_bytes: 4 * 1024,
        max_metadata_bytes: 4 * 1024,
    };
    let _ = visit_tar_archive(data, limits, |mut entry| {
        std::io::copy(&mut entry, &mut std::io::sink())?;
        Ok(ControlFlow::<()>::Continue(()))
    });
});
