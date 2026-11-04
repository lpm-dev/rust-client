//! `lpm internal-package-signals`, hidden: a registry's code-signal analysis
//! of one published release. It reads the release's gzipped tarball from
//! stdin and prints one JSON document on stdout. It reads no configuration,
//! makes no network request, writes nothing to disk and runs no package
//! code.

use lpm_common::LpmError;
use lpm_security::behavioral::release::{self, Ecosystem, ReleaseSignals};
use serde::Serialize;
use std::io::{IsTerminal as _, Write as _};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output<'a> {
    lpm_version: &'static str,
    #[serde(flatten)]
    signals: &'a ReleaseSignals,
}

pub(crate) fn run(ecosystem: Ecosystem) -> Result<(), LpmError> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pipe a release's gzipped tarball into stdin",
        )));
    }
    let signals = release::analyze_release_tarball(stdin.lock(), ecosystem)?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(
        &mut stdout,
        &Output {
            lpm_version: crate::build_version::version(),
            signals: &signals,
        },
    )?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
