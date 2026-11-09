//! `lpm internal-package-signals`, hidden: a registry's code-signal analysis
//! of one published release. It reads the release's gzipped tarball from
//! stdin and prints one JSON document on stdout. It reads no configuration,
//! makes no network request, writes nothing to disk and runs no package
//! code.

use lpm_common::LpmError;
use lpm_security::behavioral::release::{self, Ecosystem, ReleaseSignals};
use serde::Serialize;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::Path;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output<'a> {
    lpm_version: &'static str,
    #[serde(flatten)]
    signals: &'a ReleaseSignals,
}

/// The largest evaluated manifest read: `swift package dump-package` output
/// of a package with many targets and dependencies stays far below it.
const MAX_SWIFT_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) fn run(ecosystem: Ecosystem, swift_manifest: Option<&Path>) -> Result<(), LpmError> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pipe a release's gzipped tarball into stdin",
        )));
    }
    let swift_manifest = swift_manifest.map(read_swift_manifest).transpose()?;
    let signals =
        release::analyze_release_tarball(stdin.lock(), ecosystem, swift_manifest.as_ref())?;
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

/// A Swift release's evaluated manifest, the JSON object `swift package
/// dump-package` prints.
fn read_swift_manifest(path: &Path) -> Result<serde_json::Value, LpmError> {
    let invalid = |message: String| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            message,
        ))
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_SWIFT_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SWIFT_MANIFEST_BYTES {
        return Err(invalid(format!(
            "the Swift manifest is larger than {MAX_SWIFT_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("the Swift manifest isn't JSON: {error}")))?;
    if !manifest.is_object() {
        return Err(invalid(
            "the Swift manifest isn't a JSON object".to_string(),
        ));
    }
    Ok(manifest)
}
