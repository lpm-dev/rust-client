//! `lpm internal-verify-release`: verifies a release's signed
//! `SHA256SUMS.txt` from local files with the policy `lpm self-update`
//! enforces. The release workflow runs it from the binary it is about to
//! publish, so a signing change that installed clients would refuse fails
//! the release before anything is published.

use super::{
    BUNDLE_MAX_BYTES, MANIFEST_MAX_BYTES, VerifiedReleaseManifest, verify_release_manifest,
};
use crate::output;
use crate::release_lookup::GithubRelease;
use lpm_common::LpmError;
use std::io::Read;
use std::path::Path;

pub(crate) fn run(
    version: &str,
    manifest_path: &Path,
    bundle_path: &Path,
    release: &GithubRelease,
    json_output: bool,
) -> Result<(), LpmError> {
    let manifest = read_capped(manifest_path, MANIFEST_MAX_BYTES, "SHA256SUMS.txt")?;
    let bundle = read_capped(bundle_path, BUNDLE_MAX_BYTES, "Sigstore bundle")?;
    let verified = verify_release_manifest(version, &manifest, &bundle, release)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&verification_json(version, &verified))?
        );
    } else {
        output::success(&format!(
            "v{version} satisfies the self-update signing policy"
        ));
        output::field(
            "signed by",
            &format!(
                "{} {}@{}",
                verified.publisher.as_deref().unwrap_or_default(),
                verified.workflow_path.as_deref().unwrap_or_default(),
                verified.workflow_ref.as_deref().unwrap_or_default(),
            ),
        );
        output::field("source commit", &verified.source_commit);
        output::field(
            "integrated",
            &format!(
                "{} (Rekor log index {})",
                verified.integrated_time.to_rfc3339(),
                verified.log_index
            ),
        );
        output::field("assets", &verified.entries.len().to_string());
    }
    Ok(())
}

fn read_capped(path: &Path, cap: usize, label: &str) -> Result<Vec<u8>, LpmError> {
    let unreadable = |error: std::io::Error| {
        LpmError::SelfUpdate(format!(
            "could not read the {label} at {}: {error}",
            path.display()
        ))
    };
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut bytes = Vec::with_capacity(cap.min(64 * 1024));
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > cap {
        return Err(LpmError::SelfUpdate(format!(
            "the {label} at {} exceeds the {cap}-byte limit self-update enforces",
            path.display()
        )));
    }
    Ok(bytes)
}

fn verification_json(version: &str, verified: &VerifiedReleaseManifest) -> serde_json::Value {
    let mut assets: Vec<(&String, &String)> = verified.entries.iter().collect();
    assets.sort_unstable();
    let assets: Vec<serde_json::Value> = assets
        .into_iter()
        .map(|(name, sha256)| serde_json::json!({ "name": name, "sha256": sha256 }))
        .collect();
    serde_json::json!({
        "success": true,
        "version": version,
        "publisher": verified.publisher,
        "workflow_path": verified.workflow_path,
        "workflow_ref": verified.workflow_ref,
        "source_commit": verified.source_commit,
        "integrated_time": verified.integrated_time.to_rfc3339(),
        "log_index": verified.log_index,
        "log_id": verified.log_id,
        "leaf_cert_sha256": verified.leaf_cert_sha256,
        "manifest_sha256": verified.manifest_sha256,
        "assets": assets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_capped_rejects_files_over_the_self_update_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("SHA256SUMS.txt");
        std::fs::write(&path, vec![b'a'; 17]).unwrap();
        let err = read_capped(&path, 16, "SHA256SUMS.txt").expect_err("17 bytes exceeds 16");
        assert!(err.to_string().contains("16-byte limit"), "{err}");
        assert_eq!(read_capped(&path, 17, "SHA256SUMS.txt").unwrap().len(), 17);
    }

    #[test]
    fn read_capped_names_the_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("SHA256SUMS.txt.sigstore");
        let err = read_capped(&path, 16, "Sigstore bundle").expect_err("file does not exist");
        let message = err.to_string();
        assert!(message.contains("Sigstore bundle"), "{message}");
        assert!(message.contains("SHA256SUMS.txt.sigstore"), "{message}");
    }
}
