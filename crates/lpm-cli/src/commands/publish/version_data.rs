use crate::commands::publish_common;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

pub(crate) fn build_publish_version_data(
    pkg_json: &serde_json::Value,
    name: &str,
    version: &str,
    readme: Option<&str>,
    tarball_data: &[u8],
) -> serde_json::Value {
    let hashes = publish_common::compute_hashes(tarball_data);
    let mut version_data = pkg_json.clone();
    version_data["_id"] = serde_json::json!(format!("{name}@{version}"));
    if let Some(readme_text) = readme {
        version_data["readme"] = serde_json::json!(readme_text);
    }
    version_data["dist"] = serde_json::json!({
        "shasum": hashes.shasum,
        "integrity": hashes.integrity,
    });
    version_data
}

/// Extract SHA-512 hex from an integrity string (strip "sha512-" prefix and decode base64).
pub(super) fn integrity_to_sha512_hex(integrity: &str) -> String {
    let b64 = integrity.strip_prefix("sha512-").unwrap_or(integrity);
    let bytes = BASE64.decode(b64).unwrap_or_default();
    hex::encode(&bytes)
}
