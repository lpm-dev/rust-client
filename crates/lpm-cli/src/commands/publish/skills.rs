use crate::install_ui;
use lpm_common::LpmError;
use serde::Serialize;
use std::path::Path;

/// Compute a digest from previously published skills for staleness comparison.
pub(super) fn compute_published_skills_digest(skills: &[lpm_registry::Skill]) -> String {
    use sha2::{Digest, Sha256};
    let mut entries: Vec<(&str, &str)> = skills
        .iter()
        .map(|s| {
            let content = s
                .raw_content
                .as_deref()
                .or(s.content.as_deref())
                .unwrap_or("");
            (s.name.as_str(), content)
        })
        .collect();

    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut hasher = Sha256::new();
    for (name, content) in &entries {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(content.as_bytes());
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

/// Ensure ".lpm/skills" is present in the `files` array in package.json.
///
/// IMPORTANT: Only `.lpm/skills` is added — NOT `.lpm` broadly. The `.lpm/`
/// directory also contains certs, webhook logs, install hashes, and other
/// project-local data that must NEVER be published in the tarball.
pub(super) fn ensure_lpm_in_files(
    pkg_json_path: &Path,
    pkg_json: &serde_json::Value,
) -> Result<bool, LpmError> {
    if let Some(files) = pkg_json.get("files").and_then(|f| f.as_array()) {
        let has_skills = files.iter().any(|f| {
            let s = f.as_str().unwrap_or("");
            s == ".lpm/skills" || s == ".lpm/skills/" || s == ".lpm"
        });
        if !has_skills {
            let content = lpm_common::read_text_file_capped(
                pkg_json_path,
                lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            )?;
            let mut updated = pkg_json.clone();
            let updated_files = updated
                .get_mut("files")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_else(|| {
                    LpmError::Registry(
                        "package.json `files` changed while preparing the publish tarball".into(),
                    )
                })?;
            updated_files.push(serde_json::Value::String(".lpm/skills".into()));

            let indent = package_json_indent(&content);
            let formatter = serde_json::ser::PrettyFormatter::with_indent(&indent);
            let mut serialized = Vec::with_capacity(content.len() + 32);
            let mut serializer = serde_json::Serializer::with_formatter(&mut serialized, formatter);
            updated.serialize(&mut serializer).map_err(|error| {
                LpmError::Registry(format!("failed to serialize package.json: {error}"))
            })?;
            serialized.push(b'\n');
            lpm_common::write_file_atomic(pkg_json_path, serialized)?;

            install_ui::warn(
                "Added \".lpm/skills\" to package.json \"files\" — skills would be excluded otherwise",
            );
            return Ok(true);
        }
    }
    Ok(false)
}

fn package_json_indent(content: &str) -> Vec<u8> {
    content
        .lines()
        .skip(1)
        .find_map(|line| {
            let indent = line
                .as_bytes()
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .copied()
                .collect::<Vec<_>>();
            (!indent.is_empty() && !line.trim().is_empty()).then_some(indent)
        })
        .unwrap_or_else(|| b"  ".to_vec())
}
