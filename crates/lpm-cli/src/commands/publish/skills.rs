use crate::install_ui;
use lpm_common::LpmError;
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
            let content = std::fs::read_to_string(pkg_json_path)?;

            if let Some(files_pos) = content.find("\"files\"")
                && let Some(bracket_offset) = content[files_pos..].find('[')
            {
                let insert_pos = files_pos + bracket_offset + 1;
                let mut new_content = String::with_capacity(content.len() + 32);
                new_content.push_str(&content[..insert_pos]);
                let after_bracket = &content[insert_pos..];
                let indent = after_bracket.find('"').map_or("    ", |i| {
                    let segment = &after_bracket[..i];
                    segment.rfind('\n').map_or(segment, |nl| &segment[nl + 1..])
                });
                new_content.push('\n');
                new_content.push_str(indent);
                new_content.push_str("\".lpm/skills\",");
                new_content.push_str(&content[insert_pos..]);

                let tmp = pkg_json_path.with_extension("json.tmp");
                std::fs::write(&tmp, &new_content)?;
                std::fs::rename(&tmp, pkg_json_path)?;

                install_ui::warn(
                    "Added \".lpm/skills\" to package.json \"files\" — skills would be excluded otherwise",
                );
                return Ok(true);
            }
        }
    }
    Ok(false)
}
