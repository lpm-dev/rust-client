use crate::install_ui;
use lpm_common::LpmError;
use lpm_security::skill_security;
use std::path::Path;

// Skills validation helpers
// ---------------------------------------------------------------------------

/// Walk the skills directory (including subdirectories), parse frontmatter,
/// run security scans, and validate size limits.
///
/// Returns `(valid_count, errors, security_issues)`.
pub(super) fn validate_skills_for_publish(
    skills_dir: &Path,
) -> (usize, Vec<String>, Vec<skill_security::SkillSecurityIssue>) {
    let mut valid = 0usize;
    let mut errors = Vec::new();
    let mut security_issues = Vec::new();
    let mut total_size: u64 = 0;

    collect_skill_files(skills_dir, &mut |path| {
        let rel = path
            .strip_prefix(skills_dir)
            .unwrap_or(path)
            .display()
            .to_string();

        let size = std::fs::metadata(path).map_or(0, |m| m.len());
        total_size += size;

        if size > 15 * 1024 {
            errors.push(format!("{rel}: exceeds 15KB limit ({size} bytes)"));
            return;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{rel}: failed to read — {e}"));
                return;
            }
        };

        if content.len() < 100 {
            errors.push(format!("{rel}: content too short (need 100+ chars)"));
            return;
        }

        // Security scan
        let issues = skill_security::scan_skill_content(&content);
        if !issues.is_empty() {
            security_issues.extend(issues);
            return;
        }

        // Frontmatter validation
        let (_meta, _body, fm_errors) = skill_security::parse_skill_frontmatter(&content);
        if !fm_errors.is_empty() {
            for e in fm_errors {
                errors.push(format!("{rel}: {e}"));
            }
            return;
        }

        valid += 1;
    });

    if total_size > 100 * 1024 {
        errors.push(format!(
            "total skills size {} bytes exceeds 100KB limit",
            total_size
        ));
    }

    (valid, errors, security_issues)
}

/// Recursively collect .md files under a directory and call `f` for each.
pub(super) fn collect_skill_files(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_skill_files(&path, f);
        } else if path.extension().is_some_and(|e| e == "md") {
            f(&path);
        }
    }
}

/// Compute a deterministic digest of local skill files for staleness comparison.
pub(super) fn compute_skills_digest(skills_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut entries: Vec<(String, String)> = Vec::new();

    collect_skill_files(skills_dir, &mut |path| {
        let rel = path
            .strip_prefix(skills_dir)
            .unwrap_or(path)
            .display()
            .to_string();
        let content = std::fs::read_to_string(path).unwrap_or_default();
        entries.push((rel, content));
    });

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (name, content) in &entries {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(content.as_bytes());
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

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
) -> Result<(), LpmError> {
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
            }
        }
    }
    Ok(())
}
