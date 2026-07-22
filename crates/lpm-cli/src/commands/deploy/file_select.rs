use lpm_common::LpmError;
use std::path::Path;

#[derive(Debug, Clone)]
pub(in crate::commands::deploy) struct PackageFileSelector {
    files: Option<Vec<String>>,
    ignore_rules: Vec<IgnoreRule>,
}

#[derive(Debug, Clone)]
struct IgnoreRule {
    pattern: String,
    negated: bool,
    anchored: bool,
    directory_only: bool,
}

impl PackageFileSelector {
    pub(in crate::commands::deploy) fn from_package_dir(
        package_dir: &Path,
    ) -> Result<Self, LpmError> {
        let manifest_path = package_dir.join("package.json");
        let manifest = lpm_common::read_text_file_capped(
            &manifest_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .map_err(|e| {
            LpmError::Script(format!(
                "deploy: failed to read package manifest {manifest_path:?}: {e}"
            ))
        })?;
        let doc: serde_json::Value = serde_json::from_str(&manifest)
            .map_err(|e| LpmError::Script(format!("deploy: invalid package.json: {e}")))?;
        let files = doc
            .get("files")
            .and_then(|value| value.as_array())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.as_str())
                    .map(normalize_package_pattern)
                    .filter(|entry| !entry.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|entries| !entries.is_empty());

        let ignore_rules = if files.is_none() {
            read_ignore_rules(package_dir)?
        } else {
            Vec::new()
        };

        Ok(Self {
            files,
            ignore_rules,
        })
    }

    pub(in crate::commands::deploy) fn should_copy(&self, rel_path: &Path, is_dir: bool) -> bool {
        let rel = normalize_relative_path(rel_path);
        if rel.is_empty() || package_publish_always_includes(&rel) {
            return true;
        }
        if let Some(files) = &self.files {
            return files
                .iter()
                .any(|pattern| files_entry_matches(pattern, &rel, is_dir));
        }

        let mut included = true;
        for rule in &self.ignore_rules {
            if rule.matches(&rel, is_dir) {
                included = rule.negated;
            }
        }
        included
    }
}

impl IgnoreRule {
    fn matches(&self, rel: &str, is_dir: bool) -> bool {
        if self.directory_only && !is_dir {
            return false;
        }
        let pattern = self.pattern.as_str();
        if self.anchored || pattern.contains('/') {
            glob_match(pattern, rel)
        } else {
            rel.split('/')
                .any(|component| glob_match(pattern, component))
        }
    }
}

fn read_ignore_rules(package_dir: &Path) -> Result<Vec<IgnoreRule>, LpmError> {
    let npmignore = package_dir.join(".npmignore");
    let gitignore = package_dir.join(".gitignore");
    let ignore_path = if npmignore.exists() {
        Some(npmignore)
    } else if gitignore.exists() {
        Some(gitignore)
    } else {
        None
    };
    let Some(ignore_path) = ignore_path else {
        return Ok(Vec::new());
    };
    let content =
        lpm_common::read_text_file_capped(&ignore_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
                LpmError::Script(format!(
                    "deploy: failed to read ignore file {ignore_path:?}: {e}"
                ))
            })?;
    let mut rules = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let negated = line.starts_with('!');
        let without_negation = if negated { &line[1..] } else { line };
        let anchored = without_negation.starts_with('/');
        let without_anchor = without_negation.trim_start_matches('/');
        let directory_only = without_anchor.ends_with('/');
        let pattern = normalize_package_pattern(without_anchor.trim_end_matches('/'));
        if pattern.is_empty() {
            continue;
        }
        rules.push(IgnoreRule {
            pattern,
            negated,
            anchored,
            directory_only,
        });
    }
    Ok(rules)
}

pub(in crate::commands::deploy) fn normalize_relative_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            std::path::Component::ParentDir => Some("..".to_string()),
            std::path::Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_package_pattern(pattern: &str) -> String {
    pattern
        .trim()
        .trim_start_matches("./")
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn package_publish_always_includes(rel: &str) -> bool {
    if rel == "package.json" {
        return true;
    }
    let lowercase = rel.to_ascii_lowercase();
    lowercase == "readme"
        || lowercase.starts_with("readme.")
        || lowercase == "license"
        || lowercase.starts_with("license.")
}

fn files_entry_matches(pattern: &str, rel: &str, is_dir: bool) -> bool {
    let pattern = pattern.trim_end_matches('/');
    if rel == pattern || rel.starts_with(&format!("{pattern}/")) {
        return true;
    }
    if is_dir && pattern.starts_with(&format!("{rel}/")) {
        return true;
    }
    glob_match(pattern, rel)
}

fn glob_match(pattern: &str, rel: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|pattern| pattern.matches_path(Path::new(rel)))
        .unwrap_or(false)
}
