use lpm_common::LpmError;
use std::path::Path;

const PROJECT_KEY: &str = "workspace.changed-files-ignore-pattern";

pub(crate) fn resolve_changed_files_ignore_patterns(
    workspace_root: &Path,
    cli_patterns: &[String],
) -> Result<Vec<String>, LpmError> {
    let project_path = workspace_root.join("lpm.toml");
    let mut patterns =
        read_project_changed_files_ignore_patterns_from_file(&project_path)?.unwrap_or_default();
    patterns.extend_from_slice(cli_patterns);
    Ok(patterns)
}

fn read_project_changed_files_ignore_patterns_from_file(
    path: &Path,
) -> Result<Option<Vec<String>>, LpmError> {
    let Some(table) = read_toml_table(path)? else {
        return Ok(None);
    };

    let Some(workspace) = table.get("workspace") else {
        return Ok(None);
    };

    let workspace_table = workspace.as_table().ok_or_else(|| {
        LpmError::Registry(format!(
            "{}: `workspace` must be a TOML table when present",
            path.display()
        ))
    })?;

    let Some(value) = workspace_table.get("changed-files-ignore-pattern") else {
        return Ok(None);
    };

    parse_changed_files_ignore_patterns(path, PROJECT_KEY, value).map(Some)
}

fn read_toml_table(path: &Path) -> Result<Option<toml::map::Map<String, toml::Value>>, LpmError> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| LpmError::Registry(format!("failed to read {}: {e}", path.display())))?;
    let parsed: toml::Value = toml::from_str(&raw)
        .map_err(|e| LpmError::Registry(format!("failed to parse {}: {e}", path.display())))?;

    match parsed {
        toml::Value::Table(table) => Ok(Some(table)),
        _ => Err(LpmError::Registry(format!(
            "{} must be a TOML table at the top level",
            path.display()
        ))),
    }
}

fn parse_changed_files_ignore_patterns(
    path: &Path,
    key: &str,
    value: &toml::Value,
) -> Result<Vec<String>, LpmError> {
    match value {
        toml::Value::String(pattern) => Ok(vec![pattern.clone()]),
        toml::Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    LpmError::Registry(format!(
                        "{}: `{key}` entries must be strings, got {value}",
                        path.display()
                    ))
                })
            })
            .collect(),
        _ => Err(LpmError::Registry(format!(
            "{}: `{key}` must be a string or an array of strings, got {value}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn project_config_accepts_string_pattern() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.toml"),
            "[workspace]\nchanged-files-ignore-pattern = \"**/README.md\"\n",
        )
        .unwrap();

        let patterns = resolve_changed_files_ignore_patterns(dir.path(), &[]).unwrap();

        assert_eq!(patterns, vec!["**/README.md"]);
    }

    #[test]
    fn project_config_accepts_pattern_array() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.toml"),
            "[workspace]\nchanged-files-ignore-pattern = [\"**/README.md\", \"docs/**\"]\n",
        )
        .unwrap();

        let patterns = resolve_changed_files_ignore_patterns(dir.path(), &[]).unwrap();

        assert_eq!(patterns, vec!["**/README.md", "docs/**"]);
    }

    #[test]
    fn cli_patterns_append_to_project_config() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.toml"),
            "[workspace]\nchanged-files-ignore-pattern = \"**/README.md\"\n",
        )
        .unwrap();
        let cli_patterns = vec!["docs/**".to_string()];

        let patterns = resolve_changed_files_ignore_patterns(dir.path(), &cli_patterns).unwrap();

        assert_eq!(patterns, vec!["**/README.md", "docs/**"]);
    }

    #[test]
    fn project_config_rejects_non_string_entries() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.toml"),
            "[workspace]\nchanged-files-ignore-pattern = [\"**/README.md\", 1]\n",
        )
        .unwrap();

        let err = resolve_changed_files_ignore_patterns(dir.path(), &[])
            .unwrap_err()
            .to_string();

        assert!(
            err.contains(PROJECT_KEY),
            "error should name the invalid key: {err}"
        );
    }
}
