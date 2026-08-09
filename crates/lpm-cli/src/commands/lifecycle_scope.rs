use lpm_common::LpmError;
use std::collections::HashSet;
use std::path::Path;

const SCHEMA_VERSION: u32 = 1;
const COMMAND: &str = "trust lifecycle-scope";
const PROJECT_SCOPE: &str = "project";
const TRUSTED_SCOPES_KEY: &str = "trustedScopes";

#[derive(Clone, Copy, Debug)]
pub(crate) enum LifecycleScopeOperation<'a> {
    Add(&'a str),
    Remove(&'a str),
    List,
}

impl<'a> LifecycleScopeOperation<'a> {
    fn action(self) -> &'static str {
        match self {
            Self::Add(_) => "add",
            Self::Remove(_) => "remove",
            Self::List => "list",
        }
    }

    fn selector(self) -> Option<&'a str> {
        match self {
            Self::Add(selector) | Self::Remove(selector) => Some(selector),
            Self::List => None,
        }
    }

    pub(crate) fn mutates(self) -> bool {
        !matches!(self, Self::List)
    }
}

#[derive(Debug)]
struct EditResult {
    scopes: Vec<String>,
    selector: Option<String>,
    changed: bool,
    normalized: bool,
}

impl EditResult {
    fn storage_changed(&self) -> bool {
        self.changed || self.normalized
    }
}

pub(crate) fn run_project(
    project_dir: &Path,
    operation: LifecycleScopeOperation<'_>,
    json_output: bool,
) -> Result<(), LpmError> {
    let (manifest_path, mut manifest, result) = prepare_project_edit(project_dir, operation)?;
    match operation {
        LifecycleScopeOperation::Add(_) => {
            // Authorize the complete candidate before the manifest can contain a wider trust scope.
            crate::security_approval::ensure_project_scope_candidate_authorized(
                project_dir,
                &result.scopes,
                json_output,
                crate::security_approval::ApprovalSource::CliFlag,
            )?;
        }
        LifecycleScopeOperation::Remove(_) => {
            // Revoke authority even when the selector is absent because stale state can outlive a manual manifest edit.
            crate::security_approval::record_project_scope_candidate_narrowing(
                project_dir,
                &result.scopes,
                result
                    .selector
                    .as_deref()
                    .expect("remove results have a selector"),
                crate::security_approval::ApprovalSource::CliFlag,
            )?;
        }
        LifecycleScopeOperation::List => {}
    }

    if result.storage_changed() {
        set_project_scopes(&mut manifest, &result.scopes)?;
        write_project_manifest(&manifest_path, &manifest)?;
    }
    print_result(operation, &result, json_output)
}

pub(crate) fn validate_project(
    project_dir: &Path,
    operation: LifecycleScopeOperation<'_>,
) -> Result<(), LpmError> {
    prepare_project_edit(project_dir, operation).map(|_| ())
}

fn prepare_project_edit(
    project_dir: &Path,
    operation: LifecycleScopeOperation<'_>,
) -> Result<(std::path::PathBuf, serde_json::Value, EditResult), LpmError> {
    let manifest_path = project_dir.join("package.json");
    let content = match lpm_common::read_text_file_capped(
        &manifest_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Err(LpmError::NotFound(
                "lpm trust lifecycle-scope requires a package.json in the current directory."
                    .into(),
            ));
        }
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };
    let manifest: serde_json::Value = serde_json::from_str(&content)
        .map_err(|error| LpmError::Registry(format!("failed to parse package.json: {error}")))?;
    if !manifest.is_object() {
        return Err(LpmError::Registry(
            "package.json must contain a JSON object at the top level".into(),
        ));
    }

    let existing = project_scopes(&manifest)?;
    let result = edit_scopes(existing, operation)?;
    Ok((manifest_path, manifest, result))
}

fn edit_scopes(
    existing: Vec<String>,
    operation: LifecycleScopeOperation<'_>,
) -> Result<EditResult, LpmError> {
    let mut scopes =
        validate_scope_selectors("package.json > lpm > scripts > trustedScopes", &existing)?;
    let normalized = operation.mutates() && scopes != existing;
    let selector = operation
        .selector()
        .map(|selector| normalize_scope_selector("lifecycle scope selector", selector))
        .transpose()?;
    let changed = match operation {
        LifecycleScopeOperation::Add(_) => {
            let selector = selector.as_ref().expect("add has a selector");
            if scopes.iter().any(|entry| entry == selector) {
                false
            } else {
                scopes.push(selector.clone());
                true
            }
        }
        LifecycleScopeOperation::Remove(_) => {
            let selector = selector.as_ref().expect("remove has a selector");
            let previous_len = scopes.len();
            scopes.retain(|entry| entry != selector);
            scopes.len() != previous_len
        }
        LifecycleScopeOperation::List => false,
    };
    Ok(EditResult {
        scopes,
        selector,
        changed,
        normalized,
    })
}

fn validate_scope_selectors(source: &str, scopes: &[String]) -> Result<Vec<String>, LpmError> {
    let mut seen = HashSet::with_capacity(scopes.len());
    let mut normalized = Vec::with_capacity(scopes.len());
    for scope in scopes {
        let scope = normalize_scope_selector(source, scope)?;
        if seen.insert(scope.clone()) {
            normalized.push(scope);
        }
    }
    Ok(normalized)
}

fn normalize_scope_selector(source: &str, raw: &str) -> Result<String, LpmError> {
    let Some(scope) = raw
        .strip_prefix('@')
        .and_then(|value| value.strip_suffix("/*"))
    else {
        return Err(invalid_scope(source, raw));
    };
    if raw.trim() != raw
        || raw.chars().any(char::is_whitespace)
        || raw.len() > 214
        || !is_valid_npm_scope(scope)
    {
        return Err(invalid_scope(source, raw));
    }
    Ok(raw.to_string())
}

fn is_valid_npm_scope(scope: &str) -> bool {
    let mut bytes = scope.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit() || matches!(first, b'-' | b'~')) {
        return false;
    }
    bytes.all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
    })
}

fn invalid_scope(source: &str, raw: &str) -> LpmError {
    LpmError::Registry(format!(
        "{source} `{raw}` is invalid; expected one lowercase npm scope wildcard such as `@company/*`. Use `lpm approve-scripts <package>` for one package"
    ))
}

fn project_scopes(manifest: &serde_json::Value) -> Result<Vec<String>, LpmError> {
    let Some(lpm) = manifest.get("lpm") else {
        return Ok(Vec::new());
    };
    let Some(lpm) = lpm.as_object() else {
        return Err(LpmError::Registry(
            "package.json > lpm must be an object".into(),
        ));
    };
    let Some(scripts) = lpm.get("scripts") else {
        return Ok(Vec::new());
    };
    let Some(scripts) = scripts.as_object() else {
        return Err(LpmError::Registry(
            "package.json > lpm > scripts must be an object".into(),
        ));
    };
    let Some(scopes) = scripts.get(TRUSTED_SCOPES_KEY) else {
        return Ok(Vec::new());
    };
    let Some(scopes) = scopes.as_array() else {
        return Err(LpmError::Registry(
            "package.json > lpm > scripts > trustedScopes must be an array of strings".into(),
        ));
    };
    scopes
        .iter()
        .map(|scope| {
            scope.as_str().map(str::to_string).ok_or_else(|| {
                LpmError::Registry(
                    "package.json > lpm > scripts > trustedScopes must be an array of strings"
                        .into(),
                )
            })
        })
        .collect()
}

fn set_project_scopes(manifest: &mut serde_json::Value, scopes: &[String]) -> Result<(), LpmError> {
    let root = manifest.as_object_mut().ok_or_else(|| {
        LpmError::Registry("package.json must contain a JSON object at the top level".into())
    })?;
    if scopes.is_empty() {
        let remove_lpm = if let Some(lpm) = root.get_mut("lpm") {
            let lpm = lpm
                .as_object_mut()
                .ok_or_else(|| LpmError::Registry("package.json > lpm must be an object".into()))?;
            let remove_scripts = if let Some(scripts) = lpm.get_mut("scripts") {
                let scripts = scripts.as_object_mut().ok_or_else(|| {
                    LpmError::Registry("package.json > lpm > scripts must be an object".into())
                })?;
                scripts.remove(TRUSTED_SCOPES_KEY);
                scripts.is_empty()
            } else {
                false
            };
            if remove_scripts {
                lpm.remove("scripts");
            }
            lpm.is_empty()
        } else {
            false
        };
        if remove_lpm {
            root.remove("lpm");
        }
        return Ok(());
    }

    let lpm = root
        .entry("lpm")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| LpmError::Registry("package.json > lpm must be an object".into()))?;
    let scripts = lpm
        .entry("scripts")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            LpmError::Registry("package.json > lpm > scripts must be an object".into())
        })?;
    scripts.insert(TRUSTED_SCOPES_KEY.to_string(), serde_json::json!(scopes));
    Ok(())
}

fn write_project_manifest(path: &Path, manifest: &serde_json::Value) -> Result<(), LpmError> {
    let content = serde_json::to_string_pretty(manifest).map_err(|error| {
        LpmError::Registry(format!("failed to serialize package.json: {error}"))
    })?;
    lpm_common::write_file_atomic(path, format!("{content}\n")).map_err(LpmError::Io)
}

fn print_result(
    operation: LifecycleScopeOperation<'_>,
    result: &EditResult,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output {
        let envelope = if let Some(selector) = result.selector.as_ref() {
            serde_json::json!({
                "success": true,
                "schema_version": SCHEMA_VERSION,
                "command": COMMAND,
                "scope": PROJECT_SCOPE,
                "action": operation.action(),
                "selector": selector,
                "changed": result.changed,
                "normalized": result.normalized,
                "count": result.scopes.len(),
                "scopes": result.scopes,
            })
        } else {
            serde_json::json!({
                "success": true,
                "schema_version": SCHEMA_VERSION,
                "command": COMMAND,
                "scope": PROJECT_SCOPE,
                "action": operation.action(),
                "changed": result.changed,
                "normalized": result.normalized,
                "count": result.scopes.len(),
                "scopes": result.scopes,
            })
        };
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    match operation {
        LifecycleScopeOperation::List => {
            if result.scopes.is_empty() {
                println!("No project lifecycle scopes configured");
            } else {
                println!("Project lifecycle scopes");
                for scope in &result.scopes {
                    println!("  {}", lpm_common::sanitize_terminal_inline(scope));
                }
            }
        }
        LifecycleScopeOperation::Add(_) => {
            let selector = display_selector(result);
            let normalization = normalization_suffix(result);
            if result.changed {
                crate::install_ui::done_untrusted(&format!(
                    "Added {selector} to project lifecycle scope trust{normalization}"
                ));
            } else {
                crate::install_ui::done_untrusted(&format!(
                    "{selector} is already in project lifecycle scope trust{normalization}"
                ));
            }
        }
        LifecycleScopeOperation::Remove(_) => {
            let selector = display_selector(result);
            let normalization = normalization_suffix(result);
            if result.changed {
                crate::install_ui::done_untrusted(&format!(
                    "Removed {selector} from project lifecycle scope trust{normalization}"
                ));
            } else {
                crate::install_ui::done_untrusted(&format!(
                    "{selector} was not in project lifecycle scope trust{normalization}"
                ));
            }
        }
    }
    Ok(())
}

fn normalization_suffix(result: &EditResult) -> &'static str {
    if result.normalized {
        " (normalized existing entries)"
    } else {
        ""
    }
}

fn display_selector(result: &EditResult) -> String {
    lpm_common::sanitize_terminal_inline(
        result
            .selector
            .as_deref()
            .expect("add and remove results have selectors"),
    )
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_scope_selector_accepts_lowercase_npm_scope_wildcards() {
        assert_eq!(
            normalize_scope_selector("test", "@company.tools/*").unwrap(),
            "@company.tools/*"
        );
    }

    #[test]
    fn normalize_scope_selector_rejects_package_and_version_selectors() {
        for selector in ["react", "react@1.0.0", "@company/package"] {
            assert!(normalize_scope_selector("test", selector).is_err());
        }
    }

    #[test]
    fn normalize_scope_selector_rejects_lookalike_and_control_input() {
        for selector in ["@Company/*", "@company-evil/pkg/*", "@company/\n*"] {
            assert!(normalize_scope_selector("test", selector).is_err());
        }
    }

    #[test]
    fn duplicate_add_reports_selector_unchanged_after_storage_normalization() {
        let result = edit_scopes(
            vec!["@company/*".to_string(), "@company/*".to_string()],
            LifecycleScopeOperation::Add("@company/*"),
        )
        .unwrap();

        assert!(!result.changed);
        assert!(result.normalized);
        assert_eq!(result.scopes, ["@company/*"]);
    }

    #[test]
    fn absent_remove_reports_selector_unchanged_after_storage_normalization() {
        let result = edit_scopes(
            vec!["@company/*".to_string(), "@company/*".to_string()],
            LifecycleScopeOperation::Remove("@internal/*"),
        )
        .unwrap();

        assert!(!result.changed);
        assert!(result.normalized);
        assert_eq!(result.scopes, ["@company/*"]);
    }
}
