use super::npm_artifact::load_provenance_file;
use super::types::{ProvenanceContext, ResolvedProvenance};
use crate::oidc;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProvenanceRequest {
    Generate,
    File(PathBuf),
    Disabled,
}

pub(crate) async fn materialize_provenance_request(
    request: ProvenanceRequest,
) -> Result<Option<ResolvedProvenance>, LpmError> {
    match request {
        ProvenanceRequest::Disabled => Ok(None),
        ProvenanceRequest::File(path) => load_provenance_file(&path)
            .map(ResolvedProvenance::File)
            .map(Some),
        ProvenanceRequest::Generate => {
            let (ci, jwt) = oidc::resolve_provenance_jwt().await?;
            Ok(Some(ResolvedProvenance::Generate(ProvenanceContext {
                ci,
                jwt,
            })))
        }
    }
}

pub(crate) fn resolve_provenance_request(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
) -> Result<ProvenanceRequest, LpmError> {
    if no_provenance {
        return Ok(ProvenanceRequest::Disabled);
    }
    if provenance_flag {
        return Ok(ProvenanceRequest::Generate);
    }
    if let Some(path) = provenance_file {
        return Ok(ProvenanceRequest::File(resolve_provenance_file_path(
            project_dir,
            path,
        )?));
    }

    if let Some(value) = package_publish_config_bool(pkg_json, "provenance")? {
        return Ok(if value {
            ProvenanceRequest::Generate
        } else {
            ProvenanceRequest::Disabled
        });
    }

    if let Some(request) = env_request()? {
        return request.resolve_paths(project_dir);
    }

    if let Some(request) = npmrc_request(&project_dir.join(".npmrc"))? {
        return request.resolve_paths(project_dir);
    }
    if let Some(home) = dirs::home_dir()
        && let Some(request) = npmrc_request(&home.join(".npmrc"))?
    {
        return request.resolve_paths(project_dir);
    }

    Ok(ProvenanceRequest::Disabled)
}

fn resolve_provenance_file_path(project_dir: &Path, path: &Path) -> Result<PathBuf, LpmError> {
    if path.as_os_str().is_empty() {
        return Err(LpmError::Registry(
            "provenance file path must not be empty".into(),
        ));
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        project_dir.join(path)
    })
}

fn env_request() -> Result<Option<NpmrcRequest>, LpmError> {
    let provenance_file =
        env_path_pair("NPM_CONFIG_PROVENANCE_FILE", "npm_config_provenance_file")?;
    let provenance = env_bool_pair("NPM_CONFIG_PROVENANCE", "npm_config_provenance")?;
    match (provenance_file, provenance) {
        (Some(_), Some(_)) => Err(LpmError::Registry(
            "NPM_CONFIG_PROVENANCE and NPM_CONFIG_PROVENANCE_FILE are mutually exclusive".into(),
        )),
        (Some(path), None) => Ok(Some(NpmrcRequest::File(path))),
        (None, Some(true)) => Ok(Some(NpmrcRequest::Generate)),
        (None, Some(false)) => Ok(Some(NpmrcRequest::Disabled)),
        (None, None) => Ok(None),
    }
}

fn env_bool(key: &str) -> Result<Option<bool>, LpmError> {
    match std::env::var(key) {
        Ok(value) => parse_bool_config(key, &value).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(LpmError::Registry(format!(
            "{key} must be valid UTF-8 to configure npm provenance"
        ))),
    }
}

fn env_bool_pair(upper: &str, lower: &str) -> Result<Option<bool>, LpmError> {
    let upper_value = env_bool(upper)?;
    let lower_value = env_bool(lower)?;
    match (upper_value, lower_value) {
        (Some(upper_value), Some(lower_value)) if upper_value != lower_value => {
            Err(LpmError::Registry(format!(
                "{upper} and {lower} configure conflicting npm provenance values"
            )))
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn env_path(key: &str) -> Result<Option<PathBuf>, LpmError> {
    match std::env::var_os(key) {
        Some(value) if value.is_empty() => Err(LpmError::Registry(format!(
            "{key} must not be empty when used as a provenance file path"
        ))),
        Some(value) => Ok(Some(PathBuf::from(value))),
        None => Ok(None),
    }
}

fn env_path_pair(upper: &str, lower: &str) -> Result<Option<PathBuf>, LpmError> {
    let upper_value = env_path(upper)?;
    let lower_value = env_path(lower)?;
    match (upper_value, lower_value) {
        (Some(upper_value), Some(lower_value)) if upper_value != lower_value => {
            Err(LpmError::Registry(format!(
                "{upper} and {lower} configure conflicting provenance file paths"
            )))
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn package_publish_config_bool(
    pkg_json: &serde_json::Value,
    key: &str,
) -> Result<Option<bool>, LpmError> {
    let Some(value) = pkg_json
        .get("publishConfig")
        .and_then(|config| config.get(key))
    else {
        return Ok(None);
    };
    match value {
        serde_json::Value::Bool(value) => Ok(Some(*value)),
        serde_json::Value::String(value) => {
            parse_bool_config(&format!("publishConfig.{key}"), value).map(Some)
        }
        other => Err(LpmError::Registry(format!(
            "publishConfig.{key} must be a boolean, got {other}"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NpmrcRequest {
    Generate,
    File(PathBuf),
    Disabled,
}

impl NpmrcRequest {
    fn resolve_paths(self, project_dir: &Path) -> Result<ProvenanceRequest, LpmError> {
        match self {
            Self::Generate => Ok(ProvenanceRequest::Generate),
            Self::Disabled => Ok(ProvenanceRequest::Disabled),
            Self::File(path) => {
                resolve_provenance_file_path(project_dir, &path).map(ProvenanceRequest::File)
            }
        }
    }
}

fn npmrc_request(path: &Path) -> Result<Option<NpmrcRequest>, LpmError> {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::NPMRC_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };

    let mut request = None;
    let mut provenance_line = None;
    let mut provenance_file_line = None;
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = trim_config_quotes(raw_value.trim());
        match key.as_str() {
            "provenance" => {
                provenance_line = Some(index + 1);
                request = Some(
                    if parse_bool_config(
                        &format!("{}:{} provenance", path.display(), index + 1),
                        value,
                    )? {
                        NpmrcRequest::Generate
                    } else {
                        NpmrcRequest::Disabled
                    },
                );
            }
            "provenance-file" | "provenancefile" => {
                provenance_file_line = Some(index + 1);
                if value.is_empty() {
                    return Err(LpmError::Registry(format!(
                        "{}:{} provenance-file must not be empty",
                        path.display(),
                        index + 1
                    )));
                }
                request = Some(NpmrcRequest::File(PathBuf::from(value)));
            }
            _ => {}
        }
    }

    if let (Some(provenance_line), Some(provenance_file_line)) =
        (provenance_line, provenance_file_line)
    {
        return Err(LpmError::Registry(format!(
            "{} has mutually exclusive npm provenance settings at lines {provenance_line} and {provenance_file_line}",
            path.display()
        )));
    }

    Ok(request)
}

fn trim_config_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value)
}

fn parse_bool_config(source: &str, value: &str) -> Result<bool, LpmError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(LpmError::Registry(format!(
            "{source} must be true or false for npm provenance, got {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ScopedEnv;

    fn pkg_json(value: serde_json::Value) -> serde_json::Value {
        value
    }

    #[test]
    fn resolve_provenance_request_cli_flag_enables_generation_over_config() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::set([("NPM_CONFIG_PROVENANCE", "false".into())]);
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            true,
            false,
            None,
        )
        .unwrap();
        assert_eq!(request, ProvenanceRequest::Generate);
    }

    #[test]
    fn resolve_provenance_request_no_provenance_disables_generation() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::set([("NPM_CONFIG_PROVENANCE", "true".into())]);
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({"publishConfig": {"provenance": true}})),
            false,
            true,
            None,
        )
        .unwrap();
        assert_eq!(request, ProvenanceRequest::Disabled);
    }

    #[test]
    fn resolve_provenance_request_cli_file_resolves_relative_to_project() {
        let dir = tempfile::tempdir().unwrap();
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            Some(Path::new("bundle.sigstore")),
        )
        .unwrap();
        assert_eq!(
            request,
            ProvenanceRequest::File(dir.path().join("bundle.sigstore"))
        );
    }

    #[test]
    fn resolve_provenance_request_uses_publish_config_when_env_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({"publishConfig": {"provenance": true}})),
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(request, ProvenanceRequest::Generate);
    }

    #[test]
    fn resolve_provenance_request_publish_config_overrides_env_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", Some("false".into())),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({"publishConfig": {"provenance": true}})),
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(request, ProvenanceRequest::Generate);
    }

    #[test]
    fn resolve_provenance_request_publish_config_overrides_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", Some("bundle.sigstore".into())),
            ("npm_config_provenance_file", None),
        ]);
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({"publishConfig": {"provenance": true}})),
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(request, ProvenanceRequest::Generate);
    }

    #[test]
    fn resolve_provenance_request_rejects_env_bool_and_file_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", Some("true".into())),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", Some("bundle.sigstore".into())),
            ("npm_config_provenance_file", None),
        ]);
        let err = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn resolve_provenance_request_uses_project_npmrc_when_package_config_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        std::fs::write(dir.path().join(".npmrc"), "provenance=true\n").unwrap();
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(request, ProvenanceRequest::Generate);
    }

    #[test]
    fn resolve_provenance_request_rejects_project_npmrc_bool_and_file_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        std::fs::write(
            dir.path().join(".npmrc"),
            "provenance=true\nprovenance-file=bundle.sigstore\n",
        )
        .unwrap();
        let err = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }
}
