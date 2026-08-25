use super::npm_artifact::{
    load_provenance_bytes, load_provenance_file, read_open_provenance_file_with_known_size,
};
use super::types::{ProvenanceContext, ResolvedProvenance};
use crate::oidc;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) enum ProvenanceFileRequest {
    AmbientPath(PathBuf),
    ProjectFile {
        display_path: PathBuf,
        relative_path: PathBuf,
        source_dir: Arc<cap_std::fs::Dir>,
    },
}

impl std::fmt::Debug for ProvenanceFileRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmbientPath(path) => formatter.debug_tuple("AmbientPath").field(path).finish(),
            Self::ProjectFile {
                display_path,
                relative_path,
                source_dir: _,
            } => formatter
                .debug_struct("ProjectFile")
                .field("display_path", display_path)
                .field("relative_path", relative_path)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ProvenanceRequest {
    Generate,
    File(ProvenanceFileRequest),
    Disabled,
}

pub(crate) async fn materialize_provenance_request(
    request: ProvenanceRequest,
) -> Result<Option<ResolvedProvenance>, LpmError> {
    match request {
        ProvenanceRequest::Disabled => Ok(None),
        ProvenanceRequest::File(file) => load_provenance_request_file(&file)
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

pub(super) fn load_provenance_request_file(
    request: &ProvenanceFileRequest,
) -> Result<super::types::LoadedProvenanceFile, LpmError> {
    match request {
        ProvenanceFileRequest::AmbientPath(path) => load_provenance_file(path),
        ProvenanceFileRequest::ProjectFile {
            display_path,
            relative_path,
            source_dir,
        } => {
            let (file, known_size) = crate::commands::publish_common::open_tarball_source_file(
                source_dir,
                relative_path,
                &display_path.to_string_lossy(),
            )?;
            let bytes = read_open_provenance_file_with_known_size(file, display_path, known_size)?;
            load_provenance_bytes(display_path, bytes)
        }
    }
}

#[cfg(test)]
pub(crate) fn resolve_provenance_request(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
) -> Result<ProvenanceRequest, LpmError> {
    let canonical_project_dir = project_dir.canonicalize().map_err(LpmError::Io)?;
    let project_source = Arc::new(crate::commands::publish_common::open_tarball_source_root(
        &canonical_project_dir,
    )?);
    resolve_provenance_request_with_sources(
        &canonical_project_dir,
        pkg_json,
        provenance_flag,
        no_provenance,
        provenance_file,
        |path| resolve_provenance_file_request(&canonical_project_dir, &project_source, path),
    )
}

pub(crate) fn resolve_provenance_request_from_project_source(
    project_dir: &Path,
    project_source: &Arc<cap_std::fs::Dir>,
    pkg_json: &serde_json::Value,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
) -> Result<ProvenanceRequest, LpmError> {
    resolve_provenance_request_with_sources(
        project_dir,
        pkg_json,
        provenance_flag,
        no_provenance,
        provenance_file,
        |path| resolve_provenance_file_request(project_dir, project_source, path),
    )
}

fn resolve_provenance_request_with_sources(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
    mut resolve_file: impl FnMut(&Path) -> Result<ProvenanceFileRequest, LpmError>,
) -> Result<ProvenanceRequest, LpmError> {
    if no_provenance {
        return Ok(ProvenanceRequest::Disabled);
    }
    if provenance_flag {
        return Ok(ProvenanceRequest::Generate);
    }
    if let Some(path) = provenance_file {
        return Ok(ProvenanceRequest::File(resolve_file(path)?));
    }

    if let Some(request) = package_publish_config_request(pkg_json)? {
        return request.resolve_file(|path| {
            resolve_repository_provenance_file(
                path,
                "publishConfig.provenance-file",
                &mut resolve_file,
            )
        });
    }

    let home = dirs::home_dir();
    let project_npmrc_path = publish_project_npmrc_path(project_dir);
    let project = npmrc_request(&project_npmrc_path)?;
    let user_path = lpm_common::npm_user_config_path(home.as_deref());
    let user_opened = user_path
        .as_deref()
        .map(read_user_npmrc_content)
        .transpose()?
        .flatten();
    let user = user_path
        .as_deref()
        .zip(user_opened.as_ref())
        .map(|(path, (content, _))| parse_npmrc_request(path, content))
        .transpose()?
        .flatten();
    let global_path = lpm_common::npm_global_config_path_from_user_config(
        home.as_deref(),
        user_opened
            .as_ref()
            .map(|(content, metadata)| (content.as_str(), metadata)),
    );
    let global = npmrc_request(&global_path)?;
    let environment = env_request()?;

    let layers = [
        global.as_ref(),
        user.as_ref(),
        project.as_ref(),
        environment.as_ref(),
    ];
    let has_boolean = layers
        .iter()
        .flatten()
        .any(|request| !matches!(request, NpmrcRequest::File(_)));
    let has_file = layers
        .iter()
        .flatten()
        .any(|request| matches!(request, NpmrcRequest::File(_)));
    if has_boolean && has_file {
        return Err(LpmError::Registry(
            "provenance and provenance-file are mutually exclusive across npm configuration layers"
                .into(),
        ));
    }

    if let Some(request) = environment {
        return request.resolve_file(&mut resolve_file);
    }
    if let Some(request) = project {
        return request.resolve_file(|path| {
            resolve_repository_provenance_file(
                path,
                "project .npmrc provenance-file",
                &mut resolve_file,
            )
        });
    }
    if let Some(request) = user.or(global) {
        return request.resolve_file(&mut resolve_file);
    }

    Ok(ProvenanceRequest::Disabled)
}

fn resolve_repository_provenance_file(
    path: &Path,
    source: &str,
    resolve: &mut impl FnMut(&Path) -> Result<ProvenanceFileRequest, LpmError>,
) -> Result<ProvenanceFileRequest, LpmError> {
    if path.is_absolute() {
        return Err(LpmError::Registry(format!(
            "{source} must not use an absolute path; repository configuration can select only files inside the selected project"
        )));
    }
    resolve(path)
}

fn publish_project_npmrc_path(project_dir: &Path) -> PathBuf {
    lpm_workspace::find_workspace_root(project_dir)
        .ok()
        .flatten()
        .unwrap_or_else(|| project_dir.to_path_buf())
        .join(".npmrc")
}

fn resolve_provenance_file_request(
    project_dir: &Path,
    project_source: &Arc<cap_std::fs::Dir>,
    path: &Path,
) -> Result<ProvenanceFileRequest, LpmError> {
    if path.as_os_str().is_empty() {
        return Err(LpmError::Registry(
            "provenance file path must not be empty".into(),
        ));
    }
    if path.is_absolute() {
        return Ok(ProvenanceFileRequest::AmbientPath(path.to_path_buf()));
    }
    let mut relative_path = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(component) => relative_path.push(component),
            std::path::Component::CurDir => {}
            _ => {
                return Err(LpmError::Registry(format!(
                    "provenance file path {} is unsafe: relative paths must stay inside the selected project",
                    path.display()
                )));
            }
        }
    }
    if relative_path.as_os_str().is_empty() {
        return Err(LpmError::Registry(
            "provenance file path must identify a file inside the selected project".into(),
        ));
    }
    let display_path = project_dir.join(&relative_path);
    Ok(ProvenanceFileRequest::ProjectFile {
        display_path,
        relative_path,
        source_dir: Arc::clone(project_source),
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
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value == "true")),
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

fn package_publish_config_request(
    pkg_json: &serde_json::Value,
) -> Result<Option<NpmrcRequest>, LpmError> {
    let Some(config) = pkg_json
        .get("publishConfig")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let provenance = config
        .get("provenance")
        .and_then(serde_json::Value::as_bool)
        .map(|value| {
            if value {
                NpmrcRequest::Generate
            } else {
                NpmrcRequest::Disabled
            }
        });
    let provenance_file = config
        .get("provenance-file")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(NpmrcRequest::File);
    match (provenance, provenance_file) {
        (Some(_), Some(_)) => Err(LpmError::Registry(
            "publishConfig.provenance and publishConfig.provenance-file are mutually exclusive"
                .into(),
        )),
        (Some(request), None) | (None, Some(request)) => Ok(Some(request)),
        (None, None) => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NpmrcRequest {
    Generate,
    File(PathBuf),
    Disabled,
}

impl NpmrcRequest {
    fn resolve_file(
        self,
        mut resolve: impl FnMut(&Path) -> Result<ProvenanceFileRequest, LpmError>,
    ) -> Result<ProvenanceRequest, LpmError> {
        match self {
            Self::Generate => Ok(ProvenanceRequest::Generate),
            Self::Disabled => Ok(ProvenanceRequest::Disabled),
            Self::File(path) => resolve(&path).map(ProvenanceRequest::File),
        }
    }
}

fn npmrc_request(path: &Path) -> Result<Option<NpmrcRequest>, LpmError> {
    let Some(content) = read_npmrc_content(path)? else {
        return Ok(None);
    };

    parse_npmrc_request(path, &content)
}

fn read_npmrc_content(path: &Path) -> Result<Option<String>, LpmError> {
    match lpm_common::read_text_file_capped_nofollow(path, lpm_common::NPMRC_FILE_SIZE_CAP_BYTES) {
        Ok(content) => Ok(Some(content)),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => Ok(None),
        Err(error) => Err(LpmError::Registry(format!(
            "refusing unreadable or unsafe npm config {}: {error}",
            path.display()
        ))),
    }
}

fn read_user_npmrc_content(path: &Path) -> Result<Option<(String, std::fs::Metadata)>, LpmError> {
    match lpm_common::read_text_regular_file_capped_with_metadata(
        path,
        lpm_common::NPMRC_FILE_SIZE_CAP_BYTES,
    ) {
        Ok((content, metadata)) => {
            if !lpm_common::npmrc_can_influence_config_discovery(&metadata) {
                tracing::warn!(
                    "refusing writable user npm config {} for provenance and global config discovery",
                    path.display()
                );
                return Ok(None);
            }
            Ok(Some((content, metadata)))
        }
        Err(lpm_common::BoundedReadError::NotFound { .. }) => Ok(None),
        Err(error) => Err(LpmError::Registry(format!(
            "refusing unreadable or unsafe npm config {}: {error}",
            path.display()
        ))),
    }
}

fn parse_npmrc_request(path: &Path, content: &str) -> Result<Option<NpmrcRequest>, LpmError> {
    let mut request = None;
    let mut provenance_line = None;
    let mut provenance_file_line = None;
    let mut warnings = Vec::new();
    let content = lpm_common::strip_utf8_bom_str(content);
    for setting in
        lpm_common::parse_npmrc_ini_settings(content, &path.display().to_string(), &mut warnings)
    {
        if setting.is_array {
            continue;
        }
        let key = lpm_common::interpolate_npmrc_env(&setting.key, &|name| std::env::var(name).ok())
            .map_err(|error| {
                LpmError::Registry(format!(
                    "{}: npm config key interpolation failed: {error}",
                    path.display()
                ))
            })?;
        if !matches!(key.as_ref(), "provenance" | "provenance-file") {
            continue;
        }
        let Some(raw_value) = setting.values.last() else {
            continue;
        };
        let value = lpm_common::interpolate_npmrc_env(raw_value.value.as_ref(), &|name| {
            std::env::var(name).ok()
        })
        .map_err(|error| {
            LpmError::Registry(format!(
                "{}:{}: npm config value interpolation failed: {error}",
                path.display(),
                raw_value.line
            ))
        })?;
        match key.as_ref() {
            "provenance" => {
                provenance_line = Some(raw_value.line);
                request = Some(if value.is_empty() || value == "true" {
                    NpmrcRequest::Generate
                } else {
                    NpmrcRequest::Disabled
                });
            }
            "provenance-file" => {
                provenance_file_line = Some(raw_value.line);
                if value.is_empty() {
                    return Err(LpmError::Registry(format!(
                        "{}:{} provenance-file must not be empty",
                        path.display(),
                        raw_value.line
                    )));
                }
                request = Some(NpmrcRequest::File(PathBuf::from(value.as_ref())));
            }
            _ => {}
        }
    }

    for warning in warnings {
        tracing::warn!("{warning}");
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
        assert!(matches!(request, ProvenanceRequest::Generate));
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
        assert!(matches!(request, ProvenanceRequest::Disabled));
    }

    #[test]
    fn resolve_provenance_request_cli_file_binds_relative_to_project_source() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bundle.sigstore"), b"retained bundle").unwrap();
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            Some(Path::new("bundle.sigstore")),
        )
        .unwrap();
        let ProvenanceRequest::File(ProvenanceFileRequest::ProjectFile {
            display_path,
            relative_path,
            source_dir: _,
        }) = request
        else {
            panic!("expected a project provenance file");
        };
        assert_eq!(
            (display_path, relative_path),
            (
                dir.path().canonicalize().unwrap().join("bundle.sigstore"),
                PathBuf::from("bundle.sigstore")
            )
        );
    }

    #[test]
    fn resolve_provenance_request_normalizes_current_directory_components() {
        let dir = tempfile::tempdir().unwrap();
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            Some(Path::new("./bundle.sigstore")),
        )
        .unwrap();
        let ProvenanceRequest::File(ProvenanceFileRequest::ProjectFile { relative_path, .. }) =
            request
        else {
            panic!("expected a project provenance file");
        };

        assert_eq!(relative_path, Path::new("bundle.sigstore"));
    }

    #[test]
    fn resolve_provenance_request_rejects_relative_parent_traversal() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(root.path().join("outside.sigstore"), b"outside bundle").unwrap();
        let canonical = project.canonicalize().unwrap();
        let source = Arc::new(
            crate::commands::publish_common::open_tarball_source_root(&canonical).unwrap(),
        );

        let error = resolve_provenance_request_from_project_source(
            &canonical,
            &source,
            &pkg_json(serde_json::json!({})),
            false,
            false,
            Some(Path::new("../outside.sigstore")),
        )
        .expect_err("relative provenance paths must stay inside the project")
        .to_string();

        assert!(error.contains("unsafe"), "{error}");
    }

    #[test]
    fn resolve_provenance_request_keeps_absolute_paths_explicitly_ambient() {
        let project = tempfile::tempdir().unwrap();
        let canonical = project.path().canonicalize().unwrap();
        let source = Arc::new(
            crate::commands::publish_common::open_tarball_source_root(&canonical).unwrap(),
        );
        let absolute = canonical.join("bundle.sigstore");

        let request = resolve_provenance_request_from_project_source(
            &canonical,
            &source,
            &pkg_json(serde_json::json!({})),
            false,
            false,
            Some(&absolute),
        )
        .unwrap();

        let ProvenanceRequest::File(ProvenanceFileRequest::AmbientPath(resolved)) = request else {
            panic!("expected an ambient provenance file");
        };
        assert_eq!(resolved, absolute);
    }

    #[test]
    fn environment_provenance_file_keeps_absolute_paths_ambient() {
        let project = tempfile::tempdir().unwrap();
        let absolute = project.path().join("ambient.sigstore");
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            (
                "NPM_CONFIG_PROVENANCE_FILE",
                Some(absolute.as_os_str().to_os_string()),
            ),
            ("npm_config_provenance_file", None),
        ]);

        let request = resolve_provenance_request(
            project.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();

        let ProvenanceRequest::File(ProvenanceFileRequest::AmbientPath(resolved)) = request else {
            panic!("environment configuration must retain ambient authority");
        };
        assert_eq!(resolved, absolute);
    }

    #[test]
    fn user_npmrc_provenance_file_keeps_absolute_paths_ambient() {
        let project = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let user_npmrc = config_dir.path().join("user.npmrc");
        let absolute = config_dir.path().join("ambient.sigstore");
        std::fs::write(
            &user_npmrc,
            format!("provenance-file={}\n", absolute.display()),
        )
        .unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
            (
                "NPM_CONFIG_USERCONFIG",
                Some(user_npmrc.as_os_str().to_os_string()),
            ),
            ("npm_config_userconfig", None),
        ]);

        let request = resolve_provenance_request(
            project.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();

        let ProvenanceRequest::File(ProvenanceFileRequest::AmbientPath(resolved)) = request else {
            panic!("user configuration must retain ambient authority");
        };
        assert_eq!(resolved, absolute);
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
        assert!(matches!(request, ProvenanceRequest::Generate));
    }

    #[test]
    fn publish_config_provenance_string_does_not_enable_generation() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({"publishConfig": {"provenance": "true"}})),
            false,
            false,
            None,
        )
        .unwrap();

        assert!(matches!(request, ProvenanceRequest::Disabled));
    }

    #[test]
    fn publish_config_provenance_file_selects_a_project_relative_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({
                "publishConfig": {"provenance-file": "bundle.sigstore"}
            })),
            false,
            false,
            None,
        )
        .unwrap();

        let ProvenanceRequest::File(ProvenanceFileRequest::ProjectFile { relative_path, .. }) =
            request
        else {
            panic!("publishConfig.provenance-file must select a file");
        };
        assert_eq!(relative_path, Path::new("bundle.sigstore"));
    }

    #[test]
    fn publish_config_provenance_file_rejects_an_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        let absolute = dir.path().join("outside.sigstore");

        let error = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({
                "publishConfig": {"provenance-file": absolute}
            })),
            false,
            false,
            None,
        )
        .expect_err("repository publishConfig must not select an ambient file")
        .to_string();

        assert!(
            error.contains("absolute") && error.contains("publishConfig"),
            "{error}"
        );
    }

    #[test]
    fn npm_boolean_strings_other_than_exact_lowercase_true_do_not_enable_provenance() {
        let dir = tempfile::tempdir().unwrap();
        for value in ["yes", "on", "1", "TRUE"] {
            let _env = ScopedEnv::update([
                ("NPM_CONFIG_PROVENANCE", Some(value.into())),
                ("npm_config_provenance", None),
                ("NPM_CONFIG_PROVENANCE_FILE", None),
                ("npm_config_provenance_file", None),
            ]);
            let request = resolve_provenance_request(
                dir.path(),
                &pkg_json(serde_json::json!({})),
                false,
                false,
                None,
            )
            .unwrap_or_else(|error| panic!("{value:?} must remain a non-Boolean value: {error}"));
            assert!(
                matches!(request, ProvenanceRequest::Disabled),
                "{value:?} must not enable provenance"
            );
        }
    }

    #[test]
    fn empty_env_provenance_keeps_the_default_disabled_value() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", Some(String::new().into())),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);

        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();
        assert!(matches!(request, ProvenanceRequest::Disabled));
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
        assert!(matches!(request, ProvenanceRequest::Generate));
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
        assert!(matches!(request, ProvenanceRequest::Generate));
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
        assert!(matches!(request, ProvenanceRequest::Generate));
    }

    #[test]
    fn project_npmrc_provenance_file_rejects_an_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        let absolute = dir.path().join("outside.sigstore");
        std::fs::write(
            dir.path().join(".npmrc"),
            format!("provenance-file={}\n", absolute.display()),
        )
        .unwrap();

        let error = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .expect_err("repository npmrc must not select an ambient file")
        .to_string();

        assert!(
            error.contains("absolute") && error.contains("project .npmrc"),
            "{error}"
        );
    }

    #[test]
    fn project_npmrc_provenance_uses_npm_ini_comments_and_env_interpolation() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
            ("NPMRC_PROVENANCE", Some("true".into())),
        ]);
        std::fs::write(
            dir.path().join(".npmrc"),
            "provenance=${NPMRC_PROVENANCE} # generated in CI\n",
        )
        .unwrap();

        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .expect("npm-compatible ini should parse");
        assert!(matches!(request, ProvenanceRequest::Generate));
    }

    #[test]
    fn unrelated_npmrc_value_expansion_does_not_block_provenance_selection() {
        let oversized = "x".repeat(lpm_common::NPMRC_INTERPOLATED_VALUE_CAP_BYTES + 1);
        let _env = ScopedEnv::update([("NPMRC_UNUSED_OVERSIZED", Some(oversized.into()))]);

        let request = parse_npmrc_request(
            Path::new("project.npmrc"),
            "registry=${NPMRC_UNUSED_OVERSIZED}\nprovenance=true\n",
        )
        .expect("unrelated npm settings must not affect provenance selection");

        assert!(matches!(request, Some(NpmrcRequest::Generate)));
    }

    #[test]
    fn empty_project_npmrc_provenance_enables_generation() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        std::fs::write(dir.path().join(".npmrc"), "provenance=\n").unwrap();

        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();
        assert!(matches!(request, ProvenanceRequest::Generate));
    }

    #[test]
    fn project_npmrc_uses_only_exact_lowercase_provenance_keys() {
        let dir = tempfile::tempdir().unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);
        std::fs::write(
            dir.path().join(".npmrc"),
            "PROVENANCE=true\nprovenancefile=bundle.sigstore\n",
        )
        .unwrap();

        let request = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();
        assert!(matches!(request, ProvenanceRequest::Disabled));
    }

    #[test]
    fn publish_from_a_workspace_member_uses_the_workspace_root_npmrc() {
        let root = tempfile::tempdir().unwrap();
        let member = root.path().join("packages/member");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        std::fs::write(
            member.join("package.json"),
            r#"{"name":"member","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(root.path().join(".npmrc"), "provenance=true\n").unwrap();
        std::fs::write(member.join(".npmrc"), "provenance=false\n").unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);

        let request = resolve_provenance_request(
            &member,
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();
        assert!(matches!(request, ProvenanceRequest::Generate));
    }

    #[test]
    fn provenance_conflicts_are_rejected_across_env_and_project_layers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".npmrc"),
            "provenance-file=bundle.sigstore\n",
        )
        .unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", Some("false".into())),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);

        let error = resolve_provenance_request(
            dir.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .expect_err("npm rejects provenance and provenance-file across layers");
        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn provenance_discovery_honors_userconfig_override() {
        let project = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let userconfig = config.path().join("publish.npmrc");
        std::fs::write(&userconfig, "provenance=true\n").unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
            (
                "NPM_CONFIG_USERCONFIG",
                Some(userconfig.as_os_str().to_owned()),
            ),
            ("npm_config_userconfig", None),
        ]);

        let request = resolve_provenance_request(
            project.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();
        assert!(matches!(request, ProvenanceRequest::Generate));
    }

    #[cfg(unix)]
    #[test]
    fn writable_user_npmrc_cannot_redirect_global_provenance_discovery() {
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let redirected_prefix = config.path().join("redirected-prefix");
        std::fs::create_dir_all(redirected_prefix.join("etc")).unwrap();
        std::fs::write(redirected_prefix.join("etc/npmrc"), "provenance=true\n").unwrap();
        let userconfig = config.path().join("user.npmrc");
        std::fs::write(
            &userconfig,
            format!("prefix={}\n", redirected_prefix.display()),
        )
        .unwrap();
        std::fs::set_permissions(&userconfig, std::fs::Permissions::from_mode(0o622)).unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
            (
                "NPM_CONFIG_USERCONFIG",
                Some(userconfig.as_os_str().to_owned()),
            ),
            ("npm_config_userconfig", None),
            ("NPM_CONFIG_GLOBALCONFIG", None),
            ("npm_config_globalconfig", None),
            ("NPM_CONFIG_PREFIX", None),
            ("npm_config_prefix", None),
            ("PREFIX", None),
        ]);

        let request = resolve_provenance_request(
            project.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();

        assert!(matches!(request, ProvenanceRequest::Disabled));
    }

    #[test]
    fn provenance_discovery_expands_a_tilde_userconfig_override() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("publish.npmrc"), "provenance=true\n").unwrap();
        let _env = ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
            ("NPM_CONFIG_USERCONFIG", Some("~/publish.npmrc".into())),
            ("npm_config_userconfig", None),
        ]);

        let request = resolve_provenance_request(
            project.path(),
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .unwrap();
        assert!(matches!(request, ProvenanceRequest::Generate));
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

    #[cfg(unix)]
    #[test]
    fn resolve_provenance_request_rejects_a_linked_project_npmrc() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let external = root.path().join("external.npmrc");
        std::fs::write(&external, "provenance=true\n").unwrap();
        std::os::unix::fs::symlink(&external, project.join(".npmrc")).unwrap();
        let _env = ScopedEnv::update([
            ("NPM_CONFIG_PROVENANCE", None),
            ("npm_config_provenance", None),
            ("NPM_CONFIG_PROVENANCE_FILE", None),
            ("npm_config_provenance_file", None),
        ]);

        let error = resolve_provenance_request(
            &project,
            &pkg_json(serde_json::json!({})),
            false,
            false,
            None,
        )
        .expect_err("linked project .npmrc must not configure publish")
        .to_string();

        assert!(
            error.contains(".npmrc") && error.contains("unsafe"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ambient_npmrc_fifo_is_rejected_promptly() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join(".npmrc");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let fifo_for_worker = fifo.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = npmrc_request(&fifo_for_worker)
                .map(|_| ())
                .map_err(|error| error.to_string());
            sender.send(result).unwrap();
        });
        let result = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(result) => result,
            Err(error) => {
                let writer = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                drop(writer);
                let _ = receiver.recv_timeout(std::time::Duration::from_secs(1));
                worker.join().unwrap();
                panic!("ambient .npmrc loading blocked on a FIFO: {error}");
            }
        };
        worker.join().unwrap();

        let error = result.expect_err("an ambient FIFO .npmrc must be rejected");
        assert!(error.contains(".npmrc"), "{error}");
    }

    #[test]
    fn project_relative_provenance_keeps_the_selected_project_generation() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let displaced = root.path().join("displaced");
        let replacement = root.path().join("replacement");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        std::fs::write(project.join("bundle.sigstore"), [0xff]).unwrap();
        std::fs::write(replacement.join("bundle.sigstore"), b"{}").unwrap();
        let canonical = project.canonicalize().unwrap();
        let source = Arc::new(
            crate::commands::publish_common::open_tarball_source_root(&canonical).unwrap(),
        );
        let request = resolve_provenance_request_from_project_source(
            &canonical,
            &source,
            &pkg_json(serde_json::json!({})),
            false,
            false,
            Some(Path::new("bundle.sigstore")),
        )
        .unwrap();
        std::fs::rename(&project, &displaced).unwrap();
        std::fs::rename(&replacement, &project).unwrap();

        let ProvenanceRequest::File(request) = request else {
            panic!("expected a project provenance snapshot");
        };

        let error = load_provenance_request_file(&request)
            .expect_err("the selected invalid provenance generation must be loaded")
            .to_string();

        assert!(
            error.contains("expected UTF-8 Sigstore bundle JSON"),
            "{error}"
        );
    }
}
