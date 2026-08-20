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
    resolve_provenance_request_with_project_npmrc_loader(
        &canonical_project_dir,
        pkg_json,
        provenance_flag,
        no_provenance,
        provenance_file,
        || {
            super::prepare::read_optional_publish_text(
                &project_source,
                Path::new(".npmrc"),
                &canonical_project_dir.join(".npmrc"),
                lpm_common::NPMRC_FILE_SIZE_CAP_BYTES,
            )
        },
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
    resolve_provenance_request_with_project_npmrc_loader(
        project_dir,
        pkg_json,
        provenance_flag,
        no_provenance,
        provenance_file,
        || {
            super::prepare::read_optional_publish_text(
                project_source,
                Path::new(".npmrc"),
                &project_dir.join(".npmrc"),
                lpm_common::NPMRC_FILE_SIZE_CAP_BYTES,
            )
        },
        |path| resolve_provenance_file_request(project_dir, project_source, path),
    )
}

fn resolve_provenance_request_with_project_npmrc_loader(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
    load_project_npmrc: impl FnOnce() -> Result<Option<String>, LpmError>,
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

    if let Some(value) = package_publish_config_bool(pkg_json, "provenance")? {
        return Ok(if value {
            ProvenanceRequest::Generate
        } else {
            ProvenanceRequest::Disabled
        });
    }

    if let Some(request) = env_request()? {
        return request.resolve_file(&mut resolve_file);
    }

    let project_npmrc_path = project_dir.join(".npmrc");
    if let Some(content) = load_project_npmrc()?
        && let Some(request) = parse_npmrc_request(&project_npmrc_path, &content)?
    {
        return request.resolve_file(&mut resolve_file);
    }
    if let Some(home) = dirs::home_dir()
        && let Some(request) = npmrc_request(&home.join(".npmrc"))?
    {
        return request.resolve_file(&mut resolve_file);
    }

    Ok(ProvenanceRequest::Disabled)
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
    let content = match lpm_common::read_text_file_capped_nofollow(
        path,
        lpm_common::NPMRC_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    parse_npmrc_request(path, &content)
}

fn parse_npmrc_request(path: &Path, content: &str) -> Result<Option<NpmrcRequest>, LpmError> {
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
