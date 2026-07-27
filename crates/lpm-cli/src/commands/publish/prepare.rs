use super::types::PublishProject;
use crate::commands::publish_common;
use lpm_common::LpmError;
use lpm_runner::lpm_json;
use std::path::Path;

pub(super) const MAX_PUBLISH_TARBALL_BYTES: usize = 500 * 1024 * 1024;

pub(super) struct PublishManifest {
    pub(super) package_json_path: std::path::PathBuf,
    pub(super) package_json_content: String,
    pub(super) package_json_override: Option<Vec<u8>>,
    pub(super) pkg_json: serde_json::Value,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) publish_config: Option<lpm_json::PublishConfig>,
}

pub(crate) fn prepare_publish_project(
    project_dir: &Path,
    scan_secrets: bool,
) -> Result<PublishProject, LpmError> {
    let manifest = read_publish_manifest(project_dir)?;
    prepare_publish_project_from_manifest(project_dir, manifest, scan_secrets)
}

pub(super) fn read_publish_manifest(project_dir: &Path) -> Result<PublishManifest, LpmError> {
    let package_json_path = project_dir.join("package.json");
    let content = match lpm_common::read_text_file_capped(
        &package_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Err(LpmError::NotFound(
                "no package.json found in current directory".to_string(),
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let pkg_json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let name = pkg_json
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LpmError::Registry("package.json missing \"name\"".into()))?
        .to_string();

    let version = pkg_json
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LpmError::Registry("package.json missing \"version\"".into()))?
        .to_string();

    let lpm_config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Registry)?;
    let publish_config = lpm_config.and_then(|c| c.publish);

    Ok(PublishManifest {
        package_json_path,
        package_json_content: content,
        package_json_override: None,
        pkg_json,
        name,
        version,
        publish_config,
    })
}

pub(super) fn prepare_publish_project_from_manifest(
    project_dir: &Path,
    manifest: PublishManifest,
    scan_secrets: bool,
) -> Result<PublishProject, LpmError> {
    let PublishManifest {
        package_json_path: _,
        package_json_content,
        package_json_override,
        pkg_json,
        name,
        version,
        publish_config,
    } = manifest;
    let readme = publish_common::read_readme(project_dir);
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .ok()
        .flatten();
    let mut prepared_package_json =
        package_json_override.unwrap_or_else(|| package_json_content.into_bytes());
    if let Some(ref ws) = workspace
        && let Some(rewritten) =
            publish_common::rewrite_workspace_deps_in_package_json(&prepared_package_json, ws)?
    {
        prepared_package_json = rewritten;
    }

    let prepared_tarball = publish_common::prepare_tarball(
        project_dir,
        &pkg_json,
        publish_common::TarballOptions {
            package_json_content: Some(&prepared_package_json),
            scan_secrets,
        },
    )?;
    let tarball_data = std::sync::Arc::new(prepared_tarball.data);
    let tarball_size = tarball_data.len();
    validate_publish_tarball_size(tarball_size)?;

    let (detected_ecosystem, swift_manifest) = detect_publish_ecosystem(project_dir)?;

    Ok(PublishProject {
        pkg_json,
        name,
        version,
        publish_config,
        readme,
        tarball_data,
        tarball_files: prepared_tarball.files,
        secret_scan: prepared_tarball.secret_scan,
        tarball_size,
        detected_ecosystem,
        swift_manifest,
    })
}

pub(crate) fn validate_publish_tarball_size(tarball_size: usize) -> Result<(), LpmError> {
    if tarball_size > MAX_PUBLISH_TARBALL_BYTES {
        return Err(LpmError::Registry(format!(
            "tarball too large: {} (max 500 MiB)",
            lpm_common::format_bytes(tarball_size as u64)
        )));
    }
    Ok(())
}

pub(super) fn read_optional_lpm_config(
    project_dir: &Path,
) -> Result<Option<serde_json::Value>, LpmError> {
    let path = project_dir.join("lpm.config.json");
    let content =
        match lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    crate::lpm_config::parse_and_validate(&path, &content).map(Some)
}

pub(super) fn detect_publish_ecosystem(
    project_dir: &Path,
) -> Result<(String, Option<serde_json::Value>), LpmError> {
    let mut detected_ecosystem = "js".to_string();
    if let Some(config) = read_optional_lpm_config(project_dir)?
        && let Some(eco) = config.get("ecosystem").and_then(|v| v.as_str())
    {
        detected_ecosystem = eco.to_string();
    }
    if project_dir.join("Package.swift").exists() && detected_ecosystem == "js" {
        detected_ecosystem = "swift".to_string();
    }

    let swift_manifest = if detected_ecosystem == "swift" {
        std::process::Command::new("swift")
            .args(["package", "dump-package"])
            .current_dir(project_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
    } else {
        None
    };

    Ok((detected_ecosystem, swift_manifest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_padded_empty_config(path: &Path, size: usize) {
        let mut content = vec![b' '; size];
        content[0] = b'{';
        content[1] = b'}';
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn lpm_config_at_the_16_mib_local_limit_is_accepted() {
        let project = tempfile::tempdir().unwrap();
        write_padded_empty_config(
            &project.path().join("lpm.config.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize,
        );

        assert_eq!(
            read_optional_lpm_config(project.path()).unwrap(),
            Some(serde_json::json!({}))
        );
    }

    #[test]
    fn lpm_config_one_byte_over_the_16_mib_local_limit_is_rejected() {
        let project = tempfile::tempdir().unwrap();
        write_padded_empty_config(
            &project.path().join("lpm.config.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize + 1,
        );

        let error = read_optional_lpm_config(project.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("16777216-byte limit"), "{error}");
    }
}
