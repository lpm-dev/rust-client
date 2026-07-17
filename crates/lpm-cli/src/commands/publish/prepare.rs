use super::types::PublishProject;
use crate::commands::publish_common;
use lpm_common::LpmError;
use lpm_runner::lpm_json;
use std::path::Path;

pub(super) struct PublishManifest {
    pub(super) package_json_path: std::path::PathBuf,
    pub(super) pkg_json: serde_json::Value,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) publish_config: Option<lpm_json::PublishConfig>,
}

pub(crate) fn prepare_publish_project(project_dir: &Path) -> Result<PublishProject, LpmError> {
    let manifest = read_publish_manifest(project_dir)?;
    prepare_publish_project_from_manifest(project_dir, manifest)
}

pub(super) fn read_publish_manifest(project_dir: &Path) -> Result<PublishManifest, LpmError> {
    let package_json_path = project_dir.join("package.json");
    if !package_json_path.exists() {
        return Err(LpmError::NotFound(
            "no package.json found in current directory".to_string(),
        ));
    }

    let content = std::fs::read_to_string(&package_json_path)?;
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
        pkg_json,
        name,
        version,
        publish_config,
    })
}

pub(super) fn prepare_publish_project_from_manifest(
    project_dir: &Path,
    manifest: PublishManifest,
) -> Result<PublishProject, LpmError> {
    let PublishManifest {
        package_json_path: _,
        pkg_json,
        name,
        version,
        publish_config,
    } = manifest;
    let readme = publish_common::read_readme(project_dir);
    let (mut tarball_data, tarball_files) = publish_common::create_tarball(project_dir, &pkg_json)?;

    let workspace = lpm_workspace::discover_workspace(project_dir)
        .ok()
        .flatten();
    if let Some(ref ws) = workspace {
        tarball_data = publish_common::rewrite_workspace_deps_in_tarball(&tarball_data, ws)?;
    }

    let tarball_size = tarball_data.len();
    if tarball_size > 500 * 1024 * 1024 {
        return Err(LpmError::Registry(format!(
            "tarball too large: {} (max 500MB)",
            lpm_common::format_bytes(tarball_size as u64)
        )));
    }

    let (detected_ecosystem, swift_manifest) = detect_publish_ecosystem(project_dir);

    Ok(PublishProject {
        pkg_json,
        name,
        version,
        publish_config,
        readme,
        tarball_data,
        tarball_files,
        tarball_size,
        detected_ecosystem,
        swift_manifest,
    })
}

pub(super) fn detect_publish_ecosystem(project_dir: &Path) -> (String, Option<serde_json::Value>) {
    let mut detected_ecosystem = "js".to_string();
    let lpm_config_path = project_dir.join("lpm.config.json");
    if lpm_config_path.exists()
        && let Ok(config_str) = std::fs::read_to_string(&lpm_config_path)
        && let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str)
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

    (detected_ecosystem, swift_manifest)
}
