use super::types::PublishProject;
use crate::commands::publish_common;
use lpm_common::LpmError;
use lpm_runner::lpm_json;
use std::path::Path;

pub(super) const MAX_PUBLISH_TARBALL_BYTES: usize = 500 * 1024 * 1024;

pub(crate) struct PublishManifest {
    pub(crate) package_json_path: std::path::PathBuf,
    pub(crate) package_json_content: String,
    pub(crate) package_json_override: Option<Vec<u8>>,
    pub(crate) pkg_json: serde_json::Value,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) publish_config: Option<lpm_json::PublishConfig>,
}

pub(crate) fn prepare_publish_project(
    project_dir: &Path,
    scan_secrets: bool,
) -> Result<PublishProject, LpmError> {
    let manifest = read_publish_manifest(project_dir)?;
    prepare_publish_project_from_manifest(project_dir, manifest, scan_secrets)
}

pub(crate) fn read_publish_manifest(project_dir: &Path) -> Result<PublishManifest, LpmError> {
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
    validate_publish_version(&version).map_err(|error| {
        LpmError::Registry(format!(
            "package.json \"version\" must be a valid semantic version (got \"{version}\"): {error}"
        ))
    })?;
    if pkg_json.get("private").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err(LpmError::Registry(
            "package.json is marked as private; remove \"private\": true before publishing".into(),
        ));
    }

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

fn validate_publish_version(version: &str) -> Result<lpm_semver::Version, &'static str> {
    let (without_build, build) = version
        .split_once('+')
        .map_or((version, None), |(base, build)| (base, Some(build)));
    if build.is_some_and(|identifiers| {
        identifiers.is_empty()
            || identifiers.contains('+')
            || !valid_semver_identifiers(identifiers, true)
    }) {
        return Err("invalid build metadata");
    }

    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    if prerelease.is_some_and(|identifiers| {
        identifiers.is_empty() || !valid_semver_identifiers(identifiers, false)
    }) {
        return Err("invalid prerelease identifiers");
    }

    let mut core_identifiers = core.split('.');
    let major = core_identifiers.next().ok_or("missing major version")?;
    let minor = core_identifiers.next().ok_or("missing minor version")?;
    let patch = core_identifiers.next().ok_or("missing patch version")?;
    if core_identifiers.next().is_some()
        || !valid_semver_number(major)
        || !valid_semver_number(minor)
        || !valid_semver_number(patch)
    {
        return Err("version core must contain three canonical numeric identifiers");
    }

    lpm_semver::Version::parse(version).map_err(|_| "version number is out of range")
}

fn valid_semver_number(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.bytes().all(|byte| byte.is_ascii_digit())
        && (identifier == "0" || !identifier.starts_with('0'))
}

fn valid_semver_identifiers(identifiers: &str, allow_numeric_leading_zeroes: bool) -> bool {
    identifiers.split('.').all(|identifier| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && (allow_numeric_leading_zeroes
                || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                || valid_semver_number(identifier))
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
