use super::types::PublishProject;
use crate::commands::publish_common;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use lpm_common::LpmError;
use lpm_runner::lpm_json;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

pub(super) const MAX_PUBLISH_TARBALL_BYTES: usize = 500 * 1024 * 1024;

pub(crate) struct PublishManifest {
    pub(crate) package_json_path: std::path::PathBuf,
    pub(crate) package_json_parent: Arc<cap_std::fs::Dir>,
    pub(crate) package_json_parent_identity: Arc<same_file::Handle>,
    pub(crate) package_json_content: String,
    pub(crate) package_json_override: Option<Vec<u8>>,
    pub(crate) lpm_json_content: Option<String>,
    pub(crate) pkg_json: serde_json::Value,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) publish_config: Option<lpm_json::PublishConfig>,
}

impl PublishManifest {
    pub(crate) fn validate_named_project_root(&self) -> Result<(), LpmError> {
        validate_named_project_root(
            self.package_json_path
                .parent()
                .ok_or_else(|| publish_project_changed_error(&self.package_json_path))?,
            &self.package_json_parent_identity,
            &self.package_json_path,
        )
    }
}

pub(crate) struct PublishSource {
    project_dir: std::path::PathBuf,
    directory: Arc<cap_std::fs::Dir>,
    identity: Arc<same_file::Handle>,
}

impl PublishSource {
    pub(crate) fn open(project_dir: &Path) -> Result<Self, LpmError> {
        let selected =
            cap_std::fs::Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())
                .map_err(LpmError::Io)?;
        let identity =
            same_file::Handle::from_file(selected.into_std_file()).map_err(LpmError::Io)?;
        let project_dir = project_dir.canonicalize().map_err(LpmError::Io)?;
        let directory = publish_common::open_tarball_source_root(&project_dir)?;
        let opened_identity = same_file::Handle::from_file(
            directory.try_clone().map_err(LpmError::Io)?.into_std_file(),
        )
        .map_err(LpmError::Io)?;
        if opened_identity != identity {
            return Err(publish_project_changed_error(
                &project_dir.join("package.json"),
            ));
        }
        Ok(Self {
            project_dir,
            directory: Arc::new(directory),
            identity: Arc::new(identity),
        })
    }

    pub(crate) fn from_open_directory(
        project_dir: std::path::PathBuf,
        directory: cap_std::fs::Dir,
    ) -> Result<Self, LpmError> {
        let identity = same_file::Handle::from_file(
            directory.try_clone().map_err(LpmError::Io)?.into_std_file(),
        )
        .map_err(LpmError::Io)?;
        Ok(Self {
            project_dir,
            directory: Arc::new(directory),
            identity: Arc::new(identity),
        })
    }

    pub(crate) fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    pub(crate) fn try_clone_directory(&self) -> Result<cap_std::fs::Dir, LpmError> {
        self.directory.try_clone().map_err(LpmError::Io)
    }

    pub(crate) fn validate_named_project_root(&self) -> Result<(), LpmError> {
        validate_named_project_root(
            &self.project_dir,
            &self.identity,
            &self.project_dir.join("package.json"),
        )
    }
}

pub(crate) fn prepare_publish_project(
    project_dir: &Path,
    scan_secrets: bool,
) -> Result<PublishProject, LpmError> {
    let manifest = read_publish_manifest(project_dir)?;
    let workspace = discover_workspace_for_publish(project_dir, &manifest)?;
    let validation = crate::commands::skills::author::validate_publish_directory(
        &manifest.package_json_parent,
        project_dir,
    )?;
    if !validation.security_issues.is_empty() {
        return Err(LpmError::Registry(
            "skills contain blocked security patterns".into(),
        ));
    }
    if !validation.errors.is_empty() {
        return Err(LpmError::Registry(format!(
            "skills validation failed: {}",
            validation.errors.join("; ")
        )));
    }
    prepare_publish_project_from_manifest(
        manifest,
        workspace.as_ref(),
        Some(&validation.validated_files),
        scan_secrets,
    )
}

pub(super) fn discover_workspace_for_publish(
    _project_dir: &Path,
    manifest: &PublishManifest,
) -> Result<Option<lpm_workspace::Workspace>, LpmError> {
    if !publish_common::package_json_requires_workspace_projection(
        manifest.package_json_content.as_bytes(),
    ) {
        return Ok(None);
    }
    let project_dir = manifest
        .package_json_path
        .parent()
        .ok_or_else(|| publish_project_changed_error(&manifest.package_json_path))?;
    let workspace_root = lpm_workspace::find_workspace_root_from_open_project(
        project_dir,
        &manifest.package_json_parent,
    )
    .map_err(|error| LpmError::Workspace(error.to_string()))?
    .ok_or_else(|| {
        LpmError::Registry(
            "package.json uses workspace: or catalog: dependencies outside a workspace".to_string(),
        )
    })?;
    let workspace = lpm_workspace::discover_workspace_from_open_root(
        workspace_root.path(),
        workspace_root.directory(),
        project_dir,
    )
    .map_err(|error| LpmError::Workspace(error.to_string()))?;
    workspace.map_or_else(
        || {
            Err(LpmError::Registry(
                "package.json uses workspace: or catalog: dependencies outside a workspace"
                    .to_string(),
            ))
        },
        |workspace| Ok(Some(workspace)),
    )
}

pub(crate) fn read_publish_manifest(project_dir: &Path) -> Result<PublishManifest, LpmError> {
    read_publish_manifest_from_source(PublishSource::open(project_dir)?)
}

pub(crate) fn read_publish_manifest_from_source(
    source: PublishSource,
) -> Result<PublishManifest, LpmError> {
    source.validate_named_project_root()?;
    let PublishSource {
        project_dir: canonical_project_dir,
        directory: package_json_parent,
        identity: package_json_parent_identity,
    } = source;
    let package_json_path = canonical_project_dir.join("package.json");
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let package_json_file = match package_json_parent.open_with("package.json", &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LpmError::NotFound(
                "no package.json found in current directory".to_string(),
            ));
        }
        Err(_) => {
            return Err(LpmError::Registry(
                "package.json changed or became unsafe while preparing the publish tarball".into(),
            ));
        }
    };
    let package_json_metadata = package_json_file.metadata().map_err(LpmError::Io)?;
    if !package_json_metadata.is_file()
        || publish_common::metadata_is_link_or_reparse(&package_json_metadata)
    {
        return Err(LpmError::Registry(
            "package.json changed or became unsafe while preparing the publish tarball".into(),
        ));
    }
    let content = lpm_common::read_text_file_capped_from_open_file_with_known_size(
        package_json_file.into_std(),
        &package_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        package_json_metadata.len(),
    )?;
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

    let lpm_json_content = read_optional_publish_text(
        &package_json_parent,
        Path::new("lpm.json"),
        &canonical_project_dir.join("lpm.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )?;
    let lpm_config = lpm_json_content
        .as_deref()
        .map(|content| lpm_json::parse_lpm_json(content).map_err(LpmError::Registry))
        .transpose()?;
    let publish_config = lpm_config.and_then(|c| c.publish);
    Ok(PublishManifest {
        package_json_path,
        package_json_parent,
        package_json_parent_identity,
        package_json_content: content,
        package_json_override: None,
        lpm_json_content,
        pkg_json,
        name,
        version,
        publish_config,
    })
}

#[cfg(test)]
fn read_publish_manifest_with_selection_hook(
    project_dir: &Path,
    after_selection: impl FnOnce(),
) -> Result<PublishManifest, LpmError> {
    let selected = PublishSource::open(project_dir)?;
    after_selection();
    selected.validate_named_project_root()?;
    read_publish_manifest_from_source(selected)
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
    manifest: PublishManifest,
    workspace: Option<&lpm_workspace::Workspace>,
    validated_skills: Option<&[crate::commands::skills::author::ValidatedSkillFile]>,
    scan_secrets: bool,
) -> Result<PublishProject, LpmError> {
    prepare_publish_project_from_manifest_with_hook(
        manifest,
        workspace,
        validated_skills,
        scan_secrets,
        || {},
    )
}

fn prepare_publish_project_from_manifest_with_hook(
    manifest: PublishManifest,
    workspace: Option<&lpm_workspace::Workspace>,
    validated_skills: Option<&[crate::commands::skills::author::ValidatedSkillFile]>,
    scan_secrets: bool,
    before_tarball_preparation: impl FnOnce(),
) -> Result<PublishProject, LpmError> {
    manifest.validate_named_project_root()?;
    let package_json_parent = Arc::clone(&manifest.package_json_parent);
    let package_json_parent_identity = Arc::clone(&manifest.package_json_parent_identity);
    let package_json_path = manifest.package_json_path.clone();
    let project_root = package_json_path
        .parent()
        .ok_or_else(|| publish_project_changed_error(&package_json_path))?
        .to_path_buf();
    let PublishManifest {
        package_json_path: _,
        package_json_parent: _,
        package_json_parent_identity: _,
        package_json_content,
        package_json_override,
        lpm_json_content,
        mut pkg_json,
        name,
        version,
        publish_config,
    } = manifest;
    let mut prepared_package_json =
        package_json_override.unwrap_or_else(|| package_json_content.into_bytes());
    if publish_common::package_json_requires_workspace_projection(&prepared_package_json) {
        let workspace = workspace.ok_or_else(|| {
            LpmError::Registry(
                "package.json uses workspace: or catalog: dependencies outside a workspace"
                    .to_string(),
            )
        })?;
        if let Some(rewritten) = publish_common::rewrite_workspace_deps_in_package_json(
            &prepared_package_json,
            workspace,
        )? {
            prepared_package_json = rewritten;
            pkg_json = serde_json::from_slice(&prepared_package_json).map_err(|error| {
                LpmError::Registry(format!(
                    "failed to parse projected package.json while preparing publish metadata: {error}"
                ))
            })?;
        }
    }

    let lpm_config_content = read_optional_lpm_config_from_source_root(
        &package_json_parent,
        &project_root.join("lpm.config.json"),
    )?;
    let lpm_config_scan =
        lpm_config_content
            .as_ref()
            .map(|content| publish_common::PublishScanInput {
                path: "lpm.config.json",
                content: content.as_bytes(),
            });
    let extra_scan_files = lpm_config_scan.as_slice();
    let validated_skill_overrides = validated_skills.map(|skills| {
        skills
            .iter()
            .map(|skill| publish_common::PublishContentOverride {
                path: &skill.archive_path,
                content: &skill.content,
                include_if_missing: true,
            })
            .collect::<Vec<_>>()
    });
    let mut content_overrides = Vec::with_capacity(2);
    if let Some(content) = lpm_config_content.as_ref() {
        content_overrides.push(publish_common::PublishContentOverride {
            path: "lpm.config.json",
            content: content.as_bytes(),
            include_if_missing: true,
        });
    }
    if let Some(content) = lpm_json_content.as_ref() {
        content_overrides.push(publish_common::PublishContentOverride {
            path: "lpm.json",
            content: content.as_bytes(),
            include_if_missing: true,
        });
    }
    let mut excluded_paths = Vec::with_capacity(2);
    if lpm_config_content.is_none() {
        excluded_paths.push("lpm.config.json");
    }
    if lpm_json_content.is_none() {
        excluded_paths.push("lpm.json");
    }
    before_tarball_preparation();
    let mut compare_scratch = Vec::new();
    ensure_optional_publish_document_unchanged(
        &package_json_parent,
        Path::new("lpm.config.json"),
        &project_root.join("lpm.config.json"),
        lpm_config_content.as_deref().map(str::as_bytes),
        &mut compare_scratch,
    )?;
    ensure_optional_publish_document_unchanged(
        &package_json_parent,
        Path::new("lpm.json"),
        &project_root.join("lpm.json"),
        lpm_json_content.as_deref().map(str::as_bytes),
        &mut compare_scratch,
    )?;
    let prepared_tarball = publish_common::prepare_tarball_from_source_root(
        &pkg_json,
        publish_common::TarballOptions {
            package_json_content: Some(&prepared_package_json),
            scan_secrets,
            extra_scan_files,
            content_overrides: &content_overrides,
            excluded_paths: &excluded_paths,
            validated_authored_skills: validated_skill_overrides.as_deref(),
        },
        &package_json_parent,
        &project_root,
    )?;
    let tarball_data = std::sync::Arc::new(prepared_tarball.data);
    let tarball_hashes = std::sync::Arc::new(publish_common::compute_hashes(&tarball_data));
    let tarball_size = tarball_data.len();
    let readme = prepared_tarball.readme;
    validate_publish_tarball_size(tarball_size)?;

    let lpm_config = lpm_config_content
        .as_deref()
        .map(parse_validated_lpm_config_metadata)
        .transpose()?;

    let (detected_ecosystem, swift_manifest) =
        detect_publish_ecosystem(&tarball_data, &prepared_tarball.files, lpm_config.as_ref());
    validate_named_project_root(
        &project_root,
        &package_json_parent_identity,
        &package_json_path,
    )?;

    Ok(PublishProject {
        source_dir: package_json_parent,
        pkg_json,
        name,
        version,
        publish_config,
        readme,
        tarball_data,
        tarball_hashes,
        tarball_files: prepared_tarball.files,
        secret_scan: prepared_tarball.secret_scan,
        tarball_size,
        lpm_config,
        detected_ecosystem,
        swift_manifest,
    })
}

fn validate_named_project_root(
    project_root: &Path,
    expected: &same_file::Handle,
    package_json_path: &Path,
) -> Result<(), LpmError> {
    let current = publish_common::open_tarball_source_root(project_root)
        .and_then(|directory| {
            same_file::Handle::from_file(directory.into_std_file()).map_err(LpmError::Io)
        })
        .map_err(|_| publish_project_changed_error(package_json_path))?;
    if &current != expected {
        return Err(publish_project_changed_error(package_json_path));
    }
    Ok(())
}

fn publish_project_changed_error(package_json_path: &Path) -> LpmError {
    LpmError::Registry(format!(
        "{} changed while preparing the publish tarball; retry the command",
        package_json_path.display()
    ))
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

pub(crate) fn read_optional_publish_text(
    source_dir: &cap_std::fs::Dir,
    relative_path: &Path,
    display_path: &Path,
    max_bytes: u64,
) -> Result<Option<String>, LpmError> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match source_dir.open_with(relative_path, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(LpmError::Registry(format!(
                "{} changed or became unsafe while preparing the publish tarball",
                display_path.display()
            )));
        }
    };
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if !metadata.is_file() || publish_common::metadata_is_link_or_reparse(&metadata) {
        return Err(LpmError::Registry(format!(
            "{} changed or became unsafe while preparing the publish tarball",
            display_path.display()
        )));
    }
    let content = lpm_common::read_text_file_capped_from_open_file_with_known_size(
        file.into_std(),
        display_path,
        max_bytes,
        metadata.len(),
    )?;
    Ok(Some(content))
}

fn ensure_optional_publish_document_unchanged(
    source_dir: &cap_std::fs::Dir,
    relative_path: &Path,
    display_path: &Path,
    expected: Option<&[u8]>,
    scratch: &mut Vec<u8>,
) -> Result<(), LpmError> {
    let changed = || {
        LpmError::Registry(format!(
            "{} changed while preparing the publish tarball; retry the command",
            display_path.display()
        ))
    };
    let Some(expected) = expected else {
        return match source_dir.symlink_metadata(relative_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(changed()),
            Err(error) => Err(LpmError::Io(error)),
        };
    };
    if scratch.is_empty() {
        scratch.resize(64 * 1024, 0);
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = source_dir
        .open_with(relative_path, &options)
        .map_err(|_| changed())?;
    let metadata = file.metadata().map_err(|_| changed())?;
    if !metadata.is_file()
        || publish_common::metadata_is_link_or_reparse(&metadata)
        || metadata.len() != expected.len() as u64
    {
        return Err(changed());
    }
    let mut file = file.into_std();
    for expected_chunk in expected.chunks(scratch.len()) {
        let current = &mut scratch[..expected_chunk.len()];
        file.read_exact(current).map_err(|_| changed())?;
        if current != expected_chunk {
            return Err(changed());
        }
    }
    if file.read(&mut scratch[..1]).map_err(|_| changed())? != 0 {
        return Err(changed());
    }
    Ok(())
}

fn read_optional_lpm_config_from_source_root(
    source_dir: &cap_std::fs::Dir,
    path: &Path,
) -> Result<Option<String>, LpmError> {
    let Some(content) = read_optional_publish_text(
        source_dir,
        Path::new("lpm.config.json"),
        path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )?
    else {
        return Ok(None);
    };
    crate::lpm_config::parse_and_validate(path, &content)?;
    Ok(Some(content))
}

fn parse_validated_lpm_config_metadata(content: &str) -> Result<serde_json::Value, LpmError> {
    serde_json::from_str(content).map_err(|error| {
        LpmError::Registry(format!(
            "failed to reparse validated lpm.config.json while preparing publish metadata: {error}"
        ))
    })
}

#[cfg(test)]
pub(super) fn read_optional_lpm_config(
    project_dir: &Path,
) -> Result<Option<serde_json::Value>, LpmError> {
    let canonical_root = project_dir.canonicalize().map_err(LpmError::Io)?;
    let source_dir = publish_common::open_tarball_source_root(&canonical_root)?;
    read_optional_lpm_config_from_source_root(&source_dir, &canonical_root.join("lpm.config.json"))?
        .as_deref()
        .map(parse_validated_lpm_config_metadata)
        .transpose()
}

pub(super) fn detect_publish_ecosystem(
    tarball_data: &[u8],
    tarball_files: &[publish_common::TarballFile],
    lpm_config: Option<&serde_json::Value>,
) -> (String, Option<serde_json::Value>) {
    let mut detected_ecosystem = "js".to_string();
    if let Some(config) = lpm_config
        && let Some(eco) = config.get("ecosystem").and_then(|v| v.as_str())
    {
        detected_ecosystem = eco.to_string();
    }
    if tarball_files
        .iter()
        .any(|file| file.path == "Package.swift")
        && detected_ecosystem == "js"
    {
        detected_ecosystem = "swift".to_string();
    }

    let swift_manifest = if detected_ecosystem == "swift" {
        dump_swift_manifest_from_publish_artifact(tarball_data)
    } else {
        None
    };

    (detected_ecosystem, swift_manifest)
}

fn dump_swift_manifest_from_publish_artifact(tarball_data: &[u8]) -> Option<serde_json::Value> {
    dump_swift_manifest_from_publish_artifact_with_command(
        tarball_data,
        std::ffi::OsStr::new("swift"),
        std::time::Duration::from_secs(30),
        4 * 1024 * 1024,
    )
}

fn dump_swift_manifest_from_publish_artifact_with_command(
    tarball_data: &[u8],
    program: &std::ffi::OsStr,
    timeout: std::time::Duration,
    output_limit: usize,
) -> Option<serde_json::Value> {
    use std::io::Write as _;

    let snapshot = tempfile::tempdir().ok()?;
    let package_root = snapshot.path().join("package");
    std::fs::create_dir(&package_root).ok()?;
    let decoder = flate2::read::GzDecoder::new(tarball_data);
    let archive_limits = lpm_extractor::TarArchiveLimits {
        max_entry_bytes: publish_common::MAX_UNCOMPRESSED_TARBALL_BYTES,
        max_path_depth: publish_common::MAX_PUBLISH_ARCHIVE_PATH_DEPTH,
        ..lpm_extractor::TarArchiveLimits::new(publish_common::MAX_PUBLISH_ARCHIVE_ENTRIES)
    };
    lpm_extractor::visit_tar_archive(decoder, archive_limits, |mut entry| {
        if !entry.header().entry_type().is_file() {
            return Err(LpmError::Registry(
                "Swift publish artifact contains a non-file entry".into(),
            ));
        }
        let path = entry.path();
        let mut components = path.components();
        let Some(std::path::Component::Normal(prefix)) = components.next() else {
            return Err(LpmError::Registry(
                "Swift publish artifact contains an invalid path".into(),
            ));
        };
        if prefix != std::ffi::OsStr::new("package") {
            return Err(LpmError::Registry(
                "Swift publish artifact contains an invalid root".into(),
            ));
        }
        let mut relative = std::path::PathBuf::new();
        for component in components {
            let std::path::Component::Normal(name) = component else {
                return Err(LpmError::Registry(
                    "Swift publish artifact contains an unsafe path".into(),
                ));
            };
            relative.push(name);
        }
        if relative.as_os_str().is_empty() {
            return Err(LpmError::Registry(
                "Swift publish artifact contains an empty path".into(),
            ));
        }
        let output = package_root.join(relative);
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .map_err(LpmError::Io)?;
        std::io::copy(&mut entry, &mut file).map_err(LpmError::Io)?;
        file.flush().map_err(LpmError::Io)?;
        Ok(std::ops::ControlFlow::<()>::Continue(()))
    })
    .ok()?;
    let mut command = std::process::Command::new(program);
    command
        .args(["package", "dump-package"])
        .current_dir(package_root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = lpm_sandbox::spawn_tracked_command(&mut command).ok()?;
    let Some(stdout) = child.stdout.take() else {
        terminate_swift_manifest_child(&mut child);
        return None;
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_swift_manifest_child(&mut child);
        return None;
    };
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stdout_reader = match spawn_bounded_swift_output_reader(
        stdout,
        output_limit,
        Arc::clone(&cancelled),
        "lpm-swift-manifest-stdout",
    ) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_swift_manifest_child(&mut child);
            return None;
        }
    };
    let stderr_reader = match spawn_bounded_swift_output_reader(
        stderr,
        output_limit,
        Arc::clone(&cancelled),
        "lpm-swift-manifest-stderr",
    ) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_swift_manifest_child(&mut child);
            let _ = stdout_reader.join();
            return None;
        }
    };
    let status = crate::commands::rebuild::process_tree::wait_with_timeout_or_cancel(
        child,
        &timeout,
        &cancelled,
        "Swift manifest output exceeded the configured limit",
    );
    let stdout = stdout_reader.join().ok()?.ok()?;
    let stderr = stderr_reader.join().ok()?.ok()?;
    if !status.ok()?.success() || stdout.len() > output_limit || stderr.len() > output_limit {
        return None;
    }
    serde_json::from_slice::<serde_json::Value>(&stdout).ok()
}

fn spawn_bounded_swift_output_reader(
    reader: impl std::io::Read + Send + 'static,
    output_limit: usize,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    thread_name: &str,
) -> std::io::Result<std::thread::JoinHandle<std::io::Result<Vec<u8>>>> {
    let output_limit = u64::try_from(output_limit).unwrap_or(u64::MAX);
    std::thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || {
            let result = lpm_common::read_stream_capped(reader, output_limit);
            if result.is_err() {
                cancelled.store(true, std::sync::atomic::Ordering::Release);
            }
            result
        })
}

fn terminate_swift_manifest_child(child: &mut std::process::Child) {
    crate::commands::rebuild::process_tree::kill_process_tree(child);
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn write_executable(path: &Path, content: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn swift_fixture_tarball() -> Vec<u8> {
        use std::io::Write as _;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let content = b"// swift-tools-version: 6.0\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/Package.swift", content.as_slice())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn write_padded_empty_config(path: &Path, size: usize) {
        let mut content = vec![b' '; size];
        content[0] = b'{';
        content[1] = b'}';
        std::fs::write(path, content).unwrap();
    }

    fn write_publish_fixture(project: &Path, files: &[&str]) {
        std::fs::write(
            project.join("package.json"),
            serde_json::json!({
                "name": "publisher",
                "version": "1.0.0",
                "files": files,
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {};").unwrap();
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

    #[cfg(unix)]
    #[test]
    fn read_publish_manifest_rejects_a_linked_lpm_json() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"publisher","version":"1.0.0"}"#,
        )
        .unwrap();
        let external = root.path().join("external-lpm.json");
        std::fs::write(&external, r#"{"publish":{"registries":["npm"]}}"#).unwrap();
        std::os::unix::fs::symlink(&external, project.join("lpm.json")).unwrap();

        let error = read_publish_manifest(&project)
            .err()
            .expect("linked lpm.json must not be accepted")
            .to_string();

        assert!(
            error.contains("lpm.json") && error.contains("unsafe"),
            "{error}"
        );
    }

    #[test]
    fn selected_publish_project_cannot_be_replaced_before_manifest_open() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let displaced = root.path().join("displaced");
        let replacement = root.path().join("replacement");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"selected","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            replacement.join("package.json"),
            r#"{"name":"replacement","version":"9.9.9"}"#,
        )
        .unwrap();

        let error = read_publish_manifest_with_selection_hook(&project, || {
            std::fs::rename(&project, &displaced).unwrap();
            std::fs::rename(&replacement, &project).unwrap();
        })
        .err()
        .expect("the selected project identity must remain stable")
        .to_string();

        assert!(
            error.contains("changed") && error.contains("retry"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn selected_publish_project_replaced_by_fifo_is_rejected_promptly() {
        use std::os::unix::ffi::OsStrExt as _;

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let displaced = root.path().join("displaced");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"selected","version":"1.0.0"}"#,
        )
        .unwrap();
        let project_for_worker = project.clone();
        let fifo_for_worker = project.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = read_publish_manifest_with_selection_hook(&project_for_worker, || {
                std::fs::rename(&project_for_worker, &displaced).unwrap();
                let path = std::ffi::CString::new(fifo_for_worker.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            })
            .map(|_| ())
            .map_err(|error| error.to_string());
            sender.send(result).unwrap();
        });

        let result = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(result) => result,
            Err(error) => {
                let writer = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&project)
                    .unwrap();
                drop(writer);
                let _ = receiver.recv_timeout(std::time::Duration::from_secs(1));
                worker.join().unwrap();
                panic!("publish root validation blocked on a FIFO: {error}");
            }
        };
        worker.join().unwrap();

        let error = result.expect_err("a FIFO cannot replace the selected publish directory");
        assert!(
            error.contains("changed") && error.contains("retry"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_optional_lpm_config_rejects_a_linked_file() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let external = root.path().join("external-lpm.config.json");
        std::fs::write(&external, r#"{"defaultConfig":{"theme":"private"}}"#).unwrap();
        std::os::unix::fs::symlink(&external, project.join("lpm.config.json")).unwrap();

        let error = read_optional_lpm_config(&project)
            .expect_err("linked lpm.config.json must not be accepted")
            .to_string();

        assert!(
            error.contains("lpm.config.json") && error.contains("unsafe"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_projection_rejects_a_linked_root_manifest() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let project = workspace.join("packages/app");
        std::fs::create_dir_all(&project).unwrap();
        let external_manifest = root.path().join("external-package.json");
        std::fs::write(
            &external_manifest,
            r#"{
                "name":"workspace-root",
                "workspaces":["packages/*"],
                "catalogs":{"default":{"dep":"^1.0.0"}}
            }"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&external_manifest, workspace.join("package.json")).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{
                "name":"app",
                "version":"1.0.0",
                "dependencies":{"dep":"catalog:"}
            }"#,
        )
        .unwrap();
        let manifest = read_publish_manifest(&project).unwrap();

        let error = discover_workspace_for_publish(&project, &manifest)
            .expect_err("linked workspace metadata must not influence publish")
            .to_string();

        assert!(
            error.contains("package.json") && error.contains("safe"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_projection_rejects_a_fifo_root_manifest_promptly() {
        use std::os::unix::ffi::OsStrExt as _;

        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let project = workspace.join("packages/app");
        std::fs::create_dir_all(&project).unwrap();
        let workspace_manifest = workspace.join("package.json");
        let encoded = std::ffi::CString::new(workspace_manifest.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
        std::fs::write(
            project.join("package.json"),
            r#"{
                "name":"app",
                "version":"1.0.0",
                "dependencies":{"dep":"workspace:*"}
            }"#,
        )
        .unwrap();
        let manifest = read_publish_manifest(&project).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = discover_workspace_for_publish(&project, &manifest)
                .map(|_| ())
                .map_err(|error| error.to_string());
            sender.send(result).unwrap();
        });

        let timely = receiver.recv_timeout(std::time::Duration::from_millis(250));
        let completed_without_blocking = timely.is_ok();
        let result = match timely {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let writer = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&workspace_manifest)
                    .unwrap();
                drop(writer);
                receiver.recv().unwrap()
            }
            Err(error) => panic!("workspace discovery worker disconnected: {error}"),
        };
        worker.join().unwrap();

        assert!(
            completed_without_blocking,
            "workspace projection blocked on a FIFO root manifest"
        );
        assert!(
            result.is_err(),
            "a FIFO workspace manifest must be rejected"
        );
    }

    #[test]
    fn ecosystem_detection_ignores_files_missing_from_the_publish_artifact() {
        let (ecosystem, _) = detect_publish_ecosystem(&[], &[], None);

        assert_eq!(ecosystem, "js");
    }

    #[test]
    fn publish_secret_scan_includes_uploaded_lpm_config_metadata() {
        let project = tempfile::tempdir().unwrap();
        let secret = format!("sk_{}_{}", "live", "F".repeat(24));
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"publisher","version":"1.0.0","files":["index.js"]}"#,
        )
        .unwrap();
        std::fs::write(project.path().join("index.js"), "module.exports = {};").unwrap();
        std::fs::write(
            project.path().join("lpm.config.json"),
            serde_json::json!({"defaultConfig":{"token": secret}}).to_string(),
        )
        .unwrap();

        let prepared = prepare_publish_project(project.path(), true).unwrap();
        let scan = prepared
            .secret_scan
            .expect("uploaded lpm.config.json metadata must be scanned");

        assert!(
            scan.matches
                .iter()
                .any(|finding| finding.description.contains("lpm.config.json"))
        );
    }

    #[test]
    fn packaged_lpm_config_bytes_match_the_validated_upload_metadata() {
        use std::io::Read as _;

        let project = tempfile::tempdir().unwrap();
        let original = r#"{"defaultConfig":{"theme":"validated"}}"#;
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"publisher","version":"1.0.0","files":["lpm.config.json"]}"#,
        )
        .unwrap();
        std::fs::write(project.path().join("lpm.config.json"), original).unwrap();
        let prepared = prepare_publish_project(project.path(), false).unwrap();

        let decoder = flate2::read::GzDecoder::new(prepared.tarball_data.as_slice());
        let mut archive = tar::Archive::new(decoder);
        let mut packaged = None;
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap() == Path::new("package/lpm.config.json") {
                let mut content = String::new();
                entry.read_to_string(&mut content).unwrap();
                packaged = Some(content);
                break;
            }
        }

        assert_eq!(
            (packaged.as_deref(), prepared.lpm_config),
            (
                Some(original),
                Some(serde_json::json!({"defaultConfig":{"theme":"validated"}}))
            )
        );
    }

    #[test]
    fn publish_rejects_lpm_config_replaced_after_validation() {
        let project = tempfile::tempdir().unwrap();
        let original = r#"{"defaultConfig":{"theme":"validated"}}"#;
        let replacement = r#"{"defaultConfig":{"theme":"replacement"}}"#;
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"publisher","version":"1.0.0","files":["lpm.config.json"]}"#,
        )
        .unwrap();
        std::fs::write(project.path().join("lpm.config.json"), original).unwrap();
        let manifest = read_publish_manifest(project.path()).unwrap();

        let error = match prepare_publish_project_from_manifest_with_hook(
            manifest,
            None,
            None,
            false,
            || std::fs::write(project.path().join("lpm.config.json"), replacement).unwrap(),
        ) {
            Ok(_) => panic!("replaced lpm.config.json must be rejected"),
            Err(error) => error.to_string(),
        };

        assert!(
            error.contains("lpm.config.json") && error.contains("changed"),
            "{error}"
        );
    }

    #[test]
    fn publish_rejects_lpm_config_mismatch_after_the_first_comparison_chunk() {
        let project = tempfile::tempdir().unwrap();
        let mut original = vec![b' '; 128 * 1024];
        original[0] = b'{';
        original[1] = b'}';
        let mut replacement = original.clone();
        replacement[96 * 1024] = b'\n';
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"publisher","version":"1.0.0","files":["lpm.config.json"]}"#,
        )
        .unwrap();
        std::fs::write(project.path().join("lpm.config.json"), original).unwrap();
        let manifest = read_publish_manifest(project.path()).unwrap();

        let error =
            prepare_publish_project_from_manifest_with_hook(manifest, None, None, false, || {
                std::fs::write(project.path().join("lpm.config.json"), replacement).unwrap()
            })
            .err()
            .expect("a later comparison chunk mismatch must be rejected")
            .to_string();

        assert!(
            error.contains("lpm.config.json") && error.contains("changed"),
            "{error}"
        );
    }

    #[test]
    fn publish_rejects_lpm_config_deleted_after_validation() {
        let project = tempfile::tempdir().unwrap();
        write_publish_fixture(project.path(), &["index.js", "lpm.config.json"]);
        std::fs::write(
            project.path().join("lpm.config.json"),
            r#"{"defaultConfig":{"theme":"validated"}}"#,
        )
        .unwrap();
        let manifest = read_publish_manifest(project.path()).unwrap();

        let error =
            prepare_publish_project_from_manifest_with_hook(manifest, None, None, false, || {
                std::fs::remove_file(project.path().join("lpm.config.json")).unwrap()
            })
            .err()
            .expect("deleting validated lpm.config.json must invalidate preparation")
            .to_string();

        assert!(
            error.contains("lpm.config.json") && error.contains("changed"),
            "{error}"
        );
    }

    #[test]
    fn publish_rejects_lpm_config_created_after_absence_was_observed() {
        let project = tempfile::tempdir().unwrap();
        write_publish_fixture(project.path(), &["index.js", "lpm.config.json"]);
        let manifest = read_publish_manifest(project.path()).unwrap();

        let error =
            prepare_publish_project_from_manifest_with_hook(manifest, None, None, false, || {
                std::fs::write(
                    project.path().join("lpm.config.json"),
                    r#"{"defaultConfig":{"theme":"late"}}"#,
                )
                .unwrap()
            })
            .err()
            .expect("late lpm.config.json creation must invalidate preparation")
            .to_string();

        assert!(
            error.contains("lpm.config.json") && error.contains("changed"),
            "{error}"
        );
    }

    #[test]
    fn publish_rejects_lpm_json_replaced_after_target_selection() {
        let project = tempfile::tempdir().unwrap();
        write_publish_fixture(project.path(), &["index.js", "lpm.json"]);
        std::fs::write(
            project.path().join("lpm.json"),
            r#"{"publish":{"registries":["npm"]}}"#,
        )
        .unwrap();
        let manifest = read_publish_manifest(project.path()).unwrap();

        let error =
            prepare_publish_project_from_manifest_with_hook(manifest, None, None, false, || {
                std::fs::write(
                    project.path().join("lpm.json"),
                    r#"{"publish":{"registries":["lpm"]}}"#,
                )
                .unwrap()
            })
            .err()
            .expect("replacing selected lpm.json must invalidate preparation")
            .to_string();

        assert!(
            error.contains("lpm.json") && error.contains("changed"),
            "{error}"
        );
    }

    #[test]
    fn publish_rejects_lpm_json_deleted_after_target_selection() {
        let project = tempfile::tempdir().unwrap();
        write_publish_fixture(project.path(), &["index.js", "lpm.json"]);
        std::fs::write(
            project.path().join("lpm.json"),
            r#"{"publish":{"registries":["npm"]}}"#,
        )
        .unwrap();
        let manifest = read_publish_manifest(project.path()).unwrap();

        let error =
            prepare_publish_project_from_manifest_with_hook(manifest, None, None, false, || {
                std::fs::remove_file(project.path().join("lpm.json")).unwrap()
            })
            .err()
            .expect("deleting selected lpm.json must invalidate preparation")
            .to_string();

        assert!(
            error.contains("lpm.json") && error.contains("changed"),
            "{error}"
        );
    }

    #[test]
    fn publish_rejects_lpm_json_created_after_absence_was_observed() {
        let project = tempfile::tempdir().unwrap();
        write_publish_fixture(project.path(), &["index.js", "lpm.json"]);
        let manifest = read_publish_manifest(project.path()).unwrap();

        let error =
            prepare_publish_project_from_manifest_with_hook(manifest, None, None, false, || {
                std::fs::write(
                    project.path().join("lpm.json"),
                    r#"{"publish":{"registries":["npm"]}}"#,
                )
                .unwrap()
            })
            .err()
            .expect("late lpm.json creation must invalidate preparation")
            .to_string();

        assert!(
            error.contains("lpm.json") && error.contains("changed"),
            "{error}"
        );
    }

    #[test]
    fn publish_readme_metadata_uses_the_replacement_bytes_that_are_archived() {
        let project = tempfile::tempdir().unwrap();
        write_publish_fixture(project.path(), &["index.js", "README.md"]);
        std::fs::write(project.path().join("README.md"), "selected readme").unwrap();
        let manifest = read_publish_manifest(project.path()).unwrap();

        let prepared =
            prepare_publish_project_from_manifest_with_hook(manifest, None, None, false, || {
                std::fs::write(project.path().join("README.md"), "archived readme").unwrap()
            })
            .unwrap();

        assert_eq!(prepared.readme.as_deref(), Some("archived readme"));
    }

    #[test]
    fn publish_readme_metadata_is_absent_when_the_archive_has_no_readme() {
        let project = tempfile::tempdir().unwrap();
        write_publish_fixture(project.path(), &["index.js", "README.md"]);
        std::fs::write(project.path().join("README.md"), "selected readme").unwrap();
        let manifest = read_publish_manifest(project.path()).unwrap();

        let prepared =
            prepare_publish_project_from_manifest_with_hook(manifest, None, None, false, || {
                std::fs::remove_file(project.path().join("README.md")).unwrap()
            })
            .unwrap();

        assert_eq!(prepared.readme, None);
    }

    #[test]
    fn stage_preparation_rejects_invalid_authored_package_skills() {
        let project = tempfile::tempdir().unwrap();
        write_publish_fixture(project.path(), &["index.js", ".lpm/skills"]);
        std::fs::create_dir_all(project.path().join(".lpm/skills")).unwrap();
        std::fs::write(
            project.path().join(".lpm/skills/invalid.md"),
            "not a valid authored package skill",
        )
        .unwrap();

        let error = prepare_publish_project(project.path(), false)
            .err()
            .expect("stage preparation must validate authored skills")
            .to_string();

        assert!(error.contains("skills validation failed"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn swift_manifest_inspection_rejects_output_over_the_limit() {
        let fixture = swift_fixture_tarball();
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("swift-output");
        write_executable(
            &executable,
            "#!/bin/sh\nprintf '{\"payload\":\"'\nhead -c 1024 /dev/zero | tr '\\000' x\nprintf '\"}'\n",
        );

        let manifest = dump_swift_manifest_from_publish_artifact_with_command(
            &fixture,
            executable.as_os_str(),
            std::time::Duration::from_secs(1),
            128,
        );

        assert!(manifest.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn swift_manifest_inspection_stops_a_stalled_process_at_the_timeout() {
        let fixture = swift_fixture_tarball();
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("swift-timeout");
        write_executable(&executable, "#!/bin/sh\nsleep 2\nprintf '{}'\n");
        let started = std::time::Instant::now();

        let manifest = dump_swift_manifest_from_publish_artifact_with_command(
            &fixture,
            executable.as_os_str(),
            std::time::Duration::from_millis(20),
            128,
        );

        assert!(manifest.is_none());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn swift_manifest_inspection_rejects_deep_archives_before_starting_swift() {
        use std::io::Write as _;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut path = String::from("package/");
            path.push_str(&"a/".repeat(256));
            path.push_str("Package.swift");
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, &path, std::io::empty())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        let archive = encoder.finish().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("swift-marker");
        let marker = directory.path().join("started");
        write_executable(
            &executable,
            &format!("#!/bin/sh\ntouch '{}'\nprintf '{{}}'\n", marker.display()),
        );

        let manifest = dump_swift_manifest_from_publish_artifact_with_command(
            &archive,
            executable.as_os_str(),
            std::time::Duration::from_secs(1),
            128,
        );

        assert!(manifest.is_none());
        assert!(
            !marker.exists(),
            "Swift started for a rejected deep archive"
        );
    }
}
