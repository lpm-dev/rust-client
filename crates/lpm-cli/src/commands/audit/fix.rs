use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use lpm_common::{LpmError, PackageName};
use lpm_registry::{PackageMetadata, RegistryClient, VersionMetadata};
use lpm_resolver::{NpmRange, NpmVersion};
use lpm_semver::Version;

use crate::install_ui;
use crate::npm_public_source::{
    LockfileRootIndex, NpmMetadataSource, locked_package_npm_metadata_source,
};

use super::discovery::{self, ManagerKind};
use super::lpm_dependencies::{DependencyAdvisory, LpmDependencyAdvisories};
use super::osv::{OsvVulnerability, run_osv_scan};

#[derive(Debug, Clone)]
struct AuditFixDirectDep {
    local_name: String,
    target_name: String,
    current_range: String,
    dependency_key: &'static str,
    is_dev: bool,
    is_optional: bool,
    unsupported_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct AuditFixPlan {
    name: String,
    target_name: String,
    from: String,
    to: String,
    current_range: String,
    new_range: String,
    dependency_key: &'static str,
    is_dev: bool,
    is_optional: bool,
    vulnerability_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct AuditFixSkipped {
    name: String,
    reason: String,
}

pub async fn run_fix(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    dry_run: bool,
) -> Result<(), LpmError> {
    run_fix_inner(client, project_dir, json_output, dry_run).await
}

async fn run_fix_inner(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    dry_run: bool,
) -> Result<(), LpmError> {
    let started_at = std::time::Instant::now();
    let pkg_json_path = project_dir.join("package.json");
    let original_content = match lpm_common::read_file_capped(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Err(LpmError::NotFound("no package.json found".into()));
        }
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read package.json: {error}"
            )));
        }
    };
    let mut doc: serde_json::Value =
        serde_json::from_slice(lpm_common::strip_utf8_bom_bytes(&original_content))
            .map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?;

    let discovery = discovery::discover_packages_retaining_lpm_lockfile(project_dir)?;
    if discovery.manager != ManagerKind::Lpm {
        return Err(LpmError::Script(format!(
            "`lpm audit fix` currently supports LPM-managed projects only (found {} inventory). \
             Run the native package manager's audit fix for this project, or migrate to LPM first.",
            discovery.manager,
        )));
    }

    if discovery.packages.is_empty() {
        emit_audit_fix_report(&[], &[], dry_run, json_output, started_at.elapsed());
        return Ok(());
    }

    let osv_outcome = run_osv_scan(&discovery.packages, true, None).await;
    if let Some(reason) = osv_outcome.degraded_reason {
        return Err(LpmError::Script(format!(
            "`lpm audit fix` cannot safely choose patched versions because the OSV scan degraded: {reason}"
        )));
    }
    let lockfile = discovery.lpm_lockfile.as_ref().ok_or_else(|| {
        LpmError::Script("audit fix discovery did not retain its LPM lockfile snapshot".into())
    })?;
    let lockfile_content = discovery.lpm_lockfile_content.as_ref().ok_or_else(|| {
        LpmError::Script("audit fix discovery did not retain its LPM lockfile bytes".into())
    })?;
    let retained_lockfile_path = discovery.lockfile_path.as_ref().ok_or_else(|| {
        LpmError::Script("audit fix discovery did not retain its LPM lockfile path".into())
    })?;

    let mut vulns_by_instance: HashMap<(String, String), Vec<&OsvVulnerability>> = HashMap::new();
    for vuln in &osv_outcome.vulns {
        vulns_by_instance
            .entry((vuln.package.clone(), vuln.version.clone()))
            .or_default()
            .push(vuln);
    }

    let lpm_advisories = LpmDependencyAdvisories::new(&discovery.packages, &osv_outcome.vulns);
    let mut dependency_metadata = DependencyCache::new();
    // A workspace member installs with the workspace's lockfile kept; a
    // single project's is removed first, so its install resolves afresh.
    let keeps_lockfile = discovery.workspace_root.is_some();

    let mut planned = Vec::new();
    let mut skipped = Vec::new();
    let root_index = LockfileRootIndex::new(Some(lockfile));
    for dep in audit_fix_direct_deps_from_value(&doc) {
        let target_name = dep.target_name.as_str();
        let locked_package = match select_installed_direct_locked_package(
            project_dir,
            lockfile,
            &root_index,
            &dep.local_name,
            target_name,
        ) {
            Ok(package) => package,
            Err(reason) => {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason,
                });
                continue;
            }
        };
        let installed_version = &locked_package.version;
        let is_lpm_package = target_name.starts_with("@lpm.dev/");
        let lpm_dependency_advisories = if is_lpm_package {
            let advisories = lpm_advisories.of(locked_package);
            if advisories.is_empty() {
                continue;
            }
            advisories
        } else {
            &[]
        };
        let npm_vulns = if is_lpm_package {
            None
        } else {
            let Some(vulns) =
                vulns_by_instance.get(&(target_name.to_string(), installed_version.clone()))
            else {
                continue;
            };
            Some(vulns)
        };
        // Before any request: a dependency the fixer can't rewrite discloses
        // nothing, a local package's name included.
        if let Some(reason) = dep.unsupported_reason.clone() {
            skipped.push(AuditFixSkipped {
                name: dep.local_name,
                reason,
            });
            continue;
        }

        let npm_source = if is_lpm_package {
            None
        } else {
            match locked_package_npm_metadata_source(locked_package, client) {
                Some(source) => Some(source),
                None => {
                    skipped.push(AuditFixSkipped {
                        name: dep.local_name,
                        reason: "lockfile source is not public npm or the configured LPM registry; refusing to disclose the name to npm metadata endpoints".into(),
                    });
                    continue;
                }
            }
        };

        let metadata = match fetch_audit_fix_metadata(client, target_name, npm_source).await {
            Ok(metadata) => metadata,
            Err(err) => {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason: format!("metadata lookup failed: {err}"),
                });
                continue;
            }
        };
        if let Some(installed) = metadata.version(installed_version)
            && let Err(error) = super::registry::validate_registry_version(
                target_name,
                installed_version,
                installed,
            )
        {
            skipped.push(AuditFixSkipped {
                name: dep.local_name,
                reason: error.to_string(),
            });
            continue;
        }

        let (target, vulnerability_ids) = if is_lpm_package {
            if metadata.version(installed_version).is_none() {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason: format!(
                        "registry metadata omitted installed version {target_name}@{installed_version}"
                    ),
                });
                continue;
            }
            match choose_lpm_audit_fix_target(
                client,
                lockfile,
                target_name,
                installed_version,
                &metadata,
                lpm_dependency_advisories,
                &mut dependency_metadata,
                keeps_lockfile,
            )
            .await
            {
                Ok(target) => (target, advisory_ids(lpm_dependency_advisories)),
                Err(reason) => {
                    skipped.push(AuditFixSkipped {
                        name: dep.local_name,
                        reason,
                    });
                    continue;
                }
            }
        } else {
            let vulns = npm_vulns.expect("set for npm packages");
            match choose_audit_fix_target(target_name, installed_version, &metadata, vulns) {
                Ok(target) => (
                    target,
                    vulns
                        .iter()
                        .map(|vulnerability| vulnerability.id.clone())
                        .collect(),
                ),
                Err(reason) => {
                    skipped.push(AuditFixSkipped {
                        name: dep.local_name,
                        reason,
                    });
                    continue;
                }
            }
        };
        let new_range = match audit_fix_range_for_target(&dep.current_range, &target) {
            Ok(range) => range,
            Err(reason) => {
                skipped.push(AuditFixSkipped {
                    name: dep.local_name,
                    reason,
                });
                continue;
            }
        };
        planned.push(AuditFixPlan {
            name: dep.local_name,
            target_name: target_name.to_string(),
            from: installed_version.clone(),
            to: target.clone(),
            current_range: dep.current_range.clone(),
            new_range,
            dependency_key: dep.dependency_key,
            is_dev: dep.is_dev,
            is_optional: dep.is_optional,
            vulnerability_ids,
        });
    }

    planned.sort_by(|a, b| a.name.cmp(&b.name));
    skipped.sort_by(|a, b| a.name.cmp(&b.name));

    if planned.is_empty() || dry_run {
        emit_audit_fix_report(
            &planned,
            &skipped,
            dry_run,
            json_output,
            started_at.elapsed(),
        );
        return audit_fix_completion(&skipped);
    }

    let project_dirs = [project_dir.to_path_buf()];
    let fix_result =
        crate::commands::install::workspace_lockfile::scope_workspace_mutation_if_present(
            project_dir,
            &project_dirs,
            async {
                let lockfile_path =
                    crate::commands::install::workspace_lockfile::active_lockfile_path(project_dir);
                if lockfile_path != *retained_lockfile_path {
                    return Err(LpmError::Script(
                        "the active lpm.lock changed while audit fixes were being planned; no changes were applied"
                            .to_string(),
                    ));
                }
                let lockfile_binary_path = lockfile_path.with_extension("lockb");
                let install_hash_path = project_dir.join(".lpm").join("install-hash");
                maybe_test_pause_before_transaction_snapshot();
                let transaction =
                    crate::manifest_tx::ManifestTransaction::snapshot_install_state_if_unchanged(
                        &[
                            (pkg_json_path.as_path(), original_content.as_slice()),
                            (lockfile_path.as_path(), lockfile_content.as_ref()),
                        ],
                        &[lockfile_binary_path.as_path()],
                        &[install_hash_path.as_path()],
                    )
                    .map_err(|error| {
                        LpmError::Script(format!(
                            "package.json or lpm.lock changed while audit fix was planning; no changes were applied: {error}"
                        ))
                    })?;

                apply_audit_fixes_to_manifest(&mut doc, &planned)?;
                let updated_content = serde_json::to_string_pretty(&doc).map_err(|e| {
                    LpmError::Script(format!("failed to serialize package.json: {e}"))
                })?;
                lpm_common::write_file_atomic(&pkg_json_path, format!("{updated_content}\n"))
                    .map_err(LpmError::Io)?;

                if !crate::commands::install::workspace_lockfile::mutation_active() {
                    audit_fix_remove_optional_file(&lockfile_path)?;
                    audit_fix_remove_optional_file(&lockfile_binary_path)?;
                }

                if let Err(error) =
                    crate::commands::install::run_silent_for_audit_fix(client, project_dir).await
                {
                    if !json_output {
                        install_ui::warn("install failed — restored original package.json");
                    }
                    return Err(error);
                }
                verify_audit_fixes(client, project_dir, &planned).await?;
                crate::commands::install::workspace_lockfile::commit_manifest_transaction(
                    transaction,
                );
                Ok(())
            },
        )
        .await;

    fix_result?;

    emit_audit_fix_report(
        &planned,
        &skipped,
        dry_run,
        json_output,
        started_at.elapsed(),
    );
    audit_fix_completion(&skipped)
}

fn maybe_test_pause_before_transaction_snapshot() {
    if !cfg!(debug_assertions) {
        return;
    }
    let Ok(marker) = std::env::var("LPM_TEST_PAUSE_BEFORE_AUDIT_FIX_SNAPSHOT") else {
        return;
    };
    let marker = PathBuf::from(marker);
    std::fs::write(&marker, b"ready").expect("write audit-fix snapshot test marker");
    let resume = marker.with_extension("resume");
    for _ in 0..1_000 {
        if resume.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for audit-fix snapshot test resume marker {}",
        resume.display()
    );
}

fn audit_fix_completion(skipped: &[AuditFixSkipped]) -> Result<(), LpmError> {
    if skipped.is_empty() {
        Ok(())
    } else {
        Err(LpmError::ExitCode(1))
    }
}

fn select_installed_direct_locked_package<'a>(
    project_dir: &Path,
    lockfile: &'a lpm_lockfile::Lockfile,
    root_index: &LockfileRootIndex<'a>,
    local_name: &str,
    target_name: &str,
) -> Result<&'a lpm_lockfile::LockedPackage, String> {
    let manifest_path = installed_direct_manifest_path(project_dir, local_name)?;
    let content = lpm_common::read_text_file_capped_nofollow(
        &manifest_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| {
        format!(
            "cannot read installed direct dependency {}: {error}",
            manifest_path.display()
        )
    })?;
    let manifest: serde_json::Value =
        serde_json::from_str(lpm_common::strip_utf8_bom_str(&content)).map_err(|error| {
            format!(
                "installed direct dependency {} has invalid package.json: {error}",
                manifest_path.display()
            )
        })?;
    let installed_name = manifest
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!(
                "installed direct dependency {} is missing its package name",
                manifest_path.display()
            )
        })?;
    if installed_name != target_name {
        return Err(format!(
            "installed direct dependency '{local_name}' resolves to '{installed_name}', expected '{target_name}'"
        ));
    }
    let installed_version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!(
                "installed direct dependency {} is missing its version",
                manifest_path.display()
            )
        })?;

    if lockfile
        .root_resolutions
        .get(local_name)
        .is_some_and(|root| root.instance_id.is_some())
    {
        let selected = root_index.root_package(local_name, target_name).ok_or_else(|| {
            format!("installed direct dependency '{local_name}' has no matching exact root in lpm.lock")
        })?;
        if selected.version != installed_version || selected.name != installed_name {
            return Err(format!(
                "installed direct dependency {target_name}@{installed_version} does not match its exact lpm.lock root"
            ));
        }
        return Ok(selected);
    }

    let start = lockfile
        .packages
        .partition_point(|package| package.name.as_str() < target_name);
    let end = start
        + lockfile.packages[start..]
            .partition_point(|package| package.name.as_str() == target_name);
    let mut matches = lockfile.packages[start..end]
        .iter()
        .filter(|package| package.version == installed_version);
    let Some(installed) = matches.next() else {
        return Err(format!(
            "installed direct dependency {target_name}@{installed_version} is not present in lpm.lock"
        ));
    };
    if matches.next().is_some() {
        return Err(format!(
            "installed direct dependency {target_name}@{installed_version} has ambiguous lockfile instances from multiple sources"
        ));
    }
    Ok(installed)
}

fn installed_direct_manifest_path(project_dir: &Path, local_name: &str) -> Result<PathBuf, String> {
    if local_name.contains('\\') {
        return Err(format!(
            "dependency name '{local_name}' is not safe to resolve on disk"
        ));
    }
    let parts: Vec<&str> = local_name.split('/').collect();
    let valid_part = |part: &str| !part.is_empty() && part != "." && part != "..";
    let valid = match parts.as_slice() {
        [name] => valid_part(name) && !name.starts_with('@'),
        [scope, name] => {
            scope.starts_with('@')
                && scope.len() > 1
                && valid_part(scope)
                && valid_part(name)
                && !name.starts_with('@')
        }
        _ => false,
    };
    if !valid {
        return Err(format!(
            "dependency name '{local_name}' is not safe to resolve on disk"
        ));
    }

    let mut path = project_dir.to_path_buf();
    path.push("node_modules");
    for part in parts {
        path.push(part);
    }
    path.push("package.json");
    Ok(path)
}

fn audit_fix_direct_deps_from_value(doc: &serde_json::Value) -> Vec<AuditFixDirectDep> {
    let mut deps = Vec::new();
    let mut seen = HashSet::new();
    for (key, is_dev, is_optional) in [
        ("optionalDependencies", false, true),
        ("dependencies", false, false),
        ("devDependencies", true, false),
    ] {
        if let Some(obj) = doc.get(key).and_then(|value| value.as_object()) {
            deps.reserve(obj.len());
            for (name, range) in obj {
                let Some(range) = range.as_str() else {
                    continue;
                };
                if !seen.insert(name.clone()) {
                    continue;
                }
                let (target_name, unsupported_reason) = match lpm_resolver::Specifier::parse(range)
                {
                    Ok(lpm_resolver::Specifier::SemverRange(_)) => (name.clone(), None),
                    Ok(lpm_resolver::Specifier::NpmAlias { target, .. })
                        if range.starts_with("npm:") =>
                    {
                        (target, None)
                    }
                    Ok(_) | Err(_) => (
                        name.clone(),
                        Some(format!(
                            "dependency specifier '{range}' cannot be updated automatically without changing its source protocol"
                        )),
                    ),
                };
                deps.push(AuditFixDirectDep {
                    local_name: name.clone(),
                    target_name,
                    current_range: range.to_string(),
                    dependency_key: key,
                    is_dev,
                    is_optional,
                    unsupported_reason,
                });
            }
        }
    }
    deps
}

async fn fetch_audit_fix_metadata(
    client: &RegistryClient,
    name: &str,
    npm_source: Option<NpmMetadataSource>,
) -> Result<PackageMetadata, LpmError> {
    if name.starts_with("@lpm.dev/") {
        let package_name = PackageName::parse(name)
            .map_err(|err| LpmError::Script(format!("invalid LPM package name '{name}': {err}")))?;
        client.get_package_metadata(&package_name).await
    } else {
        match npm_source {
            Some(NpmMetadataSource::PublicNpm) => client.get_npm_package_metadata(name).await,
            Some(NpmMetadataSource::ConfiguredRegistry) => {
                client.get_npm_package_metadata_proxy_only(name).await
            }
            None => Err(LpmError::Script(format!(
                "missing npm metadata source for '{name}'"
            ))),
        }
    }
}

fn choose_audit_fix_target(
    package: &str,
    installed_version: &str,
    metadata: &PackageMetadata,
    vulns: &[&OsvVulnerability],
) -> Result<String, String> {
    let installed = Version::parse(installed_version)
        .map_err(|error| format!("installed version '{installed_version}' is invalid: {error}"))?;
    let mut candidates: Vec<Version> = metadata
        .versions
        .keys()
        .filter_map(|version| Version::parse(version).ok())
        .filter(|version| !version.is_prerelease())
        .filter(|version| version > &installed)
        .collect();
    candidates.sort();
    for candidate in candidates {
        let candidate_text = candidate.to_string();
        let version = metadata.version(&candidate_text).ok_or_else(|| {
            format!("registry metadata omitted canonical candidate {package}@{candidate_text}")
        })?;
        super::registry::validate_registry_version(package, &candidate_text, version)
            .map_err(|error| error.to_string())?;
        let mut safe = true;
        for vulnerability in vulns {
            match vulnerability.affects_version(&candidate_text) {
                Ok(false) => {}
                Ok(true) => {
                    safe = false;
                    break;
                }
                Err(reason) => return Err(reason),
            }
        }
        if safe {
            return Ok(candidate_text);
        }
    }
    Err(format!(
        "registry has no verified non-vulnerable version of '{package}' newer than {installed_version}"
    ))
}

/// A dependency's npm metadata, with its versions parsed once as the
/// resolver parses them.
struct DependencyVersions {
    metadata: PackageMetadata,
    /// Every version that parses, newest first.
    versions: Vec<NpmVersion>,
    /// The `latest` tag, when it names a published version.
    latest: Option<NpmVersion>,
}

impl DependencyVersions {
    fn new(metadata: PackageMetadata) -> Self {
        let mut versions: Vec<NpmVersion> = metadata
            .versions
            .keys()
            .filter_map(|version| NpmVersion::parse(version).ok())
            .collect();
        versions.sort_unstable_by(|left, right| right.cmp(left));
        let latest = metadata
            .dist_tags
            .get("latest")
            .filter(|latest| metadata.versions.contains_key(latest.as_str()))
            .and_then(|latest| NpmVersion::parse(latest).ok());
        Self {
            metadata,
            versions,
            latest,
        }
    }
}

/// A range as the resolver reads it against one dependency's dist-tags: a
/// dist-tag range allows only its tagged version, and `latest` the stable
/// versions up to the tag.
struct InstallRange {
    range: NpmRange,
    tagged: Option<NpmVersion>,
}

impl InstallRange {
    fn new(dependency: &DependencyVersions, raw: &str) -> Option<Self> {
        let range = NpmRange::parse_registry_spec(raw).ok()?;
        let tagged = match range.dist_tag() {
            Some("latest") => dependency.latest.clone(),
            Some(tag) => dependency
                .metadata
                .dist_tags
                .get(tag)
                .and_then(|version| NpmVersion::parse(version).ok()),
            None => None,
        };
        Some(Self { range, tagged })
    }

    fn allows(&self, version: &NpmVersion) -> bool {
        self.range
            .satisfies_with_dist_tag(version, self.tagged.as_ref())
    }

    fn prefers_latest(&self) -> bool {
        self.range.dist_tag().is_none_or(|tag| tag == "latest")
    }
}

/// The dependencies' metadata read so far, by name and by the source their
/// lockfile entries name.
type DependencyCache = HashMap<(String, NpmMetadataSource), DependencyVersions>;

/// The first release of an LPM package newer than the installed one that
/// leaves every advisory on the installed release's npm dependencies: each
/// range it gives an affected package resolves, as `lpm audit fix`'s install
/// resolves it, outside every advisory, or it no longer depends on that
/// package. Verification then asks OSV about the installed tree again.
#[allow(clippy::too_many_arguments)]
async fn choose_lpm_audit_fix_target(
    client: &RegistryClient,
    lockfile: &lpm_lockfile::Lockfile,
    package: &str,
    installed_version: &str,
    metadata: &PackageMetadata,
    advisories: &[DependencyAdvisory<'_>],
    cache: &mut DependencyCache,
    keeps_lockfile: bool,
) -> Result<String, String> {
    let installed = Version::parse(installed_version)
        .map_err(|error| format!("installed version '{installed_version}' is invalid: {error}"))?;
    let mut candidates: Vec<Version> = metadata
        .versions
        .keys()
        .filter_map(|version| Version::parse(version).ok())
        .filter(|version| !version.is_prerelease() && version > &installed)
        .collect();
    candidates.sort();

    let mut by_dependency: BTreeMap<&str, Vec<&DependencyAdvisory<'_>>> = BTreeMap::new();
    for advisory in advisories {
        by_dependency
            .entry(advisory.dependency)
            .or_default()
            .push(advisory);
    }

    'candidates: for candidate in candidates {
        let candidate = candidate.to_string();
        let Some(release) = metadata.version(&candidate) else {
            continue;
        };
        super::registry::validate_registry_version(package, &candidate, release)
            .map_err(|error| error.to_string())?;
        for (dependency, dependency_advisories) in &by_dependency {
            let ranges = declared_ranges(release, dependency);
            if ranges.is_empty() {
                continue;
            }
            let installed_versions: BTreeSet<&str> = dependency_advisories
                .iter()
                .map(|advisory| advisory.version)
                .collect();
            let versions = locked_dependency_versions(
                client,
                lockfile,
                dependency,
                &installed_versions,
                cache,
            )
            .await?;
            let kept: Vec<&str> = if keeps_lockfile {
                installed_versions.iter().copied().collect()
            } else {
                Vec::new()
            };
            if !installs_no_affected_version(
                &ranges,
                versions,
                &locked_versions(lockfile, dependency),
                &kept,
                dependency_advisories,
            )? {
                continue 'candidates;
            }
        }
        return Ok(candidate);
    }
    Err(format!(
        "registry has no verified non-vulnerable version of '{package}' newer than {installed_version}"
    ))
}

/// How a release depends on a package: it installs it, or it takes the
/// version the tree provides as a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Dependency,
    Peer { optional: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeclaredRange {
    range: String,
    slot: Slot,
}

/// Every range `release` gives `dependency`: under its own name and under
/// each npm alias of it, in `dependencies`, `optionalDependencies`, whose
/// entry replaces a `dependencies` entry of the same name as npm's does, and
/// `peerDependencies`. Empty when it no longer depends on it.
fn declared_ranges(release: &VersionMetadata, dependency: &str) -> Vec<DeclaredRange> {
    let names = |key: &str, spec: &str| match lpm_resolver::ranges::parse_npm_alias(spec) {
        Some(alias) => (alias.target == dependency).then_some(alias.range),
        None => (key == dependency).then(|| spec.to_string()),
    };
    let installed = release
        .dependencies
        .iter()
        .filter(|(key, _)| !release.optional_dependencies.contains_key(*key))
        .chain(&release.optional_dependencies)
        .filter_map(|(key, spec)| names(key, spec))
        .map(|range| DeclaredRange {
            range,
            slot: Slot::Dependency,
        });
    let peers = release.peer_dependencies.iter().filter_map(|(key, spec)| {
        names(key, spec).map(|range| DeclaredRange {
            range,
            slot: Slot::Peer {
                optional: release
                    .peer_dependencies_meta
                    .get(key)
                    .is_some_and(|meta| meta.optional),
            },
        })
    });
    let mut ranges: Vec<DeclaredRange> = installed.chain(peers).collect();
    ranges.sort_unstable();
    ranges.dedup();
    ranges
}

/// The version an install picks for `range`, as the resolver picks it: a
/// version the kept lockfile holds that the range allows; the `latest` tag
/// when it satisfies the range; or else the newest version it allows.
fn version_an_install_picks(
    dependency: &DependencyVersions,
    range: &str,
    kept: &[&str],
) -> Option<String> {
    let range = InstallRange::new(dependency, range)?;
    if let Some(locked) = kept
        .iter()
        .filter_map(|version| NpmVersion::parse(version).ok())
        .filter(|version| range.allows(version))
        .max()
    {
        return Some(locked.to_string());
    }
    if range.prefers_latest()
        && let Some(latest) = dependency
            .latest
            .as_ref()
            .filter(|latest| range.allows(latest))
    {
        return Some(latest.to_string());
    }
    dependency
        .versions
        .iter()
        .find(|version| range.allows(version))
        .map(ToString::to_string)
}

/// Whether every version `ranges` can install of a dependency is outside
/// every advisory on it. A peer takes a version the tree already holds when
/// its range allows one, as the resolver binds it, so each of those counts;
/// otherwise the install adds one, except for an optional peer.
fn installs_no_affected_version(
    ranges: &[DeclaredRange],
    dependency: &DependencyVersions,
    in_tree: &BTreeSet<&str>,
    kept: &[&str],
    advisories: &[&DependencyAdvisory<'_>],
) -> Result<bool, String> {
    for declared in ranges {
        let bound: Vec<String> = match declared.slot {
            Slot::Dependency => Vec::new(),
            Slot::Peer { .. } => match InstallRange::new(dependency, &declared.range) {
                Some(range) => in_tree
                    .iter()
                    .filter(|version| {
                        NpmVersion::parse(version).is_ok_and(|version| range.allows(&version))
                    })
                    .map(|version| (*version).to_string())
                    .collect(),
                None => return Ok(false),
            },
        };
        let installs = if !bound.is_empty() {
            bound
        } else if declared.slot == (Slot::Peer { optional: true }) {
            continue;
        } else {
            match version_an_install_picks(dependency, &declared.range, kept) {
                Some(picked) => vec![picked],
                None => return Ok(false),
            }
        };
        for version in &installs {
            for advisory in advisories {
                if advisory.vulnerability.affects_version(version)? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// Every version of `dependency` the lockfile installs, wherever in the tree.
fn locked_versions<'a>(
    lockfile: &'a lpm_lockfile::Lockfile,
    dependency: &str,
) -> BTreeSet<&'a str> {
    let start = lockfile
        .packages
        .partition_point(|locked| locked.name.as_str() < dependency);
    lockfile.packages[start..]
        .iter()
        .take_while(|locked| locked.name == dependency)
        .map(|locked| locked.version.as_str())
        .collect()
}

/// The source every locked instance of `dependency` at `versions` came
/// from. Instances that disagree, or one from a source that is neither
/// public npm nor the configured registry, are refused, so the name is never
/// disclosed elsewhere and no other source's metadata decides.
fn dependency_metadata_source(
    dependency: &str,
    sources: impl IntoIterator<Item = Option<NpmMetadataSource>>,
) -> Result<NpmMetadataSource, String> {
    let mut chosen = None;
    for source in sources {
        let Some(source) = source else {
            return Err(format!(
                "lockfile source of dependency {dependency} is not public npm or the configured LPM registry; refusing to disclose the name to npm metadata endpoints"
            ));
        };
        match chosen {
            None => chosen = Some(source),
            Some(earlier) if earlier == source => {}
            Some(_) => {
                return Err(format!(
                    "dependency {dependency} is installed from more than one registry; refusing to choose one"
                ));
            }
        }
    }
    chosen.ok_or_else(|| format!("lpm.lock has no entry for dependency {dependency}"))
}

/// The npm metadata of an installed dependency, read once per name and
/// source, from the source its lockfile entries name.
async fn locked_dependency_versions<'cache>(
    client: &RegistryClient,
    lockfile: &lpm_lockfile::Lockfile,
    dependency: &str,
    versions: &BTreeSet<&str>,
    cache: &'cache mut DependencyCache,
) -> Result<&'cache DependencyVersions, String> {
    let start = lockfile
        .packages
        .partition_point(|locked| locked.name.as_str() < dependency);
    let source = dependency_metadata_source(
        dependency,
        lockfile.packages[start..]
            .iter()
            .take_while(|locked| locked.name == dependency)
            .filter(|locked| versions.contains(locked.version.as_str()))
            .map(|locked| locked_package_npm_metadata_source(locked, client)),
    )?;
    let key = (dependency.to_string(), source);
    if !cache.contains_key(&key) {
        let metadata = fetch_audit_fix_metadata(client, dependency, Some(source))
            .await
            .map_err(|error| {
                format!("metadata lookup for dependency {dependency} failed: {error}")
            })?;
        cache.insert(key.clone(), DependencyVersions::new(metadata));
    }
    Ok(&cache[&key])
}

fn advisory_ids(advisories: &[DependencyAdvisory<'_>]) -> Vec<String> {
    advisories
        .iter()
        .map(|advisory| advisory.vulnerability.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn audit_fix_range_for_target(current_range: &str, target: &str) -> Result<String, String> {
    if current_range.starts_with("catalog:") {
        return Err(format!(
            "dependency specifier '{current_range}' cannot be updated automatically without changing its source protocol"
        ));
    }
    match lpm_resolver::Specifier::parse(current_range) {
        Ok(lpm_resolver::Specifier::SemverRange(_)) => update_semver_range(current_range, target),
        Ok(lpm_resolver::Specifier::NpmAlias {
            target: alias_target,
            range,
        }) if current_range.starts_with("npm:") => Ok(format!(
            "npm:{alias_target}@{}",
            update_semver_range(&range, target)?
        )),
        Ok(_) | Err(_) => Err(format!(
            "dependency specifier '{current_range}' cannot be updated automatically without changing its source protocol"
        )),
    }
}

fn update_semver_range(_current_range: &str, target: &str) -> Result<String, String> {
    Version::parse(target)
        .map_err(|error| format!("candidate version '{target}' is invalid: {error}"))?;
    Ok(target.to_string())
}

fn apply_audit_fixes_to_manifest(
    doc: &mut serde_json::Value,
    fixes: &[AuditFixPlan],
) -> Result<(), LpmError> {
    for fix in fixes {
        let dep_key = fix.dependency_key;
        let deps = doc
            .get_mut(dep_key)
            .and_then(|value| value.as_object_mut())
            .ok_or_else(|| {
                LpmError::Script(format!(
                    "package.json is missing `{dep_key}` while fixing {}",
                    fix.name
                ))
            })?;
        match deps.get_mut(&fix.name) {
            Some(serde_json::Value::String(current)) => {
                if current != &fix.current_range {
                    return Err(LpmError::Script(format!(
                        "package.json drifted before audit fix could write {}: expected `{}`, found `{}`",
                        fix.name, fix.current_range, current
                    )));
                }
                *current = fix.new_range.clone();
            }
            _ => {
                return Err(LpmError::Script(format!(
                    "package.json is missing string dependency entry `{}` in `{dep_key}`",
                    fix.name
                )));
            }
        }
        if fix.is_optional
            && let Some(serde_json::Value::String(duplicate_range)) = doc
                .get_mut("dependencies")
                .and_then(|value| value.as_object_mut())
                .and_then(|dependencies| dependencies.get_mut(&fix.name))
        {
            *duplicate_range =
                audit_fix_range_for_target(duplicate_range, &fix.to).map_err(LpmError::Script)?;
        }
    }
    Ok(())
}

async fn verify_audit_fixes(
    client: &RegistryClient,
    project_dir: &Path,
    fixes: &[AuditFixPlan],
) -> Result<(), LpmError> {
    let lockfile = crate::commands::install::workspace_lockfile::read_project(project_dir)
        .map_err(|error| LpmError::Script(format!("failed to verify updated lpm.lock: {error}")))?;
    let root_index = LockfileRootIndex::new(Some(&lockfile));

    let mut installed_fixes = Vec::with_capacity(fixes.len());
    for fix in fixes.iter() {
        let installed = select_installed_direct_locked_package(
            project_dir,
            &lockfile,
            &root_index,
            &fix.name,
            &fix.target_name,
        )
        .map_err(|reason| {
            LpmError::Script(format!(
                "audit fix verification could not identify direct dependency {}: {reason}",
                fix.name
            ))
        })?;
        if installed.version != fix.to {
            return Err(LpmError::Script(format!(
                "audit fix verification expected {} at planned version {}, found {}",
                fix.name, fix.to, installed.version
            )));
        }
        installed_fixes.push((fix, installed));
    }

    let discovery = discovery::discover_packages(project_dir)?;
    let osv_outcome = run_osv_scan(&discovery.packages, true, None).await;
    if let Some(reason) = osv_outcome.degraded_reason {
        return Err(LpmError::Script(format!(
            "audit fix verification could not query OSV: {reason}"
        )));
    }
    let remaining_osv: HashSet<(&str, &str)> = osv_outcome
        .vulns
        .iter()
        .map(|vulnerability| {
            (
                vulnerability.package.as_str(),
                vulnerability.version.as_str(),
            )
        })
        .collect();
    let lpm_advisories = LpmDependencyAdvisories::new(&discovery.packages, &osv_outcome.vulns);

    for (fix, installed) in installed_fixes {
        if fix.target_name.starts_with("@lpm.dev/") {
            let name = PackageName::parse(&fix.target_name)?;
            let metadata = client.refetch_package_metadata(&name).await?;
            let version = metadata.version(&fix.to).ok_or_else(|| {
                LpmError::Script(format!(
                    "audit fix verification metadata omitted {}@{}",
                    fix.target_name, fix.to
                ))
            })?;
            super::registry::validate_registry_version(&fix.target_name, &fix.to, version)?;
            let remaining = lpm_advisories.of(installed);
            if !remaining.is_empty() {
                let found = remaining
                    .iter()
                    .map(|advisory| {
                        format!(
                            "{} in {}@{}",
                            advisory.vulnerability.id, advisory.dependency, advisory.version
                        )
                    })
                    .collect::<Vec<_>>();
                return Err(LpmError::Script(format!(
                    "audit fix verification found {}@{} still installs a vulnerable dependency: {}",
                    fix.target_name,
                    fix.to,
                    found.join(", ")
                )));
            }
        } else if remaining_osv.contains(&(fix.target_name.as_str(), fix.to.as_str())) {
            return Err(LpmError::Script(format!(
                "audit fix verification found {}@{} still vulnerable according to OSV",
                fix.target_name, fix.to
            )));
        }
    }
    Ok(())
}

fn emit_audit_fix_report(
    fixes: &[AuditFixPlan],
    skipped: &[AuditFixSkipped],
    dry_run: bool,
    json_output: bool,
    elapsed: std::time::Duration,
) {
    if json_output {
        let packages: Vec<_> = fixes
            .iter()
            .map(|fix| {
                serde_json::json!({
                    "name": fix.name,
                    "from": fix.from,
                    "to": fix.to,
                    "current_range": fix.current_range,
                    "new_range": fix.new_range,
                    "is_dev": fix.is_dev,
                    "is_optional": fix.is_optional,
                    "vulnerabilities": fix.vulnerability_ids,
                })
            })
            .collect();
        let skipped_json: Vec<_> = skipped
            .iter()
            .map(|skip| serde_json::json!({"name": skip.name, "reason": skip.reason}))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": skipped.is_empty(),
                "dry_run": dry_run,
                "fixed": if dry_run { 0 } else { fixes.len() },
                "planned": fixes.len(),
                "packages": packages,
                "skipped": skipped_json,
                "elapsed_ms": elapsed.as_millis(),
            }))
            .unwrap()
        );
        return;
    }

    if fixes.is_empty() {
        if skipped.is_empty() {
            install_ui::done("No OSV vulnerabilities found in direct dependencies");
        } else {
            install_ui::warn("No direct dependency fixes could be applied");
            for skip in skipped {
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "  {} {}",
                    install_ui::bold(&skip.name),
                    install_ui::dim(&skip.reason),
                ));
            }
        }
        return;
    }

    let verb = if dry_run { "Would fix" } else { "Fixed" };
    install_ui::done_line(crate::install_ui::terminal_line!(
        "{} {} vulnerable direct {} in {}",
        verb,
        fixes.len(),
        install_ui::packages_word(fixes.len()),
        install_ui::format_duration(elapsed),
    ));
    for fix in fixes {
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {} {} {}  {}",
            install_ui::bold(&fix.name),
            install_ui::dim(&fix.from),
            install_ui::dim("→"),
            install_ui::yellow(&fix.to),
            install_ui::dim(&fix.vulnerability_ids.join(", ")),
        ));
    }
    if !skipped.is_empty() {
        install_ui::warn_untrusted(&format!(
            "{} direct {} could not be evaluated or fixed automatically",
            skipped.len(),
            install_ui::packages_word(skipped.len()),
        ));
    }
}

fn audit_fix_remove_optional_file(path: &Path) -> Result<(), LpmError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(LpmError::Script(format!(
            "failed to remove {}: {err}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(
        dependencies: &[(&str, &str)],
        optional: &[(&str, &str)],
        peers: &[(&str, &str)],
    ) -> VersionMetadata {
        let specs = |entries: &[(&str, &str)]| {
            entries
                .iter()
                .map(|(name, spec)| (name.to_string(), spec.to_string()))
                .collect()
        };
        VersionMetadata {
            dependencies: specs(dependencies),
            optional_dependencies: specs(optional),
            peer_dependencies: specs(peers),
            ..Default::default()
        }
    }

    fn dependency(latest: &str, versions: &[&str], tags: &[(&str, &str)]) -> DependencyVersions {
        let mut dist_tags = serde_json::Map::new();
        dist_tags.insert("latest".into(), latest.into());
        for (tag, version) in tags {
            dist_tags.insert((*tag).into(), (*version).into());
        }
        let documents: serde_json::Map<String, serde_json::Value> = versions
            .iter()
            .map(|version| {
                (
                    version.to_string(),
                    serde_json::json!({ "name": "dep", "version": version }),
                )
            })
            .collect();
        let metadata: PackageMetadata = serde_json::from_value(serde_json::json!({
            "name": "dep",
            "dist-tags": dist_tags,
            "versions": documents
        }))
        .unwrap();
        DependencyVersions::new(metadata)
    }

    /// Each range `release` gives `dependency`, with how it takes it.
    fn ranges_of(release: &VersionMetadata, dependency: &str) -> Vec<(String, &'static str)> {
        declared_ranges(release, dependency)
            .into_iter()
            .map(|declared| {
                let slot = match declared.slot {
                    Slot::Dependency => "dependency",
                    Slot::Peer { optional: false } => "peer",
                    Slot::Peer { optional: true } => "optional peer",
                };
                (declared.range, slot)
            })
            .collect()
    }

    fn installed(range: &str) -> (String, &'static str) {
        (range.to_string(), "dependency")
    }

    #[test]
    fn declared_ranges_follow_names_aliases_and_peers_and_report_a_dropped_dependency() {
        let direct = release(&[("lodash", "^4.17.21")], &[], &[]);
        assert_eq!(ranges_of(&direct, "lodash"), [installed("^4.17.21")]);

        let aliased = release(&[("lo", "npm:lodash@~4.17.21")], &[], &[]);
        assert_eq!(ranges_of(&aliased, "lodash"), [installed("~4.17.21")]);

        let scoped = release(&[("node", "npm:@types/node@20")], &[], &[]);
        assert_eq!(ranges_of(&scoped, "@types/node"), [installed("20")]);

        let renamed = release(&[("lodash", "npm:lodash-es@4")], &[], &[]);
        assert!(declared_ranges(&renamed, "lodash").is_empty());

        let mut peer = release(&[], &[], &[("react", ">=18"), ("vue", "^3")]);
        peer.peer_dependencies_meta.insert(
            "vue".into(),
            lpm_registry::PeerDependencyMeta { optional: true },
        );
        assert_eq!(ranges_of(&peer, "react"), [(">=18".to_string(), "peer")]);
        assert_eq!(
            ranges_of(&peer, "vue"),
            [("^3".to_string(), "optional peer")]
        );

        assert!(declared_ranges(&release(&[], &[], &[]), "lodash").is_empty());
    }

    #[test]
    fn declared_ranges_list_every_slot_that_installs_the_dependency() {
        let both = release(&[("dep", "1.0.1"), ("bad", "npm:dep@1.0.0")], &[], &[]);
        assert_eq!(
            ranges_of(&both, "dep"),
            [installed("1.0.0"), installed("1.0.1")]
        );
    }

    #[test]
    fn an_optional_entry_replaces_the_dependency_entry_of_the_same_name() {
        let overridden = release(&[("dep", "1.0.1")], &[("dep", "1.0.0")], &[]);
        assert_eq!(ranges_of(&overridden, "dep"), [installed("1.0.0")]);
    }

    #[test]
    fn a_malformed_alias_target_is_no_range_and_no_panic() {
        let malformed = release(&[("x", "npm:é@1"), ("y", "npm:")], &[], &[]);
        assert!(declared_ranges(&malformed, "dep").is_empty());
        assert_eq!(ranges_of(&malformed, "é"), [installed("1")]);
    }

    #[test]
    fn an_install_prefers_latest_then_the_newest_satisfying_version() {
        let dep = dependency("1.2.0", &["1.0.0", "1.1.0", "1.2.0", "2.0.0"], &[]);
        let picks = |range| version_an_install_picks(&dep, range, &[]);
        assert_eq!(picks("^1.0.0").as_deref(), Some("1.2.0"));
        assert_eq!(picks("^2.0.0").as_deref(), Some("2.0.0"));
        assert_eq!(picks("~1.1.0").as_deref(), Some("1.1.0"));
        assert_eq!(picks("").as_deref(), Some("1.2.0"));
        assert_eq!(picks("^3.0.0"), None);
        assert_eq!(picks("git+https://x"), None);
    }

    #[test]
    fn an_install_resolves_a_dist_tag_range() {
        let dep = dependency(
            "1.2.0",
            &["1.2.0", "2.0.0-beta.1"],
            &[("next", "2.0.0-beta.1")],
        );
        assert_eq!(
            version_an_install_picks(&dep, "next", &[]).as_deref(),
            Some("2.0.0-beta.1")
        );
    }

    #[test]
    fn a_latest_range_installs_the_newest_stable_version_up_to_the_tag() {
        let dep = dependency(
            "2.0.0-beta.1",
            &["1.0.0", "2.0.0-beta.1"],
            &[("next", "2.0.0-beta.1")],
        );
        let picks = |range| version_an_install_picks(&dep, range, &[]);
        assert_eq!(picks("latest").as_deref(), Some("1.0.0"));
        assert_eq!(picks("*").as_deref(), Some("1.0.0"));
        assert_eq!(picks("next").as_deref(), Some("2.0.0-beta.1"));
        assert_eq!(
            picks("1.x || >=2.0.0-beta.0").as_deref(),
            Some("2.0.0-beta.1")
        );
    }

    #[test]
    fn a_peer_takes_a_version_the_tree_holds_before_the_install_adds_one() {
        let dep = dependency("1.0.1", &["1.0.0", "1.0.1"], &[]);
        let advisory_on = OsvVulnerability::for_test("dep", "1.0.0", "GHSA-dep").fixed_in("1.0.1");
        let advisory = DependencyAdvisory {
            dependency: "dep",
            version: "1.0.0",
            vulnerability: &advisory_on,
        };
        let check = |ranges: &[DeclaredRange], in_tree: &[&'static str]| {
            installs_no_affected_version(
                ranges,
                &dep,
                &in_tree.iter().copied().collect(),
                &[],
                &[&advisory],
            )
            .unwrap()
        };
        let peer = |range: &str, optional| DeclaredRange {
            range: range.into(),
            slot: Slot::Peer { optional },
        };
        let dependency_on = |range: &str| DeclaredRange {
            range: range.into(),
            slot: Slot::Dependency,
        };

        assert!(check(&[dependency_on("*")], &["1.0.0"]));
        assert!(!check(&[peer("*", false)], &["1.0.0"]));
        assert!(!check(&[peer("*", false)], &["1.0.0", "1.0.1"]));
        assert!(check(&[peer(">=1.0.1", false)], &["1.0.0"]));
        assert!(check(&[peer("*", false)], &[]));
        assert!(!check(&[peer("1.0.0", false)], &[]));
        assert!(check(&[peer("1.0.0", true)], &[]));
        assert!(!check(
            &[dependency_on("1.0.1"), dependency_on("1.0.0")],
            &[]
        ));
    }

    #[test]
    fn an_install_with_its_lockfile_kept_keeps_a_locked_version_the_range_allows() {
        let dep = dependency("1.0.1", &["1.0.0", "1.0.1"], &[]);
        assert_eq!(
            version_an_install_picks(&dep, "^1.0.0", &["1.0.0"]).as_deref(),
            Some("1.0.0")
        );
        assert_eq!(
            version_an_install_picks(&dep, "^1.0.1", &["1.0.0"]).as_deref(),
            Some("1.0.1")
        );
    }

    #[test]
    fn dependency_metadata_comes_from_one_source_every_instance_agrees_on() {
        use NpmMetadataSource::{ConfiguredRegistry, PublicNpm};
        assert_eq!(
            dependency_metadata_source("dep", [Some(PublicNpm), Some(PublicNpm)]),
            Ok(PublicNpm)
        );
        assert!(
            dependency_metadata_source("dep", [Some(PublicNpm), Some(ConfiguredRegistry)])
                .unwrap_err()
                .contains("more than one registry")
        );
        assert!(
            dependency_metadata_source("dep", [Some(PublicNpm), None])
                .unwrap_err()
                .contains("refusing to disclose")
        );
        assert!(
            dependency_metadata_source("dep", [])
                .unwrap_err()
                .contains("no entry")
        );
    }

    #[test]
    fn audit_fix_range_pins_npm_alias_to_planned_target() {
        assert_eq!(
            audit_fix_range_for_target("npm:lodash@^4.17.0", "4.17.21").unwrap(),
            "npm:lodash@4.17.21"
        );
    }

    #[test]
    fn audit_fix_range_refuses_non_registry_source_protocol_rewrites() {
        for specifier in [
            "catalog:",
            "workspace:^",
            "file:../local-package",
            "git+https://github.com/example/package.git",
            "jsr:@scope/package@^1.0.0",
        ] {
            let error = audit_fix_range_for_target(specifier, "4.17.21").unwrap_err();
            assert!(
                error.contains("source protocol"),
                "unexpected error for {specifier}: {error}"
            );
        }
    }

    #[test]
    fn direct_dependency_inventory_applies_optional_precedence() {
        let document = serde_json::json!({
            "dependencies": {"shared": "1.0.0"},
            "optionalDependencies": {"shared": "1.0.1", "optional": "2.0.0"},
            "devDependencies": {"dev": "3.0.0"}
        });
        let dependencies = audit_fix_direct_deps_from_value(&document);
        assert_eq!(dependencies.len(), 3);
        let shared = dependencies
            .iter()
            .find(|dependency| dependency.local_name == "shared")
            .unwrap();
        assert_eq!(shared.current_range, "1.0.1");
        assert_eq!(shared.dependency_key, "optionalDependencies");
        assert!(shared.is_optional);
    }
}
