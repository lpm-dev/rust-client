use super::diff_util::{
    MapDiff, btree_from_hash_map, compare_nested_string_maps, compare_option, compare_string_maps,
    nested_btree_from_hash_map,
};
use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum FrozenLockfileMode {
    #[default]
    Auto,
    Always,
    Never,
}

impl FrozenLockfileMode {
    pub(super) fn is_active(self, lockfile_path: &Path) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => lockfile_path.exists() && install_running_in_ci(),
        }
    }
}

pub(crate) fn install_running_in_ci() -> bool {
    crate::install_state::ci_env_is_truthy()
}

pub(super) struct LockfileValidationInput<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) lockfile_path: &'a Path,
    pub(super) package: &'a lpm_workspace::PackageJson,
    pub(super) lpm_overrides: &'a HashMap<String, String>,
    pub(super) overrides: &'a HashMap<String, String>,
    pub(super) resolutions: &'a HashMap<String, String>,
    pub(super) catalogs: &'a HashMap<String, HashMap<String, String>>,
    pub(super) auto_install_peers: bool,
    pub(super) frozen_lockfile_active: bool,
    pub(super) force: bool,
}

pub(super) struct LockfileValidationState {
    pub(super) current_patches: HashMap<String, PatchedDependencyEntry>,
    pub(super) current_patch_fingerprint: String,
    pub(super) current_lockfile_patches: lpm_lockfile::LockfilePatches,
    pub(super) current_importer_snapshot: lpm_lockfile::ImporterSnapshot,
    pub(super) prior_verified_provenance:
        std::collections::BTreeMap<String, lpm_lockfile::LockedProvenance>,
}

fn peer_rules_fingerprint(pkg: &lpm_workspace::PackageJson) -> Option<String> {
    let rules = pkg.lpm.as_ref().map(|lpm| &lpm.peer_dependency_rules)?;
    if rules == &lpm_workspace::PeerDependencyRules::default() {
        return None;
    }
    let bytes = serde_json::to_vec(rules).ok()?;
    use sha2::{Digest, Sha256};
    Some(format!("sha256-{}", hex::encode(Sha256::digest(bytes))))
}

fn importer_snapshot_for_current_manifest(
    pkg: &lpm_workspace::PackageJson,
    lpm_overrides: &HashMap<String, String>,
    overrides: &HashMap<String, String>,
    resolutions: &HashMap<String, String>,
    catalogs: &HashMap<String, HashMap<String, String>>,
    patches_fingerprint: Option<&str>,
    auto_install_peers: bool,
) -> lpm_lockfile::ImporterSnapshot {
    lpm_lockfile::ImporterSnapshot {
        dependencies: btree_from_hash_map(&pkg.dependencies),
        dev_dependencies: btree_from_hash_map(&pkg.dev_dependencies),
        optional_dependencies: btree_from_hash_map(&pkg.optional_dependencies),
        peer_dependencies: btree_from_hash_map(&pkg.peer_dependencies),
        lpm_overrides: btree_from_hash_map(lpm_overrides),
        overrides: btree_from_hash_map(overrides),
        resolutions: btree_from_hash_map(resolutions),
        catalogs: nested_btree_from_hash_map(catalogs),
        patches_fingerprint: patches_fingerprint.map(str::to_string),
        peer_dependency_rules_fingerprint: peer_rules_fingerprint(pkg),
        auto_install_peers: Some(auto_install_peers),
    }
}

pub(super) fn validate_install_lockfile_state(
    input: LockfileValidationInput<'_>,
) -> Result<LockfileValidationState, LpmError> {
    let current_patches: HashMap<String, PatchedDependencyEntry> = input
        .package
        .lpm
        .as_ref()
        .map(|l| l.patched_dependencies.clone())
        .unwrap_or_default();
    let current_patch_fingerprint = patch_state::compute_fingerprint(&current_patches);
    let current_importer_patch_fingerprint =
        (!current_patches.is_empty()).then_some(current_patch_fingerprint.as_str());
    let current_lockfile_patches =
        patch_state::lockfile_patches_from_manifest(input.project_dir, &current_patches)?;
    let current_importer_snapshot = importer_snapshot_for_current_manifest(
        input.package,
        input.lpm_overrides,
        input.overrides,
        input.resolutions,
        input.catalogs,
        current_importer_patch_fingerprint,
        input.auto_install_peers,
    );
    let lockfile_for_validation = if input.lockfile_path.exists() || input.frozen_lockfile_active {
        match lpm_lockfile::Lockfile::read_fast(input.lockfile_path) {
            Ok(lockfile) => Some(lockfile),
            Err(e) if input.frozen_lockfile_active => {
                return Err(LpmError::Registry(format!(
                    "Frozen lockfile mismatch\n  lockfile    {}\n  error       {}\n  hint        run `lpm install` locally and commit lpm.lock before running a frozen install",
                    input.lockfile_path.display(),
                    e,
                )));
            }
            Err(e) if !current_lockfile_patches.is_empty() => {
                return Err(LpmError::Registry(format!(
                    "Patch lockfile mismatch\n  lockfile    {}\n  error       {}\n  hint        run `lpm install` after restoring a readable lpm.lock",
                    input.lockfile_path.display(),
                    e,
                )));
            }
            Err(_) => None,
        }
    } else {
        None
    };
    if let Some(lockfile) = lockfile_for_validation.as_ref() {
        validate_lockfile_patch_records(input.lockfile_path, lockfile, &current_lockfile_patches)?;
    }
    if input.frozen_lockfile_active {
        if input.force {
            return Err(LpmError::Registry(
                "Frozen lockfile mismatch\n  flag        --force\n  hint        frozen installs cannot force fresh resolution; pass --no-frozen-lockfile for a mutable install"
                    .into(),
            ));
        }
        let lockfile = lockfile_for_validation
            .as_ref()
            .expect("frozen lockfile validation loaded lockfile or returned");
        validate_frozen_importer_snapshot(
            input.lockfile_path,
            lockfile,
            &current_importer_snapshot,
        )?;
    }

    let prior_verified_provenance = lockfile_for_validation
        .map(|lockfile| lockfile.provenance)
        .unwrap_or_default();

    Ok(LockfileValidationState {
        current_patches,
        current_patch_fingerprint,
        current_lockfile_patches,
        current_importer_snapshot,
        prior_verified_provenance,
    })
}

fn validate_frozen_importer_snapshot(
    lockfile_path: &Path,
    lockfile: &lpm_lockfile::Lockfile,
    current: &lpm_lockfile::ImporterSnapshot,
) -> Result<(), LpmError> {
    if lockfile.metadata.lockfile_version < lpm_lockfile::LOCKFILE_VERSION {
        return Err(LpmError::Registry(format!(
            "Frozen lockfile mismatch\n  lockfile    {}\n  found       v{}\n  required    v{}\n  hint        run `lpm install` locally and commit lpm.lock before running a frozen install",
            lockfile_path.display(),
            lockfile.metadata.lockfile_version,
            lpm_lockfile::LOCKFILE_VERSION,
        )));
    }
    let locked = lockfile.importers.get(".").ok_or_else(|| {
        LpmError::Registry(format!(
            "Frozen lockfile mismatch\n  lockfile    {}\n  importer    .\n  hint        run `lpm install` locally and commit lpm.lock",
            lockfile_path.display()
        ))
    })?;

    if let Some(diff) = first_importer_snapshot_diff(current, locked) {
        return Err(LpmError::Registry(format!(
            "Frozen lockfile mismatch\n  {}  {}\n  manifest    {}\n  lockfile    {}\n  hint        run `lpm install` locally and commit lpm.lock, or pass --no-frozen-lockfile",
            diff.kind, diff.name, diff.manifest, diff.lockfile,
        )));
    }

    Ok(())
}

fn validate_lockfile_patch_records(
    lockfile_path: &Path,
    lockfile: &lpm_lockfile::Lockfile,
    current: &lpm_lockfile::LockfilePatches,
) -> Result<(), LpmError> {
    if lockfile.patches == *current {
        return Ok(());
    }

    let diff = first_lockfile_patch_diff(current, &lockfile.patches).unwrap_or_else(|| {
        LockfilePatchDiff {
            selector: "<unknown>".to_string(),
            field: "patches",
            current: "<unknown>".to_string(),
            lockfile: "<unknown>".to_string(),
        }
    });
    Err(LpmError::Registry(format!(
        "Patch lockfile mismatch\n  patch       {}\n  field       {}\n  current     {}\n  lockfile    {}\n  file        {}\n  hint        restore the patch file recorded in lpm.lock, or re-run `lpm patch` and `lpm patch-commit`",
        diff.selector,
        diff.field,
        diff.current,
        diff.lockfile,
        lockfile_path.display(),
    )))
}

struct LockfilePatchDiff {
    selector: String,
    field: &'static str,
    current: String,
    lockfile: String,
}

fn first_lockfile_patch_diff(
    current: &lpm_lockfile::LockfilePatches,
    locked: &lpm_lockfile::LockfilePatches,
) -> Option<LockfilePatchDiff> {
    let selectors: BTreeSet<&String> = current.keys().chain(locked.keys()).collect();
    for selector in selectors {
        match (current.get(selector), locked.get(selector)) {
            (Some(current), Some(locked)) => {
                if current.path != locked.path {
                    return Some(LockfilePatchDiff {
                        selector: selector.clone(),
                        field: "path",
                        current: current.path.clone(),
                        lockfile: locked.path.clone(),
                    });
                }
                if current.sha256 != locked.sha256 {
                    return Some(LockfilePatchDiff {
                        selector: selector.clone(),
                        field: "sha256",
                        current: current.sha256.clone(),
                        lockfile: locked.sha256.clone(),
                    });
                }
                if current.original_integrity != locked.original_integrity {
                    return Some(LockfilePatchDiff {
                        selector: selector.clone(),
                        field: "original-integrity",
                        current: current.original_integrity.clone(),
                        lockfile: locked.original_integrity.clone(),
                    });
                }
            }
            (Some(current), None) => {
                return Some(LockfilePatchDiff {
                    selector: selector.clone(),
                    field: "record",
                    current: format!(
                        "{} {} {}",
                        current.path, current.sha256, current.original_integrity
                    ),
                    lockfile: "<absent>".to_string(),
                });
            }
            (None, Some(locked)) => {
                return Some(LockfilePatchDiff {
                    selector: selector.clone(),
                    field: "record",
                    current: "<absent>".to_string(),
                    lockfile: format!(
                        "{} {} {}",
                        locked.path, locked.sha256, locked.original_integrity
                    ),
                });
            }
            (None, None) => {}
        }
    }
    None
}

fn first_importer_snapshot_diff(
    current: &lpm_lockfile::ImporterSnapshot,
    locked: &lpm_lockfile::ImporterSnapshot,
) -> Option<MapDiff> {
    compare_string_maps("dependency", &current.dependencies, &locked.dependencies)
        .or_else(|| {
            compare_string_maps(
                "dev dependency",
                &current.dev_dependencies,
                &locked.dev_dependencies,
            )
        })
        .or_else(|| {
            compare_string_maps(
                "optional dependency",
                &current.optional_dependencies,
                &locked.optional_dependencies,
            )
        })
        .or_else(|| {
            compare_string_maps(
                "peer dependency",
                &current.peer_dependencies,
                &locked.peer_dependencies,
            )
        })
        .or_else(|| {
            compare_string_maps(
                "lpm override",
                &current.lpm_overrides,
                &locked.lpm_overrides,
            )
        })
        .or_else(|| compare_string_maps("override", &current.overrides, &locked.overrides))
        .or_else(|| compare_string_maps("resolution", &current.resolutions, &locked.resolutions))
        .or_else(|| compare_nested_string_maps("catalog", &current.catalogs, &locked.catalogs))
        .or_else(|| {
            compare_option(
                "patches",
                &current.patches_fingerprint,
                &locked.patches_fingerprint,
            )
        })
        .or_else(|| {
            compare_option(
                "peer dependency rules",
                &current.peer_dependency_rules_fingerprint,
                &locked.peer_dependency_rules_fingerprint,
            )
        })
        .or_else(|| {
            let manifest = current.auto_install_peers.map(|value| value.to_string());
            let lockfile = locked.auto_install_peers.map(|value| value.to_string());
            compare_option("auto install peers", &manifest, &lockfile)
        })
}
