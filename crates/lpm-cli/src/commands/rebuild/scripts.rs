use super::trust::TrustReason;
use crate::install_ui;
use crate::script_policy_config::ScriptPolicy;
use lpm_security::{EXECUTED_INSTALL_PHASES, SecurityPolicy};
use lpm_store::{V2BaselineIndex, find_installed_package_baseline_indexed};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::path::Path;

pub(super) const BUILD_MARKER: &str = ".lpm-built";

pub(super) fn package_baseline_dir_indexed(
    index: &V2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
) -> Option<std::path::PathBuf> {
    find_installed_package_baseline_indexed(index, lpm_root, name, version).map(|b| b.package_dir)
}

pub(super) fn read_lifecycle_scripts(
    pkg_json_path: &Path,
) -> Result<Option<HashMap<String, String>>, lpm_common::LpmError> {
    let content =
        lpm_common::read_file_capped(pkg_json_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?;

    // Fast byte pre-scan: if "scripts" never appears as a JSON key, the
    // result is always None — skip the full parse.
    const SCRIPTS_KEY: &[u8] = b"\"scripts\"";
    if !content.windows(SCRIPTS_KEY.len()).any(|w| w == SCRIPTS_KEY) {
        serde_json::from_slice::<serde::de::IgnoredAny>(&content).map_err(|error| {
            lpm_common::LpmError::Store(format!(
                "installed manifest {} is malformed: {error}",
                pkg_json_path.display()
            ))
        })?;
        return Ok(None);
    }

    let parsed: serde_json::Value = serde_json::from_slice(&content).map_err(|error| {
        lpm_common::LpmError::Store(format!(
            "installed manifest {} is malformed: {error}",
            pkg_json_path.display()
        ))
    })?;
    let Some(scripts_value) = parsed.get("scripts") else {
        return Ok(None);
    };
    let scripts = scripts_value.as_object().ok_or_else(|| {
        lpm_common::LpmError::Store(format!(
            "installed manifest {} has a non-object scripts field",
            pkg_json_path.display()
        ))
    })?;

    let mut lifecycle = HashMap::new();
    for phase in EXECUTED_INSTALL_PHASES {
        if let Some(value) = scripts.get(*phase) {
            let cmd = value.as_str().ok_or_else(|| {
                lpm_common::LpmError::Store(format!(
                    "installed manifest {} has a non-string {phase} script",
                    pkg_json_path.display()
                ))
            })?;
            if !cmd.is_empty() {
                lifecycle.insert((*phase).to_string(), cmd.to_string());
            }
        }
    }

    if lifecycle.is_empty() {
        Ok(None)
    } else {
        Ok(Some(lifecycle))
    }
}

pub(super) struct ScriptablePackage {
    pub(super) instance_id: Option<lpm_common::PackageInstanceId>,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) integrity: Option<String>,
    /// Wrapper-id for non-Registry sources. `None` for Registry deps
    /// (canonical CAS-backed wrapper segment shape `<safe>@<version>`);
    /// `Some(wid)` for Tarball / Directory / Link / Git sources
    /// (segment shape `<safe>+<wid>`). Computed once at construction
    /// from [`lpm_lockfile::Source::source_id`] so the rebuild loop's
    /// per-package wrapper lookup matches the linker's segment exactly.
    ///
    /// Previously, the rebuild loop hardcoded
    /// `<safe>@<version>` for every package, silently falling back to
    /// the store path for any non-Registry dep with lifecycle scripts.
    /// Now the lookup is correct for every source kind.
    pub(super) wrapper_id: Option<String>,
    pub(super) store_path: std::path::PathBuf,
    pub(super) pristine_path: std::path::PathBuf,
    pub(super) source_integrity: String,
    pub(super) graph_key_digest: Option<String>,
    pub(super) scripts: HashMap<String, String>,
    pub(super) is_built: bool,
    pub(super) build_marker_key: Option<String>,
    pub(super) is_trusted: bool,
    /// the specific basis on which
    /// `is_trusted` was decided. Preserved so the dry-run output and
    /// the pre-loop summary can surface WHY a script was trusted
    /// (strict binding vs. scope vs. green-tier auto-approval under
    /// triage). `is_trusted` is a direct read of
    /// [`TrustReason::is_trusted`] — the field pair is kept because
    /// most call sites only care about the boolean and splitting the
    /// read avoids threading [`TrustReason`] through downstream code.
    pub(super) trust_reason: TrustReason,
}

#[derive(Debug, Clone, Default)]
pub(super) struct BuildCacheMetrics {
    pub(super) eligible: usize,
    pub(super) hits: usize,
    pub(super) misses: usize,
    pub(super) bypassed: usize,
    pub(super) local_state_hits: usize,
    pub(super) scripts_avoided: usize,
    pub(super) restored_bytes: u64,
    pub(super) lifecycle_ms_avoided: u64,
    pub(super) preparation_ms: u64,
    pub(super) key_ms: u64,
    pub(super) lookup_ms: u64,
    pub(super) restore_ms: u64,
    pub(super) rematerialize_ms: u64,
    pub(super) publish_ms: u64,
}

impl BuildCacheMetrics {
    pub(super) fn merge(&mut self, other: Self) {
        self.eligible += other.eligible;
        self.hits += other.hits;
        self.misses += other.misses;
        self.bypassed += other.bypassed;
        self.local_state_hits += other.local_state_hits;
        self.scripts_avoided += other.scripts_avoided;
        self.restored_bytes += other.restored_bytes;
        self.lifecycle_ms_avoided += other.lifecycle_ms_avoided;
        self.preparation_ms += other.preparation_ms;
        self.key_ms += other.key_ms;
        self.lookup_ms += other.lookup_ms;
        self.restore_ms += other.restore_ms;
        self.rematerialize_ms += other.rematerialize_ms;
        self.publish_ms += other.publish_ms;
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "eligible": self.eligible,
            "hits": self.hits,
            "misses": self.misses,
            "bypassed": self.bypassed,
            "local_state_hits": self.local_state_hits,
            "scripts_avoided": self.scripts_avoided,
            "restored_bytes": self.restored_bytes,
            "lifecycle_ms_avoided": self.lifecycle_ms_avoided,
            "timings_ms": {
                "preparation": self.preparation_ms,
                "key": self.key_ms,
                "lookup": self.lookup_ms,
                "restore": self.restore_ms,
                "rematerialize": self.rematerialize_ms,
                "publish": self.publish_ms,
            }
        })
    }
}

pub(crate) type RebuildPackageIdentity = (String, String, Option<String>);

#[derive(Debug, Clone, Default)]
pub(crate) struct RebuildRunReport {
    pub(crate) covered_packages: Vec<RebuildPackageIdentity>,
    pub(crate) built_packages: Vec<RebuildPackageIdentity>,
}

impl RebuildRunReport {
    pub(crate) fn covered_any_packages(&self) -> bool {
        !self.covered_packages.is_empty()
    }

    pub(crate) fn built_any_packages(&self) -> bool {
        !self.built_packages.is_empty()
    }
}

pub(super) fn rebuild_dry_run_envelope(
    packages: &[&ScriptablePackage],
    force_security_floor: bool,
) -> serde_json::Value {
    let mut json = serde_json::json!({
        "dry_run": true,
        "packages": packages.iter().map(|p| {
            serde_json::json!({
                "name": p.name,
                "version": p.version,
                "scripts": p.scripts,
                "trusted": p.is_trusted,
            })
        }).collect::<Vec<_>>(),
    });
    crate::security_floor::attach_security_posture(&mut json, force_security_floor);
    json
}

pub(super) fn rebuild_summary_envelope(
    successes: usize,
    failures: usize,
    force_security_floor: bool,
    build_cache: &BuildCacheMetrics,
) -> serde_json::Value {
    let mut json = serde_json::json!({
        "success": failures == 0,
        "built": successes,
        "failed": failures,
        "build_cache": build_cache.to_json(),
    });
    crate::security_floor::attach_security_posture(&mut json, force_security_floor);
    json
}

pub(super) fn rebuild_package_label(pkg: &ScriptablePackage) -> String {
    format!(
        "{}@{}",
        lpm_common::sanitize_terminal_inline(&pkg.name),
        lpm_common::sanitize_terminal_inline(&pkg.version)
    )
}

pub(super) fn rebuild_package_failure_message(
    pkg: &ScriptablePackage,
    error: &impl std::fmt::Display,
) -> String {
    let error = error.to_string();
    format!(
        "{} failed: {}",
        rebuild_package_label(pkg),
        lpm_common::sanitize_terminal_inline(&error)
    )
}

pub(super) fn scripts_word(count: usize) -> &'static str {
    if count == 1 { "script" } else { "scripts" }
}

pub(super) fn count_untrusted_unbuilt(scriptable: &[ScriptablePackage], force: bool) -> usize {
    scriptable
        .iter()
        .filter(|p| force || !p.is_built)
        .filter(|p| !p.is_trusted)
        .count()
}

/// Pure selection step for `lpm rebuild`'s default-branch `to_build` set.
///
/// Keeps the policy-aware widening rule outside `rebuild::run`'s I/O
/// path and makes the trust split explicit: `evaluate_trust` handles
/// manifest bindings, scope trust, and triage tiers, while this helper
/// applies the command-level `allow` / `--all` selection semantics.
///
/// Branching rules (+ existing behavior):
///
/// - `all = true` → widen to every scriptable package regardless of
///   trust or policy. `--all` is the explicit escape
///   hatch and keeps that contract.
/// - `effective_policy == ScriptPolicy::Allow` → widen to every
///   scriptable package regardless of `is_trusted`. Allow runs
///   every lifecycle script without the triage gate; the
///   selection step is where that semantic lives.
/// - Else (`Deny` or `Triage` without `--all`) → filter to
///   `is_trusted` only. Under `Triage`, `is_trusted` already
///   reflects the green-tier promotion — so triage widens
///   to greens-plus-strict-plus-scope automatically via the
///   `is_trusted` computation, NOT via this helper. The
///   green-only widening stays gated at [`evaluate_trust`].
///
/// Does NOT apply the `rebuild` / already-built filter — that stays
/// at the call site because it composes with both the specific-
/// package path and this default-branch widening; keeping it
/// separate preserves the existing call shape for `specific_packages`
/// (which warns on missing names, a side effect we don't want
/// leaking into this pure function).
pub(super) fn widen_to_build_by_policy(
    scriptable: &[ScriptablePackage],
    all: bool,
    effective_policy: ScriptPolicy,
) -> Vec<&ScriptablePackage> {
    if all || effective_policy == ScriptPolicy::Allow {
        scriptable.iter().collect()
    } else {
        scriptable.iter().filter(|p| p.is_trusted).collect()
    }
}

#[cfg(test)]
pub(super) fn toposort_packages<'a>(
    packages: Vec<&'a ScriptablePackage>,
    lockfile: &lpm_lockfile::Lockfile,
) -> Vec<&'a ScriptablePackage> {
    package_build_layers(packages, lockfile)
        .into_iter()
        .flatten()
        .collect()
}

pub(super) fn package_build_layers<'a>(
    packages: Vec<&'a ScriptablePackage>,
    lockfile: &lpm_lockfile::Lockfile,
) -> Vec<Vec<&'a ScriptablePackage>> {
    if packages.is_empty() {
        return Vec::new();
    }
    if packages.len() <= 1 {
        return vec![packages];
    }

    let selected_by_instance = packages
        .iter()
        .enumerate()
        .filter_map(|(index, package)| package.instance_id.map(|id| (id, index)))
        .collect::<HashMap<_, _>>();
    let locked_by_instance = lockfile
        .packages
        .iter()
        .filter_map(|package| package.instance_id.map(|id| (id, package)))
        .collect::<HashMap<_, _>>();
    let mut in_degree = vec![0_usize; packages.len()];
    let mut dependents = vec![Vec::<usize>::new(); packages.len()];
    let mut edges = HashSet::new();

    for (consumer_index, package) in packages.iter().enumerate() {
        if let Some(instance_id) = package.instance_id
            && let Some(locked) = locked_by_instance.get(&instance_id)
        {
            for target in locked
                .dependency_targets
                .values()
                .chain(locked.peer_targets.values())
            {
                if let Some(&dependency_index) = selected_by_instance.get(target)
                    && dependency_index != consumer_index
                    && edges.insert((dependency_index, consumer_index))
                {
                    in_degree[consumer_index] += 1;
                    dependents[dependency_index].push(consumer_index);
                }
            }
            continue;
        }

        let Some(locked) = lockfile.packages.iter().find(|candidate| {
            candidate.instance_id.is_none()
                && candidate.name == package.name
                && candidate.version == package.version
                && candidate.integrity == package.integrity
        }) else {
            continue;
        };
        for dependency in locked.dependencies.iter().chain(&locked.peers) {
            let Some((local_name, version)) = dependency.rsplit_once('@') else {
                continue;
            };
            let target_name = locked
                .alias_dependencies
                .iter()
                .find(|alias| alias[0] == local_name)
                .map_or(local_name, |alias| alias[1].as_str());
            for (dependency_index, candidate) in packages.iter().enumerate() {
                if candidate.name == target_name
                    && candidate.version == version
                    && dependency_index != consumer_index
                    && edges.insert((dependency_index, consumer_index))
                {
                    in_degree[consumer_index] += 1;
                    dependents[dependency_index].push(consumer_index);
                }
            }
        }
    }

    let queue_key = |index: usize| {
        let package = packages[index];
        (
            package.name.as_str(),
            package.version.as_str(),
            package.instance_id,
            package.store_path.as_path(),
            index,
        )
    };
    let mut queue = BinaryHeap::new();
    for (index, degree) in in_degree.iter().enumerate() {
        if *degree == 0 {
            queue.push(Reverse(queue_key(index)));
        }
    }
    let mut layers = Vec::new();
    let mut emitted = vec![false; packages.len()];
    while !queue.is_empty() {
        let mut layer = Vec::with_capacity(queue.len());
        while let Some(Reverse((_, _, _, _, index))) = queue.pop() {
            emitted[index] = true;
            layer.push(index);
        }
        for &index in &layer {
            for &dependent in &dependents[index] {
                in_degree[dependent] -= 1;
                if in_degree[dependent] == 0 {
                    queue.push(Reverse(queue_key(dependent)));
                }
            }
        }
        layers.push(layer);
    }

    let mut cyclic = (0..packages.len())
        .filter(|&index| !emitted[index])
        .collect::<Vec<_>>();
    cyclic.sort_unstable_by_key(|&index| queue_key(index));
    layers.extend(cyclic.into_iter().map(|index| vec![index]));
    layers
        .into_iter()
        .map(|layer| layer.into_iter().map(|index| packages[index]).collect())
        .collect()
}

/// Warn if any entries in `trustedDependencies` don't actually have lifecycle scripts.
///
/// `policy.trusted_dependencies` is now a `TrustedDependencies`
/// enum (Legacy | Rich). The iter() method yields `(name, optional binding)`
/// tuples; we only care about the name for the staleness check.
pub(super) fn warn_stale_trusted_deps(
    policy: &SecurityPolicy,
    scriptable_packages: &[ScriptablePackage],
) {
    let scriptable_names: HashSet<&str> = scriptable_packages
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    let mut stale: Vec<String> = policy
        .trusted_dependencies
        .iter()
        .filter_map(|(name, _binding)| {
            if scriptable_names.contains(name.as_str()) {
                None
            } else {
                Some(name)
            }
        })
        .collect();

    if !stale.is_empty() {
        stale.sort();
        install_ui::warn_untrusted(&format!(
            "Stale trustedDependencies (no lifecycle scripts): {}",
            stale.join(", ")
        ));
    }
}
