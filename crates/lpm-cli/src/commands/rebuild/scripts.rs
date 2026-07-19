use super::trust::TrustReason;
use crate::install_ui;
use crate::script_policy_config::ScriptPolicy;
use lpm_security::{EXECUTED_INSTALL_PHASES, SecurityPolicy};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

pub(super) const BUILD_MARKER: &str = ".lpm-built";

pub(super) fn read_lifecycle_scripts(pkg_json_path: &Path) -> Option<HashMap<String, String>> {
    let content = std::fs::read(pkg_json_path).ok()?;

    // Fast byte pre-scan: if "scripts" never appears as a JSON key, the
    // result is always None — skip the full parse.
    const SCRIPTS_KEY: &[u8] = b"\"scripts\"";
    if !content.windows(SCRIPTS_KEY.len()).any(|w| w == SCRIPTS_KEY) {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_slice(&content).ok()?;
    let scripts = parsed.get("scripts")?.as_object()?;

    let mut lifecycle = HashMap::new();
    for phase in EXECUTED_INSTALL_PHASES {
        if let Some(cmd) = scripts
            .get(*phase)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
        {
            lifecycle.insert((*phase).to_string(), cmd.to_string());
        }
    }

    if lifecycle.is_empty() {
        None
    } else {
        Some(lifecycle)
    }
}

pub(super) struct ScriptablePackage {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) source: Option<String>,
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

impl ScriptablePackage {
    pub(super) fn package_key(&self) -> lpm_lockfile::PackageKey {
        let source_id = self
            .source
            .as_deref()
            .and_then(|source| lpm_lockfile::Source::parse(source).ok())
            .map_or_else(
                || lpm_lockfile::PackageKey::UNKNOWN_SOURCE_ID.to_string(),
                |source| source.source_id_with_integrity(self.integrity.as_deref()),
            );
        lpm_lockfile::PackageKey::new(&self.name, &self.version, source_id)
    }
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

pub(crate) type RebuildPackageIdentity = (String, String, Option<String>, Option<String>);

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
    format!("{}@{}", pkg.name, pkg.version)
}

pub(super) fn rebuild_package_failure_message(
    pkg: &ScriptablePackage,
    error: &impl std::fmt::Display,
) -> String {
    format!("{} failed: {error}", rebuild_package_label(pkg))
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

pub(super) fn toposort_packages<'a>(
    packages: Vec<&'a ScriptablePackage>,
    lockfile: &lpm_lockfile::Lockfile,
) -> Vec<&'a ScriptablePackage> {
    if packages.len() <= 1 {
        return packages;
    }

    let package_keys: Vec<lpm_lockfile::PackageKey> = packages
        .iter()
        .map(|package| package.package_key())
        .collect();
    let selected_by_key: HashMap<lpm_lockfile::PackageKey, usize> = package_keys
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, key)| (key, index))
        .collect();
    let locked_by_key: HashMap<lpm_lockfile::PackageKey, &lpm_lockfile::LockedPackage> = lockfile
        .packages
        .iter()
        .map(|package| (package.package_key(), package))
        .collect();

    let mut reference_targets: HashMap<String, Option<lpm_lockfile::PackageKey>> =
        HashMap::with_capacity(lockfile.packages.len());
    for locked in &lockfile.packages {
        let binding = match locked.source_kind() {
            Some(Ok(lpm_lockfile::Source::Registry { .. })) | None => locked.version.clone(),
            Some(Ok(source)) => source.source_id_with_integrity(locked.integrity.as_deref()),
            Some(Err(_)) => continue,
        };
        let mut reference = String::with_capacity(locked.name.len() + binding.len() + 1);
        reference.push_str(&locked.name);
        reference.push('\0');
        reference.push_str(&binding);
        let package_key = locked.package_key();
        match reference_targets.entry(reference) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(package_key));
            }
            std::collections::hash_map::Entry::Occupied(mut entry)
                if entry.get().as_ref() != Some(&package_key) =>
            {
                entry.insert(None);
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
        }
    }

    let mut in_degree = vec![0usize; packages.len()];
    let mut dependents = vec![Vec::<usize>::new(); packages.len()];
    let mut edges = HashSet::new();
    for (consumer_index, consumer_key) in package_keys.iter().enumerate() {
        let Some(locked) = locked_by_key.get(consumer_key) else {
            continue;
        };
        for dependency in &locked.dependencies {
            let Some(at) = dependency.rfind('@') else {
                continue;
            };
            let local = &dependency[..at];
            let binding = &dependency[at + 1..];
            let canonical = locked
                .alias_dependencies
                .iter()
                .find(|alias| alias[0] == local)
                .map_or(local, |alias| alias[1].as_str());
            let mut reference = String::with_capacity(canonical.len() + binding.len() + 1);
            reference.push_str(canonical);
            reference.push('\0');
            reference.push_str(binding);
            let Some(Some(dependency_key)) = reference_targets.get(&reference) else {
                continue;
            };
            let Some(&dependency_index) = selected_by_key.get(dependency_key) else {
                continue;
            };
            if dependency_index != consumer_index
                && edges.insert((dependency_index, consumer_index))
            {
                in_degree[consumer_index] += 1;
                dependents[dependency_index].push(consumer_index);
            }
        }
    }

    let compare_indices = |left: &usize, right: &usize| {
        let left = &package_keys[*left];
        let right = &package_keys[*right];
        left.name
            .cmp(&right.name)
            .then_with(|| left.version.cmp(&right.version))
            .then_with(|| left.source_id.cmp(&right.source_id))
    };
    let mut initial: Vec<usize> = in_degree
        .iter()
        .enumerate()
        .filter_map(|(index, degree)| (*degree == 0).then_some(index))
        .collect();
    initial.sort_by(compare_indices);
    let mut queue: VecDeque<usize> = initial.into();
    let mut sorted = Vec::with_capacity(packages.len());
    let mut emitted = HashSet::with_capacity(packages.len());
    while let Some(index) = queue.pop_front() {
        if !emitted.insert(index) {
            continue;
        }
        sorted.push(packages[index]);
        let mut newly_ready = Vec::new();
        for dependent in &dependents[index] {
            in_degree[*dependent] -= 1;
            if in_degree[*dependent] == 0 {
                newly_ready.push(*dependent);
            }
        }
        newly_ready.sort_by(compare_indices);
        queue.extend(newly_ready);
    }

    let mut remaining: Vec<usize> = (0..packages.len())
        .filter(|index| !emitted.contains(index))
        .collect();
    remaining.sort_by(compare_indices);
    sorted.extend(remaining.into_iter().map(|index| packages[index]));
    sorted
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
        install_ui::warn(&format!(
            "Stale trustedDependencies (no lifecycle scripts): {}",
            stale.join(", ")
        ));
    }
}
