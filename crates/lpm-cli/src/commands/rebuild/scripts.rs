use super::trust::TrustReason;
use crate::install_ui;
use crate::script_policy_config::ScriptPolicy;
use lpm_security::{EXECUTED_INSTALL_PHASES, SecurityPolicy};
use lpm_store::{V2BaselineIndex, find_installed_package_baseline_indexed};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

pub(super) const BUILD_MARKER: &str = ".lpm-built";

pub(super) fn package_baseline_dir_indexed(
    index: &V2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
    integrity: Option<&str>,
) -> Option<std::path::PathBuf> {
    find_installed_package_baseline_indexed(index, lpm_root, name, version, integrity)
        .map(|b| b.package_dir)
}

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

    // Build a set of names we're building
    let build_set: HashSet<&str> = packages.iter().map(|p| p.name.as_str()).collect();

    // Build adjacency: for each package, which of the other build-set packages depend on it?
    // Edge: dep_name → pkg_name (dep must be built before pkg)
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for name in &build_set {
        in_degree.insert(name, 0);
    }

    for lp in &lockfile.packages {
        if !build_set.contains(lp.name.as_str()) {
            continue;
        }
        for dep_ref in &lp.dependencies {
            if let Some(at) = dep_ref.rfind('@') {
                let dep_name = &dep_ref[..at];
                if build_set.contains(dep_name) {
                    // lp.name depends on dep_name → dep_name must come first
                    *in_degree.entry(lp.name.as_str()).or_insert(0) += 1;
                    dependents
                        .entry(dep_name)
                        .or_default()
                        .push(lp.name.as_str());
                }
            }
        }
    }

    // Kahn's algorithm
    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(&name, _)| name)
        .collect();

    // Sort the initial queue for deterministic output
    let mut q_vec: Vec<&str> = queue.drain(..).collect();
    q_vec.sort();
    queue.extend(q_vec);

    let mut sorted_names: Vec<&str> = Vec::with_capacity(packages.len());

    while let Some(name) = queue.pop_front() {
        sorted_names.push(name);
        if let Some(deps) = dependents.get(name) {
            for &dep in deps {
                if let Some(deg) = in_degree.get_mut(dep) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(dep);
                    }
                }
            }
        }
    }

    // Any remaining packages (cycles or not in lockfile) — append at the end
    for name in &build_set {
        if !sorted_names.contains(name) {
            sorted_names.push(name);
        }
    }

    // Map sorted names back to package references
    let pkg_by_name: HashMap<&str, &ScriptablePackage> =
        packages.iter().map(|p| (p.name.as_str(), *p)).collect();

    sorted_names
        .iter()
        .filter_map(|name| pkg_by_name.get(name).copied())
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
        install_ui::warn(&format!(
            "Stale trustedDependencies (no lifecycle scripts): {}",
            stale.join(", ")
        ));
    }
}
