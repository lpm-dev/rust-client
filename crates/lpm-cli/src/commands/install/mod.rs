use crate::install_ui;
use crate::output;
use crate::overrides_state;
use crate::patch_engine;
use crate::patch_state;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle}; // kept for concurrent download progress bar
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_linker::{LinkResult, LinkTarget, MaterializedPackage};
use lpm_registry::{GateDecision, RegistryClient, RouteTable, UpstreamRoute, evaluate_cached_url};
use lpm_resolver::{
    CachedPackageInfo, CanonicalKey, CompiledPeerRules, OverrideHit, OverrideSet,
    PeerConflictReport, PeerWarning, ResolvedPackage, SpeculativePackageMetadata,
    check_unmet_peers,
};
use lpm_store::PackageStore;
use lpm_workspace::PatchedDependencyEntry;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::Semaphore;

mod catalog;
mod fetch;
mod fetch_overlap;
mod gitignore;
mod installer_spike;
mod lifecycle;
mod linking;
mod lockfile;
mod manifest;
mod package;
mod patches;
mod peer;
mod skills;
mod source_resolution;
mod state;
mod swift;
#[cfg(test)]
mod tests;
mod timing;
mod workspace;

use catalog::*;
use fetch::*;
use fetch_overlap::*;
use gitignore::*;
pub use gitignore::{
    ensure_lpm_hoisted_gitignore, ensure_lpm_wrappers_gitignore, ensure_skills_gitignore,
};
use lifecycle::*;
use linking::*;
use lockfile::*;
pub(crate) use lockfile::{
    requested_range_for_locked_lookup, select_locked_package_for_requested_spec,
};
#[cfg(test)]
pub(crate) use manifest::finalize_packages_in_manifest;
use manifest::*;
#[cfg(test)]
pub(crate) use manifest::{StagedKind, stage_packages_to_manifest};
pub use manifest::{run_add_packages, run_install_filtered_add};
use package::*;
use patches::*;
use peer::*;
use skills::*;
use source_resolution::*;
use state::*;
use swift::*;
use timing::*;
pub(crate) use workspace::confirm_multi_member_mutation;
use workspace::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InstallOmitPolicy {
    pub dev: bool,
    pub optional: bool,
}

fn publish_ages_from_resolved_metadata(
    packages: &[InstallPackage],
) -> HashMap<(String, String), u64> {
    let mut map = HashMap::with_capacity(packages.len());
    for package in packages {
        if let Some(age) = lpm_security::publish_age_secs(package.registry_published_at.as_deref())
        {
            map.insert((package.name.clone(), package.version.clone()), age);
        }
    }
    map
}

fn release_age_policy_applies_to_install_package(
    policy: crate::release_age_config::ReleaseAgePolicy,
    package: &InstallPackage,
) -> bool {
    policy.is_strict() || package.is_direct
}

fn direct_release_age_canonicals(deps: &HashMap<String, String>) -> Vec<CanonicalKey> {
    let mut canonicals: Vec<CanonicalKey> = deps
        .iter()
        .map(|(name, range)| {
            lpm_resolver::ranges::parse_npm_alias(range).map_or_else(
                || CanonicalKey::from_dep_name(name),
                |alias| CanonicalKey::from_dep_name(&alias.target),
            )
        })
        .collect();
    canonicals.sort_by_key(ToString::to_string);
    canonicals.dedup();
    canonicals
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum FrozenLockfileMode {
    #[default]
    Auto,
    Always,
    Never,
}

impl FrozenLockfileMode {
    fn is_active(self, lockfile_path: &Path) -> bool {
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

const V2_CACHE_CHECK_MAX_CONCURRENCY: usize = 16;
const V2_LINK_TASK_MAX_CONCURRENCY: usize = 16;

fn v2_cache_check_concurrency(candidate_count: usize) -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(4);
    parallelism
        .clamp(1, V2_CACHE_CHECK_MAX_CONCURRENCY)
        .min(candidate_count.max(1))
}

fn v2_link_task_concurrency(target_count: usize) -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(4);
    parallelism
        .clamp(1, V2_LINK_TASK_MAX_CONCURRENCY)
        .min(target_count.max(1))
}

fn timing_detail_start(enabled: bool) -> Option<Instant> {
    enabled.then(Instant::now)
}

fn record_timing_detail_ms(bucket: &mut u128, start: Option<Instant>) {
    if let Some(start) = start {
        *bucket = bucket.saturating_add(start.elapsed().as_millis());
    }
}

struct V2ReusablePrevalidation {
    hits: HashMap<String, lpm_store::v2::ReusableObject>,
    candidate_count: usize,
    concurrency: usize,
    validation_timings: V2ReusableValidationTimings,
}

struct V2LinkTaskResult {
    materialized: MaterializedPackage,
    freshly_populated: bool,
    ms: u128,
}

type V2LinkHandle = tokio::task::JoinHandle<Result<V2LinkTaskResult, LpmError>>;

fn spawn_v2_link_task(
    plan: std::sync::Arc<lpm_linker::v2::LinkPlanV2>,
    target: lpm_linker::v2::V2Target,
    store: std::sync::Arc<lpm_store::v2::Store>,
    semaphore: Arc<Semaphore>,
) -> V2LinkHandle {
    tokio::spawn(async move {
        let _permit = semaphore
            .acquire_owned()
            .await
            .map_err(|_| LpmError::Registry("v2 link semaphore closed".into()))?;
        tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            let (materialized, freshly_populated) =
                lpm_linker::v2::link_v2_one(&plan, &target, &store)?;
            Ok(V2LinkTaskResult {
                materialized,
                freshly_populated,
                ms: start.elapsed().as_millis(),
            })
        })
        .await
        .map_err(|e| LpmError::Registry(format!("v2 link task panicked: {e}")))?
    })
}

async fn prevalidate_v2_reusable_objects(
    packages: &[InstallPackage],
    store_v2: Arc<lpm_store::v2::Store>,
) -> Result<V2ReusablePrevalidation, LpmError> {
    let candidates: Vec<(String, String)> = packages
        .iter()
        .filter(|package| {
            !matches!(
                package.source_kind(),
                Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
            )
        })
        .filter_map(|package| {
            Some((
                install_pkg_key(package),
                package.integrity.as_ref()?.clone(),
            ))
        })
        .collect();

    if candidates.is_empty() {
        return Ok(V2ReusablePrevalidation {
            hits: HashMap::new(),
            candidate_count: 0,
            concurrency: 0,
            validation_timings: V2ReusableValidationTimings::default(),
        });
    }

    let candidate_count = candidates.len();
    let concurrency = v2_cache_check_concurrency(candidate_count);
    let mut checks = futures::stream::iter(candidates.into_iter().map(|(key, sri)| {
        let store_v2 = Arc::clone(&store_v2);
        tokio::task::spawn_blocking(move || {
            store_v2
                .reusable_object_with_timings(&sri)
                .map(|(hit, timings)| (key, hit, timings))
        })
    }))
    .buffer_unordered(concurrency);

    let mut hits = HashMap::with_capacity(candidate_count);
    let mut validation_timings = V2ReusableValidationTimings::default();
    while let Some(result) = checks.next().await {
        let (key, hit, timings) = result
            .map_err(|e| LpmError::Registry(format!("v2 cache check task panicked: {e}")))??;
        validation_timings.record(timings, hit.is_some());
        if let Some(hit) = hit {
            hits.insert(key, hit);
        }
    }
    Ok(V2ReusablePrevalidation {
        hits,
        candidate_count,
        concurrency,
        validation_timings,
    })
}

fn btree_from_hash_map(map: &HashMap<String, String>) -> BTreeMap<String, String> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn nested_btree_from_hash_map(
    map: &HashMap<String, HashMap<String, String>>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    map.iter()
        .map(|(key, value)| (key.clone(), btree_from_hash_map(value)))
        .collect()
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
            "Frozen lockfile mismatch\n  lockfile    {}\n  importer    .\n  hint        run `lpm install` locally and commit the v5 lpm.lock",
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

struct ImporterSnapshotDiff {
    kind: &'static str,
    name: String,
    manifest: String,
    lockfile: String,
}

fn first_importer_snapshot_diff(
    current: &lpm_lockfile::ImporterSnapshot,
    locked: &lpm_lockfile::ImporterSnapshot,
) -> Option<ImporterSnapshotDiff> {
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

fn compare_string_maps(
    kind: &'static str,
    current: &BTreeMap<String, String>,
    locked: &BTreeMap<String, String>,
) -> Option<ImporterSnapshotDiff> {
    let keys: BTreeSet<&String> = current.keys().chain(locked.keys()).collect();
    for key in keys {
        if current.get(key) != locked.get(key) {
            return Some(ImporterSnapshotDiff {
                kind,
                name: key.clone(),
                manifest: current
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| "<absent>".to_string()),
                lockfile: locked
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| "<absent>".to_string()),
            });
        }
    }
    None
}

fn compare_nested_string_maps(
    kind: &'static str,
    current: &BTreeMap<String, BTreeMap<String, String>>,
    locked: &BTreeMap<String, BTreeMap<String, String>>,
) -> Option<ImporterSnapshotDiff> {
    let outer_keys: BTreeSet<&String> = current.keys().chain(locked.keys()).collect();
    for outer in outer_keys {
        let empty = BTreeMap::new();
        if let Some(diff) = compare_string_maps(
            kind,
            current.get(outer).unwrap_or(&empty),
            locked.get(outer).unwrap_or(&empty),
        ) {
            return Some(ImporterSnapshotDiff {
                name: format!("{outer}.{}", diff.name),
                ..diff
            });
        }
    }
    None
}

fn compare_option(
    name: &'static str,
    current: &Option<String>,
    locked: &Option<String>,
) -> Option<ImporterSnapshotDiff> {
    (current != locked).then(|| ImporterSnapshotDiff {
        kind: "setting",
        name: name.to_string(),
        manifest: current.clone().unwrap_or_else(|| "<absent>".to_string()),
        lockfile: locked.clone().unwrap_or_else(|| "<absent>".to_string()),
    })
}

/// Test-only deterministic-panic injection hook.
///
/// argument AND the build is `cfg!(debug_assertions)` OR
/// `LPM_TEST_MODE=1`, panics with a recognizable message that
/// includes the stage name. Production builds without
/// `LPM_TEST_MODE=1` silently treat this as a no-op — the env is
/// read but never honored.
///
/// **Why a panic, not an error.** The hook exists to drive workflow
/// tests that pin the [`crate::manifest_tx::ManifestTransaction`]
/// Drop-based rollback. Drop fires on `?` early-return AND on panic
/// AND during normal scope exit. A `?`-early-return path can already
/// be tested by injecting a recoverable error (e.g., an invalid
/// `--policy=` flag); the panic path needed a separate hook because
/// no recoverable error reliably triggers Drop after EVERY stage
/// in the install pipeline. SIGKILL bypasses Drop entirely.
///
/// **Stages currently wired in [`run_add_packages`]:**
///
/// - `"after-snapshot"` — right after
///   `snapshot_install_state` succeeds; the manifest is unchanged.
///   Drop should be a no-op (snapshot bytes == on-disk bytes).
/// - `"after-stage"` — right after
///   `stage_packages_to_manifest` writes the `*` placeholder into
///   `package.json`. Drop must restore the pre-stage bytes — this
///   is the load-bearing test for the rollback contract.
/// - `"after-install"` — right after
///   `run_with_options` returns Ok. The lockfile is now fresh; the
///   manifest still has `*` placeholders. Drop must restore both.
/// - `"after-finalize"` — right after
///   `finalize_packages_in_manifest` resolves the `*` to concrete
///   versions. Drop runs ONE step before commit; the test asserts
///   the manifest snaps back to its pre-stage shape rather than
///   landing in a half-committed state.
///
/// Used by [B.4](../../../tests/workflows/tests/install_concurrency.rs)
/// (`install_panics_mid_pipeline_rollback_restores_manifest`).
fn maybe_test_panic(stage: &str) {
    let allowed = cfg!(debug_assertions)
        || std::env::var("LPM_TEST_MODE")
            .ok()
            .as_deref()
            .is_some_and(|v| v == "1");
    if !allowed {
        return;
    }
    if std::env::var("LPM_TEST_PANIC_AT").as_deref() == Ok(stage) {
        panic!("LPM_TEST_PANIC_AT={stage} (test-only panic injection)");
    }
}

/// Test-only failure injection for the audit-after-install wrapper.
///
/// Returns `true` when the workflow harness has asked us to simulate
/// an audit-pass failure. The install pipeline then skips the real
/// `audit::run_install_summary` call, logs a `tracing::warn!`, and
/// proceeds as if the audit had errored — letting the workflow test
/// pin the "errors degrade to no envelope field, install still exits
/// 0" contract without depending on a real audit failure mode
/// (network outage, store-lock contention, lockfile corruption).
///
/// Gated the same way as [`maybe_test_panic`]: enabled in debug
/// builds OR when `LPM_TEST_MODE=1` is exported. Production release
/// builds never honor the trigger env even if it's set.
fn maybe_test_audit_after_install_should_fail() -> bool {
    let allowed = cfg!(debug_assertions)
        || std::env::var("LPM_TEST_MODE")
            .ok()
            .as_deref()
            .is_some_and(|v| v == "1");
    if !allowed {
        return false;
    }
    std::env::var("LPM_TEST_AUDIT_AFTER_INSTALL_FAIL").as_deref() == Ok("1")
}

#[allow(clippy::too_many_arguments)]
pub async fn run_with_options(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    offline: bool,
    frozen_lockfile: FrozenLockfileMode,
    force: bool,
    allow_new: bool,
    // () — strict_integrity: when true, tarball-URL
    // deps without a manifest-declared SRI fail rather than
    // trust-on-first-use. Lockfile-resident integrity is still
    // trusted; only the manifest-boundary trust-on-first-use is
    // disabled.
    strict_integrity: bool, // CLI-level override for strict peer-dependency handling. `None`
    // falls through to package.json / global config / default.
    strict_peer_dependencies_override: Option<bool>,
    // Already-resolved linker override from CLI / `~/.lpm/config.toml` / env.
    // `None` means fall through to `package.json > lpm > linker` (which is
    // validated against `lpm_linker::LinkerMode::parse_str` inside the
    // install pipeline) and finally the default isolated layout.
    linker_override: Option<lpm_linker::LinkerMode>,
    no_skills: bool,
    no_editor_setup: bool,
    no_security_summary: bool,
    auto_build: bool,
    // when invoked from the workspace-aware install path,
    // the list of `package.json` files that were modified before this call.
    // Surfaced in the JSON output as `target_set` so agents can see which
    // workspace members were touched. `None` for legacy/standalone callers.
    target_set: Option<&[String]>,
    // Invariant: when `Some`, the install pipeline
    // populates the map with `name → resolved_version` for every DIRECT
    // dependency. Used by `run_add_packages` and `run_install_filtered_add`
    // to feed `finalize_packages_in_manifest` without doing a flat scan
    // over the lockfile (which can't distinguish direct from transitive
    // when the same name appears at different versions). Bare install
    // callers pass `None`.
    direct_versions_out: Option<&mut HashMap<String, lpm_semver::Version>>,
    // add-path reporting count. `Some(n)` means this install was
    // triggered by `lpm install <pkg...>` after staging `n` explicit
    // package specs into the manifest; the phase / Done lines should
    // report the user-requested count, not the full resolved graph.
    // Bare `lpm install` callers pass `None`.
    requested_add_count: Option<usize>,
    // CLI-side `--policy` / `--yolo` / `--triage`
    // override, already collapsed to at most one value by
    // [`crate::script_policy_config::collapse_policy_flags`]. `None`
    // means no CLI flag was passed on this invocation and the
    // resolver should fall through to the project config →
    // `~/.lpm/config.toml` → default-deny precedence chain.
    //
    // Only consumed in for the triage-mode install summary line
    // (branches at the two `show_install_build_hint` call sites). No
    // execution semantics are changed — tier-aware auto-run is,
    // gated on the sandbox.
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    // CLI `--advisor` override. Resolves to the
    // top of the [`AdvisorSession::preflight`] precedence chain
    // (CLI → package.json → ~/.lpm/config.toml → `none`). Owned
    // `String` rather than `&str` so the value crosses the
    // store-lock async hop (the inner future is `'static`-bound)
    // without a borrowed-lifetime gymnastic. Internal callers
    // (`upgrade`, `add`, `dev`, `deploy`, `doctor`, `run`,
    // `migrate`) pass `None` — they don't accept their own
    // `--advisor` flag today and a future opt-in is a one-line
    // change.
    //
    // The slug is validated at the clap layer (`parse_advisor_slug`
    // in `main.rs`), so an `Some` value here is guaranteed to be
    // `"none"` or a known provider slug. The session itself still
    // warn-degrades on unavailable adapters at runtime — clap only
    // catches typos, not "claude-cli configured but not on PATH."
    advisor_override: Option<String>,
    //: already-parsed `--min-release-age=<dur>` override. `Some`
    // short-circuits the package.json / global / default chain in
    // [`crate::release_age_config::ReleaseAgeResolver::resolve`]; `None`
    // walks the chain normally. Clap parses the duration string via
    // [`crate::release_age_config::parse_duration`] before this fn runs, so
    // validation errors never make it this far.
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    // canonicalized `--ignore-provenance-drift[-all]`
    // override (see [`crate::provenance_fetch::DriftIgnorePolicy`] for
    // the three variants). `EnforceAll` is the default; the drift gate
    // consults `.ignores_all()` for a short-circuit and
    // `.ignores_name(...)` per-package. `--allow-new` does NOT compose
    // into this policy (): drift and cooldown are orthogonal, so
    // their override flags stay separate.
    drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    // Composed `(EnforceMode, SkipPolicy)` for the Sigstore
    // verifier. The drift gate at the install-time call
    // consults `verify_policy.skip` to route skip-listed packages
    // through the legacy identity-only parser (producing
    // `ProvenanceStatus::Unverified`) instead of hard-failing on a
    // cryptographic rejection. Orthogonal to `drift_ignore_policy`:
    // one suppresses the *crypto* layer, the other suppresses the
    // *drift* layer.
    verify_policy: crate::provenance_fetch::VerifyPolicy,
    omit_policy: InstallOmitPolicy,
    // CLI sandbox-mode overrides.
    // `strict_sandbox=true` flips outbound network denial on for the
    // auto-build call; `no_sandbox=true` drops all containment for
    // that call. Clap-level mutex guarantees they never both arrive
    // `true`. The full precedence chain — CLI > env > project >
    // user > default — is resolved inside
    // [`crate::sandbox_config::resolve_sandbox_mode_from_chain`] at
    // the auto-build site; install-time pre-fetch does not engage
    // the sandbox, so this flag only matters when `auto_build` is
    // true.
    strict_sandbox: bool,
    no_sandbox: bool,
    // Top-level `--verbose` flag (long form only — `-v` is `--version`).
    // When true, the Done block appends a footer with per-phase timings
    // and the on-disk lockfile size.
    verbose: bool,
    // Resolved audit-after-install precedence (CLI > env > config >
    // default false). When true, the install pipeline runs the silent
    // [`crate::commands::audit::run_install_summary`] after the Done
    // block and emits a one-line advisory (or attaches `audit_summary`
    // to the JSON envelope). Audit results NEVER fail the install.
    audit_after_install: bool,
    compatibility_bin_names: &[String],
) -> Result<(), LpmError> {
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    run_with_options_with_lpm_root(
        client,
        project_dir,
        json_output,
        offline,
        frozen_lockfile,
        force,
        allow_new,
        strict_integrity,
        strict_peer_dependencies_override,
        linker_override,
        no_skills,
        no_editor_setup,
        no_security_summary,
        auto_build,
        target_set,
        direct_versions_out,
        requested_add_count,
        script_policy_override,
        advisor_override,
        min_release_age_override,
        min_release_age_exclude,
        drift_ignore_policy,
        verify_policy,
        omit_policy,
        strict_sandbox,
        no_sandbox,
        verbose,
        audit_after_install,
        compatibility_bin_names,
        lpm_root,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with_options_with_lpm_root(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    offline: bool,
    frozen_lockfile: FrozenLockfileMode,
    force: bool,
    allow_new: bool,
    strict_integrity: bool,
    strict_peer_dependencies_override: Option<bool>,
    linker_override: Option<lpm_linker::LinkerMode>,
    no_skills: bool,
    no_editor_setup: bool,
    no_security_summary: bool,
    auto_build: bool,
    target_set: Option<&[String]>,
    direct_versions_out: Option<&mut HashMap<String, lpm_semver::Version>>,
    requested_add_count: Option<usize>,
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    advisor_override: Option<String>,
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    verify_policy: crate::provenance_fetch::VerifyPolicy,
    omit_policy: InstallOmitPolicy,
    strict_sandbox: bool,
    no_sandbox: bool,
    verbose: bool,
    audit_after_install: bool,
    compatibility_bin_names: &[String],
    lpm_root: lpm_common::LpmRoot,
) -> Result<(), LpmError> {
    // Round 2: hold a shared lock on the store for the
    // entire install pipeline. Multiple concurrent installs share it
    // freely; `lpm cache prune --apply` and `lpm store clean` (which take it
    // exclusively) wait until every in-flight install releases. This
    // closes the read-vs-write race where gc could `remove_dir_all`
    // a CAS entry mid-`link_dir_recursive`.
    //
    // Acquired via the async helper so a contended lock doesn't block
    // the tokio reactor; the held handle lives for the lifetime of
    // the inner future and releases when the future returns.
    let store_lock_path = lpm_root.store_lock();
    lpm_common::with_shared_lock_async(
        store_lock_path,
        run_with_options_under_store_lock(
            client,
            project_dir,
            json_output,
            offline,
            frozen_lockfile,
            force,
            allow_new,
            strict_integrity,
            strict_peer_dependencies_override,
            linker_override,
            no_skills,
            no_editor_setup,
            no_security_summary,
            auto_build,
            target_set,
            direct_versions_out,
            requested_add_count,
            script_policy_override,
            advisor_override,
            min_release_age_override,
            min_release_age_exclude,
            drift_ignore_policy,
            verify_policy,
            omit_policy,
            strict_sandbox,
            no_sandbox,
            verbose,
            audit_after_install,
            compatibility_bin_names,
            &lpm_root,
        ),
    )
    .await
}

/// Body of [`run_with_options`] — the actual install pipeline. Lives
/// in a private fn so the outer wrapper can hold the store-lock
/// handle for its full duration via `with_shared_lock_async`.
#[allow(clippy::too_many_arguments)]
async fn run_with_options_under_store_lock(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    offline: bool,
    frozen_lockfile: FrozenLockfileMode,
    force: bool,
    allow_new: bool,
    strict_integrity: bool,
    strict_peer_dependencies_override: Option<bool>,
    linker_override: Option<lpm_linker::LinkerMode>,
    no_skills: bool,
    no_editor_setup: bool,
    no_security_summary: bool,
    auto_build: bool,
    target_set: Option<&[String]>,
    direct_versions_out: Option<&mut HashMap<String, lpm_semver::Version>>,
    requested_add_count: Option<usize>,
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    // see `run_with_options` for the contract.
    advisor_override: Option<String>,
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    // see `run_with_options` for the contract.
    verify_policy: crate::provenance_fetch::VerifyPolicy,
    omit_policy: InstallOmitPolicy,
    // Threaded down so the auto-build call below honors the user's
    // CLI sandbox-mode override.
    strict_sandbox: bool,
    no_sandbox: bool,
    // Forwarded `--verbose` flag from the CLI entry. Used only by the
    // Done-block footer; the rest of the pipeline ignores it.
    verbose: bool,
    // Resolved audit-after-install boolean — see [`run_with_options`].
    audit_after_install: bool,
    compatibility_bin_names: &[String],
    lpm_root: &lpm_common::LpmRoot,
) -> Result<(), LpmError> {
    let start = Instant::now();
    lpm_registry::timing::reset_metadata_http_versions();
    lpm_registry::timing::reset_metadata_detail();
    crate::build_state::reset_write_timing();
    crate::security_floor::clear_recorded_suppressions();
    let timing_detail_mode = TimingDetailMode::from_env();
    let global_config = crate::commands::config::GlobalConfig::load();
    let verify_registry_signatures = registry_signature_verification_enabled(&global_config);
    let registry_signature_timings = timing_detail_mode
        .enabled()
        .then(|| Arc::new(crate::registry_signatures::RegistrySignatureTimings::default()));
    let provenance_timings = timing_detail_mode
        .enabled()
        .then(crate::provenance_fetch::ProvenanceTimings::default);
    let mut slow_package_timings = SlowPackageTimings::default();
    let mut wf_tail_lockfile_write_ms = 0u128;
    let mut wf_tail_lockfile_write_count = 0u64;
    let mut wf_tail_audit_after_install_ms = 0u128;
    let force_security_floor = crate::security_floor::force_security_floor_enabled(&global_config);
    let mut drift_ignore_policy = drift_ignore_policy;
    let mut verify_policy = verify_policy;

    // Step 1: Read package.json
    let pkg_json_path = project_dir.join("package.json");
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let frozen_lockfile_active = frozen_lockfile.is_active(&lockfile_path);
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "no package.json found in current directory or any parent. \
             Run `lpm init` to create one, or `lpm install <pkg>` to auto-create."
                .to_string(),
        ));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;

    crate::security_approval::ensure_project_policy_authorized(
        project_dir,
        json_output,
        crate::security_approval::ApprovalSource::ProjectConfig,
    )?;
    crate::typosquat_guard::guard_manifest_direct_dependencies(
        project_dir,
        &pkg_json_path,
        &pkg,
        json_output,
    )?;

    let release_age_config = crate::release_age_config::ReleaseAgeResolver::resolve_config(
        project_dir,
        min_release_age_override,
        min_release_age_exclude,
        json_output,
    )?;
    let effective_min_age_secs = release_age_config.minimum_release_age_secs;
    if allow_new && effective_min_age_secs > 0 {
        crate::security_approval::approve_project_runtime_override(
            crate::security_approval::ApprovalScope::CooldownBypass,
            project_dir,
            json_output,
            crate::security_approval::ApprovalSource::CliFlag,
            "This install bypasses the minimum release age for this project.",
            &[],
        )?;
    }
    let resolver_min_age_secs = if allow_new { 0 } else { effective_min_age_secs };
    let release_age_policy = release_age_config.minimum_release_age_policy;
    let resolver_trust_policy = match global_config.get_trust_policy().as_deref() {
        Some("no-downgrade") => lpm_resolver::TrustPolicyMode::NoDowngrade,
        _ => lpm_resolver::TrustPolicyMode::Off,
    };
    let minimum_release_age_exclude = release_age_config.minimum_release_age_exclude;

    // Hoisted
    // here (above the empty-deps short-circuit, the lockfile fast
    // path, and the freshness check) so the v1-lockfile gate AND
    // the pubgrub-mismatch warning fire regardless of which install
    // codepath ultimately runs. Same precedence chain documented on
    // `LpmConfig.auto_install_peers`:
    // `package.json > lpm > autoInstallPeers`
    // → `~/.lpm/config.toml > auto-install-peers`
    // → default `true` (bun-parity beta).
    let auto_install_peers: bool = pkg
        .lpm
        .as_ref()
        .and_then(|l| l.auto_install_peers)
        .or_else(|| global_config.get_bool("auto-install-peers"))
        .unwrap_or(true);
    let strict_peer_dependencies =
        resolve_strict_peer_dependencies(strict_peer_dependencies_override, &pkg, &global_config);
    let pubgrub_opt_out = std::env::var("LPM_RESOLVER").as_deref() == Ok("pubgrub");

    // pubgrub-mismatch warning.
    //
    // Previously this warning was emitted only when `!json_output`,
    // which silenced it for any wrapper, CI, or tooling using
    // `--json` — exactly the audience that needs the signal MOST,
    // since they consume the install programmatically and otherwise
    // silently take the install-tree-divergence between
    // `LPM_RESOLVER=pubgrub` (no auto-install) and the default
    // greedy-fusion (auto-install on).
    //
    // Post-fix the warning fires unconditionally on stderr.
    // `--json` consumers parse stdout for the envelope; stderr is
    // separate. Matches every other warning in the install pipeline
    // (`output::warn` → stderr).
    //
    // Hoisted above the empty-deps short-circuit + lockfile fast
    // path so the warning surfaces even on installs that don't run
    // the resolver — the same env-var + config combination produces
    // a different install tree on a non-empty `lpm install` later,
    // and surfacing the warning early gives the user a chance to
    // notice before they hit it.
    if pubgrub_opt_out && auto_install_peers {
        output::warn(
            "LPM_RESOLVER=pubgrub does not support eager peer auto-install \
             (lpm.autoInstallPeers = true). Missing peers will surface as \
             warnings only — the install tree will differ from the default \
             greedy-fusion resolver. To silence this warning, either unset \
             LPM_RESOLVER or set `lpm.autoInstallPeers = false` in package.json.",
        );
    }

    // Resolve the effective linker BEFORE the freshness check so:
    // 1. Invalid CLI / config.toml / `LPM_LINKER` / `package.json > lpm
    // > linker` values fail loudly here, regardless of whether the
    // cache would otherwise short-circuit the install. Previously, an
    // invalid env value was silently masked on the up-to-date path.
    // 2. The resolved mode folds into the install-hash via
    // `check_install_state_with_linker`, so a post-install flip of
    // `LPM_LINKER` or `~/.lpm/config.toml > linker` invalidates the
    // "up to date" cache and triggers a re-link.
    // Precedence: caller-supplied CLI override > config.toml > env >
    // `package.json > lpm > linker` > workspace auto-detection > default
    // hoisted. A persisted peer-conflict auto-isolation flag can override
    // that final default on warm installs without taking over explicit
    // linker choices.
    let (configured_linker_mode, linker_source) =
        crate::linker_config::resolve_effective_linker_with_source(
            linker_override,
            &pkg,
            &global_config,
            project_dir,
        )
        .map_err(|e| {
            LpmError::Script(format!(
                "{e} \
             Update the offending surface or override with \
             `--linker=<isolated|hoisted>`."
            ))
        })?;
    let peer_conflict_auto_isolation_allowed = matches!(
        linker_source,
        crate::linker_config::LinkerModeSource::Default
    );
    let mut auto_isolated_peer_conflicts = peer_conflict_auto_isolation_allowed
        && lockfile_has_auto_isolated_peer_conflicts(&lockfile_path);
    let mut linker_mode = if auto_isolated_peer_conflicts {
        lpm_linker::LinkerMode::Isolated
    } else {
        configured_linker_mode
    };
    let requested_v2_mode = lpm_store::StoreVersion::from_env().is_v2();

    // Fast-exit: if package.json + lockfile haven't changed AND the
    // resolved linker matches the one used for the prior install, skip
    // the entire install pipeline. Two stats + one read + one SHA-256
    // hash ≈ 1-2ms vs 82ms for a full warm install.
    // --force bypasses this check to force a full re-install.
    //
    // Linker freshness: `check_install_state_with_linker` folds the
    // mode into the hash so a post-install flip of `LPM_LINKER` /
    // `~/.lpm/config.toml > linker` invalidates the cache. The mtime
    // fast path also reads the `l:<mode>` line written by
    // `write_install_hash` to detect the same flip without re-hashing.
    // Strict peer mode runs a fresh peer check because the fast path
    // does not have the resolver metadata needed to prove the tree is clean.
    let pkg_content_for_state = std::fs::read_to_string(&pkg_json_path).unwrap_or_default();
    let setup_state_t = Instant::now();
    let install_state = crate::install_state::check_install_state_with_linker(
        project_dir,
        &pkg_content_for_state,
        linker_mode,
    );
    let wf_setup_install_state_ms = setup_state_t.elapsed().as_millis();
    let compatibility_bins_ready = !requested_v2_mode
        || compatibility_bin_names.is_empty()
        || lpm_linker::v2::project_compatibility_bins_ready(project_dir, compatibility_bin_names);
    let cleanup_catalogs_in_pipeline = requested_add_count.is_none();
    if !frozen_lockfile_active
        && !force
        && !offline
        && !strict_peer_dependencies
        && install_state.up_to_date
        && compatibility_bins_ready
    {
        let catalogs_cleaned = if cleanup_catalogs_in_pipeline {
            cleanup_unused_catalogs_after_install(project_dir)?
        } else {
            false
        };
        if catalogs_cleaned {
            write_post_install_v6_hash(project_dir, linker_mode);
        }
        let elapsed = start.elapsed();
        let total_ms = elapsed.as_millis();
        if json_output {
            // Emit the same `timing` object shape as the main and offline paths
            // so benchmark scripts can parse install output uniformly regardless
            // of which fast-path was taken. Stages are zero because no real work
            // ran — the entire pipeline was skipped.
            let mut json = serde_json::json!({
                           "success": true,
                           "up_to_date": true,
                           "duration_ms": total_ms as u64,
                           "timing": {
                               "resolve_ms": 0u128,
                               "fetch_ms": 0u128,
                               "link_ms": 0u128,
                               "total_ms": total_ms,
                               "waterfall": {
                                   "setup_ms": total_ms,
                                   "resolve_ms": 0u128,
                                   "pre_fetch_ms": 0u128,
                                   "fetch_ms": 0u128,
                                   "pre_link_ms": 0u128,
                                   "link_ms": 0u128,
                                   "link_await_ms": 0u128,
                                   "link_finalize_ms": 0u128,
                                   "tail_ms": 0u128,
                                   "total_ms": total_ms,
                               },
                           },
            //always-present empty array: up-to-date fast
            // path runs no resolve, so no fresh conflict trace.
                           "peer_conflicts": [],
                           "peer_issues": peer_issues_json_value(&[], &[]),
                       });
            if timing_detail_mode.enabled() {
                json["timing"]["detail"] = setup_only_timing_detail_json(
                    timing_detail_mode,
                    total_ms,
                    wf_setup_install_state_ms,
                    0,
                );
            }
            // surface workspace target set for agents.
            if let Some(targets) = target_set {
                json["target_set"] = serde_json::Value::Array(
                    targets.iter().map(|s| serde_json::json!(s)).collect(),
                );
            }
            crate::security_floor::attach_security_posture(&mut json, force_security_floor);
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            install_ui::done(&format!("Up to date · {total_ms}ms"));
        }
        return Ok(());
    }

    let pkg_name = pkg.name.as_deref().unwrap_or("(unnamed)");
    // The persistent `› Resolving …` phase line is emitted below after
    // the route table is built so it can name the actual registry hosts
    // (e.g. `lpm.dev`, `npmjs.org`) the resolver will hit. The previously
    // `Installing dependencies for X` line was redundant with that.

    // + hoisted-symmetry — legacy linker-state migration.
    // Detects upgrade-in-place users (binary upgraded but
    // `node_modules/` not wiped) and wipes any legacy state subtrees
    // — the pre-61.1 isolated wrapper root at `node_modules/.lpm/`
    // and/or the pre-symmetry hoisted state at
    // `node_modules/.lpm-metadata.json` + `node_modules/.lpm/nested/`
    // — so the rest of the install pipeline rebuilds at the new
    // `<project>/.lpm/{wrappers,hoisted}/` locations. The fast-lane
    // gate in `install_state::needs_layout_migration` already forced
    // a real install when either migration is owed; here we just
    // clear the old state. Idempotent — calling on a project without
    // legacy state is a no-op.
    migrate_legacy_wrapper_layout(project_dir, json_output);

    // + hoisted-symmetry — ensure `.gitignore` contains
    // BOTH `.lpm/wrappers/` (isolated) and `.lpm/hoisted/` so neither
    // mode's project-local state can accidentally land in commits.
    // Runtime "ensure once" pattern (matches the existing skills
    // helper); idempotent for projects that already have either
    // entry. Both run unconditionally because the user's mode could
    // change between installs and a project already on one mode may
    // accumulate the other mode's state during a future toggle.
    ensure_lpm_wrappers_gitignore(project_dir);
    ensure_lpm_hoisted_gitignore(project_dir);

    //: surface silent additions to `trustedDependencies`
    // BEFORE the install pipeline does any work.
    // A "bump dep" PR that quietly grew the trust list would otherwise
    // slip past local review; this diff is the local-reviewer safety
    // net. Emission is suppressed in --json mode (no stable JSON
    // schema for this surface yet — callers will learn the additions
    // via `lpm trust diff` once that lands in chunk C).
    if !json_output {
        let current_snapshot =
            crate::trust_snapshot::TrustSnapshot::capture_current(pkg.lpm.as_ref().map_or(
                &lpm_workspace::TrustedDependencies::Legacy(Vec::new()),
                |l| &l.trusted_dependencies,
            ));
        let previous_snapshot = crate::trust_snapshot::read_snapshot(project_dir);
        let additions = current_snapshot.diff_additions(previous_snapshot.as_ref());
        if let Some(notice) = crate::trust_snapshot::format_new_bindings_notice(&additions) {
            output::info(&notice);
        }
    }

    // — shared gate counters. Populated by the lockfile
    // fast path (Change 1) when a stored URL fails the scheme/shape/
    // origin gate, and (in follow-up commits) by the stale-URL retry
    // path. Surfaced on `timing.fetch_breakdown.tarball_url_gate`.
    let gate_stats = Arc::new(GateStats::default());

    let mut deps = pkg.dependencies.clone();

    // `lpm install` resolves BOTH `dependencies` and `devDependencies`,
    // matching npm/pnpm/yarn semantics. Pre-only `dependencies`
    // flowed through the pipeline, which silently no-op'd `lpm install -D`
    // (the spec landed in the manifest but was never resolved or linked).
    //
    // Conflict rule: `dependencies` wins. npm treats the same key in both
    // sections as malformed, and `dependencies` is the production contract —
    // it should never be shadowed by a dev-only entry.
    //
    // `lpm deploy` strips `devDependencies` from the output manifest before
    // re-entering this path, so the deploy closure stays prod-only. `--prod`
    // / `--omit dev` still resolve the full graph for lockfile parity, then
    // filter dev-only packages before linking.
    for (name, range) in &pkg.dev_dependencies {
        deps.entry(name.clone()).or_insert_with(|| range.clone());
    }
    reject_workspace_self_dependency(&pkg)?;

    let production_dependency_names: HashSet<String> = pkg.dependencies.keys().cloned().collect();
    let declared_deps = deps.clone();

    // Resolve `catalog:` protocols and EXTRACT `workspace:*` member references
    // before anything else (lockfile fast path, resolver). This ensures the
    // `deps` HashMap contains only real registry ranges by the time the
    // resolver sees it.
    //
    // previously
    // we called `lpm_workspace::resolve_workspace_protocol` which rewrote
    // `"@scope/member": "workspace:^"` to `"@scope/member": "^1.5.0"` and
    // LEFT IT in `deps`. The resolver then tried to fetch
    // `@scope/member@^1.5.0` from npm/lpm.dev and 404'd against the upstream
    // proxy, because unpublished workspace members can't be looked up
    // remotely. Post-fix, we strip workspace member references from `deps`
    // entirely; they are linked from disk after the install pipeline
    // finishes via [`link_workspace_members`].
    //
    // Catalog resolution must use the workspace ROOT catalogs when inside a
    // workspace, because workspace members define `"catalog:"` references
    // that point to centralized version definitions in the root package.json.
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .ok()
        .flatten();

    let (mut workspace_member_deps, mut catalog_resolutions): (
        Vec<WorkspaceMemberLink>,
        Vec<lpm_workspace::CatalogProtocolResolution>,
    ) = if let Some(ref ws) = workspace {
        // workspace:* extraction (NEW: replaces resolve_workspace_protocol)
        let extracted = extract_workspace_protocol_deps(&mut deps, ws)?;
        if !extracted.is_empty() && !json_output {
            for member in &extracted {
                tracing::debug!(
                    "workspace member (local): {} @ {} from {}",
                    member.name,
                    member.version,
                    member.source_dir.display()
                );
            }
        }

        // catalog: protocol — resolve from workspace root catalogs
        let mut catalog_resolutions: Vec<lpm_workspace::CatalogProtocolResolution> = Vec::new();

        if !ws.root_package.catalogs.is_empty() {
            match lpm_workspace::resolve_catalog_protocol(&mut deps, &ws.root_package.catalogs) {
                Ok(resolved) => {
                    if !resolved.is_empty() && !json_output {
                        for entry in &resolved {
                            tracing::debug!(
                                "catalog: {} → {}",
                                entry.package_name,
                                entry.specifier
                            );
                        }
                    }
                    catalog_resolutions = resolved;
                }
                Err(e) => {
                    return Err(catalog_protocol_error_to_lpm(e));
                }
            }
        }
        (extracted, catalog_resolutions)
    } else {
        // Standalone project (no workspace): no workspace member deps possible.
        // Local catalogs are still resolved if present.
        let mut catalog_resolutions = Vec::new();
        if !pkg.catalogs.is_empty() {
            match lpm_workspace::resolve_catalog_protocol(&mut deps, &pkg.catalogs) {
                Ok(resolved) => {
                    if !resolved.is_empty() && !json_output {
                        for entry in &resolved {
                            tracing::debug!(
                                "catalog: {} → {}",
                                entry.package_name,
                                entry.specifier
                            );
                        }
                    }
                    catalog_resolutions = resolved;
                }
                Err(e) => {
                    return Err(catalog_protocol_error_to_lpm(e));
                }
            }
        }
        (Vec::new(), catalog_resolutions)
    };
    let direct_workspace_member_deps = if requested_v2_mode {
        workspace_member_deps.clone()
    } else {
        Vec::new()
    };

    //
    // `workspace_member_deps` above is the EXTRACTED top-level subset
    // (entries the consumer's manifest declared via `workspace:*`).
    // That set drives `link_workspace_members` (which plants root
    // node_modules symlinks for explicit references).
    //
    // `pre_resolve_non_registry_deps` needs a DIFFERENT set: every
    // member of the workspace, regardless of whether the consumer's
    // top-level manifest references it via `workspace:*`. Pre-the invariant
    // the same `workspace_member_deps` slice was reused, but that
    // meant a workspace member was visible to overlap detection
    // and to the invariant's transitive `workspace:` check ONLY when the
    // consumer's root explicitly imported it via `workspace:*`. The
    // regression the invariant repro: root depends on `foo` via `file:`, and
    // foo's `package.json` declares `bar: workspace:*` — bar is a
    // valid sibling member, but because the root never wrote
    // `"bar": "workspace:*"`, `extracted` is empty and the invariant
    // (correctly, given its inputs) errored "not a workspace member."
    //
    // The fix: build a separate `all_workspace_members` slice
    // straight from `ws.members`, independent of extraction. This is
    // the slice + the invariant should have used all along (membership
    // is membership; bun/pnpm don't gate transitive `workspace:`
    // resolution on top-level reference).
    let all_workspace_members: Vec<WorkspaceMemberLink> = workspace
        .as_ref()
        .map(|ws| {
            ws.members
                .iter()
                .filter_map(|m| {
                    let name = m.package.name.as_deref()?.to_string();
                    let version = m.package.version.as_deref().unwrap_or("0.0.0").to_string();
                    Some(WorkspaceMemberLink {
                        name,
                        version,
                        source_dir: m.path.clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // dedupe pre-pass.
    // Replaces the dedupe that lived only in the online path's
    // `pre_resolve_non_registry_deps`. By running BEFORE the
    // offline/online dispatch and BEFORE the lockfile fast-path,
    // both modes converge on the same `(deps, workspace_member_deps)`
    // shape:
    // - `file:./packages/foo` (a workspace member) → removed from
    // `deps`, added to `workspace_member_deps`.
    // - The lockfile fast-path no longer sees `foo` as a missing
    // root dep (it WAS removed before the check).
    // - `link_workspace_members` plants `node_modules/foo` because
    // the entry is in `workspace_member_deps`.
    pre_extract_file_link_workspace_members(
        &mut deps,
        &mut workspace_member_deps,
        &all_workspace_members,
        project_dir,
        json_output,
    );

    let resolver_excludes = minimum_release_age_exclude
        .iter()
        .map(|name| lpm_resolver::CanonicalKey::from_dep_name(name));
    let resolver_policy = if release_age_policy.is_strict() {
        lpm_resolver::ResolverPolicy::new_with_release_age_excludes(
            resolver_min_age_secs,
            resolver_trust_policy,
            resolver_excludes,
        )
    } else {
        let direct_release_age_canonicals = direct_release_age_canonicals(&deps);
        lpm_resolver::ResolverPolicy::new_with_release_age_excludes_and_packages(
            resolver_min_age_secs,
            resolver_trust_policy,
            resolver_excludes,
            direct_release_age_canonicals,
        )
    };
    let minimum_release_age_exclude: std::collections::HashSet<String> =
        minimum_release_age_exclude.into_iter().collect();

    // fully parse and validate the override set
    // up-front (fail-closed). This runs BEFORE the empty-deps
    // short-circuit so a malformed override is surfaced even when
    // the project has zero dependencies — otherwise users would only
    // discover the validation failure after adding their first dep.
    //
    // The three sources are merged through the resolver's parser. Any
    // malformed selector, target, or multi-segment path is a HARD
    // ERROR here, surfaced to the user as a clear validation message.
    //
    // - `lpm.overrides` (LPM-native, wins on conflict)
    // - `overrides` (npm-standard, top-level)
    // - `resolutions` (yarn-style alias for overrides)
    let lpm_overrides_map = pkg
        .lpm
        .as_ref()
        .map(|l| l.overrides.clone())
        .unwrap_or_default();
    let dependency_catalog_resolution_count = catalog_resolutions.len();
    let override_catalogs = workspace
        .as_ref()
        .map_or(&pkg.catalogs, |ws| &ws.root_package.catalogs);
    let (lpm_overrides_map, lpm_override_catalog_resolutions) =
        resolve_catalog_protocol_in_override_map(&lpm_overrides_map, override_catalogs)?;
    let (overrides_map, npm_override_catalog_resolutions) =
        resolve_catalog_protocol_in_override_map(&pkg.overrides, override_catalogs)?;
    let (resolutions_map, resolution_catalog_resolutions) =
        resolve_catalog_protocol_in_override_map(&pkg.resolutions, override_catalogs)?;
    let mut override_catalog_resolutions = Vec::new();
    extend_catalog_resolutions(
        &mut override_catalog_resolutions,
        lpm_override_catalog_resolutions,
    );
    extend_catalog_resolutions(
        &mut override_catalog_resolutions,
        npm_override_catalog_resolutions,
    );
    extend_catalog_resolutions(
        &mut override_catalog_resolutions,
        resolution_catalog_resolutions,
    );
    extend_catalog_resolutions(
        &mut catalog_resolutions,
        override_catalog_resolutions.clone(),
    );

    let override_set = OverrideSet::parse(
        lpm_overrides_map.as_ref(),
        overrides_map.as_ref(),
        resolutions_map.as_ref(),
    )
    .map_err(|e| LpmError::Script(format!("invalid override in package.json: {e}")))?;

    // Manifest-side compatibility warnings (pnpm overrides / patches
    // / peer rules drift, ignored other-PM `engines.*` keys) fire from
    // the engine_check preflight gate (`engine_check::enforce`) which
    // runs before this point in install / rebuild / add. The shared
    // source of truth is `PackageJson::manifest_compat_issues` in
    // `lpm-workspace`. Automation pipelines pull the same signals
    // from `lpm doctor --json`, where every issue lands as a
    // `Check::warn` with a stable code.

    // — build the RouteTable (npmrc) early and surface its
    // warnings. The `strict-ssl=false` install-start warning must fire
    // regardless of whether deps actually need fetching: a user who
    // explicitly disabled TLS verification deserves the diagnostic, and
    // the empty-deps short-circuit below shouldn't suppress it.
    //
    // Cost: 4 npmrc-layer file reads on every install, including the
    // empty-deps short-circuit below. Measured at ms-scale on a cold
    // disk; acceptable trade for never silencing the security warning.
    // If the empty-deps fast path becomes a measured hot path for any
    // workflow, the right escape valve is a "did any layer touch TLS?"
    // probe (4 stat() calls) gating the full parse — not relocating
    // the warning back inside the deps-bearing path, which would
    // regress the fix.
    //
    // Fatal `${MISSING_VAR}` errors propagate via `?`, aborting the
    // install before any further work — npm parity.
    let setup_route_t = Instant::now();
    let route_table = lpm_registry::RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|e| LpmError::Registry(format!("npmrc: {e}")))?;
    let wf_setup_route_table_ms = setup_route_t.elapsed().as_millis();
    if !json_output {
        // Routine npmrc warnings (per-origin TLS deferred to 58.3,
        // path-prefix token loose-binding, etc.) are advisory and
        // human-targeted. They stay inside the json_output guard so
        // they don't compete with the structured stdout JSON.
        for w in route_table.npmrc_warnings() {
            output::warn(w);
        }
    }
    // The `strict-ssl=false` warning is a SECURITY signal — it must
    // reach automation / CI logs regardless of output mode. JSON output
    // goes to stdout; this warning is on stderr, so the structured
    // contract is unaffected. Previously this lived inside the
    // `json_output` guard above and silenced exactly the users
    // (`--json`-driven CI / agents) most likely to need it.
    if let Some(tagged) = route_table.tls_overrides().strict_ssl.as_ref()
        && !tagged.value
    {
        output::warn(&format!(
            "strict-ssl=false in {}:{} — TLS certificate verification is \
             DISABLED for this install across ALL registries. This is a \
             security risk.",
            tagged.source, tagged.line
        ));
    }
    // Project-local `.npmrc` security refusals are surfaced even in JSON
    // mode: agent/CI runs need to see when repo-owned config tried to
    // downgrade TLS or expand env-backed auth/routing, even when refused.
    for w in route_table.npmrc_security_warnings() {
        output::warn(w);
    }

    // Compute the actual set of registry hosts the resolver will hit
    // for THIS project's top-level deps. Workspace-member file refs
    // and other non-registry protocols contribute no origin — they
    // don't route through a registry. Reused below as `eager_origins`
    // for the per-origin TLS overrides; computing once here keeps the
    // slim-UI resolving line and the TLS plumbing in lockstep.
    //
    // Showing `client.base_url()` (always `lpm.dev`) for every project
    // would be a lie for any tree without `@lpm.dev/*` deps — the most
    // common case. The route table knows the real destination per
    // package; this line surfaces that truth.
    let top_level_specs: Vec<String> = deps
        .iter()
        .filter_map(
            |(local_name, range)| match lpm_resolver::Specifier::parse(range) {
                Ok(lpm_resolver::Specifier::SemverRange(_)) => Some(local_name.clone()),
                Ok(lpm_resolver::Specifier::NpmAlias { target, .. }) => Some(target),
                _ => None,
            },
        )
        .collect();
    let eager_origins = route_table.effective_registry_origins(
        &top_level_specs,
        client.base_url(),
        client.npm_registry_url(),
    );

    // Persistent `› Resolving …` phase line. Sits ABOVE the resolver so
    // the user sees what hosts are about to be hit before any network
    // I/O. `is_add_invocation` distinguishes `lpm i <pkg>` (already named
    // the target on the command line) from bare `lpm install` (where the
    // project name is the only handle the user has on what's being
    // resolved).
    let is_add_invocation = requested_add_count.is_some();
    if !json_output {
        let hosts_label = if eager_origins.is_empty() {
            // No top-level registry deps (workspace-only or empty
            // install). Fall back to the configured worker host so the
            // line isn't empty in the user's terminal.
            install_ui::yellow(&install_ui::short_registry_host(client.base_url()))
        } else {
            eager_origins
                .iter()
                .map(|o| {
                    let host = o
                        .host_lower
                        .strip_prefix("registry.")
                        .unwrap_or(&o.host_lower)
                        .to_owned();
                    install_ui::yellow(&host)
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        let line = if is_add_invocation {
            format!("Resolving dependencies from {hosts_label}")
        } else {
            format!(
                "Resolving dependencies from {hosts_label} for {}",
                install_ui::bold(pkg_name)
            )
        };
        install_ui::phase(&line);
    }

    // `linker_mode` was resolved above — before `check_install_state` —
    // so it covers both validation (fail-loud on invalid values) and
    // freshness (post-install env/config flips invalidate the cache).
    // No re-resolution here.

    let current_patches: HashMap<String, PatchedDependencyEntry> = pkg
        .lpm
        .as_ref()
        .map(|l| l.patched_dependencies.clone())
        .unwrap_or_default();
    let current_patch_fingerprint = patch_state::compute_fingerprint(&current_patches);
    let current_importer_patch_fingerprint =
        (!current_patches.is_empty()).then_some(current_patch_fingerprint.as_str());
    let current_lockfile_patches =
        patch_state::lockfile_patches_from_manifest(project_dir, &current_patches)?;
    let current_importer_snapshot = importer_snapshot_for_current_manifest(
        &pkg,
        lpm_overrides_map.as_ref(),
        overrides_map.as_ref(),
        resolutions_map.as_ref(),
        override_catalogs,
        current_importer_patch_fingerprint,
        auto_install_peers,
    );
    let lockfile_for_validation = if lockfile_path.exists() || frozen_lockfile_active {
        match lpm_lockfile::Lockfile::read_fast(&lockfile_path) {
            Ok(lockfile) => Some(lockfile),
            Err(e) if frozen_lockfile_active => {
                return Err(LpmError::Registry(format!(
                    "Frozen lockfile mismatch\n  lockfile    {}\n  error       {}\n  hint        run `lpm install` locally and commit lpm.lock before running a frozen install",
                    lockfile_path.display(),
                    e,
                )));
            }
            Err(e) if !current_lockfile_patches.is_empty() => {
                return Err(LpmError::Registry(format!(
                    "Patch lockfile mismatch\n  lockfile    {}\n  error       {}\n  hint        run `lpm install` after restoring a readable lpm.lock",
                    lockfile_path.display(),
                    e,
                )));
            }
            Err(_) => None,
        }
    } else {
        None
    };
    if let Some(lockfile) = lockfile_for_validation.as_ref() {
        validate_lockfile_patch_records(&lockfile_path, lockfile, &current_lockfile_patches)?;
    }
    if frozen_lockfile_active {
        if force {
            return Err(LpmError::Registry(
                "Frozen lockfile mismatch\n  flag        --force\n  hint        frozen installs cannot force fresh resolution; pass --no-frozen-lockfile for a mutable install"
                    .into(),
            ));
        }
        let lockfile = lockfile_for_validation
            .as_ref()
            .expect("frozen lockfile validation loaded lockfile or returned");
        validate_frozen_importer_snapshot(&lockfile_path, lockfile, &current_importer_snapshot)?;
    }

    if deps.is_empty() && workspace_member_deps.is_empty() {
        if cleanup_catalogs_in_pipeline {
            cleanup_unused_catalogs_after_install(project_dir)?;
        }
        // invariant: emit a proper JSON object even on the
        // empty-deps short-circuit so agents driving install always get a
        // parseable result. Previously this branch returned silently in JSON
        // mode, which combined with the workspace-aware filtered install
        // path produced a complete output silence on fresh workspaces.
        let elapsed = start.elapsed();
        let total_ms = elapsed.as_millis();
        if json_output {
            let mut json = serde_json::json!({
                           "success": true,
                           "no_dependencies": true,
                           "duration_ms": total_ms as u64,
                           "timing": {
                               "resolve_ms": 0u128,
                               "fetch_ms": 0u128,
                               "link_ms": 0u128,
                               "total_ms": total_ms,
                               "waterfall": {
                                   "setup_ms": total_ms,
                                   "resolve_ms": 0u128,
                                   "pre_fetch_ms": 0u128,
                                   "fetch_ms": 0u128,
                                   "pre_link_ms": 0u128,
                                   "link_ms": 0u128,
                                   "link_await_ms": 0u128,
                                   "link_finalize_ms": 0u128,
                                   "tail_ms": 0u128,
                                   "total_ms": total_ms,
                               },
                           },
            //always-present empty array: zero deps means
            // zero peer requirements means zero conflicts.
                           "peer_conflicts": [],
                           "peer_issues": peer_issues_json_value(&[], &[]),
                       });
            if timing_detail_mode.enabled() {
                json["timing"]["detail"] = setup_only_timing_detail_json(
                    timing_detail_mode,
                    total_ms,
                    wf_setup_install_state_ms,
                    wf_setup_route_table_ms,
                );
            }
            if let Some(targets) = target_set {
                json["target_set"] = serde_json::Value::Array(
                    targets.iter().map(|s| serde_json::json!(s)).collect(),
                );
            }
            crate::security_floor::attach_security_posture(&mut json, force_security_floor);
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            output::success("No dependencies to install");
        }
        // clean up stale overrides-state.json
        // when the user removes all overrides from a no-dep project.
        // We can't write a fresh state because there are no overrides,
        // and a stale state would cause `lpm graph --why` to surface
        // ghost trace data. Mirrors the same logic in the main path.
        if override_set.is_empty()
            && overrides_state::read_state(project_dir).is_some()
            && let Err(e) = overrides_state::delete_state(project_dir)
        {
            tracing::warn!("failed to delete stale overrides-state.json: {e}");
        }
        // Single-writer ownership: the install pipeline writes the v6
        // install-hash on EVERY successful exit path so `dev.rs` and
        // the freshness helpers don't need a parallel writer that
        // would (a) duplicate the write and (b) clobber the v6 mtime
        // / linker metadata with a stale single-line bare hash. The
        // empty-deps case is meaningful when the project transitioned
        // from "had deps" → "removed all deps": the hash captures the
        // post-removal state so a future freshness check sees a
        // consistent fingerprint instead of the pre-removal hash.
        materialize_empty_install_artifacts(project_dir)?;
        write_post_install_v6_hash(project_dir, linker_mode);
        return Ok(());
    }

    // read the persisted override state and
    // compute whether the override set has drifted since the last
    // recorded install. This MUST run BEFORE the `--offline` branch
    // so that:
    //
    // 1. **Online mode** can drop the lockfile fast path on drift and
    // force a fresh resolve.
    // 2. **Offline mode** can hard-error on drift (since it can't
    // re-resolve) and can write/delete the state file alongside
    // the link step.
    //
    // This must run before the offline branch can return; otherwise the
    // offline path silently shadows override edits, never writes a state
    // file, and never cleans up stale state.
    let prior_overrides_state = overrides_state::read_state(project_dir);
    let overrides_changed = prior_overrides_state
        .as_ref()
        .map_or(!override_set.is_empty(), |s| {
            s.fingerprint != override_set.fingerprint()
        });
    if overrides_changed {
        tracing::debug!(
            "overrides changed since last install (fingerprint drift) — \
             invalidating lockfile fast path"
        );
    }

    //
    // Mirror of the overrides drift detection. Patches must be
    // checked BEFORE the offline branch so:
    // 1. Online mode can drop the lockfile fast path on drift and
    // force a fresh resolve (the patches themselves don't affect
    // resolution, but a re-applied patch is required after any
    // re-link).
    // 2. Offline mode can hard-error on drift since it can't
    // re-resolve to bring the lockfile in sync.
    let prior_patch_state = patch_state::read_state(project_dir);
    let patches_changed = prior_patch_state
        .as_ref()
        .map_or(!current_patches.is_empty(), |s| {
            s.fingerprint != current_patch_fingerprint
        });
    if patches_changed {
        tracing::debug!(
            "patches changed since last install (fingerprint drift) — \
             invalidating lockfile fast path"
        );
    }

    // Step 2: Try lockfile fast path, else resolve
    // Capture pre-install direct-dep versions BEFORE the resolver writes
    // a fresh lockfile. The Done block compares against this snapshot to
    // print the `+ pkg@version` diff list — only direct deps that
    // CHANGED in this run (newly installed or upgraded). A bare
    // `lpm install` that does no work prints no list; `lpm i react`
    // prints just `+ react@…`; a hand-edited manifest prints exactly the
    // diff. Reading from the lockfile (not from `node_modules`) keeps
    // the snapshot cheap and robust against partial installs.
    let pre_install_direct_versions: HashMap<String, String> = if lockfile_path.exists() {
        lpm_lockfile::Lockfile::read_fast(&lockfile_path)
            .ok()
            .map(|lf| collect_locked_direct_versions(&pkg, &lf))
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    // — apply `.npmrc`-derived TLS overrides to the cloned
    // client BEFORE any network use, then shadow the parameter so every
    // downstream callsite (including the `try_lockfile_fast_path` /
    // `download_tarball_streaming_routed` paths that take `client`
    // directly, not `arc_client`) sees the configured client. The
    // `route_table` itself was built earlier (above the empty-deps
    // short-circuit) so its warnings always surface.
    //
    // `top_level_specs` + `eager_origins` are computed above (where the
    // slim-UI resolving line consumes them) — both surfaces must agree
    // on the same route map, so they share one derivation. Workspace-
    // member file refs, link/file/tarball/git specs, and unparseable
    // ranges all contribute no origin per `Specifier::parse`.
    let owned_client = client
        .clone_with_config()
        .with_tls_overrides_for(route_table.tls_overrides(), &eager_origins)?;
    let client = &owned_client;
    // — emit a one-line summary of EFFECTIVE TLS overrides
    // (default surface + eager per-origin clients). `None` ⇒ nothing
    // active ⇒ no line. Suppressed under `--json` so structured stdout
    // stays clean; the strict-ssl=false security warning above remains
    // unconditional regardless.
    if !json_output && let Some(line) = client.render_effective_tls_summary() {
        output::info(&line);
    }

    let arc_client = Arc::new(client.clone_with_config());

    let v2_workspace_root_pre_resolve = if requested_v2_mode {
        pre_resolve_v2_direct_workspace_member_deps(
            project_dir,
            &mut deps,
            &direct_workspace_member_deps,
            &all_workspace_members,
            json_output,
        )?
    } else {
        V2WorkspaceRootPreResolveResult::default()
    };
    if requested_v2_mode {
        workspace_member_deps.clear();
    }

    // Offline mode: require lockfile, no network
    if offline {
        // Offline
        // mode cannot re-resolve, so any fingerprint drift is
        // unsafe: the lockfile would silently shadow the user's
        // override edits. Refuse with a clear, actionable message
        // that tells the user how to recover.
        if overrides_changed {
            let detail = match prior_overrides_state.as_ref() {
                Some(prior) => format!(
                    "previous fingerprint {} differs from current {}",
                    prior.fingerprint,
                    override_set.fingerprint()
                ),
                None if !override_set.is_empty() => {
                    "no previously-recorded override fingerprint; the lockfile may have \
                     been generated without these overrides"
                        .to_string()
                }
                None => "override state inconsistency".to_string(),
            };
            return Err(LpmError::Registry(format!(
                "--offline: override set differs from the lockfile's recorded set ({detail}). \
                 Run `lpm install` (online) to re-resolve, then retry --offline."
            )));
        }

        // same hard-error semantics for the
        // patch set. Offline mode can't re-resolve OR re-fetch a
        // possibly-changed store baseline, so any drift in the
        // declared patch set leaves the install in an unknown state.
        if patches_changed {
            let detail = match prior_patch_state.as_ref() {
                Some(prior) => format!(
                    "previous fingerprint {} differs from current {}",
                    prior.fingerprint, current_patch_fingerprint
                ),
                None if !current_patches.is_empty() => {
                    "no previously-recorded patch fingerprint; the lockfile may have \
                     been written without these patches"
                        .to_string()
                }
                None => "patch state inconsistency".to_string(),
            };
            return Err(LpmError::Registry(format!(
                "--offline: lpm.patchedDependencies differs from the previously-recorded \
                 patch set ({detail}). Run `lpm install` (online) to re-resolve, then retry \
                 --offline."
            )));
        }

        // **Invariant:** offline mode passes `accept_unsafe_sources =
        // true` so the fast-path admits `directory+`/`link+`/
        // `tarball+local` lockfile entries that fresh-resolve fallback
        // would otherwise reject. Online installs at line 3514 stay
        // strict (`false`) — they have the fresh-resolve fallback for
        // any non-admissible lockfile shape, and skipping the fresh-
        // resolve re-checks would be a real correctness regression.
        let fast = try_lockfile_fast_path(
            &lockfile_path,
            &deps,
            &catalog_resolutions,
            client,
            &gate_stats,
            true,
        )
        .ok_or_else(|| {
            LpmError::Registry(
                "--offline could not load the lockfile. Possible causes: (1) lpm.lock is \
                         missing — run `lpm install` online first; (2) lpm.lock is corrupted — \
                         delete it and re-run online; (3) a root dependency in package.json is \
                         absent from the lockfile (e.g., declared but never installed online). \
                         Run `lpm install` online to reconcile."
                    .into(),
            )
        })?;
        // Same repair-gate semantic as
        // the online path, but `--offline` can't re-resolve to
        // re-derive the missing. The choice is between
        // replaying a known-broken tree (older lockfiles from builds
        // with the peer-tracking bug were missing
        // `ambient-peer-installs` and per-package `peers`, so
        // `node_modules/<auto-installed-peer>/` is dropped on
        // replay and `require('react-redux')` hard-fails at runtime)
        // and refusing the install with an actionable message.
        // Refusing is the only safe answer: the offline path
        // cannot detect whether the v1 lockfile was ever buggy or
        // always correct, so it has to assume the worst when
        // `auto_install_peers` is on.
        if lockfile_needs_peer_state_repair(&fast.lockfile, auto_install_peers) {
            return Err(LpmError::Registry(
                "--offline cannot use a pre-R2.5 lockfile under \
                 `lpm.autoInstallPeers = true`: the lockfile may be missing \
                 ambient-peer-install state. Run \
                 `lpm install` (online) once to re-derive and upgrade the \
                 lockfile to v2, then retry --offline. To bypass this check \
                 and accept warn-only peer semantics, set \
                 `lpm.autoInstallPeers = false` in package.json."
                    .into(),
            ));
        }
        let mut locked = fast.packages; // Offline mode skips the writeback machinery —
        // no fetch happens, no URLs diverge, and any v1
        // → v2 binary migration is deferred to the next
        // online install (intentional — `--offline` is
        // the "don't touch anything remote" mode).
        if omit_policy.dev {
            filter_dev_packages(&mut locked, &production_dependency_names);
        }
        let _platform_skipped = filter_platform_packages(&mut locked)?;
        if !json_output {
            output::info(&format!(
                "Offline: using lockfile ({} packages)",
                locked.len().to_string().bold()
            ));
        }

        // Verify all packages are in the global store
        let store = PackageStore::from_root(lpm_root);
        let store_v2 = requested_v2_mode.then(|| lpm_store::v2::Store::from_lpm_root(lpm_root));
        let mut missing = Vec::new();
        for p in &locked {
            // Source-aware existence check for the offline gate.
            // Source::Tarball lives in the integrity-keyed CAS, so
            // a `(name, version)`-keyed registry hit doesn't satisfy
            // it. Trust-on-first-use Source::Tarball (no integrity
            // recorded) is treated as missing — offline mode can't
            // legally fetch, so the install must abort with a clear
            // missing-package signal.
            if !p.store_has_for_install_layout(&store, store_v2.as_ref(), project_dir) {
                missing.push(format!("{}@{}", p.name, p.version));
            }
        }
        if !missing.is_empty() {
            return Err(LpmError::Registry(format!(
                "--offline: {} package(s) not in global store: {}",
                missing.len(),
                missing[..missing.len().min(5)].join(", ")
            )));
        }

        // **— state file lifecycle in offline mode
        // .** Reaching this point means the fingerprint
        // check above passed — i.e., the on-disk state file matches
        // the current parsed override set, OR both sides are empty.
        // Two sub-cases:
        //
        // - **Both empty** (`prior` is `None`, `current.is_empty()`):
        // no state file exists and none should — nothing to do.
        // - **Both have the SAME non-empty fingerprint**: the state
        // file is already correct; preserving it across an offline
        // install matches what `lpm graph --why` consumers expect.
        //
        // We do NOT rewrite the state file here. The `applied` trace
        // belongs to the most recent FRESH resolution; offline mode
        // never re-resolves and would produce an empty trace, which
        // would be a regression for `graph --why`. Preserving the
        // existing trace is correct.
        //
        // The "user removed all overrides offline" cleanup case is
        // handled UPSTREAM by the fingerprint hard-error: removing
        // overrides flips the fingerprint, which trips the
        // `overrides_changed` branch above, returning a clear
        // "re-resolve online" error.

        // **invariant (round 6) — offline path runs
        // workspace-member BFS too.** Pre-the invariant the offline arm
        // passed the EXTRACTED top-level `workspace_member_deps`
        // slice straight to `run_link_and_finish` and missed
        // transitive `workspace:` refs in member manifests, dropping
        // root symlinks the online path would have planted. The
        // helper expands the slice before dispatch so both modes
        // produce the same root-symlink set. Pre-the invariant/6 the
        // -deduped + the invariant-transitive merge step ran at the
        // online callsite — in offline mode there's no pre_resolve
        // (nothing to merge), so the BFS is the only expansion that
        // applies. (The the invariant pre-pass at install start has
        // already populated `workspace_member_deps` with file:/link:
        // deps that match members, so the BFS seed set already
        // includes those.)
        merge_workspace_member_links(
            &mut workspace_member_deps,
            v2_workspace_root_pre_resolve
                .additional_workspace_links
                .iter()
                .cloned(),
        );
        expand_workspace_member_deps_with_transitives(
            &mut workspace_member_deps,
            &all_workspace_members,
        )?;
        enforce_registry_integrity_policy(&locked, strict_integrity, json_output)?;
        if verify_registry_signatures {
            enforce_registry_signature_policy(
                Arc::clone(&arc_client),
                &route_table,
                &locked,
                json_output,
                false,
                registry_signature_timings.clone(),
            )
            .await?;
        }

        // Go directly to link step (skip resolution and download).
        // forward the already-resolved
        // script-policy override so the link-and-finish path shows
        // the same triage summary line the fresh-resolution path
        // would.
        return run_link_and_finish(
            client,
            project_dir,
            &deps,
            &pkg,
            locked,
            &v2_workspace_root_pre_resolve.install_pkgs,
            &v2_workspace_root_pre_resolve.source_deps,
            0,
            0,
            true,
            json_output,
            start,
            linker_mode,
            force,
            &workspace_member_deps,
            script_policy_override,
            lpm_root,
            &global_config,
            auto_build,
            no_sandbox,
            strict_sandbox,
            compatibility_bin_names,
        )
        .await;
    }

    // `auto_install_peers` and `pubgrub_opt_out` are
    // computed at the top of `run_with_options` (above the empty-deps
    // short-circuit) so the pubgrub-mismatch warning fires regardless
    // of which install codepath ultimately runs. The lockfile-repair
    // gate below reuses the same `auto_install_peers` value.

    // --force skips lockfile fast path to force fresh resolution from registry.
    // --overrides-changed also skips it.
    // --patches-changed also skips it — re-applying a
    // patch that's been added or moved since the last install requires
    // a clean re-link from store before the patch engine runs, and the
    // lockfile fast path bypasses linker work.
    // Add-path installs also skip it: once the manifest has been
    // staged with new top-level entries, a stale lockfile can contain
    // the same package name only transitively, which is insufficient to
    // answer what concrete direct version the add path should pick.
    let lockfile_result = if frozen_lockfile_active {
        let candidate = try_lockfile_fast_path(
            &lockfile_path,
            &deps,
            &catalog_resolutions,
            client,
            &gate_stats,
            false,
        )
        .ok_or_else(|| {
            LpmError::Registry(
                "Frozen lockfile mismatch\n  lockfile    lpm.lock\n  hint        lockfile cannot satisfy the current manifest; run `lpm install` locally and commit lpm.lock, or pass --no-frozen-lockfile"
                    .into(),
            )
        })?;
        if lockfile_needs_peer_state_repair(&candidate.lockfile, auto_install_peers) {
            return Err(LpmError::Registry(format!(
                "Frozen lockfile mismatch\n  lockfile    v{}\n  required    v{}\n  hint        run `lpm install` locally and commit the upgraded lpm.lock",
                candidate.lockfile.metadata.lockfile_version,
                lpm_lockfile::LOCKFILE_VERSION,
            )));
        }
        Some(candidate)
    } else if force || overrides_changed || patches_changed || is_add_invocation {
        None
    } else {
        // Online installs keep the safety gate strict
        // (`accept_unsafe_sources = false`): if the lockfile contains
        // a `directory+` / `link+` / `tarball+local` source, bail to
        // fresh resolve. The offline arm at line 3395 passes `true`
        // and trusts the lockfile because fresh-resolve isn't
        // available offline.
        let candidate = try_lockfile_fast_path(
            &lockfile_path,
            &deps,
            &catalog_resolutions,
            client,
            &gate_stats,
            false,
        );
        match candidate {
            Some(fast) if lockfile_needs_peer_state_repair(&fast.lockfile, auto_install_peers) => {
                if !json_output {
                    output::info(
                        "Lockfile is in an older format; rebuilding to capture \
                         peer auto-install state. Subsequent installs will be fast.",
                    );
                }
                None
            }
            other => other,
        }
    };
    // applied-override trace for the rest of the
    // install pipeline. Empty for the lockfile-fast-path branch (we
    // preserve the previously-recorded trace from disk in that case);
    // populated for fresh resolution from the resolver's apply log.
    let mut applied_overrides: Vec<OverrideHit> = Vec::new();

    // best-effort peer-conflict
    // reports from the resolver. Each entry is one peer canonical
    // whose required consumer ranges were pairwise-incompatible: the
    // resolver picked the version satisfying the most consumers and
    // recorded the unsatisfied ones here. Surfaced as a `WARN` block
    // in text mode AND as the always-present `peer_conflicts` array
    // on `--json` output so machine consumers (CI, dashboards, audit
    // tooling) can rely on the field's existence.
    //
    // Empty for the lockfile-fast-path (no fresh resolve); empty when
    // the peer graph is clean. Always serialized as an array — even
    // empty — to match the `applied_patches` shape contract that
    // tooling already depends on.
    let mut peer_conflicts: Vec<lpm_resolver::PeerConflictReport> = Vec::new();
    let mut peer_warnings: Vec<PeerWarning> = Vec::new();

    // ambient peer installs synthesized by the resolver,
    // captured here so the cold-resolve lockfile-write site below
    // can persist them. Empty when the fast path takes over (we
    // already have the lockfile, no need to re-derive); populated by
    // the fresh-resolve branch from
    // `resolve_result.ambient_peer_installs`.
    let mut ambient_peer_installs_for_lockfile: Vec<String> = Vec::new();

    //: fetch semaphore hoisted out of the fetch loop so the
    // optional speculative dispatcher can share the download
    // pool with the post-resolve real-fetch loop. Without sharing, a
    // spec dispatcher racing alongside the later real loop would
    // saturate the network for no wall-clock win. One pool,
    // used first by speculation, then drained by real fetch.
    let fetch_semaphore = Arc::new(Semaphore::new(max_concurrent_downloads()));
    let fetch_extract_limiter = configured_fetch_extract_limiter(requested_v2_mode);
    // `LPM_STREAM_FETCH=0` falls back to the temp-file spool path for both
    // early overlap fetches and the post-resolve fetch loop.
    let streaming_fetch = std::env::var("LPM_STREAM_FETCH").map_or(true, |v| v != "0");
    //: also hoist the `PackageStore` so the speculative
    // dispatcher can write tarballs into the real store during the
    // resolve phase. Post-resolve, the fetch loop rebinds to the same
    // handle (cheap Arc-style clone underneath).
    let store = PackageStore::from_root(lpm_root);
    // confidence-followup S5b — `lpm_root` lifted to function
    // scope so post-install helpers (`show_install_build_hint`,
    // `all_scripted_packages_trusted`) can reach the v2 store via
    // `find_installed_package_baseline`. Previously, those helpers took
    // `&PackageStore` (v1-only) and silently dropped every v2-installed
    // scripted package — auto-build never fired, build hints reported
    // 0 packages even when prisma / esbuild / sharp were waiting.
    // — read the store-version flag once per
    // install. `LPM_STORE_VERSION=v2` opts in to the virtual-store
    // pipeline; everything else (unset, "v1", typos) takes the v1
    // path that's been shipping.
    //
    // The v2 store handle is constructed eagerly when the flag is
    // active, then wrapped in `Arc` so per-package spawn tasks can
    // capture a cheap clone alongside the v1 `store_ref`. Holding
    // it as `Option<Arc<…>>` keeps the v1-default code path
    // allocation-free.
    let store_version = lpm_store::StoreVersion::from_env();
    let store_v2_handle: Option<std::sync::Arc<lpm_store::v2::Store>> = if store_version.is_v2() {
        Some(std::sync::Arc::new(lpm_store::v2::Store::from_lpm_root(
            lpm_root,
        )))
    } else {
        None
    };
    if store_v2_handle.is_some() {
        tracing::info!(
            "{}=v2 — install pipeline routing object extracts to ~/.lpm/store/v2/",
            lpm_store::StoreVersion::ENV_VAR
        );
    }

    // — silent v1 → v2 layout migration on first
    // v2-mode install in this project.
    //
    // Detection (design): the project is on v1 if either
    // `<project>/.lpm/wrappers/` or `<project>/.lpm/hoisted/` exists.
    // Both are wiped during migration so the v2 install can populate
    // a clean slate. The store-side `~/.lpm/store/v1/` is NOT touched
    // here — it may still serve other projects on the same machine.
    // `lpm store clean` is the blunt-wipe escape hatch.
    //
    // Migration is idempotent: re-running on partial state succeeds
    // (every `rm -rf` is a no-op on already-clean state). A crash
    // mid-migration leaves a half-wiped project; the next install
    // re-runs the same wipes and re-attempts the v2 install.
    if store_v2_handle.is_some() && needs_v2_migration(project_dir) {
        if !json_output {
            output::info("migrating to v2 store layout (one-time, ~5\u{2013}10s)");
        }
        migrate_v1_to_v2(project_dir)
            .map_err(|e| LpmError::Registry(format!("v1→v2 migration failed: {e}")))?;
    }

    let installer_spike_requested = installer_spike::enabled();
    let installer_spike_script_policy_is_default = if installer_spike_requested {
        let script_policy_cfg =
            crate::script_policy_config::ScriptPolicyConfig::from_package_json(project_dir);
        let effective_policy = crate::script_policy_config::resolve_script_policy_with_security(
            project_dir,
            script_policy_override,
            &script_policy_cfg,
            json_output,
        )?;
        script_policy_cfg == crate::script_policy_config::ScriptPolicyConfig::default()
            && effective_policy == crate::script_policy_config::ScriptPolicy::Deny
    } else {
        true
    };

    if installer_spike::should_run(installer_spike::InstallerSpikeAdmission {
        json_output,
        frozen_lockfile_active,
        omit_policy,
        has_workspace_member_deps: !workspace_member_deps.is_empty()
            || !direct_workspace_member_deps.is_empty(),
        has_v2_workspace_member_deps: !v2_workspace_root_pre_resolve.install_pkgs.is_empty()
            || !v2_workspace_root_pre_resolve
                .additional_workspace_links
                .is_empty(),
        has_tarball_source_deps: installer_spike::has_tarball_source_deps(project_dir, &deps),
        has_patches: !current_patches.is_empty(),
        patches_changed,
        verify_registry_signatures,
        strict_integrity,
        force_security_floor,
        auto_build,
        script_policy_override,
        script_policy_is_default: installer_spike_script_policy_is_default,
        has_trusted_dependencies: pkg
            .lpm
            .as_ref()
            .is_some_and(|lpm| !lpm.trusted_dependencies.is_empty()),
        strict_release_age_replay: release_age_policy.is_strict() && effective_min_age_secs > 0,
        allow_new,
        is_add_invocation,
        has_direct_versions_out: direct_versions_out.is_some(),
        has_target_set: target_set.is_some(),
        audit_after_install,
        no_skills,
        no_security_summary,
        verbose,
        drift_ignore_policy_is_default: matches!(
            &drift_ignore_policy,
            crate::provenance_fetch::DriftIgnorePolicy::EnforceAll
        ),
        verify_policy_is_default: matches!(
            verify_policy.enforce,
            crate::provenance_fetch::EnforceMode::Deny
        ) && matches!(
            &verify_policy.skip,
            crate::provenance_fetch::SkipPolicy::None
        ),
    })? {
        let NonRegistryPreResolveResult {
            install_pkgs: mut spike_pre_resolved_install_pkgs,
            source_deps: mut spike_pre_resolved_source_deps,
            additional_workspace_links,
        } = pre_resolve_non_registry_deps(
            &arc_client,
            &store,
            project_dir,
            &mut deps,
            json_output,
            strict_integrity,
            &all_workspace_members,
        )
        .await?;

        merge_workspace_member_links(
            &mut workspace_member_deps,
            additional_workspace_links.into_iter().chain(
                v2_workspace_root_pre_resolve
                    .additional_workspace_links
                    .iter()
                    .cloned(),
            ),
        );
        expand_workspace_member_deps_with_transitives(
            &mut workspace_member_deps,
            &all_workspace_members,
        )?;
        spike_pre_resolved_install_pkgs
            .extend(v2_workspace_root_pre_resolve.install_pkgs.iter().cloned());
        for (source, deps) in &v2_workspace_root_pre_resolve.source_deps {
            spike_pre_resolved_source_deps
                .entry(source.clone())
                .or_insert_with(|| deps.clone());
        }

        return installer_spike::run(
            arc_client.clone(),
            project_dir,
            &deps,
            &pkg,
            route_table.clone(),
            json_output,
            start,
            linker_mode,
            force,
            lpm_root,
            store_v2_handle.clone(),
            compatibility_bin_names,
            override_set.clone(),
            resolver_policy.clone(),
            auto_install_peers,
            !omit_policy.optional,
            &spike_pre_resolved_install_pkgs,
            &spike_pre_resolved_source_deps,
            &workspace_member_deps,
            &all_workspace_members,
            &catalog_resolutions,
        )
        .await;
    }

    // pre-resolve direct
    // tarball-URL deps from the manifest BEFORE the resolver runs.
    // Each tarball-URL dep is downloaded, extracted into the
    // integrity-keyed CAS, and turned into an InstallPackage with
    // `source = "tarball+<url>"`. The resolver only sees the
    // remaining registry-style deps. The merged package list is
    // assembled post-resolver below.
    let NonRegistryPreResolveResult {
        install_pkgs: tarball_url_install_pkgs,
        source_deps: non_registry_source_deps,
        additional_workspace_links,
    } = pre_resolve_non_registry_deps(
        &arc_client,
        &store,
        project_dir,
        &mut deps,
        json_output,
        strict_integrity,
        // Invariant invariant: pass the FULL workspace membership
        // set (`all_workspace_members`), not the extracted top-level
        // subset (`workspace_member_deps`). overlap detection AND
        // the the invariant transitive `workspace:` check both need to see
        // every member, regardless of whether the consumer's root
        // explicitly references them via `workspace:*`. See the
        // construction comment near line 2807.
        &all_workspace_members,
    )
    .await?;

    // Merge the workspace members discovered through dedupe
    // (immediate file:/link: + transitive walker) and the transitive
    // `workspace:` arm into the slice that drives `link_workspace_members`.
    // Dropping either branch leaves the root-symlink set incomplete:
    // - `"foo": "file:./packages/foo"` where foo is a member
    // produced no `node_modules/foo` after install.
    // - `"foo": "workspace:*"` + foo's `bar: workspace:*` produced
    // `node_modules/foo` but no `node_modules/bar`.
    //
    // Dedupe key: `(name, canonical source_dir)`. Same name pointing
    // at the same realpath = one entry; aliased references (e.g.,
    // consumer's `"alias-of-foo": "file:./packages/foo"` plus
    // `"foo": "workspace:*"`) get distinct entries so each gets its
    // own `node_modules/<name>` symlink. (`workspace_member_deps` is
    // mutable from its declaration site; the invariant hoisted the
    // pre-pass before the offline/online dispatch.)
    merge_workspace_member_links(
        &mut workspace_member_deps,
        additional_workspace_links.into_iter().chain(
            v2_workspace_root_pre_resolve
                .additional_workspace_links
                .iter()
                .cloned(),
        ),
    );

    // **Invariant invariant — factor BFS into helper.** The
    // the invariant BFS lived inline here, which left the offline branch
    // at `run_link_and_finish` (install.rs:3252) without expansion
    // — the regression reproduced an offline install dropping
    // `node_modules/bar`. Helper now lives at
    // `expand_workspace_member_deps_with_transitives` and is called
    // from BOTH the online path (here, after merge of
    // `additional_workspace_links`) AND the offline path (right
    // before `run_link_and_finish` is invoked).
    expand_workspace_member_deps_with_transitives(
        &mut workspace_member_deps,
        &all_workspace_members,
    )?;

    // stats — filled by the speculation dispatcher drain.
    let mut spec_stats = SpeculativeStats::default();
    let spec_tracker = SpeculativeKeyTracker::default();

    //: shared fetch coordinator — serializes per-key fetch
    // work across the speculative dispatcher and the real fetch loop
    // now that the drain-wait between them is gone.
    let fetch_coord: Arc<FetchCoordinator> = Arc::new(FetchCoordinator::default());

    // Speculation handles are hoisted out of the fresh-resolve arm so
    // the main task drains them after the real fetch loop. Awaiting
    // the dispatcher early removes the resolve/fetch overlap.
    let mut speculation_join: Option<SpeculationJoin> = None;
    let mut fetch_overlap_join: Option<FetchOverlapJoin> = None;
    // Post-lockfile metadata: which resolver actually ran.
    // Stamped into `lpm.lock`'s `resolved-with` field at the cold-
    // write site below. Defaults to the greedy-fusion install default
    // (matches `Lockfile::new()`) and is overridden inside the fresh-
    // resolve dispatch branch when the legacy walker arm or the
    // PubGrub escape hatch fires. Previously this field was hardcoded
    // to "pubgrub" inside `Lockfile::new`, so every default install
    // post-v0.28.0 wrote a lie into the lockfile.
    let mut resolved_with: &'static str = "greedy-fusion";
    //: streaming-BFS observability counters. Shared Arc
    // between the resolver (incrementing inside `ensure_cached` +
    // `direct_fetch_and_cache`) and the JSON-output block that
    // snapshots the counts for `timing.resolve.streaming_bfs`.
    // Declared at outer scope because the JSON emit is outside the
    // fresh-resolve arm. Stays default-zero on the warm lockfile-
    // fast-path where the walker never runs.
    let streaming_metrics = lpm_resolver::StreamingBfsMetrics::new();

    //a — substage breakdown of cold-resolve wall-clock.
    // Captured here (outside the fresh/warm branch) so the JSON output
    // code path can surface a consistent shape whether the lockfile
    // fast path kicked in or not. Zeros on lockfile-fast-path;
    // populated from the resolver on fresh resolution.
    let mut initial_batch_ms: u128 = 0;
    let mut resolver_stage_timing = lpm_resolver::StageTiming::default();

    // — stash the parsed lockfile + `needs_binary_upgrade`
    // flag from the fast path so the writeback step at install-end
    // can patch + re-emit it. `None` on fresh-resolve branches (the
    // resolver builds its own lockfile via `resolved_to_install_packages`
    // and the writer at install-end already handles that case).
    let mut fast_path_lockfile: Option<lpm_lockfile::Lockfile> = None;
    let mut lockfile_peer_context_authoritative = false;
    let mut needs_binary_upgrade = false;

    // `route_table` is built upstream of this fork (
    // hoisted it above the lockfile-vs-resolve match so custom-
    // registry tarball auth + stale-tarball invalidation work on both
    // arms; hoisted it further to above the empty-deps
    // short-circuit so TLS overrides + `strict-ssl=false` security
    // warning surface for empty-deps installs too).
    let wf_setup_ms = start.elapsed().as_millis();
    let (mut packages, resolve_ms, used_lockfile, mut platform_skipped, latest_stable_versions) =
        match lockfile_result {
            Some(fast_path) => {
                if !json_output {
                    output::info(&format!(
                        "Using lockfile ({} packages)",
                        fast_path.packages.len().to_string().bold()
                    ));
                }
                lockfile_peer_context_authoritative = fast_path.lockfile.metadata.lockfile_version
                    >= MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE;
                fast_path_lockfile = Some(fast_path.lockfile);
                needs_binary_upgrade = fast_path.needs_binary_upgrade;
                // Fast path doesn't run the resolver, so we have no
                // registry metadata — the `+` list's "(vX.Y.Z available)"
                // hint is suppressed in this branch. Honest > guessing.
                (fast_path.packages, 0u128, true, 0usize, HashMap::new())
            }
            None => {
                let resolve_start = Instant::now();
                // The persistent `› Resolving …` phase line above already
                // narrates that resolution is in flight — no spinner needed.

                // route_table is constructed above the lockfile match
                // () — we just borrow/clone it here.

                // **Default flip .** Greedy-fusion is now the
                // global install default. The fused dispatcher
                // (`resolve_greedy_fused`) skips the walker spawn entirely
                // and IS the metadata fetch dispatcher.
                //
                // Resolver dispatch matrix:
                //
                // | LPM_RESOLVER | LPM_GREEDY_FUSION | Result |
                // |-----------------|-------------------|-------------------------|
                // | unset (default) | unset / non-"0" | greedy-fusion (new) |
                // | unset (default) | "0" | greedy + legacy walker |
                // | "greedy" | unset / non-"0" | greedy-fusion |
                // | "greedy" | "0" | greedy + legacy walker |
                // | "pubgrub" | (any) | PubGrub + legacy walker |
                //
                // Escape hatches:
                // - `LPM_RESOLVER=pubgrub` — full opt-out to the previous
                // install default (PubGrub-with-split-retry + walker).
                // Use only if you hit a greedy-fusion edge case in the
                // wild and need a tested fallback while we land a fix.
                // - `LPM_GREEDY_FUSION=0` — opt-out from the fused
                // dispatcher to the legacy walker arm ( // orchestration: walker + dispatcher +
                // resolver_with_shared_cache in parallel) while still
                // using the greedy resolver. Useful for debugging
                // dispatcher-specific issues with greedy-resolver
                // behavior held constant.
                //
                // Reference n=20 bench (median, bench/fixture-large) from
                //:
                // greedy-stream (walker) 4,521 ms total
                // greedy-fusion 918 ms total — 1.10× bun
                // bun reference 833 ms
                // -3,603 ms median delta, paired t = -23.27. The default-
                // flip preserves these numbers (now reachable without the
                // `LPM_RESOLVER=greedy` opt-in env var).
                // `pubgrub_opt_out` and `auto_install_peers`
                // are computed at the top of `run_with_options` (above
                // the lockfile fast-path call) so the v1-lockfile gate
                // and the pubgrub-mismatch warning fire even on warm
                // installs that take the lockfile fast path. The two
                // values are reused unchanged here.
                let fusion_disabled = std::env::var("LPM_GREEDY_FUSION").as_deref() == Ok("0");
                let fusion_enabled_local = !pubgrub_opt_out && !fusion_disabled;

                // Stamp `lpm.lock`'s `resolved-with` field with the arm
                // that's about to run. Mirrors the dispatch matrix in the
                // comment block above. Read by the cold-resolve writer
                // at the bottom of `run_with_options`.
                resolved_with = if pubgrub_opt_out {
                    "pubgrub"
                } else if fusion_disabled {
                    "greedy"
                } else {
                    "greedy-fusion"
                };

                let (resolve_res, initial_batch_ms_measured): (
                    Result<lpm_resolver::ResolveResult, LpmError>,
                    u128,
                ) = if fusion_enabled_local {
                    // ── FUSION PATH ─────────────────────────────────────
                    let npm_fanout = positive_usize_env_or_default(
                        "LPM_NPM_FANOUT",
                        default_fusion_npm_fanout_for_policy(resolver_min_age_secs),
                    );
                    let speculation_permits = positive_usize_env_or_default(
                        ENV_FUSION_SPECULATION_PERMITS,
                        DEFAULT_FUSION_SPECULATION_PERMITS,
                    );

                    let shared_cache: lpm_resolver::SharedCache = Arc::new(dashmap::DashMap::new());
                    seed_workspace_resolver_cache(&shared_cache, &all_workspace_members);
                    let (spec_tx, spec_rx) =
                        tokio::sync::mpsc::channel::<(String, SpeculativePackageMetadata)>(512);
                    let (dispatcher_handle, dispatcher_counters) = spawn_speculation_dispatcher(
                        spec_rx,
                        arc_client.clone(),
                        route_table.clone(),
                        store.clone(),
                        fetch_semaphore.clone(),
                        Some(Arc::new(Semaphore::new(speculation_permits))),
                        fetch_coord.clone(),
                        deps.clone(),
                        spec_tracker.clone(),
                        store_v2_handle.clone(),
                        fetch_extract_limiter.clone(),
                    );
                    let selected_package_tx = if fetch_overlap_enabled(fusion_enabled_local, force)
                    {
                        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                        fetch_overlap_join = Some(spawn_fetch_overlap_dispatcher(
                            rx,
                            arc_client.clone(),
                            route_table.clone(),
                            store.clone(),
                            store_v2_handle.clone(),
                            fetch_semaphore.clone(),
                            fetch_coord.clone(),
                            project_dir.to_path_buf(),
                            gate_stats.clone(),
                            fetch_extract_limiter.clone(),
                            streaming_fetch,
                            fetch_overlap_min_selected(),
                        ));
                        Some(tx)
                    } else {
                        None
                    };
                    let res = lpm_resolver::resolve_greedy_fused_with_cache_options_policy_and_selected_events(
                        arc_client.clone(),
                        deps.clone(),
                        override_set.clone(),
                        route_table.clone(),
                        npm_fanout,
                        Some(spec_tx),
                        shared_cache,
                        auto_install_peers,
                        !omit_policy.optional,
                        resolver_policy.clone(),
                        selected_package_tx,
                    )
                    .await
                    .map_err(crate::resolver_error::resolver_error_to_lpm);

                    // initial_batch_ms is meaningless under fusion (no
                    // walker → no roots-ready boundary); 0 reads as
                    // "lockfile fast path" in --json which is technically
                    // wrong but harmless — the real story is in
                    // `timing.resolve.dispatcher.*` (W1 plumbing).
                    speculation_join = Some(SpeculationJoin {
                        producer: None,
                        dispatcher: dispatcher_handle,
                        dispatched: dispatcher_counters.dispatched,
                        completed: dispatcher_counters.completed,
                        task_ms_sum: dispatcher_counters.task_ms_sum,
                        transitive_dispatched: dispatcher_counters.transitive_dispatched,
                        max_depth_reached: dispatcher_counters.max_depth_reached,
                        no_version_match: dispatcher_counters.no_version_match,
                        unresolved_parked: dispatcher_counters.unresolved_parked,
                        failed: dispatcher_counters.failed,
                        skipped_no_permit: dispatcher_counters.skipped_no_permit,
                        skipped_auth: dispatcher_counters.skipped_auth,
                    });
                    (res, 0u128)
                } else {
                    // ── LEGACY PATH (walker + spec dispatcher) ──
                    let dep_names: Vec<String> = deps.keys().cloned().collect();

                    // orchestration (design): spawn walker +
                    // dispatcher; resolve concurrently waiting on roots_ready.
                    // Walker is the manifest producer; the dispatcher is the
                    // pure consumer of the existing `(name, SpeculativePackageMetadata)`
                    // mpsc. The three run in parallel — walker fetches,
                    // dispatcher speculates tarballs, resolver waits on
                    // roots_ready_rx then solves against the shared cache.
                    //
                    // Critically: walker + dispatcher `JoinHandle`s are NOT
                    // awaited here. They're bundled into `SpeculationJoin` below
                    // and drained at the existing post-fetch drain point —
                    // preserving the speculation overlap and
                    // matching design's "tail drains post-fetch, not
                    // aborted" invariant.
                    use lpm_resolver::{BfsWalker, NotifyMap, SharedCache, WalkerDone};
                    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
                    seed_workspace_resolver_cache(&shared_cache, &all_workspace_members);
                    let notify_map: NotifyMap = Arc::new(dashmap::DashMap::new());
                    // wait-loop shutdown handshake: the walker stores
                    // `true` (Release) and broadcasts `notify_waiters()` across
                    // every notify_map entry at the end of its `run()`. The
                    // resolver's wait-loop in `ensure_cached` checks this flag
                    // after `Notified::enable()` and short-circuits to the
                    // escape-hatch fetch in microseconds, instead of burning
                    // the full `fetch_wait_timeout` for keys the walker decided
                    // not to fetch. Same Arc on both sides — must be allocated
                    // before either is constructed.
                    let walker_done: WalkerDone =
                        Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let (spec_tx, spec_rx) =
                        tokio::sync::mpsc::channel::<(String, SpeculativePackageMetadata)>(512);
                    let (roots_ready_tx, roots_ready_rx) = tokio::sync::oneshot::channel::<()>();

                    let batch_start = Instant::now();

                    // Walker — metadata producer.
                    let walker_handle = if dep_names.is_empty() {
                        // No deps → fire roots_ready immediately + flip the
                        // walker_done flag so any (vacuously-empty) wait-loop
                        // sleeper short-circuits, then spawn a no-op task so
                        // the `SpeculationJoin` shape stays uniform.
                        let _ = roots_ready_tx.send(());
                        walker_done.store(true, std::sync::atomic::Ordering::Release);
                        tokio::spawn(async { Ok(lpm_resolver::WalkerSummary::default()) })
                    } else {
                        tokio::spawn(
                            BfsWalker::new(
                                arc_client.clone(),
                                shared_cache.clone(),
                                notify_map.clone(),
                                walker_done.clone(),
                                spec_tx,
                                roots_ready_tx,
                                dep_names.clone(),
                                route_table.clone(),
                            )
                            .run(),
                        )
                    };

                    // Dispatcher — speculation consumer.
                    let (dispatcher_handle, dispatcher_counters) = spawn_speculation_dispatcher(
                        spec_rx,
                        arc_client.clone(),
                        route_table.clone(),
                        store.clone(),
                        fetch_semaphore.clone(),
                        None,
                        fetch_coord.clone(),
                        deps.clone(),
                        spec_tracker.clone(),
                        store_v2_handle.clone(),
                        fetch_extract_limiter.clone(),
                    );

                    // Resolver — awaits roots_ready then solves against the
                    // shared cache. `fetch_wait_timeout` = 5s is the design
                    // default: the provider waits on the per-canonical
                    // Notify for up to 5s before falling through to its
                    // escape-hatch fetch.
                    let resolve_client = arc_client.clone();
                    let resolve_deps = deps.clone();
                    let resolve_overrides = override_set.clone();
                    let shared_cache_for_resolve = shared_cache.clone();
                    let notify_map_for_resolve = notify_map.clone();
                    let walker_done_for_resolve = walker_done.clone();
                    //: clone the outer-scope metrics Arc for the
                    // resolver's ownership; the outer `streaming_metrics`
                    // stays readable by the JSON-emit block via its own Arc
                    // handle.
                    let streaming_metrics_for_resolve = streaming_metrics.clone();
                    // `initial_batch_ms` captures the time from
                    // orchestration start to the moment the resolver could
                    // begin solving — i.e. roots-ready fire. This is the
                    // new-shape analog of the pre-49 "batch prefetch done"
                    // timestamp. Measuring it at the end of resolve (as the
                    // previously code did) lumped in PubGrub wall-clock, which
                    // made the JSON output internally inconsistent — PubGrub
                    // timing is already reported separately by
                    // `resolver_stage_timing.pubgrub_ms`.
                    let (resolve_res_legacy, batch_ms): (
                        Result<lpm_resolver::ResolveResult, LpmError>,
                        u128,
                    ) = async {
                        let _ = roots_ready_rx.await;
                        let roots_ready_at = batch_start.elapsed().as_millis();
                        let w2_resolve_start = Instant::now();
                        let result = lpm_resolver::resolve_with_shared_cache_options_and_policy(
                            resolve_client,
                            resolve_deps,
                            resolve_overrides,
                            shared_cache_for_resolve,
                            notify_map_for_resolve,
                            walker_done_for_resolve,
                            std::time::Duration::from_secs(5),
                            route_table.clone(),
                            streaming_metrics_for_resolve,
                            auto_install_peers,
                            !omit_policy.optional,
                            resolver_policy.clone(),
                        )
                        .await
                        .map_err(crate::resolver_error::resolver_error_to_lpm);
                        tracing::debug!(
                            "perf.w2_resolve_after_roots ms={}",
                            w2_resolve_start.elapsed().as_millis()
                        );
                        (result, roots_ready_at)
                    }
                    .await;

                    speculation_join = Some(SpeculationJoin {
                        producer: Some(walker_handle),
                        dispatcher: dispatcher_handle,
                        dispatched: dispatcher_counters.dispatched,
                        completed: dispatcher_counters.completed,
                        task_ms_sum: dispatcher_counters.task_ms_sum,
                        transitive_dispatched: dispatcher_counters.transitive_dispatched,
                        max_depth_reached: dispatcher_counters.max_depth_reached,
                        no_version_match: dispatcher_counters.no_version_match,
                        unresolved_parked: dispatcher_counters.unresolved_parked,
                        failed: dispatcher_counters.failed,
                        skipped_no_permit: dispatcher_counters.skipped_no_permit,
                        skipped_auth: dispatcher_counters.skipped_auth,
                    });

                    (resolve_res_legacy, batch_ms)
                };
                initial_batch_ms = initial_batch_ms_measured;

                let resolve_result = resolve_res?;

                // The speculation join drains after fetch so downloads
                // dispatched during resolution can overlap the authoritative
                // fetch phase without being awaited early.
                let ms = resolve_start.elapsed().as_millis();

                // Post-resolution peer dependency check: warn about unmet peers
                // using each package's actual selected version (not a union).
                //
                // #33: peer rules from `package.json > lpm.peerDependencyRules`
                // (translated from `pnpm.peerDependencyRules` by `lpm migrate`)
                // are compiled once and applied inside the warning loop.
                // `ignore_missing` suppresses missing-peer warnings,
                // `allow_any` suppresses version-mismatch warnings, and
                // `allowed_versions` widens the accepted range as a fallback.
                //
                // Compile is **fail-closed** — any unparseable selector key
                // or version range in `allowed_versions` aborts the install
                // before any further work. Mirrors the `OverrideSet::parse`
                // posture for `lpm.overrides`. Hand-authored typos surface
                // here rather than silently no-op'ing the rule.
                let peer_rules_cfg = pkg.lpm.as_ref().map(|l| &l.peer_dependency_rules);
                let compiled_peer_rules = match peer_rules_cfg {
                    Some(r) => CompiledPeerRules::compile(
                        &r.ignore_missing,
                        &r.allowed_versions,
                        &r.allow_any,
                    )
                    .map_err(|e| {
                        LpmError::Script(format!("invalid lpm.peerDependencyRules: {e}"))
                    })?,
                    None => CompiledPeerRules::default(),
                };
                peer_warnings = check_unmet_peers(
                    &resolve_result.packages,
                    &resolve_result.cache,
                    &compiled_peer_rules,
                );
                if !peer_warnings.is_empty() && !json_output {
                    for w in &peer_warnings {
                        output::warn(&format!("peer dep: {w}"));
                    }
                }

                // capture the override apply trace
                // from this fresh resolution. We surface it to the install
                // summary, the JSON output, and `.lpm/overrides-state.json`.
                applied_overrides = resolve_result.applied_overrides.clone();

                //capture best-effort peer-conflict reports. Drained
                // alongside applied_overrides so the JSON envelope below
                // can serialize them whether or not the user is running
                // with `--json`. Cloned (not moved) because
                // `resolve_result` is consumed by `resolved_to_install_packages`
                // a few lines down.
                peer_conflicts = resolve_result.peer_conflicts.clone();

                if strict_peer_dependencies
                    && let Some(err) = strict_peer_dependency_error(&peer_warnings, &peer_conflicts)
                {
                    return Err(err);
                }

                if peer_conflict_auto_isolation_allowed {
                    auto_isolated_peer_conflicts = !peer_conflicts.is_empty();
                    linker_mode = if auto_isolated_peer_conflicts {
                        if matches!(configured_linker_mode, lpm_linker::LinkerMode::Hoisted)
                            && !json_output
                        {
                            output::info(
                                "Peer conflicts detected; using isolated linker for this install.",
                            );
                        }
                        lpm_linker::LinkerMode::Isolated
                    } else {
                        configured_linker_mode
                    };
                }

                // — capture the platform-filtered optional
                // skip count. Surfaced as `timing.resolve.platform_skipped`
                // in `--json` output.
                let platform_skipped = resolve_result.platform_skipped;

                // capture the resolver substage
                // breakdown. Combined with the `initial_batch_ms`
                // measurement above, these feed the cold-resolve
                // observability story in `timing.resolve.*`.
                resolver_stage_timing = resolve_result.stage_timing;

                // clone the ambient peer install set BEFORE we
                // hand `resolve_result` off to `resolved_to_install_packages`
                // (which only borrows it). Persisted to the lockfile far
                // below at the cold-resolve write site so warm reinstalls
                // reproduce the same top-level node_modules layout.
                ambient_peer_installs_for_lockfile = resolve_result.ambient_peer_installs.clone();

                let mut packages = resolved_to_install_packages_with_workspace_members(
                    &resolve_result.packages,
                    &deps,
                    &resolve_result.root_aliases,
                    &resolve_result.ambient_peer_installs,
                    &resolve_result.cache,
                    &route_table,
                    &all_workspace_members,
                    project_dir,
                );

                // Snapshot the resolver's metadata cache as
                // `canonical_name → latest stable version`. The map drives
                // the post-install `+` list's `(vX.Y.Z available)` hint
                // when a direct dep was pinned to an older version than
                // the registry's current `latest` stable release.
                let latest_stable = build_latest_stable_versions(&resolve_result.cache);

                // + (manifest wiring): merge
                // in the non-registry InstallPackages produced by
                // `pre_resolve_non_registry_deps`. They were fetched +
                // extracted before the resolver ran (so the source-aware
                // fast-path will mark them cached on the next iteration),
                // but they aren't part of the resolver's output — append
                // them here so the install loop sees the full set.
                packages.extend(tarball_url_install_pkgs.iter().cloned());

                // (-transitive): post-resolve fix-up.
                // Now that BOTH the resolver output AND the non-registry
                // InstallPackages are in `packages`, populate each
                // directory/link InstallPackage's `dependencies` field
                // from its stashed source-deps. Resolver-agnostic per
                // plan — runs once after the merge regardless of
                // PubGrub vs fusion.
                apply_post_resolve_directory_link_fixup(&mut packages, &non_registry_source_deps);
                enforce_registry_integrity_policy(&packages, strict_integrity, json_output)?;

                if !json_output {
                    // Persistent second phase line. Sub-second resolves don't
                    // need their own "Resolved in Xms" beat — the count is
                    // the signal, the timing lands in the verbose footer.
                    let reported_install_count = requested_add_count.unwrap_or(packages.len());
                    install_ui::phase(&format!(
                        "Installing {} {}",
                        reported_install_count.to_string().bold(),
                        install_ui::packages_word(reported_install_count),
                    ));
                    //surface best-effort peer-conflict reports as
                    // warnings so the user knows which transitive
                    // consumers got a peer version outside their declared
                    // range. Mirrors npm v7+'s unconditional `npm WARN`
                    // behavior. Suppressed under `--json` to keep
                    // machine-readable output clean; `--json` consumers
                    // get the same data on the always-present
                    // `peer_conflicts` array in the install JSON envelope
                    // (constructed below).
                    for report in &resolve_result.peer_conflicts {
                        let unsatisfied_str = report
                            .unsatisfied_consumers
                            .iter()
                            .map(|(c, r)| format!("{c} wants {r}"))
                            .collect::<Vec<_>>()
                            .join("; ");
                        output::warn(&format!(
                            "peer {} pinned to {} but {} unsatisfied consumer(s): {}",
                            report.canonical.bold(),
                            report.chosen_version,
                            report.unsatisfied_consumers.len(),
                            unsatisfied_str,
                        ));
                    }
                }
                (packages, ms, false, platform_skipped, latest_stable)
            }
        };
    let wf_resolve_end_ms = start.elapsed().as_millis();

    if requested_v2_mode && !v2_workspace_root_pre_resolve.install_pkgs.is_empty() {
        packages.extend(v2_workspace_root_pre_resolve.install_pkgs.iter().cloned());
        apply_post_resolve_directory_link_fixup(
            &mut packages,
            &v2_workspace_root_pre_resolve.source_deps,
        );
    }
    dedupe_install_packages_by_identity(&mut packages);

    let mut packages_for_lockfile = packages.clone();
    if omit_policy.dev {
        filter_dev_packages(&mut packages, &production_dependency_names);
    }
    platform_skipped += filter_platform_packages(&mut packages)?;

    append_workspace_links_from_local_packages(
        project_dir,
        &packages,
        &mut workspace_member_deps,
        &all_workspace_members,
        &direct_workspace_member_deps,
    );

    if verify_registry_signatures {
        enforce_registry_signature_policy(
            Arc::clone(&arc_client),
            &route_table,
            &packages,
            json_output,
            true,
            registry_signature_timings.clone(),
        )
        .await?;
    }

    let mut walker_summary_final: Option<lpm_resolver::WalkerSummary> = None;
    // Step 3: Download & store (parallel).: `store` is
    // already bound above — speculative dispatcher writes into it
    // during resolve, so by the time we reach here the store may hold
    // tarballs the `has_package` loop below picks up as cache hits.
    let wf_fetch_start_ms = start.elapsed().as_millis();
    let fetch_start = Instant::now();
    let fetch_plan_start = Instant::now();
    let mut fetch_stage_timings = FetchStageTimings::default();
    let mut v2_link_task_timings = V2LinkTaskTimings::default();

    // — aggregation buffer for the generalized writeback.
    // Populated inside the fetch block with every (name, version) →
    // final-URL pair (only when the final URL diverges from the
    // stored lockfile URL). Consumed at install-end to trigger a
    // lockfile rewrite. Hoisted out of the fetch block so the
    // writeback logic (below the block) can see it.
    // ( completion) — keyed on PackageKey so
    // a registry react@19.0.0 and a tarball-URL react@19.0.0 don't
    // clobber each other's writeback URL. Pre-used a
    // (name, version) tuple key.
    let mut fresh_urls: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut integrity_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Pre-compute the per-target
    // patch fingerprint map so each `LinkTarget` carries its own
    // `Some("p-…")` when patched. v2's GraphKey folds it in, splitting
    // patched installs into project-isolated link entries.
    let patch_fingerprints = compute_patch_fingerprints(&current_patches, project_dir)?;

    //b: build link_targets up front so the event-driven
    // path can start per-package linking as each tarball lands.
    // `LinkTarget` fields don't depend on fetch completion — just on
    // resolver output — so building them here is safe. Reused by both
    // the event-driven and serial link paths.
    let source_index = Arc::new(source_dependency_index(&packages));
    let link_targets: Vec<LinkTarget> = packages
        .iter()
        .map(|p| -> Result<LinkTarget, LpmError> {
            // Typed-error path for the source-aware store path.
            // - Source::Tarball (https://) routes to the integrity-
            // keyed CAS.
            // - Source::Tarball (file:) routes to the local-CAS
            // ( follow-up).
            // - Source::Directory / Link routes to the source's
            // canonicalized realpath .
            // - Source::Registry routes to the
            // (name, version)-keyed slot.
            Ok(LinkTarget {
                name: p.name.clone(),
                version: p.version.clone(),
                store_path: p.store_path_or_err(&store, project_dir, None)?,
                dependencies: link_dependencies_for_package(p, &source_index)?,
                aliases: p.aliases.clone(),
                is_direct: p.is_direct,
                root_link_names: p.root_link_names.clone(),
                wrapper_id: p.wrapper_id_for_source(),
                materialization: p.materialization_for_source(),
                peers: p.peers.clone(),
                patch_fingerprint: patch_fingerprints
                    .get(&(p.name.clone(), p.version.clone()))
                    .cloned(),
            })
        })
        .collect::<Result<_, _>>()?;

    //b: event-driven link mode. Per-packagea future release2 work
    // runs inside the fetch pipeline (parallel with tarball downloads
    // of other packages).a future release3.5+4 run as a final batch. Default
    // on for the isolated linker; `LPM_SERIAL_LINK=1` reverts to the
    // single-shot `link_packages` path. Hoisted linker always uses
    // the serial path — it has a different layout model and isn't the
    // hot path for the default `lpm install`.
    let serial_link = std::env::var("LPM_SERIAL_LINK").is_ok_and(|v| v == "1");
    let v2_mode = store_v2_handle.is_some();
    if v2_mode {
        let store_v2 = store_v2_handle
            .as_deref()
            .expect("v2_mode implies v2 store handle is available");
        for target in &link_targets {
            if !matches!(
                target.materialization,
                lpm_linker::Materialization::DirectorySource
            ) {
                continue;
            }
            let sri = local_source_sri_for_target(target);
            store_v2.populate_object_from_local_source(&target.store_path, &sri)?;
        }
    }
    // — under v2 mode, link_packages_v2 needs the
    // full LinkTarget set in one batch so the GraphKey pre-pass can
    // resolve cross-references. Per-package event-driven linking
    // (which v1's isolated path uses) doesn't fit the v2 dispatcher's
    // shape, so v2 always takes the serial path.
    let event_driven_link =
        !serial_link && !v2_mode && matches!(linker_mode, lpm_linker::LinkerMode::Isolated);

    //b: collection of per-package link handles. Cached
    // packages push into this before the fetch loop; fetch tasks push
    // as each tarball materializes. Awaited during the link-finalize
    // step below (post-fetch).
    let mut event_link_handles: Vec<
        tokio::task::JoinHandle<
            Result<(MaterializedPackage, lpm_linker::OnePackageResult), LpmError>,
        >,
    > = Vec::new();

    // followup #6b — event-driven v2 link dispatch.
    //
    // Predicate: the v2 plan can be precomputed BEFORE fetch iff every
    // CAS-backed target arrives with both
    // (a) a known SRI (`p.integrity = Some(_)`), and
    // (b) resolver-threaded peers (`LinkTarget.peers` populated, or
    // the package declares no peer dependencies).
    // Otherwise `link_v2_prepare` would silently produce an
    // empty-peer-context graph key for any target whose peers are
    // discovered post-fetch by reading `objects/<sri>/package.json`,
    // diverging from the serial path. On predicate failure we fall
    // through to today's serial v2 link at the link stage.
    //
    // Local-source targets now get synthetic v2 objects keyed by a
    // stable sha512 of their resolved source identity, so they stay in
    // the same target set as CAS-backed packages during GraphKey
    // derivation and link-entry population.
    //
    // Mode independence: `link_v2_prepare` / `link_v2_one` /
    // `link_v2_finalize` are linker-mode-agnostic for per-package
    // work. `linker_mode` feeds into `LinkerModeTag` which is folded
    // into graph-key derivation (Isolated vs Hoisted both produce
    // valid keys), and `link_v2_finalize` handles project-side
    // wiring identically across modes. So the gate does NOT require
    // Isolated — the post-Hoisted default is fully
    // supported.
    let v2_targets_pre: Vec<lpm_linker::v2::V2Target> = if v2_mode && !serial_link {
        let mut acc: Vec<lpm_linker::v2::V2Target> = Vec::with_capacity(link_targets.len());
        let mut all_have_sri = true;
        for (lt, p) in link_targets.iter().zip(packages.iter()) {
            match lt.materialization {
                lpm_linker::Materialization::CasBacked => match p.integrity.as_deref() {
                    Some(sri) => acc.push(lpm_linker::v2::V2Target {
                        target: lt.clone(),
                        source_sri: sri.to_string(),
                        verified_object_tree_integrity: None,
                    }),
                    None => {
                        all_have_sri = false;
                        break;
                    }
                },
                lpm_linker::Materialization::DirectorySource => {
                    acc.push(lpm_linker::v2::V2Target {
                        target: lt.clone(),
                        source_sri: local_source_sri_for_target(lt),
                        verified_object_tree_integrity: None,
                    });
                }
            }
        }
        if all_have_sri { acc } else { Vec::new() }
    } else {
        Vec::new()
    };
    // Why `v2_linking_can_prepare_before_fetch` instead of
    // `LinkPlanV2::all_targets_have_resolver_threaded_peers`:
    // `LinkTarget.peers` is empty for THREE reasons documented on the
    // field — (a) package declares no peer deps, (b) all declared
    // peers absent from install set, (c) an old lockfile fast-path
    // didn't thread peers. (a) + (b) are legitimate empty results
    // from a live resolver or a current-schema lockfile; (c) is the
    // actual hazard the gate must catch.
    // The library helper `all_targets_have_resolver_threaded_peers`
    // uses `peers.is_empty()` as its sole signal, which conflates
    // (a)+(b) with (c) and would reject most installs (any package
    // with no peer deps fails it). On a fresh resolution, the
    // resolver always traverses peer-context. On a current-schema
    // lockfile fast path, the `peers` field is authoritative: empty
    // means "no resolved peers", not "unknown". Older lockfiles
    // remain conservative and fall back to serial v2.
    let v2_event_driven = v2_linking_can_prepare_before_fetch(
        v2_mode,
        serial_link,
        !v2_targets_pre.is_empty(),
        used_lockfile,
        lockfile_peer_context_authoritative,
    );

    // Plan + per-key V2Target index — both shared across the cache-hit
    // dispatch loop and every per-pkg fetch task. `Arc<LinkPlanV2>`
    // because the plan is read-only after build and lives across many
    // blocking tasks. Empty on the !v2_event_driven path; the link
    // stage falls through to `link_packages_v2` unchanged.
    let v2_plan: Option<std::sync::Arc<lpm_linker::v2::LinkPlanV2>> = if v2_event_driven {
        let store_v2 = store_v2_handle
            .as_deref()
            .expect("v2_event_driven implies v2 store");
        let plan = if used_lockfile && lockfile_peer_context_authoritative {
            lpm_linker::v2::link_v2_prepare_with_authoritative_peer_context_and_compatibility_bin_names(
                project_dir,
                v2_targets_pre,
                store_v2,
                linker_mode,
                compatibility_bin_names,
            )?
        } else {
            lpm_linker::v2::link_v2_prepare_with_compatibility_bin_names(
                project_dir,
                v2_targets_pre,
                store_v2,
                linker_mode,
                compatibility_bin_names,
            )?
        };
        Some(std::sync::Arc::new(plan))
    } else {
        None
    };
    let v2_target_by_key: std::collections::HashMap<String, lpm_linker::v2::V2Target> =
        if v2_event_driven {
            packages
                .iter()
                .zip(link_targets.iter())
                .filter_map(|(p, lt)| {
                    let sri = match lt.materialization {
                        lpm_linker::Materialization::CasBacked => {
                            p.integrity.as_deref()?.to_string()
                        }
                        lpm_linker::Materialization::DirectorySource => {
                            local_source_sri_for_target(lt)
                        }
                    };
                    Some((
                        install_pkg_key(p),
                        lpm_linker::v2::V2Target {
                            target: lt.clone(),
                            source_sri: sri,
                            verified_object_tree_integrity: None,
                        },
                    ))
                })
                .collect()
        } else {
            std::collections::HashMap::new()
        };

    // Per-package v2 link handles populated by both the cache-hit
    // short-circuits below and the fetch tasks further down. Drained
    // at the link stage and folded into the LinkResult.
    let v2_link_task_semaphore = Arc::new(Semaphore::new(v2_link_task_concurrency(
        v2_target_by_key.len(),
    )));
    let mut v2_event_link_handles: Vec<V2LinkHandle> = Vec::new();
    fetch_stage_timings.plan_ms = fetch_plan_start.elapsed().as_millis();
    let v2_prevalidate_start = Instant::now();
    let v2_reusable_prevalidation = if !force && v2_mode {
        match store_v2_handle.as_ref() {
            Some(store_v2) => {
                prevalidate_v2_reusable_objects(&packages, std::sync::Arc::clone(store_v2)).await?
            }
            None => V2ReusablePrevalidation {
                hits: HashMap::new(),
                candidate_count: 0,
                concurrency: 0,
                validation_timings: V2ReusableValidationTimings::default(),
            },
        }
    } else {
        V2ReusablePrevalidation {
            hits: HashMap::new(),
            candidate_count: 0,
            concurrency: 0,
            validation_timings: V2ReusableValidationTimings::default(),
        }
    };
    fetch_stage_timings.v2_reusable_prevalidate_ms = v2_prevalidate_start.elapsed().as_millis();
    fetch_stage_timings.v2_reusable_candidate_count =
        v2_reusable_prevalidation.candidate_count as u64;
    fetch_stage_timings.v2_reusable_concurrency = v2_reusable_prevalidation.concurrency as u64;
    fetch_stage_timings.v2_reusable_hit_count = v2_reusable_prevalidation.hits.len() as u64;
    fetch_stage_timings.v2_reusable_validation = v2_reusable_prevalidation.validation_timings;
    let v2_reusable_objects = v2_reusable_prevalidation.hits;

    //b: stale-entry cleanup runs once, up front — must
    // happen before any per-pkg link spawn touches `.lpm/` so the
    // `read_dir` scan sees a stable snapshot.
    //
    // followup #6b: under v2_event_driven, `link_v2_prepare`
    // above already ran `cleanup_v1_state` (the v2-side equivalent),
    // so this v1-shaped cleanup is skipped — running it would wipe
    // node_modules a second time with no benefit.
    if event_driven_link {
        lpm_linker::cleanup_stale_entries(project_dir, &link_targets)?;
    }

    let mut to_download = Vec::new();
    let mut cached = 0usize;
    let cache_classify_start = Instant::now();
    let fetch_detail_timing_enabled = timing_detail_mode.enabled();

    for p in &packages {
        // --force: re-download everything to verify integrity against registry,
        // even if the store already has it. The store's extract-to-temp + atomic
        // rename handles the case where the existing entry is valid.
        //
        // Use a source-aware existence check. For Source::Tarball, this consults the
        // integrity-keyed CAS layout — a coincidentally-named
        // registry copy in the legacy `(name, version)` slot does
        // NOT satisfy the tarball dependency. Trust-on-first-use Source::Tarball
        // (no recorded integrity) returns false → fetch runs.
        //
        // — under v2 mode, a hit in v1's
        // `<HOME>/.lpm/store/v1/` does NOT mean v2's
        // `objects/<sri>/` is populated. Force a fetch so the v2
        // path repopulates the object. (follow-up:
        // detect-and-translate v1 → v2 to skip re-download for
        // already-extracted bytes.)
        //
        // Per-source carve-out: local sources (`Source::Directory`
        // / `Source::Link`) still skip the fetch loop, but under v2
        // they now flow through pre-populated synthetic objects
        // instead of a project-root-only post-link step.
        let is_local_source = matches!(
            p.source_kind(),
            Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
        );
        if is_local_source {
            fetch_stage_timings.local_source_count += 1;
        }

        if v2_mode && is_local_source {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            cached += 1;
            if v2_event_driven
                && let Some(plan) = v2_plan.as_ref()
                && let Some(target) = v2_target_by_key.get(&install_pkg_key(p)).cloned()
            {
                let link_dispatch_start = timing_detail_start(fetch_detail_timing_enabled);
                let plan_arc = std::sync::Arc::clone(plan);
                let store_arc = std::sync::Arc::clone(
                    store_v2_handle
                        .as_ref()
                        .expect("v2_event_driven implies v2 store"),
                );
                fetch_stage_timings.link_dispatch_count += 1;
                v2_event_link_handles.push(spawn_v2_link_task(
                    plan_arc,
                    target,
                    store_arc,
                    Arc::clone(&v2_link_task_semaphore),
                ));
                record_timing_detail_ms(
                    &mut fetch_stage_timings.cache_classify_link_dispatch_ms,
                    link_dispatch_start,
                );
            }
            record_timing_detail_ms(
                &mut fetch_stage_timings.cache_classify_local_source_ms,
                classification_start,
            );
            continue;
        }

        // — v2 native cache-hit short-circuit.
        //
        // When v2 mode is active AND the v2 object dir for this
        // package's SRI already exists (populated by a prior install
        // OR by the speculative pre-fetcher earlier in this install),
        // skip the fetch entirely. The v2 link dispatch reads
        // `objects/<sri>/` directly, so no per-package linker hint
        // is needed here — same shape as the v1 cache-hit gate
        // below.
        //
        // Pre-this branch was missing because the v2 fetch
        // path is itself idempotent (`extract_object_from_bytes`
        // short-circuits on object hits), so a duplicate fetch was
        // "free" in correctness terms but wasted network on every
        // package. Workflow tests that mock the registry with
        // `expect(1)` per tarball relied on the speculation path
        // being a no-op (pre-4d drain) and broke under the wired-up
        // 4d spec path because every package was downloaded twice.
        let package_key = install_pkg_key(p);
        if !force
            && v2_mode
            && !is_local_source
            && let Some(reusable_object) = v2_reusable_objects.get(&package_key)
        {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            cached += 1;
            spec_tracker.mark_consumed_if_completed(&package_key);
            // followup #6b — dispatch link_v2_one immediately.
            // The v2 object is already populated, so the link entry's
            // clonefile pass can run on the blocking pool in parallel
            // with sibling fetches. Awaited at the link stage below.
            if v2_event_driven
                && let Some(plan) = v2_plan.as_ref()
                && let Some(target) = v2_target_by_key.get(&package_key).cloned()
            {
                let link_dispatch_start = timing_detail_start(fetch_detail_timing_enabled);
                let mut target = target;
                target.verified_object_tree_integrity =
                    Some(reusable_object.tree_integrity.clone());
                let plan_arc = std::sync::Arc::clone(plan);
                let store_arc = std::sync::Arc::clone(
                    store_v2_handle
                        .as_ref()
                        .expect("v2_event_driven implies v2 store"),
                );
                fetch_stage_timings.link_dispatch_count += 1;
                v2_event_link_handles.push(spawn_v2_link_task(
                    plan_arc,
                    target,
                    store_arc,
                    Arc::clone(&v2_link_task_semaphore),
                ));
                record_timing_detail_ms(
                    &mut fetch_stage_timings.cache_classify_link_dispatch_ms,
                    link_dispatch_start,
                );
            }
            record_timing_detail_ms(
                &mut fetch_stage_timings.cache_classify_v2_reusable_hit_ms,
                classification_start,
            );
            continue;
        }

        // — v1 → v2 cache-hit translation.
        //
        // When we're under v2 mode AND v1 already has the extracted
        // bytes for this package AND we know the SRI (lockfile-fast-
        // path or prior install populated `p.integrity`), copy the
        // bytes from `~/.lpm/store/v1/<name>/<version>/` into
        // `~/.lpm/store/v2/objects/<sri>/` instead of forcing a fresh
        // tarball download. The translation is bounded by a single
        // `copy_dir_recursively` (kernel CoW reflink on supporting
        // filesystems, plain copy elsewhere) — cheaper than the
        // network + extract round-trip.
        //
        // After translation, this package falls into the same
        // `cached += 1; continue;` slot as the v1 cache-hit gate
        // below, because the v2 link dispatch (around L5325) reads
        // `~/.lpm/store/v2/objects/<sri>/` directly and the object
        // is now populated.
        //
        // Falls through to the regular fetch path on any error — the
        // re-download is the correct fallback and matches pre- // behavior under v2 mode.
        if !force
            && v2_mode
            && !is_local_source
            && let Some(v2_store) = store_v2_handle.as_deref()
            && let Some(sri) = p.integrity.as_deref()
            && p.store_has_source_aware(&store, project_dir)
            && let Ok(v1_pkg_dir) = p.store_path_or_err(&store, project_dir, None)
        {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            match v2_store.populate_object_from_v1(&v1_pkg_dir, sri) {
                Ok(_) => {
                    fetch_stage_timings.v1_to_v2_translate_count += 1;
                    cached += 1;
                    // followup #6b — see the v2 SRI-direct
                    // cache-hit branch above. Translation populated
                    // `objects/<sri>/`; dispatch link immediately.
                    if v2_event_driven
                        && let Some(plan) = v2_plan.as_ref()
                        && let Some(target) = v2_target_by_key.get(&install_pkg_key(p)).cloned()
                    {
                        let link_dispatch_start = timing_detail_start(fetch_detail_timing_enabled);
                        let plan_arc = std::sync::Arc::clone(plan);
                        let store_arc = std::sync::Arc::clone(
                            store_v2_handle
                                .as_ref()
                                .expect("v2_event_driven implies v2 store"),
                        );
                        fetch_stage_timings.link_dispatch_count += 1;
                        v2_event_link_handles.push(spawn_v2_link_task(
                            plan_arc,
                            target,
                            store_arc,
                            Arc::clone(&v2_link_task_semaphore),
                        ));
                        record_timing_detail_ms(
                            &mut fetch_stage_timings.cache_classify_link_dispatch_ms,
                            link_dispatch_start,
                        );
                    }
                    record_timing_detail_ms(
                        &mut fetch_stage_timings.cache_classify_v1_to_v2_translate_ms,
                        classification_start,
                    );
                    continue;
                }
                Err(e) => {
                    fetch_stage_timings.v1_to_v2_translate_failure_count += 1;
                    record_timing_detail_ms(
                        &mut fetch_stage_timings.cache_classify_v1_to_v2_translate_ms,
                        classification_start,
                    );
                    tracing::debug!(
                        "v1→v2 translation for {}@{} failed: {e} (falling back to fetch)",
                        p.name,
                        p.version
                    );
                }
            }
        }

        if !force && !v2_mode && p.store_has_source_aware(&store, project_dir) {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            cached += 1;
            fetch_stage_timings.v1_cache_hit_count += 1;
            spec_tracker.mark_consumed_if_completed(&package_key);
            //b: spawn per-pkg link task immediately — this
            // package is already materialized in the store, so // can run in parallel with the fetch loop below.
            if event_driven_link {
                // Source-aware store path keeps the linker pointed at
                // the correct slot (tarball CAS for remote tarballs,
                // tarball-local CAS for file: tarballs, source
                // realpath for directory/link deps, registry CAS for
                // Registry). `store_has_source_aware()` returned true
                // above, so the SRI / source-path invariant holds —
                // `store_path_or_err` can't fail.
                let store_path = p.store_path_or_err(&store, project_dir, None)?;
                let target = LinkTarget {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    store_path,
                    dependencies: link_dependencies_for_package(p, &source_index)?,
                    aliases: p.aliases.clone(),
                    is_direct: p.is_direct,
                    root_link_names: p.root_link_names.clone(),
                    wrapper_id: p.wrapper_id_for_source(),
                    materialization: p.materialization_for_source(),
                    peers: p.peers.clone(),
                    patch_fingerprint: patch_fingerprints
                        .get(&(p.name.clone(), p.version.clone()))
                        .cloned(),
                };
                let pd = project_dir.to_path_buf();
                let force_flag = force;
                let link_dispatch_start = timing_detail_start(fetch_detail_timing_enabled);
                fetch_stage_timings.link_dispatch_count += 1;
                event_link_handles.push(tokio::task::spawn_blocking(move || {
                    lpm_linker::link_one_package(&pd, &target, force_flag)
                }));
                record_timing_detail_ms(
                    &mut fetch_stage_timings.cache_classify_link_dispatch_ms,
                    link_dispatch_start,
                );
            }
            record_timing_detail_ms(
                &mut fetch_stage_timings.cache_classify_v1_cache_hit_ms,
                classification_start,
            );
        } else {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            to_download.push(p.clone());
            record_timing_detail_ms(
                &mut fetch_stage_timings.cache_classify_download_candidate_ms,
                classification_start,
            );
        }
    }
    fetch_stage_timings.cache_classify_ms = cache_classify_start.elapsed().as_millis();

    let policy_gate_start = Instant::now();
    let drift_ignore_packages: Vec<String> = match &drift_ignore_policy {
        crate::provenance_fetch::DriftIgnorePolicy::IgnoreNames(names) => {
            let mut values: Vec<_> = names.iter().cloned().collect();
            values.sort();
            values
        }
        _ => Vec::new(),
    };
    let drift_ignore_unlock_authorized = if !matches!(
        drift_ignore_policy,
        crate::provenance_fetch::DriftIgnorePolicy::EnforceAll
    ) {
        crate::security_approval::ensure_project_unlock(
            crate::security_approval::ApprovalScope::ProvenanceIgnoreDrift,
            project_dir,
            json_output,
            crate::security_approval::ApprovalSource::CliFlag,
            "This install waives provenance drift checks for this project.",
            None,
            &drift_ignore_packages,
        )?;
        true
    } else {
        false
    };
    if force_security_floor
        && !matches!(
            drift_ignore_policy,
            crate::provenance_fetch::DriftIgnorePolicy::EnforceAll
        )
        && !drift_ignore_unlock_authorized
    {
        let requested = match &drift_ignore_policy {
            crate::provenance_fetch::DriftIgnorePolicy::EnforceAll => "enforce-all".to_string(),
            crate::provenance_fetch::DriftIgnorePolicy::IgnoreAll => "ignore-all".to_string(),
            crate::provenance_fetch::DriftIgnorePolicy::IgnoreNames(names) => {
                let mut values: Vec<_> = names.iter().cloned().collect();
                values.sort();
                values.join(",")
            }
        };
        crate::security_floor::record_suppression(
            crate::security_floor::SuppressionRecord::new(
                crate::security_floor::GuardedControl::ProvenanceDriftWaiver,
                crate::security_floor::SuppressionSource::Cli,
                requested,
                "enforce-all",
            ),
            json_output,
        );
        drift_ignore_policy = crate::provenance_fetch::DriftIgnorePolicy::EnforceAll;
    }
    let (_resolved_runtime_sigstore, runtime_sigstore_source) =
        crate::provenance_fetch::EnforceMode::resolve_from_chain(
            std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
            || global_config.get_sigstore_verify(),
        );
    crate::security_approval::ensure_runtime_sigstore_posture(
        project_dir,
        json_output,
        verify_policy.enforce,
        runtime_sigstore_source,
    )?;
    let unverified_provenance_packages: Vec<String> = match &verify_policy.skip {
        crate::provenance_fetch::SkipPolicy::Names(names) => {
            let mut values: Vec<_> = names.iter().cloned().collect();
            values.sort();
            values
        }
        _ => Vec::new(),
    };
    let unverified_provenance_unlock_authorized = if !matches!(
        verify_policy.skip,
        crate::provenance_fetch::SkipPolicy::None
    ) && !matches!(
        verify_policy.enforce,
        crate::provenance_fetch::EnforceMode::Off
    ) {
        crate::security_approval::ensure_project_unlock(
            crate::security_approval::ApprovalScope::ProvenanceUnverified,
            project_dir,
            json_output,
            crate::security_approval::ApprovalSource::CliFlag,
            "This install skips Sigstore verification for one or more packages in this project.",
            None,
            &unverified_provenance_packages,
        )?;
        true
    } else {
        false
    };
    if force_security_floor
        && !matches!(
            verify_policy.skip,
            crate::provenance_fetch::SkipPolicy::None
        )
        && !matches!(
            verify_policy.enforce,
            crate::provenance_fetch::EnforceMode::Off
        )
        && !unverified_provenance_unlock_authorized
    {
        let requested = match &verify_policy.skip {
            crate::provenance_fetch::SkipPolicy::None => "none".to_string(),
            crate::provenance_fetch::SkipPolicy::All => "all".to_string(),
            crate::provenance_fetch::SkipPolicy::Names(names) => {
                let mut values: Vec<_> = names.iter().cloned().collect();
                values.sort();
                values.join(",")
            }
        };
        crate::security_floor::record_suppression(
            crate::security_floor::SuppressionRecord::new(
                crate::security_floor::GuardedControl::UnverifiedProvenance,
                crate::security_floor::SuppressionSource::Cli,
                requested,
                "none",
            ),
            json_output,
        );
        verify_policy.skip = crate::provenance_fetch::SkipPolicy::None;
    }
    let cooldown_policy = lpm_security::SecurityPolicy::with_resolved_min_age(
        &project_dir.join("package.json"),
        effective_min_age_secs,
    );

    let publish_ages: HashMap<(String, String), u64> = if cooldown_policy.minimum_release_age_secs
        > 0
        && (!used_lockfile || release_age_policy.is_strict())
    {
        publish_ages_from_resolved_metadata(&packages)
    } else {
        HashMap::new()
    };

    // Enforce minimumReleaseAge: block recently published packages unless --allow-new.
    // The default policy checks direct packages on fresh resolution only; strict mode
    // also revalidates lockfile replay from stored registry-published-at timestamps.
    if !allow_new
        && cooldown_policy.minimum_release_age_secs > 0
        && (!used_lockfile || release_age_policy.is_strict())
    {
        let mut too_new = Vec::new();
        for p in &packages {
            if !release_age_policy_applies_to_install_package(release_age_policy, p) {
                continue;
            }
            if minimum_release_age_exclude.contains(&p.name) {
                continue;
            }
            let key = (p.name.clone(), p.version.clone());
            let age_secs = publish_ages.get(&key).copied();
            // Use the existing `check_release_age` semantics:
            // `None` age = no timestamp available → no warning
            // (matches pre-46b behaviour). Below-threshold age =
            // warning carrying the time-remaining info. Match the
            // existing ts-string-based API by re-running it; the
            // `publish_ages` map only carries successful parses, so
            // missing entries collapse to the `None` case here.
            if age_secs.is_none() {
                continue;
            }
            // Reconstruct a synthetic check by hand: if the age is
            // below the threshold, build a warning with the same
            // shape the helper would have returned. Keeps the
            // user-visible message identical.
            let age = age_secs.unwrap();
            if age < cooldown_policy.minimum_release_age_secs {
                let remaining = cooldown_policy.minimum_release_age_secs.saturating_sub(age);
                let hours = remaining / 3600;
                let minutes = (remaining % 3600) / 60;
                too_new.push((p.name.clone(), p.version.clone(), hours, minutes));
            }
        }

        if !too_new.is_empty() {
            if !json_output {
                output::warn(&format!(
                    "{} package(s) blocked by minimumReleaseAge ({}s):",
                    too_new.len(),
                    cooldown_policy.minimum_release_age_secs,
                ));
                for (name, version, hours, minutes) in &too_new {
                    eprintln!(
                        "    {}@{} — {}h {}m remaining",
                        name, version, hours, minutes
                    );
                }
                //: three override paths, ordered narrowest
                // to broadest persistence:
                // (1) --min-release-age=0 per-install, numeric
                // (2) --allow-new per-install, blanket bypass
                // (3) package.json persistent, repo-wide
                eprintln!(
                    "  To override: {} for one package, {} or {} (this install), or set {} in package.json.",
                    "--min-release-age-exclude <pkg>".bold(),
                    "--min-release-age=0".bold(),
                    "--allow-new".bold(),
                    "\"lpm\": { \"minimumReleaseAge\": 0 }".dimmed(),
                );
            }
            return Err(LpmError::Registry(format!(
                "{} package(s) published too recently (minimumReleaseAge={}s). Use --min-release-age-exclude <pkg>, --allow-new, or --min-release-age=<dur> to override.",
                too_new.len(),
                cooldown_policy.minimum_release_age_secs,
            )));
        }
    }

    // provenance-drift gate.
    //
    // For every resolved package with a prior approval that captured
    // `provenance_at_approval`, fetch the candidate version's
    // Sigstore attestation and compare identities. Block on
    // "provenance dropped" (axios signal) or "identity changed"
    // (publisher rotation without explicit re-approval).
    //
    // **Gating:** fires only on fresh resolution — lockfile fast-path
    // is skipped by design (the lockfile locks integrity, not
    // attestation identity). `--allow-new`
    // does NOT bypass this gate because provenance and cooldown
    // are orthogonal signals, and the cooldown override doesn't
    // imply acknowledgement of publisher drift. The caller wires the
    // `--ignore-provenance-drift[-all]` override below.
    //
    // **Performance:** sequential fetches per package. The fetcher's
    // 7-day cache under `cache/metadata/attestations/` makes repeat
    // installs O(1) per package. Revisit concurrency if sequential
    // round-trips on first install prove too costly in practice.
    //
    // **Override short-circuit:** `--ignore-provenance-drift-all`
    // skips the entire gate (no trusted-dependencies read, no
    // per-package fetch). `--ignore-provenance-drift <pkg>` skips
    // the per-package fetch for the named entries. Both paths emit a
    // concise advisory to stderr so the waived drift is auditable
    // (users explicitly asked for the opt-out; silent skip would
    // hide that they're accepting a non-zero-risk identity).
    if !used_lockfile && drift_ignore_policy.ignores_all() && !json_output {
        output::warn(
            "provenance-drift check waived for this install by --ignore-provenance-drift-all",
        );
    }
    // Per-package `ProvenanceStatus` map for the install --json
    // envelope. Declared at this scope (rather than inside the
    // `if has_rich_approvals` block) so the JSON emission below at
    // the `blocked_packages` enumeration can consume it. Sparse —
    // only packages the drift gate fetched for are present; the
    // `blocked_to_json_with_provenance` helper omits the
    // `provenance` block when the key is absent.
    let mut install_provenance_status_map: HashMap<(String, String), lpm_common::ProvenanceStatus> =
        HashMap::new();
    if !used_lockfile && !drift_ignore_policy.ignores_all() {
        let trusted =
            lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"))
                .trusted_dependencies;

        // Short-circuit the whole gate when there's no rich-form
        // approval to compare against. Pre- projects with only
        // Legacy approvals (or no `trustedDependencies` at all) skip
        // the gate entirely — zero network cost.
        let has_rich_approvals = matches!(
            &trusted,
            lpm_workspace::TrustedDependencies::Rich(map) if !map.is_empty()
        );

        if has_rich_approvals {
            let cache_root = lpm_root.cache_metadata_attestations();
            let http = reqwest::Client::new();

            // (name, version, verdict, approved_version, approved_snapshot)
            let mut drifted: Vec<(
                String,
                String,
                lpm_security::provenance::DriftVerdict,
                String,
                Option<lpm_workspace::ProvenanceSnapshot>,
            )> = Vec::new();

            for p in &packages {
                let Some((approved_version, reference_binding)) =
                    trusted.provenance_reference_for_candidate(&p.name, &p.version)
                else {
                    continue;
                };

                // Per-package override: user explicitly waived this
                // name. Emit a one-line advisory so the opt-out is
                // visible in the install log, then skip the fetch +
                // compare.
                if drift_ignore_policy.ignores_name(&p.name) {
                    if !json_output {
                        output::warn(&format!(
                            "{}@{} — provenance-drift check waived by \
                             --ignore-provenance-drift (approved reference: v{approved_version})",
                            p.name, p.version,
                        ));
                    }
                    continue;
                }
                let approved_snapshot = reference_binding.provenance_at_approval.as_ref();

                // Extract the candidate version's attestation ref
                // from the resolver's TTL cache (same pattern as the
                // cooldown gate above).
                let attestation_ref = if p.is_lpm {
                    match lpm_common::PackageName::parse(&p.name) {
                        Ok(pkg_name) => lpm_registry::timing::with_metadata_purpose(
                            lpm_registry::timing::MetadataPurpose::ProvenanceDrift,
                            arc_client.get_package_metadata(&pkg_name),
                        )
                        .await
                        .ok()
                        .and_then(|meta| {
                            meta.versions
                                .get(&p.version)
                                .and_then(|v| v.dist.as_ref())
                                .and_then(|d| d.attestations.clone())
                        }),
                        Err(_) => None,
                    }
                } else {
                    // follow-up: route via RouteTable so
                    // the provenance-drift gate doesn't fall through to
                    // public npm for a custom-registry package.
                    let route = route_table.route_for_package(&p.name);
                    lpm_registry::timing::with_metadata_purpose(
                        lpm_registry::timing::MetadataPurpose::ProvenanceDrift,
                        arc_client.get_npm_metadata_routed(&p.name, route),
                    )
                    .await
                    .ok()
                    .and_then(|meta| {
                        meta.versions
                            .get(&p.version)
                            .and_then(|v| v.dist.as_ref())
                            .and_then(|d| d.attestations.clone())
                    })
                };

                // When the operator skip-listed this name (CLI
                // `--unverified-provenance`) OR set the fleet-wide
                // enforce mode to `Off` (env / config), route the
                // fetch through the `Unverified` path — bytes
                // through the legacy identity-only parser, no
                // cryptographic checks. The drift gate still gets
                // a populated snapshot so publisher / workflow_path
                // identity drift is detected even when the operator
                // opted out of crypto.
                let now_snapshot: Option<lpm_workspace::ProvenanceSnapshot> = if verify_policy
                    .should_skip_verification_for(&p.name)
                {
                    let raw = crate::provenance_fetch::fetch_unverified_snapshot(
                        &http,
                        &p.name,
                        &p.version,
                        attestation_ref.as_ref(),
                    )
                    .await;
                    // Re-label `Unverified` → `Disabled` when fleet-
                    // wide `EnforceMode::Off` was the trigger, so the
                    // JSON envelope distinguishes wholesale opt-out
                    // (`"disabled"`) from per-package CLI carve-out
                    // (`"skipped"`). Logic shared with the batch
                    // caller in `provenance_fetch.rs` so the two
                    // sites cannot drift on the labeling rule.
                    let status = crate::provenance_fetch::relabel_skip_status_for_enforce_mode(
                        raw,
                        verify_policy.enforce,
                    );
                    // Record for the install --json envelope
                    // before consuming for the drift gate.
                    install_provenance_status_map
                        .insert((p.name.clone(), p.version.clone()), status.clone());
                    // Projection: `Unverified(snap)` / `Disabled(snap)`
                    // → Some(snap), `Absent` → Some(present:false),
                    // `TransportDegraded` → None. `VerificationRejected`
                    // is unreachable on the skip path (the verifier
                    // didn't run).
                    status.into_snapshot_for_binding(&p.name, &p.version)?
                } else {
                    let raw = crate::provenance_fetch::fetch_provenance_snapshot(
                        &http,
                        &cache_root,
                        &p.name,
                        &p.version,
                        attestation_ref.as_ref(),
                        provenance_timings.as_ref(),
                    )
                    .await;
                    // Branch arms:
                    // - `Ok(Some(snap))`: Verified (snap.present)
                    // or Absent (registry served no attestation).
                    // - `Ok(None)`: transport-degraded; drift
                    // comparator absorbs as NoDrift.
                    // - `Err(ProvenanceVerification)`: policy
                    // decision per `verify_policy.enforce`.
                    // Warn degrades to None + loud log; Deny
                    // propagates the typed error and `?`
                    // refuses the install.
                    // - `Err(other)`: infrastructure failure
                    // (cache unwritable, etc.) — propagate
                    // as-is so the user sees a real diagnostic,
                    // not a silent degrade.
                    let (snapshot_for_drift, status_for_map) = match raw {
                        Ok(Some(snap)) if snap.present => {
                            let status = lpm_common::ProvenanceStatus::Verified(snap.clone());
                            (Some(snap), status)
                        }
                        Ok(Some(_)) => (
                            Some(lpm_workspace::ProvenanceSnapshot {
                                present: false,
                                ..Default::default()
                            }),
                            lpm_common::ProvenanceStatus::Absent,
                        ),
                        Ok(None) => (None, lpm_common::ProvenanceStatus::TransportDegraded),
                        Err(lpm_common::LpmError::ProvenanceVerification(reason)) => {
                            let status = lpm_common::ProvenanceStatus::VerificationRejected {
                                reason: reason.clone(),
                            };
                            let snapshot = match verify_policy.enforce {
                                crate::provenance_fetch::EnforceMode::Warn => {
                                    if !json_output {
                                        crate::output::warn(&format!(
                                            "provenance verification FAILED for {pkg}@{ver}: {reason}\n  \
                                             LPM_PROVENANCE_ENFORCE=warn — install proceeds without \
                                             verified provenance for this package. Re-run with \
                                             LPM_PROVENANCE_ENFORCE=deny (default) to refuse, or pass \
                                             `--unverified-provenance {pkg}` to opt out explicitly.",
                                            pkg = p.name,
                                            ver = p.version,
                                        ));
                                    }
                                    tracing::warn!(
                                        target = "lpm::provenance",
                                        pkg = %p.name,
                                        version = %p.version,
                                        reason = %reason,
                                        enforce_mode = "warn",
                                        "install drift gate: verifier rejected bundle \
                                         under warn enforce-mode — degrading to NoDrift",
                                    );
                                    None
                                }
                                // `Off` short-circuits the verifier
                                // upstream via `should_skip_verification_for`,
                                // so the verifier-rejection path is
                                // unreachable in `Off` mode. Defensive
                                // arm to keep the match exhaustive if
                                // a future refactor accidentally
                                // bypasses the skip-route — degrade
                                // identically to Warn so the install
                                // doesn't fail on a state that the
                                // operator already declared "fleet-wide
                                // off".
                                crate::provenance_fetch::EnforceMode::Off => None,
                                crate::provenance_fetch::EnforceMode::Deny => {
                                    // Surface the status in the map before
                                    // returning so a `--json` consumer that
                                    // tees stderr can correlate the failure
                                    // with the per-package envelope.
                                    install_provenance_status_map
                                        .insert((p.name.clone(), p.version.clone()), status);
                                    return Err(LpmError::ProvenanceVerification(reason));
                                }
                            };
                            (snapshot, status)
                        }
                        Err(other) => return Err(other),
                    };
                    install_provenance_status_map
                        .insert((p.name.clone(), p.version.clone()), status_for_map);
                    snapshot_for_drift
                };

                let verdict = lpm_security::provenance::check_provenance_drift(
                    approved_snapshot,
                    now_snapshot.as_ref(),
                );

                if !matches!(verdict, lpm_security::provenance::DriftVerdict::NoDrift) {
                    drifted.push((
                        p.name.clone(),
                        p.version.clone(),
                        verdict,
                        approved_version.to_string(),
                        reference_binding.provenance_at_approval.clone(),
                    ));
                }
            }

            if !drifted.is_empty() {
                // UX. extends the footer with the
                // `--ignore-provenance-drift` override suggestion.
                if !json_output {
                    output::warn(&format!(
                        "{} package(s) blocked by provenance drift:",
                        drifted.len(),
                    ));
                    for (name, version, verdict, approved_version, approved_snap) in &drifted {
                        let kind = match verdict {
                            lpm_security::provenance::DriftVerdict::ProvenanceDropped => {
                                "provenance dropped"
                            }
                            lpm_security::provenance::DriftVerdict::IdentityChanged => {
                                "publisher identity changed"
                            }
                            lpm_security::provenance::DriftVerdict::NoDrift => {
                                unreachable!("NoDrift is filtered out above")
                            }
                        };
                        // Registry- and lockfile-supplied identifiers
                        // pass through `sanitize_for_terminal` before
                        // hitting the TTY so a crafted name like
                        // `\x1b]8;;file:///etc/passwd\x07evil\x1b]8;;\x07`
                        // can't render as a clickable hyperlink or
                        // mutate the clipboard via OSC 52.
                        let name_safe = lpm_common::sanitize_for_terminal(name);
                        let version_safe = lpm_common::sanitize_for_terminal(version);
                        let approved_version_safe =
                            lpm_common::sanitize_for_terminal(approved_version);
                        eprintln!("    {}@{} — {}", name_safe, version_safe, kind);
                        let identity = approved_snap.as_ref().and_then(|s| {
                            match (s.publisher.as_deref(), s.workflow_path.as_deref()) {
                                (Some(pub_), Some(path)) => Some(format!(
                                    "{} / {}",
                                    lpm_common::sanitize_for_terminal(pub_),
                                    lpm_common::sanitize_for_terminal(path),
                                )),
                                (Some(pub_), None) => Some(lpm_common::sanitize_for_terminal(pub_)),
                                _ => None,
                            }
                        });
                        let ref_hint = approved_snap
                            .as_ref()
                            .and_then(|s| s.workflow_ref.as_deref())
                            .map(|r| format!(" (ref: {})", lpm_common::sanitize_for_terminal(r)))
                            .unwrap_or_default();
                        match identity {
                            Some(ident) => eprintln!(
                                "      last approved: v{approved_version_safe} via {ident}{ref_hint}",
                            ),
                            None => eprintln!(
                                "      last approved: v{approved_version_safe} with attestation{ref_hint}",
                            ),
                        }
                        if matches!(
                            verdict,
                            lpm_security::provenance::DriftVerdict::ProvenanceDropped
                        ) {
                            eprintln!("      this version: (no provenance attestation)");
                        }
                    }
                    eprintln!();
                    eprintln!(
                        "  This pattern was seen in the axios 1.14.1 compromise (March 2026).",
                    );
                    // narrowest-to-broadest
                    // recovery paths. Prefer re-approval (captures
                    // the new identity and tightens the subsequent
                    // gate). Per-package override for single-case
                    // acknowledged migrations. Blanket override for
                    // users consciously suspending the entire check
                    // — listed last on purpose.
                    eprintln!(
                        "  Recovery: re-approve via {}; or opt out with {} / {}.",
                        "lpm approve-scripts".bold(),
                        "--ignore-provenance-drift <pkg>".bold(),
                        "--ignore-provenance-drift-all".bold(),
                    );
                }
                return Err(LpmError::Registry(format!(
                    "{} package(s) blocked by provenance drift. Review the identity change and re-approve via `lpm approve-scripts`, or opt out per-package via `--ignore-provenance-drift <pkg>` / blanket via `--ignore-provenance-drift-all`.",
                    drifted.len(),
                )));
            }
        }
    }
    fetch_stage_timings.policy_gate_ms = policy_gate_start.elapsed().as_millis();

    let downloaded = to_download.len();
    //: accumulate per-task timings across the parallel pool so we
    // can emit a proper fetch-stage breakdown in `lpm install --json`. Empty
    // breakdown on the cached-everything path; filled in below when work runs.
    let mut fetch_breakdown = FetchBreakdown::default();
    spec_stats.completed_before_fetch = spec_tracker.completed_count();
    if !to_download.is_empty() {
        let download_wall_start = Instant::now();
        let overall = ProgressBar::new(to_download.len() as u64);
        overall.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} Downloading [{bar:30.cyan/dim}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("━╸─"),
        );
        overall.enable_steady_tick(std::time::Duration::from_millis(80));

        //: share the hoisted `fetch_semaphore` so speculative
        // dispatches (pre-resolve) and real fetches (post-resolve) draw
        // from the same 24-permit pool.
        let semaphore = fetch_semaphore.clone();
        let mut handles = Vec::new();

        for p in to_download {
            let sem = semaphore.clone();
            let client = arc_client.clone();
            let store_ref = store.clone();
            // — clone the Optional v2 handle into the
            // per-package spawn. `Option::clone` is a Some/None match
            // and `Arc::clone` is a refcount bump; cheap.
            let store_v2_ref = store_v2_handle.clone();
            let coord = fetch_coord.clone();
            let overall = overall.clone();
            let force_flag = force;
            // Per-task link scheduling captures.
            let event_link = event_driven_link;
            let project_dir_buf = project_dir.to_path_buf();
            // Shared gate/retry counters for the stale-URL recovery path
            // in `fetch_and_store_*`.
            let gate_stats_c = gate_stats.clone();
            // — `.npmrc`-derived routing carried into
            // the per-package fetch task. Cheap clone (Arc ref-bump
            // for the inner NpmrcConfig).
            let route_table_c = route_table.clone();
            // followup #6b — per-task v2 event-driven link
            // captures. `v2_plan_arc` is None on the !v2_event_driven
            // path; `v2_target_for_pkg` resolved here once so the
            // per-task closure doesn't carry the whole index map.
            let v2_plan_arc = v2_plan.as_ref().map(std::sync::Arc::clone);
            let v2_target_for_pkg = if v2_event_driven {
                v2_target_by_key.get(&install_pkg_key(&p)).cloned()
            } else {
                None
            };
            let v2_link_task_semaphore_c = Arc::clone(&v2_link_task_semaphore);
            let spec_tracker_c = spec_tracker.clone();
            // confidence-followup — pre-resolve THIS
            // package's patch fingerprint outside the move closure so
            // the closure doesn't carry the whole map. `None` for the
            // overwhelmingly common case (package has no
            // `lpm.patchedDependencies` entry).
            let patch_fingerprint_for_pkg = patch_fingerprints
                .get(&(p.name.clone(), p.version.clone()))
                .cloned();
            let source_index_for_pkg = Arc::clone(&source_index);
            let trace_slow_packages = timing_detail_mode.trace();
            let fetch_extract_limiter_c = fetch_extract_limiter.clone();

            handles.push(tokio::spawn(async move {
                type LinkHandle = tokio::task::JoinHandle<
                    Result<(MaterializedPackage, lpm_linker::OnePackageResult), LpmError>,
                >;
                // followup #6b — v2-shape link handle. Mutually
                // exclusive with `LinkHandle` at runtime: under v2_mode,
                // `event_link` is false (so `LinkHandle` is always None);
                // under !v2_mode, `v2_plan_arc` is None (so this is
                // always None).
                type FetchTaskResult = (
                    String,
                    Option<String>,
                    String,
                    TaskTimings,
                    Option<LinkHandle>,
                    Option<V2LinkHandle>,
                    Option<String>,
                );

                // timing: spawn→key-lock→permit captures the full time this
                // task sat queued.: now also covers the
                // FetchCoordinator wait — if a speculation is mid-fetch for
                // the same `(name, ver)`, we wait on the per-key lock and
                // short-circuit via the store-hit check below.
                let queue_start = std::time::Instant::now();
                let package_display =
                    trace_slow_packages.then(|| format!("{}@{}", p.name, p.version));
                let package_key = install_pkg_key(&p);

                //: per-key fetch coordination. Acquired BEFORE
                // the download permit — if a sibling (speculation) is
                // already fetching this key, we wait here without consuming
                // a permit. On wake, `has_package` is true and we skip the
                // real fetch entirely (zero bandwidth, zero CPU).
                let key_lock = coord.lock_for(package_key.clone()).await;
                let _key_guard = key_lock.lock().await;

                // Spawn the per-pkg link task once the tarball is in the
                // store. Used in both the sibling-skip path and the normal
                // fetch path — in either case the package is materialized
                // by the time we call `link_one_package`.
                //
                // The closure takes an optional sri_override so the post-fetch
                // path can pass the freshly-computed SRI before it
                // reaches `p.integrity`. Source-aware store_path
                // routes Source::Tarball to the integrity-keyed CAS,
                // never to the registry-keyed path.
                let spawn_link = |p: &InstallPackage,
                                  sri_override: Option<&str>|
                 -> Result<Option<LinkHandle>, LpmError> {
                    if !event_link {
                        return Ok(None);
                    }
                    // (reviewed): store_path_or_err
                    // surfaces the missing-SRI invariant violation
                    // as a typed error with full package context
                    // instead of panicking. Reachable only on a
                    // malformed lockfile that bypassed the
                    // writer guard — should never fire in practice.
                    let store_path =
                        p.store_path_or_err(&store_ref, &project_dir_buf, sri_override)?;
                    let target = LinkTarget {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        store_path,
                        dependencies: link_dependencies_for_package(p, &source_index_for_pkg)?,
                        aliases: p.aliases.clone(),
                        is_direct: p.is_direct,
                        root_link_names: p.root_link_names.clone(),
                        wrapper_id: p.wrapper_id_for_source(),
                        materialization: p.materialization_for_source(),
                        peers: p.peers.clone(),
                        patch_fingerprint: patch_fingerprint_for_pkg.clone(),
                    };
                    let pd = project_dir_buf.clone();
                    Ok(Some(tokio::task::spawn_blocking(move || {
                        lpm_linker::link_one_package(&pd, &target, force_flag)
                    })))
                };

                if !force_flag
                    && let (Some(store_v2), Some(expected_sri)) =
                        (store_v2_ref.as_ref(), p.integrity.clone())
                {
                    let sri_for_result = expected_sri.clone();
                    let store_v2_check = std::sync::Arc::clone(store_v2);
                    let reusable_object = tokio::task::spawn_blocking(move || {
                        store_v2_check.reusable_object(&expected_sri)
                    })
                    .await
                    .map_err(|e| {
                        LpmError::Registry(format!("v2 cache check task panicked: {e}"))
                    })??;
                    if let Some(reusable_object) = reusable_object {
                        let v2_link_h: Option<V2LinkHandle> =
                            if let (Some(plan), Some(target), Some(store_v2)) = (
                                v2_plan_arc.as_ref(),
                                v2_target_for_pkg.as_ref(),
                                store_v2_ref.as_ref(),
                            ) {
                                let plan_c = std::sync::Arc::clone(plan);
                                let mut target_c = target.clone();
                                target_c.verified_object_tree_integrity =
                                    Some(reusable_object.tree_integrity);
                                let store_c = std::sync::Arc::clone(store_v2);
                                Some(spawn_v2_link_task(
                                    plan_c,
                                    target_c,
                                    store_c,
                                    Arc::clone(&v2_link_task_semaphore_c),
                                ))
                            } else {
                                None
                            };
                        overall.inc(1);
                        spec_tracker_c.mark_consumed_if_completed(&package_key);
                        return Ok::<FetchTaskResult, LpmError>((
                            package_key,
                            package_display,
                            sri_for_result,
                            TaskTimings {
                                queue_wait_ms: queue_start.elapsed().as_millis(),
                                ..Default::default()
                            },
                            None,
                            v2_link_h,
                            None,
                        ));
                    }
                }

                //b: only honour the store-hit short-circuit when
                // NOT in `--force` mode. `--force` is the "re-verify
                // integrity against registry" path: the user explicitly
                // wants every tarball re-downloaded and re-hashed, even if
                // the store already has a valid copy. Without this gate, a
                // sibling task (or a prior install) making the store hot
                // would neuter `--force`.
                //
                // Source-aware existence check: a registry-CAS hit must NOT
                // satisfy a Source::Tarball pkg with the same
                // (name, version).
                let store_path_pre_fetch = (!force_flag)
                    .then(|| p.store_path_source_aware(&store_ref, &project_dir_buf, None))
                    .flatten();
                if !force_flag
                    && p.store_has_source_aware(&store_ref, &project_dir_buf)
                    && let Some(existing_path) = store_path_pre_fetch
                {
                    // A sibling completed the fetch while we waited on the
                    // key lock. Use the stored SRI for lockfile output;
                    // task_timings stays at defaults (no download work done
                    // on THIS task's critical path — the sibling's timings
                    // covered it). `None` for `final_url` here
                    // because THIS task didn't hit the registry — the
                    // sibling's task already reported the URL it used
                    // (via its own return value) and will be folded into
                    // the writeback aggregator. Reporting `None` avoids
                    // double-counting a divergence or conflicting on the
                    // URL value.
                    let sri = lpm_store::read_stored_integrity(&existing_path).unwrap_or_default();
                    let link_h = spawn_link(&p, None)?;
                    // followup #6b — sibling-skip path. The
                    // v2 object dir was populated by the sibling's
                    // fetch task (or the sibling is in the middle of
                    // populating it; the per-key fetch lock above
                    // ensures we observe the post-extract state).
                    // Dispatch the v2 link entry materialization in
                    // the same shape as the post-fetch path below.
                    let v2_link_h: Option<V2LinkHandle> =
                        if let (Some(plan), Some(target), Some(store_v2)) = (
                            v2_plan_arc.as_ref(),
                            v2_target_for_pkg.as_ref(),
                            store_v2_ref.as_ref(),
                        ) {
                            let plan_c = std::sync::Arc::clone(plan);
                            let target_c = target.clone();
                            let store_c = std::sync::Arc::clone(store_v2);
                            Some(spawn_v2_link_task(
                                plan_c,
                                target_c,
                                store_c,
                                Arc::clone(&v2_link_task_semaphore_c),
                            ))
                        } else {
                            None
                        };
                    overall.inc(1);
                    spec_tracker_c.mark_consumed_if_completed(&package_key);
                    return Ok::<FetchTaskResult, LpmError>((
                        package_key,
                        package_display,
                        sri,
                        TaskTimings {
                            queue_wait_ms: queue_start.elapsed().as_millis(),
                            ..Default::default()
                        },
                        link_h,
                        v2_link_h,
                        None,
                    ));
                }

                // W6a — `acquire_owned` so the permit can be
                // *moved* into the fetch fn and dropped between
                // download and extract. The fn drops it as soon as
                // bytes are on the heap (streaming) or on temp disk
                // (legacy), letting the next download start while this
                // task continues with extract on the blocking pool.
                let permit = sem
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| LpmError::Registry("download semaphore closed".into()))?;
                let queue_wait_ms = queue_start.elapsed().as_millis();

                overall.set_message(format!("{}@{}", p.name, p.version));

                // — Source::Tarball install packages
                // bypass the registry-routed legacy/streaming paths
                // entirely. The URL is the source identity; the
                // store path is content-addressable by integrity.
                let is_tarball_source =
                    matches!(p.source_kind(), Ok(lpm_lockfile::Source::Tarball { .. }));
                let store_v2_arg = store_v2_ref.as_deref();
                let (computed_sri, task_timings, final_url) = if is_tarball_source {
                    fetch_and_store_tarball_url(
                        &client,
                        &store_ref,
                        store_v2_arg,
                        &p,
                        queue_wait_ms,
                        permit,
                        &fetch_extract_limiter_c,
                    )
                    .await?
                } else if streaming_fetch {
                    fetch_and_store_streaming(
                        &client,
                        &route_table_c,
                        &store_ref,
                        store_v2_arg,
                        &p,
                        queue_wait_ms,
                        &project_dir_buf,
                        &gate_stats_c,
                        permit,
                        &fetch_extract_limiter_c,
                    )
                    .await?
                } else {
                    fetch_and_store_legacy(
                        &client,
                        &route_table_c,
                        &store_ref,
                        store_v2_arg,
                        &p,
                        queue_wait_ms,
                        &project_dir_buf,
                        &gate_stats_c,
                        permit,
                        &fetch_extract_limiter_c,
                    )
                    .await?
                };
                // Spawn per-pkg link immediately; the package is
                // now materialized. Runs on the blocking pool in parallel
                // with sibling fetch tasks still downloading.
                //
                // Pass the freshly-computed SRI as override so Source::Tarball
                // packages link from the integrity-keyed CAS path
                // (the freshly-stored content), not the legacy
                // registry slot. Registry sources ignore the override.
                let link_h = spawn_link(&p, Some(&computed_sri))?;

                // Dispatch v2 link entry materialization on the blocking pool now that the
                // tarball is extracted into `objects/<sri>/`. Runs in
                // parallel with sibling fetch tasks still downloading
                // and (importantly) cuts the post-fetch link-stage tail.
                let v2_link_h: Option<V2LinkHandle> =
                    if let (Some(plan), Some(target), Some(store_v2)) = (
                        v2_plan_arc.as_ref(),
                        v2_target_for_pkg.as_ref(),
                        store_v2_ref.as_ref(),
                    ) {
                        let plan_c = std::sync::Arc::clone(plan);
                        let target_c = target.clone();
                        let store_c = std::sync::Arc::clone(store_v2);
                        Some(spawn_v2_link_task(
                            plan_c,
                            target_c,
                            store_c,
                            Arc::clone(&v2_link_task_semaphore_c),
                        ))
                    } else {
                        None
                    };

                overall.inc(1);
                spec_tracker_c.mark_duplicated_if_failed(&package_key);
                Ok::<FetchTaskResult, LpmError>((
                    package_key,
                    package_display,
                    computed_sri,
                    task_timings,
                    link_h,
                    v2_link_h,
                    Some(final_url),
                ))
            }));
        }

        // Collect computed integrity hashes and fold per-task timings into
        // the aggregate breakdown. `fresh_urls` aggregates
        // the URL that actually served bytes for each (name, version),
        // so the writeback step at install-end can detect divergence
        // from the stored lockfile URL (stale-URL recovery) or from
        // `None` (origin-mismatch rebase that on-demand-resolved a
        // fresh URL).
        for handle in handles {
            let (pkg_key, package_display, sri, timings, link_h, v2_link_h, final_url) = handle
                .await
                .map_err(|e| LpmError::Registry(format!("download task panicked: {e}")))??;
            integrity_map.insert(pkg_key.clone(), sri);
            fetch_breakdown.record(timings);
            if let Some(package_display) = package_display.as_deref() {
                slow_package_timings.record_fetch(package_display, timings);
            }
            if let Some(lh) = link_h {
                event_link_handles.push(lh);
            }
            // followup #6b — funnel v2 link handles emitted
            // by the fetch tasks into the same drain queue the cache-
            // hit branches above feed.
            if let Some(lh) = v2_link_h {
                v2_event_link_handles.push(lh);
            }
            if let Some(url) = final_url {
                fresh_urls.insert(pkg_key, url);
            }
        }

        overall.finish_and_clear();
        fetch_stage_timings.download_wall_ms = download_wall_start.elapsed().as_millis();
    }

    if let Some(join) = fetch_overlap_join.take() {
        let drain = join.drain().await?;
        fetch_stage_timings.overlap = drain.stats;
        for outcome in drain.outcomes {
            if let Some(sri) = outcome.computed_sri {
                integrity_map.entry(outcome.key.clone()).or_insert(sri);
            }
            if let Some(timings) = outcome.timings {
                slow_package_timings.record_fetch(&outcome.package_display, timings);
            }
            if let Some(url) = outcome.final_url {
                fresh_urls.entry(outcome.key).or_insert(url);
            }
        }
    }

    let apply_fetch_writebacks = |packages: &mut [InstallPackage]| {
        for p in packages {
            let key = install_pkg_key(p);
            if let Some(sri) = integrity_map.get(&key) {
                p.integrity = Some(sri.clone());
            }
            if let Some(url) = fresh_urls.get(&key) {
                p.tarball_url = Some(url.clone());
            }
        }
    };
    apply_fetch_writebacks(&mut packages);
    apply_fetch_writebacks(&mut packages_for_lockfile);

    let fetch_ms = fetch_start.elapsed().as_millis();
    let wf_fetch_end_ms = start.elapsed().as_millis();

    // Drain any speculation tail after the authoritative fetch phase.
    // This preserves resolve/fetch overlap while making completed
    // speculation visible in the JSON counters.
    //
    // The walker summary is folded into
    // `timing.resolve.streaming_bfs` in the JSON-output block below.
    // `None` on warm lockfile-fast-path installs (walker never ran).
    if let Some(join) = speculation_join.take() {
        let summary = join.drain(&mut spec_stats).await;
        tracing::debug!(
            "walker summary: manifests_fetched={} cache_hits={} max_depth={} spec_tx_send_wait_ms={} walker_wall_ms={}",
            summary.manifests_fetched,
            summary.cache_hits,
            summary.max_depth,
            summary.spec_tx_send_wait_ms,
            summary.walker_wall_ms,
        );
        walker_summary_final = Some(summary);
    }
    let final_graph_keys: HashSet<String> = packages.iter().map(install_pkg_key).collect();
    spec_stats.consumed_by_fetch = spec_tracker.consumed_count();
    spec_stats.duplicated_with_fetch = spec_tracker.duplicated_count();
    spec_stats.failed = spec_tracker.failed_count();
    spec_stats.wasted = spec_tracker.wasted_count(&final_graph_keys);

    // Fetch / cache-hit counters are recorded into `fetch_ms` etc. and
    // surfaced via the verbose footer and JSON envelope. The default
    // human output is intentionally quiet here — the persistent
    // `› Installing N packages` line above already narrates this phase.

    // Step 4: link_targets — already built before the fetch loop ( //b) so the event-driven path could dispatch per-pkg link work
    // during fetch. No-op here to keep the surrounding structure stable.
    let _ = &link_targets; // retained for downstream consumers below

    // Step 5: Link into node_modules
    let wf_link_start_ms = start.elapsed().as_millis();
    let link_start = Instant::now();
    // Split of `link_ms` on the v2 event-driven path: time spent awaiting
    // per-package materialization tasks that spilled past fetch vs the
    // serial finalize pass (top-level symlinks + bin linking). Zero on the
    // other link paths.
    let mut wf_link_await_ms = 0u128;
    let mut wf_link_finalize_ms = 0u128;
    let mut wf_link_reconcile_ms = 0u128;
    let mut wf_link_root_symlinks_ms = 0u128;
    let mut wf_link_compatibility_ms = 0u128;
    let mut wf_link_bin_shims_ms = 0u128;

    let mut link_result = if event_driven_link {
        //b: event-driven path. Per-pkga future release2 tasks were
        // spawned inside the fetch loop and for each cached package
        // before the loop; await them here, aggregate counters, then
        // runa future release3.5+4 via `link_finalize`. `link_ms` measures
        // only the tail: any per-pkg link task still running past
        // `fetch_ms` plus the final finalize pass. Well-overlapped
        // installs show a near-zero link_ms.
        let mut linked_count = 0usize;
        let mut skipped_count = 0usize;
        let mut symlinked_count = 0usize;
        let mut materialized_all: Vec<MaterializedPackage> =
            Vec::with_capacity(event_link_handles.len());

        for lh in event_link_handles.drain(..) {
            let (m, r) = lh
                .await
                .map_err(|e| LpmError::Registry(format!("link task panicked: {e}")))??;
            materialized_all.push(m);
            if r.linked {
                linked_count += 1;
            } else {
                skipped_count += 1;
            }
            symlinked_count += r.symlinks_created;
        }

        let finalize = lpm_linker::link_finalize(project_dir, &link_targets, pkg.name.as_deref())?;
        symlinked_count += finalize.symlinks_created;

        LinkResult {
            linked: linked_count,
            symlinked: symlinked_count,
            bin_linked: finalize.bin_count,
            skipped: skipped_count,
            self_referenced: finalize.self_referenced,
            materialized: materialized_all,
        }
    } else if v2_mode {
        let store_v2 = store_v2_handle
            .as_deref()
            .expect("v2_mode implies v2 store handle is available");
        let v2_targets = build_v2_targets(&packages, &link_targets)?;

        // followup #6b — event-driven v2 path.
        //
        // When `v2_event_driven` was true, `link_v2_prepare` already
        // ran above and per-package `link_v2_one` tasks were spawned
        // by the cache-hit short-circuits and the fetch tasks.
        // Here we just await those handles, run `link_v2_finalize`,
        // and assemble the same `LinkResult` shape `link_packages_v2`
        // would have produced. The serial fall-back below keeps the
        // shape of the pre-#6b path for installs that didn't pass the
        // gate (e.g. `Source::Tarball` TOFU before the SRI is known).
        if v2_event_driven {
            let plan = v2_plan
                .as_ref()
                .expect("v2_event_driven implies v2_plan is Some");
            let mut materialized_all: Vec<MaterializedPackage> =
                Vec::with_capacity(v2_event_link_handles.len());
            let mut linked_count = 0usize;
            let link_await_start = Instant::now();
            for h in v2_event_link_handles.drain(..) {
                let task = h
                    .await
                    .map_err(|e| LpmError::Registry(format!("v2 link task panicked: {e}")))??;
                let package_display = timing_detail_mode
                    .trace()
                    .then(|| format!("{}@{}", task.materialized.name, task.materialized.version));
                v2_link_task_timings.record(task.ms, task.freshly_populated);
                if let Some(package_display) = package_display.as_deref() {
                    slow_package_timings.record_link_v2_one(package_display, task.ms);
                }
                if task.freshly_populated {
                    linked_count += 1;
                }
                materialized_all.push(task.materialized);
            }
            wf_link_await_ms = link_await_start.elapsed().as_millis();
            let link_finalize_start = Instant::now();
            let finalize =
                lpm_linker::v2::link_v2_finalize(project_dir, plan, store_v2, pkg.name.as_deref())?;
            wf_link_finalize_ms = link_finalize_start.elapsed().as_millis();
            wf_link_reconcile_ms = finalize.reconcile_ms;
            wf_link_root_symlinks_ms = finalize.root_symlinks_ms;
            wf_link_compatibility_ms = finalize.compatibility_ms;
            wf_link_bin_shims_ms = finalize.bin_shims_ms;
            let target_total = plan.augmented_targets.len();
            LinkResult {
                linked: linked_count,
                symlinked: finalize.symlinked,
                bin_linked: finalize.bin_count,
                skipped: target_total.saturating_sub(linked_count),
                self_referenced: finalize.self_referenced,
                materialized: materialized_all,
            }
        } else {
            lpm_linker::v2::link_packages_v2_with_compatibility_bin_names(
                project_dir,
                v2_targets,
                store_v2,
                linker_mode,
                pkg.name.as_deref(),
                compatibility_bin_names,
            )?
        }
    } else {
        match linker_mode {
            lpm_linker::LinkerMode::Hoisted => lpm_linker::link_packages_hoisted(
                project_dir,
                &link_targets,
                force,
                pkg.name.as_deref(),
            )?,
            lpm_linker::LinkerMode::Isolated => {
                lpm_linker::link_packages(project_dir, &link_targets, force, pkg.name.as_deref())?
            }
        }
    };

    let link_ms = link_start.elapsed().as_millis();
    let wf_link_end_ms = start.elapsed().as_millis();
    let mut wf_tail_blocked_metadata_ms = 0u128;
    let wf_tail_trust_snapshot_ms;
    // `link_ms` lands in the verbose footer and the JSON timing object;
    // no dedicated "Linked in Xms" line.

    // invariant: link workspace member dependencies AFTER
    // the regular linker run. The linker's stale-symlink cleanup pass at the
    // top of `link_packages` would otherwise wipe these symlinks on every
    // install (they're not in `direct_names` because workspace members were
    // stripped from `deps` before resolution by `extract_workspace_protocol_deps`).
    // Re-creating them here every time keeps the layout consistent.
    let workspace_links_created = link_workspace_members(project_dir, &workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info(&format!(
            "Linked {} workspace member(s)",
            workspace_links_created.to_string().bold()
        ));
    }

    //
    //
    // Run AFTER both the regular linker pass AND the workspace-member
    // linker pass, so every materialized destination is in place. Run
    // BEFORE the build-state capture so the patched bytes
    // are what `lpm rebuild` and `lpm approve-scripts` see.
    //
    // Apply is unconditional even on the lockfile fast path: see the
    // module-level comment in `patch_engine.rs` for why.
    let applied_patches = apply_patches_for_install(
        &current_patches,
        &link_result,
        &store,
        project_dir,
        json_output,
    )?;

    // Lifecycle script security audit + trusted script execution.
    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));

    // capture the install-time blocked set into
    // `<project_dir>/.lpm/build-state.json` so that:
    // 1. `lpm approve-scripts` doesn't have to re-walk the store on startup
    // 2. The post-install warning is suppressed when the blocked set is
    // unchanged from the previous install (the spam-prevention rule)
    // 3. Agents driving install via JSON output get a structured
    // `blocked_count` / `blocked_set_changed` summary
    let installed_with_integrity: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();
    let blocked_metadata_start = std::time::Instant::now();
    let blocked_set_metadata = if used_lockfile {
        let metadata = blocked_set_metadata_from_previous_state(project_dir);
        tracing::debug!(
            "perf.reuse_blocked_set_metadata pkgs={} entries={} ms={}",
            packages.len(),
            metadata.by_pkg.len(),
            blocked_metadata_start.elapsed().as_millis()
        );
        metadata
    } else {
        let metadata = lpm_registry::timing::with_metadata_purpose(
            lpm_registry::timing::MetadataPurpose::BlockedSet,
            build_blocked_set_metadata(arc_client.as_ref(), &route_table, &packages),
        )
        .await;
        wf_tail_blocked_metadata_ms = blocked_metadata_start.elapsed().as_millis();
        tracing::debug!(
            "perf.build_blocked_set_metadata pkgs={} ms={}",
            packages.len(),
            wf_tail_blocked_metadata_ms
        );
        metadata
    };
    // Parse the project
    // capability request + user bound ONCE per install so the
    // install-time blocked-set capture, the autoBuild trust check
    // below, and approve-scripts later all see the same canonical
    // object. Without threading these through the capture call,
    // capability-widened packages with matching script-hash
    // approvals would slip past the blocked-set (build_state.rs's
    // compute_blocked_packages_with_metadata filter) — the
    // reviewer's High finding. Fix makes install-time capture
    // consistent with 6c's runtime enforcement.
    let install_requested_capabilities =
        crate::capability::CapabilitySet::from_package_json(&project_dir.join("package.json"))
            .map_err(|e| LpmError::Registry(format!("{e}")))?;
    let install_user_bound = crate::security_approval::authorized_capability_user_bound();

    // **Resolve script-policy + preflight advisor BEFORE the blocked-set capture.**
    //
    // The capture writes to `.lpm/build-state.json`. If the advisor
    // approves an amber package this run, that package's scripts run
    // via the AdvisorApprovedThisRun trust path during autoBuild; we
    // therefore want it EXCLUDED from the persisted blocked set so
    // post-install JSON + the "remain blocked after auto-build"
    // pointer don't report stale state.
    //
    // Order:
    // 1. Read project script-policy config (one disk read; reused
    // by the autoBuild branch later).
    // 2. Resolve effective policy through the precedence chain.
    // 3. Build the AdvisorSession (preflight + classify amber).
    // 4. Pass `session.approvals()` into the capture call below.
    let step10_script_policy_cfg =
        crate::script_policy_config::ScriptPolicyConfig::from_package_json(project_dir);
    let config_auto_build = step10_script_policy_cfg.auto_build;
    let step10_effective_policy = crate::script_policy_config::resolve_script_policy_with_security(
        project_dir,
        script_policy_override,
        &step10_script_policy_cfg,
        json_output,
    )?;

    //: include integrity so the auto-build predicate's
    // strict gate matches what `rebuild::run` will do. Same data
    // shape as `installed_with_integrity` above; named separately
    // because it's consumed by `all_scripted_packages_trusted`
    // later and historically lived next to that call.
    let all_pkgs_for_build: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();

    //
    //
    // Preflight the configured advisor ONCE per run. Session stays
    // active only when:
    // - script-policy resolved to `triage`,
    // - `triage-advisor` is set to something other than `none`,
    // - detect + test-invoke succeed.
    //
    // Any failure degrades to none with a single warning. Per-
    // package classification failures later stay silent — preflight
    // already warned (or didn't, if the user configured `none`).
    //
    // Precedence chain for `triage-advisor` (highest first):
    // - CLI `--advisor` flag (slug validated at the clap layer in
    // `main.rs::parse_advisor_slug`; `Some` here is guaranteed to
    // be `"none"` or a known provider).
    // - `package.json > lpm > triageAdvisor`
    // - `~/.lpm/config.toml` `triage-advisor` key
    // - default `none`
    let advisor_session =
        if step10_effective_policy == crate::script_policy_config::ScriptPolicy::Triage {
            let triage_advisor_pkg_json = step10_script_policy_cfg.triage_advisor.as_deref();
            let triage_advisor_global = global_config.get_str("triage-advisor");
            let mut session = crate::triage_advisor_session::AdvisorSession::preflight(
                advisor_override.as_deref(),
                triage_advisor_pkg_json,
                triage_advisor_global,
                json_output,
            )
            .await;
            // If the session is active, classify every amber package
            // declared in the current install set. The advisor's
            // `Approve` verdicts populate an in-memory approval set
            // that's threaded into the blocked-set capture (so
            // approved packages are excluded from the persisted
            // blocked set), the autoBuild predicate, AND
            // `rebuild::run` (the actual script-execution path).
            // The set never persists.
            if session.is_active() {
                let amber_requests = collect_amber_classification_requests(
                    &store,
                    &installed_with_integrity,
                    &publish_ages,
                    cooldown_policy.minimum_release_age_secs,
                );
                // `classify_amber` is async + serial. Slice 1 keeps
                // it simple; future parallel-fanout can ride on top.
                session.classify_amber(&amber_requests).await;
            }
            Some(session)
        } else {
            None
        };

    // Compute the
    // auto-build decision BEFORE the blocked-set capture so the
    // capture can condition the advisor-approval exclusion on
    // whether scripts will actually run this install.
    //
    // The bug we are closing: an advisor `Approve` verdict has two
    // observable effects — (1) the package's scripts run via the
    // AdvisorApprovedThisRun trust path during autoBuild, and
    // (2) the package is omitted from the persisted blocked set
    // (so post-install messaging + `lpm approve-scripts` don't
    // report stale "still blocked" state). Effect (2) is only
    // valid when (1) actually fires. In a mixed-triage install
    // where the advisor approves A but leaves B blocked, with
    // `--auto-build` off and `autoBuild: false`, `all_trusted` is
    // false → autoBuild does not fire → A's scripts never run, AND
    // A vanishes from `build-state.json` → unreachable via
    // `approve-scripts` either. "Stranded: not executed, not
    // reviewable."
    //
    // Fix: pass `advisor_approvals` to the capture iff
    // `auto_build_attempted` is true. When auto-build won't fire,
    // the persisted blocked set continues to surface the
    // advisor-approved-but-not-run package, and the user can review
    // it explicitly via `lpm approve-scripts` (the ephemeral
    // approval is gone after this run — by design, since approvals
    // never persist).
    //
    // `all_scripted_packages_trusted` ALWAYS receives the approvals
    // — its purpose is to decide whether autoBuild should fire, and
    // an advisor-approved amber correctly counts as trusted for
    // that gate.
    let force_security_floor = global_config
        .get_bool("force-security-floor")
        .unwrap_or(false);
    let all_trusted_for_auto_build = crate::commands::rebuild::all_scripted_packages_trusted(
        lpm_root,
        &all_pkgs_for_build,
        &policy,
        project_dir,
        step10_effective_policy,
        force_security_floor,
        &install_requested_capabilities,
        &install_user_bound,
        advisor_session.as_ref().map(|s| s.approvals()),
    );
    let auto_build_attempted = should_auto_build(
        auto_build,
        config_auto_build,
        all_trusted_for_auto_build,
        step10_effective_policy,
    );
    let auto_build_will_execute = auto_build_attempted && !step10_script_policy_cfg.deny_all;

    let capture_start = std::time::Instant::now();
    let mut blocked_capture = crate::build_state::capture_blocked_set_after_install_with_metadata(
        project_dir,
        &store,
        &installed_with_integrity,
        &policy,
        &blocked_set_metadata,
        &install_requested_capabilities,
        &install_user_bound,
        // Conditional: only exclude advisor-approved triples when
        // autoBuild will actually execute their scripts this run.
        // See `select_approvals_for_capture` for the rationale —
        // closes the "stranded approval" bug.
        select_approvals_for_capture(
            auto_build_will_execute,
            advisor_session.as_ref().map(|s| s.approvals()),
        ),
    )?;
    tracing::debug!(
        "perf.capture_blocked_set pkgs={} ms={}",
        installed_with_integrity.len(),
        capture_start.elapsed().as_millis()
    );

    //: persist the current `trustedDependencies` as a
    // snapshot so the NEXT install's diff has a baseline. Write
    // failures are non-fatal — an install that reached this point has
    // already succeeded as far as the user cares, and the worst-case
    // of a missing snapshot is "the next install's diff notice
    // doesn't fire," which degrades to the pre-46 behavior.
    {
        let trust_snap_start = std::time::Instant::now();
        let snap = crate::trust_snapshot::TrustSnapshot::capture_current(pkg.lpm.as_ref().map_or(
            &lpm_workspace::TrustedDependencies::Legacy(Vec::new()),
            |l| &l.trusted_dependencies,
        ));
        if let Err(e) = crate::trust_snapshot::write_snapshot(project_dir, &snap) {
            tracing::warn!("failed to write trust-snapshot.json: {e}");
        }
        wf_tail_trust_snapshot_ms = trust_snap_start.elapsed().as_millis();
        tracing::debug!("perf.trust_snapshot ms={}", wf_tail_trust_snapshot_ms);
    }

    // Step 7: LPM-Native Intelligence
    // Read strictness from package.json "lpm" config
    let strict_deps = pkg
        .lpm
        .as_ref()
        .and_then(|l| l.strict_deps.as_deref())
        .unwrap_or("warn");

    if strict_deps != "loose" && !json_output {
        let installed_names: std::collections::HashSet<String> =
            packages.iter().map(|p| p.name.clone()).collect();

        // Phantom dependency detection
        let phantom_result =
            crate::intelligence::detect_phantom_deps(project_dir, &declared_deps, &installed_names);

        if !phantom_result.phantom_imports.is_empty() {
            eprintln!();
            install_ui::warn(&format!(
                "{} phantom dependency import(s) detected:",
                phantom_result.phantom_imports.len()
            ));
            for phantom in phantom_result.phantom_imports.iter().take(5) {
                let rel_file = phantom
                    .file
                    .strip_prefix(project_dir)
                    .unwrap_or(&phantom.file);
                eprintln!(
                    "    {} ({}:{})",
                    phantom.package_name.bold(),
                    rel_file.display().to_string().dimmed(),
                    phantom.line,
                );
                if let Some(via) = &phantom.available_via {
                    eprintln!("      {}", via.dimmed());
                }
                eprintln!(
                    "      Fix: {}",
                    format!("lpm install {}", phantom.package_name).dimmed()
                );
            }
            if phantom_result.phantom_imports.len() > 5 {
                eprintln!(
                    "    ... and {} more",
                    phantom_result.phantom_imports.len() - 5
                );
            }
        }

        // Import verification (only in strict mode)
        if strict_deps == "strict" {
            let verification =
                crate::intelligence::verify_imports(project_dir, &installed_names, &deps);
            if !verification.unresolved.is_empty() {
                eprintln!();
                install_ui::warn(&format!(
                    "{} import(s) will fail at runtime:",
                    verification.unresolved.len()
                ));
                for unresolved in &verification.unresolved {
                    let rel_file = unresolved
                        .file
                        .strip_prefix(project_dir)
                        .unwrap_or(&unresolved.file);
                    eprintln!(
                        "    {}:{} → {}",
                        rel_file.display().to_string().dimmed(),
                        unresolved.line,
                        format!("import \"{}\"", unresolved.specifier).bold(),
                    );
                    eprintln!("      {}", unresolved.suggestion.dimmed());
                }
            }
        }

        // Quality warnings for LPM packages
        let lpm_packages: Vec<(String, String)> = packages
            .iter()
            .filter(|p| p.is_lpm)
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();

        if !lpm_packages.is_empty() {
            let quality_threshold = pkg
                .lpm
                .as_ref()
                .and_then(|l| l.strict_deps.as_deref()) // reuse as quality gate
                .map_or(30, |_| 50u32); // default: only warn below 30

            // Step 6 fix (empty-bearer regression #1).
            // Previously this site constructed a fresh RegistryClient and
            // attached `crate::auth::get_token(...).unwrap_or_default()`,
            // which sent literal `Authorization: Bearer ` (empty value)
            // headers when no token was stored. Now we use the
            // injected client directly — its `current_bearer` filters
            // empty strings and its `SessionManager` carries the
            // refresh-eligible session.
            let warnings = crate::intelligence::check_install_quality(
                client,
                &lpm_packages,
                quality_threshold,
            )
            .await;

            for warning in &warnings {
                let icon = match warning.severity {
                    crate::intelligence::WarningSeverity::Critical => "✗".to_string(),
                    crate::intelligence::WarningSeverity::Warning => "!".to_string(),
                    crate::intelligence::WarningSeverity::Info => "ℹ".to_string(),
                };
                println!(
                    "  {icon} {}@{}: {}",
                    warning.package_name, warning.version, warning.message
                );
            }

            // Security summary for ALL packages (client-side analysis + registry enrichment)
            if !no_security_summary {
                let all_packages: Vec<(String, String, bool)> = packages
                    .iter()
                    .map(|p| (p.name.clone(), p.version.clone(), p.is_lpm))
                    .collect();
                // Step 6 fix (empty-bearer regression #2).
                // Same defect as the intelligence::check_install_quality
                // site above; resolved the same way — use the injected
                // client.
                crate::security_check::post_install_security_summary(
                    client,
                    &store,
                    &all_packages,
                    json_output,
                    false, // not quiet — show Medium tier too
                )
                .await;
            }
        }
    }

    // Step 8: Auto-install skills for direct LPM packages
    if !json_output && !no_skills {
        let lpm_packages: Vec<String> = packages
            .iter()
            .filter(|p| p.is_lpm && p.is_direct)
            .map(|p| p.name.clone())
            .collect();

        if !lpm_packages.is_empty() {
            install_skills_for_packages(&arc_client, &lpm_packages, project_dir, no_editor_setup)
                .await;
        }
    }

    // Step 9: Write lockfile (only if we resolved fresh)
    if !used_lockfile {
        let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver(resolved_with);
        lockfile.metadata.auto_isolated_peer_conflicts = auto_isolated_peer_conflicts;
        let ephemeral_workspace_pkg_keys: HashSet<String> = v2_workspace_root_pre_resolve
            .install_pkgs
            .iter()
            .map(install_pkg_key)
            .collect();
        let persisted_packages: Vec<InstallPackage> = packages_for_lockfile
            .iter()
            .filter(|p| !ephemeral_workspace_pkg_keys.contains(&install_pkg_key(p)))
            .cloned()
            .collect();
        for p in &persisted_packages {
            let dep_strings: Vec<String> = p
                .dependencies
                .iter()
                .map(|(dep_name, dep_ver)| format!("{dep_name}@{dep_ver}"))
                .collect();

            // — persist npm-alias edges as `[local, target]`
            // pairs. The matching `<local>@<version>` entry is already
            // in `dep_strings`; this map keys the alias target so the
            // warm-install path can rebuild `InstallPackage.aliases`
            // without re-running the resolver.
            let alias_pairs: Vec<[String; 2]> = p
                .aliases
                .iter()
                .map(|(local, target)| [local.clone(), target.clone()])
                .collect();

            // persist resolved peers per package as
            // `<peer_name>@<version>` strings (same shape as
            // `dependencies`). Sorted upstream by `format_solution` /
            // `into_resolved_packages`; copied verbatim. Empty for
            // packages without peers — the serde
            // `skip_serializing_if = "Vec::is_empty"` keeps lockfiles
            // of older projects byte-identical.
            let peer_strings: Vec<String> = p
                .peers
                .iter()
                .map(|(name, version)| format!("{name}@{version}"))
                .collect();
            let tarball_field_hint =
                if matches!(p.source_kind(), Ok(lpm_lockfile::Source::Registry { .. })) {
                    p.tarball_url.clone()
                } else {
                    None
                };

            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                source: Some(p.source.clone()),
                integrity: p.integrity.clone(),
                registry_signatures: lockfile_registry_signatures(&p.registry_signatures),
                registry_published_at: p.registry_published_at.clone(),
                os: p.platform.as_ref().map_or_else(Vec::new, |m| m.os.clone()),
                cpu: p.platform.as_ref().map_or_else(Vec::new, |m| m.cpu.clone()),
                libc: p
                    .platform
                    .as_ref()
                    .map_or_else(Vec::new, |m| m.libc.clone()),
                optional: p.optional,
                dependencies: dep_strings,
                alias_dependencies: alias_pairs,
                peers: peer_strings,
                // — persist the tarball URL the registry
                // returned at resolve time so warm installs can skip
                // the per-package metadata round-trip. Consumed by
                // `try_lockfile_fast_path` through `evaluate_cached_url`.
                tarball: tarball_field_hint,
            });
        }

        // — persist the root-level alias map so warm
        // installs can rebuild `node_modules/<local>/` symlinks
        // without re-resolving. The HashMap → BTreeMap conversion
        // gives deterministic serialized order, matching the
        // sort-by-name policy on `packages`.
        lockfile.root_aliases = root_aliases_for_lockfile(&persisted_packages, &deps);

        // persist the resolver's `ambient_peer_installs`
        // set so the warm-install fast path knows which canonicals
        // to surface as top-level node_modules entries. Without this,
        // `rm -rf node_modules && lpm install` from the lockfile
        // would skip the auto-installed peer (it isn't in
        // `pkg.dependencies`) and produce a broken tree.
        lockfile.ambient_peer_installs = ambient_peer_installs_for_lockfile.clone();
        let lockfile_catalog_resolutions = catalog_resolutions_for_lockfile(
            &catalog_resolutions[..dependency_catalog_resolution_count],
            &override_catalog_resolutions,
            &applied_overrides,
        );
        lockfile.catalogs = catalog_snapshot_from_install_packages(
            &lockfile_catalog_resolutions,
            &persisted_packages,
        )?;
        lockfile.patches = current_lockfile_patches.clone();
        lockfile
            .importers
            .insert(".".to_string(), current_importer_snapshot.clone());

        let lockfile_write_start = std::time::Instant::now();
        lockfile
            .write_all(&lockfile_path)
            .map_err(|e| LpmError::Registry(format!("failed to write lockfile: {e}")))?;
        wf_tail_lockfile_write_ms =
            wf_tail_lockfile_write_ms.saturating_add(lockfile_write_start.elapsed().as_millis());
        wf_tail_lockfile_write_count = wf_tail_lockfile_write_count.saturating_add(1);

        lpm_lockfile::ensure_gitattributes(project_dir)
            .map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

    // The lockfile-size line moved into the `--verbose` footer at
    // the end of the install, alongside the per-phase timing
    // breakdown.
    } else if !frozen_lockfile_active && let Some(mut lockfile) = fast_path_lockfile.take() {
        // When the fast path ran, we skip the fresh-resolve writer
        // above. A few lockfile-maintenance signals can still require
        // a rewrite:
        //
        // 1. `fresh_urls` is non-empty — at least one URL diverged
        // from the stored value (stale-URL recovery and/or
        // origin-mismatch rebase). Without the rewrite, the
        // divergence recurs on every subsequent install.
        // 2. `needs_binary_upgrade` — the `lpm.lockb` was
        // missing or out-of-version. Fast-path-only runs would
        // otherwise defer the binary migration indefinitely.
        // 3. Importer snapshots are missing/stale, or the TOML schema
        // version predates the current frozen-install contract.
        //
        // On the true happy path, all signals are clean and no write
        // fires, so lockfiles stay byte-identical.
        let url_churn = !fresh_urls.is_empty();
        let importer_snapshot_changed =
            lockfile.importers.get(".") != Some(&current_importer_snapshot);
        let patch_records_changed = lockfile.patches != current_lockfile_patches;
        let schema_version_changed =
            lockfile.metadata.lockfile_version < lpm_lockfile::LOCKFILE_VERSION;
        if importer_snapshot_changed || patch_records_changed || schema_version_changed {
            lockfile.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION;
            lockfile.patches = current_lockfile_patches.clone();
            lockfile
                .importers
                .insert(".".to_string(), current_importer_snapshot.clone());
        }

        if url_churn
            || needs_binary_upgrade
            || importer_snapshot_changed
            || patch_records_changed
            || schema_version_changed
        {
            // Patch `lp.tarball` in place for every package whose
            // final URL diverged. Linear scan over `fresh_urls` is
            // fine — even large workspaces have <1k packages and
            // churn is rare in steady state.
            for lp in &mut lockfile.packages {
                // Build the same compound key used during insertion
                // ("name\x00version\x00source"). LockedPackage.source
                // matches InstallPackage.source for all packages written
                //+; pre-59 lockfiles have source=None but
                // fresh_urls will be empty for those warm installs.
                let src = lp.source.as_deref().unwrap_or("");
                let lp_key = {
                    let mut k =
                        String::with_capacity(lp.name.len() + 1 + lp.version.len() + 1 + src.len());
                    k.push_str(&lp.name);
                    k.push('\x00');
                    k.push_str(&lp.version);
                    k.push('\x00');
                    k.push_str(src);
                    k
                };
                if let Some(url) = fresh_urls.get(&lp_key) {
                    lp.tarball = Some(url.clone());
                }
            }

            let lockfile_write_start = std::time::Instant::now();
            lockfile
                .write_all(&lockfile_path)
                .map_err(|e| LpmError::Registry(format!("failed to rewrite lockfile: {e}")))?;
            wf_tail_lockfile_write_ms = wf_tail_lockfile_write_ms
                .saturating_add(lockfile_write_start.elapsed().as_millis());
            wf_tail_lockfile_write_count = wf_tail_lockfile_write_count.saturating_add(1);

            if !json_output {
                // Observable output so the user can see why the
                // lockfile's mtime changed.
                if url_churn && needs_binary_upgrade {
                    output::info(&format!(
                        "Refreshed {} stale tarball URL(s) + upgraded lpm.lockb to v{}",
                        fresh_urls.len(),
                        lpm_lockfile::binary::BINARY_VERSION,
                    ));
                } else if url_churn {
                    output::info(&format!(
                        "Refreshed {} stale tarball URL(s) in lockfile",
                        fresh_urls.len(),
                    ));
                } else {
                    output::info(&format!(
                        "Upgraded lpm.lockb to v{} format",
                        lpm_lockfile::binary::BINARY_VERSION,
                    ));
                }
            }
        }
    }

    // Step 10: Auto-build trusted packages (after lockfile is written)
    // Triggers when: --auto-build flag, lpm.scripts.autoBuild config,
    // ALL scripted packages are individually trusted, OR the effective
    // policy is Allow (— `--yolo` / `--policy=allow` runs
    // scripts at install time, matching npm/pnpm/bun semantics).
    //
    //: consolidated into ScriptPolicyConfig so all four
    // script-related keys come from a single read.
    //
    // Script-policy resolution + advisor preflight runs before the
    // blocked-set capture (so approved packages can be excluded from the
    // persisted set). The
    // `step10_*` locals + `all_pkgs_for_build` + `advisor_session`
    // they produce are still in scope here; only the autoBuild
    // predicate + the rebuild::run call read them. No duplication.

    // These values are computed before blocked-set capture so the
    // advisor-approval exclusion can depend on whether auto-build will
    // actually execute.
    if auto_build_attempted {
        //: preflight version-diff cards for any green
        // about to auto-execute that has a prior-approved binding
        // for a strictly-lesser version. Renders BEFORE `rebuild::run`
        // so the user sees the unified script-body diff and the
        // behavioral-tag delta before any code runs. No-ops for
        // non-triage policies and json mode (gates inside the helper).
        maybe_emit_pre_autobuild_version_diff_cards(
            project_dir,
            &store,
            auto_build_attempted,
            step10_effective_policy,
            &blocked_capture,
            json_output,
        );
    }
    let mut auto_build_report = crate::commands::rebuild::RebuildRunReport::default();
    if auto_build_attempted {
        match crate::commands::rebuild::run_with_report(
            project_dir,
            &[],   // no specific packages — build all trusted
            false, // not --all
            false, // not dry-run
            false, // not --force
            None,  // default timeout
            json_output,
            false, // not --deny-all
            // forward the user's CLI
            // sandbox-mode choice to the auto-build rebuild call.
            // When the user explicitly opts into strict, the
            // auto-build greens run under strict too. When the user
            // explicitly drops the sandbox (`--no-sandbox`), the
            // auto-build greens skip containment too — consistent
            // with the user's chosen capability boundary. The
            // env / config / default precedence stays intact when
            // both flags are false (the chain resolver inside
            // `rebuild::run_under_store_lock` walks lpm.toml /
            // `~/.lpm/config.toml` / `LPM_STRICT_SANDBOX` env).
            //
            // `sandbox_log` stays false: it's a diagnostic-only
            // override the user must spell out explicitly on
            // `lpm rebuild`, not a default that auto-build inherits.
            no_sandbox,
            strict_sandbox,
            false, // sandbox_log
            step10_effective_policy,
            advisor_session.as_ref().map(|s| s.approvals()),
        )
        .await
        {
            Ok(report) => {
                auto_build_report = report;
            }
            Err(e) => {
                if !json_output {
                    output::warn(&format!("Auto-build failed: {e}"));
                }
                return Err(e);
            }
        }
    }

    if auto_build_report.covered_any_packages() {
        let execution_exclusions = auto_build_report
            .covered_packages
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        blocked_capture =
            crate::build_state::capture_blocked_set_after_install_with_metadata_and_exclusions(
                project_dir,
                &store,
                &installed_with_integrity,
                &policy,
                &blocked_set_metadata,
                &install_requested_capabilities,
                &install_user_bound,
                select_approvals_for_capture(true, advisor_session.as_ref().map(|s| s.approvals())),
                Some(&execution_exclusions),
            )?;
    }

    if auto_build_report.covered_any_packages() || auto_build_report.built_any_packages() {
        let relinked_bins = relink_bins_after_lifecycle_build(
            project_dir,
            &packages,
            &link_targets,
            linker_mode,
            lpm_root,
            pkg.name.as_deref(),
            compatibility_bin_names,
        )?;
        link_result.bin_linked = relinked_bins;
    }

    // post-auto-build canonical pointer.
    //
    // Under `script-policy = "triage"` the rebuild helper runs green
    // packages when auto-build fires, while amber / red packages remain
    // in `build-state.json`. The pre-auto-build triage summary line is
    // then stale, so emit a follow-up pointer for the remaining reviews.
    //
    // JSON mode: per-entry `static_tier` enrichment below in the
    // JSON output block gives agents the machine-readable shape; no
    // extra line here. Non-JSON: one concise warn line after a
    // successful auto-build that still leaves amber/red packages for
    // explicit review.
    maybe_emit_post_auto_build_triage_pointer(
        auto_build_attempted,
        step10_effective_policy,
        &blocked_capture,
        json_output,
    );

    let elapsed = start.elapsed();

    // persist `.lpm/overrides-state.json`. Three
    // cases:
    // 1. Override set is non-empty → write the fresh state (or, on the
    // lockfile fast path, preserve the previously-recorded apply
    // trace so `lpm graph --why` doesn't go blind).
    // 2. Override set is empty AND a stale state file exists → delete
    // it so introspection commands don't pick up old data.
    // 3. Override set is empty AND no state file → no-op.
    if !override_set.is_empty() {
        let state = if used_lockfile {
            // Lockfile fast path: nothing was re-resolved, so preserve
            // whatever the previous fresh-resolve recorded.
            let prior_applied = prior_overrides_state
                .as_ref()
                .map(|s| s.applied.clone())
                .unwrap_or_default();
            overrides_state::OverridesState::capture_preserving_applied(
                &override_set,
                prior_applied,
            )
        } else {
            overrides_state::OverridesState::capture(&override_set, applied_overrides.clone())
        };
        if let Err(e) = overrides_state::write_state(project_dir, &state) {
            tracing::warn!("failed to write overrides-state.json: {e}");
        }
    } else if prior_overrides_state.is_some()
        && let Err(e) = overrides_state::delete_state(project_dir)
    {
        tracing::warn!("failed to delete stale overrides-state.json: {e}");
    }

    // persist `.lpm/patch-state.json`.
    // invariant : preserve the prior `applied` trace on
    // idempotent reruns so `lpm graph --why` doesn't lose provenance
    // when an install does no work. See `persist_patch_state`.
    persist_patch_state(
        project_dir,
        &current_patches,
        &prior_patch_state,
        &applied_patches,
    );

    if cleanup_catalogs_in_pipeline {
        cleanup_unused_catalogs_after_install(project_dir)?;
    }

    // Audit-after-install: run a silent audit pass and stash the
    // resulting counts. Both the JSON envelope and the human Done
    // block consume `audit_summary_for_envelope` below; computing
    // once here keeps the two surfaces in sync.
    //
    // Failure mode: never fails the install — audit findings are
    // informational only, per the opt-in contract. Errors degrade to
    // `None` and the install pipeline carries on. The error is logged
    // for operators tailing `LPM_LOG`.
    let audit_summary_for_envelope: Option<crate::commands::audit::AuditCounts> =
        if audit_after_install {
            let audit_start = std::time::Instant::now();
            let summary = if maybe_test_audit_after_install_should_fail() {
                tracing::warn!(
                    "audit-after-install failed: test-injected failure \
                 (LPM_TEST_AUDIT_AFTER_INSTALL_FAIL=1)"
                );
                None
            } else {
                match crate::commands::audit::run_install_summary(client, project_dir).await {
                    Ok(opt) => opt,
                    Err(e) => {
                        tracing::warn!("audit-after-install failed: {e}");
                        None
                    }
                }
            };
            wf_tail_audit_after_install_ms = audit_start.elapsed().as_millis();
            summary
        } else {
            None
        };

    if json_output {
        let metadata_http_versions = lpm_registry::timing::snapshot_metadata_http_versions();
        let timing_metadata_detail = if timing_detail_mode.enabled() {
            Some(metadata_detail_snapshots())
        } else {
            None
        };
        let resolve_wall_ms = wf_resolve_end_ms.saturating_sub(wf_setup_ms);
        let fetch_wall_ms = wf_fetch_end_ms.saturating_sub(wf_fetch_start_ms);
        let pkg_list: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "direct": p.is_direct,
                })
            })
            .collect();

        let mut json = serde_json::json!({
                   "success": true,
                   "packages": pkg_list,
                   "count": packages.len(),
                   "downloaded": downloaded,
                   "cached": cached,
                   "linked": link_result.linked,
                   "symlinked": link_result.symlinked,
                   "used_lockfile": used_lockfile,
                   "duration_ms": elapsed.as_millis() as u64,
                   "timing": {
                       "resolve_ms": resolve_ms,
                       "fetch_ms": fetch_ms,
                       "link_ms": link_ms,
                       "total_ms": elapsed.as_millis(),
                       "waterfall": {
                           "setup_ms": wf_setup_ms,
                           "resolve_ms": wf_resolve_end_ms.saturating_sub(wf_setup_ms),
                           "pre_fetch_ms": wf_fetch_start_ms.saturating_sub(wf_resolve_end_ms),
                           "fetch_ms": wf_fetch_end_ms.saturating_sub(wf_fetch_start_ms),
                           "pre_link_ms": wf_link_start_ms.saturating_sub(wf_fetch_end_ms),
                           "link_ms": wf_link_end_ms.saturating_sub(wf_link_start_ms),
                           "link_await_ms": wf_link_await_ms,
                           "link_finalize_ms": wf_link_finalize_ms,
                           "tail_ms": elapsed.as_millis().saturating_sub(wf_link_end_ms),
                           "total_ms": elapsed.as_millis(),
                       },
        // Nested resolver breakdown:
        //
        // seeded this object with `platform_skipped`.
        // grows with the cold-resolve substage
        // breakdown so consumers can attribute `resolve_ms`
        // to a specific contributor before work starts on
        // (deeper worker walk) / (parallel follow-
        // ups) /d (slim batch response).
        //
        // Field shape:
        // platform_skipped — optional deps filtered by os/cpu ()
        // initial_batch_ms — wall-clock from
        // orchestration start to the
        // moment the resolver could begin
        // solving (walker's roots_ready
        // signal). The new-shape analog
        // of the pre-49 "batch prefetch
        // done" timestamp. On
        // lockfile-fast-path, zero.
        // Does NOT include PubGrub
        // wall-clock (reported separately
        // as `pubgrub_ms`).
        // followup_rpc_ms — metadata RPCs fired by the
        // resolver's PubGrub callbacks
        // (theb/ lever).
        // followup_rpc_count — count of those follow-up RPCs.
        // parse_ndjson_ms — serde_json CPU time for
        // follow-up batches ( lever).
        // pubgrub_ms — wall-clock inside
        // `pubgrub::resolve()` (includes
        // provider callbacks).
        //
        // `resolve_ms` stays as a top-level scalar for
        // backwards compatibility; the substages inside
        // `resolve` are additive observability.
                       "resolve": {
                           "platform_skipped": platform_skipped,
                           "initial_batch_ms": initial_batch_ms,
                           "followup_rpc_ms": resolver_stage_timing.followup_rpc_ms,
                           "followup_rpc_count": resolver_stage_timing.followup_rpc_count,
        // A1 — split formerly-conflated count into
        // walker-driven and escape-hatch buckets so
        // operators can tell whether the walker covered the
        // tree or the resolver picked up slack via direct
        // fetches. Sum of these two equals followup_rpc_count.
        //
        // zero on the fused dispatcher arm
        // (`LPM_GREEDY_FUSION=1`); see `dispatcher.*`
        // below. Retained for one release; removed in.
                           "walker_rpc_count": resolver_stage_timing.walker_rpc_count,
                           "escape_hatch_rpc_count": resolver_stage_timing.escape_hatch_rpc_count,
                           "parse_ndjson_ms": resolver_stage_timing.parse_ndjson_ms,
                           "pubgrub_ms": resolver_stage_timing.pubgrub_ms,
                           "metadata_http_versions": {
                               "http_09": metadata_http_versions.http_09,
                               "http_10": metadata_http_versions.http_10,
                               "http_11": metadata_http_versions.http_11,
                               "http_2": metadata_http_versions.http_2,
                               "http_3": metadata_http_versions.http_3,
                               "unknown": metadata_http_versions.unknown,
                           },
        // — fused metadata-dispatcher counters. Zero on
        // the walker arm; populated under greedy fusion.
        // Field shape:
        // rpc_count — total metadata RPCs the
        // dispatcher fired
        // (replaces walker +
        // escape_hatch on fusion).
        // inflight_high_water — peak in-flight metadata
        // fetches; approaching the
        // configured fanout means the
        // semaphore is binding.
        // parked_max_depth — peak Vec length in the
        // per-canonical park map;
        // healthy values are O(few),
        // hundreds = stalled CDN
        // pin on one package.
        // tarball_dispatched — speculative tarball
        // metadata frames emitted
        // by resolver arms that
        // enable CLI speculation.
        // Fusion leaves this at 0
        // by default and lets the
        // exact graph feed fetch.
        // peer_prefetch_count — speculative
        // peer-manifest fetches
        // dispatched concurrent with
        // the regular dep walk.
        // Each such fetch saved one
        // sequential round-trip from
        // the post-loop drain pass.
                           "dispatcher": {
                               "rpc_count": resolver_stage_timing.dispatcher_rpc_count,
                               "inflight_high_water":
                                   resolver_stage_timing.dispatcher_inflight_high_water,
                               "parked_max_depth": resolver_stage_timing.parked_max_depth,
                               "tarball_dispatched":
                                   resolver_stage_timing.tarball_dispatched_count,
                               "peer_prefetch_count":
                                   resolver_stage_timing.peer_prefetch_count,
                           },
        //: streaming-BFS observability per
        // design. Null on warm lockfile-fast-path
        // installs (walker never ran). Field shape:
        // walk_ms — walker's metadata-producer
        // window (from
        // `WalkerSummary::walker_wall_ms`).
        // manifests_fetched — count of packages the walker
        // inserted into SharedCache.
        // cache_hits — count of names skipped because
        // SharedCache already held them
        // (walker's cache-hit path).
        // cache_waits — provider-side: PubGrub callbacks
        // that entered the wait-loop on
        // a cache miss (fast-path cache
        // hits NOT counted). NOT equal to
        // installed package count —
        // ensure_cached is called from
        // multiple sites and may re-enter
        // across split retries. Treat
        // qualitatively: "how many times
        // did PubGrub wait on the walker."
        // cache_wait_timeouts — provider-side: wait-loop exits
        // by `fetch_wait_timeout`
        // firing. Healthy 0; non-zero
        // means a sleeper waited the
        // full timeout without the
        // walker either inserting or
        // flipping `walker_done`
        // (pre-49 wait-loop shape, or
        // a regression of the
        // shutdown handshake).
        // cache_wait_walker_done_shortcuts
        // — provider-side: wait-loop
        // exits *early* because the
        // walker terminated without
        // inserting this key. The
        // healthy outcome of the
        // shutdown handshake:
        // a transient walker gap
        // (e.g. older-version dep
        // missed by newest-only
        // expansion) routes to the
        // escape-hatch in micros
        // rather than burning the
        // 5s timeout.
        // escape_hatch_fetches — provider-side: non-root fetches
        // that bypassed the wait-loop.
        // Healthy 0 when walker attached
        // and keeps ahead of PubGrub.
        // Non-zero = walker gap OR no
        // walker (pre-shape with
        // fetch_wait_timeout == ZERO).
        // Compare against
        // `cache_wait_walker_done_shortcuts`
        // to distinguish "walker had a
        // gap, recovered cheaply" (good)
        // from "walker isn't attached"
        // (no waits at all).
        // spec_tx_send_wait_ms — walker time blocked on
        // `spec_tx.send().await`
        // (dispatcher backpressure
        // canary per design).
        // max_depth — deepest BFS level the walker
        // walked (0 = roots only).
                           "streaming_bfs": walker_summary_final.as_ref().map(|s| {
        // Per-BFS-level three-phase wall breakdown. `total_ms − fetch_ms` per level is the
        // inter-fetch dead time that's
        // continuous-stream walker is designed to eliminate.
        // Empty when the walker did zero levels (warm-cache
        // full hit). Built outside the outer json! macro so
        // its expansion doesn't blow recursion_limit.
                               let levels: Vec<serde_json::Value> = s
                                   .levels
                                   .iter()
                                   .map(|l| serde_json::json!({
                                       "depth": l.depth,
                                       "seeded_count": l.seeded_count,
                                       "cache_hit_count": l.cache_hit_count,
                                       "npm_fetch_count": l.npm_fetch_count,
                                       "lpm_fetch_count": l.lpm_fetch_count,
                                       "setup_ms": l.setup_ms,
                                       "fetch_ms": l.fetch_ms,
                                       "commit_ms": l.commit_ms,
                                       "total_ms": l.total_ms,
                                   }))
                                   .collect();
                               serde_json::json!({
                                   "walk_ms": s.walker_wall_ms,
                                   "manifests_fetched": s.manifests_fetched,
                                   "cache_hits": s.cache_hits,
                                   "cache_waits": streaming_metrics.cache_waits(),
                                   "cache_wait_timeouts": streaming_metrics.cache_wait_timeouts(),
                                   "cache_wait_walker_done_shortcuts":
                                       streaming_metrics.cache_wait_walker_done_shortcuts(),
                                   "escape_hatch_fetches": streaming_metrics.escape_hatch_fetches(),
                                   "spec_tx_send_wait_ms": s.spec_tx_send_wait_ms,
                                   "max_depth": s.max_depth,
                                   "levels": levels,
                               })
                           }),
                       },
        //: sub-stage breakdown of the fetch pool. Zeroed
        // when everything is already in the store (lockfile fast path
        // with warm cache). Field shape is the `FetchBreakdown` JSON
        // contract documented on that struct.
                       "fetch_breakdown": fetch_breakdown.to_json(),
        // — lockfile-cached URL gate telemetry. All
        // counters zero when every stored URL passed (common
        // case in steady state). `origin_mismatch > 0` is
        // expected after `LPM_REGISTRY_URL` switches;
        // `shape_mismatch > 0` is a BUG signal — the writer
        // should never emit a gate-rejectable URL.
                       "tarball_url_gate": gate_stats.to_json(),
        // speculative-fetch stats. Zero when every
        // root is already in the store before the metadata RPC
        // starts, or on the lockfile-fast-path. Field shape
        // documented on `SpeculativeStats`.
                       "speculative": spec_stats.to_json(),
                   },
                   "warnings": [],
                   "errors": [],
                   "peer_conflicts": [],
                   "peer_issues": peer_issues_json_value(&[], &[]),
               });
        if timing_detail_mode.enabled() {
            let build_state_write_timing = crate::build_state::snapshot_write_timing();
            let metadata_snapshots = timing_metadata_detail.as_deref().unwrap_or(&[]);
            let mut detail = serde_json::json!({
                "setup": {
                    "install_state_ms": wf_setup_install_state_ms,
                    "route_table_ms": wf_setup_route_table_ms,
                    "other_ms": wf_setup_ms.saturating_sub(
                        wf_setup_install_state_ms.saturating_add(wf_setup_route_table_ms),
                    ),
                },
                "metadata": metadata_detail_json_from_snapshots(
                    metadata_snapshots,
                    timing_detail_mode,
                ),
                "resolve": resolve_detail_json(
                    resolve_wall_ms,
                    initial_batch_ms,
                    &resolver_stage_timing,
                    metadata_snapshots,
                    timing_detail_mode,
                ),
                "fetch": fetch_stage_timings.to_json(
                    fetch_wall_ms,
                    packages.len(),
                    cached,
                    downloaded,
                    fetch_breakdown,
                ),
                "security": {
                    "registry_signatures": registry_signature_timings
                        .as_ref()
                        .map_or(serde_json::Value::Null, |timings| timings.to_json()),
                    "provenance": provenance_timings
                        .as_ref()
                        .map_or(serde_json::Value::Null, |timings| timings.to_json()),
                },
                "link": {
                    "reconcile_ms": wf_link_reconcile_ms,
                    "root_symlinks_ms": wf_link_root_symlinks_ms,
                    "compatibility_ms": wf_link_compatibility_ms,
                    "bin_shims_ms": wf_link_bin_shims_ms,
                    "v2_one": v2_link_task_timings.to_json(wf_link_await_ms),
                },
                "tail": {
                    "blocked_metadata_ms": wf_tail_blocked_metadata_ms,
                    "trust_snapshot_ms": wf_tail_trust_snapshot_ms,
                    "lockfile_write_ms": wf_tail_lockfile_write_ms,
                    "lockfile_write_count": wf_tail_lockfile_write_count,
                    "build_state_write_ms": build_state_write_timing.write_ms,
                    "build_state_write_count": build_state_write_timing.write_count,
                    "audit_after_install_ms": wf_tail_audit_after_install_ms,
                    "other_ms": elapsed
                        .as_millis()
                        .saturating_sub(wf_link_end_ms)
                        .saturating_sub(wf_tail_blocked_metadata_ms)
                        .saturating_sub(wf_tail_trust_snapshot_ms)
                        .saturating_sub(wf_tail_lockfile_write_ms)
                        .saturating_sub(build_state_write_timing.write_ms as u128)
                        .saturating_sub(wf_tail_audit_after_install_ms),
                },
            });
            if timing_detail_mode.trace() {
                let mut slow_packages = slow_package_timings.to_json();
                if let serde_json::Value::Object(slow_packages) = &mut slow_packages {
                    slow_packages.insert(
                        "provenance_verify".to_string(),
                        provenance_timings.as_ref().map_or_else(
                            || serde_json::Value::Array(Vec::new()),
                            crate::provenance_fetch::ProvenanceTimings::slow_verify_json,
                        ),
                    );
                }
                detail["trace"] = serde_json::json!({
                    "slow_packages": slow_packages,
                });
            }
            json["timing"]["detail"] = detail;
        }
        // surface workspace target set for agents.
        // None for legacy/standalone callers; Some(...) for the filtered path.
        if let Some(targets) = target_set {
            json["target_set"] =
                serde_json::Value::Array(targets.iter().map(|s| serde_json::json!(s)).collect());
        }
        // invariant: surface workspace member deps that
        // were linked locally instead of going through the registry.
        if !workspace_member_deps.is_empty() {
            json["workspace_members"] = serde_json::Value::Array(
                workspace_member_deps
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name,
                            "version": m.version,
                            "source_dir": m.source_dir.display().to_string(),
                        })
                    })
                    .collect(),
            );
        }
        // surface the override apply trace. Empty
        // when no overrides were declared OR when the lockfile fast
        // path was taken (in which case the persisted state file holds
        // the most recent trace from a fresh resolve).
        if !applied_overrides.is_empty() {
            json["applied_overrides"] = serde_json::Value::Array(
                applied_overrides
                    .iter()
                    .map(|h| {
                        serde_json::json!({
                            "raw_key": h.raw_key,
                            "source": h.source,
                            "package": h.package,
                            "from_version": h.from_version,
                            "to_version": h.to_version,
                            "via_parent": h.via_parent,
                        })
                    })
                    .collect(),
            );
        }
        json["overrides_count"] = serde_json::json!(override_set.len());
        json["overrides_fingerprint"] =
            fingerprint_json_value(override_set.len(), override_set.fingerprint());

        // best-effort peer-
        // conflict reports as an ALWAYS-PRESENT array. Empty when the
        // peer graph is clean OR on the lockfile fast path (no fresh
        // resolve produces no fresh conflict trace). Field is
        // unconditional so machine consumers can rely on its
        // existence — same shape contract as `applied_patches`.
        json["peer_conflicts"] = serde_json::Value::Array(
            peer_conflicts
                .iter()
                .map(peer_conflict_json_value)
                .collect(),
        );
        json["peer_issues"] = peer_issues_json_value(&peer_warnings, &peer_conflicts);

        // surface the patch apply trace + counts.
        // invariant : filter to entries that ACTUALLY did
        // work this run via `touched_anything()`. A no-op idempotent
        // rerun where every file already had the expected post-patch
        // bytes will report an empty `applied_patches` array — that's
        // the correct per-run signal. The patches are still in effect
        // (the state file still records them), but we did no work, so
        // we don't claim we did. Always emitted so agents can rely on
        // the field's existence.
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|a| a.touched_anything())
            .collect();
        json["applied_patches"] = applied_patches_to_json(&applied_patches_summary, project_dir);
        json["patches_count"] = serde_json::json!(current_patches.len());
        json["patches_fingerprint"] =
            fingerprint_json_value(current_patches.len(), current_patch_fingerprint);

        // surface the install-time blocked set so
        // agents and CI can drive `lpm approve-scripts` without re-scanning.
        json["blocked_count"] = serde_json::json!(blocked_capture.state.blocked_packages.len());
        json["blocked_set_changed"] = serde_json::json!(blocked_capture.should_emit_warning);
        json["blocked_set_fingerprint"] = fingerprint_json_value(
            blocked_capture.state.blocked_packages.len(),
            blocked_capture.state.blocked_set_fingerprint.clone(),
        );
        // + per-entry shape now
        // includes `static_tier` () and `version_diff` () via
        // the shared `version_diff::blocked_to_json_with_provenance`
        // helper, which is also the source of truth for the
        // approve-scripts JSON emitter. Both sides cannot drift on
        // the entry shape.
        //
        // `version_diff` is `null` when no prior binding for the
        // package name exists (first-time review). When a prior
        // exists, the structured object is documented on
        // `version_diff::version_diff_to_json`.
        //
        // The per-package `provenance.verified` block emits when
        // the drift gate captured a `ProvenanceStatus` for this
        // `(name, version)` pair. Sparse — only packages with a
        // rich-form `trustedDependencies` binding triggered a
        // fetch.
        let trusted_for_json = read_trusted_deps_from_manifest(project_dir).unwrap_or_default();
        json["blocked_packages"] = serde_json::Value::Array(
            blocked_capture
                .state
                .blocked_packages
                .iter()
                .map(|bp| {
                    crate::version_diff::blocked_to_json_with_provenance(
                        bp,
                        &trusted_for_json,
                        Some(&install_provenance_status_map),
                    )
                })
                .collect(),
        );
        if let Some(counts) = &audit_summary_for_envelope {
            json["audit_summary"] = serde_json::to_value(counts).unwrap_or(serde_json::Value::Null);
        }
        crate::security_floor::attach_security_posture(&mut json, force_security_floor);
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        // print the override apply summary BEFORE
        // the success line so it doesn't get lost at the bottom of the
        // output. Only emit on the fresh-resolution path; the lockfile
        // fast path already had the summary printed during the
        // resolution that produced the lockfile, so re-emitting it
        // would be misleading ("Applied N overrides" implies we just
        // applied them).
        if !applied_overrides.is_empty() {
            println!();
            output::info(&format!(
                "Applied {} override{}:",
                applied_overrides.len().to_string().bold(),
                if applied_overrides.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ));
            for hit in &applied_overrides {
                let source_ref = hit.source_display();
                let parent_suffix = match &hit.via_parent {
                    Some(p) => format!(", reached through {}", p.bold()),
                    None => String::new(),
                };
                println!(
                    "   {} {} → {} (via {}{})",
                    hit.package.bold(),
                    hit.from_version.dimmed(),
                    hit.to_version.bold(),
                    source_ref,
                    parent_suffix,
                );
            }
        }

        // summary of applied patches. Mirrors
        // the override summary above. **invariant :** filter
        // to entries that ACTUALLY did work this run (`touched_anything`)
        // so a no-op idempotent rerun doesn't print "Applied 1 patch"
        // with zero files. The patches are still in effect on disk
        // (the state file still records them), but if we did no work
        // we don't claim we did.
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|a| a.touched_anything())
            .collect();
        if !applied_patches_summary.is_empty() {
            println!();
            output::info(&format!(
                "Applied {} patch{}:",
                applied_patches_summary.len().to_string().bold(),
                if applied_patches_summary.len() == 1 {
                    ""
                } else {
                    "es"
                }
            ));
            for a in &applied_patches_summary {
                let rel_patch = a
                    .patch_path
                    .strip_prefix(project_dir)
                    .unwrap_or(&a.patch_path);
                let total = a.files_modified + a.files_added + a.files_deleted;
                println!(
                    "   {}@{} ({}, {} file{})",
                    a.name.bold(),
                    a.version.dimmed(),
                    rel_patch.display(),
                    total,
                    if total == 1 { "" } else { "s" },
                );
            }
        }

        // Diff direct deps against the pre-install lockfile snapshot.
        // Only deps whose resolved version CHANGED in this run land in
        // the `+ pkg@version` list — a no-op refresh prints no list,
        // `lpm i react` prints just `+ react@…`, and a hand-edited
        // manifest prints exactly the diff. The resolver's `is_direct`
        // flag scopes the diff to top-level deps so transitives never
        // pollute the list.
        //
        // Inlined silent variant of [`collect_direct_versions`]. The
        // canonical helper emits a `tracing::warn!` on duplicate
        // `is_direct = true` entries — useful as a diagnostic for the
        // `lpm i <pkg>` finalize path, but a latent resolver bug
        // occasionally double-marks deps like `chalk` / `ora` when
        // peer-rule auto-installs collide with their declared positions.
        // Surfacing that warning on every bare install of a typical
        // project would look broken. Silent last-wins instead.
        let post_direct_versions: HashMap<String, lpm_semver::Version> = packages
            .iter()
            .filter(|p| p.is_direct)
            .filter_map(|p| {
                lpm_semver::Version::parse(&p.version)
                    .ok()
                    .map(|v| (p.name.clone(), v))
            })
            .collect();
        let mut changed_direct: Vec<(String, String)> = Vec::new();
        for (name, post_v) in &post_direct_versions {
            let post_str = post_v.to_string();
            match pre_install_direct_versions.get(name) {
                Some(pre_v) if pre_v == &post_str => continue,
                _ => changed_direct.push((name.clone(), post_str)),
            }
        }
        changed_direct.sort();

        if !changed_direct.is_empty() {
            eprintln!();
            for (name, version) in &changed_direct {
                // Annotate with `(vX.Y.Z available)` when the
                // resolver's metadata cache has a stable release newer
                // than the version we just installed. Suppressed for:
                // * lockfile fast-path (no cache → empty map),
                // * non-registry sources (filtered out of `cache`),
                // * unparseable / equal / older latest versions.
                let hint = latest_stable_versions.get(name).and_then(|latest| {
                    let installed = lpm_semver::Version::parse(version).ok()?;
                    let candidate = lpm_semver::Version::parse(latest).ok()?;
                    (candidate > installed).then(|| format!("(v{latest} available)"))
                });
                install_ui::plus(name, version, hint.as_deref());
            }
        }

        // Verified-via-Sigstore counter. Drift gate populates this map
        // per package; `Verified` is the only state that earns the
        // green checkmark line. `Unverified` (operator-skipped) and
        // entries absent from the map are not counted — we only assert
        // the strong signal here, never inflate it.
        let verified_count = install_provenance_status_map
            .values()
            .filter(|s| matches!(s, lpm_common::ProvenanceStatus::Verified(_)))
            .count();

        let reported_count = if is_add_invocation {
            changed_direct.len()
        } else {
            packages.len()
        };
        let action = if is_add_invocation {
            "added"
        } else {
            "installed"
        };
        let duration_str = install_ui::format_duration(elapsed);
        let pkg_word = install_ui::packages_word(reported_count);
        eprintln!();
        install_ui::done(&format!(
            "Done · {action} {} {pkg_word} in {}",
            install_ui::bold(&reported_count.to_string()),
            install_ui::green(&duration_str),
        ));
        if verified_count > 0 {
            install_ui::done(&format!(
                "{verified_count} of {} {} verified via Sigstore",
                packages.len(),
                install_ui::packages_word(packages.len()),
            ));
        }

        // Audit-after-install advisory. Yellow `!` line; vulnerability
        // count goes red when non-zero. Computed above before the
        // human/JSON branch split so both surfaces agree.
        if let Some(counts) = &audit_summary_for_envelope {
            install_ui::warn(&install_ui::format_audit_advisory(
                counts.packages_audited,
                counts.vulnerabilities,
                counts.suspicious,
                counts.elapsed_ms,
            ));
        }

        if verbose {
            eprintln!(
                "  {}",
                format!("resolve: {resolve_ms}ms  fetch: {fetch_ms}ms  link: {link_ms}ms").dimmed()
            );
            let lockb_path = lockfile_path.with_extension("lockb");
            let lockb_size = std::fs::metadata(&lockb_path).map_or(0, |m| m.len());
            let lockfile_pkg_count = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
                .map_or(packages.len(), |lf| lf.packages.len());
            eprintln!(
                "  {}",
                format!(
                    "lpm.lock ({lockfile_pkg_count} {}) + lpm.lockb ({})",
                    install_ui::packages_word(lockfile_pkg_count),
                    lpm_common::format_bytes(lockb_size),
                )
                .dimmed()
            );
            eprintln!(
                "  {}",
                format!(
                    "{} linked, {} symlinked",
                    link_result.linked, link_result.symlinked,
                )
                .dimmed()
            );
        }
    }

    maybe_emit_post_install_lifecycle_hint(
        lpm_root,
        &packages,
        &policy,
        project_dir,
        script_policy_override,
        &install_requested_capabilities,
        &install_user_bound,
        &blocked_capture,
        json_output,
    )?;

    // Write install-hash so `lpm dev` knows deps are up to date.
    // uses the shared compute_install_hash from install_state.
    // Must re-read because save semantics may have modified both
    // package.json and lpm.lock during install (e.g., replacing "*" with "^4.3.6").
    //
    // delegated to `write_install_hash`, which also captures
    // manifest mtimes into the v2 file format so the next up-to-date
    // check can take the mtime fast path.
    write_post_install_v6_hash(project_dir, linker_mode);

    // Register the project in the machine-global known-projects registry.
    // `lpm cache prune` walks this set to
    // determine which v2-store link entries are reachable. Errors are
    // logged + dropped: the registry is non-load-bearing (prune
    // degrades gracefully without it) so a flaky write must never
    // block a successful install.
    if let Err(e) = lpm_common::known_projects::register(&lpm_root.known_projects(), project_dir) {
        tracing::debug!("failed to register project in known-projects registry: {e}");
    }

    // Invariant: surface the direct-dep version map
    // for callers (`run_add_packages`, `run_install_filtered_add`) that
    // need to finalize a placeholder-staged manifest entry. The map
    // contains ONLY entries where `is_direct == true`, so transitive
    // collisions on the same name are impossible by construction.
    if let Some(out) = direct_versions_out {
        out.extend(collect_direct_versions(&packages));
    }

    Ok(())
}
