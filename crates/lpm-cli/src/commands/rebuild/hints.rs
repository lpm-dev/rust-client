use super::scripts::{BUILD_MARKER, package_baseline_dir_indexed, read_lifecycle_scripts};
use super::trust::{evaluate_trust, name_matches_trusted_scope, parse_trusted_scopes};
use crate::install_ui;
use crate::script_policy_config::ScriptPolicy;
use lpm_common::color::Painted;
use lpm_security::script_hash::compute_script_hash;
use lpm_security::{SecurityPolicy, TrustMatch};
use lpm_store::V2BaselineIndex;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScriptableHintRow {
    pub name: String,
    pub version: String,
    pub scripts: HashMap<String, String>,
    pub is_built: bool,
    pub is_trusted: bool,
}

/// Pure computation of the install-hint rows.
///
/// trust decision switched from
/// [`SecurityPolicy::can_run_scripts`] (lenient, name-only) to
/// [`SecurityPolicy::can_run_scripts_strict`], matching the exact
/// semantic `rebuild::run` uses. Closes the pre-existing drift where a
/// drifted rich binding could be shown as `trusted ✓` in the install
/// hint even though `lpm rebuild` would then skip it. OR-composition
/// with [`is_scope_trusted`] preserved from the prior implementation.
///
/// The `integrity` in the `packages` tuple is what the lockfile /
/// resolver recorded at install time. `None` is accepted (some
/// packages lack an SRI hash or the caller couldn't resolve one); the
/// strict gate still works, just with a weaker binding.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scriptable_package_rows(
    // switched `&PackageStore`
    // (v1-only) for `&LpmRoot` so per-package lookups can route
    // through `find_installed_package_baseline` and pick up v2-
    // installed packages. Without this, the install-time build hint
    // silently dropped every v2 package — users saw "0 packages have
    // install scripts" even when prisma-codegen / esbuild / sharp
    // were waiting in the v2 store.
    lpm_root: &lpm_common::LpmRoot,
    packages: &[(String, String, Option<String>)], // (name, version, integrity)
    policy: &SecurityPolicy,
    project_dir: &Path,
    // Without these two
    // params, the install hint reports `trusted ✓` for packages
    // whose capability request the capability gate will block at
    // `lpm rebuild` time. The hint is a user-facing contract about
    // what the next build will do; misstating it contradicts the
    // adjacent approve-scripts guidance. Baseline defaults
    // preserve existing behavior for tests and callers that don't
    // yet parse the project capability set.
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
) -> Vec<ScriptableHintRow> {
    use rayon::prelude::*;

    // Hoist trustedScopes parsing out of the per-package loop. The previous implementation called `is_scope_trusted`
    // inside the loop, which re-read AND re-parsed
    // `project_dir/package.json` for every package. On the 266-pkg
    // bench/fixture-large fixture that's 266 redundant disk reads of
    // the same file. Reading once before the loop keeps the contract
    // (same scopes against same names → same answer) while turning
    // the per-package step into a pure in-memory glob match.
    let trusted_scopes = parse_trusted_scopes(project_dir);

    // Build the
    // v2 link-entry index ONCE before the rayon walk, scoped to this
    // project's tree. Per-package lookups become O(1) map reads;
    // the project scoping prevents the same-coordinate ambiguity where a
    // global scan might return a sibling project's link entry for
    // the same `(name, version)`.
    //
    // Index-build errors are upgraded to "no v2 store available"
    // because the legacy code silently fell back to v1 for any
    // non-Some result. Surfacing the error here would change the
    // contract observable to callers (silent skip → hard error).
    let baseline_index = V2BaselineIndex::for_project(project_dir, lpm_root).unwrap_or_default();

    let walk_start = std::time::Instant::now();

    //
    // Same pattern as `build_state::compute_blocked_packages_with_metadata`.
    // Each iteration is independent — pure CPU + read-only disk: one
    // package.json read, one `BUILD_MARKER` stat, one
    // `compute_script_hash`, and pure policy/capability lookups.
    // No shared mutable state, so `par_iter().filter_map().collect()`
    // is drop-in. Output ordering matches input ordering; downstream
    // (hint print + `unbuilt` filter) does not depend on a specific
    // ordering of equally-typed rows but the Vec preserves
    // input order anyway under rayon's stable collect.
    let per_pkg = |(name, version, integrity): &(String, String, Option<String>)|
     -> Option<ScriptableHintRow> {
        // v2-aware lookup, routed through the invocation-local index. See
        // [`package_baseline_dir`] for the silent-skip-vs-real-skip
        // semantic.
        let pkg_dir = package_baseline_dir_indexed(&baseline_index, lpm_root, name, version)?;
        let pkg_json_path = pkg_dir.join("package.json");

        let scripts = match read_lifecycle_scripts(&pkg_json_path) {
            Some(s) if !s.is_empty() => s,
            _ => return None,
        };

        let is_built = pkg_dir.join(BUILD_MARKER).exists();

        // Strict/tiered gate — same four-way match as `rebuild::run` at
        // the main rebuild loop. `Strict` + `LegacyNameOnly` are trusted;
        // `BindingDrift` + `NotTrusted` are not. A legacy bare-name
        // entry counts as trusted here because `rebuild::run` will
        // still run the script (with a deprecation warning), so the
        // hint must not mislead the user about what the subsequent
        // `lpm rebuild` will do.
        let script_hash = compute_script_hash(&pkg_dir);
        let trust = policy.can_run_scripts_strict(
            name,
            version,
            integrity.as_deref(),
            script_hash.as_deref(),
        );
        let strict_trust = matches!(trust, TrustMatch::Strict | TrustMatch::LegacyNameOnly);
        let scope_trust = name_matches_trusted_scope(name, &trusted_scopes);
        let base_trusted = strict_trust || scope_trust;

        // If the script-
        // hash / scope layer would trust the package but the
        // capability gate rejects it, `lpm rebuild` will NOT run
        // the script. The hint must reflect that accurately.
        // BindingDrift / NotTrusted don't need this adjustment —
        // they're already untrusted.
        let capability_blocks_trust = if base_trusted {
            let binding = if strict_trust {
                policy.get_binding(name, version)
            } else {
                None // scope-trust has no binding to bind a hash to
            };
            requested_capabilities.requires_review_despite_strict_match(user_bound, binding)
        } else {
            false
        };
        let is_trusted = base_trusted && !capability_blocks_trust;

        Some(ScriptableHintRow {
            name: name.clone(),
            version: version.clone(),
            scripts,
            is_built,
            is_trusted,
        })
    };

    let rows: Vec<ScriptableHintRow> = packages.par_iter().filter_map(per_pkg).collect();

    tracing::debug!(
        "perf.scriptable_package_rows pkgs={} ms={}",
        packages.len(),
        walk_start.elapsed().as_millis()
    );

    rows
}

/// Show the install-time build hint (called from install.rs).
///
/// Lists packages with unexecuted scripts and their trust status.
/// Thin I/O wrapper over [`scriptable_package_rows`]; all trust
/// decisions live in the pure helper.
#[allow(clippy::too_many_arguments)]
pub fn show_install_build_hint(
    // see
    // `scriptable_package_rows` for why this is `&LpmRoot` not
    // `&PackageStore`.
    lpm_root: &lpm_common::LpmRoot,
    packages: &[(String, String, Option<String>)], // (name, version, integrity)
    policy: &SecurityPolicy,
    project_dir: &Path,
    // threaded to
    // `scriptable_package_rows` so the hint reflects the
    // capability gate's effect on trust (see comment on that
    // function for the full rationale).
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
) {
    let rows = scriptable_package_rows(
        lpm_root,
        packages,
        policy,
        project_dir,
        requested_capabilities,
        user_bound,
    );
    let unbuilt: Vec<&ScriptableHintRow> = rows.iter().filter(|r| !r.is_built).collect();

    if unbuilt.is_empty() {
        return;
    }

    println!();
    install_ui::phase(&format!(
        "{} package(s) have install scripts:",
        unbuilt.len()
    ));

    for row in &unbuilt {
        let trust_label = if row.is_trusted {
            "trusted ✓".green().to_string()
        } else {
            "not trusted".yellow().to_string()
        };

        let script_names: Vec<&str> = row.scripts.keys().map(|s| s.as_str()).collect();
        println!(
            "  {:<30} {:<30} ({})",
            format!("{}@{}", row.name, row.version).bold(),
            script_names.join(", ").dimmed(),
            trust_label,
        );
    }

    let trusted_unbuilt = unbuilt.iter().filter(|r| r.is_trusted).count();
    println!();
    if trusted_unbuilt > 0 {
        println!(
            "  Run {} to execute scripts for trusted packages.",
            "lpm rebuild".bold()
        );
    }
    if trusted_unbuilt < unbuilt.len() {
        println!(
            "  Run {} to build specific packages.",
            "lpm rebuild <package-name>".bold()
        );
    }
}

/// Check if ALL packages with unexecuted lifecycle scripts are trusted.
///
/// Used by install.rs to decide whether to auto-build without explicit
/// opt-in.
///
/// same strict/tiered gate as
/// `scriptable_package_rows` and `rebuild::run`. A drifted rich
/// binding now correctly fails this predicate (previously `true` with
/// the name-only gate, which would trigger auto-build for a package
/// `rebuild::run` would then skip — confusing UX at best, silent trust
/// bypass at worst).
///
/// takes the already-resolved
/// [`ScriptPolicy`] so the predicate and `rebuild::run` agree on which
/// packages count as trusted.
///
/// migrated onto the shared
/// [`evaluate_trust`] helper so the install-time auto-build predicate
/// and `rebuild::run`'s per-package trust decision are single-sourced.
/// Under [`ScriptPolicy::Triage`], this means a package whose
/// lifecycle scripts worst-wins classify as [`StaticTier::Green`]
/// counts as trusted for auto-build-trigger purposes even without a
/// `trustedDependencies` entry — the auto-execution contract.
/// Under `Deny` / `Allow`, behavior is unchanged from the previous implementation:
/// only strict gate + scope glob matches count.
///
/// An empty installed-packages list or a set of only already-built
/// scripted packages returns `false` (the caller uses this to decide
/// whether to skip the auto-build step entirely), matching the
/// previous semantics.
#[allow(clippy::too_many_arguments)]
pub fn all_scripted_packages_trusted(
    // see
    // `scriptable_package_rows` for why this is `&LpmRoot` not
    // `&PackageStore`. Without the v2-aware lookup, the predicate
    // returned `false` for every v2 install with unbuilt-but-trusted
    // scripts (silent skip of v2 packages), suppressing the
    // auto-build path entirely.
    lpm_root: &lpm_common::LpmRoot,
    packages: &[(String, String, Option<String>)], // (name, version, integrity)
    policy: &SecurityPolicy,
    project_dir: &Path,
    effective_policy: ScriptPolicy,
    // Threaded through to
    // [`evaluate_trust`]. When `true`, every approval is suspended —
    // so if even one package has scripts, this function returns
    // `false`, correctly declining the auto-build path under the
    // kill-switch.
    force_security_floor: bool,
    // Threaded through to
    // [`evaluate_trust`]'s capability gate. Auto-build declines
    // cleanly when the project's `lpm.scripts.*` widens beyond
    // the user bound and no matching approval exists.
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    // Threaded through to [`evaluate_trust`]
    // so an install's autoBuild predicate sees the same ephemeral
    // advisor approvals the script-execution path will see. Without
    // this, a `Some(approvals)` install would still report "not all
    // scripts trusted" and decline autoBuild entirely — defeating
    // the whole point of advisor-enhanced triage.
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> bool {
    // Build the
    // v2 link-entry index ONCE before the per-package loop, scoped to
    // this project's tree. Same rationale as `scriptable_package_rows`
    // — install-time auto-build predicate checks every lockfile entry,
    // and the global walk could otherwise return a sibling project's
    // link entry under same-coordinate same-coord coexistence. Falling back
    // to an empty index on construction failure preserves the legacy
    // silent-skip-of-v1-only semantic.
    let baseline_index = V2BaselineIndex::for_project(project_dir, lpm_root).unwrap_or_default();

    let mut has_any_unbuilt = false;

    for (name, version, integrity) in packages {
        // v2-aware lookup, routed through the invocation-local index. Same
        // silent-skip semantics as the main loop; see
        // [`package_baseline_dir`] doc.
        let pkg_dir = match package_baseline_dir_indexed(&baseline_index, lpm_root, name, version) {
            Some(p) => p,
            None => continue,
        };
        let pkg_json_path = pkg_dir.join("package.json");

        let scripts = match read_lifecycle_scripts(&pkg_json_path) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        // Has scripts — check if built already
        if pkg_dir.join(BUILD_MARKER).exists() {
            continue; // already built, skip
        }

        // Unbuilt with scripts — first fresh trust-check.
        has_any_unbuilt = true;

        let reason = evaluate_trust(
            &pkg_dir,
            name,
            version,
            integrity.as_deref(),
            &scripts,
            policy,
            project_dir,
            effective_policy,
            force_security_floor,
            requested_capabilities,
            user_bound,
            advisor_approvals,
        );
        if !reason.is_trusted() {
            return false; // at least one untrusted package
        }
    }

    has_any_unbuilt // true only if there are unbuilt scripts AND all are trusted
}
