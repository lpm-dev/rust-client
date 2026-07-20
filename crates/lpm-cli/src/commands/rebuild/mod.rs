//! `lpm rebuild` — Selective lifecycle script execution.
//!
//! of the two-phase install model:
//! - `lpm install` downloads, extracts, and links packages — NO scripts execute.
//! - `lpm rebuild` selectively runs lifecycle scripts based on trust policy.
//!
//! Trust policy is defined in package.json `"lpm"` config:
//! ```json
//! {
//!   "lpm": {
//!     "trustedDependencies": ["esbuild", "sharp"],
//!     "scripts": {
//!       "trustedScopes": ["@myorg/*"],
//!       "denyAll": false,
//!       "autoBuild": false
//!     }
//!   }
//! }
//! ```
//!
//! Build state is tracked via `.lpm-built` marker files in the store.
//! Already-built packages are skipped (idempotent). Use `--force` to re-run them.
//!
//! ## Security (S3)
//! - 5-minute default timeout per script (--timeout to override)
//! - Credential env vars stripped (LPM_TOKEN, NPM_TOKEN, GITHUB_TOKEN, etc.)
//! - Scripts run in package's store directory, not project root
//! - On Unix: child spawned in its own process group; timeout kills the
//!   entire group (not just the direct child), preventing orphaned subprocesses
//! - On Windows: `Child::kill()` terminates the process tree via `TerminateProcess`

mod build_cache;
mod hints;
mod package_dir;
mod process_tree;
mod sandbox_env;
mod script_execution;
mod scripts;
mod trust;

#[cfg(test)]
mod tests;

use self::build_cache::{
    BuildCacheInvocation, BuildCacheScratch, build_key_for_package, is_cacheable_native_build,
    marker_requires_key_validation, read_build_marker_key, read_v2_graph_key_digest,
};
#[cfg(test)]
pub use self::hints::all_scripted_packages_trusted;
#[cfg(test)]
pub(crate) use self::hints::scriptable_package_rows;
pub use self::hints::{all_scripted_package_identities_trusted, show_install_build_hint};
use self::package_dir::{PackageLookupIdentity, prepare_live_package_dir};
use self::sandbox_env::build_sanitized_env;
use self::script_execution::execute_script;
use self::scripts::{
    BUILD_MARKER, BuildCacheMetrics, ScriptablePackage, count_untrusted_unbuilt,
    read_lifecycle_scripts, rebuild_dry_run_envelope, rebuild_package_failure_message,
    rebuild_package_label, rebuild_summary_envelope, scripts_word, toposort_packages,
    warn_stale_trusted_deps, widen_to_build_by_policy,
};
pub(crate) use self::scripts::{RebuildPackageIdentity, RebuildRunReport};
#[cfg(test)]
pub(crate) use self::trust::evaluate_trust;
pub(crate) use self::trust::{TrustReason, evaluate_trust_for_identity};

use crate::install_ui;
use crate::script_policy_config::ScriptPolicy;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_sandbox::SandboxMode;
use lpm_security::{EXECUTED_INSTALL_PHASES, SecurityPolicy};
use lpm_store::{PackageBaselineLayout, V2BaselineIndex};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_SCRIPT_TIMEOUT_SECS: u64 = 300;

fn elapsed_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    project_dir: &Path,
    specific_packages: &[String],
    all: bool,
    dry_run: bool,
    force: bool,
    timeout_secs: Option<u64>,
    json_output: bool,
    deny_all: bool,
    // Sandbox flag trio. `no_sandbox` flips execution to
    // [`SandboxMode::Disabled`] AND skips env scrubbing — the legacy
    // `--unsafe-full-env` partner was removed in the beta-cleanup pass. `strict_sandbox` opts INTO outbound network
    // denial via the [`crate::sandbox_config::resolve_sandbox_mode_from_chain`]
    // precedence resolver. `sandbox_log` flips to
    // [`SandboxMode::LogOnly`] — strictly diagnostic, never a
    // soft-enforcement substitute by contract. `no_sandbox`
    // and `strict_sandbox` are mutually exclusive at the clap layer
    // (`conflicts_with_all`) so they never both arrive `true`.
    no_sandbox: bool,
    strict_sandbox: bool,
    sandbox_log: bool,
    // already-resolved effective script policy.
    // The caller (main.rs for `lpm rebuild`, install.rs for autoBuild)
    // runs the full precedence chain before calling and hands the
    // final value here. uses this only to pick the blocked-
    // packages messaging (triage → `lpm approve-scripts`, deny/allow
    // → unchanged); adds tier-based auto-trust for greens
    // under [`ScriptPolicy::Triage`].
    effective_policy: ScriptPolicy,
    // In-memory advisor-approved exact source/content/script identities from
    // this install's
    // [`crate::triage_advisor_session::AdvisorSession`]. Standalone
    // `lpm rebuild` invocations pass `None` — the trust manifest is
    // the only authority. The install path's autoBuild call passes
    // `Some(session.approvals())` so amber packages the advisor
    // approved this run can execute their scripts without a
    // persistent `trustedDependencies` entry.
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> Result<(), LpmError> {
    run_with_report(
        project_dir,
        specific_packages,
        all,
        dry_run,
        force,
        timeout_secs,
        json_output,
        deny_all,
        no_sandbox,
        strict_sandbox,
        sandbox_log,
        effective_policy,
        advisor_approvals,
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with_report(
    project_dir: &Path,
    specific_packages: &[String],
    all: bool,
    dry_run: bool,
    force: bool,
    timeout_secs: Option<u64>,
    json_output: bool,
    deny_all: bool,
    no_sandbox: bool,
    strict_sandbox: bool,
    sandbox_log: bool,
    effective_policy: ScriptPolicy,
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> Result<RebuildRunReport, LpmError> {
    // hold the shared store lock across rebuild —
    // it traverses store package dirs to read package.json, compute
    // script hashes, and (for already-built check) inspect the
    // `.lpm-built` markers. A concurrent `lpm cache prune --apply` could
    // remove an entry mid-traversal without this gate.
    let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
    lpm_common::with_shared_lock_async(
        lock_path,
        run_under_store_lock(
            project_dir,
            specific_packages,
            all,
            dry_run,
            force,
            timeout_secs,
            json_output,
            deny_all,
            no_sandbox,
            strict_sandbox,
            sandbox_log,
            effective_policy,
            advisor_approvals,
        ),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_under_store_lock(
    project_dir: &Path,
    specific_packages: &[String],
    all: bool,
    dry_run: bool,
    force: bool,
    timeout_secs: Option<u64>,
    json_output: bool,
    deny_all: bool,
    no_sandbox: bool,
    strict_sandbox: bool,
    sandbox_log: bool,
    effective_policy: ScriptPolicy,
    // see `run` for the contract.
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> Result<RebuildRunReport, LpmError> {
    crate::security_floor::clear_recorded_suppressions();
    // Defense-in-depth on the sandbox flag pair. The CLI boundary
    // (clap `conflicts_with_all` on `--no-sandbox` ⊥ `--strict-sandbox`
    // / `--paranoid`) is the primary guard, but `rebuild::run` is also
    // reachable from internal callers (autoBuild during `lpm install`).
    // Asserting here catches a future caller that wires both true —
    // a combination users can never reach via the parser. Debug-only
    // so release builds stay hot-path clean.
    debug_assert!(
        !(no_sandbox && strict_sandbox),
        "`no_sandbox` and `strict_sandbox` are mutually exclusive; never both true"
    );

    // Check deny-all: --deny-all flag or lpm.scripts.denyAll config.
    //: consolidated into the ScriptPolicyConfig loader so
    // the package.json read is a single pass across all four keys
    // (scriptPolicy, autoBuild, denyAll, trustedScopes).
    let config_deny_all =
        crate::script_policy_config::ScriptPolicyConfig::from_package_json(project_dir).deny_all;
    if deny_all || config_deny_all {
        if !json_output {
            install_ui::warn(
                "Script execution denied. All scripts are blocked by --deny-all or lpm.scripts.denyAll config.",
            );
        }
        return Ok(RebuildRunReport::default());
    }

    // `find_installed_package_baseline`
    // (via [`package_baseline_dir`]) prefers the v2 store (default since
    // 4b) and falls back to v1, so the post-install pipeline
    // doesn't blindly call the v1-only `PackageStore::package_dir`.
    // Without this, every v2-installed scripted package silently skipped
    // at the `pkg_json_path.exists()` check below — i.e., lifecycle
    // scripts never executed for v2 installs.
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let policy = SecurityPolicy::from_package_json(&project_dir.join("package.json"));

    // Load lockfile to get installed packages with their scripts
    let lockfile_path = project_dir.join("lpm.lock");
    if !lockfile_path.exists() {
        return Err(LpmError::NotFound(
            "No lpm.lock found. Run `lpm install` first.".into(),
        ));
    }

    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .map_err(|e| LpmError::Registry(format!("failed to read lockfile: {e}")))?;

    // Read the force-security-floor
    // kill-switch once per invocation and thread it through every
    // [`evaluate_trust`] call below. When set, approvals in
    // `package.json > lpm > trustedDependencies` are suspended (the
    // match becomes [`TrustReason::SuspendedByForceFloor`]); the
    // summary below emits a single warning if any approvals were
    // suspended so the user can discover the flag is active.
    let global_config = crate::commands::config::GlobalConfig::load();
    let force_security_floor = global_config
        .get_bool("force-security-floor")
        .unwrap_or(false);

    crate::security_approval::ensure_project_policy_authorized(
        project_dir,
        json_output,
        crate::security_approval::ApprovalSource::ProjectConfig,
    )?;

    // Parse the project's capability
    // request and read the user's configured bounds. Both values
    // flow into every `evaluate_trust` call below; baseline
    // defaults short-circuit cleanly so projects that don't
    // declare `lpm.scripts.{passEnv, readProject, sandboxLimits}`
    // see zero behavior change.
    let requested_capabilities =
        crate::capability::CapabilitySet::from_package_json(&project_dir.join("package.json"))
            .map_err(|e| LpmError::Registry(format!("{e}")))?;
    let user_bound = crate::security_approval::authorized_capability_user_bound();

    // Build the v2 link-entry index once before the per-package loop,
    // scoped to this project's tree. A global scan is ambiguous when
    // same-coordinate packages coexist; the project-scoped walk avoids
    // returning a sibling project's patched copy of the same package.
    let baseline_index = V2BaselineIndex::for_project(project_dir, &lpm_root)?;
    let store_version = lpm_store::StoreVersion::from_env();

    // Collect packages that have lifecycle scripts
    let mut scriptable_packages: Vec<ScriptablePackage> = Vec::new();

    for lp in &lockfile.packages {
        // v2-aware lookup, routed through the invocation-local index.
        // `live_package_dir` returns `None` when the package isn't in
        // either store (workspace/file/link sources, corrupt
        // installs); silent skip preserves the previously
        // `pkg_json_path.exists()` semantic for non-store sources
        // while fixing the v2-installed-and-skipped data-loss bug.
        let package_key = lp.package_key();
        let baseline = match lpm_store::find_installed_package_baseline_exact_indexed(
            &baseline_index,
            &lpm_root,
            store_version,
            &package_key.name,
            &package_key.version,
            &package_key.source_id,
            lp.integrity.as_deref(),
        ) {
            Some(baseline) => baseline,
            None => continue,
        };
        let graph_key_digest = if baseline.layout == PackageBaselineLayout::V2 {
            read_v2_graph_key_digest(&baseline.package_dir)
        } else {
            None
        };
        let pkg_dir = baseline.package_dir;
        let pristine_path = baseline.pristine_dir;
        let pkg_json_path = pkg_dir.join("package.json");

        if !pkg_json_path.exists() {
            continue;
        }

        let scripts = match read_lifecycle_scripts(&pkg_json_path) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let marker_path = pkg_dir.join(BUILD_MARKER);
        let is_built = marker_path.exists();
        let build_marker_key = is_built
            .then(|| read_build_marker_key(&marker_path))
            .flatten();

        // trust decision
        // now flows through the shared [`evaluate_trust`] helper so
        // `rebuild::run` and `all_scripted_packages_trusted` cannot
        // disagree. The helper composes the strict gate (same fn
        // `lpm install` uses to populate `build-state.json`) with the
        // `is_scope_trusted` scope glob AND the green-tier auto-
        // trust path (*active only under
        // [`ScriptPolicy::Triage`]).
        let trust_reason = evaluate_trust_for_identity(
            &pkg_dir,
            &lp.name,
            &lp.version,
            lp.source.as_deref(),
            lp.integrity.as_deref(),
            &scripts,
            &policy,
            project_dir,
            effective_policy,
            force_security_floor,
            &requested_capabilities,
            &user_bound,
            advisor_approvals,
        );
        let is_trusted = trust_reason.is_trusted();

        // Surface drift to the user — even though the script is skipped,
        // they need to know WHY so they can re-review with `lpm approve-scripts`.
        if trust_reason == TrustReason::BindingDrift && !json_output {
            install_ui::warn(&format!(
                "{}: stored approval drifted (script changed since approval). \
                 Re-run `lpm approve-scripts {}` to re-review.",
                lp.name, lp.name,
            ));
        }
        // Surface legacy bare-name entries with a soft deprecation warning,
        // so users migrate to the strict binding form. Only emit when the
        // strict gate was the deciding factor (the helper returns
        // `LegacyName` only when `TrustMatch::LegacyNameOnly` won AND
        // scope did not).
        if trust_reason == TrustReason::LegacyName && !json_output {
            install_ui::warn(&format!(
                "{}: legacy bare-name trustedDependencies entry — run \
                 `lpm approve-scripts {}` to upgrade to a strict (script-hash-bound) approval",
                lp.name, lp.name,
            ));
        }

        // Derive `wrapper_id` from `lp.source` so the per-package
        // wrapper lookup matches the linker's segment shape. For
        // Registry sources (the common case) `wrapper_id` is `None`
        // and the segment is `<safe>@<version>`; for everything else
        // we pass through `Source::source_id()`. A malformed or
        // missing `source` collapses to `None` (matches pre-
        // behavior — old paths silently fell back to the store anyway).
        let wrapper_id = lp
            .source
            .as_deref()
            .and_then(|s| lpm_lockfile::Source::parse(s).ok())
            .and_then(|src| match src {
                lpm_lockfile::Source::Registry { .. } => None,
                other => Some(other.source_id()),
            });

        scriptable_packages.push(ScriptablePackage {
            name: lp.name.clone(),
            version: lp.version.clone(),
            source: lp.source.clone(),
            integrity: lp.integrity.clone(),
            wrapper_id,
            store_path: pkg_dir,
            pristine_path,
            source_integrity: baseline.integrity,
            graph_key_digest,
            scripts,
            is_built,
            build_marker_key,
            is_trusted,
            trust_reason,
        });
    }

    // If the kill-switch suspended any
    // approvals, emit a single summary line so users don't get
    // one warning per affected package (potentially dozens). The
    // individual BindingDrift / LegacyName warnings above stay
    // per-package because they're package-specific remediation
    // ("re-approve THIS package"); suspension is a machine-wide
    // state with a single user-level remediation, so one line
    // is the right shape.
    if force_security_floor && !json_output {
        let suspended_count = scriptable_packages
            .iter()
            .filter(|p| p.trust_reason == TrustReason::SuspendedByForceFloor)
            .count();
        if suspended_count > 0 {
            install_ui::warn(&format!(
                "{suspended_count} approval(s) suspended by \
                 `force-security-floor = true` in ~/.lpm/config.toml. \
                 Run `lpm config unset force-security-floor` to reactivate."
            ));
        }
    }

    if scriptable_packages.is_empty() {
        if json_output {
            let result = if dry_run {
                rebuild_dry_run_envelope(&[], force_security_floor)
            } else {
                rebuild_summary_envelope(0, 0, force_security_floor, &BuildCacheMetrics::default())
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        } else {
            install_ui::done("No packages have lifecycle scripts · nothing to build");
            warn_stale_trusted_deps(&policy, &scriptable_packages);
        }
        return Ok(RebuildRunReport::default());
    }

    // Warn about stale trustedDependencies entries
    if !json_output {
        warn_stale_trusted_deps(&policy, &scriptable_packages);
    }

    // Determine which packages to build
    let selected_for_policy: Vec<&ScriptablePackage> = if !specific_packages.is_empty() {
        let mut selected = Vec::new();
        let mut selected_identities = HashSet::new();
        let mut missing = Vec::new();
        for name in specific_packages {
            let suffix = format!(".{name}");
            let mut matched = false;
            for pkg in scriptable_packages
                .iter()
                .filter(|pkg| pkg.name == *name || pkg.name.ends_with(&suffix))
            {
                matched = true;
                let identity = (
                    pkg.name.clone(),
                    pkg.version.clone(),
                    pkg.source.clone(),
                    pkg.integrity.clone(),
                );
                if selected_identities.insert(identity) {
                    selected.push(pkg);
                }
            }
            if matched {
                continue;
            }
            let safe_name = lpm_common::sanitize_for_terminal(name);
            if !json_output {
                install_ui::warn(&format!(
                    "{safe_name} has no lifecycle scripts or is not installed"
                ));
            }
            missing.push(safe_name);
        }
        if !missing.is_empty() {
            let package_word = if missing.len() == 1 {
                "package"
            } else {
                "packages"
            };
            return Err(LpmError::Registry(format!(
                "requested {package_word} {} have no lifecycle scripts or are not installed",
                missing.join(", ")
            )));
        }
        selected
    } else {
        widen_to_build_by_policy(&scriptable_packages, all, effective_policy)
    };
    let covered_packages = selected_for_policy
        .iter()
        .map(|pkg| {
            (
                pkg.name.clone(),
                pkg.version.clone(),
                pkg.source.clone(),
                pkg.integrity.clone(),
            )
        })
        .collect::<Vec<_>>();

    // Filter out already-built (unless --force)
    let to_build: Vec<&ScriptablePackage> = if force {
        selected_for_policy
    } else {
        selected_for_policy
            .into_iter()
            .filter(|p| !p.is_built || (!dry_run && marker_requires_key_validation(p)))
            .collect()
    };

    // Sort in dependency order: if A depends on B, build B first (Kahn's toposort)
    let to_build = toposort_packages(to_build, &lockfile);

    if to_build.is_empty() {
        if json_output {
            let result = if dry_run {
                rebuild_dry_run_envelope(&to_build, force_security_floor)
            } else {
                rebuild_summary_envelope(0, 0, force_security_floor, &BuildCacheMetrics::default())
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        } else {
            let total = scriptable_packages.len();
            let built = scriptable_packages.iter().filter(|p| p.is_built).count();
            // fix: distinguish "all built" from
            // "none trusted". The all-built success message was
            // firing under deny/triage when every scripted package
            // was untrusted, producing "All 0/N packages are
            // already built" — a misleading line that blamed
            // staleness for a trust-gate outcome, AND buried the
            // actionable pointer toward `lpm approve-scripts` /
            // `trustedDependencies`. The skipped-count warning
            // block further down was unreachable in this branch
            // because `return Ok(())` fired first. Now the
            // skipped-count warning is rendered inline here too,
            // gated on the same `!all && specific_packages.is_empty()`
            // guard it has below, so the deny and triage UX is
            // consistent whether the set is empty-because-built or
            // empty-because-untrusted. Surfaced by the
            // subprocess fixture.
            // close-out mirrors the `!= Allow`
            // guard on the non-empty-to_build warning site below —
            // "will be skipped" is false under allow because the
            // widening rule folds all scripted packages in. Under
            // the current widening, reaching this branch under
            // allow implies `to_build` is empty because all
            // scriptable packages are already built (force=false
            // filter empties the set); in that case
            // `count_untrusted_unbuilt(…, false)` is zero, so the
            // guard is defensive. Keeping it aligned with the other
            // site prevents a future change to the widening from
            // silently re-opening the spurious-warning path.
            let untrusted_unbuilt_count_local =
                count_untrusted_unbuilt(&scriptable_packages, force);
            if untrusted_unbuilt_count_local > 0
                && !all
                && specific_packages.is_empty()
                && effective_policy != ScriptPolicy::Allow
            {
                install_ui::warn(&format!(
                    "{untrusted_unbuilt_count_local} package(s) are not in trustedDependencies and will be skipped."
                ));
                if effective_policy == ScriptPolicy::Triage {
                    eprintln!(
                        "  Run {} to review and approve blocked packages.",
                        "lpm approve-scripts".bold(),
                    );
                } else {
                    eprintln!(
                        "  Add them to {} or use {}.",
                        "package.json > lpm > trustedDependencies".dimmed(),
                        "lpm rebuild --all".bold(),
                    );
                }
            } else {
                install_ui::done(&format!(
                    "All {built}/{total} packages with scripts are already built."
                ));
                if !force {
                    eprintln!("  Use {} to rebuild.", "--force".dimmed());
                }
            }
        }
        return Ok(RebuildRunReport {
            covered_packages,
            built_packages: Vec::new(),
        });
    }

    let timeout = Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_SCRIPT_TIMEOUT_SECS));

    // Dry run — show what would be executed
    if dry_run {
        if json_output {
            let json = rebuild_dry_run_envelope(&to_build, force_security_floor);
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            install_ui::phase(&format!(
                "Dry run: {} package(s) would be built:",
                to_build.len()
            ));
            for pkg in &to_build {
                // when a package is trusted via
                // the green-tier auto-trust path (no manifest binding,
                // no scope match — only the Layer 1 static-gate
                // classifier + triage policy) surface that to the
                // user. Without this suffix a triage user who sees
                // `trusted ✓` next to a package they never added to
                // `trustedDependencies` has no visible explanation;
                // the suffix also makes it obvious which packages
                // move into the manual-review lane if the user flips
                // back to `deny`.
                let trust = if pkg.is_trusted {
                    match pkg.trust_reason {
                        TrustReason::GreenTierUnderTriage => {
                            "trusted ✓ (green-tier auto-approval)".green().to_string()
                        }
                        _ => "trusted ✓".green().to_string(),
                    }
                } else {
                    "not trusted".yellow().to_string()
                };
                println!(
                    "\n  {} {} ({})",
                    pkg.name.bold(),
                    format!("({})", pkg.version).dimmed(),
                    trust,
                );
                for (phase, cmd) in &pkg.scripts {
                    println!("    {phase}: {}", cmd.dimmed());
                }
            }
        }
        return Ok(RebuildRunReport {
            covered_packages,
            built_packages: Vec::new(),
        });
    }

    // Warn if scripted packages are being skipped for lack of trust.
    //
    // under `script-policy = "triage"` the canonical
    // next step for an untrusted blocked package is `lpm approve-scripts`
    // (which renders the tier, lets the user review diffs, and writes
    // strict bindings into `trustedDependencies`). Pointing triage users
    // at the raw manifest edit is misleading — that bypasses the tiered
    // gate entirely. Under `deny` and `allow` the existing pointer stays:
    // deny expects hand-authored trust entries, and `allow` never reaches
    // this branch in practice (every package is trusted).
    //
    // The count is taken from `scriptable_packages` via the
    // [`count_untrusted_unbuilt`] helper, NOT from `to_build`. In the
    // default `lpm rebuild` path (no `--all`, no named args) `to_build`
    // is already filtered to trusted-only at the selection step
    // above, so a `to_build.iter().filter(|p| !p.is_trusted)` count
    // is structurally always zero and the warning never reaches the
    // user — a previous unreachable-code bug that also silently buried the
    // "Add to trustedDependencies" hint. Counting from the
    // pre-trust-filter set restores the intended UX and is what the
    // messaging swap actually needs to be observable. The
    // `!all && specific_packages.is_empty()` guard stays because
    // those two branches already run untrusted scripts directly (the
    // user has either opted in with `--all` or named packages
    // explicitly), so the skipped-packages framing is wrong there.
    //
    // the whole block is now gated on
    // `!json_output`, and the continuation pointer uses `eprintln!`
    // (stderr) instead of `println!` (stdout). The previous code
    // used `println!` for the "Add them to trustedDependencies"
    // pointer and lacked a `!json_output` guard — a latent bug
    // because the block was unreachable-code (the counter
    // issue). With the counter now reaching users, the stdout /
    // JSON-mode bleed is real: `--json` consumers parse stdout and
    // any human-readable continuation text on stdout breaks
    // `JSON.parse`. Surfaced by the subprocess integration
    // fixture which routes stdout through `serde_json::from_str`.
    // The adjacent slim warning already emits on stderr via
    // cliclack; routing the continuation there too keeps the
    // two-line UX visually grouped on the same stream.
    // close-out the "will be skipped" warning is
    // *about* untrusted packages that fell out of the default-branch
    // filter. Under `ScriptPolicy::Allow` the filter doesn't exclude
    // them anymore (the widening happens in
    // [`widen_to_build_by_policy`]), so calling them "skipped" is a
    // lie and the accompanying pointer toward
    // `trustedDependencies` / `lpm rebuild --all` is misdirection —
    // the allow user explicitly opted OUT of that lane. Suppress
    // under Allow. Deny and Triage keep the existing behavior:
    // untrusted scripted packages genuinely don't run, and the
    // pointer tells the user how to approve.
    let untrusted_unbuilt_count = count_untrusted_unbuilt(&scriptable_packages, force);
    if !json_output
        && untrusted_unbuilt_count > 0
        && !all
        && specific_packages.is_empty()
        && effective_policy != ScriptPolicy::Allow
    {
        install_ui::warn(&format!(
            "{untrusted_unbuilt_count} package(s) are not in trustedDependencies and will be skipped."
        ));
        if effective_policy == ScriptPolicy::Triage {
            eprintln!(
                "  Run {} to review and approve blocked packages.",
                "lpm approve-scripts".bold(),
            );
        } else {
            eprintln!(
                "  Add them to {} or use {}.",
                "package.json > lpm > trustedDependencies".dimmed(),
                "lpm rebuild --all".bold(),
            );
        }
    }

    if !json_output {
        install_ui::phase("Rebuilding lifecycle scripts for trusted packages");
        // summary line for green-tier auto-
        // approvals. Under `script-policy = "triage"`, the shared
        // [`evaluate_trust`] helper promotes packages whose lifecycle
        // scripts match the Layer 1 static-gate allowlist (the green-tier path) even
        // without a `trustedDependencies` entry. Most installs won't
        // have any; skip the line when the count is zero so quiet
        // builds stay quiet. The line is descriptive-only — it does
        // NOT change what runs or in which order.
        let green_auto_count = to_build
            .iter()
            .filter(|p| p.trust_reason == TrustReason::GreenTierUnderTriage)
            .count();
        if green_auto_count > 0 {
            install_ui::phase(&format!(
                "  {green_auto_count} of these were auto-approved by green-tier classification \
                 (script-policy = \"triage\"). Run `lpm rebuild --dry-run` to see why."
            ));
        }
    }

    let rebuild_start = std::time::Instant::now();

    // Execute scripts
    let mut successes = 0usize;
    let mut failures = 0usize;
    let mut completed_scripts = 0usize;
    let mut build_cache_metrics = BuildCacheMetrics::default();
    let mut built_packages = Vec::with_capacity(to_build.len());
    let package_label_width = to_build
        .iter()
        .map(|pkg| rebuild_package_label(pkg).len())
        .max()
        .unwrap_or(0);

    // Sandbox backend setup
    // : resolve the full sandbox-mode precedence chain
    // ONCE up front so the env-scrub strategy AND the `SandboxMode`
    // selection both consult the same resolved state.
    //
    // The previous version of this function computed `SandboxMode`
    // from the `no_sandbox` CLI flag alone and discarded the
    // resolved mode from the chain — so persistent
    // `[sandbox] mode = "none"` (set via `lpm config sandbox --set none`
    // or directly in `lpm.toml` / `~/.lpm/config.toml`) silently
    // fell back to the enforced default.
    // caught that gap; the test
    // `sandbox_config::tests::decide_runtime_no_flags_config_none_yields_disabled_no_scrub`
    // pins the corrected contract.
    //
    // Note `--no-sandbox` is still passed through the resolver as a
    // CLI flag — that ensures the precedence ordering inside
    // `resolve_sandbox_mode_from_chain` and `decide_runtime_sandbox_mode`
    // is single-sourced and matches `lpm doctor`'s view.
    let (sandbox_options, resolved_sandbox_mode) =
        crate::sandbox_config::resolve_sandbox_mode_from_chain(
            project_dir,
            no_sandbox,
            strict_sandbox,
            json_output,
        )?;
    let (sandbox_mode, scrub_env) = crate::sandbox_config::decide_runtime_sandbox_mode(
        no_sandbox,
        sandbox_log,
        resolved_sandbox_mode,
    );

    // `--no-sandbox` is the single collapsed
    // escape — it drops both containment AND env scrubbing in one
    // flag (per of the DX redline). The persistent `[sandbox]
    // mode = "none"` shape has the same runtime semantics, just
    // sourced from config / the wizard instead of a CLI flag.
    // `scrub_env=false` covers BOTH paths so the contract is
    // symmetric.
    let sanitized_env = if scrub_env {
        build_sanitized_env()
    } else {
        // L29: when sandbox is disabled, also emit via tracing::warn
        // so the security signal survives `--json` mode. Surfaces a
        // CI-aware hint when `CI=true` or `GITHUB_ACTIONS=true` is
        // set — CI pipelines that ended up at no-sandbox are almost
        // always a misconfiguration; the hint nudges operators to
        // gate sandbox loosening behind an explicit policy knob
        // rather than discovering it post-incident.
        tracing::warn!(
            target: "lpm_cli::sandbox",
            "sandbox disabled — credential env vars will NOT be stripped and scripts run \
             WITHOUT filesystem / network containment."
        );
        let in_ci = std::env::var("CI").is_ok_and(|v| !v.is_empty())
            || std::env::var("GITHUB_ACTIONS").is_ok_and(|v| !v.is_empty());
        if in_ci {
            tracing::warn!(
                target: "lpm_cli::sandbox",
                "CI environment detected with sandbox disabled — review whether \
                 `--no-sandbox` / `[sandbox] mode = \"none\"` is intentional. \
                 Recommended: leave the default (strict via `LPM_STRICT_SANDBOX=1`) \
                 and gate any opt-out behind a CI-specific job that explicitly sets it."
            );
        }
        if !json_output {
            install_ui::warn(
                "sandbox disabled: credential env vars will NOT be stripped and scripts run \
                 WITHOUT filesystem / network containment.",
            );
            if in_ci {
                install_ui::warn(
                    "CI environment detected with sandbox disabled — confirm this is intentional. \
                     The default (containment ON) is the safer posture for CI.",
                );
            }
        }
        std::env::vars().collect::<HashMap<String, String>>()
    };

    let lpm_root = lpm_common::paths::LpmRoot::from_env()
        .map_err(|e| LpmError::Registry(format!("failed to locate LPM root: {e}")))?;
    let store_root = lpm_root.store_root();
    let home_dir = dirs::home_dir().ok_or_else(|| {
        LpmError::Registry(
            "cannot determine $HOME — sandbox needs it for the writable-cache allow list"
                .to_string(),
        )
    })?;

    // Read the user-global allowlist for
    // `sandboxWriteDirs` entries. Expansion rules:
    // - `~/...` entries are expanded to `$HOME/...`.
    // - Entries that aren't absolute after expansion are silently
    //   dropped (callers don't get to cross the user-config trust
    //   boundary with relative paths; only explicit absolute roots
    //   are meaningful here).
    // Empty / absent → empty `Vec`. Pre-the validator
    // skipped the allowlist intersection in this case (back-compat
    // semantic pinned in ); flipped that to
    // "no opt-in" so absolute `sandboxWriteDirs` entries outside
    // `project_dir` now require an explicit covering root here.
    let max_write_roots: Vec<PathBuf> = crate::commands::config::GlobalConfig::load()
        .get_str_array("max-sandbox-write-roots")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| {
            if let Some(rest) = s.strip_prefix("~/") {
                Some(home_dir.join(rest))
            } else if s == "~" {
                Some(home_dir.clone())
            } else {
                let p = PathBuf::from(s);
                p.is_absolute().then_some(p)
            }
        })
        .collect();

    let extra_write_dirs = lpm_sandbox::load_sandbox_write_dirs(
        &project_dir.join("package.json"),
        project_dir,
        &max_write_roots,
        Some(&home_dir),
    )
    .map_err(|e| LpmError::Registry(format!("{e}")))?;

    // Per-user `[sandbox] script-read-allow` opt-in — list of
    // project-relative paths the user has chosen to exempt from
    // the secret-file deny list across every project they run
    // `lpm install` in. Per-project entries (in
    // `package.json > lpm > scripts > sandboxReadAllow`) are
    // unioned with this list by the loader.
    //
    // Empty / absent → empty list; the secret-deny block applies
    // to every match without exception. This is the safe default.
    let script_read_allow_user: Vec<String> = crate::commands::config::GlobalConfig::load()
        .get_str_array("script-read-allow")
        .unwrap_or_default();

    let extra_secret_read_allow = lpm_sandbox::load_sandbox_read_allow(
        &project_dir.join("package.json"),
        project_dir,
        &script_read_allow_user,
    )
    .map_err(|e| LpmError::Registry(format!("{e}")))?;
    // round-5 : `std::env::temp_dir()` resolves
    // tmpdir portably — POSIX checks `TMPDIR` → falls back to `/tmp`;
    // Windows checks `TMP` → `TEMP` → `USERPROFILE\AppData\Local\Temp`.
    // Pre-46.2-round-5 the helper hardcoded `TMPDIR` + `/tmp` fallback,
    // which on Windows produced a non-absolute path string (`/tmp` is
    // relative under Windows path resolution — no drive letter, no UNC
    // prefix). The sandbox spec validator then rejected the spec with
    // `tmpdir must be absolute, got /tmp`, breaking every lifecycle
    // spawn under triage / autoBuild on Windows. `std::env::temp_dir()`
    // is what every other cross-platform tool uses for this resolution.
    let tmpdir = std::env::temp_dir();

    // Ensure the "standard" writable subpaths
    // exist on disk before spawning scripts. Sandbox rules allow
    // writes INSIDE `.husky`, `.lpm`, `node_modules`, `~/.cache`,
    // `~/.node-gyp`, `~/.npm` but NOT their creation (creating
    // `.husky` would need write on `{project}` which we don't
    // grant). Without this, a first-time `husky install` would
    // fail under Enforce.
    //
    // round-2 : thread `extra_write_dirs`
    // through too — user-declared `sandboxWriteDirs` entries had to
    // be pre-created for the same reason the built-ins do (creating
    // `<project>/build-output` requires write on `<project>`, which
    // we deliberately don't grant). Pre-46.2-round-2 this Vec was
    // hardcoded empty, so the lib.rs::prepare_writable_dirs fix that
    // also iterates extras was unreachable in production. The
    // clone is intentional: extra_write_dirs is consumed per-package
    // in the loop below, so we hand a copy to the install-wide prep
    // step and keep the original for the per-package SandboxSpecs.
    let prepare_spec = lpm_sandbox::SandboxSpec {
        package_dir: project_dir.to_path_buf(), // placeholder, unused by prepare
        project_dir: project_dir.to_path_buf(),
        package_name: "__lpm-prepare".to_string(),
        package_version: "0.0.0".to_string(),
        store_root: store_root.clone(),
        home_dir: home_dir.clone(),
        tmpdir: tmpdir.clone(),
        secret_read_allow: Vec::new(),
        extra_write_dirs: extra_write_dirs.clone(),
    };
    lpm_sandbox::prepare_writable_dirs(&prepare_spec)
        .map_err(|e| LpmError::Registry(format!("{e}")))?;

    let mut effective_sandbox_posture = lpm_sandbox::SandboxPosture::Disabled;

    // `sandbox_options` already carries `allow-degraded` and
    // `deny_outbound_network` from the resolver call above. Reusing
    // it here preserves the resolved mode for both the pre-probe and
    // per-package sandbox construction.

    // Pre-probe the sandbox factory with a
    // synthetic spec so unsupported-platform and mode-not-supported
    // errors surface BEFORE any banner or package loop starts.
    // Without this, a Linux user passing `--sandbox-log` would first
    // see the "rule triggers logged but NOT enforced" banner and
    // then get ModeNotSupportedOnPlatform, which is contradictory UX.
    //
    // additionally uses the pre-probe to read the
    // backend's effective [`SandboxPosture`] — if `allow-degraded`
    // activated the V1 fallback, this is where we emit the
    // structured per-install stderr warning (exactly once,
    // regardless of how many scripted packages are about to build).
    //
    // Disabled is skipped: NoopSandbox is available on every
    // platform, so the probe would always succeed and we'd just
    // burn an allocation.
    if !matches!(sandbox_mode, SandboxMode::Disabled) {
        let probe_spec = lpm_sandbox::SandboxSpec {
            package_dir: project_dir.to_path_buf(),
            project_dir: project_dir.to_path_buf(),
            package_name: "__lpm-sandbox-probe".to_string(),
            package_version: "0.0.0".to_string(),
            store_root: store_root.clone(),
            home_dir: home_dir.clone(),
            tmpdir: tmpdir.clone(),
            secret_read_allow: Vec::new(),
            extra_write_dirs: Vec::new(),
        };
        let probe_sandbox = lpm_sandbox::new_for_platform_with_options(
            probe_spec,
            sandbox_mode,
            sandbox_options.clone(),
        )
        .map_err(|e| LpmError::Registry(format!("sandbox unavailable: {e}")))?;
        effective_sandbox_posture = probe_sandbox.posture();
        // per-install warning: emitted once when the
        // probe's effective posture is `Degraded`. The structured
        // line names kernel + active ABI + missing dimension so log
        // scrapers can detect the gap mechanically. Human mode
        // formats via the slim warning path; JSON mode emits the same line
        // via `tracing::warn` so consumers running with `RUST_LOG=warn`
        // see the degraded posture without parsing stderr — the JSON
        // envelope on stdout stays well-formed. Previously suppressed
        // entirely under `--json`, which hid the degradation from
        // CI gates that consume only the JSON envelope.
        if let Some(line) = probe_sandbox.posture().degraded_warning_line() {
            // M65: always emit via tracing::warn (CI / RUST_LOG=warn
            // pipelines pick it up regardless of output mode) AND via
            // a slim warning for the human path. Previously, JSON mode
            // emitted via tracing only and human mode emitted via
            // output only — splitting the visibility unnecessarily.
            // Now both paths fire in both modes; the degraded posture
            // is a security signal a strict-mode user must not miss.
            tracing::warn!(target: "lpm_cli::sandbox", "{line}");
            if !json_output {
                install_ui::warn(&line);
                install_ui::warn(
                    "strict sandbox requested but kernel-level network containment is NOT \
                     enforced under this posture. Lifecycle scripts can reach the network. \
                     Either upgrade to kernel >= 6.7 (landlock V4) or unset \
                     `[sandbox] allow-degraded = true` to fail-closed instead of falling back.",
                );
            }
        }
        drop(probe_sandbox);
    }

    let cache_preparation_start = std::time::Instant::now();
    let build_cache_invocation = BuildCacheInvocation::prepare(
        &lockfile,
        &sanitized_env,
        project_dir,
        sandbox_mode,
        &effective_sandbox_posture,
        &sandbox_options,
        &extra_write_dirs,
        &extra_secret_read_allow,
        &requested_capabilities,
    );
    build_cache_metrics.preparation_ms = elapsed_millis(cache_preparation_start.elapsed());

    // Banners fire AFTER the probe succeeds. On Linux + LogOnly the
    // probe above bailed with ModeNotSupportedOnPlatform, so this
    // banner's "logged but NOT enforced" promise never reaches a
    // user whose platform can't actually honor it.
    //
    // rework note: the `--no-sandbox` banner is emitted
    // up at the `sanitized_env` selector — see the `if no_sandbox`
    // branch in env construction — so users see "credentials NOT
    // stripped + no containment" as one combined warning rather
    // than two split announcements.
    //
    // Low + Medium: the strict banner gate
    // must consult BOTH the resolved tier and the final SandboxMode.
    //
    // previously the banner only fired for `--strict-sandbox`
    // / `--paranoid` on the CLI. Config-set / env-set strict was
    // silent, contradicting DX-doc walkthroughs / /.
    //
    // once the banner fired for all resolved-Strict
    // sources, it ALSO fired when `--sandbox-log` was passed with
    // strict (clap allows that pair, and env/config strict + CLI
    // `--sandbox-log` can't be clap-rejected at all). But
    // `decide_runtime_sandbox_mode` collapses to LogOnly in that
    // case, so the user saw "outbound network will be denied"
    // immediately followed by "logged but NOT enforced" —
    // contradictory UX.
    //
    // `strict_banner_for_runtime` gates on both axes: only emits
    // when the final mode is Enforce AND the resolved tier is
    // Strict. LogOnly / Disabled paths fall through silently —
    // the existing `--sandbox-log` banner just below + the
    // `no-sandbox` banner up at the env-scrub site cover those
    // cases truthfully.
    if !json_output
        && let Some(line) =
            crate::sandbox_config::strict_banner_for_runtime(sandbox_mode, resolved_sandbox_mode)
    {
        install_ui::warn(line);
    }
    if sandbox_log {
        // The `--sandbox-log` banner is a SECURITY signal — the user
        // has opted into permissive-with-report which leaves the
        // install effectively unsandboxed on macOS. JSON-mode callers
        // (CI / agents) need to know they're NOT getting enforcement,
        // so emit via `tracing::warn` (lands on stderr regardless of
        // mode) AND via a slim warning for the human path. Matches
        // the M11/L11 posture for the same class of "loud signal
        // must survive --json" warnings.
        tracing::warn!(
            target: "lpm_cli::sandbox",
            "--sandbox-log: diagnostic mode only — rule triggers are LOGGED but NOT enforced. Do not treat a clean run as a safety signal."
        );
        if !json_output {
            install_ui::warn(
                "--sandbox-log: diagnostic mode only. Rule triggers are logged but NOT \
                 enforced — do not treat a clean run as a safety signal. View reported \
                 accesses via `log show --last 5m --predicate 'senderImagePath CONTAINS \
                 \"Sandbox\"'` and grep for the script's pid.",
            );
        }
    }

    for pkg in &to_build {
        let mut pkg_success = true;

        let key_start = std::time::Instant::now();
        let mut build_key = build_cache_invocation
            .as_ref()
            .and_then(|invocation| build_key_for_package(invocation, pkg, project_dir));
        build_cache_metrics.key_ms += elapsed_millis(key_start.elapsed());
        if build_key.is_some() {
            build_cache_metrics.eligible += 1;
        } else if is_cacheable_native_build(pkg) {
            build_cache_metrics.bypassed += 1;
        }
        let v2_store = lpm_store::v2::Store::from_lpm_root(&lpm_root);
        let _build_entry_lock = if let Some(graph_key_digest) = pkg.graph_key_digest.as_deref() {
            match v2_store
                .paths()
                .build_entry_lock_path(graph_key_digest)
                .and_then(lpm_common::acquire_exclusive_lock)
            {
                Ok(lock) => Some(lock),
                Err(error) => {
                    if !json_output {
                        let label = rebuild_package_label(pkg);
                        install_ui::detail(&format!(
                            "  {} {label:<package_label_width$}  failed to lock package build state: {error}",
                            install_ui::red("✗"),
                        ));
                    }
                    if json_output {
                        install_ui::failed(&rebuild_package_failure_message(pkg, &error));
                    }
                    failures += 1;
                    continue;
                }
            }
        } else {
            None
        };
        let _build_key_lock = if let Some(key) = build_key.as_ref() {
            match lpm_common::acquire_exclusive_lock(v2_store.paths().build_lock_path(key)) {
                Ok(lock) => Some(lock),
                Err(error) => {
                    tracing::warn!(
                        "build cache bypassed for {}@{} because the per-key lock failed: {error}",
                        pkg.name,
                        pkg.version
                    );
                    build_cache_metrics.bypassed += 1;
                    build_key = None;
                    None
                }
            }
        } else {
            None
        };

        // fix: lifecycle scripts must run from the LIVE
        // per-package directory (where the symlinked sibling
        // node_modules/ exists), not the global content-addressable
        // store path. Previously, scripts ran from `~/.lpm/store/v1/...`
        // which has no `node_modules/` upstream, so a postinstall
        // doing `require.resolve('@scope/sibling-pkg')` failed —
        // most visibly with `esbuild`'s install.js trying to find
        // its platform-specific binary subpackage.
        //
        // on Linux the linker hardlinks store
        // files into the live directory, so the live and store files
        // share an inode. Detach hardlinks before any script runs so
        // a script that mutates its own package files doesn't bleed
        // into the global store. macOS (clonefile, already CoW) and
        // Windows (always copies) get a no-op return.
        let package_key = pkg.package_key();
        let exact_v2_index = pkg.graph_key_digest.as_ref().map(|_| &baseline_index);
        let live_pkg_dir = match prepare_live_package_dir(
            project_dir,
            PackageLookupIdentity::new(
                &pkg.name,
                &pkg.version,
                pkg.wrapper_id.as_deref(),
                Some(&package_key.source_id),
                Some(&pkg.source_integrity),
            ),
            &pkg.store_path,
            &store_root,
            exact_v2_index,
        ) {
            Ok(d) => d,
            Err(e) => {
                if !json_output {
                    let label = rebuild_package_label(pkg);
                    install_ui::detail(&format!(
                        "  {} {label:<package_label_width$}  {e}",
                        install_ui::red("✗"),
                    ));
                }
                if json_output {
                    install_ui::failed(&rebuild_package_failure_message(pkg, &e));
                }
                failures += 1;
                continue;
            }
        };

        let marker_path = pkg.store_path.join(BUILD_MARKER);
        let current_marker_exists = marker_path.is_file();
        let current_marker_key = current_marker_exists
            .then(|| read_build_marker_key(&marker_path))
            .flatten();
        if force {
            if let Err(error) = std::fs::remove_file(&marker_path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(
                    "failed to clear build marker for forced rebuild of {}: {error}",
                    pkg.name
                );
            }
        } else if current_marker_exists {
            match (current_marker_key.as_deref(), build_key.as_ref()) {
                (Some(marker_key), Some(key)) if marker_key == key.as_str() => {
                    build_cache_metrics.local_state_hits += 1;
                    continue;
                }
                (_, None) => continue,
                _ => {
                    if let Err(error) = std::fs::remove_file(&marker_path)
                        && error.kind() != std::io::ErrorKind::NotFound
                    {
                        tracing::warn!(
                            "failed to clear stale build marker for {}: {error}",
                            pkg.name
                        );
                    }
                }
            }
        }
        if !force && let Some(key) = build_key.as_ref() {
            let store = lpm_store::v2::Store::from_lpm_root(&lpm_root);
            let lookup_start = std::time::Instant::now();
            match store.reusable_build_artifact(key) {
                Ok(Some(artifact)) => {
                    build_cache_metrics.lookup_ms += elapsed_millis(lookup_start.elapsed());
                    let restore_start = std::time::Instant::now();
                    match store.restore_build_artifact(&artifact, &pkg.store_path) {
                        Ok(()) => {
                            build_cache_metrics.restore_ms +=
                                elapsed_millis(restore_start.elapsed());
                            build_cache_metrics.hits += 1;
                            build_cache_metrics.scripts_avoided += pkg.scripts.len();
                            build_cache_metrics.restored_bytes += artifact.manifest.unpacked_bytes;
                            build_cache_metrics.lifecycle_ms_avoided +=
                                artifact.manifest.lifecycle_duration_ms;
                            if let Err(error) = std::fs::write(
                                pkg.store_path.join(BUILD_MARKER),
                                key.as_str().as_bytes(),
                            ) {
                                tracing::warn!(
                                    "failed to write restored build marker for {}: {error}",
                                    pkg.name
                                );
                            }
                            if !json_output {
                                let label = rebuild_package_label(pkg);
                                install_ui::detail(&format!(
                                    "  {} {label:<package_label_width$}  {}",
                                    install_ui::green("✓"),
                                    install_ui::dim("build cache hit"),
                                ));
                            }
                            successes += 1;
                            built_packages.push((
                                pkg.name.clone(),
                                pkg.version.clone(),
                                pkg.source.clone(),
                                pkg.integrity.clone(),
                            ));
                            continue;
                        }
                        Err(error) => {
                            build_cache_metrics.restore_ms +=
                                elapsed_millis(restore_start.elapsed());
                            build_cache_metrics.misses += 1;
                            tracing::warn!(
                                "failed to restore build cache entry for {}@{}: {error}",
                                pkg.name,
                                pkg.version
                            );
                        }
                    }
                }
                Ok(None) => {
                    build_cache_metrics.lookup_ms += elapsed_millis(lookup_start.elapsed());
                    build_cache_metrics.misses += 1;
                }
                Err(error) => {
                    build_cache_metrics.lookup_ms += elapsed_millis(lookup_start.elapsed());
                    build_cache_metrics.misses += 1;
                    tracing::warn!(
                        "failed to inspect build cache entry for {}@{}: {error}",
                        pkg.name,
                        pkg.version
                    );
                }
            }
        }

        if build_key.is_some() {
            let store = lpm_store::v2::Store::from_lpm_root(&lpm_root);
            let rematerialize_start = std::time::Instant::now();
            if let Err(error) = store.restore_pristine_package(&pkg.pristine_path, &pkg.store_path)
            {
                build_cache_metrics.rematerialize_ms +=
                    elapsed_millis(rematerialize_start.elapsed());
                if !json_output {
                    let label = rebuild_package_label(pkg);
                    install_ui::detail(&format!(
                        "  {} {label:<package_label_width$}  failed to restore pristine source: {error}",
                        install_ui::red("✗"),
                    ));
                }
                failures += 1;
                continue;
            }
            build_cache_metrics.rematerialize_ms += elapsed_millis(rematerialize_start.elapsed());
        }

        let build_cache_scratch = if build_key.is_some() {
            let scratch = pkg
                .graph_key_digest
                .as_deref()
                .ok_or_else(|| std::io::Error::other("package has no v2 graph identity"))
                .and_then(|digest| BuildCacheScratch::create(&pkg.store_path, digest));
            match scratch {
                Ok(scratch) => Some(scratch),
                Err(error) => {
                    tracing::warn!(
                        "build cache bypassed for {}@{} because isolated scratch setup failed: {error}",
                        pkg.name,
                        pkg.version
                    );
                    build_key = None;
                    None
                }
            }
        } else {
            None
        };
        let script_tmpdir = build_cache_scratch
            .as_ref()
            .map_or(tmpdir.as_path(), BuildCacheScratch::path);
        let mut package_sandbox_options = sandbox_options.clone();
        package_sandbox_options.build_cache_isolation = build_key.is_some();

        let lifecycle_start = std::time::Instant::now();
        for phase in EXECUTED_INSTALL_PHASES {
            let cmd = match pkg.scripts.get(*phase) {
                Some(c) => c,
                None => continue,
            };

            match execute_script(
                cmd,
                &pkg.name,
                &pkg.version,
                &live_pkg_dir,
                project_dir,
                &sanitized_env,
                &timeout,
                sandbox_mode,
                &package_sandbox_options,
                &extra_write_dirs,
                &extra_secret_read_allow,
                &store_root,
                &home_dir,
                script_tmpdir,
            ) {
                Ok(()) => {
                    if !json_output {
                        let label = rebuild_package_label(pkg);
                        install_ui::detail(&format!(
                            "  {} {label:<package_label_width$}  {}",
                            install_ui::green("✓"),
                            install_ui::dim(phase),
                        ));
                    }
                    completed_scripts += 1;
                }
                Err(e) => {
                    pkg_success = false;
                    if !json_output {
                        let label = rebuild_package_label(pkg);
                        install_ui::detail(&format!(
                            "  {} {label:<package_label_width$}  {} failed: {e}",
                            install_ui::red("✗"),
                            install_ui::dim(phase),
                        ));
                    }
                    break; // Don't run subsequent phases if one fails
                }
            }
        }

        if pkg_success {
            if let Some(key) = build_key.as_ref() {
                let store = lpm_store::v2::Store::from_lpm_root(&lpm_root);
                let publish_start = std::time::Instant::now();
                if let Err(error) = store.publish_build_artifact(
                    key,
                    &pkg.source_integrity,
                    &pkg.store_path,
                    elapsed_millis(lifecycle_start.elapsed()),
                    force,
                ) {
                    tracing::warn!(
                        "failed to publish build cache entry for {}@{}: {error}",
                        pkg.name,
                        pkg.version
                    );
                }
                build_cache_metrics.publish_ms += elapsed_millis(publish_start.elapsed());
            }
            let marker_path = pkg.store_path.join(BUILD_MARKER);
            let marker = build_key
                .as_ref()
                .map_or(&[][..], |key| key.as_str().as_bytes());
            if let Err(e) = std::fs::write(&marker_path, marker) {
                tracing::warn!("failed to write build marker for {}: {e}", pkg.name);
            }
            successes += 1;
            built_packages.push((
                pkg.name.clone(),
                pkg.version.clone(),
                pkg.source.clone(),
                pkg.integrity.clone(),
            ));
        } else {
            failures += 1;
        }
    }

    // Summary
    if json_output {
        let json = rebuild_summary_envelope(
            successes,
            failures,
            force_security_floor,
            &build_cache_metrics,
        );
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if failures == 0 {
        eprintln!();
        install_ui::done(&format!(
            "Completed {completed_scripts} {}",
            scripts_word(completed_scripts),
        ));
        if untrusted_unbuilt_count > 0
            && !all
            && specific_packages.is_empty()
            && effective_policy != ScriptPolicy::Allow
        {
            let package_word = install_ui::packages_word(untrusted_unbuilt_count);
            install_ui::detail(&format!(
                "  {} {} blocked {package_word}",
                install_ui::dim("skipped:"),
                install_ui::section(&untrusted_unbuilt_count.to_string()),
            ));
            let hint = if effective_policy == ScriptPolicy::Triage {
                "run lpm approve-scripts"
            } else {
                "add trustedDependencies or run lpm rebuild --all"
            };
            install_ui::detail(&format!("  {} {hint}", install_ui::dim("hint:")));
        }
        eprintln!();
        install_ui::done(&format!(
            "Done · rebuild finished in {}",
            install_ui::green(&install_ui::format_duration(rebuild_start.elapsed())),
        ));
    } else {
        eprintln!();
        install_ui::warn(&format!("{successes} succeeded, {failures} failed"));
    }

    if failures > 0 {
        Err(LpmError::Registry(format!(
            "{failures} package(s) failed to build"
        )))
    } else {
        Ok(RebuildRunReport {
            covered_packages,
            built_packages,
        })
    }
}
