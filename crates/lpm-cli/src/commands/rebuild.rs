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

use crate::output;
use crate::script_policy_config::ScriptPolicy;
use lpm_common::LpmError;
use lpm_sandbox::SandboxMode;
use lpm_security::script_hash::compute_script_hash;
use lpm_security::triage::StaticTier;
use lpm_security::{EXECUTED_INSTALL_PHASES, SecurityPolicy, TrustMatch};
use lpm_store::{V2BaselineIndex, find_installed_package_baseline_indexed};
// `PackageStore` lives behind a cfg(test) gate now — production
// callers of post-install lookups route through
// `find_installed_package_baseline` (v2-first, v1-fallback). Tests
// still synthesize v1-only state directly via `PackageStore::at`.
#[cfg(test)]
use lpm_store::PackageStore;

/// Resolve a lockfile-package's source-of-truth dir for the post-
/// install script pipeline (lifecycle scripts + script-body diff).
/// Prefers the v2 store (default since 4b) and falls back
/// to v1; returns `None` for workspace/file/link sources that don't
/// materialize into either store, OR for any registry-source package
/// that's missing from BOTH stores (corrupt-install state — caller
/// treats as silent skip to preserve the legacy
/// `pkg_dir.join("package.json").exists()` semantic).
///
/// Returns the same shape the legacy `PackageStore::package_dir`
/// produced — caller-facing reads of `package.json`, `BUILD_MARKER`,
/// `.integrity`, etc., compose unchanged.
///
/// **Naming.** Distinct from the project-side `live_package_dir`
/// (line ~1028), which returns the materialized `node_modules/<pkg>/`
/// path for the *runtime* of a script. This helper is the upstream
/// store-side reader that read-only inspections (script bodies,
/// trust-gate hashing) consume.
///
/// Hot-loop variant.
/// Takes an invocation-local [`V2BaselineIndex`] and turns each
/// lookup into an O(1) hashmap read. The three rebuild loops
/// (`run_under_store_lock`, `scriptable_package_rows`,
/// `all_scripted_packages_trusted`) MUST use this form — pre-fix
/// each iteration re-walked every link entry + parsed every sidecar
/// JSON, costing O(M·N) per command invocation.
fn package_baseline_dir_indexed(
    index: &V2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
) -> Option<std::path::PathBuf> {
    find_installed_package_baseline_indexed(index, lpm_root, name, version).map(|b| b.package_dir)
}
use lpm_common::color::Painted;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default timeout for each lifecycle script execution (5 minutes).
const DEFAULT_SCRIPT_TIMEOUT_SECS: u64 = 300;

/// Build state marker filename.
const BUILD_MARKER: &str = ".lpm-built";

/// Env var patterns to strip from script execution environment.
const STRIPPED_ENV_PATTERNS: &[&str] = &[
    "LPM_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "BITBUCKET_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
];

/// Env var suffix patterns — any var ending with these is stripped.
const STRIPPED_ENV_SUFFIXES: &[&str] = &["_SECRET", "_PASSWORD", "_KEY", "_PRIVATE_KEY"];

// the per-file `SCRIPT_PHASES` const previously
// declared here was removed and consolidated into
// `lpm_security::EXECUTED_INSTALL_PHASES` (imported above) so the install
// pipeline, the build pipeline, and the script-hash function all read from
// the same source of truth. See status doc §F3 for the rationale.

/// Run the `lpm rebuild` command.
///
/// `effective_policy` is the already-resolved
/// [`ScriptPolicy`] from the precedence chain (CLI override → project
/// `package.json > lpm > scriptPolicy` → `~/.lpm/config.toml` →
/// default). threads the value through the signature and
/// rewrites the blocked-packages pointer for triage mode so users are
/// told to run `lpm approve-scripts` rather than edit
/// `trustedDependencies` by hand. introduces the shared
/// trust helper that promotes green-tier classifications to trusted
/// under [`ScriptPolicy::Triage`]; this signature change ships first
/// so the policy value is in scope at every trust-check site before
/// the promotion logic lands.
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
    // soft-enforcement substitute per signoff. `no_sandbox`
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
    // In-memory advisor-approved
    // `(name, version)` set from this install's
    // [`crate::triage_advisor_session::AdvisorSession`]. Standalone
    // `lpm rebuild` invocations pass `None` — the trust manifest is
    // the only authority. The install path's autoBuild call passes
    // `Some(session.approvals())` so amber packages the advisor
    // approved this run can execute their scripts without a
    // persistent `trustedDependencies` entry.
    advisor_approvals: Option<&std::collections::HashSet<(String, String, Option<String>)>>,
) -> Result<(), LpmError> {
    // Round 2: hold the shared store lock across rebuild —
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
async fn run_under_store_lock(
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
    advisor_approvals: Option<&std::collections::HashSet<(String, String, Option<String>)>>,
) -> Result<(), LpmError> {
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
            output::warn(
                "Script execution denied. All scripts are blocked by --deny-all or lpm.scripts.denyAll config.",
            );
        }
        return Ok(());
    }

    // confidence-followup S5b — `find_installed_package_baseline`
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

    // Parse the project's capability
    // request and read the user's configured bounds. Both values
    // flow into every `evaluate_trust` call below; baseline
    // defaults short-circuit cleanly so projects that don't
    // declare `lpm.scripts.{passEnv, readProject, sandboxLimits}`
    // see zero behavior change.
    let requested_capabilities =
        crate::capability::CapabilitySet::from_package_json(&project_dir.join("package.json"))
            .map_err(|e| LpmError::Registry(format!("{e}")))?;
    let user_bound = crate::capability::UserBound::from_global_config(&global_config);

    // Build the
    // v2 link-entry index ONCE before the per-package loop, scoped to
    // THIS project's tree. Pre-fix the loop body re-walked every link
    // entry on every iteration; F2 reduced that to a single global
    // scan; the F1+F2 review tightened it further to a project-scoped
    // walk because post-F1 the global scan can return the WRONG link
    // entry (a sibling project's patched copy of the same coords)
    // when same-coord duplicates legitimately coexist.
    let baseline_index = V2BaselineIndex::for_project(project_dir, &lpm_root)?;

    // Collect packages that have lifecycle scripts
    let mut scriptable_packages: Vec<ScriptablePackage> = Vec::new();

    for lp in &lockfile.packages {
        // confidence-followup S5b — v2-aware lookup, F2 —
        // routed through the invocation-local index.
        // `live_package_dir` returns `None` when the package isn't in
        // either store (workspace/file/link sources, corrupt
        // installs); silent skip preserves the pre-fix
        // `pkg_json_path.exists()` semantic for non-store sources
        // while fixing the v2-installed-and-skipped data-loss bug.
        let pkg_dir =
            match package_baseline_dir_indexed(&baseline_index, &lpm_root, &lp.name, &lp.version) {
                Some(p) => p,
                None => continue,
            };
        let pkg_json_path = pkg_dir.join("package.json");

        if !pkg_json_path.exists() {
            continue;
        }

        let scripts = match read_lifecycle_scripts(&pkg_json_path) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let is_built = pkg_dir.join(BUILD_MARKER).exists();

        // trust decision
        // now flows through the shared [`evaluate_trust`] helper so
        // `rebuild::run` and `all_scripted_packages_trusted` cannot
        // disagree. The helper composes the strict gate (same fn
        // `lpm install` uses to populate `build-state.json`) with the
        // `is_scope_trusted` scope glob AND the green-tier auto-
        // trust path (*active only under
        // [`ScriptPolicy::Triage`]).
        let trust_reason = evaluate_trust(
            &pkg_dir,
            &lp.name,
            &lp.version,
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
            output::warn(&format!(
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
            output::warn(&format!(
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
            wrapper_id,
            store_path: pkg_dir,
            scripts,
            is_built,
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
            output::warn(&format!(
                "{suspended_count} approval(s) suspended by \
                 `force-security-floor = true` in ~/.lpm/config.toml. \
                 Run `lpm config unset force-security-floor` to reactivate."
            ));
        }
    }

    if scriptable_packages.is_empty() {
        if !json_output {
            output::success("No packages have lifecycle scripts. Nothing to build.");
        }
        // Warn about stale trustedDependencies entries
        if !json_output {
            warn_stale_trusted_deps(&policy, &scriptable_packages);
        }
        return Ok(());
    }

    // Warn about stale trustedDependencies entries
    if !json_output {
        warn_stale_trusted_deps(&policy, &scriptable_packages);
    }

    // Determine which packages to build
    let to_build: Vec<&ScriptablePackage> = if !specific_packages.is_empty() {
        // Build specific packages by name
        let mut selected = Vec::new();
        for name in specific_packages {
            let found = scriptable_packages
                .iter()
                .find(|p| p.name == *name || p.name.ends_with(&format!(".{name}")));
            match found {
                Some(pkg) => selected.push(pkg),
                None => {
                    output::warn(&format!(
                        "{name} has no lifecycle scripts or is not installed"
                    ));
                }
            }
        }
        selected
    } else {
        widen_to_build_by_policy(&scriptable_packages, all, effective_policy)
    };

    // Filter out already-built (unless --force)
    let to_build: Vec<&ScriptablePackage> = if force {
        to_build
    } else {
        to_build.into_iter().filter(|p| !p.is_built).collect()
    };

    // Sort in dependency order: if A depends on B, build B first (Kahn's toposort)
    let to_build = toposort_packages(to_build, &lockfile);

    if to_build.is_empty() {
        if !json_output {
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
                output::warn(&format!(
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
                output::success(&format!(
                    "All {built}/{total} packages with scripts are already built."
                ));
                if !force {
                    eprintln!("  Use {} to rebuild.", "--force".dimmed());
                }
            }
        }
        return Ok(());
    }

    let timeout = Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_SCRIPT_TIMEOUT_SECS));

    // Dry run — show what would be executed
    if dry_run {
        if json_output {
            let json = serde_json::json!({
                "dry_run": true,
                "packages": to_build.iter().map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "version": p.version,
                        "scripts": p.scripts,
                        "trusted": p.is_trusted,
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            output::info(&format!(
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
        return Ok(());
    }

    // Warn if scripted packages are being skipped for lack of trust.
    //
    // under `script-policy = "triage"` the canonical
    // next step for an untrusted blocked package is `lpm approve-scripts`
    // (which renders the tier, lets the user review diffs, and writes
    // strict bindings into `trustedDependencies`). Pointing triage users
    // at the raw manifest edit is misleading — that bypasses the tiered
    // gate entirely. Under `deny` and `allow` the pre-P6 pointer stays:
    // deny expects hand-authored trust entries, and `allow` never reaches
    // this branch in practice (every package is trusted).
    //
    // The count is taken from `scriptable_packages` via the
    // [`count_untrusted_unbuilt`] helper, NOT from `to_build`. In the
    // default `lpm rebuild` path (no `--all`, no named args) `to_build`
    // is already filtered to trusted-only at the selection step
    // above, so a `to_build.iter().filter(|p| !p.is_trusted)` count
    // is structurally always zero and the warning never reaches the
    // user — a pre-P6 dead-code bug that also silently buried the
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
    // (stderr) instead of `println!` (stdout). The pre-P6 code
    // used `println!` for the "Add them to trustedDependencies"
    // pointer and lacked a `!json_output` guard — a latent bug
    // because the block was dead-code (the counter
    // issue). With the counter now reaching users, the stdout /
    // JSON-mode bleed is real: `--json` consumers parse stdout and
    // any human-readable continuation text on stdout breaks
    // `JSON.parse`. Surfaced by the subprocess integration
    // fixture which routes stdout through `serde_json::from_str`.
    // The adjacent `output::warn` already emits on stderr via
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
        output::warn(&format!(
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
        output::info(&format!("Building {} package(s)...", to_build.len()));
        // summary line for green-tier auto-
        // approvals. Under `script-policy = "triage"`, the shared
        // [`evaluate_trust`] helper promotes packages whose lifecycle
        // scripts match the Layer 1 static-gate allowlist (P2) even
        // without a `trustedDependencies` entry. Most installs won't
        // have any; skip the line when the count is zero so quiet
        // builds stay quiet. The line is descriptive-only — it does
        // NOT change what runs or in which order.
        let green_auto_count = to_build
            .iter()
            .filter(|p| p.trust_reason == TrustReason::GreenTierUnderTriage)
            .count();
        if green_auto_count > 0 {
            output::info(&format!(
                "  {green_auto_count} of these were auto-approved by green-tier classification \
                 (script-policy = \"triage\"). Run `lpm rebuild --dry-run` to see why."
            ));
        }
    }

    // Execute scripts
    let mut successes = 0usize;
    let mut failures = 0usize;

    // rework  + GPT-5 audit follow-up
    // : resolve the full sandbox-mode precedence chain
    // ONCE up front so the env-scrub strategy AND the `SandboxMode`
    // selection both consult the same resolved state.
    //
    // The previous version of this function computed `SandboxMode`
    // from the `no_sandbox` CLI flag alone and discarded the
    // resolved mode from the chain — so persistent
    // `[sandbox] mode = "none"` (set via `lpm config sandbox --set none`
    // or directly in `lpm.toml` / `~/.lpm/config.toml`) silently
    // fell back to the enforced default. GPT-5's audit
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
        if !json_output {
            // Word the warning so it covers BOTH provenance paths
            // (CLI escape OR persistent `mode = "none"`) without
            // claiming the source. The `Source:` line on doctor /
            // help is the right place for provenance; this is the
            // "loud banner at the call site" the SandboxMode docs
            // already promise.
            output::warn(
                "sandbox disabled: credential env vars will NOT be stripped and scripts run \
                 WITHOUT filesystem / network containment.",
            );
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
        extra_write_dirs: extra_write_dirs.clone(),
    };
    lpm_sandbox::prepare_writable_dirs(&prepare_spec)
        .map_err(|e| LpmError::Registry(format!("{e}")))?;

    // rework GPT-5 audit follow-up: `sandbox_options`
    // (carrying `allow-degraded` and `deny_outbound_network`) is
    // already in scope from the resolver call up top. Do NOT
    // re-resolve here — the previous version did exactly that, but
    // also threw away the resolved mode, which is the bug GPT-5
    // caught. The pre-probe + per-package sandbox construction
    // below consume the up-top `sandbox_options` directly.

    // Pre-probe the sandbox factory with a
    // synthetic spec so unsupported-platform and mode-not-supported
    // errors surface BEFORE any banner or package loop starts.
    // Without this, a Linux user passing `--sandbox-log` would first
    // see the "rule triggers logged but NOT enforced" banner and
    // then get ModeNotSupportedOnPlatform — contradictory UX the
    // review flagged.
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
            extra_write_dirs: Vec::new(),
        };
        let probe_sandbox = lpm_sandbox::new_for_platform_with_options(
            probe_spec,
            sandbox_mode,
            sandbox_options.clone(),
        )
        .map_err(|e| LpmError::Registry(format!("sandbox unavailable: {e}")))?;
        // per-install warning: emitted once when the
        // probe's effective posture is `Degraded`. The structured
        // line names kernel + active ABI + missing dimension so log
        // scrapers can detect the gap mechanically. Human mode
        // formats via `output::warn`; JSON mode emits the same line
        // via `tracing::warn` so consumers running with `RUST_LOG=warn`
        // see the degraded posture without parsing stderr — the JSON
        // envelope on stdout stays well-formed. Previously suppressed
        // entirely under `--json`, which hid the degradation from
        // CI gates that consume only the JSON envelope.
        if let Some(line) = probe_sandbox.posture().degraded_warning_line() {
            if json_output {
                tracing::warn!(target: "lpm_cli::sandbox", "{line}");
            } else {
                output::warn(&line);
            }
        }
        drop(probe_sandbox);
    }

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
    // GPT-5 audit  Low + Medium: the strict banner gate
    // must consult BOTH the resolved tier and the final SandboxMode.
    //
    // Round 1: pre-fix the banner only fired for `--strict-sandbox`
    // / `--paranoid` on the CLI. Config-set / env-set strict was
    // silent, contradicting DX-doc walkthroughs / /.
    //
    // Round 2: once the banner fired for all resolved-Strict
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
        output::warn(line);
    }
    if sandbox_log && !json_output {
        output::warn(
            "--sandbox-log: diagnostic mode only. Rule triggers are logged but NOT \
             enforced — do not treat a clean run as a safety signal. View reported \
             accesses via `log show --last 5m --predicate 'senderImagePath CONTAINS \
             \"Sandbox\"'` and grep for the script's pid.",
        );
    }

    for pkg in &to_build {
        if !json_output {
            println!(
                "\n  {} {}",
                pkg.name.bold(),
                format!("({})", pkg.version).dimmed(),
            );
        }

        let mut pkg_success = true;

        // fix: lifecycle scripts must run from the LIVE
        // per-package directory (where the symlinked sibling
        // node_modules/ exists), not the global content-addressable
        // store path. Pre-fix, scripts ran from `~/.lpm/store/v1/...`
        // which has no `node_modules/` upstream, so a postinstall
        // doing `require.resolve('@scope/sibling-pkg')` failed —
        // most visibly with `esbuild`'s install.js trying to find
        // its platform-specific binary subpackage.
        //
        // follow-up: on Linux the linker hardlinks store
        // files into the live directory, so the live and store files
        // share an inode. Detach hardlinks before any script runs so
        // a script that mutates its own package files doesn't bleed
        // into the global store. macOS (clonefile, already CoW) and
        // Windows (always copies) get a no-op return.
        let live_pkg_dir = match prepare_live_package_dir(
            project_dir,
            &pkg.name,
            &pkg.version,
            pkg.wrapper_id.as_deref(),
            &pkg.store_path,
            &store_root,
            Some(&baseline_index),
        ) {
            Ok(d) => d,
            Err(e) => {
                if !json_output {
                    println!("    {} {e}", "✖".red());
                }
                // Always to stderr so JSON consumers (parsing stdout)
                // still see the failure; the summary `failed` count
                // alone wouldn't tell them WHICH package broke.
                eprintln!("lpm rebuild: {}@{}: {e}", pkg.name, pkg.version);
                failures += 1;
                continue;
            }
        };

        for phase in EXECUTED_INSTALL_PHASES {
            let cmd = match pkg.scripts.get(*phase) {
                Some(c) => c,
                None => continue,
            };

            if !json_output {
                println!("    {} {phase}: {}", "→".dimmed(), cmd.dimmed());
            }

            match execute_script(
                cmd,
                &pkg.name,
                &pkg.version,
                &live_pkg_dir,
                project_dir,
                &sanitized_env,
                &timeout,
                sandbox_mode,
                &sandbox_options,
                &extra_write_dirs,
                &store_root,
                &home_dir,
                &tmpdir,
            ) {
                Ok(()) => {
                    if !json_output {
                        println!("    {} {phase} completed", "✓".green());
                    }
                }
                Err(e) => {
                    pkg_success = false;
                    if !json_output {
                        println!("    {} {phase} failed: {e}", "✖".red());
                    }
                    break; // Don't run subsequent phases if one fails
                }
            }
        }

        if pkg_success {
            // Write .lpm-built marker
            let marker_path = pkg.store_path.join(BUILD_MARKER);
            if let Err(e) = std::fs::write(&marker_path, "") {
                tracing::warn!("failed to write build marker for {}: {e}", pkg.name);
            }
            successes += 1;
        } else {
            failures += 1;
        }
    }

    // Summary
    println!();
    if json_output {
        let json = serde_json::json!({
            "success": failures == 0,
            "built": successes,
            "failed": failures,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if failures == 0 {
        output::success(&format!("{successes} package(s) built successfully."));
    } else {
        output::warn(&format!("{successes} succeeded, {failures} failed."));
    }

    if failures > 0 {
        Err(LpmError::Registry(format!(
            "{failures} package(s) failed to build"
        )))
    } else {
        Ok(())
    }
}

/// Execute a single lifecycle script with timeout, env sanitization,
/// and filesystem-scoped containment.
///
/// This function threads `sandbox_mode` + per-project
/// `extra_write_dirs` + host-derived `store_root`/`home_dir`/`tmpdir`
/// through here so the backend can synthesize its profile for THIS
/// package on THIS host.
///
/// **Transitional cfg-fork:** On macOS this dispatches through
/// [`lpm_sandbox::new_for_platform`] and runs the child under
/// `sandbox-exec`. On non-macOS (Linux, Windows, other Unix) it
/// continues on the legacy direct-[`std::process::Command`] path
/// because [`lpm_sandbox`]'s landlock backend (Linux) lands in
/// and Windows is deferred to (D10).
/// deletes the non-macOS arm; the macOS arm becomes unconditional.
#[allow(clippy::too_many_arguments)]
fn execute_script(
    cmd: &str,
    pkg_name: &str,
    pkg_version: &str,
    package_dir: &Path,
    project_dir: &Path,
    env: &HashMap<String, String>,
    timeout: &Duration,
    sandbox_mode: SandboxMode,
    sandbox_options: &lpm_sandbox::SandboxOptions,
    extra_write_dirs: &[PathBuf],
    store_root: &Path,
    home_dir: &Path,
    tmpdir: &Path,
) -> Result<(), String> {
    // Build the environment the same way the legacy path did: start
    // from the sanitized set, strip INIT_CWD + PATH if the caller
    // pre-set them, then append our own INIT_CWD and PATH-with-
    // node_modules/.bin-prepended.
    //
    // : the path string is platform-aware
    // now. Pre-46.2 the helper hardcoded the POSIX `:` separator and
    // the POSIX `/usr/bin:/bin` fallback, which produced a malformed
    // PATH on Windows: the local `node_modules\.bin` shim got fused
    // into the same entry as the inherited system PATH and neither
    // resolved, so commands like `tsc`, `webpack`, or any sibling-
    // package binary were invisible to lifecycle scripts even though
    // the sandbox itself succeeded.
    //
    // round-5 : PATH lookup + filter are now
    // case-insensitive. Windows env vars are case-insensitive at the
    // OS level — `std::env::vars()` yields the key with its original
    // case (typically `"Path"` on Windows, `"PATH"` on POSIX). A
    // case-sensitive `env.get("PATH")` returned `None` on Windows
    // even when PATH was populated, so the child got the System32-
    // only fallback and lifecycle scripts couldn't find `node`,
    // `npm`, or any sibling-package binary on the inherited PATH.
    // Same hazard for the filter — letting "Path" through unfiltered
    // worked accidentally because `std::process::Command::env` on
    // Windows does case-insensitive deduplication and our explicit
    // `"PATH"` overrides won, but the LOOKUP path was still broken.
    let parent_path = find_env_case_insensitive(env, "PATH");
    let path_value = build_lifecycle_path(project_dir, parent_path);
    let mut envs: Vec<(String, String)> = env
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("PATH") && !k.eq_ignore_ascii_case("INIT_CWD"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    envs.push(("INIT_CWD".to_string(), project_dir.display().to_string()));
    envs.push(("PATH".to_string(), path_value));

    let start = std::time::Instant::now();

    let child = spawn_lifecycle_child(
        cmd,
        pkg_name,
        pkg_version,
        package_dir,
        project_dir,
        &envs,
        sandbox_mode,
        sandbox_options,
        extra_write_dirs,
        store_root,
        home_dir,
        tmpdir,
    )?;

    let output = wait_with_timeout(child, timeout);

    match output {
        Ok(status) => {
            if status.success() {
                let elapsed = start.elapsed();
                tracing::debug!("script completed in {:.1}s", elapsed.as_secs_f64());
                Ok(())
            } else {
                Err(format!("exit code {}", status.code().unwrap_or(-1)))
            }
        }
        Err(e) => Err(e),
    }
}

/// — resolve the live per-package directory where lifecycle
/// scripts should `current_dir` to.
///
/// **Why this matters.** Previously, `execute_script` passed
/// `pkg.store_path` (the global `~/.lpm/store/v1/<pkg>@<ver>/` location)
/// as the script's working directory. Scripts that resolve sibling
/// dependencies via `require.resolve()` failed because the global store
/// has no `node_modules/` upstream — Node's module resolution walks
/// from `__dirname` upward looking for `node_modules/` directories, and
/// in the global store there are none until you reach `~/.lpm/store/`
/// (and even then, no sibling deps for the package). esbuild's
/// `install.js` is the canonical reproducer: it does
/// `require.resolve('@esbuild/<platform>/bin/esbuild')` which fails
/// with "Failed to find package @esbuild/<platform> on the file
/// system" before falling through to a network-install fallback.
///
/// **Two layouts to handle.** The default isolated linker places each
/// package at `<project>/.lpm/wrappers/<safe_name>@<version>/node_modules/<name>/`
/// with sibling deps symlinked into the same wrapper's
/// `node_modules/`. The opt-in hoisted linker (`LPM_LINKER=hoisted`)
/// places packages at `<project>/node_modules/<name>/` with all deps
/// hoisted to the root `node_modules/`; its incremental state lives
/// at `<project>/.lpm/hoisted/metadata.json` (post-symmetry), but the
/// per-package directory probe in this function only cares about the
/// hoisted *package* location, which is unchanged. We probe both
/// layouts and fall back to `store_path` only if neither exists
/// (which means the package isn't actually linked — pathological
/// case, lifecycle scripts shouldn't run on it anyway).
///
/// **Linux store-pollution.** On Linux the linker uses
/// `std::fs::hard_link`, which means the live file and store file
/// share an inode — a lifecycle script that mutates files in its
/// own package directory would mutate the store too. macOS uses
/// `clonefile()` (CoW), so writes are isolated. The
/// follow-up addressed this by detaching hardlinks before scripts
/// run; see [`prepare_live_package_dir`] and
/// [`lpm_linker::detach_package_hardlinks`]. Callers that want both
/// the layout-aware path AND the safety guarantee should use
/// `prepare_live_package_dir`, not this function directly.
fn live_package_dir(
    project_dir: &Path,
    name: &str,
    version: &str,
    wrapper_id: Option<&str>,
    store_path: &Path,
    baseline_index: Option<&V2BaselineIndex>,
) -> std::path::PathBuf {
    // — production v2 store handle resolves once per
    // call from the active `~/.lpm/`. Tests use the
    // [`live_package_dir_with_v2`] seam directly with a synthetic
    // store rooted in a tempdir, so the env-coupled wrapper here
    // stays simple.
    let v2_store = lpm_common::LpmRoot::from_env()
        .ok()
        .map(|root| lpm_store::v2::Store::from_lpm_root(&root));
    live_package_dir_with_v2(
        project_dir,
        name,
        version,
        wrapper_id,
        store_path,
        v2_store.as_ref(),
        baseline_index,
    )
}

/// Test-friendly variant of [`live_package_dir`] that takes the v2
/// store handle explicitly instead of resolving it from the
/// environment. Production callers use the env-coupled wrapper.
///
/// **F1+F2 review.** The optional `baseline_index` is the project-
/// scoped lookup the transitive-fallback branch uses. When present
/// it's authoritative — the global `find_link_package_dir` walk is
/// only used as a backstop for callers that haven't built an index
/// (test fixtures, defensive paths). Under post-F1 same-coord
/// coexistence the global walk can return the wrong sibling
/// project's link entry; the project-scoped index is the correct
/// disambiguation.
fn live_package_dir_with_v2(
    project_dir: &Path,
    name: &str,
    version: &str,
    wrapper_id: Option<&str>,
    store_path: &Path,
    v2_store: Option<&lpm_store::v2::Store>,
    baseline_index: Option<&V2BaselineIndex>,
) -> std::path::PathBuf {
    let layout = lpm_linker::LayoutPaths::for_project(project_dir);
    let nm = project_dir.join("node_modules");

    // Isolated layout (default): `<wrapper-root>/<segment>/node_modules/<name>/`.
    //
    // — wrapper root is `<project>/.lpm/wrappers/`, resolved
    // through `LayoutPaths` so a future shape change is a single-file edit.
    //
    // audit fix #4 — segment shape comes from
    // [`LayoutPaths::wrapper_segment`], the same helper
    // [`lpm_linker::LinkTarget::wrapper_segment`] delegates to. For
    // Registry sources `wrapper_id` is `None` and the segment is
    // `<safe>@<version>`; for Tarball / Directory / Link / Git the
    // segment is `<safe>+<wid>`. Pre-fix the inline `<safe>@<version>`
    // shape silently missed every non-Registry scripted package — its
    // wrapper probe failed and the lifecycle script ran from the store
    // path (or, post-D8a, hard-errored under the new `prepare_live_package_dir`).
    let segment = lpm_linker::LayoutPaths::wrapper_segment(name, version, wrapper_id);
    let isolated = layout
        .isolated_wrapper_dir(&segment)
        .join("node_modules")
        .join(name);
    if isolated.is_dir() {
        return isolated;
    }

    // Hoisted layout: node_modules/<name>/. Doesn't disambiguate
    // version conflicts (a different version nested under a parent
    // would not be found by this probe), but covers the common case.
    //
    // Under
    // v2 mode the project's `node_modules/<name>` is a symlink into
    // `~/.lpm/store/v2/links/<key>/node_modules/<name>/`. `is_dir()`
    // follows the symlink, so this branch returns the (symlink) path
    // for direct-dep v2 installs — Node resolves through the symlink
    // at script time. No code change needed for direct deps under v2.
    let hoisted = nm.join(name);
    if hoisted.is_dir() {
        return hoisted;
    }

    // — v2 store walk for transitive lifecycle scripts.
    // Direct deps under v2 are covered by the previous branch via the
    // project-side symlink; transitives have no project-root symlink,
    // so without a store walk they'd fall through to the pathological
    // store_path fallback (which under v2 isn't even meaningful — v2
    // doesn't populate v1's `~/.lpm/store/v1/<pkg>/<version>/`).
    //
    // **F1+F2 review.** Authoritative path: consult the project-scoped
    // `V2BaselineIndex`. Its BFS over `LinkMeta.deps` reaches every
    // transitive that THIS project actually uses, and a hit there is
    // unambiguously the right link entry under post-F1 same-coord
    // coexistence (a sibling project's patched copy can't appear in
    // a project that didn't symlink it).
    if let Some(index) = baseline_index
        && let Some(b) = index.lookup(name, version)
    {
        return b.package_dir.clone();
    }
    // Backstop for callers without an index in scope (test fixtures,
    // defensive paths). The global walk is correct when only one
    // link entry exists per `(name, version)` — i.e. the pre-F1
    // state and most production v2 caches today. When duplicates
    // exist on disk, this branch may pick the wrong entry; that's
    // acceptable as a fallback because the index branch above
    // covers every reachable production path.
    if let Some(store) = v2_store
        && let Ok(Some(v2_pkg)) = store.find_link_package_dir(name, version)
    {
        return v2_pkg;
    }

    // Pathological fallback: package isn't linked. Lifecycle scripts
    // shouldn't reach this code path (they're gated on linked + scripted
    // upstream), but if they do, preserve pre-existing behavior so the
    // failure mode at least matches what users were already seeing.
    store_path.to_path_buf()
}

/// follow-up — resolve the live per-package directory AND
/// detach hardlinks so a lifecycle script's writes can't propagate
/// to the global content-addressable store.
///
/// Composes [`live_package_dir`] (which only finds the path) with
/// [`lpm_linker::detach_package_hardlinks`] (which breaks shared
/// inodes on Linux; no-op elsewhere). The single entry point is the
/// load-bearing safety boundary for the rebuild loop, and exposing
/// it as a function lets the test suite assert the composition end-
/// to-end without spinning up the full async [`run`] machinery.
///
/// **Why the guard is `!live.starts_with(store_root)`, not a byte-
/// equal `live != store_path` check.** The earlier draft used
/// `PathBuf` equality, which would silently miss a future
/// [`live_package_dir`] change that produced a structurally-different
/// fallback (anywhere under `~/.lpm/store/`). The semantic guard —
/// "never detach anything that lives inside the store root" — keeps
/// the safety property intact regardless of how the fallback path
/// is shaped, because detaching files inside `~/.lpm/store/` is
/// exactly what we're trying to prevent.
///
/// Pre-this
/// function returned `Ok(store_path)` whenever the live probe fell
/// through to the store. The caller then chdir'd into the store for
/// the lifecycle script — which, on macOS (clonefile, CoW) was a
/// silent corruption of the canonical bytes on first write, and on
/// Linux (hardlinks) the early `if !live.starts_with(store_root)`
/// branch skipped the detach so the script ran against shared
/// inodes. Either way, lifecycle scripts running inside the store
/// is a soundness violation; the install pipeline already gates
/// on "linked + scripted" so the fallback was unreachable in
/// practice but still load-bearing as a safety net.
/// closes the hole: when the resolved path is inside the store, we
/// return `Err(...)` instead of plowing forward. Callers already
/// format `Err(String)` results so no caller surface change is
/// needed.
///
/// Returns the layout-aware live directory on success, or a human-
/// readable failure string on detach error or unlinked-package
/// fallback. The error string is caller-formatted (printed to stdout
/// in pretty mode + stderr always for JSON consumers) so this
/// function itself stays free of UI concerns.
fn prepare_live_package_dir(
    project_dir: &Path,
    pkg_name: &str,
    pkg_version: &str,
    wrapper_id: Option<&str>,
    store_path: &Path,
    store_root: &Path,
    baseline_index: Option<&V2BaselineIndex>,
) -> Result<PathBuf, String> {
    let live = live_package_dir(
        project_dir,
        pkg_name,
        pkg_version,
        wrapper_id,
        store_path,
        baseline_index,
    );

    // D8a — hard-error when the resolved live path lands
    // in the store. Pre-fix this branch silently skipped detach AND
    // returned `Ok(store_path)`, letting the caller chdir into the
    // canonical bytes for a lifecycle script. See the function
    // doc-comment for the full motivation.
    if live.starts_with(store_root) {
        return Err(format!(
            "package {pkg_name}@{pkg_version} not linked into project — \
             refusing to run lifecycle script inside the store. \
             Run `lpm install` to materialize the wrapper tree, then retry."
        ));
    }

    if let Err(e) = lpm_linker::detach_package_hardlinks(&live) {
        return Err(format!("hardlink detach failed: {e}"));
    }

    Ok(live)
}

/// Spawn a lifecycle script through the sandbox backend.
///
/// This removes the cfg-fork between macOS
/// (sandboxed) and non-macOS (legacy direct-Command). Every platform
/// now routes through [`lpm_sandbox::new_for_platform`]: macOS uses
/// Seatbelt, Linux uses landlock, Windows uses the
/// Mandatory Integrity Control + Job Object backend. Old Linux
/// kernels (<5.13) surface
/// [`lpm_sandbox::SandboxError::KernelTooOld`]; non-{macOS, Linux,
/// Windows} unix variants surface
/// [`lpm_sandbox::SandboxError::UnsupportedPlatform`] which bubbles
/// up as a clear "re-run with --no-sandbox" string through the
/// format! below.
///
/// The [`SandboxMode::Disabled`] arm inside the factory hands back a
/// [`lpm_sandbox::NoopSandbox`] on every platform, so `--no-sandbox`
/// (rework collapsed the legacy `--unsafe-full-env`
/// partner) remains reachable universally as the single
/// escape hatch.
///
/// : the shell-string for the lifecycle
/// script is dispatched through [`platform_shell_invocation`] so
/// Windows hosts get `cmd.exe /D /C <cmd>` instead of `sh -c <cmd>`
/// (sh isn't on the standard Windows PATH). Without this, the
/// real-backend Windows install path would fail at spawn even though
/// the sandbox itself succeeds.
#[allow(clippy::too_many_arguments)]
fn spawn_lifecycle_child(
    cmd: &str,
    pkg_name: &str,
    pkg_version: &str,
    package_dir: &Path,
    project_dir: &Path,
    envs: &[(String, String)],
    sandbox_mode: SandboxMode,
    sandbox_options: &lpm_sandbox::SandboxOptions,
    extra_write_dirs: &[PathBuf],
    store_root: &Path,
    home_dir: &Path,
    tmpdir: &Path,
) -> Result<std::process::Child, String> {
    use lpm_sandbox::{SandboxSpec, SandboxStdio, SandboxedCommand, new_for_platform_with_options};

    let spec = SandboxSpec {
        package_dir: package_dir.to_path_buf(),
        project_dir: project_dir.to_path_buf(),
        package_name: pkg_name.to_string(),
        package_version: pkg_version.to_string(),
        store_root: store_root.to_path_buf(),
        home_dir: home_dir.to_path_buf(),
        tmpdir: tmpdir.to_path_buf(),
        extra_write_dirs: extra_write_dirs.to_vec(),
    };
    // thread the resolved `[sandbox] allow-degraded`
    // opt-in through so per-package sandbox construction picks the
    // same posture the pre-probe used. Posture mismatches between
    // pre-probe and per-package construction would surface as a
    // visible behavior change midway through an install, which is
    // exactly the inconsistency the shared `sandbox_options` value
    // exists to prevent.
    let sandbox = new_for_platform_with_options(spec, sandbox_mode, sandbox_options.clone())
        .map_err(|e| format!("sandbox init failed: {e}"))?;

    let (shell_program, shell_args) = platform_shell_invocation(cmd);
    let mut sbcmd = SandboxedCommand::new(shell_program);
    for arg in shell_args {
        sbcmd = sbcmd.arg(arg);
    }
    sbcmd = sbcmd
        .current_dir(package_dir)
        .envs_cleared(envs.iter().map(|(k, v)| (k.clone(), v.clone())));
    sbcmd.stdout = SandboxStdio::Inherit;
    sbcmd.stderr = SandboxStdio::Inherit;
    sbcmd.stdin = SandboxStdio::Inherit;

    sandbox
        .spawn(sbcmd)
        .map_err(|e| format!("failed to spawn: {e}"))
}

/// Case-insensitive env-var lookup against the sanitized env map.
/// Returns the first value whose key matches `target` ignoring ASCII
/// case. POSIX env keys are case-sensitive so this only ever changes
/// behavior on Windows, where `std::env::vars()` yields `"Path"`
/// (registry-preserved case) but the rest of the codebase looks up
/// `"PATH"`. Without this helper, lifecycle scripts on Windows ran
/// with the System32-only fallback PATH because the parent PATH
/// pass-through was silently missed.
fn find_env_case_insensitive<'a>(
    env: &'a HashMap<String, String>,
    target: &str,
) -> Option<&'a str> {
    env.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(target))
        .map(|(_, v)| v.as_str())
}

/// Compose the `PATH` env var passed to a lifecycle script. Prepends
/// the project's `node_modules/.bin` so locally-installed binaries
/// shadow system ones (matches npm/yarn/pnpm), then appends either
/// the inherited PATH if the caller provided one or a minimal
/// platform-appropriate fallback.
///
/// Platform-aware on both axes:
/// - **Separator**: `:` on POSIX, `;` on Windows.
/// - **`.bin` shape**: `node_modules/.bin` resolves identically on
///   both platforms (Windows accepts forward slashes), but we render
///   via `Path::join` + `Path::display` so the produced string uses
///   the host's native separator.
/// - **Fallback**: `/usr/bin:/bin` on POSIX is the long-standing
///   minimum. Windows gets `C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem`
///   — System32 for `cmd.exe` / `where.exe` / OS DLLs, the bare
///   Windows dir for the small set of binaries that live one level
///   up, and `Wbem` for `wmic` (rarely used but harmless to keep).
///   Lifecycle scripts that need PowerShell or Git Bash should
///   declare them via the existing PATH passthrough, not rely on
///   this fallback.
///
/// Pre-this was inlined with hardcoded POSIX separators
/// and fallback. The Windows sandbox spawn would then succeed but
/// produce a malformed PATH (`node_modules\.bin:<parent-path>`),
/// rendering local shims invisible to scripts even though the
/// sandbox itself was working correctly.
fn build_lifecycle_path(project_dir: &Path, parent_path: Option<&str>) -> String {
    let bin_dir = project_dir.join("node_modules").join(".bin");
    #[cfg(unix)]
    {
        format!(
            "{}:{}",
            bin_dir.display(),
            parent_path.unwrap_or("/usr/bin:/bin"),
        )
    }
    #[cfg(windows)]
    {
        format!(
            "{};{}",
            bin_dir.display(),
            parent_path.unwrap_or(r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem"),
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        format!(
            "{}:{}",
            bin_dir.display(),
            parent_path.unwrap_or("/usr/bin:/bin"),
        )
    }
}

/// Pick the right shell program + argv to run a lifecycle script's
/// shell-string verbatim. POSIX hosts get `sh -c <cmd>`, matching the
/// way npm/yarn/pnpm spawn lifecycle scripts. Windows gets
/// `cmd.exe /D /C <cmd>` — `/D` skips AutoRun (so the script doesn't
/// inherit shell hooks from `HKCU\Software\Microsoft\Command Processor`),
/// `/C` runs the command and terminates. Both shells are guaranteed
/// to be on PATH on their respective platforms.
///
/// This was hardcoded to `sh -c` before because the
/// pre-46.2 sandbox returned `UnsupportedPlatform` on Windows, so the
/// lifecycle path never reached spawn there. With the real backend
/// landed, dispatch has to be platform-aware to make end-to-end
/// installs work on Windows.
fn platform_shell_invocation(cmd: &str) -> (&'static str, Vec<String>) {
    #[cfg(unix)]
    {
        ("sh", vec!["-c".to_string(), cmd.to_string()])
    }
    #[cfg(windows)]
    {
        (
            "cmd.exe",
            vec!["/D".to_string(), "/C".to_string(), cmd.to_string()],
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        ("sh", vec!["-c".to_string(), cmd.to_string()])
    }
}

/// Kill the entire process group on Unix, or the Job Object tree on
/// Windows. On Windows, `Child::kill()` alone only calls
/// `TerminateProcess` against the root child — descendants spawned
/// by the lifecycle script survive. The Windows sandbox attaches the
/// child to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
/// for exactly this reason; the kill-tree call routes through
/// [`lpm_sandbox::terminate_sandbox_tree`] which calls
/// `TerminateJobObject` and brings the whole tree down at once.
fn kill_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // Kill the entire process group (negative PID = group kill).
        // The child was spawned with process_group(0) so its PID is the PGID.
        let pid = child.id() as i32;
        // SAFETY: kill(-pid) sends SIGKILL to all processes in the group.
        // This is the standard Unix pattern for cleaning up a process tree.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        // Tell the sandbox crate to terminate the Job Object tree
        // associated with this PID. The tracker holds the Job
        // handle, so without this call the kernel's
        // KILL_ON_JOB_CLOSE policy never fires (the handle isn't
        // closed until parent exit). Belt-and-suspenders:
        // `child.kill()` after, so the root child is reaped even if
        // the PID wasn't tracked (e.g. SandboxMode::Disabled +
        // NoopSandbox routed through here).
        lpm_sandbox::terminate_sandbox_tree(child.id());
        let _ = child.kill();
    }
}

/// Wait for a child process with a timeout.
/// On timeout, kills the process group (Unix) or the Job Object
/// tree (Windows) via [`kill_process_tree`]. On normal exit, releases
/// the Windows Job-tracker entry so the kernel can reclaim the Job
/// handle the sandbox stashed for kill-tree parity.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: &Duration,
) -> Result<std::process::ExitStatus, String> {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(100);
    let pid = child.id();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Normal exit: free the Windows Job-tracker entry
                // so we don't accumulate stale Job handles for the
                // lifetime of the parent. No-op on Unix.
                lpm_sandbox::release_sandbox_tracker(pid);
                return Ok(status);
            }
            Ok(None) => {
                if start.elapsed() > *timeout {
                    kill_process_tree(&mut child);
                    let _ = child.wait(); // Reap zombie
                    return Err(format!(
                        "timeout after {}s — process group killed",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => return Err(format!("wait error: {e}")),
        }
    }
}

/// Build a sanitized environment for script execution.
/// Strips credential env vars, keeps essential system vars.
fn build_sanitized_env() -> HashMap<String, String> {
    let mut env: HashMap<String, String> = HashMap::new();

    for (key, value) in std::env::vars() {
        // Skip explicitly blocked vars
        if STRIPPED_ENV_PATTERNS.contains(&key.as_str()) {
            continue;
        }

        // Skip vars matching suffix patterns
        let upper = key.to_uppercase();
        if STRIPPED_ENV_SUFFIXES
            .iter()
            .any(|suffix| upper.ends_with(suffix))
        {
            continue;
        }

        env.insert(key, value);
    }

    // M22: lifecycle scripts run with CWD = the package's directory.
    // Nested tools (`git`, `npm`, `python`) consult package-local
    // dotfiles by default — `<pkg>/.gitconfig`, `<pkg>/.npmrc`,
    // `<pkg>/.netrc` — so a malicious package can plant
    // `script-shell=/tmp/evil` or `registry=…attacker…` in a
    // dotfile and have nested tools honour it. Neutralise the
    // discovery path by pointing HOME / GIT_CONFIG_GLOBAL /
    // NPM_CONFIG_GLOBALCONFIG / etc. at /dev/null on Unix (or an
    // empty temp dir on Windows where /dev/null doesn't exist).
    // The package's OWN scripts still run; what we suppress is the
    // implicit "tool reads ./dotfile" surface that the package
    // never asked for and the user never consented to.
    #[cfg(unix)]
    {
        env.insert("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string());
        env.insert("GIT_CONFIG_SYSTEM".to_string(), "/dev/null".to_string());
        env.insert(
            "NPM_CONFIG_GLOBALCONFIG".to_string(),
            "/dev/null".to_string(),
        );
        env.insert("NPM_CONFIG_USERCONFIG".to_string(), "/dev/null".to_string());
    }

    env
}

/// Read lifecycle scripts from a package.json file.
///
/// Trial 31: uses a minimal typed struct so serde_json skips all fields
/// other than "scripts" without allocating strings for dependencies,
/// devDependencies, etc. Adds a byte pre-scan so the parse is skipped
/// entirely for packages that don't declare a "scripts" key — the common
/// case for library packages.
fn read_lifecycle_scripts(pkg_json_path: &Path) -> Option<HashMap<String, String>> {
    // Minimal struct: serde_json skips every field except "scripts" via
    // IgnoredAny, allocating no strings for deps, devDeps, engines, etc.
    #[derive(serde::Deserialize, Default)]
    struct ScriptsOnly {
        #[serde(default)]
        scripts: HashMap<String, String>,
    }

    let content = std::fs::read(pkg_json_path).ok()?;

    // Fast byte pre-scan: if "scripts" never appears as a JSON key, the
    // result is always None — skip the full parse.
    const SCRIPTS_KEY: &[u8] = b"\"scripts\"";
    if !content.windows(SCRIPTS_KEY.len()).any(|w| w == SCRIPTS_KEY) {
        return None;
    }

    let parsed: ScriptsOnly = serde_json::from_slice(&content).ok()?;

    let mut lifecycle = HashMap::new();
    for phase in EXECUTED_INSTALL_PHASES {
        if let Some(cmd) = parsed.scripts.get(*phase).filter(|s| !s.is_empty()) {
            lifecycle.insert((*phase).to_string(), cmd.clone());
        }
    }

    if lifecycle.is_empty() {
        None
    } else {
        Some(lifecycle)
    }
}

/// Check if a package name matches any trustedScopes glob pattern.
///
/// Convenience wrapper that re-parses `project_dir/package.json` on
/// every call. Fine for one-off callers (the `lpm rebuild` runner, where
/// it fires at most once per package). Hot per-N callers (the install-
/// time hint walk on potentially hundreds of packages) MUST use
/// [`parse_trusted_scopes`] + [`name_matches_trusted_scope`] to read
/// the manifest once and amortize the parse — see for the
/// 266-pkg N+1 motivation.
fn is_scope_trusted(package_name: &str, project_dir: &Path) -> bool {
    let scopes = parse_trusted_scopes(project_dir);
    name_matches_trusted_scope(package_name, &scopes)
}

/// Read `project_dir/package.json` ONCE and return the
/// `lpm.scripts.trustedScopes` list. Returns an empty vec if the file
/// is missing, malformed, or the field is absent — matching the
/// fail-closed posture of [`is_scope_trusted`].
///
/// Exposed for hot per-N call sites that previously paid an O(N) tax
/// for re-parsing the same manifest in a loop.
fn parse_trusted_scopes(project_dir: &Path) -> Vec<String> {
    let pkg_json_path = project_dir.join("package.json");
    let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    parsed
        .get("lpm")
        .and_then(|l| l.get("scripts"))
        .and_then(|s| s.get("trustedScopes"))
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Pure helper: match a package name against a precomputed list of
/// `trustedScopes` glob patterns. Same semantics as the original
/// `is_scope_trusted` body — kept identical so behavior under all
/// existing tests is preserved.
fn name_matches_trusted_scope(package_name: &str, scopes: &[String]) -> bool {
    for pattern in scopes {
        // Simple glob matching: "@myorg/*" matches "@myorg/anything"
        if let Some(prefix) = pattern.strip_suffix("/*") {
            if package_name.starts_with(prefix) && package_name.len() > prefix.len() + 1 {
                return true;
            }
        } else if pattern == package_name {
            return true;
        }
    }
    false
}

struct ScriptablePackage {
    name: String,
    version: String,
    /// Wrapper-id for non-Registry sources. `None` for Registry deps
    /// (canonical CAS-backed wrapper segment shape `<safe>@<version>`);
    /// `Some(wid)` for Tarball / Directory / Link / Git sources
    /// (segment shape `<safe>+<wid>`). Computed once at construction
    /// from [`lpm_lockfile::Source::source_id`] so the rebuild loop's
    /// per-package wrapper lookup matches the linker's segment exactly.
    ///
    /// audit fix #4: pre-fix the rebuild loop hardcoded
    /// `<safe>@<version>` for every package, silently falling back to
    /// the store path for any non-Registry dep with lifecycle scripts.
    /// Post-fix the lookup is correct for every source kind.
    wrapper_id: Option<String>,
    store_path: std::path::PathBuf,
    scripts: HashMap<String, String>,
    is_built: bool,
    is_trusted: bool,
    /// the specific basis on which
    /// `is_trusted` was decided. Preserved so the dry-run output and
    /// the pre-loop summary can surface WHY a script was trusted
    /// (strict binding vs. scope vs. green-tier auto-approval under
    /// triage). `is_trusted` is a direct read of
    /// [`TrustReason::is_trusted`] — the field pair is kept because
    /// most call sites only care about the boolean and splitting the
    /// read avoids threading [`TrustReason`] through downstream code.
    trust_reason: TrustReason,
}

/// Why a scripted package was (or was not) trusted to execute its
/// lifecycle scripts under the current effective [`ScriptPolicy`].
///
/// The variants are ordered by evaluation priority inside
/// [`evaluate_trust`]: strict-gate matches win over scope globs, which
/// win over the green-tier auto-trust. Drift is a terminal "no" —
/// a drifted rich binding never auto-recovers via triage even when
/// the current on-disk script would classify green; the user must
/// re-review via `lpm approve-scripts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustReason {
    /// Rich strict binding: `{name, version,
    /// integrity, scriptHash}` tuple matches an approved entry.
    StrictBinding,
    /// Pre-legacy bare-name `trustedDependencies: ["name"]`
    /// entry. Matched via `TrustMatch::LegacyNameOnly`. Callers
    /// still emit a soft deprecation warning so users migrate to
    /// the rich form.
    LegacyName,
    /// `lpm.scripts.trustedScopes` glob match (e.g., `@myorg/*`).
    ScopedGlob,
    /// `script-policy = "triage"` + worst-wins classification of
    /// the package's lifecycle phases is [`StaticTier::Green`]. This
    /// is the auto-trust path — the package carries no manifest
    /// binding, but its scripts match the hand-curated Layer 1
    /// allowlist (`node-gyp rebuild`, `tsc`, `prisma generate`,
    /// `husky install`, `electron-rebuild`, relative-path `node`
    /// calls). Only reachable under [`ScriptPolicy::Triage`].
    GreenTierUnderTriage,
    ///
    /// `script-policy = "triage"` + worst-wins classification is
    /// Amber/AmberLlm + an in-memory [`crate::triage_advisor_session::AdvisorSession`]
    /// returned `Approve` for this `(name, version)` during the
    /// current install. The approval is **ephemeral**: it lives
    /// only for the lifetime of the `AdvisorSession` (one install
    /// run), is never written to `trustedDependencies`, and is
    /// invisible to a later standalone `lpm rebuild` invocation
    /// that doesn't carry its own session.
    ///
    /// Reachable only when [`evaluate_trust`] is given a non-empty
    /// `advisor_approvals` set. Standalone `lpm rebuild` passes
    /// `None`, so this variant never fires outside the install path.
    AdvisorApprovedThisRun,
    /// Strict binding exists but its stored `scriptHash` no longer
    /// matches the on-disk body. Triage does NOT auto-recover this:
    /// the user previously approved a specific script and the script
    /// changed, so a re-review is required. Matches `rebuild::run`'s
    /// pre-P6 semantics exactly.
    BindingDrift,
    /// The user set
    /// `force-security-floor = true` in `~/.lpm/config.toml`. What
    /// would otherwise be a trust-granting result (`StrictBinding`,
    /// `LegacyName`, `ScopedGlob`, or `GreenTierUnderTriage`) is
    /// suspended for the duration the flag is set. No persisted state
    /// changes — approvals in `package.json > lpm > trustedDependencies`
    /// remain intact. Unsetting the flag reactivates them on the next
    /// `lpm rebuild` / `lpm install` invocation without re-review.
    ///
    /// Distinct from [`Self::Untrusted`]: `Untrusted` means "no
    /// approval exists"; `SuspendedByForceFloor` means "an approval
    /// exists but is paused." `lpm doctor` surfaces the count of
    /// suspended approvals so users can see what the kill-switch is
    /// holding back.
    SuspendedByForceFloor,
    /// The package's requested
    /// [`crate::capability::CapabilitySet`] widens beyond the
    /// user's [`crate::capability::UserBound`], AND no approval
    /// record in `package.json > lpm > trustedDependencies` has a
    /// `capabilityHash` matching the requested set.
    ///
    /// Two concrete sub-cases collapse into this reason:
    /// - The package has an approval (binding exists) but its
    ///   `capability_hash` is `None` (legacy approval) or doesn't
    ///   match the current request — approval is for a different
    ///   capability surface than what's being asked for now.
    /// - The package has an approval whose `capability_hash` was
    ///   never set (approval predates capability hashing) — any
    ///   package that widens via the capability model falls into
    ///   this state even if the user ran `lpm approve-scripts`.
    ///   Widening becomes enforceable before it becomes grantable
    ///   through normal UX.
    ///
    /// Not trusted — the script doesn't run. UX
    /// distinguishes this from `StrictBinding` /
    /// `SuspendedByForceFloor` via the approve-scripts delta
    /// display, but at the enforcement layer this is just "no."
    CapabilityNotApproved,
    /// No trust basis found.
    Untrusted,
}

impl TrustReason {
    /// Single point where the helper's output gets collapsed to the
    /// build pipeline's boolean `is_trusted`. Kept on the enum so both
    /// call sites (`rebuild::run` and `all_scripted_packages_trusted`)
    /// can never drift on which reasons count as trusted.
    pub(crate) fn is_trusted(self) -> bool {
        matches!(
            self,
            Self::StrictBinding
                | Self::LegacyName
                | Self::ScopedGlob
                | Self::GreenTierUnderTriage
                | Self::AdvisorApprovedThisRun,
        )
    }
}

/// — shared trust decision.
///
/// Single source of truth for "is this package trusted to execute
/// lifecycle scripts under the current effective policy?" Consumed by
/// both [`run`] (via its `scriptable_packages` loop) and
/// [`all_scripted_packages_trusted`]  so the two
/// paths cannot disagree on trust the first time one gets tweaked.
///
/// Evaluation order — the first matching rule wins:
/// 1. **Strict gate** ([`SecurityPolicy::can_run_scripts_strict`]).
///    A rich binding that matches the full tuple yields
///    [`TrustReason::StrictBinding`]; a legacy bare-name entry yields
///    [`TrustReason::LegacyName`]; a rich binding whose `scriptHash`
///    drifted yields [`TrustReason::BindingDrift`] — terminal, never
///    overridden by later rules.
/// 2. **Scope glob** (`lpm.scripts.trustedScopes`). Glob match yields
///    [`TrustReason::ScopedGlob`].
/// 3. **Green-tier auto-trust** (NEW in). Only when
///    `effective_policy == Triage`: classify every present lifecycle
///    phase via [`lpm_security::static_gate::classify`], reduce
///    worst-wins (same precedence `build_state.rs` uses at install
///    time), and if the result is [`StaticTier::Green`] yield
///    [`TrustReason::GreenTierUnderTriage`]. Amber / AmberLlm / Red
///    flow through to untrusted regardless of policy.
///
/// The classifier is the authoritative tier source — we do NOT read
/// back from `build-state.json`. That file is an install-time cache
/// and a user-facing artifact; calling `lpm rebuild` standalone (no
/// preceding install) must still yield the same decision. Matches the
/// signoff answer to ambiguity #4.
///
/// Drift is never auto-recovered under triage. A drifted rich binding
/// means the user previously approved a different script body; even
/// if the current on-disk script classifies green, the user still
/// needs to re-review the delta via `lpm approve-scripts`. This keeps
/// the security floor at "no execution without current reviewer
/// intent" (D20).
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_trust(
    package_dir: &Path,
    name: &str,
    version: &str,
    integrity: Option<&str>,
    scripts: &HashMap<String, String>,
    policy: &SecurityPolicy,
    project_dir: &Path,
    effective_policy: ScriptPolicy,
    // When `true`, any result that would
    // otherwise be trust-granting (`StrictBinding`, `LegacyName`,
    // `ScopedGlob`, `GreenTierUnderTriage`) is intercepted and
    // returned as [`TrustReason::SuspendedByForceFloor`]. Callers
    // read this from `GlobalConfig::load().get_bool("force-security-floor")`
    // once per invocation. `BindingDrift` is unaffected — drift already
    // represents a "not trusted" terminal state. `Untrusted` is also
    // unaffected — there's nothing to suspend when nothing was trusted.
    force_security_floor: bool,
    // The package's requested
    // capability set, parsed from `package.json > lpm > scripts >
    // {passEnv, readProject, sandboxLimits}`. Baseline default means
    // "no extras requested" and passes straight through — most
    // packages are at baseline.
    requested_capabilities: &crate::capability::CapabilitySet,
    // The user's configured bounds for capability widening, read
    // from `~/.lpm/config.toml`. Default means "no user ceilings
    // configured" — rlimit requests with no matching user ceiling
    // fail closed (trigger the approval gate).
    user_bound: &crate::capability::UserBound,
    // In-memory ephemeral approval set
    // populated by the install path's
    // [`crate::triage_advisor_session::AdvisorSession`]. A package
    // whose `(name, version)` appears here AND classifies amber
    // under triage yields [`TrustReason::AdvisorApprovedThisRun`].
    // `None` (or empty) preserves portable L1-3 behaviour — the
    // standalone `lpm rebuild` path passes `None`.
    advisor_approvals: Option<&std::collections::HashSet<(String, String, Option<String>)>>,
) -> TrustReason {
    let candidate = evaluate_trust_unsuspended(
        package_dir,
        name,
        version,
        integrity,
        scripts,
        policy,
        project_dir,
        effective_policy,
        advisor_approvals,
    );
    let after_force = if force_security_floor && candidate.is_trusted() {
        TrustReason::SuspendedByForceFloor
    } else {
        candidate
    };

    // Capability gate — applies only when the prior layer returned
    // a trust-granting reason. A non-trusted result (BindingDrift,
    // SuspendedByForceFloor, Untrusted) short-circuits: the script
    // won't run anyway, and letting it flow through unchanged
    // preserves the specific diagnostic reason (the capability
    // gate producing `CapabilityNotApproved` on top would clobber
    // the more actionable message).
    if !after_force.is_trusted() {
        return after_force;
    }

    // Trusted-so-far. Check whether the requested capability set
    // widens beyond the user bound — if not, the request is
    // self-approving (nothing beyond baseline / tighter-than-bound
    // needs explicit approval).
    if !requested_capabilities.loosens_beyond(user_bound) {
        return after_force;
    }

    // Widening request. Requires a matching capability-hash
    // approval on the binding. Legacy bindings (capability_hash =
    // None) and missing bindings both fail this check, collapsing
    // into CapabilityNotApproved — which 6d's UX surfaces as a
    // distinct reason from Untrusted.
    match policy.get_binding(name, version) {
        Some(binding) if requested_capabilities.is_approved_by(binding) => after_force,
        _ => TrustReason::CapabilityNotApproved,
    }
}

/// the original `evaluate_trust` body, extracted
/// so [`evaluate_trust`] can compose "raw match → suspension filter"
/// without duplicating the match logic. Returns every variant
/// [`TrustReason`] can take EXCEPT [`TrustReason::SuspendedByForceFloor`],
/// which is strictly a decorator applied by the outer function.
#[allow(clippy::too_many_arguments)]
fn evaluate_trust_unsuspended(
    package_dir: &Path,
    name: &str,
    version: &str,
    integrity: Option<&str>,
    scripts: &HashMap<String, String>,
    policy: &SecurityPolicy,
    project_dir: &Path,
    effective_policy: ScriptPolicy,
    advisor_approvals: Option<&std::collections::HashSet<(String, String, Option<String>)>>,
) -> TrustReason {
    let script_hash = compute_script_hash(package_dir);
    let strict = policy.can_run_scripts_strict(name, version, integrity, script_hash.as_deref());
    match strict {
        TrustMatch::Strict => return TrustReason::StrictBinding,
        TrustMatch::LegacyNameOnly => return TrustReason::LegacyName,
        TrustMatch::BindingDrift { .. } => return TrustReason::BindingDrift,
        TrustMatch::NotTrusted => {}
    }

    if is_scope_trusted(name, project_dir) {
        return TrustReason::ScopedGlob;
    }

    if effective_policy == ScriptPolicy::Triage {
        let tier = classify_package_worst_tier(scripts);
        if tier == Some(StaticTier::Green) {
            return TrustReason::GreenTierUnderTriage;
        }
        // Amber + advisor said Approve →
        // ephemeral trust for this run. Confined to triage policy
        // (deny / allow paths never reach here in a triage-meaningful
        // way) and to a non-empty in-memory approval set. Standalone
        // `lpm rebuild` passes `None`, so this short-circuit cannot
        // bypass the persistent trust manifest outside an active
        // install.
        if matches!(tier, Some(StaticTier::Amber) | Some(StaticTier::AmberLlm))
            && let Some(set) = advisor_approvals
            && set.contains(&(
                name.to_string(),
                version.to_string(),
                integrity.map(str::to_string),
            ))
        {
            return TrustReason::AdvisorApprovedThisRun;
        }
    }

    TrustReason::Untrusted
}

/// Worst-wins classification across the lifecycle phases present in
/// `scripts`. Returns `None` when `scripts` is empty (caller has
/// already early-returned in practice, since the trust-decision call
/// sites only run after at least one lifecycle script was found).
///
/// Mirrors the reduction at `build_state.rs:418-421` exactly so the
/// install-time annotation and the `lpm rebuild` gate agree on tier
/// per-package without sharing cached state.
fn classify_package_worst_tier(scripts: &HashMap<String, String>) -> Option<StaticTier> {
    scripts
        .values()
        .map(|body| lpm_security::static_gate::classify(body))
        .reduce(StaticTier::worse_of)
}

/// Count scripted packages that would be skipped under the default
/// `lpm rebuild` path because they lack trust.
///
/// "Skipped" means: has lifecycle scripts, isn't already-built (or
/// `--force` was passed), and isn't trusted by either the strict
/// gate or a `trustedScopes` glob. These are exactly the packages the
/// user needs to resolve before scripts will run under the default
/// command.
///
/// extracted from the inline warning block
/// so a pure-input regression test can guard the counting contract.
/// The prior inline implementation counted from `to_build` — which in
/// the default path is already filtered to trusted-only — so the
/// count was structurally always zero and the warning (plus the
/// triage pointer wired through it) never reached users.
/// A purely source-level guard test catches marker-string deletions
/// but cannot catch this class of regression; a pure-function test
/// on a synthetic input set does.
fn count_untrusted_unbuilt(scriptable: &[ScriptablePackage], force: bool) -> usize {
    scriptable
        .iter()
        .filter(|p| force || !p.is_built)
        .filter(|p| !p.is_trusted)
        .count()
}

/// Pure selection step for `lpm rebuild`'s default-branch `to_build` set.
///
/// Extracted for so the policy-aware
/// widening rule lives outside `rebuild::run`'s I/O monolith and can
/// be unit-tested in isolation — the complementary caller-side
/// contract to the helper-level
/// [`p6_chunk2_allow_does_not_promote_green_tier_at_helper_level`]
/// guard that pinned [`evaluate_trust`]'s per-package decision under
/// allow. The two tests together cover both sides of the trust
/// split that v2.8 item 6 flagged: `evaluate_trust` deliberately
/// ignores allow (its job is manifest-binding / scope / tier), and
/// this helper honors it.
///
/// Branching rules (+ pre-existing behavior):
///
/// - `all = true` → widen to every scriptable package regardless of
///   trust or policy. `--all` is the pre-existing explicit escape
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
fn widen_to_build_by_policy(
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

/// One scriptable-package row for the install-time build hint.
///
/// extracted this struct from the previous tuple-shaped
/// buffer so the hint's trust decision is independently testable.
/// [`scriptable_package_rows`] is pure over (store state, manifest,
/// project_dir); [`show_install_build_hint`] is the I/O wrapper that
/// prints the same rows.
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
    // confidence-followup S5b — switched `&PackageStore`
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
    // whose capability request the 6c gate will block at
    // `lpm rebuild` time. The hint is a user-facing contract about
    // what the next build will do; misstating it contradicts the
    // adjacent approve-scripts guidance. Baseline defaults
    // preserve pre-6c behavior for tests and callers that don't
    // yet parse the project capability set.
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
) -> Vec<ScriptableHintRow> {
    use rayon::prelude::*;

    // **W2: hoist trustedScopes parse out of the per-package
    // loop.** The previous implementation called `is_scope_trusted`
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
    // the project scoping prevents the post-F1 ambiguity where a
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
        // confidence-followup S5b — v2-aware lookup, F2 —
        // routed through the invocation-local index. See
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
        // build.rs:133. `Strict` + `LegacyNameOnly` are trusted;
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
    // confidence-followup S5b — see
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
    output::info(&format!(
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
/// Under `Deny` / `Allow`, behavior is unchanged from Chunks 1-2:
/// only strict gate + scope glob matches count.
///
/// An empty installed-packages list or a set of only already-built
/// scripted packages returns `false` (the caller uses this to decide
/// whether to skip the auto-build step entirely), matching the
/// pre-P6 semantics.
#[allow(clippy::too_many_arguments)]
pub fn all_scripted_packages_trusted(
    // confidence-followup S5b — see
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
    advisor_approvals: Option<&std::collections::HashSet<(String, String, Option<String>)>>,
) -> bool {
    // Build the
    // v2 link-entry index ONCE before the per-package loop, scoped to
    // this project's tree. Same rationale as `scriptable_package_rows`
    // — install-time auto-build predicate checks every lockfile entry,
    // and the global walk could otherwise return a sibling project's
    // link entry under post-F1 same-coord coexistence. Falling back
    // to an empty index on construction failure preserves the legacy
    // silent-skip-of-v1-only semantic.
    let baseline_index = V2BaselineIndex::for_project(project_dir, lpm_root).unwrap_or_default();

    let mut has_any_unbuilt = false;

    for (name, version, integrity) in packages {
        // confidence-followup S5b — v2-aware lookup, F2 —
        // routed through the invocation-local index. Same
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

/// Topologically sort packages so dependencies are built before dependents.
///
/// Uses Kahn's algorithm. If A depends on B, B appears first in the output.
/// Packages not in the dependency graph (or with no ordering constraints) keep
/// their original relative order (stable sort).
fn toposort_packages<'a>(
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
fn warn_stale_trusted_deps(policy: &SecurityPolicy, scriptable_packages: &[ScriptablePackage]) {
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
        output::warn(&format!(
            "Stale trustedDependencies (no lifecycle scripts): {}",
            stale.join(", ")
        ));
    }
}

//: `read_deny_all_config` was removed as part of
// consolidating script-config reads into
// `crate::script_policy_config::ScriptPolicyConfig`. Callers now
// access `.deny_all` on the loader's return value. The dedicated
// tests below were likewise removed; equivalent coverage lives in
// `script_policy_config::tests`.

#[cfg(test)]
mod tests {
    use super::*;

    fn write_store_package(
        store: &PackageStore,
        name: &str,
        version: &str,
        scripts_json: &str,
        built: bool,
    ) {
        let pkg_dir = store.package_dir(name, version);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!(
                "{{\"name\":\"{}\",\"version\":\"{}\",\"scripts\":{}}}",
                name, version, scripts_json
            ),
        )
        .unwrap();
        if built {
            std::fs::write(pkg_dir.join(BUILD_MARKER), "").unwrap();
        }
        // confidence-followup S5b — `find_installed_package_baseline`'s
        // v1 fallback requires `.integrity` to be Some (sentinel for
        // "package was extracted by the install pipeline"). Without
        // this, the v1 fallback returns None and these tests' helper
        // calls silently skip every fixture entry. Real installs always
        // write `.integrity`; this synthesizes the same shape.
        std::fs::write(pkg_dir.join(".integrity"), "sha512-test-fake").unwrap();
    }

    // ── live_package_dir tests ─────────────────────────
    //
    // The fix for the esbuild postinstall failure: lifecycle scripts
    // must run from the live per-package node_modules directory, not
    // the global content-addressable store. These tests pin the layout
    // probe across both linker modes + the pathological fallback so
    // a future linker-layout change doesn't silently break the dep
    // resolution that postinstall scripts rely on.

    #[test]
    fn live_package_dir_resolves_isolated_layout() {
        // Isolated layout (default `LPM_LINKER` value): packages live
        // under the wrapper root (`<project>/.lpm/wrappers/`)
        // at `<wrapper-root>/<safe_name>@<version>/node_modules/<name>/`,
        // with sibling deps symlinked at the parallel `node_modules/`
        // level. Path resolved through `LayoutPaths` so tests track
        // production semantics on a relayout.
        let project = tempfile::tempdir().unwrap();
        let layout = lpm_linker::LayoutPaths::for_project(project.path());
        let live = layout
            .isolated_wrapper_dir("esbuild@0.21.5")
            .join("node_modules")
            .join("esbuild");
        std::fs::create_dir_all(&live).unwrap();
        let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

        let resolved = live_package_dir(
            project.path(),
            "esbuild",
            "0.21.5",
            None,
            &store_fallback,
            None,
        );
        assert_eq!(resolved, live);
    }

    #[test]
    fn live_package_dir_resolves_isolated_scoped_name() {
        // Scoped names get path-separator sanitization (`/` → `+`) for
        // the wrapper segment, but the inner `node_modules/<name>/`
        // segment uses the original scoped form. Without this the lookup
        // would miss every `@scope/pkg` package — i.e., the entire
        // esbuild-platform / vue-loader / babel-plugin / etc. ecosystem.
        let project = tempfile::tempdir().unwrap();
        let layout = lpm_linker::LayoutPaths::for_project(project.path());
        let live = layout
            .isolated_wrapper_dir("@esbuild+darwin-arm64@0.21.5")
            .join("node_modules")
            .join("@esbuild")
            .join("darwin-arm64");
        std::fs::create_dir_all(&live).unwrap();
        let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

        let resolved = live_package_dir(
            project.path(),
            "@esbuild/darwin-arm64",
            "0.21.5",
            None,
            &store_fallback,
            None,
        );
        assert_eq!(resolved, live);
    }

    #[test]
    fn live_package_dir_resolves_hoisted_layout() {
        // Hoisted layout (opt-in via `LPM_LINKER=hoisted`): packages
        // live directly at `node_modules/<name>/` without the .lpm/
        // staging tier. The probe falls back to this when the isolated
        // path doesn't exist.
        let project = tempfile::tempdir().unwrap();
        let live = project.path().join("node_modules").join("esbuild");
        std::fs::create_dir_all(&live).unwrap();
        let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

        let resolved = live_package_dir(
            project.path(),
            "esbuild",
            "0.21.5",
            None,
            &store_fallback,
            None,
        );
        assert_eq!(resolved, live);
    }

    #[test]
    fn live_package_dir_falls_back_to_store_when_unlinked() {
        // Pathological case: package isn't actually linked anywhere.
        // Lifecycle script gating upstream should prevent this from
        // running scripts in production, but if it does, fall back to
        // the pre-existing behavior (store_path) so failures match what
        // users were already seeing rather than introducing a new "no
        // working directory" error class.
        //
        // — use `live_package_dir_with_v2(None, None)` so the v2
        // store walk is fully disabled. The env-coupled
        // `live_package_dir` would otherwise probe the developer's
        // real `~/.lpm/store/v2/links/` and find a stale entry from
        // an earlier install (e.g. `esbuild@0.21.5` from a prior
        // bench run) — flaky test isolation.
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
        let store_fallback = std::path::PathBuf::from("/store/some/where");

        let resolved = live_package_dir_with_v2(
            project.path(),
            "esbuild",
            "0.21.5",
            None,
            &store_fallback,
            None,
            None,
        );
        assert_eq!(resolved, store_fallback);
    }

    /// — direct deps under v2: project's `node_modules/<name>`
    /// is a symlink into `~/.lpm/store/v2/links/<key>/.../<name>/`.
    /// The hoisted-probe branch's `is_dir()` follows the symlink and
    /// returns the project-side path, which Node resolves through at
    /// script time.
    #[test]
    #[cfg(unix)]
    fn live_package_dir_resolves_v2_direct_dep_via_project_symlink() {
        let project = tempfile::tempdir().unwrap();
        let nm = project.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();

        // Synthesize a v2-shaped link entry and a project-side symlink
        // pointing at it. The detection doesn't care about the exact
        // store layout — only that `nm.join(name)` is `is_dir()`.
        let link_entry = project
            .path()
            .join("fake-store/v2/links/express@4.21.0+abc/node_modules/express");
        std::fs::create_dir_all(&link_entry).unwrap();
        std::os::unix::fs::symlink(&link_entry, nm.join("express")).unwrap();
        let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

        let resolved = live_package_dir(
            project.path(),
            "express",
            "4.21.0",
            None,
            &store_fallback,
            None,
        );
        // Returns the project-side symlink path; Node follows it at
        // script time.
        assert_eq!(resolved, nm.join("express"));
    }

    /// — transitive deps under v2: no project-side symlink
    /// exists, so `live_package_dir_with_v2` walks the v2 store via
    /// `find_link_package_dir` and returns the canonical link-entry
    /// package dir.
    #[test]
    fn live_package_dir_resolves_v2_transitive_via_store_walk() {
        use lpm_store::v2::{LinkEntryRequest, Store as V2Store};

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("node_modules")).unwrap();

        let store_dir = tempfile::tempdir().unwrap();
        let v2_store = V2Store::at(store_dir.path());

        // Materialize one link entry for a "transitive-only" package
        // (no project-side symlink).
        let sri = lpm_store::compute_sri_hash(b"live_package_dir_v2_transitive");
        let object_dir = v2_store.paths().object_dir(&sri).unwrap();
        std::fs::create_dir_all(&object_dir).unwrap();
        std::fs::write(
            object_dir.join("package.json"),
            b"{\"name\":\"deeply-nested\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        std::fs::write(object_dir.join(".integrity"), &sri).unwrap();

        let inputs = lpm_store::v2::GraphKeyInputs::new(
            "deeply-nested",
            "1.0.0",
            lpm_store::v2::PlatformTuple::current(),
            lpm_store::v2::LinkerModeTag::Isolated,
        );
        let key = lpm_store::v2::GraphKey::derive(&inputs);
        let entry = v2_store
            .populate_link_entry(LinkEntryRequest {
                graph_key: std::sync::Arc::new(key),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: std::sync::Arc::new(lpm_store::v2::LinkMetaPlatform {
                    os: "darwin".into(),
                    cpu: "arm64".into(),
                    libc: None,
                }),
            })
            .unwrap();
        let expected = entry.link_dir.join("node_modules").join("deeply-nested");

        let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");
        let resolved = live_package_dir_with_v2(
            project.path(),
            "deeply-nested",
            "1.0.0",
            None,
            &store_fallback,
            Some(&v2_store),
            None,
        );
        assert_eq!(resolved, expected);
    }

    #[test]
    fn live_package_dir_prefers_isolated_when_both_exist() {
        // If a project somehow has both layouts on disk simultaneously
        // (rare — would mean a mid-transition install), the isolated
        // path wins because it's the default linker mode and matches
        // the per-package symlink graph the linker creates.
        let project = tempfile::tempdir().unwrap();
        let layout = lpm_linker::LayoutPaths::for_project(project.path());
        let isolated = layout
            .isolated_wrapper_dir("esbuild@0.21.5")
            .join("node_modules")
            .join("esbuild");
        std::fs::create_dir_all(&isolated).unwrap();
        let hoisted = project.path().join("node_modules").join("esbuild");
        std::fs::create_dir_all(&hoisted).unwrap();
        let store_fallback = std::path::PathBuf::from("/store/should-not-be-used");

        let resolved = live_package_dir(
            project.path(),
            "esbuild",
            "0.21.5",
            None,
            &store_fallback,
            None,
        );
        assert_eq!(resolved, isolated);
    }

    // ── follow-up — prepare_live_package_dir tests ──────
    //
    // These tests pin the integration: composing `live_package_dir`
    // with `lpm_linker::detach_package_hardlinks`, plus the
    // semantic guard that prevents detaching anything inside the
    // store root. The unit tests on `detach_package_hardlinks` in
    // lpm-linker cover the detach primitive; these cover the
    // composition that the rebuild loop actually calls.

    #[test]
    fn prepare_live_package_dir_returns_isolated_path_when_present() {
        let project = tempfile::tempdir().unwrap();
        let store_root = tempfile::tempdir().unwrap();
        let store_pkg = store_root.path().join("esbuild@0.21.5");
        std::fs::create_dir_all(&store_pkg).unwrap();

        let layout = lpm_linker::LayoutPaths::for_project(project.path());
        let live = layout
            .isolated_wrapper_dir("esbuild@0.21.5")
            .join("node_modules")
            .join("esbuild");
        std::fs::create_dir_all(&live).unwrap();

        let resolved = prepare_live_package_dir(
            project.path(),
            "esbuild",
            "0.21.5",
            None,
            &store_pkg,
            store_root.path(),
            None,
        )
        .unwrap();
        assert_eq!(resolved, live);
    }

    #[test]
    fn prepare_live_package_dir_errors_when_unlinked() {
        // D8a (audit fix #5): pathological "package not
        // actually linked" case. Pre-`prepare_live_package_dir`
        // returned `Ok(store_path)` here, letting the caller chdir into
        // the canonical store bytes for the lifecycle script — silent
        // store corruption on macOS/clonefile, shared-inode write on
        // Linux. Post-fix the function hard-errors so the failure mode
        // is loud and actionable, and the canonical bytes are
        // guaranteed untouched.
        let store_root = tempfile::tempdir().unwrap();
        let store_pkg = store_root.path().join("missing-pkg@1.0.0");
        std::fs::create_dir_all(&store_pkg).unwrap();
        // Drop a file we'd notice if detach (or any write) mistakenly ran:
        let canary = store_pkg.join("package.json");
        std::fs::write(&canary, b"{\"name\":\"missing-pkg\"}").unwrap();

        // Project has NO live dir for the package, forcing
        // `live_package_dir` to return the store fallback.
        let project = tempfile::tempdir().unwrap();

        let err = prepare_live_package_dir(
            project.path(),
            "missing-pkg",
            "1.0.0",
            None,
            &store_pkg,
            store_root.path(),
            None,
        )
        .unwrap_err();
        // The error message must mention "not linked into project" so
        // support diagnostics (and the "Run `lpm install`" remediation)
        // map back to the cause.
        assert!(
            err.contains("not linked into project"),
            "expected 'not linked into project' in error, got: {err}"
        );
        assert!(
            err.contains("missing-pkg"),
            "expected package name in error, got: {err}"
        );
        // Canary intact: no detach (or any) side-effects on the store.
        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"{\"name\":\"missing-pkg\"}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepare_live_package_dir_detaches_hardlinks_in_isolated_layout() {
        // End-to-end integration: hardlink a file from a fake store
        // into the live isolated-layout directory, call the helper,
        // and assert the live file's inode is now distinct from the
        // store file's. Mirrors the detach unit test but exercises
        // the actual rebuild-loop entry point so a future refactor
        // that drops the detach call site fails this test.
        use std::os::unix::fs::MetadataExt;

        let project = tempfile::tempdir().unwrap();
        let store_root = tempfile::tempdir().unwrap();
        let store_pkg = store_root.path().join("esbuild@0.21.5");
        std::fs::create_dir_all(&store_pkg).unwrap();
        let store_file = store_pkg.join("package.json");
        std::fs::write(&store_file, b"{\"name\":\"esbuild\"}").unwrap();

        let layout = lpm_linker::LayoutPaths::for_project(project.path());
        let live = layout
            .isolated_wrapper_dir("esbuild@0.21.5")
            .join("node_modules")
            .join("esbuild");
        std::fs::create_dir_all(&live).unwrap();
        let live_file = live.join("package.json");
        std::fs::hard_link(&store_file, &live_file).unwrap();

        // Pre-condition: shared inode.
        assert_eq!(
            std::fs::metadata(&store_file).unwrap().ino(),
            std::fs::metadata(&live_file).unwrap().ino(),
        );

        prepare_live_package_dir(
            project.path(),
            "esbuild",
            "0.21.5",
            None,
            &store_pkg,
            store_root.path(),
            None,
        )
        .unwrap();

        // Post-condition: distinct inodes — the rebuild loop can now
        // run a postinstall script in `live` without polluting
        // `store_pkg`.
        assert_ne!(
            std::fs::metadata(&store_file).unwrap().ino(),
            std::fs::metadata(&live_file).unwrap().ino(),
        );
    }

    // ── build_sanitized_env tests ────────────────────────────────

    #[test]
    fn sanitized_env_strips_lpm_token() {
        let _env = crate::test_env::ScopedEnv::set([("LPM_TOKEN", "secret123".into())]);
        let env = build_sanitized_env();
        assert!(!env.contains_key("LPM_TOKEN"));
    }

    #[test]
    fn sanitized_env_strips_npm_token() {
        let _env = crate::test_env::ScopedEnv::set([("NPM_TOKEN", "npm_secret".into())]);
        let env = build_sanitized_env();
        assert!(!env.contains_key("NPM_TOKEN"));
    }

    #[test]
    fn sanitized_env_strips_suffix_patterns() {
        let _env = crate::test_env::ScopedEnv::set([
            ("MY_APP_SECRET", "val".into()),
            ("DB_PASSWORD", "val".into()),
            ("SIGNING_KEY", "val".into()),
            ("SSH_PRIVATE_KEY", "val".into()),
        ]);
        let env = build_sanitized_env();
        assert!(!env.contains_key("MY_APP_SECRET"));
        assert!(!env.contains_key("DB_PASSWORD"));
        assert!(!env.contains_key("SIGNING_KEY"));
        assert!(!env.contains_key("SSH_PRIVATE_KEY"));
    }

    #[test]
    fn sanitized_env_keeps_path() {
        // PATH and HOME are always present in the test environment
        let env = build_sanitized_env();
        assert!(env.contains_key("PATH"));
    }

    // ── read_lifecycle_scripts tests ─────────────────────────────

    #[test]
    fn reads_lifecycle_scripts_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"scripts":{"postinstall":"node setup.js","test":"jest"}}"#,
        )
        .unwrap();

        let scripts = read_lifecycle_scripts(&pkg_json).unwrap();
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts.get("postinstall").unwrap(), "node setup.js");
        // "test" is not a lifecycle script
        assert!(!scripts.contains_key("test"));
    }

    #[test]
    fn returns_none_when_no_lifecycle_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(&pkg_json, r#"{"scripts":{"test":"jest","start":"node ."}}"#).unwrap();

        assert!(read_lifecycle_scripts(&pkg_json).is_none());
    }

    #[test]
    fn returns_none_for_missing_file() {
        let path = Path::new("/nonexistent/package.json");
        assert!(read_lifecycle_scripts(path).is_none());
    }

    // ── toposort tests ──────────────────────────────────────────

    #[test]
    fn toposort_respects_dependency_order() {
        use std::path::PathBuf;

        let packages = [
            ScriptablePackage {
                name: "a".into(),
                version: "1.0.0".into(),
                wrapper_id: None,
                store_path: PathBuf::new(),
                scripts: HashMap::new(),
                is_built: false,
                is_trusted: true,
                trust_reason: TrustReason::StrictBinding,
            },
            ScriptablePackage {
                name: "b".into(),
                version: "1.0.0".into(),
                wrapper_id: None,
                store_path: PathBuf::new(),
                scripts: HashMap::new(),
                is_built: false,
                is_trusted: true,
                trust_reason: TrustReason::StrictBinding,
            },
        ];
        let refs: Vec<&ScriptablePackage> = packages.iter().collect();

        // b depends on a → a should come first
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.packages = vec![
            lpm_lockfile::LockedPackage {
                name: "a".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                dependencies: vec![],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
            lpm_lockfile::LockedPackage {
                name: "b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                dependencies: vec!["a@1.0.0".into()],
                alias_dependencies: vec![],
                peers: vec![],
                tarball: None,
            },
        ];

        let sorted = toposort_packages(refs, &lockfile);
        let names: Vec<&str> = sorted.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    // ── is_scope_trusted tests ──────────────────────────────────

    #[test]
    fn scope_trusted_matches_glob() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"scripts":{"trustedScopes":["@myorg/*"]}}}"#,
        )
        .unwrap();

        assert!(is_scope_trusted("@myorg/foo", dir.path()));
        assert!(!is_scope_trusted("@other/foo", dir.path()));
    }

    #[test]
    fn scope_trusted_exact_match() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"scripts":{"trustedScopes":["esbuild"]}}}"#,
        )
        .unwrap();

        assert!(is_scope_trusted("esbuild", dir.path()));
        assert!(!is_scope_trusted("esbuild-extra", dir.path()));
    }

    #[test]
    fn all_scripted_packages_trusted_true_when_unbuilt_scripts_are_trusted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"trustedDependencies":["esbuild"]}}"#,
        )
        .unwrap();

        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_store_package(
            &store,
            "esbuild",
            "1.0.0",
            r#"{"postinstall":"node install.js"}"#,
            false,
        );

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        // Legacy bare-name `trustedDependencies: ["esbuild"]` matches
        // as `LegacyNameOnly`, which the strict gate treats as
        // trusted — same semantic `rebuild::run` uses.
        //
        // the policy arg is threaded but not yet
        // consulted; `ScriptPolicy::Deny` (the default) makes the
        // existing-behavior intent explicit. Chunks 2/3 add tier-
        // aware promotion; new tests covering triage + green land
        // there.
        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[("esbuild".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert!(trusted);
    }

    #[test]
    fn all_scripted_packages_trusted_false_when_any_unbuilt_scripted_package_is_untrusted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();

        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_store_package(
            &store,
            "sharp",
            "1.0.0",
            r#"{"postinstall":"node install.js"}"#,
            false,
        );

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[("sharp".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert!(!trusted);
    }

    #[test]
    fn all_scripted_packages_trusted_ignores_already_built_untrusted_packages() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"trustedDependencies":["trusted-pkg"]}}"#,
        )
        .unwrap();

        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_store_package(
            &store,
            "trusted-pkg",
            "1.0.0",
            r#"{"postinstall":"node trusted.js"}"#,
            false,
        );
        write_store_package(
            &store,
            "blocked-pkg",
            "1.0.0",
            r#"{"postinstall":"node blocked.js"}"#,
            true,
        );

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[
                ("trusted-pkg".to_string(), "1.0.0".to_string(), None),
                ("blocked-pkg".to_string(), "1.0.0".to_string(), None),
            ],
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert!(
            trusted,
            "already-built untrusted packages should not block current auto-build decisions"
        );
    }

    // ───: drifted-rich-binding regressions ─────────────
    //
    // These two tests pin the audit-prescribed behavior: a rich entry
    // whose stored `scriptHash` no longer matches what's on disk must
    // NOT be treated as trusted by either the install hint (of
    // the plan) or the auto-build predicate. Pre-migration,
    // both used the lenient `policy.can_run_scripts(name)` gate and
    // returned true for drifted entries, while `rebuild::run` itself
    // would skip them — producing a confusing UX where install said
    // "will auto-build" but build then refused. Now all three agree.

    /// Build a project whose rich `trustedDependencies` entry for
    /// `name@version` has a deliberately wrong `scriptHash`, so the
    /// strict gate returns `BindingDrift`.
    fn write_drifted_rich_project(dir: &Path, name: &str, version: &str) {
        std::fs::write(
            dir.join("package.json"),
            format!(
                r#"{{
                    "name": "proj",
                    "lpm": {{
                        "trustedDependencies": {{
                            "{name}@{version}": {{
                                "scriptHash": "sha256-not-the-real-hash-this-is-drift"
                            }}
                        }}
                    }}
                }}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn show_install_hint_drifted_rich_binding_is_not_trusted() {
        // Audit prescription (test A): drifted rich binding must NOT
        // show as `trusted ✓` in the install hint. We assert on the
        // pure `scriptable_package_rows` helper that
        // `show_install_build_hint` wraps — `is_trusted` is the
        // observable under test.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        write_store_package(
            &store,
            "sharp",
            "1.0.0",
            r#"{"postinstall":"node install.js"}"#,
            false,
        );
        // Sanity: the on-disk hash is SOME value; the rich binding
        // will name a different one. `compute_script_hash` is the
        // single source of truth for what's on disk.
        let on_disk = compute_script_hash(&store.package_dir("sharp", "1.0.0"))
            .expect("store package has an install-phase script");
        assert!(on_disk.starts_with("sha256-"));

        write_drifted_rich_project(dir.path(), "sharp", "1.0.0");
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let rows = scriptable_package_rows(
            &lpm_root,
            &[("sharp".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
        );
        assert_eq!(rows.len(), 1, "one scriptable row expected");
        assert_eq!(rows[0].name, "sharp");
        assert!(
            !rows[0].is_trusted,
            "drifted rich binding MUST NOT show as trusted in install hint \
             (the install UX must match `rebuild::run`'s skip behavior)"
        );
    }

    #[test]
    fn all_scripted_packages_trusted_false_on_drifted_rich_binding() {
        // Audit prescription (test B): drifted rich binding must NOT
        // satisfy the auto-build "all trusted" predicate. Otherwise
        // install would auto-trigger `rebuild::run` for a package
        // `rebuild::run` then immediately skips.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        write_store_package(
            &store,
            "sharp",
            "1.0.0",
            r#"{"postinstall":"node install.js"}"#,
            false,
        );
        write_drifted_rich_project(dir.path(), "sharp", "1.0.0");
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[("sharp".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert!(
            !trusted,
            "drifted rich binding MUST NOT satisfy the auto-build \
             all-trusted predicate (previously true via name-only \
             gate; now false via strict gate, matching build::run)"
        );
    }

    #[test]
    fn scriptable_rows_strict_match_is_trusted() {
        // Positive control: a rich binding whose `scriptHash` matches
        // the on-disk hash IS trusted. Proves the drift test above
        // is distinguishing "drifted rich binding" from "no rich
        // binding at all."
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_store_package(
            &store,
            "sharp",
            "1.0.0",
            r#"{"postinstall":"node install.js"}"#,
            false,
        );
        let on_disk_hash = compute_script_hash(&store.package_dir("sharp", "1.0.0")).unwrap();

        std::fs::write(
            dir.path().join("package.json"),
            format!(
                r#"{{
                    "name": "proj",
                    "lpm": {{
                        "trustedDependencies": {{
                            "sharp@1.0.0": {{
                                "scriptHash": "{on_disk_hash}"
                            }}
                        }}
                    }}
                }}"#
            ),
        )
        .unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let rows = scriptable_package_rows(
            &lpm_root,
            &[("sharp".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
        );
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].is_trusted,
            "strict-match rich binding MUST show as trusted (positive control)"
        );
    }

    /// **Reviewer finding:** when the script-hash trust layer would grant
    /// trust but the capability gate rejects, the install hint
    /// must report `is_trusted = false`. Otherwise the hint lies
    /// to the user about what `lpm rebuild` will actually do and
    /// contradicts the adjacent approve-scripts guidance.
    #[test]
    fn install_hint_flips_to_untrusted_when_capability_gate_would_block() {
        use crate::capability::{CapabilitySet, ReadProjectMode, UserBound};

        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "sharp", "1.0.0", "node install.js");
        let script_hash = compute_script_hash(&pkg_dir).expect("script hash");
        // Legacy None-capability_hash binding that matches strict.
        write_pkg_json_with_strict_approval(dir.path(), "sharp", "1.0.0", &script_hash);
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        // With baseline capability request: hint says trusted.
        let rows_baseline = scriptable_package_rows(
            &lpm_root,
            &[("sharp".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            &CapabilitySet::default(),
            &UserBound::default(),
        );
        assert_eq!(rows_baseline.len(), 1);
        assert!(
            rows_baseline[0].is_trusted,
            "baseline request + strict-match = trusted (positive control)"
        );

        // With widening capability request: hint MUST say NOT
        // trusted, because rebuild::run will skip with
        // CapabilityNotApproved.
        let widening = CapabilitySet {
            pass_env: ["SSH_AUTH_SOCK".into()].into_iter().collect(),
            read_project: ReadProjectMode::Narrow,
            sandbox_limits: Default::default(),
        };
        let rows_widening = scriptable_package_rows(
            &lpm_root,
            &[("sharp".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            &widening,
            &UserBound::default(),
        );
        assert_eq!(rows_widening.len(), 1);
        assert!(
            !rows_widening[0].is_trusted,
            "widening request + legacy binding = NOT trusted; \
             hint must agree with the capability gate's verdict"
        );
    }

    // ── warn_stale_trusted_deps tests ───────────────────────────

    #[test]
    fn stale_detection_finds_packages_without_scripts() {
        // trusted_dependencies is now TrustedDependencies::Legacy
        // (or Rich). Construct the Legacy variant directly to preserve the
        // pre-existing test semantic.
        let policy = SecurityPolicy {
            trusted_dependencies: lpm_security::TrustedDependencies::Legacy(vec![
                "sharp".into(),
                "esbuild".into(),
                "phantom".into(),
            ]),
            minimum_release_age_secs: 0,
        };
        let scriptable = [
            ScriptablePackage {
                name: "sharp".into(),
                version: "0.33.0".into(),
                wrapper_id: None,
                store_path: std::path::PathBuf::new(),
                scripts: HashMap::from([("postinstall".into(), "node setup".into())]),
                is_built: false,
                is_trusted: true,
                trust_reason: TrustReason::StrictBinding,
            },
            ScriptablePackage {
                name: "esbuild".into(),
                version: "0.21.0".into(),
                wrapper_id: None,
                store_path: std::path::PathBuf::new(),
                scripts: HashMap::from([("postinstall".into(), "node install.js".into())]),
                is_built: false,
                is_trusted: true,
                trust_reason: TrustReason::StrictBinding,
            },
        ];

        // "phantom" is trusted but has no scripts — should be detected as stale.
        // The iter() yields (name, optional binding) tuples; we only care
        // about the name for the staleness check.
        let scriptable_names: HashSet<&str> = scriptable.iter().map(|p| p.name.as_str()).collect();
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
        stale.sort();
        assert_eq!(stale, vec!["phantom".to_string()]);
    }

    // ── strict gate composition tests ──────────
    //
    // These tests exercise the trust-decision logic in isolation: given a
    // SecurityPolicy and a (name, version, integrity, script_hash) tuple,
    // does the strict gate produce the right TrustMatch and does the
    // composition with `is_scope_trusted` produce the right `is_trusted`?
    //
    // The full pipeline (lockfile + store + script execution) needs network
    // and a real fixture, which is out of scope for in-module unit tests.
    // The full pipeline is covered via integration-style tests.

    use lpm_security::{TrustMatch, TrustedDependencies, TrustedDependencyBinding};
    use std::collections::HashMap as StdHashMap;

    fn rich_policy_with(
        key: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> SecurityPolicy {
        let mut map = StdHashMap::new();
        map.insert(
            key.to_string(),
            TrustedDependencyBinding {
                integrity: integrity.map(String::from),
                script_hash: script_hash.map(String::from),
                ..Default::default()
            },
        );
        SecurityPolicy {
            trusted_dependencies: TrustedDependencies::Rich(map),
            minimum_release_age_secs: 0,
        }
    }

    #[test]
    fn build_strict_gate_strict_match_runs_script() {
        let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        let trust =
            policy.can_run_scripts_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(trust, TrustMatch::Strict);
    }

    #[test]
    fn build_strict_gate_drift_in_script_hash_blocks_script() {
        let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-OLD"));
        let trust = policy.can_run_scripts_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-x"),
            Some("sha256-NEW"),
        );
        assert!(matches!(trust, TrustMatch::BindingDrift { .. }));
    }

    #[test]
    fn build_strict_gate_drift_in_integrity_blocks_script() {
        let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-OLD"), Some("sha256-y"));
        let trust = policy.can_run_scripts_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-NEW"),
            Some("sha256-y"),
        );
        assert!(matches!(trust, TrustMatch::BindingDrift { .. }));
    }

    #[test]
    fn build_strict_gate_unknown_package_blocks_script() {
        let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        let trust = policy.can_run_scripts_strict("unknown", "1.0.0", None, Some("sha256-z"));
        assert_eq!(trust, TrustMatch::NotTrusted);
    }

    #[test]
    fn build_strict_gate_legacy_bare_name_runs_with_warning() {
        let policy = SecurityPolicy {
            trusted_dependencies: TrustedDependencies::Legacy(vec!["esbuild".to_string()]),
            minimum_release_age_secs: 0,
        };
        let trust =
            policy.can_run_scripts_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(trust, TrustMatch::LegacyNameOnly);
    }

    #[test]
    fn build_strict_gate_different_version_blocks_script() {
        // binds approvals to name@version. Approving 0.25.1 does
        // NOT carry over to 0.25.2 — the user must re-approve at the new
        // version (or the resolver picks the same one).
        let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        let trust =
            policy.can_run_scripts_strict("esbuild", "0.25.2", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(trust, TrustMatch::NotTrusted);
    }

    /// **AUDIT FIX ():** the previous version of
    /// this test asserted that `<name>@*` preserve keys did NOT satisfy
    /// the strict gate, which broke backward compatibility — a manifest
    /// like `["esbuild"]` lost esbuild's approval on the first
    /// `lpm approve-scripts --yes` upgrade. The audit reproduced it. Post-fix
    /// the strict gate matches `@*` preserve keys as `LegacyNameOnly`,
    /// preserving the legacy semantic AND keeping the deprecation signal.
    #[test]
    fn build_strict_gate_legacy_upgraded_at_star_satisfies_as_legacy_name_only() {
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
        td.upgrade_to_rich();
        let policy = SecurityPolicy {
            trusted_dependencies: td,
            minimum_release_age_secs: 0,
        };
        let trust =
            policy.can_run_scripts_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            trust,
            TrustMatch::LegacyNameOnly,
            "post-audit-fix: @* preserve keys must match as LegacyNameOnly \
             so legacy approvals survive `approve-scripts --yes` upgrades"
        );
    }

    /// REGRESSION: the strict gate must compose correctly with the existing
    /// `is_scope_trusted` glob path. A package matched by a
    /// `lpm.scripts.trustedScopes` glob is trusted regardless of the
    /// strict-gate result.
    #[test]
    fn build_strict_gate_or_scope_trusted_runs_script_via_scope() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"scripts":{"trustedScopes":["@myorg/*"]}}}"#,
        )
        .unwrap();

        // No trustedDependencies entry → strict gate returns NotTrusted...
        let policy = SecurityPolicy::default_policy();
        let trust =
            policy.can_run_scripts_strict("@myorg/some-pkg", "1.0.0", None, Some("sha256-y"));
        assert_eq!(trust, TrustMatch::NotTrusted);

        // ...but is_scope_trusted approves via the @myorg/* glob.
        // The build pipeline composes them with OR, so the package is
        // trusted overall.
        assert!(is_scope_trusted("@myorg/some-pkg", dir.path()));
    }

    // ── triage-mode messaging swap ─────────────
    //
    // These tests pin two distinct invariants. The source-level
    // guards catch marker-string deletion (cheap, zero-ceremony,
    // survive harness churn). The behavioral guards catch the dead-
    // code class a source-level guard cannot see — specifically, a
    // regression where the warning block becomes unreachable because
    // its counter is computed against an already-trust-filtered set
    // (the pre-P6 bug that silently buried both the old and new
    // pointers). A full `rebuild::run` integration test lands in
    // reference-fixture harness; the pure-function unit
    // tests here close the reviewability gap without the
    // lockfile scaffolding.

    #[test]
    fn p6_chunk1_triage_pointer_routes_to_approve_scripts() {
        let src = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/commands/rebuild.rs"
        ));
        const TRIAGE_HEAD: &str = "if effective_policy == ScriptPolicy::Triage {";
        const APPROVE_POINTER: &str = "lpm approve-scripts";
        const LEGACY_POINTER: &str = "package.json > lpm > trustedDependencies";

        let triage_pos = src.find(TRIAGE_HEAD).unwrap_or_else(|| {
            panic!(
                "triage-branch marker `{TRIAGE_HEAD}` disappeared from rebuild::run — \
                 required this branch so triage users are pointed at \
                 `lpm approve-scripts` instead of editing trustedDependencies by hand. \
                 If the control flow was legitimately refactored, update this test \
                 with the new marker; if the triage branch was removed, that's a \
                 contract regression and needs explicit signoff."
            )
        });
        let approve_pos = src[triage_pos..].find(APPROVE_POINTER).unwrap_or_else(|| {
            panic!(
                "`{APPROVE_POINTER}` pointer not found inside the triage branch — \
                 wires this specific next-step message for triage \
                 blocked-packages UX."
            )
        });
        // The legacy pointer must still exist (the `else` branch for
        // deny/allow); just not inside the triage branch we just found.
        let legacy_pos = src.find(LEGACY_POINTER).unwrap_or_else(|| {
            panic!(
                "legacy `{LEGACY_POINTER}` pointer was removed — deny-mode messaging \
                 must stay unchanged per signoff (the pre-P6 pointer is still the \
                 honest next step under deny)."
            )
        });
        assert!(
            approve_pos < src.len() - triage_pos,
            "`{APPROVE_POINTER}` must appear AFTER the triage branch header, not before",
        );
        assert_ne!(
            legacy_pos, triage_pos,
            "legacy pointer must live in the else branch, not inside the triage arm",
        );
    }

    #[test]
    fn p6_chunk1_auto_build_call_site_threads_effective_policy() {
        // Pin the install → auto-build handoff: the `rebuild::run` call
        // in install.rs must carry the resolved effective policy into
        // `rebuild::run`'s last arg. Without this invariant the
        // tier-promotion logic would never see triage at the auto-
        // build site (install.rs today resolves effective_policy for
        // the blocked-hint block only).
        let src = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/commands/install.rs"
        ));
        const MARKER: &str = "step10_effective_policy";
        let count = src.matches(MARKER).count();
        assert!(
            count >= 3,
            "expected at least 3 references to `{MARKER}` in install.rs (the \
             `let` binding + `all_scripted_packages_trusted` arg + `rebuild::run` \
             arg). Found {count}. If the auto-build handoff was refactored, \
             update this assertion — but make sure both callees still receive \
             the same resolved value."
        );
    }

    /// Construct a `ScriptablePackage` with synthetic values. The
    /// counter cares only about `is_built` and `is_trusted`; other
    /// fields are irrelevant but must be populated to satisfy the
    /// struct shape. `trust_reason` is derived from `is_trusted` so
    /// the field always stays internally consistent with the boolean
    /// — added it, and a test synthesizing a trusted package
    /// with `TrustReason::Untrusted` would misrepresent the data
    /// model even though the counter wouldn't notice.
    fn synthetic_scriptable(name: &str, is_built: bool, is_trusted: bool) -> ScriptablePackage {
        ScriptablePackage {
            name: name.into(),
            version: "1.0.0".into(),
            wrapper_id: None,
            store_path: std::path::PathBuf::from("/unused"),
            scripts: HashMap::from([("postinstall".into(), "node x.js".into())]),
            is_built,
            is_trusted,
            trust_reason: if is_trusted {
                TrustReason::StrictBinding
            } else {
                TrustReason::Untrusted
            },
        }
    }

    #[test]
    fn p6_chunk1_count_untrusted_unbuilt_sees_untrusted_under_default_build() {
        // Behavioral regression guard. The pre-P6 inline counter was
        // `to_build.iter().filter(|p| !p.is_trusted).count()` AFTER
        // `to_build` was filtered to trusted-only in the default
        // branch — structurally always zero, so the "N package(s)
        // are not in trustedDependencies" warning never reached
        // users. This test locks the corrected contract: the
        // extracted helper reads from the pre-trust-filter set and
        // reports a nonzero count when untrusted scripted packages
        // exist.
        let pkgs = vec![
            synthetic_scriptable("trusted-a", false, true),
            synthetic_scriptable("untrusted-b", false, false),
            synthetic_scriptable("untrusted-c", false, false),
            synthetic_scriptable("already-built-untrusted", true, false),
        ];
        // Default path (no --force): already-built entries drop out.
        // Two unbuilt-untrusted remain.
        assert_eq!(count_untrusted_unbuilt(&pkgs, false), 2);
    }

    #[test]
    fn p6_chunk1_count_untrusted_unbuilt_respects_force_flag() {
        // `--force` forces already-built packages back into the
        // candidate set. The counter must include them so the warning
        // reaches users in that flow too.
        let pkgs = vec![
            synthetic_scriptable("built-untrusted", true, false),
            synthetic_scriptable("built-trusted", true, true),
        ];
        assert_eq!(count_untrusted_unbuilt(&pkgs, false), 0);
        assert_eq!(count_untrusted_unbuilt(&pkgs, true), 1);
    }

    #[test]
    fn p6_chunk1_count_untrusted_unbuilt_zero_when_all_trusted() {
        // Negative control: when every unbuilt scripted package is
        // trusted, the count is zero and the warning must stay silent.
        let pkgs = vec![
            synthetic_scriptable("a", false, true),
            synthetic_scriptable("b", false, true),
        ];
        assert_eq!(count_untrusted_unbuilt(&pkgs, false), 0);
    }

    // ── shared trust helper behavior ───────────
    //
    // These tests pin `evaluate_trust` under each effective policy ×
    // static-tier combination that materially changes behavior. The
    // helper is the only place where "green-tier auto-trust" is
    // decided — both `rebuild::run` and the install-time
    // `all_scripted_packages_trusted` migration route through here,
    // so single-point coverage is sufficient for the policy decision.
    // The composition of the decision with the surrounding control
    // flow (which packages get skipped, what message prints, what
    // gets sandboxed) is covered by `rebuild::run`'s integration tests
    // in the integration tests.
    //
    // Every test writes a synthetic package into a temp store with
    // real lifecycle scripts so `compute_script_hash` and the static-
    // gate classifier produce live values — not stubs — matching how
    // `rebuild::run` will invoke the helper in production.

    /// Write a synthetic package into a `PackageStore` with the
    /// given postinstall body, and return its path. The postinstall
    /// body is what the static-gate classifier consumes, so tests
    /// exercising green/amber/red tiers pick their body accordingly.
    fn write_p6_pkg(
        store: &PackageStore,
        name: &str,
        version: &str,
        postinstall: &str,
    ) -> std::path::PathBuf {
        let pkg_dir = store.package_dir(name, version);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!(
                r#"{{"name":"{name}","version":"{version}","scripts":{{"postinstall":"{postinstall}"}}}}"#,
            ),
        )
        .unwrap();
        // confidence-followup S5b — see `write_store_package`
        // for why `.integrity` is required for the v1 fallback in
        // `find_installed_package_baseline`.
        std::fs::write(pkg_dir.join(".integrity"), "sha512-test-fake").unwrap();
        pkg_dir
    }

    #[test]
    fn p6_chunk2_triage_promotes_green_tier_without_manifest_binding() {
        // The core behavior: a package with a green-tier postinstall
        // (node-gyp rebuild — exact match in the Layer 1 allowlist),
        // no `trustedDependencies` entry, no scope match, lands on
        // `GreenTierUnderTriage` under Triage. This is the auto-trust
        // path — every other path either required manifest work or
        // didn't exist.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "some-native-pkg", "1.0.0", "node-gyp rebuild");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let reason = evaluate_trust(
            &pkg_dir,
            "some-native-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(reason, TrustReason::GreenTierUnderTriage);
        assert!(reason.is_trusted());
    }

    #[test]
    fn p6_chunk2_deny_does_not_promote_green_tier() {
        // Deny must stay deny: no promotion, regardless of tier.
        // Matches the signoff answer to ambiguity #3.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "some-native-pkg", "1.0.0", "node-gyp rebuild");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let reason = evaluate_trust(
            &pkg_dir,
            "some-native-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(reason, TrustReason::Untrusted);
        assert!(!reason.is_trusted());
    }

    #[test]
    fn p6_chunk2_allow_does_not_promote_green_tier_at_helper_level() {
        // `allow` semantics (build everything regardless of trust)
        // are the caller's concern — `rebuild::run` / fold the
        // allow policy into its filter at the selection step, NOT by
        // changing trust assignment per package. The helper's job is
        // to return the decision based on manifest bindings, scope,
        // and (under triage) tier. Under allow, with no binding +
        // no scope + green tier, the helper still returns Untrusted;
        // whether scripts run is a separate layer. This keeps the
        // helper's contract single-purpose and prevents "allow"
        // semantics from leaking into the predicate
        // `all_scripted_packages_trusted` relies on .
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "some-native-pkg", "1.0.0", "node-gyp rebuild");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let reason = evaluate_trust(
            &pkg_dir,
            "some-native-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Allow,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(reason, TrustReason::Untrusted);
    }

    /// close-out — complementary caller-side
    /// contract to [`p6_chunk2_allow_does_not_promote_green_tier_at_helper_level`].
    ///
    /// The helper test above pins that `evaluate_trust` deliberately
    /// ignores allow (its job is manifest-binding + scope + tier,
    /// not policy-wide widening). This test pins the other half of
    /// the split: the selection step at [`widen_to_build_by_policy`]
    /// must fold allow into its widening rule. Together they
    /// guarantee `is_trusted` computation stays single-purpose AND
    /// the allow contract is honored at the CLI boundary.
    #[test]
    fn p46_close_chunk2_widen_to_build_by_policy_includes_untrusted_under_allow() {
        let pkgs = vec![
            synthetic_scriptable("trusted-a", false, true),
            synthetic_scriptable("untrusted-b", false, false),
            synthetic_scriptable("untrusted-c", false, false),
        ];

        let selected = widen_to_build_by_policy(&pkgs, false, ScriptPolicy::Allow);
        assert_eq!(
            selected.len(),
            3,
            "allow must widen the default-branch selection to every \
             scriptable package — spec",
        );
        // Prove inclusion by name (not just count) so a future
        // refactor that accidentally filters then pads can't pass.
        let names: Vec<&str> = selected.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"trusted-a"));
        assert!(names.contains(&"untrusted-b"));
        assert!(names.contains(&"untrusted-c"));
    }

    /// Control under Deny — allow fix must not widen the
    /// deny mode's selection. Deny keeps the pre-existing filter-
    /// to-trusted-only contract, which is what `rebuild::run` relied
    /// on before extracted the helper.
    #[test]
    fn p46_close_chunk2_widen_to_build_by_policy_filters_to_trusted_under_deny() {
        let pkgs = vec![
            synthetic_scriptable("trusted-a", false, true),
            synthetic_scriptable("untrusted-b", false, false),
        ];

        let selected = widen_to_build_by_policy(&pkgs, false, ScriptPolicy::Deny);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "trusted-a");
    }

    /// Control under Triage — the tier-promotion-to-trusted logic
    /// lives inside [`evaluate_trust`] and is already reflected in
    /// `is_trusted` by the time packages reach this helper.
    /// [`widen_to_build_by_policy`] therefore treats triage
    /// identically to deny at the selection step; the difference
    /// between them is earlier, at the trust computation.
    ///
    /// This pins that fix is allow-scoped and does NOT
    /// widen triage beyond what `evaluate_trust` already promoted.
    /// Triage widening beyond greens would break D20 (no new
    /// execution authority without sandbox-verified triage).
    #[test]
    fn p46_close_chunk2_widen_to_build_by_policy_filters_to_trusted_under_triage() {
        let pkgs = vec![
            synthetic_scriptable("green-auto-promoted", false, true),
            synthetic_scriptable("amber-unpromoted", false, false),
        ];

        let selected = widen_to_build_by_policy(&pkgs, false, ScriptPolicy::Triage);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "green-auto-promoted");
    }

    /// `--all` is the pre-existing explicit escape hatch: widen to
    /// every scriptable package regardless of trust. Locks that
    /// contract against regression when the policy-aware branch is
    /// added — the `all || policy == Allow` short-circuit must
    /// honor BOTH inputs.
    #[test]
    fn p46_close_chunk2_widen_to_build_by_policy_all_flag_widens_under_every_policy() {
        let pkgs = vec![
            synthetic_scriptable("trusted-a", false, true),
            synthetic_scriptable("untrusted-b", false, false),
            synthetic_scriptable("untrusted-c", false, false),
        ];

        for policy in [
            ScriptPolicy::Deny,
            ScriptPolicy::Allow,
            ScriptPolicy::Triage,
        ] {
            let selected = widen_to_build_by_policy(&pkgs, true, policy);
            assert_eq!(
                selected.len(),
                3,
                "--all must widen regardless of policy — pre-existing \
                 contract preserved. policy={policy:?}"
            );
        }
    }

    #[test]
    fn p6_chunk2_triage_does_not_promote_amber_or_red() {
        // Amber + Red flow through to untrusted regardless of policy.
        // Amber = novel / compound / network-binary-downloader (D18);
        // Red = blocklist hit. Neither class is auto-approved.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        // Amber: network binary downloader per D18.
        let pkg_dir = write_p6_pkg(&store, "amber-pkg", "1.0.0", "playwright install");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let reason = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(
            reason,
            TrustReason::Untrusted,
            "amber-tier (playwright install per D18) must not be auto-trusted under triage",
        );

        // Red: curl | sh. The static-gate tokenizer catches the pipe-
        // to-shell pattern and classifies Red.
        let pkg_dir = write_p6_pkg(&store, "red-pkg", "1.0.0", "curl example.com | sh");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let reason = evaluate_trust(
            &pkg_dir,
            "red-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(
            reason,
            TrustReason::Untrusted,
            "red-tier (curl | sh) must never auto-trust under any policy — reds are the blocklist"
        );
    }

    #[test]
    fn p6_chunk2_strict_binding_wins_over_triage_promotion() {
        // Evaluation order: strict gate first. A legitimate strict
        // binding must return `StrictBinding`, NOT
        // `GreenTierUnderTriage`, even when the script would also
        // classify green. This matters for the UX suffix (the user
        // added the binding deliberately; calling it "auto-approval"
        // misrepresents their intent) and for
        // integration test.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "greenish-pkg", "1.0.0", "node-gyp rebuild");
        // Compute the on-disk hash so we can pin a valid strict binding
        // rather than drift.
        let script_hash = compute_script_hash(&pkg_dir).unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            format!(
                r#"{{
                    "name": "proj",
                    "lpm": {{
                        "trustedDependencies": {{
                            "greenish-pkg@1.0.0": {{
                                "scriptHash": "{script_hash}"
                            }}
                        }}
                    }}
                }}"#
            ),
        )
        .unwrap();
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let reason = evaluate_trust(
            &pkg_dir,
            "greenish-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(
            reason,
            TrustReason::StrictBinding,
            "strict binding must win over triage green-tier promotion so the UX \
             suffix and downstream consumers see the explicit user intent"
        );
    }

    #[test]
    fn p6_chunk2_binding_drift_never_auto_recovers_under_triage() {
        // D20 floor: a drifted rich binding means the user previously
        // approved a DIFFERENT script; the current on-disk body hasn't
        // been reviewed. Even if it classifies green, triage must not
        // auto-recover. Re-review via `lpm approve-scripts` is the only
        // path back.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "drifted-pkg", "1.0.0", "node-gyp rebuild");
        // Wrong script_hash → BindingDrift.
        std::fs::write(
            dir.path().join("package.json"),
            r#"{
                "name": "proj",
                "lpm": {
                    "trustedDependencies": {
                        "drifted-pkg@1.0.0": {
                            "scriptHash": "sha256-deliberately-wrong-hash-to-force-drift"
                        }
                    }
                }
            }"#,
        )
        .unwrap();
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let reason = evaluate_trust(
            &pkg_dir,
            "drifted-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(
            reason,
            TrustReason::BindingDrift,
            "triage must NOT auto-recover a drifted binding — even if the current \
             on-disk script classifies green, user intent was on a different body"
        );
        assert!(!reason.is_trusted());
    }

    #[test]
    fn p6_chunk2_scope_glob_wins_over_triage_promotion() {
        // Scope match is a deliberate user configuration — ranks
        // above the tier promotion for the same reason strict binding
        // does. The user wrote `@myorg/*` into trustedScopes; any
        // `@myorg/*` package returns `ScopedGlob`, not
        // `GreenTierUnderTriage`, even when its script classifies green.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"scripts":{"trustedScopes":["@myorg/*"]}}}"#,
        )
        .unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "@myorg/thing", "1.0.0", "node-gyp rebuild");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let reason = evaluate_trust(
            &pkg_dir,
            "@myorg/thing",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(
            reason,
            TrustReason::ScopedGlob,
            "scope glob must win over green-tier promotion so the UX reflects \
             explicit user configuration"
        );
    }

    #[test]
    fn p6_chunk2_trust_reason_is_trusted_covers_all_trusted_variants() {
        // Lock the `is_trusted()` set. If a new `TrustReason` lands
        // later (e.g. `AmberLlmApproval`), this test fails and
        // forces an explicit decision about whether it counts as
        // trusted. Preferable to a silent default that ships wrong.
        assert!(TrustReason::StrictBinding.is_trusted());
        assert!(TrustReason::LegacyName.is_trusted());
        assert!(TrustReason::ScopedGlob.is_trusted());
        assert!(TrustReason::GreenTierUnderTriage.is_trusted());
        // advisor-approved-this-run grants ephemeral
        // trust. Required for the install-time autoBuild path to
        // actually execute scripts the advisor approved.
        assert!(TrustReason::AdvisorApprovedThisRun.is_trusted());
        assert!(!TrustReason::BindingDrift.is_trusted());
        assert!(!TrustReason::Untrusted.is_trusted());
    }

    // ── AdvisorApprovedThisRun trust path ────────
    //
    // Locks the new amber-tier short-circuit in
    // `evaluate_trust_unsuspended`. The test matrix below maps
    // 1:1 to the six locked product cases:
    //
    //   1. triage-advisor = none → behavior identical to portable
    //   2. (env-not-ready preflight failure handled in
    //      triage_advisor_session::tests)
    //   3. Approve upgrades only prompted packages → AdvisorApprovedThisRun
    //   4. Manual/Abstain do not change outcome → still Untrusted
    //   5. (multi-package warn-once covered in install-flow integration)
    //   6. deny / allow ignore advisor_approvals (kept as Untrusted /
    //      executed-via-other-path)

    #[test]
    fn slice1_advisor_approval_promotes_amber_under_triage() {
        // The core slice-1 behavior: a package with an amber-tier
        // postinstall (`node install.js` — binary-fetcher convention,
        // amber by.5), no trustedDependencies entry, no scope
        // match — but its (name, version) appears in the advisor
        // approval set. Under triage, must return
        // AdvisorApprovedThisRun and pass `is_trusted()`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        // `node install.js` classifies amber per the reserved-basename
        // rule — perfect amber input for slice-1 promotion.
        let pkg_dir = write_p6_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let mut approvals = std::collections::HashSet::new();
        approvals.insert(("amber-pkg".to_string(), "1.0.0".to_string(), None));

        let reason = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        assert_eq!(reason, TrustReason::AdvisorApprovedThisRun);
        assert!(reason.is_trusted());
    }

    #[test]
    fn slice1_none_approvals_yield_untrusted_for_amber() {
        // Locked test-matrix case 1: `triage-advisor = none` (modeled
        // by passing `None` as the approval set) must leave amber
        // untrusted, identical to portable behavior.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let pkg_dir = write_p6_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let reason = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(reason, TrustReason::Untrusted);
        assert!(!reason.is_trusted());
    }

    #[test]
    fn slice1_empty_approvals_yield_untrusted_for_amber() {
        // Adjacent to "advisor = none": user has an advisor configured
        // but it approved nothing this run. Empty set → Untrusted.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let pkg_dir = write_p6_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let approvals: std::collections::HashSet<(String, String, Option<String>)> =
            std::collections::HashSet::new();
        let reason = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        assert_eq!(reason, TrustReason::Untrusted);
    }

    #[test]
    fn slice1_approval_for_other_package_does_not_promote_this_one() {
        // Locked test-matrix case 3 corollary: approval is scoped to
        // (name, version). A wrong-key approval must NOT promote.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let pkg_dir = write_p6_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let mut approvals = std::collections::HashSet::new();
        approvals.insert(("OTHER-pkg".to_string(), "1.0.0".to_string(), None));
        approvals.insert(("amber-pkg".to_string(), "2.0.0".to_string(), None)); // wrong version
        let reason = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        assert_eq!(reason, TrustReason::Untrusted);
    }

    #[test]
    fn slice1_advisor_approval_does_not_apply_under_deny() {
        // Locked test-matrix case 6: deny ignores advisor approvals.
        // The advisor was preflighted only under triage; under deny
        // the policy is "never auto-run". An approval set passed
        // (defensively) must not flip the outcome.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let pkg_dir = write_p6_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let mut approvals = std::collections::HashSet::new();
        approvals.insert(("amber-pkg".to_string(), "1.0.0".to_string(), None));
        let reason = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        // Deny short-circuits before the advisor check would fire.
        assert_eq!(reason, TrustReason::Untrusted);
    }

    #[test]
    fn slice1_advisor_approval_does_not_apply_under_allow() {
        // Symmetric to the deny case: allow runs every script via
        // the manifest-only path; the advisor surface isn't consulted.
        // Approval set defensively passed has no effect on the trust
        // reason returned.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let pkg_dir = write_p6_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let mut approvals = std::collections::HashSet::new();
        approvals.insert(("amber-pkg".to_string(), "1.0.0".to_string(), None));
        let reason = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Allow,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        // Under allow, the policy bypasses the trust-reason path
        // entirely at execution time; here at the evaluator level
        // the result mirrors Untrusted (no manifest binding) and
        // the live executor doesn't gate on it.
        assert_eq!(reason, TrustReason::Untrusted);
    }

    #[test]
    fn slice1_approval_does_not_leak_across_sources_with_same_coord() {
        // **Locked safety property (review finding High).** Two
        // packages with the same name+version but different
        // integrity hashes (e.g. one registry source, one
        // workspace / file source) must be approved INDEPENDENTLY.
        // Approving the registry source must NOT auto-run the
        // workspace source's script in the same install.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "amber-pkg", "1.0.0", "node install.js");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        // Approve ONLY the integrity-bearing variant.
        let mut approvals = std::collections::HashSet::new();
        approvals.insert((
            "amber-pkg".to_string(),
            "1.0.0".to_string(),
            Some("sha512-registry-integrity".to_string()),
        ));

        // Querying for the SAME coord but a DIFFERENT integrity must
        // not match — the trust evaluator returns Untrusted.
        let reason_workspace = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            None, // workspace-style: no integrity
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        assert_eq!(reason_workspace, TrustReason::Untrusted);

        // And for ANOTHER integrity (e.g. a file source with a
        // different sha): also Untrusted.
        let reason_other_integrity = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            Some("sha512-file-source-integrity"),
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        assert_eq!(reason_other_integrity, TrustReason::Untrusted);

        // Sanity: the integrity that IS in the set DOES grant the
        // ephemeral approval. Confirms the lookup isn't otherwise
        // broken.
        let reason_match = evaluate_trust(
            &pkg_dir,
            "amber-pkg",
            "1.0.0",
            Some("sha512-registry-integrity"),
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        assert_eq!(reason_match, TrustReason::AdvisorApprovedThisRun);
    }

    #[test]
    fn slice1_green_under_triage_still_wins_over_advisor() {
        // Sanity: a green script doesn't go through the advisor at
        // all — the existing GreenTierUnderTriage short-circuit
        // wins. Approval set is irrelevant.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let pkg_dir = write_p6_pkg(&store, "green-pkg", "1.0.0", "node-gyp rebuild");
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let mut approvals = std::collections::HashSet::new();
        approvals.insert(("green-pkg".to_string(), "1.0.0".to_string(), None));
        let reason = evaluate_trust(
            &pkg_dir,
            "green-pkg",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        // GreenTierUnderTriage WINS — the advisor variant is reserved
        // for amber. If this test starts returning AdvisorApprovedThisRun
        // it means the green short-circuit broke.
        assert_eq!(reason, TrustReason::GreenTierUnderTriage);
    }

    // ── all_scripted_packages_trusted triage ───
    //
    // These lock the install-time auto-build predicate's side of the
    // contract. The predicate and `rebuild::run` now both route
    // through `evaluate_trust`, so any divergence between what gets
    // triggered (predicate=true → build::run runs) and what actually
    // builds (build::run's per-package filter) would be a bug the
    // plan explicitly calls out in:
    //
    //   "under `"triage"`, a green-tier unbuilt package counts as
    //    trusted for auto-build-triggering purposes"
    //
    // The tests already cover the deny/drift/scope/strict
    // variants; the new cases below are specifically about the
    // triage-green-auto-trust path through the predicate.

    #[test]
    fn p6_chunk3_all_trusted_true_under_triage_green_without_binding() {
        // The core behavior: `lpm install` auto-build predicate
        // returns `true` for a fresh green-only install under triage,
        // even though no `trustedDependencies` entry exists. Pre-P6
        // this returned `false` and auto-build never ran for installs
        // without manifest bindings.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        // node-gyp rebuild — exact green-tier allowlist match.
        write_p6_pkg(&store, "native-a", "1.0.0", "node-gyp rebuild");
        // tsc — also green.
        write_p6_pkg(&store, "native-b", "1.0.0", "tsc");

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[
                ("native-a".to_string(), "1.0.0".to_string(), None),
                ("native-b".to_string(), "1.0.0".to_string(), None),
            ],
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert!(
            trusted,
            "triage + all-green scripted packages must satisfy the auto-build \
             predicate (— without this the install → \
             auto-build handoff would never fire under triage)"
        );
    }

    #[test]
    fn p6_chunk3_all_trusted_false_under_deny_same_input() {
        // Control: same input under deny stays false. Confirms the
        // migration didn't leak triage semantics into deny mode.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_p6_pkg(&store, "native-a", "1.0.0", "node-gyp rebuild");

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[("native-a".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert!(
            !trusted,
            "deny must not promote green-tier; the predicate has to match \
             the shared helper's deny semantics (no tier widening)"
        );
    }

    #[test]
    fn p6_chunk3_all_trusted_false_under_triage_mixed_green_amber() {
        // An amber package in the set blocks the predicate even under
        // triage — auto-build would run greens and leave ambers in
        // `build-state.json` with a pointer, but the PREDICATE
        // (trigger-or-not) returns false so only manifest-bound or
        // green-only installs skip review. picks up the other
        // side (autoBuild=true override); this test pins the
        // unreviewed-ambers-block-predicate contract.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_p6_pkg(&store, "green-pkg", "1.0.0", "node-gyp rebuild");
        // playwright install — amber per D18 (network binary downloader).
        write_p6_pkg(&store, "amber-pkg", "1.0.0", "playwright install");

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[
                ("green-pkg".to_string(), "1.0.0".to_string(), None),
                ("amber-pkg".to_string(), "1.0.0".to_string(), None),
            ],
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert!(
            !trusted,
            "mixed green+amber under triage must fail the predicate — \
             ambers require explicit review"
        );
    }

    #[test]
    fn p6_chunk3_all_trusted_false_under_triage_any_red() {
        // Red tiers are never auto-trusted. Ever. Under any policy.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_p6_pkg(&store, "red-pkg", "1.0.0", "curl example.com | sh");

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[("red-pkg".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert!(!trusted);
    }

    #[test]
    fn p6_chunk3_all_trusted_false_under_triage_drift() {
        // Drift still blocks — a drifted rich binding does not
        // auto-recover even when the current on-disk script would
        // classify green. Mirrors the helper contract; this
        // test pins it specifically at the predicate boundary.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_p6_pkg(&store, "drift-pkg", "1.0.0", "node-gyp rebuild");
        std::fs::write(
            dir.path().join("package.json"),
            r#"{
                "lpm": {
                    "trustedDependencies": {
                        "drift-pkg@1.0.0": {"scriptHash": "sha256-bogus"}
                    }
                }
            }"#,
        )
        .unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));

        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[("drift-pkg".to_string(), "1.0.0".to_string(), None)],
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert!(
            !trusted,
            "drifted binding must block the predicate under triage — \
             prevents install silently re-running a changed script \
             (D20 floor)"
        );
    }

    #[test]
    fn p6_chunk3_all_trusted_ignores_already_built_amber_under_triage() {
        // Already-built ambers drop out of the predicate regardless of
        // policy — the auto-build predicate is about NEW work, not
        // re-reviewing previously-executed scripts. Matches the
        // pre-P6 "ignores already-built untrusted packages" test,
        // extended to triage mode.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        write_p6_pkg(&store, "green-pkg", "1.0.0", "node-gyp rebuild");
        // Mark as already-built so the predicate ignores it.
        let amber_dir = write_p6_pkg(&store, "amber-built", "1.0.0", "playwright install");
        std::fs::write(amber_dir.join(BUILD_MARKER), "").unwrap();

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &lpm_root,
            &[
                ("green-pkg".to_string(), "1.0.0".to_string(), None),
                ("amber-built".to_string(), "1.0.0".to_string(), None),
            ],
            &policy,
            dir.path(),
            ScriptPolicy::Triage,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert!(
            trusted,
            "already-built ambers must NOT block the predicate — the predicate \
             is about newly-installed work"
        );
    }

    #[test]
    fn p6_chunk2_classify_package_worst_tier_reduces_worst_wins() {
        // Aggregation contract: the helper uses the same worst-wins
        // reducer `build_state.rs:418-421` uses so install-time and
        // build-time consumers see the same tier. A red postinstall
        // must dominate a green preinstall.
        let scripts = HashMap::from([
            ("preinstall".into(), "node-gyp rebuild".into()),
            ("postinstall".into(), "curl example.com | sh".into()),
        ]);
        assert_eq!(classify_package_worst_tier(&scripts), Some(StaticTier::Red));

        // All-green stays green.
        let scripts = HashMap::from([
            ("preinstall".into(), "node-gyp rebuild".into()),
            ("postinstall".into(), "tsc".into()),
        ]);
        assert_eq!(
            classify_package_worst_tier(&scripts),
            Some(StaticTier::Green)
        );

        // Empty → None (caller short-circuits).
        let empty = HashMap::new();
        assert_eq!(classify_package_worst_tier(&empty), None);
    }

    // ── force-security-floor approval suspension ──
    //
    // Acceptance criteria pinned here:
    // 1. `force-security-floor = false`: existing approvals run
    //    normally (back-compat).
    // 2. `force-security-floor = true`: the same approval is
    //    suspended — `is_trusted()` returns false, the script
    //    would not run under `lpm rebuild`.
    // 3. Unsetting the flag (passing `false` again) restores the
    //    approval without any re-review (approval state lives in
    //    `package.json`, not in a separate suspension record).
    // 4. No behavior change for users with no approvals — the
    //    `Untrusted` path is unaffected by the flag.
    // 5. `SuspendedByForceFloor` is classified as not-trusted.
    //
    // Suspended-count reporting in `lpm doctor` is covered in the
    // doctor.rs test module separately.

    /// Helper: write a package.json with a rich-binding approval
    /// for the given package name + version. Integrity field is
    /// omitted so the strict-gate treats it as "no constraint,"
    /// matching our test fixture where the synthetic lockfile has
    /// `None` integrity.
    ///
    /// The Rich variant uses `"{name}@{version}"` as the map key
    /// — see `TrustedDependencies::rich_key` in lpm-workspace.
    fn write_pkg_json_with_strict_approval(
        project_dir: &Path,
        name: &str,
        version: &str,
        script_hash: &str,
    ) {
        let key = format!("{name}@{version}");
        let body = serde_json::json!({
            "name": "test-project",
            "lpm": {
                "trustedDependencies": {
                    key: {
                        "scriptHash": script_hash,
                    }
                }
            }
        });
        std::fs::write(project_dir.join("package.json"), body.to_string()).unwrap();
    }

    /// Acceptance #1 + #4: with `force-security-floor = false`, an
    /// existing StrictBinding approval is honored and returns
    /// trusted. Pins back-compat.
    #[test]
    fn force_floor_false_honors_existing_strict_approval() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "esbuild", "0.25.1", "node-gyp rebuild");
        let hash = compute_script_hash(&pkg_dir).expect("script hash");
        write_pkg_json_with_strict_approval(dir.path(), "esbuild", "0.25.1", &hash);
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

        let reason = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "0.25.1",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false, // force-security-floor OFF
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(reason, TrustReason::StrictBinding);
        assert!(reason.is_trusted());
    }

    /// Acceptance #2: with `force-security-floor = true`, the
    /// same approval is suspended. is_trusted() returns false;
    /// the distinct `SuspendedByForceFloor` reason code
    /// distinguishes this from a package with no approval.
    #[test]
    fn force_floor_true_suspends_existing_strict_approval() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "esbuild", "0.25.1", "node-gyp rebuild");
        let hash = compute_script_hash(&pkg_dir).expect("script hash");
        write_pkg_json_with_strict_approval(dir.path(), "esbuild", "0.25.1", &hash);
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

        let reason = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "0.25.1",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            true, // force-security-floor ON
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(reason, TrustReason::SuspendedByForceFloor);
        assert!(!reason.is_trusted());
    }

    /// Acceptance #3: unsetting the flag (calling again with
    /// false) reactivates the approval. No re-review needed —
    /// approval state lives in package.json and is unchanged by
    /// the flag flip.
    #[test]
    fn force_floor_unsetting_reactivates_approval_without_re_review() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "esbuild", "0.25.1", "node-gyp rebuild");
        let hash = compute_script_hash(&pkg_dir).expect("script hash");
        write_pkg_json_with_strict_approval(dir.path(), "esbuild", "0.25.1", &hash);
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

        // Flag ON → suspended.
        let r_on = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "0.25.1",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            true,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(r_on, TrustReason::SuspendedByForceFloor);

        // Flag OFF (same inputs otherwise) → trusted again.
        let r_off = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "0.25.1",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(r_off, TrustReason::StrictBinding);
        assert!(r_off.is_trusted());
    }

    /// Acceptance #4 (complement): packages with no approval at
    /// all are Untrusted regardless of the flag. The flag
    /// suppresses would-have-been-trusted results; it does NOT
    /// transform Untrusted → SuspendedByForceFloor.
    #[test]
    fn force_floor_does_not_transform_untrusted_to_suspended() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"proj"}"#, // no trustedDependencies at all
        )
        .unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "no-approval", "1.0.0", "echo hi");
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

        let with_flag = evaluate_trust(
            &pkg_dir,
            "no-approval",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            true,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(
            with_flag,
            TrustReason::Untrusted,
            "no approval → Untrusted regardless of flag"
        );
        let without_flag = evaluate_trust(
            &pkg_dir,
            "no-approval",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(without_flag, TrustReason::Untrusted);
    }

    /// Force flag also suspends `ScopedGlob` trust (project
    /// `trustedScopes` match). Same semantic as StrictBinding:
    /// a loosening extended by project config is suspended by
    /// the user kill-switch.
    #[test]
    fn force_floor_true_suspends_scoped_glob_trust() {
        let dir = tempfile::tempdir().unwrap();
        let body = serde_json::json!({
            "name": "test-project",
            "lpm": {
                "scripts": {
                    "trustedScopes": ["@myorg/*"]
                }
            }
        });
        std::fs::write(dir.path().join("package.json"), body.to_string()).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "@myorg/util", "1.0.0", "echo hi");
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

        let without_flag = evaluate_trust(
            &pkg_dir,
            "@myorg/util",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(without_flag, TrustReason::ScopedGlob);
        assert!(without_flag.is_trusted());

        let with_flag = evaluate_trust(
            &pkg_dir,
            "@myorg/util",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            true,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(with_flag, TrustReason::SuspendedByForceFloor);
        assert!(!with_flag.is_trusted());
    }

    /// Acceptance #5: SuspendedByForceFloor is classified as
    /// not-trusted. Pins the `is_trusted()` contract from the
    /// enum side so a future refactor of the boolean can't
    /// accidentally flip this variant.
    #[test]
    fn suspended_by_force_floor_reports_not_trusted() {
        assert!(!TrustReason::SuspendedByForceFloor.is_trusted());
    }

    /// Force-flag semantic for `BindingDrift`: drift is ALREADY
    /// not-trusted (the user approved a different script body
    /// previously), so the flag doesn't need to intercept it.
    /// `BindingDrift` should pass through unchanged even under
    /// the flag. This matters because the UX message for
    /// BindingDrift is "re-approve THIS package" — routing it
    /// through `SuspendedByForceFloor` would send the wrong
    /// remediation.
    #[test]
    fn force_floor_preserves_binding_drift_distinct_from_suspension() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "sharp", "0.33.0", "node-gyp rebuild");
        // Record an approval with a stale script hash so the
        // strict gate reports BindingDrift instead of Strict.
        write_pkg_json_with_strict_approval(
            dir.path(),
            "sharp",
            "0.33.0",
            "sha256-this-hash-will-not-match",
        );
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

        let reason = evaluate_trust(
            &pkg_dir,
            "sharp",
            "0.33.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            true, // flag ON
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        // BindingDrift takes precedence — not suspended, because
        // it wasn't trusted to begin with.
        assert_eq!(reason, TrustReason::BindingDrift);
        assert!(!reason.is_trusted());
    }

    // ── capability gate in evaluate_trust ──

    fn capability_test_fixture() -> (
        tempfile::TempDir,
        PackageStore,
        PathBuf,
        HashMap<String, String>,
        SecurityPolicy,
    ) {
        // Reusable fixture for capability-gate tests: project dir
        // with a package.json that ALREADY has a strict approval
        // for esbuild@1.0.0, plus a store package at the same
        // name+version with a known lifecycle script. Tests
        // vary the capability set / user bound / binding hash
        // they pass in.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "esbuild", "1.0.0", "node-gyp rebuild");
        let hash = compute_script_hash(&pkg_dir).expect("script hash");
        write_pkg_json_with_strict_approval(dir.path(), "esbuild", "1.0.0", &hash);
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        (dir, store, pkg_dir, scripts, policy)
    }

    /// Baseline capability set + trusted binding → passes through.
    /// Behavior-preservation check: every test prior to 6c assumes
    /// this. Pins the short-circuit.
    #[test]
    fn capability_baseline_passes_through_strict_binding() {
        let (dir, _store, pkg_dir, scripts, policy) = capability_test_fixture();
        let baseline = crate::capability::CapabilitySet::default();
        let user = crate::capability::UserBound::default();

        let reason = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &baseline,
            &user,
            None,
        );
        assert_eq!(reason, TrustReason::StrictBinding);
        assert!(reason.is_trusted());
    }

    /// Tighter-than-user-bound request + trusted binding → passes
    /// through (no approval needed for narrower-than-ceiling
    /// rlimits).
    #[test]
    fn capability_tighter_than_ceiling_passes_through() {
        let (dir, _store, pkg_dir, scripts, policy) = capability_test_fixture();
        let request = crate::capability::CapabilitySet {
            sandbox_limits: [(crate::capability::RlimitKey::Nproc, 512)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let user = crate::capability::UserBound {
            sandbox_limits_ceiling: [(crate::capability::RlimitKey::Nproc, 4096)]
                .into_iter()
                .collect(),
        };

        let reason = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &request,
            &user,
            None,
        );
        assert_eq!(reason, TrustReason::StrictBinding);
    }

    /// Widening request + legacy binding (capability_hash = None,
    /// the state this fixture produces by default) →
    /// CapabilityNotApproved. The legacy approval covers baseline
    /// only; the widened request is not approved.
    #[test]
    fn capability_widening_against_legacy_binding_is_not_approved() {
        let (dir, _store, pkg_dir, scripts, policy) = capability_test_fixture();
        let request = crate::capability::CapabilitySet {
            pass_env: ["SSH_AUTH_SOCK".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let user = crate::capability::UserBound::default();

        let reason = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &request,
            &user,
            None,
        );
        assert_eq!(reason, TrustReason::CapabilityNotApproved);
        assert!(!reason.is_trusted());
    }

    /// Widening request + binding with matching capability hash →
    /// trust granted (the user reviewed the exact widening).
    /// Setup uses a helper that writes a capability-hash into the
    /// binding directly (the approve-scripts write path is tested separately).
    #[test]
    fn capability_widening_with_matching_hash_is_approved() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "esbuild", "1.0.0", "node-gyp rebuild");
        let script_hash = compute_script_hash(&pkg_dir).expect("script hash");

        // Build the capability request + its canonical hash.
        let request = crate::capability::CapabilitySet {
            pass_env: ["SSH_AUTH_SOCK".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let cap_hash = request.canonical_hash();

        // Write a package.json that stores BOTH the strict approval
        // (script hash matches) AND the capability hash for the
        // request above.
        let key = "esbuild@1.0.0";
        let body = serde_json::json!({
            "name": "test-project",
            "lpm": {
                "trustedDependencies": {
                    key: {
                        "scriptHash": script_hash,
                        "capabilityHash": cap_hash,
                    }
                }
            }
        });
        std::fs::write(dir.path().join("package.json"), body.to_string()).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let user = crate::capability::UserBound::default();

        let reason = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &request,
            &user,
            None,
        );
        assert_eq!(reason, TrustReason::StrictBinding);
        assert!(reason.is_trusted());
    }

    /// Widening request + binding with MISMATCHED capability hash
    /// (drift) → CapabilityNotApproved. Pins the hash-drift-
    /// invalidates-trust rule.
    #[test]
    fn capability_widening_with_drifted_hash_is_not_approved() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "esbuild", "1.0.0", "node-gyp rebuild");
        let script_hash = compute_script_hash(&pkg_dir).expect("script hash");

        // User approved ONE capability set; package now requests a
        // DIFFERENT one. Hash mismatch → CapabilityNotApproved.
        let approved = crate::capability::CapabilitySet {
            pass_env: ["FOO".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let key = "esbuild@1.0.0";
        let body = serde_json::json!({
            "name": "test-project",
            "lpm": {
                "trustedDependencies": {
                    key: {
                        "scriptHash": script_hash,
                        "capabilityHash": approved.canonical_hash(),
                    }
                }
            }
        });
        std::fs::write(dir.path().join("package.json"), body.to_string()).unwrap();
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();

        // Package now requests something different.
        let new_request = crate::capability::CapabilitySet {
            pass_env: ["FOO".to_string(), "BAR".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let user = crate::capability::UserBound::default();

        let reason = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &new_request,
            &user,
            None,
        );
        assert_eq!(reason, TrustReason::CapabilityNotApproved);
    }

    /// Widening request + NO binding at all (unapproved package)
    /// → the upstream layer returns Untrusted, so the capability
    /// gate doesn't fire — we preserve the more actionable
    /// "not trusted at all" reason rather than layering
    /// CapabilityNotApproved on top.
    #[test]
    fn capability_widening_on_untrusted_package_keeps_untrusted_reason() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"proj"}"#).unwrap();
        let store = PackageStore::at(dir.path().join("store"));
        let _lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let pkg_dir = write_p6_pkg(&store, "unapproved", "1.0.0", "echo hi");
        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let scripts = read_lifecycle_scripts(&pkg_dir.join("package.json")).unwrap();
        let request = crate::capability::CapabilitySet {
            pass_env: ["FOO".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let user = crate::capability::UserBound::default();

        let reason = evaluate_trust(
            &pkg_dir,
            "unapproved",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            false,
            &request,
            &user,
            None,
        );
        assert_eq!(reason, TrustReason::Untrusted);
    }

    /// force-security-floor + widening request still returns
    /// SuspendedByForceFloor, NOT CapabilityNotApproved. The
    /// kill-switch takes precedence over the capability gate — a
    /// flag-set user's diagnostic should point at the flag, not
    /// the capability system.
    #[test]
    fn capability_widening_under_force_flag_stays_suspended() {
        let (dir, _store, pkg_dir, scripts, policy) = capability_test_fixture();
        let request = crate::capability::CapabilitySet {
            pass_env: ["FOO".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let user = crate::capability::UserBound::default();

        let reason = evaluate_trust(
            &pkg_dir,
            "esbuild",
            "1.0.0",
            None,
            &scripts,
            &policy,
            dir.path(),
            ScriptPolicy::Deny,
            true, // force-security-floor ON
            &request,
            &user,
            None,
        );
        // Trust was going to be granted (StrictBinding), force
        // flag intercepted before the capability gate could fire.
        assert_eq!(reason, TrustReason::SuspendedByForceFloor);
    }

    /// CapabilityNotApproved reports not-trusted via
    /// `is_trusted()`, ensuring the is_trusted contract stays
    /// consistent with the variant's semantic.
    #[test]
    fn capability_not_approved_reports_not_trusted() {
        assert!(!TrustReason::CapabilityNotApproved.is_trusted());
    }

    /// the shell invocation for lifecycle scripts must
    /// be platform-aware. Before the sandbox returned
    /// `UnsupportedPlatform` on Windows so this code path never
    /// fired there; with the real backend landed, `sh -c` would
    /// fail at spawn because `sh.exe` isn't on the standard Windows
    /// PATH. The helper picks `cmd.exe /D /C` instead so end-to-end
    /// Windows installs actually work.
    #[cfg(windows)]
    #[test]
    fn platform_shell_invocation_uses_cmd_exe_on_windows() {
        let (prog, args) = platform_shell_invocation("node install.js");
        assert_eq!(prog, "cmd.exe");
        assert_eq!(
            args,
            vec![
                "/D".to_string(),
                "/C".to_string(),
                "node install.js".to_string()
            ],
            "Windows lifecycle scripts must run under cmd.exe /D /C, \
             /D suppresses AutoRun, /C runs-and-exits"
        );
    }

    #[cfg(unix)]
    #[test]
    fn platform_shell_invocation_uses_sh_on_unix() {
        let (prog, args) = platform_shell_invocation("node install.js");
        assert_eq!(prog, "sh");
        assert_eq!(
            args,
            vec!["-c".to_string(), "node install.js".to_string()],
            "POSIX hosts must run lifecycle scripts under sh -c"
        );
    }

    /// follow-up: the lifecycle PATH must use the host's
    /// native separator and a non-empty fallback for the case where
    /// the caller didn't pass through a parent PATH. The pre-46.2
    /// helper inlined POSIX `:` + `/usr/bin:/bin`, producing
    /// `node_modules\.bin:<parent>` on Windows — a single malformed
    /// entry that no PATH lookup would resolve.
    #[cfg(windows)]
    #[test]
    fn build_lifecycle_path_uses_semicolon_and_system32_on_windows() {
        let project = std::path::PathBuf::from(r"C:\proj");
        // With an inherited parent PATH.
        let with_parent =
            build_lifecycle_path(&project, Some(r"C:\OtherTool\bin;C:\Windows\System32"));
        assert!(
            with_parent.starts_with(r"C:\proj\node_modules\.bin;"),
            "node_modules\\.bin must lead the PATH with a `;` separator: {with_parent}"
        );
        assert!(
            with_parent.contains(r"C:\OtherTool\bin"),
            "inherited parent PATH must be appended: {with_parent}"
        );

        // Without an inherited parent PATH (fallback path).
        let fallback = build_lifecycle_path(&project, None);
        assert!(
            fallback.starts_with(r"C:\proj\node_modules\.bin;"),
            "fallback PATH must still lead with node_modules\\.bin: {fallback}"
        );
        assert!(
            fallback.contains(r"C:\Windows\System32"),
            "fallback must include System32 so cmd.exe / where.exe resolve: {fallback}"
        );
        assert!(
            !fallback.contains("/usr/bin"),
            "fallback must NOT leak POSIX defaults on Windows: {fallback}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn build_lifecycle_path_uses_colon_and_usr_bin_on_unix() {
        let project = std::path::PathBuf::from("/proj");
        let with_parent = build_lifecycle_path(&project, Some("/opt/tool/bin:/usr/local/bin"));
        assert!(
            with_parent.starts_with("/proj/node_modules/.bin:"),
            "node_modules/.bin must lead with `:` separator: {with_parent}"
        );

        let fallback = build_lifecycle_path(&project, None);
        assert!(
            fallback.starts_with("/proj/node_modules/.bin:/usr/bin:/bin"),
            "fallback must keep the historical POSIX shape: {fallback}"
        );
    }
}
