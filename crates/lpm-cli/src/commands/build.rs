//! `lpm build` — Selective lifecycle script execution.
//!
//! Phase 2 of the two-phase install model:
//! - `lpm install` downloads, extracts, and links packages — NO scripts execute.
//! - `lpm build` selectively runs lifecycle scripts based on trust policy.
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
//! Already-built packages are skipped (idempotent). Use `--rebuild` to force.
//!
//! ## Security (S3)
//! - 5-minute default timeout per script (--timeout to override)
//! - Credential env vars stripped (LPM_TOKEN, NPM_TOKEN, GITHUB_TOKEN, etc.)
//! - Scripts run in package's store directory, not project root
//! - On Unix: child spawned in its own process group; timeout kills the
//!   entire group (not just the direct child), preventing orphaned subprocesses
//! - On Windows: `Child::kill()` terminates the process tree via `TerminateProcess`

use crate::output;
use lpm_common::LpmError;
use lpm_security::script_hash::compute_script_hash;
use lpm_security::{EXECUTED_INSTALL_PHASES, SecurityPolicy, TrustMatch};
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
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

// **Phase 32 Phase 4 M1:** the per-file `SCRIPT_PHASES` const previously
// declared here was removed and consolidated into
// `lpm_security::EXECUTED_INSTALL_PHASES` (imported above) so the install
// pipeline, the build pipeline, and the script-hash function all read from
// the same source of truth. See Phase 4 status doc §F3 for the rationale.

/// Run the `lpm build` command.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    project_dir: &Path,
    specific_packages: &[String],
    all: bool,
    dry_run: bool,
    rebuild: bool,
    timeout_secs: Option<u64>,
    json_output: bool,
    unsafe_full_env: bool,
    deny_all: bool,
) -> Result<(), LpmError> {
    // Check deny-all: --deny-all flag or lpm.scripts.denyAll config.
    // Phase 46 P1: consolidated into the ScriptPolicyConfig loader so
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

    let store = PackageStore::default_location()?;
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

    // Collect packages that have lifecycle scripts
    let mut scriptable_packages: Vec<ScriptablePackage> = Vec::new();

    for lp in &lockfile.packages {
        let pkg_dir = store.package_dir(&lp.name, &lp.version);
        let pkg_json_path = pkg_dir.join("package.json");

        if !pkg_json_path.exists() {
            continue;
        }

        let scripts = match read_lifecycle_scripts(&pkg_json_path) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let is_built = pkg_dir.join(BUILD_MARKER).exists();

        // **Phase 32 Phase 4 M5:** strict gate. Compute the script hash
        // (same fn `lpm install` uses to populate `build-state.json`) and
        // ask the policy whether the binding matches an existing approval.
        // The composition with the legacy `is_scope_trusted` gate is OR —
        // either gate passing means the script runs.
        let script_hash = compute_script_hash(&pkg_dir);
        let trust = policy.can_run_scripts_strict(
            &lp.name,
            &lp.version,
            lp.integrity.as_deref(),
            script_hash.as_deref(),
        );
        let (is_trusted, drift) = match trust {
            TrustMatch::Strict => (true, false),
            TrustMatch::LegacyNameOnly => (true, false),
            TrustMatch::BindingDrift { .. } => (false, true),
            TrustMatch::NotTrusted => (false, false),
        };
        let is_trusted = is_trusted || is_scope_trusted(&lp.name, project_dir);

        // Surface drift to the user — even though the script is skipped,
        // they need to know WHY so they can re-review with `lpm approve-builds`.
        if drift && !json_output {
            output::warn(&format!(
                "{}: stored approval drifted (script changed since approval). \
                 Re-run `lpm approve-builds {}` to re-review.",
                lp.name, lp.name,
            ));
        }
        // Surface legacy bare-name entries with a soft deprecation warning,
        // so users migrate to the strict binding form. Only emit when the
        // strict gate would have been the deciding factor (skip when scope
        // trust would have approved anyway).
        if matches!(trust, TrustMatch::LegacyNameOnly) && !json_output {
            output::warn(&format!(
                "{}: legacy bare-name trustedDependencies entry — run \
                 `lpm approve-builds {}` to upgrade to a strict (script-hash-bound) approval",
                lp.name, lp.name,
            ));
        }

        scriptable_packages.push(ScriptablePackage {
            name: lp.name.clone(),
            version: lp.version.clone(),
            store_path: pkg_dir,
            scripts,
            is_built,
            is_trusted,
        });
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
    } else if all {
        // Build ALL packages with scripts
        scriptable_packages.iter().collect()
    } else {
        // Build only trusted packages
        scriptable_packages
            .iter()
            .filter(|p| p.is_trusted)
            .collect()
    };

    // Filter out already-built (unless --rebuild)
    let to_build: Vec<&ScriptablePackage> = if rebuild {
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
            output::success(&format!(
                "All {built}/{total} packages with scripts are already built."
            ));
            if !rebuild {
                println!("  Use {} to rebuild.", "--rebuild".dimmed());
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
                let trust = if pkg.is_trusted {
                    "trusted ✓".green().to_string()
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

    // Warn if building untrusted packages
    let untrusted_count = to_build.iter().filter(|p| !p.is_trusted).count();
    if untrusted_count > 0 && !all && specific_packages.is_empty() {
        output::warn(&format!(
            "{untrusted_count} package(s) are not in trustedDependencies and will be skipped."
        ));
        println!(
            "  Add them to {} or use {}.",
            "package.json > lpm > trustedDependencies".dimmed(),
            "lpm build --all".bold(),
        );
    }

    if !json_output {
        output::info(&format!("Building {} package(s)...", to_build.len()));
    }

    // Execute scripts
    let mut successes = 0usize;
    let mut failures = 0usize;
    let sanitized_env = if unsafe_full_env {
        // Pass full environment without stripping — user explicitly opted in
        if !json_output {
            output::warn("Using --unsafe-full-env: credential env vars will NOT be stripped.");
        }
        std::env::vars().collect::<HashMap<String, String>>()
    } else {
        build_sanitized_env()
    };

    for pkg in &to_build {
        if !json_output {
            println!(
                "\n  {} {}",
                pkg.name.bold(),
                format!("({})", pkg.version).dimmed(),
            );
        }

        let mut pkg_success = true;

        for phase in EXECUTED_INSTALL_PHASES {
            let cmd = match pkg.scripts.get(*phase) {
                Some(c) => c,
                None => continue,
            };

            if !json_output {
                println!("    {} {phase}: {}", "→".dimmed(), cmd.dimmed());
            }

            match execute_script(cmd, &pkg.store_path, project_dir, &sanitized_env, &timeout) {
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

/// Execute a single lifecycle script with timeout and env sanitization.
fn execute_script(
    cmd: &str,
    package_dir: &Path,
    project_dir: &Path,
    env: &HashMap<String, String>,
    timeout: &Duration,
) -> Result<(), String> {
    use std::process::Command;

    let mut command = Command::new("sh");
    command
        .args(["-c", cmd])
        .current_dir(package_dir)
        .env_clear();

    // Set sanitized environment
    for (key, value) in env {
        command.env(key, value);
    }

    // Set npm conventions
    command.env("INIT_CWD", project_dir);
    command.env(
        "PATH",
        format!(
            "{}:{}",
            project_dir.join("node_modules/.bin").display(),
            env.get("PATH")
                .map(|s| s.as_str())
                .unwrap_or("/usr/bin:/bin")
        ),
    );

    // On Unix, spawn the child in its own process group so we can kill the
    // entire tree on timeout (not just the direct child).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let start = std::time::Instant::now();

    let child = command
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn: {e}"))?;

    // Wait with timeout
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

/// Kill the entire process group on Unix, or just the child on other platforms.
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
        // On Windows, Child::kill() calls TerminateProcess which kills the tree.
        let _ = child.kill();
    }
}

/// Wait for a child process with a timeout.
/// On timeout, kills the process group (Unix) or direct child (Windows).
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: &Duration,
) -> Result<std::process::ExitStatus, String> {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
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

    env
}

/// Read lifecycle scripts from a package.json file.
fn read_lifecycle_scripts(pkg_json_path: &Path) -> Option<HashMap<String, String>> {
    let content = std::fs::read_to_string(pkg_json_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let scripts_obj = parsed.get("scripts")?.as_object()?;

    let mut lifecycle = HashMap::new();
    for phase in EXECUTED_INSTALL_PHASES {
        if let Some(cmd) = scripts_obj.get(*phase).and_then(|v| v.as_str()) {
            lifecycle.insert(phase.to_string(), cmd.to_string());
        }
    }

    if lifecycle.is_empty() {
        None
    } else {
        Some(lifecycle)
    }
}

/// Check if a package name matches any trustedScopes glob pattern.
fn is_scope_trusted(package_name: &str, project_dir: &Path) -> bool {
    let pkg_json_path = project_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Check lpm.scripts.trustedScopes
    let scopes = parsed
        .get("lpm")
        .and_then(|l| l.get("scripts"))
        .and_then(|s| s.get("trustedScopes"))
        .and_then(|t| t.as_array());

    let Some(scopes) = scopes else {
        return false;
    };

    for scope in scopes {
        let Some(pattern) = scope.as_str() else {
            continue;
        };

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
    store_path: std::path::PathBuf,
    scripts: HashMap<String, String>,
    is_built: bool,
    is_trusted: bool,
}

/// Show the install-time build hint (called from install.rs).
///
/// Lists packages with unexecuted scripts and their trust status.
pub fn show_install_build_hint(
    store: &PackageStore,
    packages: &[(String, String)], // (name, version)
    policy: &SecurityPolicy,
    project_dir: &Path,
) {
    #[allow(clippy::type_complexity)]
    let mut scriptable: Vec<(&str, &str, HashMap<String, String>, bool, bool)> = Vec::new();

    for (name, version) in packages {
        let pkg_dir = store.package_dir(name, version);
        let pkg_json_path = pkg_dir.join("package.json");

        let scripts = match read_lifecycle_scripts(&pkg_json_path) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let is_built = pkg_dir.join(BUILD_MARKER).exists();
        let is_trusted = policy.can_run_scripts(name) || is_scope_trusted(name, project_dir);

        scriptable.push((name, version, scripts, is_built, is_trusted));
    }

    let unbuilt: Vec<_> = scriptable
        .iter()
        .filter(|(_, _, _, built, _)| !built)
        .collect();

    if unbuilt.is_empty() {
        return;
    }

    println!();
    output::info(&format!(
        "{} package(s) have install scripts:",
        unbuilt.len()
    ));

    for (name, version, scripts, _, trusted) in &unbuilt {
        let trust_label = if *trusted {
            "trusted ✓".green().to_string()
        } else {
            "not trusted".yellow().to_string()
        };

        let script_names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
        println!(
            "  {:<30} {:<30} ({})",
            format!("{}@{}", name, version).bold(),
            script_names.join(", ").dimmed(),
            trust_label,
        );
    }

    let trusted_unbuilt = unbuilt.iter().filter(|(_, _, _, _, t)| *t).count();
    println!();
    if trusted_unbuilt > 0 {
        println!(
            "  Run {} to execute scripts for trusted packages.",
            "lpm build".bold()
        );
    }
    if trusted_unbuilt < unbuilt.len() {
        println!(
            "  Run {} to build specific packages.",
            "lpm build <package-name>".bold()
        );
    }
}

/// Check if ALL packages with unexecuted lifecycle scripts are trusted.
///
/// Used by install.rs to decide whether to auto-build without explicit opt-in.
pub fn all_scripted_packages_trusted(
    store: &PackageStore,
    packages: &[(String, String)],
    policy: &SecurityPolicy,
    project_dir: &Path,
) -> bool {
    let mut has_any_unbuilt = false;

    for (name, version) in packages {
        let pkg_dir = store.package_dir(name, version);
        let pkg_json_path = pkg_dir.join("package.json");

        let scripts = match read_lifecycle_scripts(&pkg_json_path) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        // Has scripts — check if built already
        if pkg_dir.join(BUILD_MARKER).exists() {
            continue; // already built, skip
        }

        // Unbuilt with scripts
        has_any_unbuilt = true;
        let _ = scripts; // used above for the is_empty check

        let is_trusted = policy.can_run_scripts(name) || is_scope_trusted(name, project_dir);

        if !is_trusted {
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
/// Phase 4 M2: `policy.trusted_dependencies` is now a `TrustedDependencies`
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

// Phase 46 P1: `read_deny_all_config` was removed as part of
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
                store_path: PathBuf::new(),
                scripts: HashMap::new(),
                is_built: false,
                is_trusted: true,
            },
            ScriptablePackage {
                name: "b".into(),
                version: "1.0.0".into(),
                store_path: PathBuf::new(),
                scripts: HashMap::new(),
                is_built: false,
                is_trusted: true,
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
                tarball: None,
            },
            lpm_lockfile::LockedPackage {
                name: "b".into(),
                version: "1.0.0".into(),
                source: None,
                integrity: None,
                dependencies: vec!["a@1.0.0".into()],
                alias_dependencies: vec![],
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
        write_store_package(
            &store,
            "esbuild",
            "1.0.0",
            r#"{"postinstall":"node install.js"}"#,
            false,
        );

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &store,
            &[("esbuild".to_string(), "1.0.0".to_string())],
            &policy,
            dir.path(),
        );

        assert!(trusted);
    }

    #[test]
    fn all_scripted_packages_trusted_false_when_any_unbuilt_scripted_package_is_untrusted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();

        let store = PackageStore::at(dir.path().join("store"));
        write_store_package(
            &store,
            "sharp",
            "1.0.0",
            r#"{"postinstall":"node install.js"}"#,
            false,
        );

        let policy = SecurityPolicy::from_package_json(&dir.path().join("package.json"));
        let trusted = all_scripted_packages_trusted(
            &store,
            &[("sharp".to_string(), "1.0.0".to_string())],
            &policy,
            dir.path(),
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
            &store,
            &[
                ("trusted-pkg".to_string(), "1.0.0".to_string()),
                ("blocked-pkg".to_string(), "1.0.0".to_string()),
            ],
            &policy,
            dir.path(),
        );

        assert!(
            trusted,
            "already-built untrusted packages should not block current auto-build decisions"
        );
    }

    // ── warn_stale_trusted_deps tests ───────────────────────────

    #[test]
    fn stale_detection_finds_packages_without_scripts() {
        // Phase 4 M2: trusted_dependencies is now TrustedDependencies::Legacy
        // (or Rich). Construct the Legacy variant directly to preserve the
        // pre-Phase-4 test semantic.
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
                store_path: std::path::PathBuf::new(),
                scripts: HashMap::from([("postinstall".into(), "node setup".into())]),
                is_built: false,
                is_trusted: true,
            },
            ScriptablePackage {
                name: "esbuild".into(),
                version: "0.21.0".into(),
                store_path: std::path::PathBuf::new(),
                scripts: HashMap::from([("postinstall".into(), "node install.js".into())]),
                is_built: false,
                is_trusted: true,
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

    // ── Phase 32 Phase 4 M5: strict gate composition tests ──────────
    //
    // These tests exercise the trust-decision logic in isolation: given a
    // SecurityPolicy and a (name, version, integrity, script_hash) tuple,
    // does the strict gate produce the right TrustMatch and does the
    // composition with `is_scope_trusted` produce the right `is_trusted`?
    //
    // The full pipeline (lockfile + store + script execution) needs network
    // and a real fixture, which is out of scope for in-module unit tests.
    // M6 covers the full pipeline via integration-style tests.

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
        // Phase 4 binds approvals to name@version. Approving 0.25.1 does
        // NOT carry over to 0.25.2 — the user must re-approve at the new
        // version (or the resolver picks the same one).
        let policy = rich_policy_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        let trust =
            policy.can_run_scripts_strict("esbuild", "0.25.2", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(trust, TrustMatch::NotTrusted);
    }

    /// **AUDIT FIX (Phase 4 D-impl-1, 2026-04-11):** the previous version of
    /// this test asserted that `<name>@*` preserve keys did NOT satisfy
    /// the strict gate, which broke backward compatibility — a manifest
    /// like `["esbuild"]` lost esbuild's approval on the first
    /// `lpm approve-builds --yes` upgrade. The audit reproduced it. Post-fix
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
             so legacy approvals survive `approve-builds --yes` upgrades"
        );
    }

    /// REGRESSION: composing M5 with the existing `is_scope_trusted` glob
    /// path. A package matched by a `lpm.scripts.trustedScopes` glob is
    /// trusted regardless of the strict-gate result. This is the OR
    /// composition documented in M5 scope.
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
}
