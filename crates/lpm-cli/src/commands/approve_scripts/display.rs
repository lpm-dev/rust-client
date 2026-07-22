use super::prelude::*;

/// Print the version-diff card for a
/// blocked entry — the fuller "changes since v<prior>" view that
/// renders alongside the package's existing card during the
/// interactive walk, the direct `<pkg>` approve, and the `--list`
/// listing.
///
/// No-op when (a) no prior approved binding exists for this
/// package name (first-time review — nothing to diff against), or
/// (b) the diff classifies as
/// [`crate::version_diff::VersionDiffReason::NoChange`].
///
/// Reads store bodies for both prior and candidate via
/// [`crate::build_state::read_install_phase_bodies`]; degrades
/// gracefully when the prior version is no longer in the store
/// (cache cleaned, fresh clone evicted the prior tarball) — the
/// renderer prints its "(prior or candidate scripts not in store)"
/// fallback rather than emitting a misleading empty diff.
///
/// Emits to stdout (cliclack TUI is stdout-driven; `--json` mode
/// can never reach this path because the interactive walk refuses
/// to combine with `--json` upstream).
pub(super) fn print_version_diff_card_for_blocked(
    blocked: &BlockedPackage,
    trusted: &TrustedDependencies,
    baseline_index: Option<&lpm_store::V2BaselineIndex>,
    lpm_root: &lpm_common::LpmRoot,
) {
    let Some((prior_version, binding)) =
        trusted.latest_binding_for_name(&blocked.name, &blocked.version)
    else {
        return;
    };
    let diff = crate::version_diff::compute_version_diff(prior_version, binding, blocked);
    if !diff.is_drift() {
        return;
    }
    let store_dir_for = |version: &str| -> Option<std::path::PathBuf> {
        crate::commands::audit::inventory::find_project_baseline(
            baseline_index,
            lpm_root,
            &blocked.name,
            version,
        )
        .map(|b| b.package_dir)
    };
    let prior_pairs = match store_dir_for(prior_version) {
        Some(dir) => crate::build_state::read_install_phase_bodies(&dir),
        None => Vec::new(),
    };
    let candidate_pairs = match store_dir_for(&blocked.version) {
        Some(dir) => crate::build_state::read_install_phase_bodies(&dir),
        None => Vec::new(),
    };
    let prior_bodies = if prior_pairs.is_empty() {
        None
    } else {
        Some(crate::version_diff::phase_bodies_from_pairs(prior_pairs))
    };
    let candidate_bodies = if candidate_pairs.is_empty() {
        None
    } else {
        Some(crate::version_diff::phase_bodies_from_pairs(
            candidate_pairs,
        ))
    };
    if let Some(card) = crate::version_diff::render_preflight_card(
        &diff,
        &blocked.name,
        prior_bodies.as_ref(),
        candidate_bodies.as_ref(),
    ) {
        println!();
        println!("{card}");
        println!();
    }
}

pub(super) fn is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

pub(super) fn emit_yes_warning_banner(count: usize, json_output: bool) {
    let msg = format!(
        "--yes blanket-approves {count} package(s) without per-package review. \
         Approvals are bound to script hashes captured at install time. \
         This bypasses LPM's default-deny security posture."
    );
    // Triple-emission per status doc §"Security requirements":
    // human stdout (only in non-JSON mode), JSON warning field (set by
    // print_summary), and tracing log so any log aggregator catches the
    // bypass.
    //
    // The tracing emission is safe in JSON mode because the global
    // tracing subscriber in `main.rs` is pinned to stderr. The relevant
    // invariant: stdout is reserved for command output (human or JSON);
    // tracing always goes to stderr.
    tracing::warn!("{}", msg);
    if !json_output {
        println!();
        output::warn(&msg);
        println!();
    }
}

pub(super) fn print_package_card(blocked: &BlockedPackage) {
    println!();
    println!(
        "{}",
        install_ui::terminal_line!(
            "  {}@{}",
            install_ui::bold(&blocked.name),
            install_ui::dim(&blocked.version),
        )
    );
    if let Some(integrity) = &blocked.integrity {
        println!(
            "{}",
            install_ui::terminal_line!(
                "    {:<14}{}",
                install_ui::dim("Integrity:"),
                truncate_for_display(integrity, 60),
            )
        );
    }
    if let Some(script_hash) = &blocked.script_hash {
        println!(
            "{}",
            install_ui::terminal_line!(
                "    {:<14}{}",
                install_ui::dim("Script hash:"),
                truncate_for_display(script_hash, 60),
            )
        );
    }
    if !blocked.phases_present.is_empty() {
        println!(
            "{}",
            install_ui::terminal_line!(
                "    {:<14}{}",
                install_ui::dim("Phases:"),
                blocked.phases_present.join(", "),
            )
        );
    }
    // — static-gate tier annotation for the
    // interactive card. Absent (None) means the blocked-state row
    // predates; don't print a line rather than showing a
    // misleading "unknown".
    if let Some(tier) = blocked.static_tier {
        println!(
            "{}",
            install_ui::terminal_line!(
                "    {:<14}{}",
                install_ui::dim("Static tier:"),
                colored_tier_label(tier),
            )
        );
    }
    if blocked.binding_drift {
        println!(
            "    {} {}",
            "!".yellow(),
            "previously approved — script content has changed since approval".yellow()
        );
    }
    println!();
}

pub(super) fn truncate_for_display(s: &str, max: usize) -> String {
    let safe = lpm_common::sanitize_terminal_inline(s);
    let Some((end, _)) = safe.char_indices().nth(max) else {
        return safe.into_owned();
    };
    let mut truncated = String::with_capacity(end + '…'.len_utf8());
    truncated.push_str(&safe[..end]);
    truncated.push('…');
    truncated
}

/// Read the package's `package.json` from the GLOBAL STORE and print every
/// non-empty install phase body. Used by the "View full script" choice in
/// the interactive walk. Read from the store (not from `node_modules`) to
/// match what the build pipeline executes — same source-of-truth as the
/// script-hash function.
pub(super) fn print_full_script(
    blocked: &BlockedPackage,
    baseline_index: Option<&lpm_store::V2BaselineIndex>,
    lpm_root: &lpm_common::LpmRoot,
) {
    let pkg_dir = match crate::commands::audit::inventory::find_project_baseline(
        baseline_index,
        lpm_root,
        &blocked.name,
        &blocked.version,
    ) {
        Some(b) => b.package_dir,
        None => {
            output::warn(&format!(
                "{}@{}: not found in store (workspace/file/link source, or corrupt install)",
                blocked.name, blocked.version
            ));
            return;
        }
    };
    let pkg_json_path = pkg_dir.join("package.json");
    let content = match lpm_common::read_text_file_capped(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
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
                println!(
                    "{}",
                    install_ui::terminal_line!(
                        "  {}: {}",
                        install_ui::bold(phase),
                        install_ui::multiline(b),
                    )
                );
            }
            None => {
                println!(
                    "{}",
                    install_ui::terminal_line!(
                        "  {}: {}",
                        install_ui::dim(phase),
                        install_ui::dim("(none)"),
                    )
                );
            }
        }
    }
    println!();
}

pub(super) fn print_listing(
    state: &BuildState,
    trusted: &TrustedDependencies,
    // The list path is structurally read-only, so dry-run is
    // semantically a no-op here, but the envelope still surfaces the
    // flag for uniform agent parsing.
    dry_run: bool,
    json_output: bool,
    baseline_index: Option<&lpm_store::V2BaselineIndex>,
    lpm_root: &lpm_common::LpmRoot,
) {
    if json_output {
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "success": true,
            "command": "approve-scripts",
            "mode": "list",
            "dry_run": dry_run,
            "blocked_count": state.blocked_packages.len(),
            "approved_count": 0,
            "skipped_count": 0,
            "blocked": state.blocked_packages.iter().map(|b| blocked_to_json(b, trusted)).collect::<Vec<_>>(),
            "warnings": [],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
        return;
    }

    output::info(&format!(
        "{} package(s) blocked:",
        state.blocked_packages.len()
    ));
    for blocked in &state.blocked_packages {
        print_package_card(blocked);
        // surface the version diff card
        // alongside each entry's regular card. No-op for entries
        // without a prior binding under the same name (first-time
        // review — nothing to diff against).
        print_version_diff_card_for_blocked(blocked, trusted, baseline_index, lpm_root);
    }
    println!();
    output::info(
        "Run `lpm approve-scripts` (interactive), `lpm approve-scripts --yes` (bulk), or `lpm approve-scripts <pkg>` to approve.",
    );
}

/// Delegates to the shared
/// canonical helper [`crate::version_diff::blocked_to_json`] so the
/// approve-scripts JSON paths and the install-pipeline JSON paths
/// emit byte-identical entry shapes. Using the shared helper prevents
/// key drift between the two callers as future fields land.
pub(super) fn blocked_to_json(
    blocked: &BlockedPackage,
    trusted: &TrustedDependencies,
) -> serde_json::Value {
    crate::version_diff::blocked_to_json(blocked, trusted)
}

// clippy::too_many_arguments: print_summary carries tier annotations,
// version diffs, dry-run state, provenance status, and output mode. A
// wrapper struct would hurt readability more than the arg count because
// every caller inside `run` constructs the same set of fields inline, and
// there's no reuse across commands. Fold into a struct only if a second
// command-level surface starts consuming the same shape.
#[allow(clippy::too_many_arguments)]
pub(super) fn print_summary(
    state: &BuildState,
    approved: &[&BlockedPackage],
    skipped: &[&BlockedPackage],
    trusted: &TrustedDependencies,
    initial_was_legacy: bool,
    yes_flag: bool,
    // When true, the JSON envelope carries `"dry_run": true` so agents
    // can distinguish preview from live runs at parse time; human output
    // reframes "X approved" as "would approve X — no changes written"
    // and drops the `lpm rebuild` next-step pointer since there are no
    // new approvals to run.
    dry_run: bool,
    json_output: bool,
    // Live `ProvenanceStatus` map from the batch fetch,
    // threaded through so each blocked entry's JSON envelope can
    // surface `provenance.verified` per package. `None` for callers
    // that have no map in scope (the read-only `--list` path bypasses
    // it entirely; the per-package named approval path uses the
    // single-entry helper directly). When `Some(_)`, the map's keys
    // are the same `(name, version)` pairs as the blocked set.
    provenance_by_pkg: Option<&HashMap<(String, String), ProvenanceStatus>>,
) {
    if json_output {
        let mut warnings: Vec<serde_json::Value> = Vec::new();
        if yes_flag {
            let msg = if dry_run {
                format!(
                    "DRY RUN — would blanket-approve {} package(s) via --yes; no write performed",
                    approved.len()
                )
            } else {
                format!(
                    "--yes blanket-approved {} package(s) without per-package review",
                    approved.len()
                )
            };
            warnings.push(serde_json::json!({
                "code": "yes_blanket_approve",
                "message": msg,
            }));
        }
        if initial_was_legacy && !approved.is_empty() && !dry_run {
            // Suppress the legacy-upgrade warning under dry-run: no
            // write happened, so the legacy array form is still on
            // disk. Surfacing it as "upgraded" would be misleading.
            warnings.push(serde_json::json!({
                "code": "legacy_upgraded_to_rich",
                "message": "trustedDependencies was upgraded from the legacy array form to the rich map form"
            }));
        }
        let mut body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "success": true,
            "command": "approve-scripts",
            "mode": if yes_flag { "yes" } else { "interactive" },
            "dry_run": dry_run,
            "blocked_count": state.blocked_packages.len(),
            "approved_count": approved.len(),
            "skipped_count": skipped.len(),
            // per-entry `version_diff` flows
            // through `blocked_to_json`. Note: when this fires
            // post-write-back (the --yes and interactive paths),
            // `trusted` includes the just-written binding for
            // `name@candidate_version`. The diff selector is
            // strictly-less-than the candidate, so it skips the
            // freshly-added entry and still reports the diff
            // against the prior version — matches what the user
            // saw when reviewing. Under `--dry-run`, no write
            // happened, so `trusted` retains the pre-run state
            // and the diff reports against the prior binding
            // identically.
            // When the live ProvenanceStatus map is in scope, each
            // entry's JSON envelope gains a `provenance` block
            // (`verified: true | "skipped" | false | null |
            // "verification_rejected"`). Additive — older agents
            // that don't expect the key remain readable.
            "approved": approved.iter().map(|b| crate::version_diff::blocked_to_json_with_provenance(b, trusted, provenance_by_pkg)).collect::<Vec<_>>(),
            "skipped": skipped.iter().map(|b| crate::version_diff::blocked_to_json_with_provenance(b, trusted, provenance_by_pkg)).collect::<Vec<_>>(),
            "warnings": warnings,
            "errors": [],
        });
        if !dry_run && !approved.is_empty() {
            body.as_object_mut().unwrap().insert(
                "next_steps".into(),
                crate::json_contract::command_next_steps(
                    "Run approved lifecycle scripts",
                    "lpm rebuild",
                ),
            );
        }
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else {
        println!();
        if approved.is_empty() && skipped.is_empty() {
            output::info("No changes to package.json.");
        } else if dry_run {
            output::info(&format!(
                "DRY RUN — would approve {}, skip {}. No changes written.",
                approved.len(),
                skipped.len(),
            ));
        } else {
            output::success(&format!(
                "{} approved, {} skipped.",
                approved.len(),
                skipped.len()
            ));
            if !approved.is_empty() {
                output::info("Run `lpm rebuild` to execute the approved scripts.");
            }
            if initial_was_legacy {
                output::info(
                    "trustedDependencies upgraded from legacy array to rich form (binding metadata).",
                );
            }
        }
    }
}

#[allow(dead_code)]
pub(super) fn _build_state_path_for_tests(project_dir: &Path) -> PathBuf {
    build_state::build_state_path(project_dir)
}
