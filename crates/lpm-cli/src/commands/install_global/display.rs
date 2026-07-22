use super::commit::CommitOutput;
use super::prepare::PrepResult;
use crate::{install_ui, output};
use lpm_common::{LpmRoot, sanitize_for_terminal};

pub(super) fn print_success(
    out: &CommitOutput,
    hint: &crate::path_onboarding::PathHintReport,
    json_output: bool,
) {
    if json_output {
        // surface the PATH hint as structured data in JSON
        // mode so agents can detect "shims installed but not on
        // PATH" without scraping stderr/stdout. The four fields
        // mirror PathHintReport so consumers can treat it as a
        // pass-through.
        let body = serde_json::json!({
            "success": true,
            "package": out.name,
            "version": out.version,
            "saved_spec": out.saved_spec,
            "source": out.source,
            "commands": out.commands,
            "install_root": out.install_root.display().to_string(),
            "path_hint": {
                "bin_dir": hint.bin_dir.display().to_string(),
                "on_path": hint.on_path,
                "marker_already_present": hint.marker_already_present,
                "banner_printed": hint.banner_printed,
            },
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
        return;
    }
    let name_safe = sanitize_for_terminal(&out.name);
    let version_safe = sanitize_for_terminal(&out.version);
    let saved_spec_safe = sanitize_for_terminal(&out.saved_spec);
    output::success_line(crate::install_ui::terminal_line!(
        "Installed {}@{} (saved as {})",
        install_ui::bold(&name_safe),
        install_ui::dim(&version_safe),
        install_ui::dim(&saved_spec_safe)
    ));
    if out.commands.is_empty() {
        // Shouldn't happen — we error out earlier when bin entries are
        // empty — but guard the message just in case.
        return;
    }
    let commands_safe: Vec<String> = out
        .commands
        .iter()
        .map(|c| sanitize_for_terminal(c))
        .collect();
    output::info(&format!(
        "Exposed command{} on PATH: {}",
        if out.commands.len() == 1 { "" } else { "s" },
        commands_safe.join(", ")
    ));
    // The banner (if any) was printed by `maybe_show_path_hint` BEFORE
    // we got here. We don't re-emit anything in human mode; the hint
    // is its own block of output. Leaving this comment so future
    // refactors don't accidentally double-print.
}

/// emit a post-install banner if the new install root's
/// per-install `build-state.json` surfaces packages not covered by the
/// global trust list. Mirrors the project-level
/// `install::run`'s post-install security summary (which is suppressed
/// for globals via `no_security_summary: true`).
///
/// Silent in JSON mode — JSON consumers already see `path_hint` in
/// `print_success`'s structured output, so JSON stays quiet.
///
/// Errors reading the build-state or trust file are non-fatal: the
/// install already committed. A missing build-state just means no
/// warning fires (no info to report). Malformed state is debug-logged.
pub(super) fn emit_post_install_blocked_warning(
    root: &LpmRoot,
    prep: &PrepResult,
    json_output: bool,
) {
    if json_output {
        return;
    }
    // Read the per-install build-state directly rather than going
    // through the aggregate path — we only care about THIS install's
    // blocked set, not every globally-installed package's.
    let Some(state) = crate::build_state::read_build_state(&prep.install_root) else {
        // No build-state file means either (a) the inner pipeline
        // didn't run the security capture for this install, or (b)
        // the install has zero scripts-carrying deps. Either way,
        // nothing to warn about.
        return;
    };
    if state.blocked_packages.is_empty() {
        return;
    }
    // Filter through the global trust list — packages already
    // approved globally shouldn't appear in the banner.
    let trust = match lpm_global::trusted_deps::read_for(root) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("emit_post_install_blocked_warning: reading global trust: {e}");
            return;
        }
    };
    let remaining: Vec<&crate::build_state::BlockedPackage> = state
        .blocked_packages
        .iter()
        .filter(|b| {
            !matches!(
                trust.matches_strict(
                    &b.name,
                    &b.version,
                    b.integrity.as_deref(),
                    b.script_hash.as_deref(),
                ),
                lpm_global::GlobalTrustMatch::Strict
            )
        })
        .collect();
    if remaining.is_empty() {
        return;
    }

    eprintln!();
    output::warn_line(crate::install_ui::terminal_line!(
        "{} package{} in this global install have lifecycle scripts blocked pending review.",
        install_ui::bold(&remaining.len().to_string()),
        if remaining.len() == 1 { "" } else { "s" },
    ));
    // Show the first few by name so the user has concrete signal.
    let preview: Vec<String> = remaining
        .iter()
        .take(5)
        .map(|b| {
            format!(
                "{}@{}",
                sanitize_for_terminal(&b.name),
                sanitize_for_terminal(&b.version)
            )
        })
        .collect();
    if !preview.is_empty() {
        output::info(&format!(
            "   {}{}",
            preview.join(", "),
            if remaining.len() > preview.len() {
                format!(", +{} more", remaining.len() - preview.len())
            } else {
                String::new()
            }
        ));
    }
    output::info("   Run `lpm approve-scripts --global` to review and approve.");
    eprintln!();
}
