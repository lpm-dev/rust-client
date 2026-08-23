use super::prelude::*;

/// Distinguishes the project and global gate call sites so the refusal
/// error's redirect prose names the correct flag set. The substring
/// `--yes refuses` is identical across scopes (agents already
/// substring-match on it); only the trailing `Run ...` redirect varies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GateScope {
    Project,
    Global,
}

/// Common shape consumed by [`enforce_tiered_yes_gate`]. Implemented by
/// both [`BlockedPackage`] (project blocked set) and
/// [`crate::global_blocked_set::AggregateBlockedRow`] (global aggregate
/// row) so a single gate function enforces the policy at every bulk-
/// approval call site. This keeps the global bulk paths from writing
/// approvals straight to the trust file without the same tier check
/// project bulk approval receives.
pub(super) trait TieredRow {
    /// `name@version` for the refusal error's per-row listing.
    fn display_id(&self) -> String;
    /// `Some(tier)` when classification ran, `None` for unclassified state.
    fn static_tier(&self) -> Option<lpm_security::triage::StaticTier>;
}

impl TieredRow for BlockedPackage {
    fn display_id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
    fn static_tier(&self) -> Option<lpm_security::triage::StaticTier> {
        self.static_tier
    }
}

impl TieredRow for crate::global_blocked_set::AggregateBlockedRow {
    fn display_id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
    fn static_tier(&self) -> Option<lpm_security::triage::StaticTier> {
        self.static_tier
    }
}

/// Blanket impl so the gate accepts both `&[Row]` and `&[&Row]`. The
/// grouped-interactive path operates on `Vec<&AggregateBlockedRow>`
/// (slicing the aggregate without cloning); without this impl the gate
/// callsite would need to either clone or own the rows.
impl<T: TieredRow + ?Sized> TieredRow for &T {
    fn display_id(&self) -> String {
        (**self).display_id()
    }
    fn static_tier(&self) -> Option<lpm_security::triage::StaticTier> {
        (**self).static_tier()
    }
}

/// — enforce the `--yes` refusal contract.
///
/// Given the **effective** blocked-set that `--yes` would approve,
/// return `Err` unless every entry carries an explicit green tier.
///
/// Pure so it's unit-testable without an end-to-end `run()`
/// invocation. The callsite threads the returned `LpmError` up and
/// the JSON-error wrapper in `main.rs` turns it into structured
/// output when `--json` is set.
///
/// Generic over [`TieredRow`] so the same gate enforces the policy on
/// both the project blocked set ([`BlockedPackage`]) and the global
/// aggregate ([`AggregateBlockedRow`]). [`GateScope`] selects the
/// per-flag redirect prose; the load-bearing `--yes refuses` prefix is
/// shared across scopes for agent substring matching.
pub(super) fn enforce_tiered_yes_gate<R: TieredRow>(
    blocked: &[R],
    scope: GateScope,
) -> Result<(), LpmError> {
    use lpm_security::triage::StaticTier;

    let refusals: Vec<&R> = blocked
        .iter()
        .filter(|bp| !matches!(bp.static_tier(), Some(StaticTier::Green)))
        .collect();

    if refusals.is_empty() {
        return Ok(());
    }

    // Actionable error shape: count → per-package lines with tier
    // label → clear redirect to the interactive / single-pkg path.
    // Agents parsing the error_code=script error can substring-match
    // the `"--yes refuses"` prefix, which is stable-onward.
    let detail = refusals
        .iter()
        .map(|bp| {
            let tier_text = bp.static_tier().map_or("unclassified", tier_label_text);
            format!("    {}  [{}]", bp.display_id(), tier_text)
        })
        .collect::<Vec<_>>()
        .join("\n");

    let redirect = match scope {
        GateScope::Project => {
            "Run `lpm approve-scripts` (interactive walk) or \
             `lpm approve-scripts <pkg>` to review individual packages. \
             Use `lpm approve-scripts --list` to inspect the full blocked set first."
        }
        GateScope::Global => {
            "Run `lpm approve-scripts --global` (interactive walk) or \
             `lpm approve-scripts --global <pkg>` to review individual packages. \
             Use `lpm approve-scripts --global --list` to inspect the full blocked set first."
        }
    };

    Err(LpmError::Script(format!(
        "--yes refuses to bulk-approve {} package(s) classified outside the \
         green tier. Each requires explicit per-package review.\n\n{}\n\n{}",
        refusals.len(),
        detail,
        redirect,
    )))
}

/// Plain text label for a [`StaticTier`] value — consumed by
/// [`colored_tier_label`] and by tests that don't want to assert
/// on ANSI escape sequences.
pub(super) fn tier_label_text(tier: lpm_security::triage::StaticTier) -> &'static str {
    use lpm_security::triage::StaticTier;
    match tier {
        StaticTier::Green => "green ✓",
        StaticTier::Amber => "amber — review required",
        StaticTier::AmberLlm => "amber (llm-advised) — review required",
        StaticTier::Red => "red ✗ — hand-curated blocklist hit",
    }
}

/// Colored rendering of the tier label. Green → green, Red → red,
/// the ambers → yellow. Kept thin so the color policy lives in one
/// place and the plain-text helper stays unit-testable.
pub(super) fn colored_tier_label(
    tier: lpm_security::triage::StaticTier,
) -> install_ui::TerminalFragment {
    use lpm_security::triage::StaticTier;
    let text = tier_label_text(tier);
    match tier {
        StaticTier::Green => install_ui::green(text),
        StaticTier::Amber | StaticTier::AmberLlm => install_ui::yellow(text),
        StaticTier::Red => install_ui::red(text),
    }
}
