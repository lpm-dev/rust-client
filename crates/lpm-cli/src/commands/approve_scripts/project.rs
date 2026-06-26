use super::prelude::*;

/// Filter the persisted build-state's blocked set against the current
/// `trustedDependencies` and return only the entries that are STILL
/// blocked.
///
/// the persisted
/// `build-state.json` is only refreshed by `lpm install`. Without this
/// filter step, `lpm approve-scripts` would re-render or re-approve
/// packages the user has already approved (until the next install
/// re-captures the state). Without this filter, approving a package and
/// immediately listing the blocked set could still show the approved
/// package as blocked.
///
/// The filter rule mirrors the install-time blocked-set computation in
/// [`build_state::compute_blocked_packages`]:
///
/// - [`TrustMatch::Strict`] / [`TrustMatch::LegacyNameOnly`] → REMOVE
///   from the effective blocked set (the script will run when `lpm rebuild`
///   eventually executes; the user has nothing to review).
/// - [`TrustMatch::BindingDrift`] → KEEP. Drift is the whole reason we
///   re-review. The blocked package's existing `binding_drift` flag is
///   already true in this case (set by the install-time capture), so the
///   downstream rendering doesn't need to know whether the drift came
///   from the persisted state or from a fresh check.
/// - [`TrustMatch::NotTrusted`] → KEEP. The default-deny case.
///
/// the filter now also
/// consults the capability gate. A persisted blocked entry whose
/// strict match succeeds BUT whose current capability request
/// widens beyond the user bound without a matching capability-
/// hash approval is KEPT in the effective blocked set. Without
/// this extension, approve-scripts would drop capability-widening rows
/// the install-time capture correctly included.
pub fn compute_effective_blocked_set<'a>(
    state: &'a BuildState,
    trusted: &TrustedDependencies,
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
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
            match trust {
                // Strict / LegacyNameOnly MAY still need review if
                // the capability gate rejects. Drop only when the
                // gate also passes — i.e., no widening requested
                // OR the binding's capability_hash covers it.
                TrustMatch::Strict => {
                    let binding = trusted.get_binding(&bp.name, &bp.version);
                    requested_capabilities.requires_review_despite_strict_match(user_bound, binding)
                }
                TrustMatch::LegacyNameOnly => {
                    requested_capabilities.requires_review_despite_strict_match(user_bound, None)
                }
                // BindingDrift / NotTrusted already need review.
                TrustMatch::BindingDrift { .. } | TrustMatch::NotTrusted => true,
            }
        })
        .collect()
}

/// Run the `lpm approve-scripts` command.
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
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    // Hold the shared store lock because the approval flow reads store
    // package dirs to inspect prior installs and diff scripts. A
    // concurrent `lpm cache prune --apply` could remove an entry
    // mid-walk without this gate.
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let lock_path = lpm_root.store_lock();
    lpm_common::with_shared_lock_async(
        lock_path,
        run_under_store_lock(
            project_dir,
            package,
            yes,
            list,
            dry_run,
            json_output,
            lpm_root,
        ),
    )
    .await
}

async fn run_under_store_lock(
    project_dir: &Path,
    package: Option<&str>,
    yes: bool,
    list: bool,
    // When true, the review flow runs end-to-end (card rendering,
    // interactive prompts, diff surfaces, outcome accounting) but NO
    // persisted state mutates —
    // [`write_back`] short-circuits at each of its three call sites
    // (direct-approve, `--yes`, interactive walk) and
    // [`print_summary`] surfaces `"dry_run": true` in the JSON
    // envelope. No-op when combined with `--list` (already
    // read-only); the JSON envelope for `--list --dry-run` still
    // carries the `dry_run` flag so agents can distinguish
    // preview-of-listing from plain-listing at parse time.
    dry_run: bool,
    json_output: bool,
    lpm_root: lpm_common::LpmRoot,
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
            "lpm approve-scripts requires a package.json in the current directory.".into(),
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

    // ── Load current trustedDependencies () ─────────
    //
    // Loading the manifest BEFORE the early-return on empty state lets
    // the persisted state be filtered through the current trust to
    // compute the *effective* blocked set, so an already-approved package
    // doesn't appear in --list / --yes output.

    let manifest_text = std::fs::read_to_string(&pkg_json_path).map_err(LpmError::Io)?;
    let mut manifest: serde_json::Value = serde_json::from_str(&manifest_text)
        .map_err(|e| LpmError::Registry(format!("failed to parse package.json: {e}")))?;

    let mut trusted = extract_trusted_dependencies(&manifest);

    // ── capability request + hash ────────
    //
    // Parse the project's per-package capability request ONCE and
    // reuse the same `CapabilitySet` object for both:
    //   1. Rendering the human-readable delta in the approve prompt
    //      (so users see env vars / read mode / rlimit bumps in
    //      concrete terms, not a bare hash).
    //   2. Computing the `capability_hash` that gets persisted into
    //      every binding written in this invocation.
    //
    // The persisted hash MUST come from the same canonical object the
    // runtime enforces against. Re-parsing in either direction
    // (prompt-time vs. write-time, or approve-time vs. enforce-time)
    // would risk divergence that ships approvals the runtime never
    // satisfies. Parsing once here and forwarding the already-computed
    // `capability_hash` down to each write site makes the invariant
    // visible in the code flow.
    //
    // The runtime uses `crate::capability::CapabilitySet::from_package_json`
    // on the same path — as long as `package.json` is byte-stable
    // between this invocation and the next install, the hashes
    // match byte-for-byte. Drift in the manifest between approve
    // and install correctly invalidates the approval via the
    // 6c hash-equality rule.
    let capability_set = crate::capability::CapabilitySet::from_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("{e}")))?;
    let user_bound = crate::security_approval::authorized_capability_user_bound();
    // Only persist the hash when the request actually widens —
    // baseline or tighter-than-bound requests never hit the
    // capability gate at enforcement time, so storing a hash for
    // them would be noise in `package.json` diffs. The 6b match
    // rule interprets `None` as "approved with no extra
    // capabilities," which is the correct semantic for both
    // baseline and tighter-than-bound cases.
    let capability_hash: Option<String> = if capability_set.loosens_beyond(&user_bound) {
        Some(capability_set.canonical_hash())
    } else {
        None
    };

    // Surface the delta once at the top of the run. Renders only
    // when there IS a widening — baseline approvals stay quiet
    // (no behavior change for the existing green path).
    if !json_output {
        let delta = capability_set.delta_vs_user_bound(&user_bound);
        if !delta.is_empty() {
            output::warn("This project requests extra capabilities for any packages you approve:");
            eprint!("{}", delta.render_human_readable());
            eprintln!(
                "  These capabilities are bound to the approval — if `package.json` later \
                 changes them, approvals are invalidated and re-review is required."
            );
            eprintln!();
        }
    }
    let initial_was_legacy = matches!(trusted, TrustedDependencies::Legacy(_));

    // Re-evaluate the persisted blocked set against the current trust.
    // The borrow returns &BlockedPackage; we materialize the underlying
    // owned values into a Vec<BlockedPackage> so the rest of the function
    // can move/iterate without lifetime gymnastics.
    let effective: Vec<BlockedPackage> =
        compute_effective_blocked_set(&state, &trusted, &capability_set, &user_bound)
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
        drift_ignore_override: None,
    };
    let baseline_index =
        crate::commands::audit::inventory::build_project_v2_baseline_index(project_dir, &lpm_root);

    // ── pre-fetch provenance for the effective set ────
    //
    // Install does not fetch provenance; approve-scripts fetches the
    // much smaller effective blocked set in parallel here, before any
    // approval call site needs the value. The fetch overlaps with the
    // user reading approval cards on the interactive path, and is
    // bounded by the join_all fan-out on `--yes` bulk.
    //
    // `--list` is read-only — skip the fetch entirely; the listing
    // doesn't materialize any binding so `provenance_at_approval` is
    // never consulted. Empty effective set: skip too (no-op).
    let (verify_policy, runtime_sigstore_source) = runtime_verify_policy_with_source();
    let runtime_enforce = verify_policy.enforce;
    if !list && !dry_run && !effective_state.blocked_packages.is_empty() {
        crate::security_approval::ensure_runtime_sigstore_posture(
            project_dir,
            json_output,
            runtime_enforce,
            runtime_sigstore_source,
        )?;
    }
    let provenance_by_pkg: HashMap<(String, String), ProvenanceStatus> = if list
        || effective_state.blocked_packages.is_empty()
    {
        HashMap::new()
    } else {
        fetch_provenance_for_effective_set(&effective_state.blocked_packages, &verify_policy).await
    };

    // ── <pkg> argument: handled BEFORE the empty-effective short-circuit ──
    //
    // When the user explicitly names a package, we want a targeted
    // message: "already approved" if they named something that's been
    // approved, or "not in blocked set" if they named something unknown.
    // The generic "nothing to approve" success path would be confusing
    // because the user is asking about ONE package.
    //
    // this branch must run BEFORE the empty-effective
    // check so the user-friendly errors are reachable.
    if let Some(arg) = package {
        // Track outcomes for the summary
        let mut approved: Vec<&BlockedPackage> = Vec::new();
        let skipped: Vec<&BlockedPackage> = Vec::new();

        let target = match lookup_blocked_by_arg(&effective_state.blocked_packages, arg) {
            BlockedLookup::Match(target) => target,
            BlockedLookup::NotFound => {
                // Was the arg in the persisted (unfiltered) state? If so,
                // it must have been filtered out by current trust →
                // already approved.
                if !matches!(
                    lookup_blocked_by_arg(&state.blocked_packages, arg),
                    BlockedLookup::NotFound
                ) {
                    return Err(LpmError::Script(format!(
                        "package '{arg}' is already approved (current binding matches). \
                         Run `lpm install` to refresh the blocked set, or pass `--list` to see what's still blocked."
                    )));
                }
                return Err(LpmError::NotFound(format!(
                    "package '{arg}' is not in the blocked set. Run `lpm approve-scripts --list` to see what's blocked."
                )));
            }
            BlockedLookup::Ambiguous { candidates } => {
                let mut keys: Vec<String> = candidates
                    .iter()
                    .map(|blocked| format!("{}@{}", blocked.name, blocked.version))
                    .collect();
                keys.sort();
                keys.dedup();
                return Err(LpmError::Script(format!(
                    "package '{arg}' is ambiguous in the blocked set — {} rows match. \
                     Re-run with `name@version` to disambiguate. Candidates: {}",
                    candidates.len(),
                    keys.join(", "),
                )));
            }
        };

        let reviewed_by_prompt = !json_output && is_tty();
        let confirmed = if reviewed_by_prompt {
            print_package_card(target);
            // surface the version diff card
            // alongside the regular card when this is an UPDATE
            // (prior binding under same name exists). No-op for
            // first-time review.
            print_version_diff_card_for_blocked(
                target,
                &trusted,
                baseline_index.as_ref(),
                &lpm_root,
            );
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
        } else {
            true
        };

        if confirmed {
            // write-path: carry install-time provenance + behavioral-tag captures
            // into the binding so subsequent installs can compare against them
            // (drift rule + version diff).
            //
            // SILENT-DROP fix: `snapshot_for_binding` returns
            // `Err(LpmError::ProvenanceVerification(_))` when the
            // verifier rejected the bundle, refusing the approval
            // rather than blanking `provenance_at_approval`.
            let snap = snapshot_for_binding(
                &provenance_by_pkg,
                &target.name,
                &target.version,
                runtime_enforce,
            )?;
            let meta = approval_metadata_preserving_existing_provenance(
                &trusted,
                target,
                capability_hash.clone(),
                snap,
            );
            trusted.approve_with_metadata(&target.name, &target.version, meta);
            approved.push(target);
            // Under `--dry-run`, short-circuit the write; the approval
            // intent is still recorded in `approved` for the summary so
            // the user sees "would approve X" with the same JSON
            // envelope shape as a live run.
            if !dry_run {
                authorize_project_trust_write(
                    project_dir,
                    &trusted,
                    json_output,
                    reviewed_by_prompt,
                )?;
                write_back(&pkg_json_path, &mut manifest, &trusted)?;
            }
        } else {
            // skip path: nothing to record besides the count (typed-out
            // here to avoid an unused mut warning if we never push)
            print_summary(
                &effective_state,
                &approved,
                &[target],
                &trusted,
                initial_was_legacy,
                false,
                dry_run,
                json_output,
                Some(&provenance_by_pkg),
            );
            return Ok(());
        }

        print_summary(
            &effective_state,
            &approved,
            &skipped,
            &trusted,
            initial_was_legacy,
            false,
            dry_run,
            json_output,
            Some(&provenance_by_pkg),
        );
        return Ok(());
    }

    if effective_state.blocked_packages.is_empty() {
        if json_output {
            // Carry `dry_run` through so agents can uniformly read
            // `envelope.dry_run`
            // regardless of which branch produced the envelope. On
            // an empty set, the flag is semantically a no-op (no
            // mutation would have happened anyway) but the field's
            // presence is a schema-level consistency guarantee.
            let body = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "success": true,
                "command": "approve-scripts",
                "dry_run": dry_run,
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
        print_listing(
            &effective_state,
            &trusted,
            dry_run,
            json_output,
            baseline_index.as_ref(),
            &lpm_root,
        );
        return Ok(());
    }

    // Track outcomes for the summary / JSON output
    let mut approved: Vec<&BlockedPackage> = Vec::new();
    let mut skipped: Vec<&BlockedPackage> = Vec::new();

    // ── --yes (bulk approve) ────────────────────────────────────────

    if yes {
        // — refuse bulk approval when any
        // effective-blocked entry is classified outside the green
        // tier. Gate runs BEFORE `emit_yes_warning_banner` so we
        // don't emit success-shaped human + tracing output and then
        // abort — that sequence would corrupt log aggregators and
        // mislead the user about whether the operation ran.
        //
        // Refusal is restricted to EXPLICIT non-green tiers:
        // - Some(Amber) / Some(AmberLlm) / Some(Red) → refuse.
        // - Some(Green) → allowed in bulk (still requires explicit
        //   --yes; auto-execution is, gated on the sandbox).
        // - None → pass-through to today's behavior. `None` means
        //   the persisted blocked state was written by a pre-P2 LPM
        //   that never classified the package; breaking those
        //   existing `--yes` flows before the next install
        //   recaptures the state would be a silent→P2 upgrade
        //   regression.
        enforce_tiered_yes_gate(&effective_state.blocked_packages, GateScope::Project)?;

        emit_yes_warning_banner(effective_state.blocked_packages.len(), json_output);
        for blocked in &effective_state.blocked_packages {
            // write-path — see the direct-approve branch above for the rationale.
            // SILENT-DROP fix: `?` propagates a verifier
            // rejection so the trust binding is NOT overwritten with
            // `None` (which would silently disarm drift detection on
            // every subsequent install).
            let snap = snapshot_for_binding(
                &provenance_by_pkg,
                &blocked.name,
                &blocked.version,
                runtime_enforce,
            )?;
            let meta = approval_metadata_preserving_existing_provenance(
                &trusted,
                blocked,
                capability_hash.clone(),
                snap,
            );
            trusted.approve_with_metadata(&blocked.name, &blocked.version, meta);
            approved.push(blocked);
        }
        // Short-circuit under `--dry-run`.
        if !dry_run {
            authorize_project_trust_write(project_dir, &trusted, json_output, false)?;
            write_back(&pkg_json_path, &mut manifest, &trusted)?;
        }
        print_summary(
            &effective_state,
            &approved,
            &skipped,
            &trusted,
            initial_was_legacy,
            yes,
            dry_run,
            json_output,
            Some(&provenance_by_pkg),
        );
        return Ok(());
    }

    // (The `<pkg>` branch is handled at the top of `run` BEFORE the
    // empty-effective short-circuit — see the  comment.)

    // ── Default: interactive walk ───────────────────────────────────

    // check `--json` BEFORE the TTY gate. Every `--json`
    // caller is by definition non-interactive (CI, scripted agent,
    // MCP server), so with the old order they always hit the
    // "requires a TTY" error — accurate but unhelpful: it doesn't
    // name the flag pairs that actually pair with `--json`. The
    // `--json`-specific error names them explicitly. Pure non-TTY
    // (no `--json`) still falls through to the TTY error below.
    if json_output {
        return Err(LpmError::Script(
            "interactive review cannot be combined with `--json`. \
             Use `--list --json`, `--yes --json`, or `<pkg> --json` for structured output."
                .into(),
        ));
    }
    if !is_tty() {
        return Err(LpmError::Script(
            "interactive review requires a TTY. \
             Use `--yes` to approve everything, `--list` to inspect, or pass a `<pkg>` argument."
                .into(),
        ));
    }

    // Walk one at a time. Quit aborts WITHOUT writing in-progress entries
    // (atomic). The accumulator only gets flushed to disk after the loop.
    // walk the EFFECTIVE blocked set, not the persisted
    // state — already-approved packages are skipped.
    output::info(&format!(
        "{} package(s) blocked. Walking one at a time — Quit aborts without writing.",
        effective_state.blocked_packages.len(),
    ));
    println!();

    let mut quit_early = false;
    for blocked in &effective_state.blocked_packages {
        print_package_card(blocked);
        // render the version-diff card for
        // updates (no-op when no prior binding exists for the same
        // package name).
        print_version_diff_card_for_blocked(blocked, &trusted, baseline_index.as_ref(), &lpm_root);

        // branch the Select on whether this is
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
                // First-time review: original labels.
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
                        print_full_script(blocked, baseline_index.as_ref(), &lpm_root);
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
        // write-path — see the direct-approve branch earlier for the rationale.
        // SILENT-DROP fix: `?` on the verifier-rejection arm refuses
        // to record an approval rather than blanking the prior
        // `provenance_at_approval` and disarming drift checks.
        // Warn-mode preservation: when the snapshot is `None` but a
        // prior verified snapshot exists for the exact same version,
        // preserve it rather than overwriting with `None` —
        // otherwise a re-approval under Warn would silently clear
        // the prior reference and disarm drift detection.
        let snap = snapshot_for_binding(
            &provenance_by_pkg,
            &blocked.name,
            &blocked.version,
            runtime_enforce,
        )?;
        let meta = approval_metadata_preserving_existing_provenance(
            &trusted,
            blocked,
            capability_hash.clone(),
            snap,
        );
        trusted.approve_with_metadata(&blocked.name, &blocked.version, meta);
    }
    // Under `--dry-run`, skip the atomic write; `approved` / `skipped`
    // still feed into `print_summary` so the agent sees the would-approve
    // count.
    if !approved.is_empty() && !dry_run {
        authorize_project_trust_write(project_dir, &trusted, json_output, true)?;
        write_back(&pkg_json_path, &mut manifest, &trusted)?;
    }

    print_summary(
        &effective_state,
        &approved,
        &skipped,
        &trusted,
        initial_was_legacy,
        false,
        dry_run,
        json_output,
        Some(&provenance_by_pkg),
    );
    Ok(())
}

/// The interactive walk's per-package
/// choice space.
///
/// `Approve` and `Skip` are the original actions used when
/// no prior approval exists for a different version of the same
/// package. adds [`AcceptNew`] and [`KeepOld`] — the same two
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
pub(super) enum InteractiveChoice {
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
    pub(super) fn decision(self) -> Option<bool> {
        match self {
            InteractiveChoice::Approve | InteractiveChoice::AcceptNew => Some(true),
            InteractiveChoice::Skip | InteractiveChoice::KeepOld => Some(false),
            InteractiveChoice::View | InteractiveChoice::Quit => None,
        }
    }
}
