use super::prelude::*;

// ─── approve-scripts --global ────────────────────────────

/// Threshold at which `--group` auto-enables for `--global` review.
/// Reviewing N-at-once packages one-by-one past this size is typically
/// impractical; the grouped UI shows the same info indexed by
/// top-level globally-installed package instead of per-dep.
pub const GROUP_AUTO_THRESHOLD: usize = 10;

#[cfg(test)]
thread_local! {
    static GLOBAL_TRUST_WRITE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_global_trust_write_count() {
    GLOBAL_TRUST_WRITE_COUNT.set(0);
}

#[cfg(test)]
pub(super) fn global_trust_write_count() -> usize {
    GLOBAL_TRUST_WRITE_COUNT.get()
}

fn write_global_trust(
    root: &lpm_common::LpmRoot,
    trust: &lpm_global::GlobalTrustedDependencies,
) -> Result<(), LpmError> {
    #[cfg(test)]
    GLOBAL_TRUST_WRITE_COUNT.with(|count| count.set(count.get() + 1));
    lpm_global::trusted_deps::write_for(root, trust)
}

#[derive(Clone, Copy)]
pub(super) struct ApprovalProvenanceContext<'a> {
    registry: &'a lpm_registry::RegistryClient,
    verify_policy: &'a crate::provenance_fetch::VerifyPolicy,
    runtime_enforce: crate::provenance_fetch::EnforceMode,
}

impl<'a> ApprovalProvenanceContext<'a> {
    pub(super) fn new(
        registry: &'a lpm_registry::RegistryClient,
        verify_policy: &'a crate::provenance_fetch::VerifyPolicy,
        runtime_enforce: crate::provenance_fetch::EnforceMode,
    ) -> Self {
        Self {
            registry,
            verify_policy,
            runtime_enforce,
        }
    }
}

/// Global-scope approve-scripts entry point. Mirrors [`run`] but sources
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
    registry: &lpm_registry::RegistryClient,
    package: Option<&str>,
    yes: bool,
    list: bool,
    group: bool,
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
    lpm_common::with_shared_lock_async(
        lock_path,
        run_global_under_store_lock(registry, package, yes, list, group, dry_run, json_output),
    )
    .await
}

async fn run_global_under_store_lock(
    registry: &lpm_registry::RegistryClient,
    package: Option<&str>,
    yes: bool,
    list: bool,
    group: bool,
    // Dry-run mirror of [`run`]'s flag for the global surface. When
    // true, each mutating write into
    // `~/.lpm/global/trusted-dependencies.json` — across
    // [`run_global_bulk_yes`], [`run_global_named`], and the three
    // write sites inside [`run_global_interactive`] (per-row
    // approve, group approve-all, non-grouped per-row) — is
    // short-circuited, and the JSON envelopes carry
    // `"dry_run": true`. No-op when combined with `--list`.
    dry_run: bool,
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
            "`--group` only affects `lpm approve-scripts --global --list` and the \
             interactive global review. It does not apply to `--yes` or direct package approval."
                .into(),
        ));
    }

    let root = lpm_common::LpmRoot::from_env()?;
    let aggregate = crate::global_blocked_set::aggregate_blocked_across_globals(&root)?;
    let effective_group = group || aggregate.rows.len() > GROUP_AUTO_THRESHOLD;

    // ── List mode ─────────────────────────────────────────────────
    if list {
        print_global_list(&aggregate, effective_group, dry_run, json_output);
        return Ok(());
    }

    if yes && !aggregate.unreadable_origins.is_empty() {
        return Err(global_blocked_set_incomplete_error(
            &aggregate.unreadable_origins,
        ));
    }

    // ── Empty set short-circuit (same as project-scoped run) ────
    if aggregate.rows.is_empty() {
        if let Some(arg) = package {
            if !aggregate.unreadable_origins.is_empty() {
                return Err(global_blocked_set_incomplete_error(
                    &aggregate.unreadable_origins,
                ));
            }
            return Err(LpmError::NotFound(format!(
                "package '{arg}' is not in the global blocked set. Run \
                 `lpm approve-scripts --global --list` to see what's blocked."
            )));
        }
        if json_output {
            // Echo `dry_run` for schema-level uniformity; no mutation
            // happens here regardless of the flag.
            let body = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "success": true,
                "command": "approve-scripts",
                "scope": "global",
                "dry_run": dry_run,
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

    let (verify_policy, runtime_sigstore_source) = runtime_verify_policy_with_source();
    let runtime_enforce = verify_policy.enforce;
    let provenance = ApprovalProvenanceContext::new(registry, &verify_policy, runtime_enforce);
    if !dry_run {
        crate::security_approval::ensure_runtime_sigstore_posture_for_global(
            json_output,
            runtime_enforce,
            runtime_sigstore_source,
        )?;
    }

    // ── Named-package approval path ───────────────────────────────
    if let Some(arg) = package {
        return run_global_named(&root, &aggregate, arg, dry_run, json_output, provenance).await;
    }

    // ── Bulk-approve mode ─────────────────────────────────────────
    if yes {
        return run_global_bulk_yes(&root, &aggregate, dry_run, json_output, provenance).await;
    }

    // ── Interactive walk ──────────────────────────────────────────
    if !is_tty() || json_output {
        // No TTY (or JSON mode) + no flags: surface the deterministic
        // error naming --list / --yes so CI / agents know how to proceed.
        // `--dry-run` without --list / --yes / <pkg> hits this too:
        // an interactive preview still needs a TTY to render the
        // prompts, so the error stays the same.
        return Err(LpmError::Script(format!(
            "`lpm approve-scripts --global` needs a TTY for the interactive walk \
             ({} global package(s) with blocked scripts). Pass `--list` to inspect, \
             `--yes` to bulk-approve, or `<pkg>` to approve one.",
            aggregate.rows.len(),
        )));
    }
    run_global_interactive(
        &root,
        &aggregate,
        effective_group,
        dry_run,
        json_output,
        provenance,
    )
    .await
}

pub(super) fn global_blocked_set_incomplete_error(unreadable_origins: &[String]) -> LpmError {
    LpmError::Registry(format!(
        "global blocked set is incomplete: missing or unreadable build-state for {}. \
         Reinstall those globals before approving scripts.",
        unreadable_origins.join(", ")
    ))
}

/// `--list` implementation: print the aggregate read-only. `--group`
/// toggles the output shape (rows-by-dep vs by-top-level).
pub(super) fn print_global_list(
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    group: bool,
    // Read-only path; the flag is surfaced for schema uniformity.
    dry_run: bool,
    json_output: bool,
) {
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
            "success": true,
            "command": "approve-scripts",
            "scope": "global",
            "dry_run": dry_run,
            "group": group,
            "blocked_count": aggregate.rows.len(),
            "blocked": entries,
            "unreadable_origins": aggregate.unreadable_origins,
            "warnings": [],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
        return;
    }
    if aggregate.rows.is_empty() {
        output::success("Nothing blocked globally.");
        return;
    }
    println!();
    output::info_line(install_ui::terminal_line!(
        "{} package{} blocked pending review:",
        install_ui::bold(&aggregate.rows.len().to_string()),
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
                "{}",
                install_ui::terminal_line!(
                    "  {} ({} blocked dep{}):",
                    install_ui::bold(origin),
                    rows.len(),
                    if rows.len() == 1 { "" } else { "s" },
                )
            );
            for r in rows {
                let drift = if r.binding_drift {
                    install_ui::terminal_line!("  {}", install_ui::yellow("[binding drift]"))
                } else {
                    install_ui::TerminalLine::new("")
                };
                println!(
                    "{}",
                    install_ui::terminal_line!(
                        "    {} @ {}{}",
                        &r.name,
                        install_ui::dim(&r.version),
                        drift,
                    )
                );
            }
            println!();
        }
    } else {
        for r in &aggregate.rows {
            let drift = if r.binding_drift {
                install_ui::terminal_line!("  {}", install_ui::yellow("[binding drift]"))
            } else {
                install_ui::TerminalLine::new("")
            };
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} @ {} — used by {}{}",
                    install_ui::bold(&r.name),
                    install_ui::dim(&r.version),
                    r.origins.join(", "),
                    drift,
                )
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
}

// ─── rerun-hint helpers (origin-aware) ─────────────────────
//
// After `lpm approve-scripts --global` writes a binding, the user must
// reinstall the affected globals to actually re-execute the lifecycle
// scripts that were blocked at install time. `lpm rebuild --global`
// is a planned follow-up; until then, the truthful path is
// `lpm uninstall -g <origin> && lpm install -g <origin>`.
//
// IMPORTANT: the affected origins are the TOP-LEVEL globally-installed
// packages whose tree contains the approved blocked row, NOT the
// approved row's own name. A transitive approval (e.g., `esbuild`
// pulled in by `eslint` and `vite-plugin-foo`) needs the user to
// reinstall both top-level globals; the row's name (`esbuild`) may
// not even be a valid `lpm uninstall -g` target.

/// Compute the sorted-deduped union of `origins` across many aggregate
/// rows. Used to render a single rerun-hint covering the full scope of
/// a bulk approval.
pub(super) fn union_origins<'a>(
    rows: impl IntoIterator<Item = &'a crate::global_blocked_set::AggregateBlockedRow>,
) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for r in rows {
        for o in &r.origins {
            set.insert(o.clone());
        }
    }
    set.into_iter().collect()
}

/// Render the post-approval rerun hint to stderr. Empty `origins`
/// triggers an actionable fallback that points the user at `--list`
/// rather than dropping silent guidance.
pub(super) fn emit_rerun_hint_stderr(origins: &[String]) {
    if origins.is_empty() {
        output::info(
            "Unable to derive the affected global list. Run \
             `lpm approve-scripts --global --list` to see which globals \
             were affected, then reinstall those to execute approved scripts.",
        );
        return;
    }
    if origins.len() == 1 {
        output::info(&format!(
            "Next step — reinstall to execute approved scripts: \
             `lpm uninstall -g {0} && lpm install -g {0}`. \
             (`lpm rebuild --global` is a planned follow-up.)",
            origins[0],
        ));
        return;
    }
    output::info("Next step — reinstall the affected globals to execute approved scripts:");
    for o in origins {
        eprintln!(
            "{}",
            install_ui::terminal_line!("    lpm uninstall -g {} && lpm install -g {}", o, o)
        );
    }
    eprintln!("(`lpm rebuild --global` is a planned follow-up.)");
}

/// Build the structured `next_step` JSON payload that mirrors
/// [`emit_rerun_hint_stderr`]. Agents can act on the structured form
/// without parsing the prose.
pub(super) fn rerun_next_step_json(origins: &[String]) -> serde_json::Value {
    serde_json::json!({
        "kind": "reinstall_globals",
        "origins": origins,
    })
}

pub(super) fn rerun_next_steps_json(origins: &[String]) -> serde_json::Value {
    if origins.is_empty() {
        return crate::json_contract::command_next_steps(
            "List affected global packages",
            "lpm approve-scripts --global --list",
        );
    }

    let mut steps = Vec::with_capacity(origins.len());
    for origin in origins {
        let description = format!("Reinstall {origin} to run approved scripts");
        let command = format!("lpm uninstall -g {origin} && lpm install -g {origin}");
        steps.push(crate::json_contract::command_next_step(
            &description,
            &command,
        ));
    }
    serde_json::Value::Array(steps)
}

/// `--yes` implementation: approve every row in the aggregate in one
/// transactional write under the global tx lock. Loud — emits a warning
/// banner in non-JSON mode; in JSON mode surfaces the warning via the
/// structured `warnings` field so agents can detect bulk-approval flows.
///
/// **Lock order:** `store_lock` (outer shared, held by the parent
/// [`run_global_under_store_lock`]) → `global_tx_lock` (inner exclusive,
/// taken here). Do not invert.
pub(super) async fn run_global_bulk_yes(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    dry_run: bool,
    json_output: bool,
    provenance_context: ApprovalProvenanceContext<'_>,
) -> Result<(), LpmError> {
    // Refuse global `--yes` for any aggregate row classified outside
    // the green tier — parity with the project `--yes` gate. The gate
    // runs BEFORE the provenance fetch + banner emission so a refused
    // run doesn't burn network round-trips or emit a success-shaped
    // human/tracing line that would later need contradiction. The
    // important parity rule: an `amber` / `amber-llm` / `red` lifecycle
    // script in a global tree must not be approvable through the bulk
    // path when project `--yes` would refuse the same classification.
    enforce_tiered_yes_gate(&aggregate.rows, GateScope::Global)?;

    // Network fetch (provenance) happens BEFORE the lock so the
    // critical section stays bounded. Transport failures degrade to
    // `ProvenanceStatus::TransportDegraded`; a verifier rejection
    // surfaces as `VerificationRejected` (SILENT-DROP fix)
    // and refuses the approval below.
    let pairs: Vec<crate::provenance_fetch::ProvenanceArtifactKey> = aggregate
        .rows
        .iter()
        .map(|r| (r.name.clone(), r.version.clone(), r.integrity.clone()))
        .collect();
    let provenance = if dry_run {
        HashMap::new()
    } else {
        crate::provenance_fetch::fetch_provenance_for_artifacts(
            provenance_context.registry,
            &pairs,
            provenance_context.verify_policy,
        )
        .await
    };

    // Resolve each row's binding snapshot BEFORE entering the tx lock
    // so a verifier rejection (which returns
    // `Err(LpmError::ProvenanceVerification)`) fails out before we
    // start mutating the trust store — preserving any prior binding
    // untouched. Doing this inside the lock would still preserve the
    // binding (the lock body returns Err without writing), but
    // resolving outside keeps the lock window smaller and the failure
    // path simpler to reason about.
    let mut row_snapshots: Vec<(usize, Option<ProvenanceSnapshot>)> =
        Vec::with_capacity(aggregate.rows.len());
    for (idx, row) in aggregate.rows.iter().enumerate() {
        let snap = snapshot_for_artifact_binding(
            &provenance,
            &row.name,
            &row.version,
            row.integrity.as_deref(),
            provenance_context.runtime_enforce,
        )?;
        row_snapshots.push((idx, snap));
    }

    // Inside the tx lock — bounded read-modify-write.
    let lock_path = root.global_tx_lock();
    let root_for_body = root;
    let aggregate_for_body = aggregate;
    let row_snapshots_for_body = row_snapshots;
    lpm_common::with_exclusive_lock_async(lock_path, async move {
        let mut trust = lpm_global::trusted_deps::read_for(root_for_body)?;
        for (idx, snap) in row_snapshots_for_body {
            let row = &aggregate_for_body.rows[idx];
            trust.insert_binding(
                &row.name,
                &row.version,
                lpm_global::TrustedDependencyBinding {
                    integrity: row.integrity.clone(),
                    script_hash: row.script_hash.clone(),
                    provenance_at_approval: snap,
                },
            );
        }
        if !dry_run {
            crate::security_approval::ensure_global_trust_candidate_authorized_from_trust(
                root_for_body,
                &trust,
                json_output,
                crate::security_approval::ApprovalSource::CliFlag,
            )?;
            write_global_trust(root_for_body, &trust)?;
        }
        Ok(())
    })
    .await?;

    let origins = union_origins(&aggregate.rows);

    if json_output {
        let warning = if dry_run {
            format!(
                "DRY RUN — would bulk-approve {} globally-blocked package(s); no write performed",
                aggregate.rows.len()
            )
        } else {
            format!(
                "bulk-approved {} globally-blocked package(s) via --yes",
                aggregate.rows.len()
            )
        };
        // Per-package `provenance` block for every bulk-approved
        // row so the JSON envelope's audit trail matches the
        // project-side `--yes` path.
        let approved_entries: Vec<serde_json::Value> = aggregate
            .rows
            .iter()
            .map(|r| {
                let mut entry = serde_json::json!({
                    "name": r.name,
                    "version": r.version,
                    "integrity": r.integrity,
                    "script_hash": r.script_hash,
                });
                if let Some(status) =
                    provenance.get(&(r.name.clone(), r.version.clone(), r.integrity.clone()))
                {
                    let (verified, rejection_reason) = status.to_json_verified();
                    let mut prov = serde_json::Map::new();
                    prov.insert("verified".into(), verified);
                    if let Some(reason) = rejection_reason {
                        prov.insert("rejection_reason".into(), serde_json::Value::String(reason));
                    }
                    entry
                        .as_object_mut()
                        .unwrap()
                        .insert("provenance".into(), serde_json::Value::Object(prov));
                }
                entry
            })
            .collect();
        let mut body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "success": true,
            "command": "approve-scripts",
            "scope": "global",
            "dry_run": dry_run,
            "blocked_count": aggregate.rows.len(),
            "approved_count": aggregate.rows.len(),
            "skipped_count": 0,
            "approved": approved_entries,
            "warnings": [warning],
            "errors": [],
        });
        // `next_step` directs agents to run a follow-up command. Under
        // `--dry-run` no mutation happened, so emitting a follow-up
        // would mislead automation into reinstalling globals whose
        // approval was never persisted. Only emit on real writes.
        if !dry_run {
            body.as_object_mut()
                .unwrap()
                .insert("next_step".into(), rerun_next_step_json(&origins));
            body.as_object_mut()
                .unwrap()
                .insert("next_steps".into(), rerun_next_steps_json(&origins));
        }
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else if dry_run {
        output::warn(&format!(
            "DRY RUN — would bulk-approve {} globally-blocked package{}. No changes written.",
            aggregate.rows.len(),
            if aggregate.rows.len() == 1 { "" } else { "s" },
        ));
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
        emit_rerun_hint_stderr(&origins);
    }
    Ok(())
}

/// Named-package approval: `lpm approve-scripts --global esbuild` or
/// `--global esbuild@0.25.1`. Finds the matching row by name or
/// `name@version` substring, writes one trust binding under the global
/// tx lock.
///
/// **Lock order:** `store_lock` (outer shared, held by the parent
/// [`run_global_under_store_lock`]) → `global_tx_lock` (inner exclusive,
/// taken here). Do not invert.
pub(super) async fn run_global_named(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    arg: &str,
    dry_run: bool,
    json_output: bool,
    provenance_context: ApprovalProvenanceContext<'_>,
) -> Result<(), LpmError> {
    // Bare-name lookup must refuse silently-picking-first when multiple
    // rows match. Aggregate rows are deduped
    // by `(name, version, integrity, script_hash)` per the dedup rule,
    // so a single bare name can legitimately resolve to multiple rows
    // (same package at different versions, OR same name@version with
    // different tarball bindings across install roots). Silently
    // approving the first match is a latent data-corruption bug —
    // require `name@version` disambiguation.
    let row = match lookup_aggregate_by_arg(&aggregate.rows, arg) {
        AggregateLookup::Match(row) => row,
        AggregateLookup::NotFound => {
            if !aggregate.unreadable_origins.is_empty() {
                return Err(global_blocked_set_incomplete_error(
                    &aggregate.unreadable_origins,
                ));
            }
            return Err(LpmError::NotFound(format!(
                "package '{arg}' is not in the global blocked set. Run \
                 `lpm approve-scripts --global --list` to see what's blocked."
            )));
        }
        AggregateLookup::Ambiguous { candidates } => {
            // List the concrete name@version strings the user could
            // disambiguate with. Sorted + deduped so the hint is
            // deterministic regardless of row order.
            let mut keys: Vec<String> = candidates
                .iter()
                .map(|row| aggregate_artifact_selector(row))
                .collect();
            keys.sort();
            keys.dedup();
            return Err(LpmError::Script(format!(
                "package '{arg}' is ambiguous in the global blocked set — {} rows match. \
                 Re-run with an artifact-qualified candidate to disambiguate. Candidates: {}",
                candidates.len(),
                keys.join(", "),
            )));
        }
    };

    // fetch provenance OUTSIDE the tx lock so a slow
    // network response doesn't block parallel `--global` invocations.
    // SILENT-DROP fix: `?` propagates a verifier rejection
    // BEFORE acquiring the lock, leaving any prior binding intact.
    let pairs = vec![(row.name.clone(), row.version.clone(), row.integrity.clone())];
    let provenance = if dry_run {
        HashMap::new()
    } else {
        crate::provenance_fetch::fetch_provenance_for_artifacts(
            provenance_context.registry,
            &pairs,
            provenance_context.verify_policy,
        )
        .await
    };
    let snap = snapshot_for_artifact_binding(
        &provenance,
        &row.name,
        &row.version,
        row.integrity.as_deref(),
        provenance_context.runtime_enforce,
    )?;

    let lock_path = root.global_tx_lock();
    let root_for_body = root;
    let row_for_body = row;
    let snap_for_body = snap;
    lpm_common::with_exclusive_lock_async(lock_path, async move {
        let mut trust = lpm_global::trusted_deps::read_for(root_for_body)?;
        trust.insert_binding(
            &row_for_body.name,
            &row_for_body.version,
            lpm_global::TrustedDependencyBinding {
                integrity: row_for_body.integrity.clone(),
                script_hash: row_for_body.script_hash.clone(),
                provenance_at_approval: snap_for_body,
            },
        );
        if !dry_run {
            crate::security_approval::ensure_global_trust_candidate_authorized_from_trust(
                root_for_body,
                &trust,
                json_output,
                crate::security_approval::ApprovalSource::CliFlag,
            )?;
            write_global_trust(root_for_body, &trust)?;
        }
        Ok(())
    })
    .await?;

    // Origin enumeration uses the matched row's `origins`. Sorted +
    // deduped via `union_origins([row])` so the rendering is stable.
    let origins = union_origins(std::iter::once(row));

    if json_output {
        // Surface the per-package `provenance.verified` alongside
        // the existing identity fields. Derived from the same
        // `ProvenanceStatus` map the binding-write path consulted,
        // so the JSON envelope and the trust binding stay mutually
        // consistent.
        let mut approved_entry = serde_json::json!({
            "name": row.name,
            "version": row.version,
            "integrity": row.integrity,
            "script_hash": row.script_hash,
        });
        if let Some(status) =
            provenance.get(&(row.name.clone(), row.version.clone(), row.integrity.clone()))
        {
            let (verified, rejection_reason) = status.to_json_verified();
            let mut prov = serde_json::Map::new();
            prov.insert("verified".into(), verified);
            if let Some(reason) = rejection_reason {
                prov.insert("rejection_reason".into(), serde_json::Value::String(reason));
            }
            approved_entry
                .as_object_mut()
                .unwrap()
                .insert("provenance".into(), serde_json::Value::Object(prov));
        }
        let mut body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "success": true,
            "command": "approve-scripts",
            "scope": "global",
            "dry_run": dry_run,
            "approved_count": 1,
            "skipped_count": 0,
            "blocked_count": aggregate.rows.len(),
            "approved": [approved_entry],
            "warnings": [],
            "errors": [],
        });
        // Same dry-run contract as `run_global_bulk_yes`: omit
        // `next_step` when no mutation was performed.
        if !dry_run {
            body.as_object_mut()
                .unwrap()
                .insert("next_step".into(), rerun_next_step_json(&origins));
            body.as_object_mut()
                .unwrap()
                .insert("next_steps".into(), rerun_next_steps_json(&origins));
        }
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else if dry_run {
        output::info_line(install_ui::terminal_line!(
            "DRY RUN — would approve {} @ {} globally. No changes written.",
            install_ui::bold(&row.name),
            install_ui::dim(&row.version),
        ));
    } else {
        output::success_line(install_ui::terminal_line!(
            "Approved {} @ {} globally.",
            install_ui::bold(&row.name),
            install_ui::dim(&row.version),
        ));
        emit_rerun_hint_stderr(&origins);
    }
    Ok(())
}

/// Result of resolving a user-supplied `<pkg>` argument to an aggregate
/// row. Three outcomes:
///
/// - `Match` — exactly one row matches. Approve it.
/// - `NotFound` — zero rows match the given arg. Caller surfaces
///   NotFound with a hint toward `--list`.
/// - `Ambiguous` — a bare name or coordinate matched multiple rows.
///   Caller lists artifact-qualified candidates so the user can re-run
///   with `name@version#artifact-id` when a coordinate is not unique.
#[derive(Debug)]
pub(super) enum AggregateLookup<'a> {
    Match(&'a crate::global_blocked_set::AggregateBlockedRow),
    NotFound,
    Ambiguous {
        candidates: Vec<&'a crate::global_blocked_set::AggregateBlockedRow>,
    },
}

/// Resolve an arg to an `AggregateLookup`. Bare-name lookups collect all
/// matches instead of silently taking the first row.
pub(super) fn lookup_aggregate_by_arg<'a>(
    rows: &'a [crate::global_blocked_set::AggregateBlockedRow],
    arg: &str,
) -> AggregateLookup<'a> {
    let (coordinate_arg, artifact_qualifier) = arg
        .rsplit_once('#')
        .map_or((arg, None), |(coordinate, qualifier)| {
            (coordinate, (!qualifier.is_empty()).then_some(qualifier))
        });
    if let Some((name, version)) = coordinate_arg.rsplit_once('@')
        && !name.is_empty()
    {
        // name@version form: collect ALL matches (different bindings
        // across installs), not just the first. One match → Match;
        // multiple → Ambiguous; zero → NotFound.
        let matches: Vec<&crate::global_blocked_set::AggregateBlockedRow> = rows
            .iter()
            .filter(|row| {
                row.name == name
                    && row.version == version
                    && artifact_qualifier
                        .is_none_or(|qualifier| aggregate_artifact_matches(row, qualifier))
            })
            .collect();
        match matches.as_slice() {
            [] => AggregateLookup::NotFound,
            [single] => AggregateLookup::Match(single),
            _ => AggregateLookup::Ambiguous {
                candidates: matches,
            },
        }
    } else {
        if artifact_qualifier.is_some() {
            return AggregateLookup::NotFound;
        }
        // Bare name: collect ALL matches. Multiple = ambiguous.
        let matches: Vec<&crate::global_blocked_set::AggregateBlockedRow> =
            rows.iter().filter(|r| r.name == coordinate_arg).collect();
        match matches.as_slice() {
            [] => AggregateLookup::NotFound,
            [single] => AggregateLookup::Match(single),
            _ => AggregateLookup::Ambiguous {
                candidates: matches,
            },
        }
    }
}

fn aggregate_artifact_matches(
    row: &crate::global_blocked_set::AggregateBlockedRow,
    qualifier: &str,
) -> bool {
    row.integrity.as_deref() == Some(qualifier)
        || row.script_hash.as_deref() == Some(qualifier)
        || lpm_common::artifact_binding_id(row.integrity.as_deref(), row.script_hash.as_deref())
            == qualifier
}

fn aggregate_artifact_selector(row: &crate::global_blocked_set::AggregateBlockedRow) -> String {
    format!(
        "{}@{}#{}",
        row.name,
        row.version,
        lpm_common::artifact_binding_id(row.integrity.as_deref(), row.script_hash.as_deref(),),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct AggregateRowKey {
    name: String,
    version: String,
    integrity: Option<String>,
    script_hash: Option<String>,
}

impl AggregateRowKey {
    pub(super) fn from_row(row: &crate::global_blocked_set::AggregateBlockedRow) -> Self {
        Self {
            name: row.name.clone(),
            version: row.version.clone(),
            integrity: row.integrity.clone(),
            script_hash: row.script_hash.clone(),
        }
    }
}

pub(super) fn group_remaining_rows_by_origin<'a>(
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

pub(super) fn print_origin_group_card(
    origin: &str,
    rows: &[&crate::global_blocked_set::AggregateBlockedRow],
) {
    println!();
    println!(
        "{}",
        install_ui::terminal_line!(
            "  {} ({} blocked dep{}):",
            install_ui::bold(origin),
            rows.len(),
            if rows.len() == 1 { "" } else { "s" },
        )
    );
    for row in rows.iter().take(8) {
        let drift = if row.binding_drift {
            install_ui::terminal_line!("  {}", install_ui::yellow("[binding drift]"))
        } else {
            install_ui::TerminalLine::new("")
        };
        println!(
            "{}",
            install_ui::terminal_line!(
                "    {} @ {}{}",
                &row.name,
                install_ui::dim(&row.version),
                drift,
            )
        );
    }
    if rows.len() > 8 {
        println!("    {}", format!("+{} more", rows.len() - 8).dimmed());
    }
    println!();
}

pub(super) async fn commit_global_approval_batch(
    root: &lpm_common::LpmRoot,
    rows: &[&crate::global_blocked_set::AggregateBlockedRow],
    dry_run: bool,
    provenance_context: ApprovalProvenanceContext<'_>,
) -> Result<(), LpmError> {
    if dry_run || rows.is_empty() {
        return Ok(());
    }
    let snapshots = fetch_global_approval_snapshots(rows, provenance_context).await?;
    let lock_path = root.global_tx_lock();
    lpm_common::with_exclusive_lock_async(lock_path, async move {
        let mut trust = lpm_global::trusted_deps::read_for(root)?;
        for (row, snapshot) in rows.iter().zip(snapshots) {
            trust.insert_binding(
                &row.name,
                &row.version,
                lpm_global::TrustedDependencyBinding {
                    integrity: row.integrity.clone(),
                    script_hash: row.script_hash.clone(),
                    provenance_at_approval: snapshot,
                },
            );
        }
        crate::security_approval::ensure_global_trust_candidate_authorized_from_trust(
            root,
            &trust,
            false,
            crate::security_approval::ApprovalSource::CliFlag,
        )?;
        write_global_trust(root, &trust)
    })
    .await
}

async fn fetch_global_approval_snapshots(
    rows: &[&crate::global_blocked_set::AggregateBlockedRow],
    provenance_context: ApprovalProvenanceContext<'_>,
) -> Result<Vec<Option<lpm_common::ProvenanceSnapshot>>, LpmError> {
    let pairs: Vec<crate::provenance_fetch::ProvenanceArtifactKey> = rows
        .iter()
        .map(|row| (row.name.clone(), row.version.clone(), row.integrity.clone()))
        .collect();
    let provenance = crate::provenance_fetch::fetch_provenance_for_artifacts(
        provenance_context.registry,
        &pairs,
        provenance_context.verify_policy,
    )
    .await;
    rows.iter()
        .map(|row| {
            snapshot_for_artifact_binding(
                &provenance,
                &row.name,
                &row.version,
                row.integrity.as_deref(),
                provenance_context.runtime_enforce,
            )
        })
        .collect()
}

/// Interactive walk. Flat mode prompts one aggregate row at a time.
/// Grouped mode prompts by top-level global first, but still records
/// approvals as individual dependency binding rows.
///
pub(super) async fn run_global_interactive(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    group: bool,
    dry_run: bool,
    _json_output: bool,
    provenance_context: ApprovalProvenanceContext<'_>,
) -> Result<(), LpmError> {
    use crate::prompt::prompt_err;

    let mut approved: Vec<&crate::global_blocked_set::AggregateBlockedRow> = Vec::new();
    let mut skipped: Vec<&crate::global_blocked_set::AggregateBlockedRow> = Vec::new();
    let mut pending_approvals: Vec<&crate::global_blocked_set::AggregateBlockedRow> = Vec::new();

    println!();
    output::info_line(install_ui::terminal_line!(
        "Reviewing {} globally-blocked package{}. Ctrl+C to stop.",
        install_ui::bold(&aggregate.rows.len().to_string()),
        if aggregate.rows.len() == 1 { "" } else { "s" },
    ));
    println!();

    if group {
        let mut decided: std::collections::HashSet<AggregateRowKey> =
            std::collections::HashSet::new();
        let mut quit_early = false;

        let grouped = group_remaining_rows_by_origin(aggregate, &decided);
        'groups: for (origin, candidate_rows) in grouped {
            let rows: Vec<_> = candidate_rows
                .into_iter()
                .filter(|row| !decided.contains(&AggregateRowKey::from_row(row)))
                .collect();
            if rows.is_empty() {
                continue;
            }
            loop {
                print_origin_group_card(&origin, &rows);
                let prompt = install_ui::terminal_line!(
                    "How would you like to review blocked deps for {}?",
                    &origin,
                )
                .to_string();
                let choice = match cliclack::select(prompt)
                    .item("approve_all", "Approve all for this global", "")
                    .item("review", "Review individually", "")
                    .item("skip_all", "Skip all for now", "")
                    .item("quit", "Quit — stop here; approved rows kept", "")
                    .initial_value("review")
                    .interact()
                {
                    Ok(choice) => choice,
                    Err(error) => {
                        commit_global_approval_batch(
                            root,
                            &pending_approvals,
                            dry_run,
                            provenance_context,
                        )
                        .await?;
                        return Err(prompt_err(error));
                    }
                };

                match choice {
                    "approve_all" => {
                        // Tier-gate parity with `--yes`. If any row in
                        // THIS group carries a non-green tier, refuse the
                        // bulk-approve action: surface the same refusal
                        // error project --yes prints, then loop back to the
                        // same group's menu so the user explicitly re-
                        // chooses Review / Skip / Quit. Leaving the group's
                        // rows out of `decided` is what re-enters this
                        // group on the next loop iteration — flat-mode has
                        // no equivalent because flat-mode is already
                        // per-package review.
                        //
                        // The grouped approve-all shortcut must use the same
                        // tier gate as non-interactive global bulk approval.
                        if let Err(gate_err) = enforce_tiered_yes_gate(&rows, GateScope::Global) {
                            output::warn(&gate_err.to_string());
                            // Fall through to the loop tail; same group is
                            // re-displayed with the menu so the user can
                            // pick Review individually instead.
                            continue;
                        }
                        for row in &rows {
                            pending_approvals.push(*row);
                            approved.push(*row);
                            decided.insert(AggregateRowKey::from_row(row));
                        }
                        break;
                    }
                    "skip_all" => {
                        for row in &rows {
                            skipped.push(*row);
                            decided.insert(AggregateRowKey::from_row(row));
                        }
                        break;
                    }
                    "review" => {
                        for row in rows {
                            let key = AggregateRowKey::from_row(row);
                            if decided.contains(&key) {
                                continue;
                            }

                            print_aggregate_card(row);
                            let prompt = install_ui::terminal_line!(
                                "{} @ {} — approve?",
                                &row.name,
                                &row.version,
                            )
                            .to_string();
                            let row_choice = match cliclack::select(prompt)
                                .item("approve", "Approve", "")
                                .item("skip", "Skip", "")
                                .item("quit", "Quit — stop here; approved rows kept", "")
                                .initial_value("approve")
                                .interact()
                            {
                                Ok(choice) => choice,
                                Err(error) => {
                                    commit_global_approval_batch(
                                        root,
                                        &pending_approvals,
                                        dry_run,
                                        provenance_context,
                                    )
                                    .await?;
                                    return Err(prompt_err(error));
                                }
                            };

                            match row_choice {
                                "approve" => {
                                    pending_approvals.push(row);
                                    approved.push(row);
                                    decided.insert(key);
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
                        break;
                    }
                    "quit" => {
                        quit_early = true;
                        break;
                    }
                    _ => unreachable!(),
                }
            }
            if quit_early {
                break 'groups;
            }
        }

        commit_global_approval_batch(root, &pending_approvals, dry_run, provenance_context).await?;
        println!();
        if dry_run {
            output::info(&format!(
                "DRY RUN — would approve {}, skip {}, leave {} remaining. No changes written.",
                approved.len(),
                skipped.len(),
                aggregate.rows.len() - approved.len() - skipped.len(),
            ));
        } else if !approved.is_empty() {
            output::success(&format!(
                "{} approved, {} skipped, {} remaining.",
                approved.len(),
                skipped.len(),
                aggregate.rows.len() - approved.len() - skipped.len(),
            ));
            // Always emit the rerun hint when at least one row was
            // approved — `emit_rerun_hint_stderr` owns the empty-origins
            // fallback (actionable "run --list to see which globals were
            // affected" prose), so guarding here would silently drop
            // that fallback when an aggregate row arrives without
            // origins (defensive: shouldn't happen, but the hint is
            // load-bearing if it does).
            let origins = union_origins(approved.iter().copied());
            emit_rerun_hint_stderr(&origins);
        } else {
            output::success(&format!(
                "{} approved, {} skipped, {} remaining.",
                approved.len(),
                skipped.len(),
                aggregate.rows.len() - approved.len() - skipped.len(),
            ));
        }
        return Ok(());
    }

    // Flat interactive path: per-row review with explicit prompts.
    // No tier gate required here because each row is its own decision
    // point — there is no bulk action (parity with the grouped
    // `approve_all` shortcut which IS gated, and the project-level
    // interactive walk which is also per-row).
    for row in &aggregate.rows {
        print_aggregate_card(row);
        let prompt =
            install_ui::terminal_line!("{} @ {} — approve?", &row.name, &row.version).to_string();
        let choice = match cliclack::select(prompt)
            .item("approve", "Approve", "")
            .item("skip", "Skip", "")
            .item("quit", "Quit — stop here; approved rows kept", "")
            .initial_value("approve")
            .interact()
        {
            Ok(choice) => choice,
            Err(error) => {
                commit_global_approval_batch(root, &pending_approvals, dry_run, provenance_context)
                    .await?;
                return Err(prompt_err(error));
            }
        };

        match choice {
            "approve" => {
                pending_approvals.push(row);
                approved.push(row);
            }
            "skip" => skipped.push(row),
            "quit" => break,
            _ => unreachable!(),
        }
    }
    commit_global_approval_batch(root, &pending_approvals, dry_run, provenance_context).await?;
    println!();
    if dry_run {
        output::info(&format!(
            "DRY RUN — would approve {}, skip {}, leave {} remaining. No changes written.",
            approved.len(),
            skipped.len(),
            aggregate.rows.len() - approved.len() - skipped.len(),
        ));
    } else if !approved.is_empty() {
        output::success(&format!(
            "{} approved, {} skipped, {} remaining.",
            approved.len(),
            skipped.len(),
            aggregate.rows.len() - approved.len() - skipped.len(),
        ));
        let origins = union_origins(approved.iter().copied());
        emit_rerun_hint_stderr(&origins);
    } else {
        output::success(&format!(
            "{} approved, {} skipped, {} remaining.",
            approved.len(),
            skipped.len(),
            aggregate.rows.len() - approved.len() - skipped.len(),
        ));
    }
    Ok(())
}

pub(super) fn print_aggregate_card(row: &crate::global_blocked_set::AggregateBlockedRow) {
    let drift = if row.binding_drift {
        install_ui::terminal_line!("  {}", install_ui::yellow("[binding drift]"))
    } else {
        install_ui::TerminalLine::new("")
    };
    println!(
        "{}",
        install_ui::terminal_line!(
            "  {} @ {}{}",
            install_ui::bold(&row.name),
            install_ui::dim(&row.version),
            drift,
        )
    );
    println!(
        "{}",
        install_ui::terminal_line!(
            "    phases: {}",
            install_ui::dim(&row.phases_present.join(", ")),
        )
    );
    println!(
        "{}",
        install_ui::terminal_line!("    origins: {}", install_ui::dim(&row.origins.join(", ")),)
    );
    if let Some(integ) = &row.integrity {
        println!(
            "{}",
            install_ui::terminal_line!("    integrity: {}", install_ui::dim(integ))
        );
    }
    if let Some(sh) = &row.script_hash {
        println!(
            "{}",
            install_ui::terminal_line!("    script_hash: {}", install_ui::dim(sh))
        );
    }
    println!();
}
