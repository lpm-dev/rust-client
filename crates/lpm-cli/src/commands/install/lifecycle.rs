use super::*;

/// Decide whether `lpm install` should auto-fire `rebuild::run` after
/// the install completes.
///
/// Triggers (any one is sufficient):
/// - `--auto-build` CLI flag.
/// - `lpm.scripts.autoBuild: true` in package.json.
/// - All packages with unbuilt scripts are individually trusted (per
///   strict binding / scope trust / capability gate). Triage policy
///   green-tier promotion lands here via `evaluate_trust`.
/// - `effective_policy == ScriptPolicy::Allow`. The user
///   explicitly opted into "run all lifecycle scripts" via `--yolo`,
///   `--policy=allow`, `package.json > lpm > scriptPolicy = "allow"`,
///   or `~/.lpm/config.toml > script-policy = "allow"`. Requiring a
///   second `--auto-build` flag would be redundant ceremony after the
///   user already consented via `--policy=allow`.
///
/// Triage policy is unchanged: greens auto-trust via `evaluate_trust`
/// and ride the `all_trusted` path; ambers/reds still require explicit
/// `--auto-build` or `lpm approve-scripts` review. That asymmetry is
/// intentional — Triage's gate IS the safety mechanism, and "run
/// greens automatically without an explicit second consent" is the
/// existing semantic that ships.
pub(super) fn should_auto_build(
    auto_build_flag: bool,
    config_auto_build: bool,
    all_trusted: bool,
    effective_policy: crate::script_policy_config::ScriptPolicy,
) -> bool {
    auto_build_flag
        || config_auto_build
        || all_trusted
        || effective_policy == crate::script_policy_config::ScriptPolicy::Allow
}

/// Decide what advisor
/// approval view (if any) should be forwarded to
/// [`crate::build_state::capture_blocked_set_after_install_with_metadata`].
///
/// Why this is its own function rather than an inline ternary:
///
/// The advisor's `Approve` verdict has two coupled effects in an
/// install — (1) the package's scripts execute via the
/// `AdvisorApprovedThisRun` trust path during autoBuild, and (2) the
/// package is omitted from the persisted blocked set so post-install
/// messaging + `lpm approve-scripts` don't report stale "still
/// blocked" state. Effect (2) is only correct when (1) actually
/// fires.
///
/// In a mixed-triage install where the advisor approves package A
/// but leaves package B blocked, with `--auto-build=false` and
/// `lpm.scripts.autoBuild=false`, `all_trusted` is false →
/// `auto_build_attempted` is false → no scripts run, AND A vanishes
/// from `build-state.json` → no path back through
/// `approve-scripts`. The user is left with "not executed, not
/// reviewable" — a stranded approval. This helper closes that hole.
///
/// Returns the input view unchanged when autoBuild will actually
/// execute approved scripts this run. Otherwise returns `None`, so
/// approved-but-not-run packages stay in the blocked set and remain
/// reviewable on a later `lpm approve-scripts` invocation. (The
/// ephemeral approval set itself is discarded at end of run — by
/// design.)
///
/// Takes the borrowed approvals view directly (rather than the full
/// `AdvisorSession`) so the install caller can compose:
/// `select_approvals_for_capture(auto_build_attempted,
/// advisor_session.as_ref().map(|s| s.approvals()))`, and tests can
/// pass a hand-built `HashSet` without constructing a real session.
pub(super) fn select_approvals_for_capture(
    auto_build_attempted: bool,
    approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> Option<&std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>> {
    if auto_build_attempted {
        approvals
    } else {
        None
    }
}

/// — decision half of the post-auto-build
/// canonical pointer. Pure — returns the message string to emit, or
/// `None` when no pointer should fire. I/O lives in
/// [`maybe_emit_post_auto_build_triage_pointer`] below.
///
/// Gates (all must be true for a Some): (a) auto-build was actually
/// attempted this run — a falsy predicate + `autoBuild: false` path
/// never triggered `rebuild::run` and a pointer would misrepresent
/// what happened; (b) `effective_policy` is
/// [`crate::script_policy_config::ScriptPolicy::Triage`] — deny /
/// allow keep pre- UX, with deny routing users through the
/// pre-auto-build blocked hint and allow running everything (no
/// blocked set in the canonical case); (c) `json_output` is false —
/// JSON mode's channel is the per-entry `static_tier` enrichment in
/// the `blocked_packages` array, so a stdout line would muddle that
/// contract for agents; (d) `amber + red` count in the pre-auto-build
/// capture is > 0 — if every blocked entry was green, the auto-build
/// path built them all and nothing remains to review.
///
/// Counts come from the blocked set captured BEFORE auto-build ran.
/// Under autoBuild+triage, the predicate trusts green+strict+scope
/// entries, so the packages whose `.lpm-built` marker will NOT exist
/// after auto-build are exactly the amber + red tier entries. This
/// avoids a post-auto-build FS scan.
pub(super) fn compute_post_auto_build_triage_pointer(
    auto_build_attempted: bool,
    effective_policy: crate::script_policy_config::ScriptPolicy,
    blocked_capture: &crate::build_state::BlockedSetCapture,
    json_output: bool,
) -> Option<String> {
    if !auto_build_attempted {
        return None;
    }
    if effective_policy != crate::script_policy_config::ScriptPolicy::Triage {
        return None;
    }
    if json_output {
        return None;
    }
    let (_green, amber, red) =
        crate::build_state::count_blocked_by_tier(&blocked_capture.state.blocked_packages);
    let remaining = amber + red;
    if remaining == 0 {
        return None;
    }
    Some(format!(
        "{remaining} package(s) remain blocked after auto-build \
         ({amber} amber, {red} red). Run `lpm approve-scripts` to review."
    ))
}

/// — I/O half. See
/// [`compute_post_auto_build_triage_pointer`] for the decision
/// contract.
pub(super) fn maybe_emit_post_auto_build_triage_pointer(
    auto_build_attempted: bool,
    effective_policy: crate::script_policy_config::ScriptPolicy,
    blocked_capture: &crate::build_state::BlockedSetCapture,
    json_output: bool,
) {
    if let Some(msg) = compute_post_auto_build_triage_pointer(
        auto_build_attempted,
        effective_policy,
        blocked_capture,
        json_output,
    ) {
        output::warn(&msg);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn maybe_emit_post_install_lifecycle_hint(
    lpm_root: &lpm_common::LpmRoot,
    packages: &[InstallPackage],
    policy: &lpm_security::SecurityPolicy,
    project_dir: &Path,
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    blocked_capture: &crate::build_state::BlockedSetCapture,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output || !blocked_capture.should_emit_warning {
        return Ok(());
    }

    if blocked_capture.all_clear_banner {
        output::success(
            "All previously-blocked packages have been approved. Run `lpm rebuild` to execute their scripts.",
        );
        return Ok(());
    }

    let script_policy_cfg =
        crate::script_policy_config::ScriptPolicyConfig::from_package_json(project_dir);
    let effective_policy = crate::script_policy_config::resolve_script_policy_with_security(
        project_dir,
        script_policy_override,
        &script_policy_cfg,
        json_output,
    )?;

    match effective_policy {
        crate::script_policy_config::ScriptPolicy::Triage => {
            println!();
            println!(
                "{}",
                crate::build_state::format_triage_summary_line(
                    &blocked_capture.state.blocked_packages
                )
            );
        }
        crate::script_policy_config::ScriptPolicy::Allow => {}
        crate::script_policy_config::ScriptPolicy::Deny => {
            let all_pkgs: Vec<crate::build_state::InstalledPackageIdentity> = packages
                .iter()
                .map(|p| {
                    crate::build_state::InstalledPackageIdentity::new(
                        p.name.clone(),
                        p.version.clone(),
                        Some(p.source.clone()),
                        p.integrity.clone(),
                    )
                })
                .collect();
            crate::commands::rebuild::show_install_build_hint(
                lpm_root,
                &all_pkgs,
                policy,
                project_dir,
                requested_capabilities,
                user_bound,
            );
            output::info(
                "Run `lpm approve-scripts` to review and approve their lifecycle scripts.",
            );
        }
    }

    maybe_emit_post_install_version_diff_hints(project_dir, blocked_capture, json_output);
    Ok(())
}

pub(super) struct OnlineLifecyclePrepareInput<'a> {
    pub(super) client: &'a lpm_registry::RegistryClient,
    pub(super) route_table: &'a RouteTable,
    pub(super) project_dir: &'a Path,
    pub(super) packages: &'a [InstallPackage],
    pub(super) materialized_packages: &'a [lpm_linker::MaterializedPackage],
    pub(super) package: &'a lpm_workspace::PackageJson,
    pub(super) store: &'a lpm_store::PackageStore,
    pub(super) used_lockfile: bool,
    pub(super) script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    pub(super) advisor_override: Option<&'a str>,
    pub(super) global_config: &'a crate::commands::config::GlobalConfig,
    pub(super) publish_ages: &'a HashMap<(String, String), u64>,
    pub(super) min_release_age_secs: u64,
    pub(super) auto_build: bool,
    pub(super) json_output: bool,
    pub(super) lpm_root: &'a lpm_common::LpmRoot,
}

pub(super) struct OnlineLifecyclePrepareResult {
    pub(super) policy: lpm_security::SecurityPolicy,
    pub(super) installed_with_integrity: Vec<crate::build_state::InstalledPackageIdentity>,
    pub(super) blocked_set_metadata: crate::build_state::BlockedSetMetadata,
    pub(super) requested_capabilities: crate::capability::CapabilitySet,
    pub(super) user_bound: crate::capability::UserBound,
    pub(super) effective_policy: crate::script_policy_config::ScriptPolicy,
    pub(super) advisor_session: Option<crate::triage_advisor_session::AdvisorSession>,
    pub(super) auto_build_attempted: bool,
    pub(super) blocked_capture: crate::build_state::BlockedSetCapture,
    pub(super) blocked_metadata_ms: u128,
    pub(super) trust_snapshot_ms: u128,
}

pub(super) async fn run_online_lifecycle_prepare_phase(
    input: OnlineLifecyclePrepareInput<'_>,
) -> Result<OnlineLifecyclePrepareResult, LpmError> {
    let OnlineLifecyclePrepareInput {
        client,
        route_table,
        project_dir,
        packages,
        materialized_packages,
        package,
        store,
        used_lockfile,
        script_policy_override,
        advisor_override,
        global_config,
        publish_ages,
        min_release_age_secs,
        auto_build,
        json_output,
        lpm_root,
    } = input;

    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
    let installed_with_integrity: Vec<crate::build_state::InstalledPackageIdentity> = packages
        .iter()
        .map(|p| {
            crate::build_state::InstalledPackageIdentity::new(
                p.name.clone(),
                p.version.clone(),
                Some(p.source.clone()),
                p.integrity.clone(),
            )
        })
        .collect();

    let blocked_metadata_start = std::time::Instant::now();
    let mut blocked_metadata_ms = 0u128;
    let blocked_set_metadata = if used_lockfile {
        let metadata = blocked_set_metadata_from_previous_state(project_dir, packages);
        tracing::debug!(
            "perf.reuse_blocked_set_metadata pkgs={} entries={} ms={}",
            packages.len(),
            metadata.by_pkg.len(),
            blocked_metadata_start.elapsed().as_millis()
        );
        metadata
    } else {
        let metadata = lpm_registry::timing::with_metadata_purpose(
            lpm_registry::timing::MetadataPurpose::BlockedSet,
            build_blocked_set_metadata(client, route_table, packages),
        )
        .await;
        blocked_metadata_ms = blocked_metadata_start.elapsed().as_millis();
        tracing::debug!(
            "perf.build_blocked_set_metadata pkgs={} ms={}",
            packages.len(),
            blocked_metadata_ms
        );
        metadata
    };

    let requested_capabilities =
        crate::capability::CapabilitySet::from_package_json(&project_dir.join("package.json"))
            .map_err(|e| LpmError::Registry(format!("{e}")))?;
    let user_bound = crate::security_approval::authorized_capability_user_bound();

    let script_policy_cfg =
        crate::script_policy_config::ScriptPolicyConfig::from_package_json(project_dir);
    let config_auto_build = script_policy_cfg.auto_build;
    let effective_policy = crate::script_policy_config::resolve_script_policy_with_security(
        project_dir,
        script_policy_override,
        &script_policy_cfg,
        json_output,
    )?;

    let advisor_session = if effective_policy == crate::script_policy_config::ScriptPolicy::Triage {
        let triage_advisor_pkg_json = script_policy_cfg.triage_advisor.as_deref();
        let triage_advisor_global = global_config.get_str("triage-advisor");
        let mut session = crate::triage_advisor_session::AdvisorSession::preflight(
            advisor_override,
            triage_advisor_pkg_json,
            triage_advisor_global,
            json_output,
        )
        .await;
        if session.is_active() {
            let baseline_index = if lpm_store::StoreVersion::from_env().is_v2() {
                Some(lpm_store::V2BaselineIndex::for_project(
                    project_dir,
                    lpm_root,
                )?)
            } else {
                None
            };
            let amber_requests = collect_amber_classification_requests(
                &installed_with_integrity,
                materialized_packages,
                baseline_index.as_ref(),
                publish_ages,
                min_release_age_secs,
            );
            session.classify_amber(&amber_requests).await;
        }
        Some(session)
    } else {
        None
    };

    let force_security_floor = global_config
        .get_bool("force-security-floor")
        .unwrap_or(false);
    let all_trusted_for_auto_build =
        crate::commands::rebuild::all_scripted_package_identities_trusted(
            lpm_root,
            lpm_store::StoreVersion::from_env(),
            &installed_with_integrity,
            &policy,
            project_dir,
            effective_policy,
            force_security_floor,
            &requested_capabilities,
            &user_bound,
            advisor_session.as_ref().map(|s| s.approvals()),
        );
    let auto_build_attempted = should_auto_build(
        auto_build,
        config_auto_build,
        all_trusted_for_auto_build,
        effective_policy,
    );
    let auto_build_will_execute = auto_build_attempted && !script_policy_cfg.deny_all;

    let capture_start = std::time::Instant::now();
    let blocked_capture =
        crate::build_state::capture_blocked_set_after_install_with_metadata_for_identities(
            project_dir,
            store,
            &installed_with_integrity,
            &policy,
            &blocked_set_metadata,
            &requested_capabilities,
            &user_bound,
            select_approvals_for_capture(
                auto_build_will_execute,
                advisor_session.as_ref().map(|s| s.approvals()),
            ),
        )?;
    tracing::debug!(
        "perf.capture_blocked_set pkgs={} ms={}",
        installed_with_integrity.len(),
        capture_start.elapsed().as_millis()
    );

    let trust_snap_start = std::time::Instant::now();
    let snap = crate::trust_snapshot::TrustSnapshot::capture_current(package.lpm.as_ref().map_or(
        &lpm_workspace::TrustedDependencies::Legacy(Vec::new()),
        |l| &l.trusted_dependencies,
    ));
    if let Err(e) = crate::trust_snapshot::write_snapshot(project_dir, &snap) {
        tracing::warn!("failed to write trust-snapshot.json: {e}");
    }
    let trust_snapshot_ms = trust_snap_start.elapsed().as_millis();
    tracing::debug!("perf.trust_snapshot ms={}", trust_snapshot_ms);

    Ok(OnlineLifecyclePrepareResult {
        policy,
        installed_with_integrity,
        blocked_set_metadata,
        requested_capabilities,
        user_bound,
        effective_policy,
        advisor_session,
        auto_build_attempted,
        blocked_capture,
        blocked_metadata_ms,
        trust_snapshot_ms,
    })
}

pub(super) struct OnlineAutoBuildPhaseInput<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) packages: &'a [InstallPackage],
    pub(super) link_targets: &'a [LinkTarget],
    pub(super) package_name: Option<&'a str>,
    pub(super) store: &'a lpm_store::PackageStore,
    pub(super) lpm_root: &'a lpm_common::LpmRoot,
    pub(super) object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
    pub(super) linker_mode: lpm_linker::LinkerMode,
    pub(super) compatibility_bin_names: &'a [String],
    pub(super) json_output: bool,
    pub(super) no_sandbox: bool,
    pub(super) strict_sandbox: bool,
    pub(super) auto_build_attempted: bool,
    pub(super) effective_policy: crate::script_policy_config::ScriptPolicy,
    pub(super) advisor_session: Option<&'a crate::triage_advisor_session::AdvisorSession>,
    pub(super) blocked_capture: crate::build_state::BlockedSetCapture,
    pub(super) installed_with_integrity: &'a [crate::build_state::InstalledPackageIdentity],
    pub(super) policy: &'a lpm_security::SecurityPolicy,
    pub(super) blocked_set_metadata: &'a crate::build_state::BlockedSetMetadata,
    pub(super) requested_capabilities: &'a crate::capability::CapabilitySet,
    pub(super) user_bound: &'a crate::capability::UserBound,
}

pub(super) struct OnlineAutoBuildPhaseResult {
    pub(super) blocked_capture: crate::build_state::BlockedSetCapture,
    pub(super) bin_linked: Option<usize>,
}

pub(super) async fn run_online_auto_build_phase(
    input: OnlineAutoBuildPhaseInput<'_>,
) -> Result<OnlineAutoBuildPhaseResult, LpmError> {
    let OnlineAutoBuildPhaseInput {
        project_dir,
        packages,
        link_targets,
        package_name,
        store,
        lpm_root,
        object_integrity_policy,
        linker_mode,
        compatibility_bin_names,
        json_output,
        no_sandbox,
        strict_sandbox,
        auto_build_attempted,
        effective_policy,
        advisor_session,
        mut blocked_capture,
        installed_with_integrity,
        policy,
        blocked_set_metadata,
        requested_capabilities,
        user_bound,
    } = input;

    if auto_build_attempted {
        maybe_emit_pre_autobuild_version_diff_cards(
            project_dir,
            store,
            lpm_root,
            lpm_store::StoreVersion::from_env(),
            effective_policy,
            &blocked_capture,
            json_output,
        );
    }

    let mut auto_build_report = crate::commands::rebuild::RebuildRunReport::default();
    if auto_build_attempted {
        match crate::commands::rebuild::run_under_store_lock(
            project_dir,
            &[],
            false,
            false,
            false,
            None,
            json_output,
            false,
            no_sandbox,
            strict_sandbox,
            false,
            effective_policy,
            advisor_session.map(|s| s.approvals()),
        )
        .await
        {
            Ok(report) => {
                auto_build_report = report;
            }
            Err(e) => {
                if !json_output {
                    output::warn(&format!("Auto-build failed: {e}"));
                }
                return Err(e);
            }
        }
    }

    if auto_build_report.covered_any_packages() {
        let execution_exclusions = auto_build_report
            .covered_packages
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        blocked_capture =
            crate::build_state::capture_blocked_set_after_install_with_metadata_for_identities_and_exclusions(
                project_dir,
                store,
                lpm_store::StoreVersion::from_env(),
                installed_with_integrity,
                policy,
                blocked_set_metadata,
                requested_capabilities,
                user_bound,
                select_approvals_for_capture(true, advisor_session.map(|s| s.approvals())),
                Some(&execution_exclusions),
            )?;
    }

    let bin_linked =
        if auto_build_report.covered_any_packages() || auto_build_report.built_any_packages() {
            Some(relink_bins_after_lifecycle_build(
                project_dir,
                packages,
                link_targets,
                linker_mode,
                lpm_root,
                object_integrity_policy,
                package_name,
                compatibility_bin_names,
            )?)
        } else {
            None
        };

    maybe_emit_post_auto_build_triage_pointer(
        auto_build_attempted,
        effective_policy,
        &blocked_capture,
        json_output,
    );

    Ok(OnlineAutoBuildPhaseResult {
        blocked_capture,
        bin_linked,
    })
}

/// Compute per-package terse version-diff
/// hints for the post-install blocked-set warning.
///
/// Iterates `blocked_capture.state.blocked_packages`; for each entry
/// whose prior-approved binding exists under the same package name
/// (via [`lpm_workspace::TrustedDependencies::latest_binding_for_name`]),
/// computes the diff and renders a terse one-liner. Skips entries
/// with no prior binding (first-time review — nothing to diff
/// against) and entries whose reason is
/// [`crate::version_diff::VersionDiffReason::NoChange`].
///
/// Pure: no I/O. Returned `Vec<String>` lines are ready for a
/// stderr emitter. Entries are in `blocked_packages` order
/// (already sorted by `(name, version)` — see
/// [`crate::build_state::compute_blocked_packages_with_metadata`]).
pub(super) fn compute_post_install_version_diff_hints(
    blocked_capture: &crate::build_state::BlockedSetCapture,
    trusted: &lpm_workspace::TrustedDependencies,
) -> Vec<String> {
    let mut hints = Vec::new();
    for bp in &blocked_capture.state.blocked_packages {
        let Some((prior_version, binding)) =
            trusted.latest_binding_for_candidate(&bp.name, &bp.version, bp.source.as_deref())
        else {
            continue;
        };
        let diff = crate::version_diff::compute_version_diff(prior_version, binding, bp);
        if let Some(line) = crate::version_diff::render_terse_hint(&diff, &bp.name) {
            hints.push(line);
        }
    }
    hints
}

/// Emit the per-package version-diff
/// hints from [`compute_post_install_version_diff_hints`] to stderr
/// beneath the existing post-install blocked-set warning.
///
/// Suppressed under `json_output=true` (C4 will enrich the JSON
/// shape with a structured `version_diff` object per entry; the
/// human lines on stdout would break `JSON.parse` on the machine
/// channel — same stream-separation discipline as structured JSON output).
///
/// Reads `trustedDependencies` from `<project_dir>/package.json`.
/// Fails gracefully on I/O / parse error: the diff hints are a
/// UX enrichment, not a gate, so a missing or malformed manifest
/// just suppresses them rather than failing the install.
pub(super) fn maybe_emit_post_install_version_diff_hints(
    project_dir: &Path,
    blocked_capture: &crate::build_state::BlockedSetCapture,
    json_output: bool,
) {
    if json_output {
        return;
    }
    if blocked_capture.state.blocked_packages.is_empty() {
        return;
    }
    let Some(trusted) = read_trusted_deps_from_manifest(project_dir) else {
        return;
    };
    let hints = compute_post_install_version_diff_hints(blocked_capture, &trusted);
    if hints.is_empty() {
        return;
    }
    // Stream-separation: stderr for human output. Matches the
    // fix (`eprintln!`) so `--json` consumers never see the
    // hints interleaved with machine output.
    eprintln!();
    eprintln!("  Changes since prior approval:");
    for line in &hints {
        eprintln!("{line}");
    }
}

/// For greens about to
/// auto-execute under `script-policy = "triage"` + `autoBuild: true`,
/// emit a unified-diff preflight card before any script runs.
///
/// Gates (all must be true):
/// - `auto_build_attempted`: the auto-build path is actually running
///   (if `rebuild::run` isn't about to fire, a preflight is premature).
/// - `effective_policy` is
///   [`crate::script_policy_config::ScriptPolicy::Triage`]:
///   under `deny` nothing auto-executes, under `allow` every
///   scripted package runs (the "manual install then `lpm rebuild`"
///   flow that C3's TUI covers more fully).
/// - `!json_output`: human cards on stdout would corrupt the JSON
///   channel. Machine output routes through C4's `version_diff`
///   object in the blocked-set JSON.
///
/// Iterates `blocked_capture.state.blocked_packages` and renders a
/// preflight card for each entry that (a) classifies as `Green` tier
/// (under triage+autoBuild, greens are what `rebuild::run` auto-
/// promotes and executes per), and (b) has a prior binding for a
/// strictly-lesser version via `latest_binding_for_name`. Under (a)
/// the script will auto-execute imminently; under (b) there's
/// something to diff against.
///
/// Reads store bodies for both sides via their active store layout.
/// V2 resolves the candidate from the current project's exact link
/// identity and the prior version from the exact source/content
/// identity retained in the v2 cache. V1 uses its coordinate-keyed
/// legacy package directory. Missing prior bytes degrade to the
/// renderer's "prior not in store" note.
pub(super) fn maybe_emit_pre_autobuild_version_diff_cards(
    project_dir: &Path,
    store: &lpm_store::PackageStore,
    lpm_root: &lpm_common::LpmRoot,
    store_version: lpm_store::StoreVersion,
    effective_policy: crate::script_policy_config::ScriptPolicy,
    blocked_capture: &crate::build_state::BlockedSetCapture,
    json_output: bool,
) {
    if effective_policy != crate::script_policy_config::ScriptPolicy::Triage {
        return;
    }
    if json_output {
        return;
    }
    let Some(trusted) = read_trusted_deps_from_manifest(project_dir) else {
        return;
    };
    let mut v2_indices_built = false;
    let mut current_v2_index = None;
    let mut cached_v2_index = None;

    let mut cards: Vec<String> = Vec::new();
    for bp in &blocked_capture.state.blocked_packages {
        // Only greens auto-execute under triage+autoBuild per; the
        // preflight card is scoped to that execution path because
        // amber/red will route through approve-scripts (C3) where the
        // full card renders anyway. Entries with `static_tier = None`
        // are treated as non-green (same conservative bias as the
        // `--yes` refusal gate: unknown tier → don't claim the
        // auto-execute path).
        if !matches!(
            bp.static_tier,
            Some(lpm_security::triage::StaticTier::Green)
        ) {
            continue;
        }
        let Some((prior_version, binding)) =
            trusted.latest_binding_for_candidate(&bp.name, &bp.version, bp.source.as_deref())
        else {
            continue;
        };
        let diff = crate::version_diff::compute_version_diff(prior_version, binding, bp);
        if !diff.is_drift() {
            continue;
        }

        if store_version.is_v2() && !v2_indices_built {
            current_v2_index = lpm_store::V2BaselineIndex::for_project(project_dir, lpm_root).ok();
            cached_v2_index = lpm_store::V2BaselineIndex::build(lpm_root).ok();
            v2_indices_built = true;
        }
        let (candidate_pkg_dir, prior_pkg_dir) = if store_version.is_v2() {
            (
                current_v2_index.as_ref().and_then(|index| {
                    v2_preflight_package_dir(
                        index,
                        &bp.name,
                        &bp.version,
                        bp.source.as_deref(),
                        bp.integrity.as_deref(),
                    )
                }),
                cached_v2_index.as_ref().and_then(|index| {
                    v2_preflight_package_dir(
                        index,
                        &bp.name,
                        prior_version,
                        binding.source.as_deref(),
                        binding.integrity.as_deref(),
                    )
                }),
            )
        } else {
            (
                Some(store.package_dir(&bp.name, &bp.version)),
                Some(store.package_dir(&bp.name, prior_version)),
            )
        };
        let candidate_pairs = candidate_pkg_dir.map_or_else(Vec::new, |dir| {
            crate::build_state::read_install_phase_bodies(&dir)
        });
        let prior_pairs = prior_pkg_dir.map_or_else(Vec::new, |dir| {
            crate::build_state::read_install_phase_bodies(&dir)
        });
        let prior_bodies = if prior_pairs.is_empty() {
            // Empty-vec result collapses two real cases: (a) prior
            // store dir missing entirely (cache clean / fresh clone),
            // and (b) prior version had no scripts. Case (b) still
            // wouldn't produce script-hash drift because the hash
            // would be None on that side; we only reach this emitter
            // when `diff.is_drift()` is true, so an empty prior here
            // is effectively "prior not in store." Degrade to None
            // so the renderer uses its "prior not in store" note.
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
            &bp.name,
            prior_bodies.as_ref(),
            candidate_bodies.as_ref(),
        ) {
            cards.push(card);
        }
    }

    if cards.is_empty() {
        return;
    }
    // Stream-separation: stderr (same discipline as the post-install
    // hints). The "PREFLIGHT" tag makes the block grep-able and
    // distinguishes it from the post-install warning above.
    eprintln!();
    eprintln!("  PREFLIGHT — auto-build will execute the following green-tier scripts:");
    for card in &cards {
        eprintln!();
        eprintln!("{card}");
    }
    eprintln!();
}

fn v2_preflight_package_dir(
    index: &lpm_store::V2BaselineIndex,
    name: &str,
    version: &str,
    source: Option<&str>,
    expected_integrity: Option<&str>,
) -> Option<PathBuf> {
    let baseline = match source {
        Some(source) => {
            let source_id = lpm_lockfile::Source::parse(source)
                .ok()?
                .source_id_with_integrity(expected_integrity);
            index.lookup_source_identity(name, version, &source_id)
        }
        None => index.lookup(name, version, expected_integrity),
    }?;
    if expected_integrity.is_some_and(|expected| expected != baseline.integrity.as_str()) {
        return None;
    }
    Some(baseline.package_dir.clone())
}

/// Read `trustedDependencies` from the
/// project manifest without failing the install on malformed input.
///
/// Returns `None` on any failure (missing file, unreadable,
/// malformed JSON, absent key). Callers treat `None` as "no prior
/// approvals to diff against" — the enrichment is UX, not a
/// gate, so the install pipeline must be tolerant.
///
/// Reuses the same parsing shape the `approve_builds` command uses
/// so a drifted or upgraded manifest still yields the same view.
pub(super) fn read_trusted_deps_from_manifest(
    project_dir: &Path,
) -> Option<lpm_workspace::TrustedDependencies> {
    let pkg_json_path = project_dir.join("package.json");
    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let manifest: serde_json::Value = serde_json::from_str(&content).ok()?;
    // `trustedDependencies` sits under `lpm.trustedDependencies` per
    // the manifest schema; also accept it at the top level for
    // leniency against older package.json shapes the test suite
    // fixtures might use.
    let raw = manifest
        .get("lpm")
        .and_then(|lpm| lpm.get("trustedDependencies"))
        .or_else(|| manifest.get("trustedDependencies"))?;
    serde_json::from_value::<lpm_workspace::TrustedDependencies>(raw.clone()).ok()
}

/// build the metadata map that
/// enriches [`crate::build_state::BlockedPackage`] entries with
/// `published_at` (RFC 3339) and `behavioral_tags_hash` (SHA-256 over
/// the sorted set of active behavioral tags).
///
/// Fetches registry metadata via the existing client API which is
/// backed by a 5-min TTL cache. On fresh resolutions the resolver
/// already populated that cache, so this is a memory-local lookup.
/// On offline installs or registry-unreachable installs, fetches
/// return `Err`; we silently drop those packages from the map and
/// the captured fields stay `None` — documented graceful
/// degradation (see [`crate::build_state::BlockedSetMetadata`]).
///
/// Walk the install set, classify every
/// lifecycle script through Layer 1, and emit one
/// [`crate::triage_advisor_session::AmberPackageRequest`] per
/// package that has at least one amber phase. Green-only packages
/// auto-run via the existing GreenTierUnderTriage path and don't
/// need an advisor call; red-only packages are hard-blocked
/// regardless of the advisor; packages with no scripts have nothing
/// to advise on.
///
/// Mirrors the worst-of reduction in
/// [`crate::build_state::compute_blocked_packages_with_metadata`]
/// and the rebuild trust evaluator so the advisor pass agrees with
/// both downstream consumers on which packages are amber-eligible.
pub(super) fn collect_amber_classification_requests(
    packages: &[crate::build_state::InstalledPackageIdentity],
    materialized_packages: &[lpm_linker::MaterializedPackage],
    baseline_index: Option<&lpm_store::V2BaselineIndex>,
    publish_ages: &std::collections::HashMap<(String, String), u64>,
    min_release_age_secs: u64,
) -> Vec<crate::triage_advisor_session::AmberPackageRequest> {
    use lpm_security::static_gate::ManifestContext;
    use lpm_security::triage::StaticTier;
    let mut out = Vec::new();
    for identity in packages {
        let name = &identity.name;
        let version = &identity.version;
        let integrity = &identity.integrity;
        let Some(pkg_dir) = advisor_package_dir(identity, materialized_packages, baseline_index)
        else {
            continue;
        };
        let bodies = crate::build_state::read_install_phase_bodies(&pkg_dir);
        if bodies.is_empty() {
            continue;
        }
        // Read the package's `repository` URL from the same store package.json.
        // It feeds both the advisor prompt and the classifier widening that
        // converts delegate-to-local-file + matching identity into Green.
        //
        // Feed the package's publish age + the configured
        // `minimum_release_age_secs` into the classifier context so
        // identity-match widening can apply
        // the cooldown defense-in-depth (refuses to widen recent
        // publishes even when `--allow-new` bypassed the
        // install-level halt).
        let repository = crate::build_state::read_manifest_repository(&pkg_dir);
        let publish_age = publish_ages.get(&(name.clone(), version.clone())).copied();
        let ctx = ManifestContext {
            package_name: name.as_str(),
            repository: repository.as_deref(),
            bin_names: &[],
            publish_age_secs: publish_age,
            min_release_age_secs,
        };
        // Classify each phase independently; collect those that
        // resolve to Amber/AmberLlm. The advisor needs the per-phase
        // body to make a per-phase judgement; the session then
        // worst-ofs across phases for the package-level outcome.
        let amber_phases: Vec<(String, String)> = bodies
            .into_iter()
            .filter(|(_, body)| {
                matches!(
                    lpm_security::static_gate::classify_with_context(body, Some(&ctx)),
                    StaticTier::Amber | StaticTier::AmberLlm
                )
            })
            .collect();
        if amber_phases.is_empty() {
            continue;
        }
        // The integrity slot carries source identity. Workspace /
        // file / link sources are `None`; registry sources carry the
        // resolved integrity hash. The same (name, version) from two
        // different sources produces TWO distinct approval keys
        // downstream — required so an approval on one source cannot
        // leak to a sibling source in the same install.
        //
        // Scan each amber phase body for files it delegates to and read them
        // with the runbook's caps
        // (depth 1, ≤ 32 KB, safe-relative only, non-text rejected).
        // Deduplicate by filename across phases so a body that says
        // `node install.js` for both preinstall and postinstall
        // doesn't emit the same content twice.
        let mut seen = std::collections::BTreeSet::new();
        let mut referenced_scripts: Vec<(String, String)> = Vec::new();
        for (_phase, body) in &amber_phases {
            for (filename, content) in
                crate::build_state::collect_referenced_scripts(&pkg_dir, body)
            {
                if seen.insert(filename.clone()) {
                    referenced_scripts.push((filename, content));
                }
            }
        }
        out.push(crate::triage_advisor_session::AmberPackageRequest {
            name: name.clone(),
            version: version.clone(),
            source: identity.source.clone(),
            integrity: integrity.clone(),
            repository,
            amber_phases,
            referenced_scripts,
        });
    }
    out
}

pub(super) fn advisor_package_dir(
    identity: &crate::build_state::InstalledPackageIdentity,
    materialized_packages: &[lpm_linker::MaterializedPackage],
    baseline_index: Option<&lpm_store::V2BaselineIndex>,
) -> Option<PathBuf> {
    let package_dir = if let Some(index) = baseline_index {
        let package_key = identity.package_key();
        let baseline = index.lookup_source_identity(
            &package_key.name,
            &package_key.version,
            &package_key.source_id,
        )?;
        if identity
            .integrity
            .as_deref()
            .is_some_and(|expected| expected != baseline.integrity)
        {
            return None;
        }
        baseline.package_dir.clone()
    } else {
        let mut matches = materialized_packages.iter().filter(|materialized| {
            materialized.name == identity.name && materialized.version == identity.version
        });
        let package_dir = matches.next()?.destination.clone();
        if matches.next().is_some() {
            return None;
        }
        if let Some(expected) = identity.integrity.as_deref()
            && lpm_store::read_stored_integrity(&package_dir).as_deref() != Some(expected)
        {
            return None;
        }
        package_dir
    };

    let manifest = std::fs::read(package_dir.join("package.json")).ok()?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest).ok()?;
    let manifest_name = manifest.get("name").and_then(serde_json::Value::as_str)?;
    let manifest_version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)?;
    if manifest_name != identity.name || manifest_version != identity.version {
        return None;
    }

    Some(package_dir)
}

pub(super) fn blocked_set_metadata_from_previous_state(
    project_dir: &Path,
    packages: &[InstallPackage],
) -> crate::build_state::BlockedSetMetadata {
    let mut metadata = blocked_set_source_metadata(packages);
    let Some(previous) = crate::build_state::read_build_state(project_dir) else {
        return metadata;
    };
    for package in previous.blocked_packages {
        if package.published_at.is_none()
            && package.behavioral_tags_hash.is_none()
            && package.behavioral_tags.is_none()
            && package.source.is_none()
        {
            continue;
        }

        let current_entry = metadata.get(
            &package.name,
            &package.version,
            package.integrity.as_deref(),
        );
        let source = match current_entry {
            Some(entry) => entry.source.clone(),
            None => package.source,
        };
        metadata.insert(
            package.name,
            package.version,
            package.integrity,
            crate::build_state::BlockedSetMetadataEntry {
                source,
                published_at: package.published_at,
                behavioral_tags_hash: package.behavioral_tags_hash,
                behavioral_tags: package.behavioral_tags,
                provenance_at_capture: None,
            },
        );
    }
    metadata
}

pub(super) fn blocked_set_source_metadata(
    packages: &[InstallPackage],
) -> crate::build_state::BlockedSetMetadata {
    let mut metadata = crate::build_state::BlockedSetMetadata {
        by_pkg: std::collections::HashMap::with_capacity(packages.len()),
    };
    for package in packages {
        use std::collections::hash_map::Entry;

        let key = crate::build_state::InstalledPackageIdentity::new(
            package.name.clone(),
            package.version.clone(),
            Some(package.source.clone()),
            package.integrity.clone(),
        )
        .package_key();
        match metadata.by_pkg.entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(crate::build_state::BlockedSetMetadataEntry {
                    source: Some(package.source.clone()),
                    ..Default::default()
                });
            }
            Entry::Occupied(_) => {}
        }
    }
    metadata
}

/// Never returns an error: metadata enrichment is best-effort and
/// must not fail an otherwise-successful install. Any fetch error
/// is recorded as "no entry for this package" and the install
/// proceeds.
pub(super) async fn build_blocked_set_metadata(
    client: &lpm_registry::RegistryClient,
    route_table: &RouteTable,
    packages: &[InstallPackage],
) -> crate::build_state::BlockedSetMetadata {
    let mut out = blocked_set_source_metadata(packages);

    // — provenance capture moved out of install.
    //
    // Pre-W2: this function fetched per-package attestation bundles in
    // parallel and persisted the parsed snapshot into
    // `BlockedSetMetadataEntry.provenance_at_capture`, which approve-
    // scripts later forwarded into `TrustedDependencyBinding.
    // provenance_at_approval`. W1b's `perf.prov_ns_split`
    // measured 99.98 % of that cost as HTTP (12.7 s summed across 24
    // permits → ~550 ms cold wall on the 266-pkg fixture, 0.02 % parse).
    //
    // The empirical finding (unblocker investigation) is
    // that the only end-consumer of `provenance_at_capture` is
    // `approve-scripts` — install reads it back from `build-state.json`
    // and copies it into the binding. Since `approve-scripts` is a
    // user-driven action that typically processes 1–10 scripted
    // packages out of an install set of hundreds, fetching at approval
    // time is strictly less work AND removes the cost from the cold
    // install critical path. Drift detection is unaffected: the drift
    // gate (install.rs:1810) re-fetches candidate attestations
    // independently and reads `provenance_at_approval` (the value
    // approve-scripts now stamps from a fresh fetch) as its reference.
    //
    // The `provenance_at_capture` field on `BlockedSetMetadataEntry`
    // is retained as `Option<>` for schema compat with persisted
    // build-state.json files — install always writes `None` here from
    // onward; approve-scripts ignores any value the field
    // may carry. Future cleanup may remove the field entirely after a
    // transition window.
    //
    // Run every package's metadata fetch CONCURRENTLY. The metadata is
    // still required for `published_at` and `behavioral_tags{,_hash}`,
    // which ship at install time (used by the version-diff card and
    // the static-tier fingerprint). Fetching in parallel keeps the metadata
    // path below the rest of the install pipeline on cold runs.
    let meta_ns = std::sync::atomic::AtomicU64::new(0);
    let meta_ns_ref = &meta_ns;
    let entry_futures = packages.iter().map(|p| async move {
        if install_package_is_local_source(p) {
            return None;
        }
        // Grab the full PackageMetadata for `time[version]` (→
        // `published_at`) and `versions[version]._behavioralTags` (→
        // `behavioral_tags_hash` + `behavioral_tags`). Errors are
        // swallowed per the graceful-degradation contract above.
        let meta_start = std::time::Instant::now();
        // `get_npm_blocked_set_meta` deserializes only `time` + `_behavioralTags`
        // on cache hits, avoiding the full `PackageMetadata` allocation cost.
        let meta: Option<lpm_registry::types::BlockedSetPackageMeta> = if p.is_lpm {
            match lpm_common::PackageName::parse(&p.name) {
                Ok(pkg_name) => client
                    .get_package_metadata(&pkg_name)
                    .await
                    .ok()
                    .map(|full| lpm_registry::types::BlockedSetPackageMeta {
                        time: full.time,
                        versions: full
                            .versions
                            .into_iter()
                            .map(|(k, v)| {
                                (
                                    k,
                                    lpm_registry::types::BlockedSetVersionMeta {
                                        behavioral_tags: v.behavioral_tags,
                                    },
                                )
                            })
                            .collect(),
                    }),
                Err(_) => None,
            }
        } else {
            let route = route_table.route_for_package(&p.name);
            client.get_npm_blocked_set_meta(&p.name, route).await
        };
        meta_ns_ref.fetch_add(
            meta_start.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        let meta = meta?;

        let published_at = meta.time.get(&p.version).cloned();

        // Extract behavioral tags if present and hash them into the
        // canonical form. `active_tag_names` returns sorted canonical
        // names; `hash_behavioral_tag_set` hashes them deterministically.
        //
        //: also persist the raw name set alongside the hash.
        // The hash gives the version-diff fast equality / fingerprint;
        // the names enable rendering the *delta* (`gained network, eval`)
        // without a registry re-fetch — required by ship
        // criterion 2 and lets the diff work offline. Both are computed
        // from the same `active_tag_names()` call so they cannot drift.
        let (behavioral_tags_hash, behavioral_tags) = meta
            .versions
            .get(&p.version)
            .and_then(|v| v.behavioral_tags.as_ref())
            .map_or((None, None), |tags| {
                let names = tags.active_tag_names();
                let hash = lpm_security::triage::hash_behavioral_tag_set(&names);
                let owned: Vec<String> = names.iter().map(|s| s.to_string()).collect();
                (Some(hash), Some(owned))
            });

        // Only materialize an entry if at least ONE field is populated
        // — empty entries just waste map memory. Callers get `None` for
        // absent keys either way.
        if published_at.is_some() || behavioral_tags_hash.is_some() {
            Some((
                p.name.clone(),
                p.version.clone(),
                p.integrity.clone(),
                crate::build_state::BlockedSetMetadataEntry {
                    source: Some(p.source.clone()),
                    published_at,
                    behavioral_tags_hash,
                    behavioral_tags,
                    //: install no longer captures
                    // provenance; approve-scripts fetches at approval
                    // time. Field retained for schema compat.
                    provenance_at_capture: None,
                },
            ))
        } else {
            None
        }
    });

    // Sequential insert into `out` after the concurrent fetches land.
    // Order is deterministic because `join_all` preserves the input order
    // and the downstream `BlockedSetMetadata` is keyed by
    // (name, version, integrity)
    // — identical output to the serial loop.
    for (name, version, integrity, e) in futures::future::join_all(entry_futures)
        .await
        .into_iter()
        .flatten()
    {
        out.merge_enrichment(name, version, integrity, e);
    }

    // Permanent perf diagnostic. dropped the `prov_sum_ms`
    // dimension — install no longer fetches provenance, so the field
    // would always be `0` and adding noise to the line. The
    // `perf.prov_ns_split` line is correspondingly removed.
    tracing::debug!(
        "perf.blocked_set_metadata_split pkgs={} meta_sum_ms={}",
        packages.len(),
        meta_ns.load(std::sync::atomic::Ordering::Relaxed) / 1_000_000,
    );
    out
}

// is_install_up_to_date() moved to crate::install_state::check_install_state()
