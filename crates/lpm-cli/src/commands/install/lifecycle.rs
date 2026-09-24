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
        crate::script_policy_config::ScriptPolicyConfig::try_from_package_json(project_dir)?;
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
            let all_pkgs: Vec<(String, String, Option<String>)> = packages
                .iter()
                .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
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

pub(super) fn resolve_blocked_capture_packages(
    project_dir: &Path,
    store: &lpm_store::PackageStore,
    packages: &[InstallPackage],
    materialized: &[lpm_linker::MaterializedPackage],
    uses_virtual_store: bool,
) -> Result<Vec<crate::build_state::BlockedCapturePackage>, LpmError> {
    let mut by_instance = HashMap::with_capacity(materialized.len());
    if uses_virtual_store {
        for location in materialized {
            let id = location.instance_id.ok_or_else(|| {
                LpmError::Store(
                    "cannot capture script approvals: installed package has no instance identity"
                        .into(),
                )
            })?;
            if let Some(previous) = by_instance.insert(id, location)
                && (previous.destination != location.destination
                    || previous.name != location.name
                    || previous.version != location.version)
            {
                return Err(LpmError::Store(
                    "cannot capture script approvals: conflicting instance locations".into(),
                ));
            }
        }
    }
    packages.iter().map(|package| {
        let package_dir = if uses_virtual_store {
            let location = package.instance_id.and_then(|id| by_instance.get(&id))
                .ok_or_else(|| LpmError::Store(format!(
                    "cannot capture script approvals for {}@{}: exact installed location is missing", package.name, package.version)))?;
            if location.name != package.name || location.version != package.version {
                return Err(LpmError::Store("cannot capture script approvals: installed coordinates do not match the instance".into()));
            }
            location.destination.clone()
        } else {
            package.store_path_or_err(store, project_dir, None)?
        };
        Ok(crate::build_state::BlockedCapturePackage {
            instance_id: package.instance_id,
            name: package.name.clone(), version: package.version.clone(), integrity: package.integrity.clone(), package_dir,
        })
    }).collect()
}

pub(super) struct OnlineLifecyclePrepareInput<'a> {
    pub(super) client: &'a lpm_registry::RegistryClient,
    pub(super) route_table: &'a RouteTable,
    pub(super) project_dir: &'a Path,
    pub(super) policy_project_dir: &'a Path,
    pub(super) packages: &'a [InstallPackage],
    pub(super) materialized: &'a [lpm_linker::MaterializedPackage],
    pub(super) package: &'a lpm_workspace::PackageJson,
    pub(super) store: &'a lpm_store::PackageStore,
    pub(super) baseline_index: Option<lpm_store::V2BaselineIndex>,
    pub(super) used_lockfile: bool,
    pub(super) script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    pub(super) advisor_override: Option<&'a str>,
    pub(super) global_config: &'a crate::commands::config::GlobalConfig,
    pub(super) auto_build: bool,
    pub(super) json_output: bool,
    pub(super) lpm_root: &'a lpm_common::LpmRoot,
}

pub(super) struct OnlineLifecyclePrepareResult {
    pub(super) policy: lpm_security::SecurityPolicy,
    pub(super) capture_packages: Vec<crate::build_state::BlockedCapturePackage>,
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
        policy_project_dir,
        packages,
        materialized,
        package,
        store,
        baseline_index,
        used_lockfile,
        script_policy_override,
        advisor_override,
        global_config,
        auto_build,
        json_output,
        lpm_root,
    } = input;

    let policy =
        lpm_security::SecurityPolicy::from_package_json(&policy_project_dir.join("package.json"));
    let installed_with_integrity: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();

    let capture_packages = resolve_blocked_capture_packages(
        project_dir,
        store,
        packages,
        materialized,
        baseline_index.is_some(),
    )?;
    let blocked_metadata_start = std::time::Instant::now();
    let mut blocked_metadata_ms = 0u128;
    let blocked_set_metadata = if used_lockfile {
        let metadata = blocked_set_metadata_from_previous_state(project_dir);
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
            build_blocked_set_metadata(client, route_table, packages, &capture_packages),
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
        crate::capability::CapabilitySet::from_project(&policy_project_dir.join("package.json"))
            .map_err(|e| LpmError::Registry(format!("{e}")))?;
    let user_bound = crate::security_approval::authorized_capability_user_bound();

    let script_policy_cfg =
        crate::script_policy_config::ScriptPolicyConfig::try_from_package_json(policy_project_dir)?;
    let config_auto_build = script_policy_cfg.auto_build;
    let effective_policy = crate::script_policy_config::resolve_script_policy_with_security(
        policy_project_dir,
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
            let amber_requests = collect_amber_requests_from_materializations(&capture_packages)?;
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
        crate::commands::rebuild::all_scripted_packages_trusted_in_context(
            lpm_root,
            &installed_with_integrity,
            &policy,
            project_dir,
            policy_project_dir,
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
    let blocked_capture = crate::build_state::capture_blocked_set_after_install_with_options(
        project_dir,
        &capture_packages,
        &policy,
        &blocked_set_metadata,
        &requested_capabilities,
        &user_bound,
        crate::build_state::BlockedSetCaptureOptions {
            advisor_approvals: select_approvals_for_capture(
                auto_build_will_execute,
                advisor_session.as_ref().map(|s| s.approvals()),
            ),
            execution_exclusions: None,
        },
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
    if let Err(e) = crate::trust_snapshot::stage_install_snapshot(project_dir, snap) {
        tracing::warn!("failed to write trust-snapshot.json: {e}");
    }
    let trust_snapshot_ms = trust_snap_start.elapsed().as_millis();
    tracing::debug!("perf.trust_snapshot ms={}", trust_snapshot_ms);

    Ok(OnlineLifecyclePrepareResult {
        policy,
        capture_packages,
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
    pub(super) policy_project_dir: &'a Path,
    pub(super) packages: &'a [InstallPackage],
    pub(super) link_targets: &'a [LinkTarget],
    pub(super) package_name: Option<&'a str>,
    pub(super) store: &'a lpm_store::PackageStore,
    pub(super) lpm_root: &'a lpm_common::LpmRoot,
    pub(super) store_version: lpm_store::StoreVersion,
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
    pub(super) capture_packages: &'a [crate::build_state::BlockedCapturePackage],
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
        policy_project_dir,
        packages,
        link_targets,
        package_name,
        store,
        lpm_root,
        store_version,
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
        capture_packages,
        policy,
        blocked_set_metadata,
        requested_capabilities,
        user_bound,
    } = input;

    if auto_build_attempted {
        maybe_emit_pre_autobuild_version_diff_cards(
            policy_project_dir,
            store,
            auto_build_attempted,
            effective_policy,
            &blocked_capture,
            json_output,
        );
    }

    let mut auto_build_report = crate::commands::rebuild::RebuildRunReport::default();
    if auto_build_attempted {
        match crate::commands::rebuild::run_with_report(
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
            false,
            Some(policy_project_dir),
        )
        .await
        {
            Ok(report) => {
                auto_build_report = report;
            }
            Err(e) => {
                if !json_output {
                    output::warn(&format!(
                        "Auto-build failed: {}",
                        lpm_common::sanitize_terminal_inline(&e.to_string())
                    ));
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
        blocked_capture = crate::build_state::capture_blocked_set_after_install_with_options(
            project_dir,
            capture_packages,
            policy,
            blocked_set_metadata,
            requested_capabilities,
            user_bound,
            crate::build_state::BlockedSetCaptureOptions {
                advisor_approvals: select_approvals_for_capture(
                    true,
                    advisor_session.map(|s| s.approvals()),
                ),
                execution_exclusions: Some(&execution_exclusions),
            },
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
                store_version,
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
        let Some((prior_version, binding)) = trusted.latest_binding_for_name(&bp.name, &bp.version)
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
/// Reads store bodies for both sides via
/// [`crate::build_state::read_install_phase_bodies`]; the prior
/// side gracefully degrades to "(prior not in store)" when the
/// cache has been cleaned or the extractor hasn't populated
/// `<store>/{name}@{prior}/`.
pub(super) fn maybe_emit_pre_autobuild_version_diff_cards(
    project_dir: &Path,
    store: &lpm_store::PackageStore,
    auto_build_attempted: bool,
    effective_policy: crate::script_policy_config::ScriptPolicy,
    blocked_capture: &crate::build_state::BlockedSetCapture,
    json_output: bool,
) {
    if !auto_build_attempted {
        return;
    }
    if effective_policy != crate::script_policy_config::ScriptPolicy::Triage {
        return;
    }
    if json_output {
        return;
    }
    let Some(trusted) = read_trusted_deps_from_manifest(project_dir) else {
        return;
    };

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
        let Some((prior_version, binding)) = trusted.latest_binding_for_name(&bp.name, &bp.version)
        else {
            continue;
        };
        let diff = crate::version_diff::compute_version_diff(prior_version, binding, bp);
        if !diff.is_drift() {
            continue;
        }

        let candidate_pkg_dir = store.package_dir(&bp.name, &bp.version);
        let prior_pkg_dir = store.package_dir(&bp.name, prior_version);
        let candidate_bodies = crate::version_diff::phase_bodies_from_pairs(
            crate::build_state::read_install_phase_bodies(&candidate_pkg_dir),
        );
        let prior_pairs = crate::build_state::read_install_phase_bodies(&prior_pkg_dir);
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
        let candidate_bodies_opt = if candidate_bodies.is_empty() {
            None
        } else {
            Some(candidate_bodies)
        };

        if let Some(card) = crate::version_diff::render_preflight_card(
            &diff,
            &bp.name,
            prior_bodies.as_ref(),
            candidate_bodies_opt.as_ref(),
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
    let content =
        lpm_common::read_text_file_capped(&pkg_json_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .ok()?;
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

/// Resolve installed source identities for advisor request tests.
#[cfg(test)]
pub(super) fn collect_amber_classification_requests(
    store: &lpm_store::PackageStore,
    lpm_root: &lpm_common::LpmRoot,
    baseline_index: Option<&lpm_store::V2BaselineIndex>,
    packages: &[(String, String, Option<String>)],
) -> Vec<crate::triage_advisor_session::AmberPackageRequest> {
    let resolved: Vec<_> = packages
        .iter()
        .filter_map(|(name, version, integrity)| {
            let package_dir = match baseline_index {
                Some(index) => {
                    lpm_store::find_installed_package_baseline_by_identity_indexed(
                        index,
                        lpm_root,
                        name,
                        version,
                        integrity.as_deref(),
                    )?
                    .package_dir
                }
                None => store.package_dir(name, version),
            };
            Some(crate::build_state::BlockedCapturePackage {
                instance_id: None,
                name: name.clone(),
                version: version.clone(),
                integrity: integrity.clone(),
                package_dir,
            })
        })
        .collect();
    collect_amber_requests_from_materializations(&resolved).unwrap()
}

pub(super) fn collect_amber_requests_from_materializations(
    packages: &[crate::build_state::BlockedCapturePackage],
) -> Result<Vec<crate::triage_advisor_session::AmberPackageRequest>, LpmError> {
    use lpm_security::static_gate::classify_for_execution;
    use lpm_security::triage::StaticTier;
    let mut out = Vec::with_capacity(packages.len());
    for package in packages {
        let crate::build_state::BlockedCapturePackage {
            name,
            version,
            integrity,
            package_dir: pkg_dir,
            ..
        } = package;
        let Some(data) =
            lpm_security::script_hash::try_compute_script_hash_with_phase_bodies(pkg_dir)?
        else {
            continue;
        };
        let bodies = data.phase_bodies;
        let repository = crate::build_state::read_manifest_repository(pkg_dir);
        if bodies
            .iter()
            .any(|(_, body)| classify_for_execution(body) == StaticTier::Red)
        {
            continue;
        }
        let amber_phases: Vec<(String, String)> = bodies
            .into_iter()
            .filter(|(_, body)| {
                matches!(
                    classify_for_execution(body),
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
            for (filename, content) in crate::build_state::collect_referenced_scripts(pkg_dir, body)
            {
                if seen.insert(filename.clone()) {
                    referenced_scripts.push((filename, content));
                }
            }
        }
        out.push(crate::triage_advisor_session::AmberPackageRequest {
            name: name.clone(),
            version: version.clone(),
            integrity: integrity.clone(),
            script_hash: data.hash,
            repository,
            amber_phases,
            referenced_scripts,
        });
    }
    Ok(out)
}

pub(super) fn blocked_set_metadata_from_previous_state(
    project_dir: &Path,
) -> crate::build_state::BlockedSetMetadata {
    let Ok(Some(mut previous)) = crate::build_state::read_build_state_for_approval(project_dir)
    else {
        return crate::build_state::BlockedSetMetadata::default();
    };

    crate::build_state::normalize_blocked_packages(&mut previous.blocked_packages);
    let mut metadata = crate::build_state::BlockedSetMetadata {
        by_pkg: std::collections::HashMap::with_capacity(previous.blocked_packages.len()),
    };
    for package in previous.blocked_packages {
        if package.integrity.is_none() {
            continue;
        }
        if package.published_at.is_none()
            && package.behavioral_tags_hash.is_none()
            && package.behavioral_tags.is_none()
        {
            continue;
        }

        metadata.insert(
            package.name,
            package.version,
            package.integrity,
            crate::build_state::BlockedSetMetadataEntry {
                published_at: package.published_at,
                behavioral_tags_hash: package.behavioral_tags_hash,
                behavioral_tags: package.behavioral_tags,
                provenance_at_capture: None,
            },
        );
    }
    metadata
}

fn blocked_metadata_for_versions(
    mut full: lpm_registry::PackageMetadata,
    versions: &[&str],
) -> lpm_registry::types::BlockedSetPackageMeta {
    let mut selected = lpm_registry::types::BlockedSetPackageMeta {
        time: HashMap::with_capacity(versions.len()),
        versions: HashMap::with_capacity(versions.len()),
    };
    for &version in versions {
        if let Some(manifest) = full.versions.remove(version) {
            selected.versions.insert(
                version.to_owned(),
                lpm_registry::types::BlockedSetVersionMeta {
                    behavioral_tags: manifest.behavioral_tags,
                    dist: manifest.dist.map(Into::into),
                },
            );
            if let Some(time) = full.time.remove(version) {
                selected.time.insert(version.to_owned(), time);
            }
        }
    }
    selected
}

/// Never returns an error: metadata enrichment is best-effort and
/// must not fail an otherwise-successful install. Any fetch error
/// is recorded as "no entry for this package" and the install
/// proceeds.
pub(super) async fn build_blocked_set_metadata(
    client: &lpm_registry::RegistryClient,
    route_table: &RouteTable,
    packages: &[InstallPackage],
    capture_packages: &[crate::build_state::BlockedCapturePackage],
) -> crate::build_state::BlockedSetMetadata {
    let mut out = crate::build_state::BlockedSetMetadata::default();

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
    // Only packages with lifecycle scripts can enter the blocked set and
    // consume this enrichment. Fetch those candidates concurrently.
    let mut metadata_packages = Vec::with_capacity(packages.len());
    for (package, capture) in packages.iter().zip(capture_packages) {
        if package_requires_blocked_set_metadata(package, &capture.package_dir) {
            metadata_packages.push(package);
        }
    }

    let mut groups: HashMap<(&str, bool), Vec<&str>> =
        HashMap::with_capacity(metadata_packages.len());
    for package in &metadata_packages {
        groups
            .entry((&package.name, package.is_lpm))
            .or_default()
            .push(&package.version);
    }
    let meta_ns = std::sync::atomic::AtomicU64::new(0);
    let meta_ns_ref = &meta_ns;
    let metadata_futures = groups
        .into_iter()
        .map(|((name, is_lpm), versions)| async move {
            let meta_start = std::time::Instant::now();
            let meta: Option<lpm_registry::types::BlockedSetPackageMeta> = if is_lpm {
                match lpm_common::PackageName::parse(name) {
                    Ok(pkg_name) => client
                        .get_package_metadata(&pkg_name)
                        .await
                        .ok()
                        .map(|full| blocked_metadata_for_versions(full, &versions)),
                    Err(_) => None,
                }
            } else {
                let route = route_table.route_for_package(name);
                client
                    .get_npm_blocked_set_meta_for_versions(name, &versions, route)
                    .await
            };
            meta_ns_ref.fetch_add(
                meta_start.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            ((name, is_lpm), meta)
        });
    let metadata_by_source: HashMap<_, _> = futures::future::join_all(metadata_futures)
        .await
        .into_iter()
        .collect();
    let entries = metadata_packages.iter().filter_map(|&p| {
        let meta = metadata_by_source
            .get(&(p.name.as_str(), p.is_lpm))?
            .as_ref()?;
        let version_meta = meta.versions.get(&p.version)?;
        let expected_integrity = p.integrity.as_deref()?;
        let dist = version_meta.dist.as_ref()?;
        if dist.integrity_or_shasum().as_deref() != Some(expected_integrity) {
            return None;
        }

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

    for (name, version, integrity, e) in entries {
        out.insert(name, version, integrity, e);
    }

    // Permanent perf diagnostic. dropped the `prov_sum_ms`
    // dimension — install no longer fetches provenance, so the field
    // would always be `0` and adding noise to the line. The
    // `perf.prov_ns_split` line is correspondingly removed.
    tracing::debug!(
        "perf.blocked_set_metadata_split pkgs={} candidates={} meta_sum_ms={}",
        packages.len(),
        metadata_packages.len(),
        meta_ns.load(std::sync::atomic::Ordering::Relaxed) / 1_000_000,
    );
    out
}

pub(super) fn package_requires_blocked_set_metadata(
    package: &InstallPackage,
    package_dir: &Path,
) -> bool {
    install_package_is_registry_source(package)
        && !crate::build_state::read_install_phase_bodies(package_dir).is_empty()
}

// is_install_up_to_date() moved to crate::install_state::check_install_state()

#[cfg(test)]
mod metadata_projection_tests {
    use super::blocked_metadata_for_versions;

    #[test]
    fn blocked_metadata_projection_retains_only_requested_versions_and_their_bindings() {
        let full: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name":"pkg", "time":{"1.0.0":"one","2.0.0":"two","3.0.0":"three"},
        "versions":{
            "1.0.0":{"name":"pkg","version":"1.0.0","dist":{"integrity":"sha512-one"},"_behavioralTags":{"network":true}},
            "2.0.0":{"name":"pkg","version":"2.0.0","dist":{"integrity":"sha512-two"}},
            "3.0.0":{"name":"pkg","version":"3.0.0"}
        }
    })).unwrap();
        let selected = blocked_metadata_for_versions(full, &["1.0.0", "2.0.0", "2.0.0", "missing"]);
        assert_eq!(selected.versions.len(), 2);
        assert_eq!(selected.time.len(), 2);
        assert_eq!(selected.time["1.0.0"], "one");
        assert_eq!(selected.time["2.0.0"], "two");
        assert_eq!(
            selected.versions["1.0.0"]
                .dist
                .as_ref()
                .unwrap()
                .integrity_or_shasum()
                .as_deref(),
            Some("sha512-one")
        );
        assert!(
            selected.versions["1.0.0"]
                .behavioral_tags
                .as_ref()
                .unwrap()
                .active_tag_names()
                .contains(&"network")
        );
    }
}
