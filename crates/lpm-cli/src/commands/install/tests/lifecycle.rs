use super::*;

#[test]
fn blocked_set_metadata_replay_preserves_previous_enrichment_only() {
    let dir = tempfile::tempdir().unwrap();
    crate::build_state::write_build_state(
        dir.path(),
        &crate::build_state::BuildState {
            state_version: crate::build_state::BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-fixture".into(),
            captured_at: "2026-06-09T00:00:00Z".into(),
            blocked_packages: vec![
                crate::build_state::BlockedPackage {
                    name: "scripted-meta".into(),
                    version: "1.0.0".into(),
                    integrity: Some("sha512-meta".into()),
                    script_hash: Some("sha256-script".into()),
                    phases_present: vec!["postinstall".into()],
                    binding_drift: false,
                    static_tier: None,
                    provenance_at_capture: None,
                    published_at: Some("2026-04-22T00:00:00Z".into()),
                    behavioral_tags_hash: Some("sha256-tags".into()),
                    behavioral_tags: Some(vec!["network".into(), "eval".into()]),
                },
                crate::build_state::BlockedPackage {
                    name: "scripted-empty".into(),
                    version: "1.0.0".into(),
                    integrity: Some("sha512-empty".into()),
                    script_hash: Some("sha256-empty".into()),
                    phases_present: vec!["postinstall".into()],
                    binding_drift: false,
                    static_tier: None,
                    provenance_at_capture: None,
                    published_at: None,
                    behavioral_tags_hash: None,
                    behavioral_tags: None,
                },
            ],
            drift_ignore_override: None,
        },
    )
    .unwrap();

    let metadata = blocked_set_metadata_from_previous_state(dir.path());

    assert_eq!(metadata.by_pkg.len(), 1);
    let entry = metadata
        .get("scripted-meta", "1.0.0")
        .expect("metadata replay should include enriched prior rows");
    assert_eq!(entry.published_at.as_deref(), Some("2026-04-22T00:00:00Z"));
    assert_eq!(entry.behavioral_tags_hash.as_deref(), Some("sha256-tags"));
    let tags = entry
        .behavioral_tags
        .as_deref()
        .expect("metadata replay should preserve behavioral tag names");
    assert_eq!(tags, ["network", "eval"]);
    assert!(metadata.get("scripted-empty", "1.0.0").is_none());
}

/// The drift gate must appear before the rebuild auto-build
/// call site. If a future refactor moves the drift check past the build
/// call, a drifted approval could spawn scripts before containment is
/// established.
///
/// This test is source-level by design. The drift check's
/// control flow is a `?`-propagated early return embedded inside
/// a large async function; isolating it behaviorally would
/// require mocking the full registry + provenance pipeline. A
/// source-offset assertion catches a reorder that moves the drift block
/// past the rebuild call at near-zero ceremony.
/// If the marker strings themselves get refactored, this test
/// fails LOUDLY rather than silently drifting; the failure
/// message names what needs updating.
#[test]
fn provenance_drift_gate_precedes_build_run_call_site() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/commands/install/mod.rs"
    ));
    const DRIFT_MARKER: &str = "provenance-drift gate";
    const BUILD_RUN_CALL: &str = "crate::commands::rebuild::run_with_report(";

    let drift_pos = src.find(DRIFT_MARKER).unwrap_or_else(|| {
        panic!(
            "drift-gate marker `{DRIFT_MARKER}` disappeared from install/mod.rs — \
             if the comment was legitimately renamed, update this test with the \
             new marker. If the drift gate was removed, that's a major regression \
             that needs explicit signoff."
        )
    });
    let build_run_pos = src.find(BUILD_RUN_CALL).unwrap_or_else(|| {
        panic!(
            "rebuild call site (`{BUILD_RUN_CALL}`) not found — the \
             install → auto-build handoff was removed or renamed; update this \
             test to target the new call."
        )
    });
    assert!(
        drift_pos < build_run_pos,
        "Order invariant broken: the provenance-drift gate (byte {drift_pos}) \
         MUST appear before the rebuild call site (byte {build_run_pos}) in \
         install/mod.rs. Reordering them means a drifted approval could spawn scripts \
         before the drift check fires — violating the approved execution order."
    );
}

#[test]
fn auto_build_trigger_enables_when_any_current_source_requests_it() {
    use crate::script_policy_config::ScriptPolicy;
    // Under Deny (default), each input alone is sufficient.
    assert!(should_auto_build(true, false, false, ScriptPolicy::Deny));
    assert!(should_auto_build(false, true, false, ScriptPolicy::Deny));
    assert!(should_auto_build(false, false, true, ScriptPolicy::Deny));
    assert!(!should_auto_build(false, false, false, ScriptPolicy::Deny));
}

#[test]
fn auto_build_fires_under_allow_policy_alone() {
    use crate::script_policy_config::ScriptPolicy;
    // --policy=allow / --yolo / package.json scriptPolicy:"allow"
    // / config.toml script-policy="allow" all resolve to ScriptPolicy::Allow,
    // which auto-fires rebuild::run at install time without requiring an
    // additional --auto-build flag. This is the apples-to-apples fix vs
    // npm/pnpm/bun (which run scripts during install by default).
    assert!(should_auto_build(false, false, false, ScriptPolicy::Allow));
    // And every other-input combination still trips it (no regression):
    assert!(should_auto_build(true, false, false, ScriptPolicy::Allow));
    assert!(should_auto_build(false, true, false, ScriptPolicy::Allow));
    assert!(should_auto_build(false, false, true, ScriptPolicy::Allow));
}

#[test]
fn auto_build_does_not_fire_under_triage_alone() {
    use crate::script_policy_config::ScriptPolicy;
    // Triage's safety mechanism IS the per-package gate: greens promote
    // via evaluate_trust → ride the `all_trusted` path; ambers/reds
    // require explicit --auto-build OR `lpm approve-scripts`. Policy
    // alone must NOT auto-fire under Triage — that would defeat the
    // tiered safety model. expands Allow only.
    assert!(!should_auto_build(
        false,
        false,
        false,
        ScriptPolicy::Triage
    ));
    // But explicit signals still work under Triage:
    assert!(should_auto_build(true, false, false, ScriptPolicy::Triage));
    assert!(should_auto_build(false, true, false, ScriptPolicy::Triage));
    assert!(should_auto_build(false, false, true, ScriptPolicy::Triage));
}

// ── Second-pass review fix ───────────────────────────
//
// `select_approvals_for_capture` decides whether the blocked-set
// capture sees the advisor's approval view. The contract is:
// 1. autoBuild won't fire → ALWAYS `None`, regardless of whether
// the session classified anything. Previously this was an
// unconditional pass-through; that stranded approved-but-
// not-run packages: scripts never executed AND the package
// vanished from `build-state.json` → unreachable via
// `lpm approve-scripts` either.
// 2. autoBuild will fire → pass the view through verbatim,
// including the absent-session case (`None` in → `None`
// out — the autoBuild path just gets no exclusions).

#[test]
fn select_approvals_returns_none_when_auto_build_skipped() {
    let mut approvals = std::collections::HashSet::new();
    approvals.insert((
        "amber-pkg".to_string(),
        "1.0.0".to_string(),
        Some("sha512-x".to_string()),
        String::new(),
    ));
    assert!(
        select_approvals_for_capture(false, Some(&approvals)).is_none(),
        "autoBuild=false MUST suppress the approval view so approved-but-not-run \
         packages remain in the blocked set and reviewable via approve-scripts"
    );
}

#[test]
fn select_approvals_returns_view_when_auto_build_fires() {
    let mut approvals = std::collections::HashSet::new();
    approvals.insert((
        "amber-pkg".to_string(),
        "1.0.0".to_string(),
        Some("sha512-x".to_string()),
        String::new(),
    ));
    let view = select_approvals_for_capture(true, Some(&approvals))
        .expect("autoBuild=true MUST forward the approval view");
    assert_eq!(view.len(), 1);
    assert!(view.contains(&(
        "amber-pkg".to_string(),
        "1.0.0".to_string(),
        Some("sha512-x".to_string()),
        String::new(),
    )));
}

#[test]
fn select_approvals_returns_none_when_session_absent() {
    // Triage-off / no-advisor path: nothing to pass through in
    // either branch. Both `false` and `true` for
    // `auto_build_attempted` MUST return `None`.
    assert!(select_approvals_for_capture(false, None).is_none());
    assert!(select_approvals_for_capture(true, None).is_none());
}

//: the two `read_auto_build_config_*` tests were
// removed alongside the ad-hoc helper. Equivalent coverage lives
// in `script_policy_config::tests::from_package_json_reads_all_four_keys`
// and `::from_package_json_missing_file_returns_defaults` and
// `::from_package_json_malformed_json_returns_defaults`.

// ── post-auto-build triage pointer ─────────
//
// Tests exercise every gate of `compute_post_auto_build_triage_pointer`
// independently, plus the all-four-gates-pass case. The I/O
// half (`maybe_emit_post_auto_build_triage_pointer`) is a one-
// line wrapper over `output::warn` and is exercised by the
// integration fixture, not these unit tests — capturing
// stdout here would add flake without buying coverage beyond
// what the decision-function tests already provide.

/// Build a `BlockedSetCapture` with the given tier counts. The
/// decision function's only dependency on `BlockedSetCapture` is
/// the per-package `static_tier`, so we don't need real
/// integrity / script_hash / etc. — just the tier histogram.
fn bc_with_tiers(green: usize, amber: usize, red: usize) -> crate::build_state::BlockedSetCapture {
    use lpm_security::triage::StaticTier;
    let build_bp = |name: &str, tier: StaticTier| crate::build_state::BlockedPackage {
        name: name.into(),
        version: "1.0.0".into(),
        integrity: None,
        script_hash: None,
        phases_present: vec!["postinstall".into()],
        binding_drift: false,
        static_tier: Some(tier),
        provenance_at_capture: None,
        published_at: None,
        behavioral_tags_hash: None,
        behavioral_tags: None,
    };
    let mut packages = Vec::new();
    for i in 0..green {
        packages.push(build_bp(&format!("green-{i}"), StaticTier::Green));
    }
    for i in 0..amber {
        packages.push(build_bp(&format!("amber-{i}"), StaticTier::Amber));
    }
    for i in 0..red {
        packages.push(build_bp(&format!("red-{i}"), StaticTier::Red));
    }
    crate::build_state::BlockedSetCapture {
        state: crate::build_state::BuildState {
            state_version: crate::build_state::BUILD_STATE_VERSION,
            captured_at: "unused-in-test".into(),
            blocked_packages: packages,
            blocked_set_fingerprint: "unused-in-test".into(),
            drift_ignore_override: None,
        },
        previous_fingerprint: None,
        should_emit_warning: false,
        all_clear_banner: false,
    }
}

#[test]
fn post_auto_build_triage_pointer_fires_when_amber_remains() {
    // The core behavior: auto-build attempted, triage,
    // non-JSON, and the capture had amber entries (reds would
    // trigger too). User sees a pointer telling them `lpm
    // approve-scripts` is next.
    let bc = bc_with_tiers(1, 2, 0);
    let msg = compute_post_auto_build_triage_pointer(
        true,
        crate::script_policy_config::ScriptPolicy::Triage,
        &bc,
        false,
    );
    let msg = msg.expect("pointer must fire under triage when amber > 0");
    // Anchor the wire shape so CI scripts that grep this line stay
    // stable across refactors. The shape is a contract.
    assert!(msg.contains("remain blocked after auto-build"));
    assert!(msg.contains("2 amber"));
    assert!(msg.contains("0 red"));
    assert!(msg.contains("lpm approve-scripts"));
}

#[test]
fn post_auto_build_triage_pointer_fires_when_red_remains() {
    // Red-only is the same contract as amber-only: the pointer
    // fires. A red blocked package cannot be auto-approved by
    // any path; the user must review.
    let bc = bc_with_tiers(3, 0, 1);
    let msg = compute_post_auto_build_triage_pointer(
        true,
        crate::script_policy_config::ScriptPolicy::Triage,
        &bc,
        false,
    );
    let msg = msg.expect("pointer must fire under triage when red > 0");
    assert!(msg.contains("0 amber"));
    assert!(msg.contains("1 red"));
}

#[test]
fn post_auto_build_triage_pointer_silent_when_only_greens_remain() {
    // Auto-build ran greens; nothing non-green survives. The
    // blocked_capture still lists the greens (captured before
    // auto-build) but the user has no review work ahead, so no
    // pointer. This is the "quiet builds stay quiet" contract.
    let bc = bc_with_tiers(5, 0, 0);
    assert_eq!(
        compute_post_auto_build_triage_pointer(
            true,
            crate::script_policy_config::ScriptPolicy::Triage,
            &bc,
            false,
        ),
        None,
        "greens-only blocked capture must not fire the pointer — auto-build \
         consumed the greens and nothing remains to review"
    );
}

#[test]
fn post_auto_build_triage_pointer_silent_when_auto_build_did_not_run() {
    // A user running `lpm install` under triage + autoBuild=false
    // + mixed tiers: auto-build never ran, so a "remain blocked
    // after auto-build" message would misrepresent what happened.
    // The pre-auto-build triage summary line covers this case;
    // pointer is strictly a follow-up.
    let bc = bc_with_tiers(1, 1, 1);
    assert_eq!(
        compute_post_auto_build_triage_pointer(
            false,
            crate::script_policy_config::ScriptPolicy::Triage,
            &bc,
            false,
        ),
        None,
        "pointer must stay silent when auto-build was not attempted — \
         otherwise the message name 'after auto-build' is a lie"
    );
}

#[test]
fn post_auto_build_triage_pointer_silent_under_deny() {
    let bc = bc_with_tiers(0, 2, 1);
    assert_eq!(
        compute_post_auto_build_triage_pointer(
            true,
            crate::script_policy_config::ScriptPolicy::Deny,
            &bc,
            false,
        ),
        None,
        "pointer must stay silent under deny — deny users route through \
         the pre-auto-build blocked hint, not a triage-specific follow-up"
    );
}

#[test]
fn post_auto_build_triage_pointer_silent_under_allow() {
    // Allow semantics don't exercise the blocked-set flow in the
    // canonical case; a pointer here would be confusing.
    // (The allow-widening gap is a deferred optimization.)
    let bc = bc_with_tiers(0, 2, 1);
    assert_eq!(
        compute_post_auto_build_triage_pointer(
            true,
            crate::script_policy_config::ScriptPolicy::Allow,
            &bc,
            false,
        ),
        None,
    );
}

#[test]
fn post_auto_build_triage_pointer_silent_in_json_mode() {
    // JSON mode's channel is the per-entry `static_tier` in the
    // `blocked_packages` array. Emitting a stdout
    // warn line here would muddle the JSON contract for agents.
    let bc = bc_with_tiers(0, 2, 1);
    assert_eq!(
        compute_post_auto_build_triage_pointer(
            true,
            crate::script_policy_config::ScriptPolicy::Triage,
            &bc,
            true,
        ),
        None,
        "pointer must stay silent in JSON mode — the structured \
         notice is the per-entry static_tier enrichment, not a \
         stdout line"
    );
}

#[test]
fn post_auto_build_triage_pointer_wire_shape_stable_for_all_tiers() {
    // Agent-parseable contract: the message names exact amber +
    // red counts. Pin shape so CI greps stay stable.
    let bc = bc_with_tiers(0, 3, 2);
    let msg = compute_post_auto_build_triage_pointer(
        true,
        crate::script_policy_config::ScriptPolicy::Triage,
        &bc,
        false,
    )
    .unwrap();
    assert!(msg.starts_with("5 package(s) remain blocked after auto-build"));
    assert!(msg.contains("3 amber"));
    assert!(msg.contains("2 red"));
    assert!(msg.ends_with("Run `lpm approve-scripts` to review."));
}

// ─── — version-diff hint computation ──────
//
// Pure-decision tests for `compute_post_install_version_diff_hints`.
// The I/O wrapper (`maybe_emit_post_install_version_diff_hints`)
// is exercised by the C5 reference fixture under a real
// subprocess + the existing stream-separation pattern; unit-
// testing it here would require capturing stderr (flaky) without
// adding coverage beyond what the pure decision already gives.

fn bp_for_diff(
    name: &str,
    version: &str,
    script_hash: Option<&str>,
    behavioral_tags: Option<Vec<&str>>,
) -> crate::build_state::BlockedPackage {
    crate::build_state::BlockedPackage {
        name: name.into(),
        version: version.into(),
        integrity: Some(format!("sha512-{name}-{version}")),
        script_hash: script_hash.map(String::from),
        phases_present: vec!["postinstall".into()],
        binding_drift: false,
        static_tier: Some(lpm_security::triage::StaticTier::Green),
        provenance_at_capture: None,
        published_at: None,
        behavioral_tags_hash: None,
        behavioral_tags: behavioral_tags.map(|v| v.into_iter().map(String::from).collect()),
    }
}

fn bc_with_blocked(
    packages: Vec<crate::build_state::BlockedPackage>,
) -> crate::build_state::BlockedSetCapture {
    crate::build_state::BlockedSetCapture {
        state: crate::build_state::BuildState {
            state_version: crate::build_state::BUILD_STATE_VERSION,
            captured_at: "unused-in-test".into(),
            blocked_packages: packages,
            blocked_set_fingerprint: "unused-in-test".into(),
            drift_ignore_override: None,
        },
        previous_fingerprint: None,
        should_emit_warning: false,
        all_clear_banner: false,
    }
}

#[test]
fn post_install_version_diff_hints_empty_when_blocked_set_is_empty() {
    let bc = bc_with_blocked(vec![]);
    let trusted = lpm_workspace::TrustedDependencies::default();
    let hints = compute_post_install_version_diff_hints(&bc, &trusted);
    assert!(hints.is_empty());
}

#[test]
fn post_install_version_diff_hints_empty_when_no_prior_bindings_match() {
    // Blocked entry exists but trusted deps have no entry for
    // any prior version of the same name. First-time review path.
    let bc = bc_with_blocked(vec![bp_for_diff(
        "esbuild",
        "0.25.1",
        Some("sha256-fresh"),
        None,
    )]);
    let trusted = lpm_workspace::TrustedDependencies::default();
    let hints = compute_post_install_version_diff_hints(&bc, &trusted);
    assert!(hints.is_empty(), "no prior binding → no hint");
}

#[test]
fn post_install_version_diff_hints_emit_one_per_drifted_blocked_with_prior() {
    // Two blocked, both with prior bindings, both drifted.
    // Expect two hints, in blocked_packages order.
    use lpm_workspace::TrustedDependencies;
    use std::collections::HashMap;

    let bc = bc_with_blocked(vec![
        bp_for_diff("axios", "1.14.1", Some("sha256-axios-new"), None),
        bp_for_diff("esbuild", "0.25.2", Some("sha256-esbuild-new"), None),
    ]);
    let mut map = HashMap::new();
    map.insert(
        "axios@1.14.0".into(),
        lpm_workspace::TrustedDependencyBinding {
            script_hash: Some("sha256-axios-old".into()),
            ..Default::default()
        },
    );
    map.insert(
        "esbuild@0.25.1".into(),
        lpm_workspace::TrustedDependencyBinding {
            script_hash: Some("sha256-esbuild-old".into()),
            ..Default::default()
        },
    );
    let trusted = TrustedDependencies::Rich(map);

    let hints = compute_post_install_version_diff_hints(&bc, &trusted);
    assert_eq!(hints.len(), 2);
    // blocked_packages is sorted by (name, version) inside
    // compute_blocked_packages_with_metadata; the bc helper here
    // uses the order passed. For this assertion we only care
    // about set membership.
    let joined = hints.join("\n");
    assert!(joined.contains("axios@1.14.1"));
    assert!(joined.contains("esbuild@0.25.2"));
    assert!(joined.contains("script content changed since v1.14.0"));
    assert!(joined.contains("script content changed since v0.25.1"));
}

#[test]
fn post_install_version_diff_hints_skip_blocked_with_prior_but_no_change() {
    // Edge case: prior binding exists, but the diff classifies
    // as NoChange (e.g., script_hash equal because it hasn't
    // actually drifted; the entry might be blocked for an
    // unrelated reason like `binding_drift = false` /
    // `NotTrusted`). The hint must NOT fire — there is nothing
    // to surface.
    use lpm_workspace::TrustedDependencies;
    use std::collections::HashMap;

    let bc = bc_with_blocked(vec![bp_for_diff(
        "stable",
        "2.0.0",
        Some("sha256-same"),
        None,
    )]);
    let mut map = HashMap::new();
    map.insert(
        "stable@1.0.0".into(),
        lpm_workspace::TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            ..Default::default()
        },
    );
    let trusted = TrustedDependencies::Rich(map);

    let hints = compute_post_install_version_diff_hints(&bc, &trusted);
    assert!(
        hints.is_empty(),
        "NoChange diff must NOT produce a terse hint — got {hints:?}"
    );
}

#[test]
fn post_install_version_diff_hints_surface_behavioral_tag_delta() {
    // Ship criterion 2 at the install layer: gained tags must
    // appear in the install output without entering approve-
    // builds. This is the C2 verification of the criterion at
    // the post-install enrichment site (the preflight card path
    // is the second verification — covered by the
    // version_diff::tests rendering tests).
    use lpm_workspace::TrustedDependencies;
    use std::collections::HashMap;

    let bc = bc_with_blocked(vec![bp_for_diff(
        "suspicious",
        "2.0.0",
        Some("sha256-same"),
        Some(vec!["crypto", "eval", "network"]),
    )]);
    let mut bp_with_hash = bc.state.blocked_packages[0].clone();
    bp_with_hash.behavioral_tags_hash = Some("sha256-after".into());
    let bc = bc_with_blocked(vec![bp_with_hash]);

    let mut map = HashMap::new();
    map.insert(
        "suspicious@1.0.0".into(),
        lpm_workspace::TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec!["crypto".into()]),
            ..Default::default()
        },
    );
    let trusted = TrustedDependencies::Rich(map);

    let hints = compute_post_install_version_diff_hints(&bc, &trusted);
    assert_eq!(hints.len(), 1);
    let line = &hints[0];
    assert!(
        line.contains("+eval") && line.contains("+network"),
        "gained tags must surface in terse hint — got {line}"
    );
}
