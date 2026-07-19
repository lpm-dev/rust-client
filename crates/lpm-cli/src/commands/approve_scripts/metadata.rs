use super::prelude::*;

/// Project the install-time-captured fields off a
/// [`BlockedPackage`] into the [`ApprovalMetadata`] bundle that
/// [`TrustedDependencies::approve_with_metadata`] persists.
///
/// Centralized so each future approval-time field addition only edits
/// one site instead of every `--yes` / direct / interactive call.
/// Keeps the approval binding in lockstep with the install-time
/// behavioral tag capture: `BlockedPackage.behavioral_tags{,_hash}`
/// flows into the binding's `behavioral_tags{,_hash}`.
///
/// Additionally threads the project-
/// level capability hash through. `capability_hash` is a single
/// value for the entire invocation — the user approved ONE project
/// capability request, which binds every package approved in this
/// run. The caller computes it once (see the `run` function) from
/// the same `CapabilitySet` object the prompt renderer consumed,
/// so the hash persisted here matches the hash the runtime will
/// later enforce against. Passing an already-computed hash (not
/// a `CapabilitySet`) makes the "same canonical object" invariant
/// visible in the function signature: if a future refactor tries
/// to re-parse or recompute here, the diff will call attention to
/// the trust-boundary slip.
///
/// `provenance_at_approval` is captured at approval time. The caller
/// pre-fetches snapshots for the effective blocked set in parallel via
/// [`fetch_provenance_for_effective_set`] and passes the looked-up
/// value here. Same downstream semantics: the binding's
/// `provenance_at_approval` is what the next install's drift gate
/// compares against.
pub(super) fn approval_metadata_from_blocked(
    blocked: &BlockedPackage,
    capability_hash: Option<String>,
    provenance_at_approval: Option<ProvenanceSnapshot>,
) -> ApprovalMetadata {
    ApprovalMetadata {
        integrity: blocked.integrity.clone(),
        script_hash: blocked.script_hash.clone(),
        provenance_at_approval,
        behavioral_tags_hash: blocked.behavioral_tags_hash.clone(),
        behavioral_tags: blocked.behavioral_tags.clone(),
        capability_hash,
    }
}

/// Build approval metadata, preserving any prior verified
/// `provenance_at_approval` if the incoming snapshot is `None` and
/// an existing exact-version binding carries one.
///
/// Why: `TrustedDependencies::approve_with_metadata` unconditionally
/// overwrites the rich-map entry for `name@version`. Under Warn /
/// Off, [`snapshot_for_binding_with_mode`] returns `Ok(None)` on
/// `VerificationRejected` so the approval can proceed without the
/// new verifier observation. If the user had previously approved
/// the SAME exact version under Deny (with a verified snapshot
/// recorded), a naive re-approval would silently clear that
/// snapshot, permanently disarming drift detection for that exact
/// version. Preserving the prior value keeps the drift reference
/// intact while the new approval still goes through.
///
/// The preservation only fires when the *new* snapshot is `None`.
/// A Verified re-approval (incoming `Some(new)`) always wins —
/// fresh successful verification is the strongest signal.
pub(super) fn approval_metadata_preserving_existing_provenance(
    trusted: &TrustedDependencies,
    blocked: &BlockedPackage,
    capability_hash: Option<String>,
    incoming: Option<ProvenanceSnapshot>,
) -> ApprovalMetadata {
    let mut meta = approval_metadata_from_blocked(blocked, capability_hash, incoming);
    if meta.provenance_at_approval.is_none()
        && let Some(existing) = trusted.binding_for_exact_version(&blocked.name, &blocked.version)
        && let Some(prior) = existing.provenance_at_approval.clone()
    {
        meta.provenance_at_approval = Some(prior);
    }
    meta
}

pub(super) fn authorize_project_trust_write(
    project_dir: &Path,
    trusted: &TrustedDependencies,
    json_output: bool,
    reviewed_by_prompt: bool,
) -> Result<(), LpmError> {
    if reviewed_by_prompt {
        crate::security_approval::record_project_trust_candidate_authorized_from_managed_flow(
            project_dir,
            trusted,
            crate::security_approval::ApprovalSource::ApproveScripts,
        )
    } else {
        crate::security_approval::ensure_project_trust_candidate_authorized(
            project_dir,
            trusted,
            json_output,
            crate::security_approval::ApprovalSource::CliFlag,
        )
    }
}

/// Fetch attestation snapshots for an effective
/// blocked set at approval time.
///
/// `lpm install` intentionally does no provenance fetching. The only
/// end-consumer is `approve-scripts`, which reviews a small subset of
/// the install (typically 1–10 scripted packages out of hundreds), so
/// fetching at approval time is strictly less work and removes the cost
/// from the cold install critical path.
///
/// Drift detection is unaffected: the install drift gate
/// (`commands/install.rs`) re-fetches candidate attestations on the
/// fresh-resolution path independently and reads
/// `provenance_at_approval` (the value this function feeds into the
/// binding) as its reference.
///
/// delegates to
/// [`crate::provenance_fetch::fetch_provenance_for_pkgs`], the
/// single source of truth shared with the global-scope approve path
/// (`lpm approve-scripts --global`). This wrapper keeps the
/// `BlockedPackage` shape callers used pre-existing working unchanged.
///
/// The `--unverified-provenance[-all]` opt-out lives on
/// `lpm install` (not on `approve-scripts`), so the policy here
/// uses the operator-persistent posture chain (env +
/// `[sigstore] verify` config) — same shape the install pipeline
/// uses. `SkipPolicy` is fixed at `None` because per-package skip
/// decisions are not surfaced on approve-scripts: the approval
/// path's only job is to record a binding, and degrading
/// individual packages to identity-only there would silently strip
/// a layer of evidence the install path already captured.
pub(super) async fn fetch_provenance_for_effective_set(
    registry: &lpm_registry::RegistryClient,
    route_table: &lpm_registry::RouteTable,
    packages: &[BlockedPackage],
    policy: &crate::provenance_fetch::VerifyPolicy,
) -> HashMap<crate::provenance_fetch::ApprovalProvenanceKey, ProvenanceStatus> {
    let pkgs: Vec<crate::provenance_fetch::ApprovalProvenanceKey> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.source.clone()))
        .collect();
    crate::provenance_fetch::fetch_provenance_for_pkgs(registry, route_table, &pkgs, policy).await
}

pub(super) fn runtime_verify_policy_with_source() -> (
    crate::provenance_fetch::VerifyPolicy,
    crate::provenance_fetch::EnforceModeSource,
) {
    let cfg = crate::commands::config::GlobalConfig::load();
    crate::provenance_fetch::VerifyPolicy::resolve_from_chain(
        Vec::new(),
        false,
        std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
        || cfg.get_sigstore_verify(),
    )
}

/// Resolve the `provenance_at_approval` value for one `(name, version)`
/// pair from a batch [`ProvenanceStatus`] map, honoring the operator's
/// `LPM_PROVENANCE_ENFORCE` setting (rollout knob).
///
/// This is the project- and global-scope approval-capture hook that
/// closes the SILENT-DROP attack window: a previous `.ok().flatten()`
/// pattern collapsed verifier rejections into `None`, which the next
/// install's drift comparator treated as "first observation" via its
/// `(None, _) => NoDrift` arm.
///
/// Behavior under each [`EnforceMode`]:
///
/// - `Deny` (default): a `VerificationRejected` status returns
///   `Err(LpmError::ProvenanceVerification(...))` and the caller's
///   `?` short-circuits before any trust-store mutation. Prior
///   binding stays intact.
/// - `Warn`: a `VerificationRejected` status emits `tracing::warn` +
///   `output::warn` (loud, named, with the verifier reason) and
///   returns `Ok(None)`. The caller's read-modify-write proceeds,
///   recording `provenance_at_approval: None` — same effect as a
///   transport-degraded fetch during the approval window. This is
///   the rollout-window posture; operators MUST monitor
///   the warn line.
///
/// Non-rejection statuses (`Verified`, `Absent`, `TransportDegraded`)
/// project identically under both modes — the mode only affects the
/// rejection arm.
pub(super) fn snapshot_for_binding(
    provenance_by_pkg: &HashMap<crate::provenance_fetch::ApprovalProvenanceKey, ProvenanceStatus>,
    name: &str,
    version: &str,
    source: Option<&str>,
    mode: crate::provenance_fetch::EnforceMode,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    snapshot_for_binding_with_mode(provenance_by_pkg, name, version, source, mode)
}

/// Pure variant of [`snapshot_for_binding`] that takes the
/// [`EnforceMode`] explicitly, for unit tests that don't want to
/// mutate process-global env state.
pub(super) fn snapshot_for_binding_with_mode(
    provenance_by_pkg: &HashMap<crate::provenance_fetch::ApprovalProvenanceKey, ProvenanceStatus>,
    name: &str,
    version: &str,
    source: Option<&str>,
    mode: crate::provenance_fetch::EnforceMode,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    let status = match provenance_by_pkg.get(&(
        name.to_string(),
        version.to_string(),
        source.map(str::to_string),
    )) {
        Some(s) => s.clone(),
        None => return Ok(None),
    };

    // Warn / Off short-circuit on VerificationRejected: log loudly but
    // do NOT propagate as Err, so the approval proceeds and the
    // binding records `provenance_at_approval: None`. Every other
    // status (Verified / Unverified / Absent / TransportDegraded)
    // falls through to the default projection regardless of mode.
    //
    // Off here is the "operator opted out fleet-wide" case: a
    // VerificationRejected reaching this point only happens when the
    // upstream verifier path ran anyway (e.g. a code path that didn't
    // consult `should_skip_verification_for`); treat it as a degraded
    // observation rather than failing the approval the operator
    // explicitly asked to allow.
    if let ProvenanceStatus::VerificationRejected { reason } = &status
        && matches!(
            mode,
            crate::provenance_fetch::EnforceMode::Warn | crate::provenance_fetch::EnforceMode::Off
        )
    {
        let mode_label = match mode {
            crate::provenance_fetch::EnforceMode::Warn => "warn",
            crate::provenance_fetch::EnforceMode::Off => "off",
            crate::provenance_fetch::EnforceMode::Deny => unreachable!("guarded by matches!"),
        };
        tracing::warn!(
            target = "lpm::provenance",
            pkg = %name,
            version = %version,
            reason = %reason,
            enforce_mode = mode_label,
            "verifier rejected provenance bundle but enforce-mode is not deny; \
             recording approval with no provenance reference. Subsequent installs will \
             treat this as a degraded state until the operator re-approves under deny."
        );
        crate::output::warn(&format!(
            "provenance verification FAILED for {name}@{version}: {reason}\n  \
             LPM_PROVENANCE_ENFORCE={mode_label} — approval proceeds; the trust binding \
             records no verified identity. Re-run with LPM_PROVENANCE_ENFORCE=deny \
             (default) to refuse, or remediate the underlying bundle and re-approve."
        ));
        return Ok(None);
    }

    status.into_snapshot_for_binding(name, version)
}

/// Stable schema version for the `--json` output. Bump on any breaking
/// change to the JSON shape so agents can branch on it.
///
/// Version history:
/// - **v1**: initial schema — blocked entries carry
///   `name`, `version`, `integrity`, `script_hash`, `phases_present`,
///   `binding_drift`.
/// - **v2** : adds `static_tier` on each
///   blocked entry. Value is one of `"green" | "amber" | "amber-llm"
///   | "red"` when classification ran, or `null` when the persisted
///   state predates (readers should tolerate `null` to stay
///   forward-compatible with v1 state that predates a re-install).
/// - **v3** : adds `version_diff` on each
///   blocked entry. `null` when no prior approved binding exists for
///   this package name (first-time review); otherwise the structured
///   object documented on
///   [`crate::version_diff::version_diff_to_json`] — includes
///   `reason: "no-change"` for "we found the prior but no dimension
///   drifted" so agents can distinguish that from "no prior to
///   compare." Pre-v3 readers ignore the new field; v3+ readers
///   branch on `schema_version >= 3` to know when to expect it.
pub const SCHEMA_VERSION: u32 = 3;
