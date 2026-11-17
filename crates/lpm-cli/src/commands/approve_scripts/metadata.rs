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
/// an existing exact-artifact binding carries one.
///
/// Why: `TrustedDependencies::approve_with_metadata` updates the rich-map
/// entry for the same artifact. Under Warn /
/// Off, [`snapshot_for_binding_with_mode`] returns `Ok(None)` on
/// `VerificationRejected` so the approval can proceed without the
/// new verifier observation. If the user had previously approved
/// the same exact artifact under Deny (with a verified snapshot
/// recorded), a naive re-approval would silently clear that
/// snapshot, permanently disarming drift detection for that exact
/// artifact. Preserving the prior value keeps the drift reference
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
        && let Some(existing) = trusted.binding_for_artifact(
            &blocked.name,
            &blocked.version,
            blocked.integrity.as_deref(),
            blocked.script_hash.as_deref(),
        )
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

pub(super) async fn commit_project_trust_write(
    project_dir: &Path,
    pkg_json_path: &Path,
    reviewed_manifest_text: &str,
    manifest: &mut serde_json::Value,
    trusted: &TrustedDependencies,
    json_output: bool,
    reviewed_by_prompt: bool,
) -> Result<(), LpmError> {
    crate::commands::install::workspace_lockfile::scope_member_project_mutation(
        project_dir,
        async {
            ensure_manifest_unchanged(pkg_json_path, reviewed_manifest_text)?;
            authorize_project_trust_write(project_dir, trusted, json_output, reviewed_by_prompt)?;
            write_back(pkg_json_path, reviewed_manifest_text, manifest, trusted)
        },
    )
    .await
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
/// [`crate::provenance_fetch::fetch_provenance_for_artifacts`], the
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
#[cfg(test)]
pub(super) async fn fetch_provenance_for_effective_set(
    registry: &lpm_registry::RegistryClient,
    routes: &lpm_registry::RouteTable,
    packages: &[BlockedPackage],
    policy: &crate::provenance_fetch::VerifyPolicy,
) -> HashMap<crate::provenance_fetch::ProvenanceArtifactKey, ProvenanceStatus> {
    let pkgs: Vec<crate::provenance_fetch::ProvenanceArtifactKey> =
        packages.iter().map(artifact_key).collect();
    crate::provenance_fetch::fetch_provenance_for_artifacts(registry, routes, &pkgs, policy).await
}

pub(super) fn artifact_key(
    package: &BlockedPackage,
) -> crate::provenance_fetch::ProvenanceArtifactKey {
    (
        package.name.clone(),
        package.version.clone(),
        package.integrity.clone(),
    )
}

/// The client and routes an install in `dir` resolves `names` with: the
/// project for a project approval, the global install root for a global
/// one. The client carries the TLS settings an `.npmrc` gives those
/// registries, as an install's does.
pub(super) fn install_registries<'a>(
    registry: &lpm_registry::RegistryClient,
    dir: &Path,
    names: impl Iterator<Item = &'a str>,
    json_output: bool,
) -> Result<crate::commands::registry_reads::RoutedReadContext, LpmError> {
    let names: Vec<String> = names.map(str::to_owned).collect();
    crate::commands::registry_reads::prepare_routed_read_context(registry, dir, &names, json_output)
}

/// Reads provenance for a project's blocked packages from the registries
/// its install got them from.
pub(super) struct ProjectProvenance {
    registries: crate::commands::registry_reads::RoutedReadContext,
    /// The registry the lockfile records for each candidate that came
    /// from one.
    recorded: HashMap<crate::provenance_fetch::ProvenanceArtifactKey, String>,
    /// The candidates the lockfile records from a tarball, a git
    /// repository or a directory.
    outside_a_registry: std::collections::HashSet<crate::provenance_fetch::ProvenanceArtifactKey>,
    lockfile_read: bool,
    availability: crate::provenance_fetch::AvailabilityMode,
}

impl ProjectProvenance {
    /// Loads the project's routes and what its lockfile records for
    /// `candidates`. A broken `.npmrc` fails here, before anything is
    /// asked of the user or a registry.
    pub(super) fn prepare(
        registry: &lpm_registry::RegistryClient,
        project_dir: &Path,
        candidates: &[BlockedPackage],
        availability: crate::provenance_fetch::AvailabilityMode,
        json_output: bool,
    ) -> Result<Self, LpmError> {
        let registries = install_registries(
            registry,
            project_dir,
            candidates.iter().map(|package| package.name.as_str()),
            json_output,
        )?;
        let lockfile = read_lockfile(project_dir, || {
            crate::commands::install::workspace_lockfile::read_project(project_dir)
        });
        let keys: std::collections::HashSet<_> = candidates.iter().map(artifact_key).collect();
        let rows = || lockfile.iter().flat_map(|lockfile| &lockfile.packages);
        let outside_a_registry = installed_from_outside_a_registry(&keys, rows());
        let recorded = recorded_registries(keys, rows());
        Ok(Self {
            registries,
            recorded,
            outside_a_registry,
            lockfile_read: lockfile.is_some(),
            availability,
        })
    }

    /// Reads the provenance of those of `packages` a registry can speak
    /// for. The rest get no status, and so no provenance to compare a
    /// later install with; under strict availability, one that should have
    /// a registry's word but can't get it here refuses them all, as a named
    /// or `--yes` approval must.
    pub(super) async fn fetch(
        &self,
        packages: impl Iterator<Item = crate::provenance_fetch::ProvenanceArtifactKey>,
        policy: &crate::provenance_fetch::VerifyPolicy,
    ) -> Result<HashMap<crate::provenance_fetch::ProvenanceArtifactKey, ProvenanceStatus>, LpmError>
    {
        let requested: Vec<_> = packages.collect();
        let (vouched, unchecked) = self.checkable(&requested)?;
        if let Some((_, reason)) = unchecked.into_iter().next() {
            return Err(LpmError::ProvenanceUnavailable(reason));
        }
        Ok(self.statuses(&vouched, policy).await)
    }

    /// [`Self::fetch`] for a review that asks about each package: one strict
    /// availability can't check is returned with why, to be skipped.
    pub(super) async fn review(
        &self,
        packages: impl Iterator<Item = crate::provenance_fetch::ProvenanceArtifactKey>,
        policy: &crate::provenance_fetch::VerifyPolicy,
    ) -> Result<ApprovalProvenance, LpmError> {
        let requested: Vec<_> = packages.collect();
        let (vouched, unchecked) = self.checkable(&requested)?;
        Ok((self.statuses(&vouched, policy).await, unchecked))
    }

    /// The packages a registry can speak for, and those strict availability
    /// can't check here.
    #[allow(clippy::type_complexity)]
    fn checkable(
        &self,
        requested: &[crate::provenance_fetch::ProvenanceArtifactKey],
    ) -> Result<
        (
            Vec<crate::provenance_fetch::ProvenanceArtifactKey>,
            Vec<(crate::provenance_fetch::ProvenanceArtifactKey, String)>,
        ),
        LpmError,
    > {
        let vouched = installed_from_their_registry(
            &self.registries,
            &self.recorded,
            requested.iter().cloned(),
        );
        let unchecked = unchecked_packages(
            self.availability,
            self.lockfile_read,
            &self.recorded,
            &self.outside_a_registry,
            &vouched,
            requested,
            ApprovalScope::Project,
        )?;
        Ok((vouched, unchecked))
    }

    async fn statuses(
        &self,
        vouched: &[crate::provenance_fetch::ProvenanceArtifactKey],
        policy: &crate::provenance_fetch::VerifyPolicy,
    ) -> HashMap<crate::provenance_fetch::ProvenanceArtifactKey, ProvenanceStatus> {
        crate::provenance_fetch::fetch_provenance_for_artifacts(
            &self.registries.client,
            &self.registries.route_table,
            vouched,
            policy,
        )
        .await
    }
}

/// The provenance a review read for each package, and, in order, the
/// packages strict availability can't check here with why.
pub(super) type ApprovalProvenance = (
    HashMap<crate::provenance_fetch::ProvenanceArtifactKey, ProvenanceStatus>,
    Vec<(crate::provenance_fetch::ProvenanceArtifactKey, String)>,
);

/// Where an approval is recorded, which decides how to get a lockfile that
/// records where its packages came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ApprovalScope {
    Project,
    Global,
}

impl ApprovalScope {
    fn reinstall(self) -> &'static str {
        match self {
            Self::Project => "Run `lpm install`",
            Self::Global => "Reinstall the global package with `lpm install -g`",
        }
    }
}

/// Under strict availability, the `requested` packages whose provenance
/// can't be read here though a registry may speak for them, in order, with
/// why: a package's route now sends it to another registry than the one it
/// was installed from, or the lockfile doesn't record one registry for it.
/// Packages from a tarball, a git repository or a directory,
/// `outside_a_registry`, have none to read. Fails when the lockfiles that
/// say where they came from can't all be read, which leaves none checkable.
pub(super) fn unchecked_packages(
    availability: crate::provenance_fetch::AvailabilityMode,
    lockfiles_read: bool,
    recorded: &HashMap<crate::provenance_fetch::ProvenanceArtifactKey, String>,
    outside_a_registry: &std::collections::HashSet<crate::provenance_fetch::ProvenanceArtifactKey>,
    vouched: &[crate::provenance_fetch::ProvenanceArtifactKey],
    requested: &[crate::provenance_fetch::ProvenanceArtifactKey],
    scope: ApprovalScope,
) -> Result<Vec<(crate::provenance_fetch::ProvenanceArtifactKey, String)>, LpmError> {
    if !availability.is_strict() || requested.is_empty() {
        return Ok(Vec::new());
    }
    let reinstall = scope.reinstall();
    if !lockfiles_read {
        return Err(LpmError::ProvenanceUnavailable(format!(
            "strict provenance availability can't check this approval: a lockfile that records \
             where its packages came from can't be read. {reinstall}, then approve again"
        )));
    }
    let vouched: std::collections::HashSet<_> = vouched.iter().collect();
    Ok(requested
        .iter()
        .filter(|package| !vouched.contains(package) && !outside_a_registry.contains(*package))
        .map(|package| {
            let reason = if recorded.contains_key(package) {
                "it now routes to another registry than the one it was installed from"
            } else {
                "the lockfile doesn't record one registry it came from"
            };
            let (name, version, _) = package;
            (
                package.clone(),
                format!(
                    "strict provenance availability can't check {name}@{version}: {reason}. \
                     {reinstall}, then approve it again"
                ),
            )
        })
        .collect())
}

/// Those of `candidates` a lockfile row says came from outside a registry:
/// a tarball, a git repository or a directory. No registry speaks for them,
/// unlike a row whose source is unknown.
pub(super) fn installed_from_outside_a_registry<'a>(
    candidates: &std::collections::HashSet<crate::provenance_fetch::ProvenanceArtifactKey>,
    rows: impl Iterator<Item = &'a lpm_lockfile::LockedPackage>,
) -> std::collections::HashSet<crate::provenance_fetch::ProvenanceArtifactKey> {
    let mut outside = std::collections::HashSet::new();
    for row in rows {
        if !matches!(row.source_kind(), Some(Ok(source)) if !matches!(source, lpm_lockfile::Source::Registry { .. }))
        {
            continue;
        }
        outside.extend(
            candidates
                .iter()
                .filter(|(name, version, integrity)| {
                    *name == row.name
                        && *version == row.version
                        && !matches!(
                            (&row.integrity, integrity),
                            (Some(pinned), Some(known))
                                if lpm_common::integrity::contradict(pinned, known)
                        )
                })
                .cloned(),
        );
    }
    outside
}

/// The lockfile of the install in `dir`, or `None` with a warning when it
/// can't be read: no package is then known to come from a registry, and
/// an approval records no provenance.
pub(super) fn read_lockfile(
    dir: &Path,
    read: impl FnOnce() -> Result<lpm_lockfile::Lockfile, lpm_lockfile::LockfileError>,
) -> Option<lpm_lockfile::Lockfile> {
    read()
        .inspect_err(|error| {
            tracing::warn!(
                "no provenance is recorded for packages installed in {}: its lockfile can't be read: {error}",
                dir.display()
            );
        })
        .ok()
}

/// Those of `packages` that `registries` still sends to the registry
/// `recorded` says they were installed from.
pub(super) fn installed_from_their_registry(
    registries: &crate::commands::registry_reads::RoutedReadContext,
    recorded: &HashMap<crate::provenance_fetch::ProvenanceArtifactKey, String>,
    packages: impl Iterator<Item = crate::provenance_fetch::ProvenanceArtifactKey>,
) -> Vec<crate::provenance_fetch::ProvenanceArtifactKey> {
    packages
        .filter(|package| {
            recorded.get(package).is_some_and(|recorded| {
                same_registry(
                    recorded,
                    &crate::commands::install::registry_source_url_for(
                        &package.0,
                        &registries.route_table,
                        &registries.client,
                    ),
                )
            })
        })
        .collect()
}

/// The registry each of `candidates` was installed from, as the lockfile
/// `rows` record it. A package installed from a tarball, a git repository
/// or a directory has none: a registry that publishes something under the
/// same name and version says nothing about it. Nor has one that rows
/// record from two registries, as two global installs can.
///
/// A row is a candidate's when the name and version are and the two
/// integrities don't contradict each other: a lockfile can pin by a
/// weaker hash the bytes an install knows by their sha512.
pub(super) fn recorded_registries<'a>(
    candidates: std::collections::HashSet<crate::provenance_fetch::ProvenanceArtifactKey>,
    rows: impl Iterator<Item = &'a lpm_lockfile::LockedPackage>,
) -> HashMap<crate::provenance_fetch::ProvenanceArtifactKey, String> {
    let mut by_version: HashMap<
        (&str, &str),
        Vec<&crate::provenance_fetch::ProvenanceArtifactKey>,
    > = HashMap::new();
    for candidate in &candidates {
        by_version
            .entry((candidate.0.as_str(), candidate.1.as_str()))
            .or_default()
            .push(candidate);
    }
    let mut recorded = HashMap::new();
    let mut disputed = std::collections::HashSet::new();
    for row in rows {
        let Some(installed) = by_version.get(&(row.name.as_str(), row.version.as_str())) else {
            continue;
        };
        let registry = match row.source_kind() {
            Some(Ok(lpm_lockfile::Source::Registry { url })) => Some(url),
            // A row from before lockfiles recorded sources is npm's, as
            // install reads it.
            None => Some(NPM_REGISTRY.to_owned()),
            _ => None,
        };
        for candidate in installed {
            if let (Some(pinned), Some(known)) = (&row.integrity, &candidate.2)
                && lpm_common::integrity::contradict(pinned, known)
            {
                continue;
            }
            match (&registry, recorded.get(*candidate)) {
                (Some(registry), None) => {
                    recorded.insert((*candidate).clone(), registry.clone());
                }
                (Some(registry), Some(earlier)) if same_registry(earlier, registry) => {}
                _ => {
                    disputed.insert((*candidate).clone());
                }
            }
        }
    }
    recorded.retain(|candidate, _| !disputed.contains(candidate));
    recorded
}

const NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// Whether two registry URLs name one registry. A package is asked about
/// only at the registry it was installed from, so a route that changed
/// since the install sends its name nowhere new.
fn same_registry(recorded: &str, routed: &str) -> bool {
    recorded.trim_end_matches('/') == routed.trim_end_matches('/')
}

/// The operator's `[sigstore] availability`, which an approval meets as an
/// install does: a config that can't be read stops it, as it stops an
/// install, rather than leaving availability at best-effort.
pub(super) fn runtime_availability_mode()
-> Result<crate::provenance_fetch::AvailabilityMode, LpmError> {
    crate::provenance_fetch::AvailabilityMode::from_config(
        crate::commands::config::GlobalConfig::load_checked()?
            .get_sigstore_availability()
            .as_deref(),
    )
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
/// rejection arm. Under strict `availability`, `Absent` and
/// `TransportDegraded` refuse the approval as they refuse an install.
/// Pure coordinate-keyed variant for unit tests of enforcement-mode behavior.
#[cfg(test)]
pub(super) fn snapshot_for_binding_with_mode(
    provenance_by_pkg: &HashMap<(String, String), ProvenanceStatus>,
    name: &str,
    version: &str,
    mode: crate::provenance_fetch::EnforceMode,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    snapshot_status_for_binding(
        provenance_by_pkg.get(&(name.to_string(), version.to_string())),
        name,
        version,
        mode,
        crate::provenance_fetch::AvailabilityMode::BestEffort,
    )
}

/// Why committing an approval of this artifact would refuse it, as
/// [`snapshot_for_artifact_binding`] would, without the warnings that
/// committing prints, so a walk skips it before asking.
pub(super) fn approval_refusal(
    provenance_by_artifact: &HashMap<
        crate::provenance_fetch::ProvenanceArtifactKey,
        ProvenanceStatus,
    >,
    name: &str,
    version: &str,
    integrity: Option<&str>,
    mode: crate::provenance_fetch::EnforceMode,
    availability: crate::provenance_fetch::AvailabilityMode,
) -> Option<LpmError> {
    let status = provenance_by_artifact.get(&(
        name.to_owned(),
        version.to_owned(),
        integrity.map(ToOwned::to_owned),
    ))?;
    if let Err(refusal) = availability.require(status, name, version) {
        return Some(refusal);
    }
    match status {
        ProvenanceStatus::VerificationRejected { .. }
            if matches!(mode, crate::provenance_fetch::EnforceMode::Deny) =>
        {
            status
                .clone()
                .into_snapshot_for_binding(name, version)
                .err()
        }
        _ => None,
    }
}

pub(super) fn snapshot_for_artifact_binding(
    provenance_by_artifact: &HashMap<
        crate::provenance_fetch::ProvenanceArtifactKey,
        ProvenanceStatus,
    >,
    name: &str,
    version: &str,
    integrity: Option<&str>,
    mode: crate::provenance_fetch::EnforceMode,
    availability: crate::provenance_fetch::AvailabilityMode,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    let key = (
        name.to_string(),
        version.to_string(),
        integrity.map(ToOwned::to_owned),
    );
    snapshot_status_for_binding(
        provenance_by_artifact.get(&key),
        name,
        version,
        mode,
        availability,
    )
}

fn snapshot_status_for_binding(
    status: Option<&ProvenanceStatus>,
    name: &str,
    version: &str,
    mode: crate::provenance_fetch::EnforceMode,
    availability: crate::provenance_fetch::AvailabilityMode,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    let Some(status) = status.cloned() else {
        return Ok(None);
    };
    availability.require(&status, name, version)?;

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
/// - **v4**: adds `reach` on each blocked entry, project and global:
///   `null` when the persisted state predates the scan, otherwise
///   `{findings, incomplete, requires_individual_review}` (see
///   [`crate::version_diff::reach_to_json`]). Global entries also gain
///   `static_tier`.
pub const SCHEMA_VERSION: u32 = 4;
