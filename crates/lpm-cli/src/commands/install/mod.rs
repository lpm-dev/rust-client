use crate::install_ui;
use crate::output;
use crate::overrides_state;
use crate::patch_engine;
use crate::patch_state;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_linker::LinkTarget;
use lpm_registry::{GateDecision, RegistryClient, RouteTable, UpstreamRoute, evaluate_cached_url};
use lpm_resolver::{
    CachedPackageInfo, CanonicalKey, CompiledPeerRules, OverrideHit, OverrideSet,
    PeerConflictReport, PeerWarning, ResolvedPackage, SpeculativePackageMetadata,
    check_unmet_peers,
};
use lpm_store::PackageStore;
use lpm_workspace::PatchedDependencyEntry;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

mod catalog;
mod concurrency;
mod diff_util;
mod fetch;
mod fetch_overlap;
mod firewall;
mod gitignore;
mod lifecycle;
mod linking;
mod lockfile;
mod manifest;
mod package;
mod patches;
mod peer;
pub(crate) mod policy_extensions;
mod reporting;
mod resolve;
mod setup;
mod skills;
mod source_resolution;
mod state;
mod swift;
mod test_support;
#[cfg(test)]
mod tests;
mod timing;
mod validation;
mod workspace;

use catalog::*;
use concurrency::*;
use fetch::*;
use fetch_overlap::*;
use firewall::{
    NpmFirewallChunkedPreflightConfig, NpmFirewallLookupMode, NpmFirewallPreflightJoin,
    NpmFirewallPreflightRequest, NpmFirewallPreflightStats, finish_npm_firewall_preflight,
    npm_firewall_chunk_size_from_env, npm_firewall_has_packages, run_npm_firewall_preflight,
    spawn_chunked_npm_firewall_preflight,
};
pub(crate) use firewall::{
    NpmFirewallMaterializationPackage, prepare_npm_firewall_materialization_preflight,
    registry_materialization_route_is_public_npm,
    run_prepared_npm_firewall_materialization_preflight,
};
use gitignore::*;
pub use gitignore::{
    ensure_lpm_hoisted_gitignore, ensure_lpm_wrappers_gitignore, ensure_skills_gitignore,
};
use lifecycle::*;
use linking::*;
use lockfile::*;
pub(crate) use lockfile::{
    requested_range_for_locked_lookup, select_locked_package_for_requested_spec,
};
#[cfg(test)]
pub(crate) use manifest::finalize_packages_in_manifest;
use manifest::*;
#[cfg(test)]
pub(crate) use manifest::{StagedKind, stage_packages_to_manifest};
pub use manifest::{run_add_packages, run_install_filtered_add};
use package::*;
use patches::*;
use peer::*;
use policy_extensions::{
    PolicyExtensionStats, load_policy_extension_configs,
    policy_extensions_disable_tarball_prefetch,
    reject_remote_tarball_url_deps_with_policy_extensions, run_policy_extensions,
};
use reporting::*;
use resolve::experimental as experimental_resolver;
use resolve::*;
use setup::*;
use skills::*;
use source_resolution::*;
use state::*;
use swift::*;
use test_support::{maybe_test_audit_after_install_should_fail, maybe_test_panic};
use timing::*;
pub(crate) use validation::{FrozenLockfileMode, install_running_in_ci};
use validation::{
    LockfileValidationInput, LockfileValidationState, validate_install_lockfile_state,
};
pub(crate) use workspace::confirm_multi_member_mutation;
use workspace::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InstallOmitPolicy {
    pub dev: bool,
    pub optional: bool,
}

impl InstallOmitPolicy {
    fn is_default(self) -> bool {
        !self.dev && !self.optional
    }
}

fn publish_ages_from_resolved_metadata(
    packages: &[InstallPackage],
) -> HashMap<(String, String), u64> {
    let mut map = HashMap::with_capacity(packages.len());
    for package in packages {
        if let Some(age) = lpm_security::publish_age_secs(package.registry_published_at.as_deref())
        {
            map.insert((package.name.clone(), package.version.clone()), age);
        }
    }
    map
}

fn release_age_policy_applies_to_install_package(
    policy: crate::release_age_config::ReleaseAgePolicy,
    package: &InstallPackage,
) -> bool {
    policy.is_strict() || package.is_direct
}

fn timing_detail_start(enabled: bool) -> Option<Instant> {
    enabled.then(Instant::now)
}

fn record_timing_detail_ms(bucket: &mut u128, start: Option<Instant>) {
    if let Some(start) = start {
        *bucket = bucket.saturating_add(start.elapsed().as_millis());
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_with_options(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    offline: bool,
    frozen_lockfile: FrozenLockfileMode,
    force: bool,
    allow_new: bool,
    // () — strict_integrity: when true, tarball-URL
    // deps without a manifest-declared SRI fail rather than
    // trust-on-first-use. Lockfile-resident integrity is still
    // trusted; only the manifest-boundary trust-on-first-use is
    // disabled.
    strict_integrity: bool,
    cli_no_engine_strict: bool,
    // CLI-level override for strict peer-dependency handling. `None`
    // falls through to package.json / global config / default.
    strict_peer_dependencies_override: Option<bool>,
    // Already-resolved linker override from CLI / `~/.lpm/config.toml` / env.
    // `None` means fall through to `package.json > lpm > linker` (which is
    // validated against `lpm_linker::LinkerMode::parse_str` inside the
    // install pipeline) and finally the default isolated layout.
    linker_override: Option<lpm_linker::LinkerMode>,
    lpm_skills_preference: crate::lpm_skills_config::LpmSkillsPreference,
    no_editor_setup: bool,
    no_security_summary: bool,
    auto_build: bool,
    // when invoked from the workspace-aware install path,
    // the list of `package.json` files that were modified before this call.
    // Surfaced in the JSON output as `target_set` so agents can see which
    // workspace members were touched. `None` for legacy/standalone callers.
    target_set: Option<&[String]>,
    // Invariant: when `Some`, the install pipeline
    // populates the map with `name → resolved_version` for every DIRECT
    // dependency. Used by `run_add_packages` and `run_install_filtered_add`
    // to feed `finalize_packages_in_manifest` without doing a flat scan
    // over the lockfile (which can't distinguish direct from transitive
    // when the same name appears at different versions). Bare install
    // callers pass `None`.
    direct_versions_out: Option<&mut HashMap<String, lpm_semver::Version>>,
    // add-path reporting count. `Some(n)` means this install was
    // triggered by `lpm install <pkg...>` after staging `n` explicit
    // package specs into the manifest; the phase / Done lines should
    // report the user-requested count, not the full resolved graph.
    // Bare `lpm install` callers pass `None`.
    requested_add_count: Option<usize>,
    // CLI-side `--policy` / `--yolo` / `--triage`
    // override, already collapsed to at most one value by
    // [`crate::script_policy_config::collapse_policy_flags`]. `None`
    // means no CLI flag was passed on this invocation and the
    // resolver should fall through to the project config →
    // `~/.lpm/config.toml` → default-deny precedence chain.
    //
    // Only consumed in for the triage-mode install summary line
    // (branches at the two `show_install_build_hint` call sites). No
    // execution semantics are changed — tier-aware auto-run is,
    // gated on the sandbox.
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    // CLI `--advisor` override. Resolves to the
    // top of the [`AdvisorSession::preflight`] precedence chain
    // (CLI → package.json → ~/.lpm/config.toml → `none`). Owned
    // `String` rather than `&str` so the value crosses the
    // store-lock async hop (the inner future is `'static`-bound)
    // without a borrowed-lifetime gymnastic. Internal callers
    // (`upgrade`, `add`, `dev`, `deploy`, `doctor`, `run`,
    // `migrate`) pass `None` — they don't accept their own
    // `--advisor` flag today and a future opt-in is a one-line
    // change.
    //
    // The slug is validated at the clap layer (`parse_advisor_slug`
    // in `main.rs`), so an `Some` value here is guaranteed to be
    // `"none"` or a known provider slug. The session itself still
    // warn-degrades on unavailable adapters at runtime — clap only
    // catches typos, not "claude-cli configured but not on PATH."
    advisor_override: Option<String>,
    //: already-parsed `--min-release-age=<dur>` override. `Some`
    // short-circuits the package.json / global / default chain in
    // [`crate::release_age_config::ReleaseAgeResolver::resolve`]; `None`
    // walks the chain normally. Clap parses the duration string via
    // [`crate::release_age_config::parse_duration`] before this fn runs, so
    // validation errors never make it this far.
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    // canonicalized `--ignore-provenance-drift[-all]`
    // override (see [`crate::provenance_fetch::DriftIgnorePolicy`] for
    // the three variants). `EnforceAll` is the default; the drift gate
    // consults `.ignores_all()` for a short-circuit and
    // `.ignores_name(...)` per-package. `--allow-new` does NOT compose
    // into this policy (): drift and cooldown are orthogonal, so
    // their override flags stay separate.
    drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    // Composed `(EnforceMode, SkipPolicy)` for the Sigstore
    // verifier. The drift gate at the install-time call
    // consults `verify_policy.skip` to route skip-listed packages
    // through the legacy identity-only parser (producing
    // `ProvenanceStatus::Unverified`) instead of hard-failing on a
    // cryptographic rejection. Orthogonal to `drift_ignore_policy`:
    // one suppresses the *crypto* layer, the other suppresses the
    // *drift* layer.
    verify_policy: crate::provenance_fetch::VerifyPolicy,
    omit_policy: InstallOmitPolicy,
    // CLI sandbox-mode overrides.
    // `strict_sandbox=true` flips outbound network denial on for the
    // auto-build call; `no_sandbox=true` drops all containment for
    // that call. Clap-level mutex guarantees they never both arrive
    // `true`. The full precedence chain — CLI > env > project >
    // user > default — is resolved inside
    // [`crate::sandbox_config::resolve_sandbox_mode_from_chain`] at
    // the auto-build site; install-time pre-fetch does not engage
    // the sandbox, so this flag only matters when `auto_build` is
    // true.
    strict_sandbox: bool,
    no_sandbox: bool,
    // Top-level `--verbose` flag (long form only — `-v` is `--version`).
    // When true, the Done block appends a footer with per-phase timings
    // and the on-disk lockfile size.
    verbose: bool,
    // Resolved audit-after-install precedence (CLI > env > config >
    // default false). When true, the install pipeline runs the silent
    // [`crate::commands::audit::run_install_summary`] after the Done
    // block and emits a one-line advisory (or attaches `audit_summary`
    // to the JSON envelope). Audit results NEVER fail the install.
    audit_after_install: bool,
    timing: bool,
    compatibility_bin_names: &[String],
) -> Result<(), LpmError> {
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    run_with_options_with_lpm_root(
        client,
        project_dir,
        json_output,
        offline,
        frozen_lockfile,
        force,
        allow_new,
        strict_integrity,
        cli_no_engine_strict,
        strict_peer_dependencies_override,
        linker_override,
        lpm_skills_preference,
        no_editor_setup,
        no_security_summary,
        auto_build,
        target_set,
        direct_versions_out,
        requested_add_count,
        script_policy_override,
        advisor_override,
        min_release_age_override,
        min_release_age_exclude,
        drift_ignore_policy,
        verify_policy,
        omit_policy,
        strict_sandbox,
        no_sandbox,
        verbose,
        audit_after_install,
        timing,
        compatibility_bin_names,
        true,
        lpm_root,
    )
    .await
}

pub(crate) async fn run_silent_for_audit_fix(
    client: &RegistryClient,
    project_dir: &Path,
) -> Result<(), LpmError> {
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    run_with_options_with_lpm_root(
        client,
        project_dir,
        true,
        false,
        FrozenLockfileMode::Never,
        false,
        false,
        false,
        false,
        None,
        None,
        crate::lpm_skills_config::LpmSkillsPreference::Config,
        false,
        true,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        &[],
        crate::provenance_fetch::DriftIgnorePolicy::default(),
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        InstallOmitPolicy::default(),
        false,
        false,
        false,
        false,
        false,
        &[],
        false,
        lpm_root,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with_options_with_lpm_root(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    offline: bool,
    frozen_lockfile: FrozenLockfileMode,
    force: bool,
    allow_new: bool,
    strict_integrity: bool,
    cli_no_engine_strict: bool,
    strict_peer_dependencies_override: Option<bool>,
    linker_override: Option<lpm_linker::LinkerMode>,
    lpm_skills_preference: crate::lpm_skills_config::LpmSkillsPreference,
    no_editor_setup: bool,
    no_security_summary: bool,
    auto_build: bool,
    target_set: Option<&[String]>,
    direct_versions_out: Option<&mut HashMap<String, lpm_semver::Version>>,
    requested_add_count: Option<usize>,
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    advisor_override: Option<String>,
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    verify_policy: crate::provenance_fetch::VerifyPolicy,
    omit_policy: InstallOmitPolicy,
    strict_sandbox: bool,
    no_sandbox: bool,
    verbose: bool,
    audit_after_install: bool,
    timing: bool,
    compatibility_bin_names: &[String],
    emit_install_report: bool,
    lpm_root: lpm_common::LpmRoot,
) -> Result<(), LpmError> {
    let dependency_engine_policy = Arc::new(crate::engine_check::prepare_dependency_policy(
        project_dir,
        cli_no_engine_strict,
        json_output,
    )?);
    // Round 2: hold a shared lock on the store for the
    // entire install pipeline. Multiple concurrent installs share it
    // freely; `lpm cache prune --apply` and `lpm store clean` (which take it
    // exclusively) wait until every in-flight install releases. This
    // closes the read-vs-write race where gc could `remove_dir_all`
    // a CAS entry mid-`link_dir_recursive`.
    //
    // Acquired via the async helper so a contended lock doesn't block
    // the tokio reactor; the held handle lives for the lifetime of
    // the inner future and releases when the future returns.
    let store_lock_path = lpm_root.store_lock();
    lpm_common::with_shared_lock_async(
        store_lock_path,
        run_with_options_under_store_lock(
            client,
            project_dir,
            json_output,
            offline,
            frozen_lockfile,
            force,
            allow_new,
            strict_integrity,
            dependency_engine_policy,
            strict_peer_dependencies_override,
            linker_override,
            lpm_skills_preference,
            no_editor_setup,
            no_security_summary,
            auto_build,
            target_set,
            direct_versions_out,
            requested_add_count,
            script_policy_override,
            advisor_override,
            min_release_age_override,
            min_release_age_exclude,
            drift_ignore_policy,
            verify_policy,
            omit_policy,
            strict_sandbox,
            no_sandbox,
            verbose,
            audit_after_install,
            timing,
            compatibility_bin_names,
            emit_install_report,
            &lpm_root,
        ),
    )
    .await
}

/// Body of [`run_with_options`] — the actual install pipeline. Lives
/// in a private fn so the outer wrapper can hold the store-lock
/// handle for its full duration via `with_shared_lock_async`.
#[allow(clippy::too_many_arguments)]
async fn run_with_options_under_store_lock(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    offline: bool,
    frozen_lockfile: FrozenLockfileMode,
    force: bool,
    allow_new: bool,
    strict_integrity: bool,
    dependency_engine_policy: Arc<crate::engine_check::DependencyEnginePolicy>,
    strict_peer_dependencies_override: Option<bool>,
    linker_override: Option<lpm_linker::LinkerMode>,
    lpm_skills_preference: crate::lpm_skills_config::LpmSkillsPreference,
    _no_editor_setup: bool,
    no_security_summary: bool,
    auto_build: bool,
    target_set: Option<&[String]>,
    direct_versions_out: Option<&mut HashMap<String, lpm_semver::Version>>,
    requested_add_count: Option<usize>,
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    // see `run_with_options` for the contract.
    advisor_override: Option<String>,
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    // see `run_with_options` for the contract.
    verify_policy: crate::provenance_fetch::VerifyPolicy,
    omit_policy: InstallOmitPolicy,
    // Threaded down so the auto-build call below honors the user's
    // CLI sandbox-mode override.
    strict_sandbox: bool,
    no_sandbox: bool,
    // Forwarded `--verbose` flag from the CLI entry. Used only by the
    // Done-block footer; the rest of the pipeline ignores it.
    verbose: bool,
    // Resolved audit-after-install boolean — see [`run_with_options`].
    audit_after_install: bool,
    timing: bool,
    compatibility_bin_names: &[String],
    emit_install_report: bool,
    lpm_root: &lpm_common::LpmRoot,
) -> Result<(), LpmError> {
    let start = Instant::now();
    let InstallSetupContext {
        timing_detail_mode,
        emit_timing,
        global_config,
        object_integrity_policy,
        verify_registry_signatures,
        registry_signature_timings,
        provenance_timings,
        npm_firewall_lookup_mode,
        npm_firewall_policy_profile,
        npm_firewall_chunk_size,
        policy_extension_configs,
        force_security_floor,
        pkg_json_path,
        lockfile_path,
        frozen_lockfile_active,
        pkg,
        npm_firewall_mode,
        effective_min_age_secs,
        resolver_min_age_secs,
        release_age_policy,
        resolver_trust_policy,
        minimum_release_age_exclude,
        auto_install_peers,
        strict_peer_dependencies,
        pubgrub_opt_out,
        configured_linker_mode,
        peer_conflict_auto_isolation_allowed,
        auto_isolated_peer_conflicts,
        linker_mode,
        requested_v2_mode,
        manifest_deps,
        production_dependency_names,
    } = prepare_install_setup_context(InstallSetupInput {
        project_dir,
        json_output,
        frozen_lockfile,
        allow_new,
        strict_peer_dependencies_override,
        linker_override,
        min_release_age_override,
        min_release_age_exclude,
        timing,
    })?;
    let no_skills = !lpm_skills_preference.resolve(&global_config)?;
    let mut slow_package_timings = SlowPackageTimings::default();
    let mut wf_tail_audit_after_install_ms = 0u128;

    let InstallFreshnessResult {
        setup_install_state_ms: wf_setup_install_state_ms,
        cleanup_catalogs_in_pipeline,
        completed: freshness_completed,
    } = run_install_freshness_phase(InstallFreshnessInput {
        client,
        project_dir,
        pkg_json_path: &pkg_json_path,
        lockfile_path: &lockfile_path,
        manifest_deps: &manifest_deps,
        production_dependency_names: &production_dependency_names,
        policy_extension_configs: &policy_extension_configs,
        force,
        offline,
        no_skills,
        omit_policy,
        strict_peer_dependencies,
        linker_mode,
        object_integrity_policy,
        dependency_engine_policy: dependency_engine_policy.as_ref(),
        requested_v2_mode,
        compatibility_bin_names,
        requested_add_count,
        json_output,
        emit_timing,
        timing_detail_mode,
        force_security_floor,
        target_set,
        start,
    })
    .await?;
    if freshness_completed {
        return Ok(());
    }

    let pkg_name = pkg.name.as_deref().unwrap_or("(unnamed)");
    // The persistent `› Resolving …` phase line is emitted below after
    // the route table is built so it can name the actual registry hosts
    // (e.g. `lpm.dev`, `npmjs.org`) the resolver will hit. The previously
    // `Installing dependencies for X` line was redundant with that.

    // + hoisted-symmetry — legacy linker-state migration.
    // Detects upgrade-in-place users (binary upgraded but
    // `node_modules/` not wiped) and wipes any legacy state subtrees
    // — the pre-61.1 isolated wrapper root at `node_modules/.lpm/`
    // and/or the pre-symmetry hoisted state at
    // `node_modules/.lpm-metadata.json` + `node_modules/.lpm/nested/`
    // — so the rest of the install pipeline rebuilds at the new
    // `<project>/.lpm/{wrappers,hoisted}/` locations. The fast-lane
    // gate in `install_state::needs_layout_migration` already forced
    // a real install when either migration is owed; here we just
    // clear the old state. Idempotent — calling on a project without
    // legacy state is a no-op.
    migrate_legacy_wrapper_layout(project_dir, json_output);

    // + hoisted-symmetry — ensure `.gitignore` contains
    // BOTH `.lpm/wrappers/` (isolated) and `.lpm/hoisted/` so neither
    // mode's project-local state can accidentally land in commits.
    // Runtime "ensure once" pattern (matches the existing skills
    // helper); idempotent for projects that already have either
    // entry. Both run unconditionally because the user's mode could
    // change between installs and a project already on one mode may
    // accumulate the other mode's state during a future toggle.
    ensure_lpm_wrappers_gitignore(project_dir);
    ensure_lpm_hoisted_gitignore(project_dir);

    // Surface silent additions to `trustedDependencies`
    // BEFORE the install pipeline does any work.
    // A "bump dep" PR that quietly grew the trust list would otherwise
    // slip past review; this diff is the local safety net.
    // Emission is suppressed in --json mode (no stable JSON
    // schema for this surface yet — callers will learn the additions
    // via `lpm trust diff` once that lands in chunk C).
    if !json_output {
        let current_snapshot =
            crate::trust_snapshot::TrustSnapshot::capture_current(pkg.lpm.as_ref().map_or(
                &lpm_workspace::TrustedDependencies::Legacy(Vec::new()),
                |l| &l.trusted_dependencies,
            ));
        let previous_snapshot = crate::trust_snapshot::read_snapshot(project_dir);
        let additions = current_snapshot.diff_additions(previous_snapshot.as_ref());
        if let Some(notice) = crate::trust_snapshot::format_new_bindings_notice(&additions) {
            output::info(&notice);
        }
    }

    // — shared gate counters. Populated by the lockfile
    // fast path (Change 1) when a stored URL fails the scheme/shape/
    // origin gate, and (in follow-up commits) by the stale-URL retry
    // path. Surfaced on `timing.fetch_breakdown.tarball_url_gate`.
    let gate_stats = Arc::new(GateStats::default());

    let mut deps = manifest_deps.clone();
    reject_workspace_self_dependency(&pkg)?;

    let declared_deps = deps.clone();

    let WorkspaceInstallContext {
        workspace,
        mut workspace_member_deps,
        direct_workspace_member_deps,
        all_workspace_members,
        mut catalog_resolutions,
    } = prepare_workspace_install_context(
        project_dir,
        &pkg,
        &mut deps,
        requested_v2_mode,
        json_output,
    )?;
    reject_remote_tarball_url_deps_with_policy_extensions(&policy_extension_configs, &deps)?;

    let resolver_excludes = minimum_release_age_exclude
        .iter()
        .map(|name| lpm_resolver::CanonicalKey::from_dep_name(name));
    let resolver_policy = if release_age_policy.is_strict() {
        lpm_resolver::ResolverPolicy::new_with_release_age_excludes(
            resolver_min_age_secs,
            resolver_trust_policy,
            resolver_excludes,
        )
    } else {
        let direct_release_age_canonicals = direct_release_age_canonicals(&deps);
        lpm_resolver::ResolverPolicy::new_with_release_age_excludes_and_packages(
            resolver_min_age_secs,
            resolver_trust_policy,
            resolver_excludes,
            direct_release_age_canonicals,
        )
    };
    let minimum_release_age_exclude: std::collections::HashSet<String> =
        minimum_release_age_exclude.into_iter().collect();

    let OverrideResolutionState {
        lpm_overrides,
        overrides,
        resolutions,
        override_catalogs,
        override_catalog_resolutions,
        dependency_catalog_resolution_count,
        override_set,
    } = prepare_override_resolution_state(OverrideResolutionInput {
        package: &pkg,
        workspace: workspace.as_ref(),
        catalog_resolutions: &mut catalog_resolutions,
    })?;

    // Manifest-side compatibility warnings (pnpm overrides / patches
    // / peer rules drift, ignored other-PM `engines.*` keys) fire from
    // dependency-engine policy preflight, which runs before this point
    // in install / rebuild / add. The shared
    // source of truth is `PackageJson::manifest_compat_issues` in
    // `lpm-workspace`. Automation pipelines pull the same signals
    // from `lpm doctor --json`, where every issue lands as a
    // `Check::warn` with a stable code.

    let is_add_invocation = requested_add_count.is_some();
    let InstallRoutingContext {
        route_table,
        eager_origins,
        setup_route_table_ms: wf_setup_route_table_ms,
    } = prepare_install_routing_context(
        project_dir,
        &deps,
        client,
        pkg_name,
        is_add_invocation,
        json_output,
    )?;

    // `linker_mode` was resolved above — before `check_install_state` —
    // so it covers both validation (fail-loud on invalid values) and
    // freshness (post-install env/config flips invalidate the cache).
    // No re-resolution here.

    let LockfileValidationState {
        current_patches,
        current_patch_fingerprint,
        current_lockfile_patches,
        current_importer_snapshot,
    } = validate_install_lockfile_state(LockfileValidationInput {
        project_dir,
        lockfile_path: &lockfile_path,
        package: &pkg,
        lpm_overrides: &lpm_overrides,
        overrides: overrides.as_ref(),
        resolutions: resolutions.as_ref(),
        catalogs: override_catalogs,
        auto_install_peers,
        frozen_lockfile_active,
        force,
    })?;

    if deps.is_empty() && workspace_member_deps.is_empty() {
        run_empty_dependency_install_phase(EmptyDependencyInstallInput {
            project_dir,
            policy_extension_configs: &policy_extension_configs,
            cleanup_catalogs_in_pipeline,
            json_output,
            start,
            timing_detail_mode,
            setup_install_state_ms: wf_setup_install_state_ms,
            setup_route_table_ms: wf_setup_route_table_ms,
            emit_timing,
            target_set,
            force_security_floor,
            override_set: &override_set,
            linker_mode,
            object_integrity_policy,
            dependency_engine_policy: dependency_engine_policy.as_ref(),
        })
        .await?;
        return Ok(());
    }

    let LockfileDriftState {
        prior_overrides_state,
        overrides_changed,
        prior_patch_state,
        patches_changed,
        pre_install_direct_versions,
    } = prepare_lockfile_drift_state(LockfileDriftInput {
        project_dir,
        lockfile_path: &lockfile_path,
        pkg: &pkg,
        override_set: &override_set,
        current_patches: &current_patches,
        current_patch_fingerprint: &current_patch_fingerprint,
    });

    let owned_client =
        configure_install_client_for_routing(client, &route_table, &eager_origins, json_output)?;
    let client = &owned_client;

    let arc_client = Arc::new(client.clone_with_config());

    let v2_workspace_root_pre_resolve = if requested_v2_mode {
        pre_resolve_v2_direct_workspace_member_deps(
            project_dir,
            &mut deps,
            &direct_workspace_member_deps,
            &all_workspace_members,
            json_output,
        )?
    } else {
        V2WorkspaceRootPreResolveResult::default()
    };
    if requested_v2_mode {
        workspace_member_deps.clear();
    }

    if offline {
        return run_offline_install_phase(OfflineInstallInput {
            client,
            project_dir,
            deps: &deps,
            current_importer_snapshot: &current_importer_snapshot,
            pkg: &pkg,
            lockfile_path: &lockfile_path,
            catalog_resolutions: &catalog_resolutions,
            gate_stats: &gate_stats,
            override_set: &override_set,
            prior_overrides_state: prior_overrides_state.as_ref(),
            overrides_changed,
            current_patches: &current_patches,
            current_patch_fingerprint: &current_patch_fingerprint,
            prior_patch_state: prior_patch_state.as_ref(),
            patches_changed,
            auto_install_peers,
            omit_policy,
            production_dependency_names: &production_dependency_names,
            requested_v2_mode,
            object_integrity_policy,
            lpm_root,
            json_output,
            verify_registry_signatures,
            registry_signature_timings: registry_signature_timings.clone(),
            arc_client: &arc_client,
            route_table: &route_table,
            npm_firewall_mode,
            npm_firewall_lookup_mode,
            npm_firewall_policy_profile,
            policy_extension_configs: &policy_extension_configs,
            workspace_member_deps: &mut workspace_member_deps,
            all_workspace_members: &all_workspace_members,
            v2_workspace_root_pre_resolve: &v2_workspace_root_pre_resolve,
            start,
            linker_mode,
            force,
            script_policy_override,
            auto_build,
            no_sandbox,
            strict_sandbox,
            emit_timing,
            global_config: &global_config,
            strict_integrity,
            compatibility_bin_names,
            dependency_engine_policy: dependency_engine_policy.as_ref(),
        })
        .await;
    }

    let lockfile_result = select_lockfile_install_plan(LockfileSelectionInput {
        lockfile_path: &lockfile_path,
        deps: &deps,
        current_importer_snapshot: &current_importer_snapshot,
        catalog_resolutions: &catalog_resolutions,
        client,
        gate_stats: &gate_stats,
        frozen_lockfile_active,
        force,
        overrides_changed,
        patches_changed,
        is_add_invocation,
        auto_install_peers,
        json_output,
    })?;
    // The fetch semaphore is hoisted out of the fetch loop so the optional
    // speculative dispatcher can share the download pool with the
    // post-resolve real-fetch loop. Without sharing, a
    // spec dispatcher racing alongside the later real loop would
    // saturate the network for no wall-clock win. One pool,
    // used first by speculation, then drained by real fetch.
    let fetch_semaphore = Arc::new(Semaphore::new(max_concurrent_downloads()));
    let fetch_extract_limiter = configured_fetch_extract_limiter(requested_v2_mode);
    // `LPM_STREAM_FETCH=0` falls back to the temp-file spool path for both
    // early overlap fetches and the post-resolve fetch loop.
    let streaming_fetch = std::env::var("LPM_STREAM_FETCH").map_or(true, |v| v != "0");
    // Hoist the `PackageStore` so the speculative dispatcher can write
    // tarballs into the real store during the resolve phase. Post-resolve,
    // the fetch loop rebinds to the same handle (cheap Arc-style clone
    // underneath).
    let store = PackageStore::from_root(lpm_root);
    // `lpm_root` stays in function scope so post-install helpers can reach
    // the v2 store via `find_installed_package_baseline`. Those helpers need
    // the actual install root to find v2-installed scripted packages for
    // auto-build and build-hint decisions.
    // — read the store-version flag once per
    // install. `LPM_STORE_VERSION=v2` opts in to the virtual-store
    // pipeline; everything else (unset, "v1", typos) takes the v1
    // path that's been shipping.
    //
    // The v2 store handle is constructed eagerly when the flag is
    // active, then wrapped in `Arc` so per-package spawn tasks can
    // capture a cheap clone alongside the v1 `store_ref`. Holding
    // it as `Option<Arc<…>>` keeps the v1-default code path
    // allocation-free.
    let store_version = lpm_store::StoreVersion::from_env();
    let store_v2_handle: Option<std::sync::Arc<lpm_store::v2::Store>> = if store_version.is_v2() {
        Some(std::sync::Arc::new(
            lpm_store::v2::Store::from_lpm_root_with_object_integrity_policy(
                lpm_root,
                object_integrity_policy,
            ),
        ))
    } else {
        None
    };
    if store_v2_handle.is_some() {
        tracing::info!(
            "{}=v2 — install pipeline routing object extracts to ~/.lpm/store/v2/",
            lpm_store::StoreVersion::ENV_VAR
        );
    }

    // — silent v1 → v2 layout migration on first
    // v2-mode install in this project.
    //
    // Detection (design): the project is on v1 if either
    // `<project>/.lpm/wrappers/` or `<project>/.lpm/hoisted/` exists.
    // Both are wiped during migration so the v2 install can populate
    // a clean slate. The store-side `~/.lpm/store/v1/` is NOT touched
    // here — it may still serve other projects on the same machine.
    // `lpm store clean` is the blunt-wipe escape hatch.
    //
    // Migration is idempotent: re-running on partial state succeeds
    // (every `rm -rf` is a no-op on already-clean state). A crash
    // mid-migration leaves a half-wiped project; the next install
    // re-runs the same wipes and re-attempts the v2 install.
    if store_v2_handle.is_some() && needs_v2_migration(project_dir) {
        if !json_output {
            output::info("migrating to v2 store layout (one-time, ~5\u{2013}10s)");
        }
        migrate_v1_to_v2(project_dir)
            .map_err(|e| LpmError::Registry(format!("v1→v2 migration failed: {e}")))?;
    }

    let experimental_resolver_requested = experimental_resolver::enabled();
    let experimental_resolver_script_policy_is_default = if experimental_resolver_requested {
        let script_policy_cfg =
            crate::script_policy_config::ScriptPolicyConfig::from_package_json(project_dir);
        let effective_policy = crate::script_policy_config::resolve_script_policy_with_security(
            project_dir,
            script_policy_override,
            &script_policy_cfg,
            json_output,
        )?;
        script_policy_cfg == crate::script_policy_config::ScriptPolicyConfig::default()
            && effective_policy == crate::script_policy_config::ScriptPolicy::Deny
    } else {
        true
    };

    if experimental_resolver::should_run(experimental_resolver::ExperimentalResolverAdmission {
        json_output,
        frozen_lockfile_active,
        omit_policy,
        has_workspace_member_deps: !workspace_member_deps.is_empty()
            || !direct_workspace_member_deps.is_empty(),
        has_v2_workspace_member_deps: !v2_workspace_root_pre_resolve.install_pkgs.is_empty()
            || !v2_workspace_root_pre_resolve
                .additional_workspace_links
                .is_empty(),
        has_tarball_source_deps: experimental_resolver::has_tarball_source_deps(project_dir, &deps),
        verify_registry_signatures,
        strict_integrity,
        force_security_floor,
        npm_firewall_enabled: npm_firewall_mode.is_enabled(),
        policy_extensions_enabled: !policy_extension_configs.is_empty(),
        auto_build,
        script_policy_override,
        script_policy_is_default: experimental_resolver_script_policy_is_default,
        has_trusted_dependencies: pkg
            .lpm
            .as_ref()
            .is_some_and(|lpm| !lpm.trusted_dependencies.is_empty()),
        strict_release_age_replay: release_age_policy.is_strict() && effective_min_age_secs > 0,
        allow_new,
        is_add_invocation,
        has_direct_versions_out: direct_versions_out.is_some(),
        has_target_set: target_set.is_some(),
        audit_after_install,
        no_skills,
        no_security_summary,
        verbose,
        drift_ignore_policy_is_default: matches!(
            &drift_ignore_policy,
            crate::provenance_fetch::DriftIgnorePolicy::EnforceAll
        ),
        verify_policy_is_default: matches!(
            verify_policy.enforce,
            crate::provenance_fetch::EnforceMode::Deny
        ) && matches!(
            &verify_policy.skip,
            crate::provenance_fetch::SkipPolicy::None
        ),
    })? {
        let NonRegistryPreResolveResult {
            install_pkgs: mut spike_pre_resolved_install_pkgs,
            source_deps: mut spike_pre_resolved_source_deps,
            additional_workspace_links,
            optional_registry_roots,
        } = pre_resolve_non_registry_deps_with_optional_registry_roots(
            &arc_client,
            &store,
            project_dir,
            &mut deps,
            json_output,
            strict_integrity,
            &all_workspace_members,
            &v2_workspace_root_pre_resolve.optional_registry_roots,
        )
        .await?;

        merge_workspace_member_links(
            &mut workspace_member_deps,
            additional_workspace_links.into_iter().chain(
                v2_workspace_root_pre_resolve
                    .additional_workspace_links
                    .iter()
                    .cloned(),
            ),
        );
        expand_workspace_member_deps_with_transitives(
            &mut workspace_member_deps,
            &all_workspace_members,
        )?;
        if !requested_v2_mode {
            enforce_required_workspace_member_engines(
                &workspace_member_deps,
                dependency_engine_policy.as_ref(),
            )?;
        }
        spike_pre_resolved_install_pkgs
            .extend(v2_workspace_root_pre_resolve.install_pkgs.iter().cloned());
        for (source, deps) in &v2_workspace_root_pre_resolve.source_deps {
            spike_pre_resolved_source_deps
                .entry(source.clone())
                .or_insert_with(|| deps.clone());
        }

        return experimental_resolver::run(
            arc_client.clone(),
            project_dir,
            &deps,
            &pkg,
            route_table.clone(),
            json_output,
            start,
            linker_mode,
            force,
            lpm_root,
            store_v2_handle.clone(),
            compatibility_bin_names,
            override_set.clone(),
            resolver_policy.clone(),
            auto_install_peers,
            !omit_policy.optional,
            &optional_registry_roots,
            &spike_pre_resolved_install_pkgs,
            &spike_pre_resolved_source_deps,
            &workspace_member_deps,
            &all_workspace_members,
            &catalog_resolutions,
            &current_importer_snapshot,
            &current_patches,
            &prior_patch_state,
            &current_patch_fingerprint,
            dependency_engine_policy.as_ref(),
        )
        .await;
    }

    let fetch_coord: Arc<FetchCoordinator> = Arc::new(FetchCoordinator::default());
    let OnlineResolutionPhaseResult {
        packages,
        packages_for_lockfile,
        resolve_ms,
        used_lockfile,
        platform_skipped,
        latest_stable_versions,
        applied_overrides,
        peer_conflicts,
        peer_warnings,
        ambient_peer_installs_for_lockfile,
        spec_tracker,
        speculation_join,
        mut fetch_overlap_join,
        mut npm_firewall_preflight_join,
        post_firewall_fetch_overlap_allowed,
        resolved_with,
        streaming_metrics,
        initial_batch_ms,
        resolver_stage_timing,
        fast_path_lockfile,
        lockfile_peer_context_authoritative,
        needs_binary_upgrade,
        wf_setup_ms,
        wf_resolve_end_ms,
        auto_isolated_peer_conflicts,
        linker_mode,
    } = run_online_resolution_phase(OnlineResolutionPhaseInput {
        start,
        lockfile_result,
        arc_client: arc_client.clone(),
        route_table: route_table.clone(),
        project_dir,
        deps: &mut deps,
        pkg: &pkg,
        requested_add_count,
        json_output,
        requested_v2_mode,
        v2_workspace_root_pre_resolve: &v2_workspace_root_pre_resolve,
        workspace_member_deps: &mut workspace_member_deps,
        all_workspace_members: &all_workspace_members,
        store: store.clone(),
        store_v2_handle: store_v2_handle.clone(),
        fetch_semaphore: fetch_semaphore.clone(),
        fetch_extract_limiter: fetch_extract_limiter.clone(),
        fetch_coord: fetch_coord.clone(),
        gate_stats: gate_stats.clone(),
        npm_firewall_mode,
        npm_firewall_lookup_mode,
        npm_firewall_policy_profile,
        npm_firewall_chunk_size,
        policy_extension_configs: &policy_extension_configs,
        force,
        offline,
        omit_policy,
        production_dependency_names: &production_dependency_names,
        pubgrub_opt_out,
        auto_install_peers,
        resolver_policy: resolver_policy.clone(),
        strict_peer_dependencies,
        peer_conflict_auto_isolation_allowed,
        configured_linker_mode,
        auto_isolated_peer_conflicts,
        linker_mode,
        strict_integrity,
        streaming_fetch,
        dependency_engine_policy: dependency_engine_policy.clone(),
        resolver_min_age_secs,
        override_set: override_set.clone(),
    })
    .await?;

    let policy_extension_stats = run_policy_extensions(
        &policy_extension_configs,
        project_dir,
        &packages,
        json_output,
    )
    .await?;
    let npm_firewall_stats = if let Some(join) = npm_firewall_preflight_join.take() {
        let result = join.drain().await?;
        finish_npm_firewall_preflight(result, json_output)?
    } else {
        run_npm_firewall_preflight(NpmFirewallPreflightRequest {
            mode: npm_firewall_mode,
            lookup_mode: npm_firewall_lookup_mode,
            policy_profile: npm_firewall_policy_profile,
            client: &arc_client,
            route_table: &route_table,
            packages: &packages,
            offline,
            json_output,
        })
        .await?
    };
    if post_firewall_fetch_overlap_allowed && fetch_overlap_join.is_none() && !packages.is_empty() {
        fetch_overlap_join = Some(spawn_fetch_overlap_for_packages(
            packages.clone(),
            arc_client.clone(),
            route_table.clone(),
            store.clone(),
            store_v2_handle.clone(),
            fetch_semaphore.clone(),
            fetch_coord.clone(),
            project_dir.to_path_buf(),
            gate_stats.clone(),
            fetch_extract_limiter.clone(),
            streaming_fetch,
        ));
    }

    append_workspace_links_from_local_packages(
        project_dir,
        &packages,
        &mut workspace_member_deps,
        &all_workspace_members,
        &direct_workspace_member_deps,
    );

    if verify_registry_signatures {
        enforce_registry_signature_policy(
            Arc::clone(&arc_client),
            &route_table,
            &packages,
            json_output,
            true,
            registry_signature_timings.clone(),
        )
        .await?;
    }

    let OnlineFetchPhaseResult {
        packages,
        packages_for_lockfile,
        link_targets,
        event_driven_link,
        event_link_handles,
        v2_mode,
        v2_event_driven,
        v2_plan,
        v2_event_link_handles,
        mut v2_link_task_timings,
        fetch_ms,
        waterfall_start_ms: wf_fetch_start_ms,
        waterfall_end_ms: wf_fetch_end_ms,
        fetch_stage_timings,
        cached,
        downloaded,
        fetch_breakdown,
        walker_summary_final,
        spec_stats,
        publish_ages,
        min_release_age_secs,
        install_provenance_status_map,
        fresh_urls,
    } = run_online_fetch_phase(OnlineFetchPhaseInput {
        start,
        arc_client: arc_client.clone(),
        route_table: route_table.clone(),
        project_dir,
        packages,
        packages_for_lockfile,
        store: store.clone(),
        store_v2_handle: store_v2_handle.clone(),
        fetch_semaphore,
        fetch_extract_limiter,
        fetch_coord,
        speculation_join,
        fetch_overlap_join,
        spec_tracker,
        gate_stats: gate_stats.clone(),
        current_patches: &current_patches,
        used_lockfile,
        lockfile_peer_context_authoritative,
        force,
        force_security_floor,
        allow_new,
        effective_min_age_secs,
        release_age_policy,
        minimum_release_age_exclude: &minimum_release_age_exclude,
        drift_ignore_policy,
        verify_policy,
        global_config: &global_config,
        lpm_root,
        provenance_timings: &provenance_timings,
        json_output,
        streaming_fetch,
        timing_detail_mode,
        slow_package_timings: &mut slow_package_timings,
        linker_mode,
        compatibility_bin_names,
    })
    .await?;

    let link_phase = run_online_link_phase(OnlineLinkPhaseInput {
        start,
        project_dir,
        package_name: pkg.name.as_deref(),
        packages: &packages,
        link_targets: &link_targets,
        event_driven_link,
        event_link_handles,
        v2_mode,
        store_v2: store_v2_handle.as_deref(),
        v2_event_driven,
        v2_plan: v2_plan.as_deref(),
        v2_event_link_handles,
        v2_link_task_timings: &mut v2_link_task_timings,
        slow_package_timings: &mut slow_package_timings,
        timing_detail_mode,
        linker_mode,
        force,
        compatibility_bin_names,
    })
    .await?;
    let mut link_result = link_phase.link_result;
    let link_ms = link_phase.link_ms;
    let wf_link_start_ms = link_phase.waterfall_start_ms;
    let wf_link_end_ms = link_phase.waterfall_end_ms;
    let wf_link_await_ms = link_phase.await_ms;
    let wf_link_finalize_ms = link_phase.finalize_ms;
    let wf_link_reconcile_ms = link_phase.reconcile_ms;
    let wf_link_root_symlinks_ms = link_phase.root_symlinks_ms;
    let wf_link_compatibility_ms = link_phase.compatibility_ms;
    let wf_link_bin_shims_ms = link_phase.bin_shims_ms;
    // `link_ms` lands in the verbose footer and the JSON timing object;
    // no dedicated "Linked in Xms" line.

    // invariant: link workspace member dependencies AFTER
    // the regular linker run. The linker's stale-symlink cleanup pass at the
    // top of `link_packages` would otherwise wipe these symlinks on every
    // install (they're not in `direct_names` because workspace members were
    // stripped from `deps` before resolution by `extract_workspace_protocol_deps`).
    // Re-creating them here every time keeps the layout consistent.
    let workspace_links_created = link_workspace_members(project_dir, &workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info(&format!(
            "Linked {} workspace member(s)",
            workspace_links_created.to_string().bold()
        ));
    }

    //
    //
    // Run AFTER both the regular linker pass AND the workspace-member
    // linker pass, so every materialized destination is in place. Run
    // BEFORE the build-state capture so the patched bytes
    // are what `lpm rebuild` and `lpm approve-scripts` see.
    //
    // Apply is unconditional even on the lockfile fast path: see the
    // module-level comment in `patch_engine.rs` for why.
    let applied_patches = apply_patches_for_install(
        &current_patches,
        &link_result,
        &store,
        project_dir,
        json_output,
    )?;

    let OnlineLifecyclePrepareResult {
        policy,
        installed_with_integrity,
        blocked_set_metadata,
        requested_capabilities: install_requested_capabilities,
        user_bound: install_user_bound,
        effective_policy: lifecycle_effective_policy,
        advisor_session,
        auto_build_attempted,
        blocked_capture,
        blocked_metadata_ms: wf_tail_blocked_metadata_ms,
        trust_snapshot_ms: wf_tail_trust_snapshot_ms,
    } = run_online_lifecycle_prepare_phase(OnlineLifecyclePrepareInput {
        client: arc_client.as_ref(),
        route_table: &route_table,
        project_dir,
        packages: &packages,
        package: &pkg,
        store: &store,
        used_lockfile,
        script_policy_override,
        advisor_override: advisor_override.as_deref(),
        global_config: &global_config,
        publish_ages: &publish_ages,
        min_release_age_secs,
        auto_build,
        json_output,
        lpm_root,
    })
    .await?;

    // Step 7: LPM-Native Intelligence
    // Read strictness from package.json "lpm" config
    let strict_deps = pkg
        .lpm
        .as_ref()
        .and_then(|l| l.strict_deps.as_deref())
        .unwrap_or("warn");

    if strict_deps != "loose" && !json_output {
        let installed_names: std::collections::HashSet<String> =
            packages.iter().map(|p| p.name.clone()).collect();

        // Phantom dependency detection
        let phantom_result =
            crate::intelligence::detect_phantom_deps(project_dir, &declared_deps, &installed_names);

        if !phantom_result.phantom_imports.is_empty() {
            eprintln!();
            install_ui::warn(&format!(
                "{} phantom dependency import(s) detected:",
                phantom_result.phantom_imports.len()
            ));
            for phantom in phantom_result.phantom_imports.iter().take(5) {
                let rel_file = phantom
                    .file
                    .strip_prefix(project_dir)
                    .unwrap_or(&phantom.file);
                eprintln!(
                    "    {} ({}:{})",
                    phantom.package_name.bold(),
                    rel_file.display().to_string().dimmed(),
                    phantom.line,
                );
                if let Some(via) = &phantom.available_via {
                    eprintln!("      {}", via.dimmed());
                }
                eprintln!(
                    "      Fix: {}",
                    format!("lpm install {}", phantom.package_name).dimmed()
                );
            }
            if phantom_result.phantom_imports.len() > 5 {
                eprintln!(
                    "    ... and {} more",
                    phantom_result.phantom_imports.len() - 5
                );
            }
        }

        // Import verification (only in strict mode)
        if strict_deps == "strict" {
            let verification =
                crate::intelligence::verify_imports(project_dir, &installed_names, &deps);
            if !verification.unresolved.is_empty() {
                eprintln!();
                install_ui::warn(&format!(
                    "{} import(s) will fail at runtime:",
                    verification.unresolved.len()
                ));
                for unresolved in &verification.unresolved {
                    let rel_file = unresolved
                        .file
                        .strip_prefix(project_dir)
                        .unwrap_or(&unresolved.file);
                    eprintln!(
                        "    {}:{} → {}",
                        rel_file.display().to_string().dimmed(),
                        unresolved.line,
                        format!("import \"{}\"", unresolved.specifier).bold(),
                    );
                    eprintln!("      {}", unresolved.suggestion.dimmed());
                }
            }
        }

        // Quality warnings for LPM packages
        let lpm_packages: Vec<(String, String)> = packages
            .iter()
            .filter(|p| p.is_lpm)
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();

        if !lpm_packages.is_empty() {
            let quality_threshold = pkg
                .lpm
                .as_ref()
                .and_then(|l| l.strict_deps.as_deref()) // reuse as quality gate
                .map_or(30, |_| 50u32); // default: only warn below 30

            // Use the injected client directly so empty bearer tokens are
            // filtered and refresh-eligible sessions are preserved.
            let warnings = crate::intelligence::check_install_quality(
                client,
                &lpm_packages,
                quality_threshold,
            )
            .await;

            for warning in &warnings {
                let icon = match warning.severity {
                    crate::intelligence::WarningSeverity::Critical => "✗".to_string(),
                    crate::intelligence::WarningSeverity::Warning => "!".to_string(),
                    crate::intelligence::WarningSeverity::Info => "ℹ".to_string(),
                };
                println!(
                    "  {icon} {}@{}: {}",
                    warning.package_name, warning.version, warning.message
                );
            }

            // Security summary for ALL packages (client-side analysis + registry enrichment)
            if !no_security_summary {
                let all_packages: Vec<(String, String, bool)> = packages
                    .iter()
                    .map(|p| (p.name.clone(), p.version.clone(), p.is_lpm))
                    .collect();
                // Use the same injected client for the security summary so
                // auth handling matches the quality check above.
                crate::security_check::post_install_security_summary(
                    client,
                    &store,
                    &all_packages,
                    json_output,
                    false, // not quiet — show Medium tier too
                )
                .await;
            }
        }
    }

    // Step 8: Auto-install skills for direct LPM packages
    if !offline && !no_skills {
        let lpm_packages: Vec<_> = packages
            .iter()
            .filter(|p| p.is_lpm && p.is_direct)
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();

        if !lpm_packages.is_empty() {
            install_skills_for_packages(&arc_client, &lpm_packages, project_dir, !json_output)
                .await?;
        }
    }

    let lockfile_write_result = run_online_lockfile_write_phase(OnlineLockfileWritePhaseInput {
        project_dir,
        lockfile_path: &lockfile_path,
        used_lockfile,
        resolved_with,
        auto_isolated_peer_conflicts,
        workspace_install_packages: &v2_workspace_root_pre_resolve.install_pkgs,
        packages_for_lockfile: &packages_for_lockfile,
        deps: &deps,
        ambient_peer_installs_for_lockfile: &ambient_peer_installs_for_lockfile,
        catalog_resolutions: &catalog_resolutions,
        dependency_catalog_resolution_count,
        override_catalog_resolutions: &override_catalog_resolutions,
        applied_overrides: &applied_overrides,
        current_lockfile_patches: &current_lockfile_patches,
        current_importer_snapshot: &current_importer_snapshot,
        frozen_lockfile_active,
        fast_path_lockfile,
        fresh_urls: &fresh_urls,
        needs_binary_upgrade,
        json_output,
    })?;
    let wf_tail_lockfile_write_ms = lockfile_write_result.write_ms;
    let wf_tail_lockfile_write_count = lockfile_write_result.write_count;

    let OnlineAutoBuildPhaseResult {
        blocked_capture,
        bin_linked,
    } = run_online_auto_build_phase(OnlineAutoBuildPhaseInput {
        project_dir,
        packages: &packages,
        link_targets: &link_targets,
        package_name: pkg.name.as_deref(),
        store: &store,
        lpm_root,
        object_integrity_policy,
        linker_mode,
        compatibility_bin_names,
        json_output,
        no_sandbox,
        strict_sandbox,
        auto_build_attempted,
        effective_policy: lifecycle_effective_policy,
        advisor_session: advisor_session.as_ref(),
        blocked_capture,
        installed_with_integrity: &installed_with_integrity,
        policy: &policy,
        blocked_set_metadata: &blocked_set_metadata,
        requested_capabilities: &install_requested_capabilities,
        user_bound: &install_user_bound,
    })
    .await?;
    if let Some(bin_linked) = bin_linked {
        link_result.bin_linked = bin_linked;
    }

    let elapsed = start.elapsed();

    // persist `.lpm/overrides-state.json`. Three
    // cases:
    // 1. Override set is non-empty → write the fresh state (or, on the
    // lockfile fast path, preserve the previously-recorded apply
    // trace so `lpm graph --why` doesn't go blind).
    // 2. Override set is empty AND a stale state file exists → delete
    // it so introspection commands don't pick up old data.
    // 3. Override set is empty AND no state file → no-op.
    if !override_set.is_empty() {
        let state = if used_lockfile {
            // Lockfile fast path: nothing was re-resolved, so preserve
            // whatever the previous fresh-resolve recorded.
            let prior_applied = prior_overrides_state
                .as_ref()
                .map(|s| s.applied.clone())
                .unwrap_or_default();
            overrides_state::OverridesState::capture_preserving_applied(
                &override_set,
                prior_applied,
            )
        } else {
            overrides_state::OverridesState::capture(&override_set, applied_overrides.clone())
        };
        if let Err(e) = overrides_state::write_state(project_dir, &state) {
            tracing::warn!("failed to write overrides-state.json: {e}");
        }
    } else if prior_overrides_state.is_some()
        && let Err(e) = overrides_state::delete_state(project_dir)
    {
        tracing::warn!("failed to delete stale overrides-state.json: {e}");
    }

    // persist `.lpm/patch-state.json`.
    // invariant : preserve the prior `applied` trace on
    // idempotent reruns so `lpm graph --why` doesn't lose provenance
    // when an install does no work. See `persist_patch_state`.
    persist_patch_state(
        project_dir,
        &current_patches,
        &prior_patch_state,
        &applied_patches,
    );

    if cleanup_catalogs_in_pipeline {
        cleanup_unused_catalogs_after_install(project_dir)?;
    }

    // Audit-after-install: run a silent audit pass and stash the
    // resulting counts. Both the JSON envelope and the human Done
    // block consume `audit_summary_for_envelope` below; computing
    // once here keeps the two surfaces in sync.
    //
    // Failure mode: never fails the install — audit findings are
    // informational only, per the opt-in contract. Errors degrade to
    // `None` and the install pipeline carries on. The error is logged
    // for operators tailing `LPM_LOG`.
    let audit_summary_for_envelope: Option<crate::commands::audit::AuditCounts> =
        if audit_after_install {
            let audit_start = std::time::Instant::now();
            let summary = if maybe_test_audit_after_install_should_fail() {
                tracing::warn!(
                    "audit-after-install failed: test-injected failure \
                 (LPM_TEST_AUDIT_AFTER_INSTALL_FAIL=1)"
                );
                None
            } else {
                match crate::commands::audit::run_install_summary(client, project_dir).await {
                    Ok(opt) => opt,
                    Err(e) => {
                        tracing::warn!("audit-after-install failed: {e}");
                        None
                    }
                }
            };
            wf_tail_audit_after_install_ms = audit_start.elapsed().as_millis();
            summary
        } else {
            None
        };

    if emit_install_report {
        emit_online_install_report(OnlineInstallReportInput {
            project_dir,
            lockfile_path: &lockfile_path,
            packages: &packages,
            downloaded,
            cached,
            link_result: &link_result,
            used_lockfile,
            elapsed,
            emit_timing,
            json_output,
            target_set,
            workspace_member_deps: &workspace_member_deps,
            applied_overrides: &applied_overrides,
            override_set: &override_set,
            peer_warnings: &peer_warnings,
            peer_conflicts: &peer_conflicts,
            current_patches: &current_patches,
            current_patch_fingerprint: &current_patch_fingerprint,
            applied_patches: &applied_patches,
            blocked_capture: &blocked_capture,
            install_provenance_status_map: &install_provenance_status_map,
            audit_summary_for_envelope: &audit_summary_for_envelope,
            force_security_floor,
            timing_detail_mode,
            resolve_ms,
            fetch_ms,
            link_ms,
            npm_firewall_stats: &npm_firewall_stats,
            policy_extension_stats: &policy_extension_stats,
            gate_stats: gate_stats.as_ref(),
            wf_setup_ms,
            wf_resolve_end_ms,
            wf_fetch_start_ms,
            wf_fetch_end_ms,
            wf_link_start_ms,
            wf_link_end_ms,
            wf_link_await_ms,
            wf_link_finalize_ms,
            wf_link_reconcile_ms,
            wf_link_root_symlinks_ms,
            wf_link_compatibility_ms,
            wf_link_bin_shims_ms,
            wf_setup_install_state_ms,
            wf_setup_route_table_ms,
            wf_tail_blocked_metadata_ms,
            wf_tail_trust_snapshot_ms,
            wf_tail_lockfile_write_ms,
            wf_tail_lockfile_write_count,
            wf_tail_audit_after_install_ms,
            registry_signature_timings: &registry_signature_timings,
            provenance_timings: &provenance_timings,
            fetch_stage_timings,
            fetch_breakdown,
            walker_summary_final: &walker_summary_final,
            streaming_metrics: &streaming_metrics,
            initial_batch_ms,
            resolver_stage_timing: &resolver_stage_timing,
            platform_skipped,
            spec_stats,
            v2_link_task_timings,
            slow_package_timings: &slow_package_timings,
            pre_install_direct_versions: &pre_install_direct_versions,
            latest_stable_versions: &latest_stable_versions,
            is_add_invocation,
            verbose,
        });
    }

    maybe_emit_post_install_lifecycle_hint(
        lpm_root,
        &packages,
        &policy,
        project_dir,
        script_policy_override,
        &install_requested_capabilities,
        &install_user_bound,
        &blocked_capture,
        json_output,
    )?;

    // Write install-hash so `lpm dev` knows deps are up to date.
    // uses the shared compute_install_hash from install_state.
    // Must re-read because save semantics may have modified both
    // package.json and lpm.lock during install (e.g., replacing "*" with "^4.3.6").
    //
    // delegated to `write_install_hash`, which also captures
    // manifest mtimes into the v2 file format so the next up-to-date
    // check can take the mtime fast path.
    write_post_install_hash(
        project_dir,
        linker_mode,
        object_integrity_policy,
        dependency_engine_policy.as_ref(),
    );

    // Register the project in the machine-global known-projects registry.
    // `lpm cache prune` walks this set to
    // determine which v2-store link entries are reachable. Errors are
    // logged + dropped: the registry is non-load-bearing (prune
    // degrades gracefully without it) so a flaky write must never
    // block a successful install.
    if let Err(e) = lpm_common::known_projects::register(&lpm_root.known_projects(), project_dir) {
        tracing::debug!("failed to register project in known-projects registry: {e}");
    }

    // Invariant: surface the direct-dep version map
    // for callers (`run_add_packages`, `run_install_filtered_add`) that
    // need to finalize a placeholder-staged manifest entry. The map
    // contains ONLY entries where `is_direct == true`, so transitive
    // collisions on the same name are impossible by construction.
    if let Some(out) = direct_versions_out {
        out.extend(collect_direct_versions(&packages));
    }

    Ok(())
}
