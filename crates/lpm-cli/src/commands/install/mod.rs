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
mod installer_spike;
mod lifecycle;
mod linking;
mod lockfile;
mod manifest;
mod package;
mod patches;
mod peer;
pub(crate) mod policy_extensions;
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
    NpmFirewallPreflightStats, finish_npm_firewall_preflight, npm_firewall_chunk_size_from_env,
    npm_firewall_has_packages, run_npm_firewall_preflight, spawn_chunked_npm_firewall_preflight,
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
    strict_integrity: bool, // CLI-level override for strict peer-dependency handling. `None`
    // falls through to package.json / global config / default.
    strict_peer_dependencies_override: Option<bool>,
    // Already-resolved linker override from CLI / `~/.lpm/config.toml` / env.
    // `None` means fall through to `package.json > lpm > linker` (which is
    // validated against `lpm_linker::LinkerMode::parse_str` inside the
    // install pipeline) and finally the default isolated layout.
    linker_override: Option<lpm_linker::LinkerMode>,
    no_skills: bool,
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
        strict_peer_dependencies_override,
        linker_override,
        no_skills,
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
    strict_peer_dependencies_override: Option<bool>,
    linker_override: Option<lpm_linker::LinkerMode>,
    no_skills: bool,
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
    lpm_root: lpm_common::LpmRoot,
) -> Result<(), LpmError> {
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
            strict_peer_dependencies_override,
            linker_override,
            no_skills,
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
    strict_peer_dependencies_override: Option<bool>,
    linker_override: Option<lpm_linker::LinkerMode>,
    no_skills: bool,
    no_editor_setup: bool,
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
        mut auto_isolated_peer_conflicts,
        mut linker_mode,
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
        omit_policy,
        strict_peer_dependencies,
        linker_mode,
        object_integrity_policy,
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
    // the engine_check preflight gate (`engine_check::enforce`) which
    // runs before this point in install / rebuild / add. The shared
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
        })
        .await;
    }

    let lockfile_result = select_lockfile_install_plan(LockfileSelectionInput {
        lockfile_path: &lockfile_path,
        deps: &deps,
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
    // applied-override trace for the rest of the
    // install pipeline. Empty for the lockfile-fast-path branch (we
    // preserve the previously-recorded trace from disk in that case);
    // populated for fresh resolution from the resolver's apply log.
    let mut applied_overrides: Vec<OverrideHit> = Vec::new();

    // best-effort peer-conflict
    // reports from the resolver. Each entry is one peer canonical
    // whose required consumer ranges were pairwise-incompatible: the
    // resolver picked the version satisfying the most consumers and
    // recorded the unsatisfied ones here. Surfaced as a `WARN` block
    // in text mode AND as the always-present `peer_conflicts` array
    // on `--json` output so machine consumers (CI, dashboards, audit
    // tooling) can rely on the field's existence.
    //
    // Empty for the lockfile-fast-path (no fresh resolve); empty when
    // the peer graph is clean. Always serialized as an array — even
    // empty — to match the `applied_patches` shape contract that
    // tooling already depends on.
    let mut peer_conflicts: Vec<lpm_resolver::PeerConflictReport> = Vec::new();
    let mut peer_warnings: Vec<PeerWarning> = Vec::new();

    // ambient peer installs synthesized by the resolver,
    // captured here so the cold-resolve lockfile-write site below
    // can persist them. Empty when the fast path takes over (we
    // already have the lockfile, no need to re-derive); populated by
    // the fresh-resolve branch from
    // `resolve_result.ambient_peer_installs`.
    let mut ambient_peer_installs_for_lockfile: Vec<String> = Vec::new();

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

    let installer_spike_requested = installer_spike::enabled();
    let installer_spike_script_policy_is_default = if installer_spike_requested {
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

    if installer_spike::should_run(installer_spike::InstallerSpikeAdmission {
        json_output,
        frozen_lockfile_active,
        omit_policy,
        has_workspace_member_deps: !workspace_member_deps.is_empty()
            || !direct_workspace_member_deps.is_empty(),
        has_v2_workspace_member_deps: !v2_workspace_root_pre_resolve.install_pkgs.is_empty()
            || !v2_workspace_root_pre_resolve
                .additional_workspace_links
                .is_empty(),
        has_tarball_source_deps: installer_spike::has_tarball_source_deps(project_dir, &deps),
        verify_registry_signatures,
        strict_integrity,
        force_security_floor,
        npm_firewall_enabled: npm_firewall_mode.is_enabled(),
        policy_extensions_enabled: !policy_extension_configs.is_empty(),
        auto_build,
        script_policy_override,
        script_policy_is_default: installer_spike_script_policy_is_default,
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
        } = pre_resolve_non_registry_deps(
            &arc_client,
            &store,
            project_dir,
            &mut deps,
            json_output,
            strict_integrity,
            &all_workspace_members,
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
        spike_pre_resolved_install_pkgs
            .extend(v2_workspace_root_pre_resolve.install_pkgs.iter().cloned());
        for (source, deps) in &v2_workspace_root_pre_resolve.source_deps {
            spike_pre_resolved_source_deps
                .entry(source.clone())
                .or_insert_with(|| deps.clone());
        }

        return installer_spike::run(
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
            &spike_pre_resolved_install_pkgs,
            &spike_pre_resolved_source_deps,
            &workspace_member_deps,
            &all_workspace_members,
            &catalog_resolutions,
            &current_patches,
            &prior_patch_state,
            &current_patch_fingerprint,
        )
        .await;
    }

    // pre-resolve direct
    // tarball-URL deps from the manifest BEFORE the resolver runs.
    // Each tarball-URL dep is downloaded, extracted into the
    // integrity-keyed CAS, and turned into an InstallPackage with
    // `source = "tarball+<url>"`. The resolver only sees the
    // remaining registry-style deps. The merged package list is
    // assembled post-resolver below.
    let NonRegistryPreResolveResult {
        install_pkgs: tarball_url_install_pkgs,
        source_deps: non_registry_source_deps,
        additional_workspace_links,
    } = pre_resolve_non_registry_deps(
        &arc_client,
        &store,
        project_dir,
        &mut deps,
        json_output,
        strict_integrity,
        // Invariant invariant: pass the FULL workspace membership
        // set (`all_workspace_members`), not the extracted top-level
        // subset (`workspace_member_deps`). overlap detection AND
        // the the invariant transitive `workspace:` check both need to see
        // every member, regardless of whether the consumer's root
        // explicitly references them via `workspace:*`. See the
        // construction comment near line 2807.
        &all_workspace_members,
    )
    .await?;

    // Merge the workspace members discovered through dedupe
    // (immediate file:/link: + transitive walker) and the transitive
    // `workspace:` arm into the slice that drives `link_workspace_members`.
    // Dropping either branch leaves the root-symlink set incomplete:
    // - `"foo": "file:./packages/foo"` where foo is a member
    // produced no `node_modules/foo` after install.
    // - `"foo": "workspace:*"` + foo's `bar: workspace:*` produced
    // `node_modules/foo` but no `node_modules/bar`.
    //
    // Dedupe key: `(name, canonical source_dir)`. Same name pointing
    // at the same realpath = one entry; aliased references (e.g.,
    // consumer's `"alias-of-foo": "file:./packages/foo"` plus
    // `"foo": "workspace:*"`) get distinct entries so each gets its
    // own `node_modules/<name>` symlink. (`workspace_member_deps` is
    // mutable from its declaration site; the invariant hoisted the
    // pre-pass before the offline/online dispatch.)
    merge_workspace_member_links(
        &mut workspace_member_deps,
        additional_workspace_links.into_iter().chain(
            v2_workspace_root_pre_resolve
                .additional_workspace_links
                .iter()
                .cloned(),
        ),
    );

    // **Invariant invariant — factor BFS into helper.** The
    // the invariant BFS lived inline here, which left the offline branch
    // at `run_link_and_finish` (install.rs:3252) without expansion
    // — the regression reproduced an offline install dropping
    // `node_modules/bar`. Helper now lives at
    // `expand_workspace_member_deps_with_transitives` and is called
    // from BOTH the online path (here, after merge of
    // `additional_workspace_links`) AND the offline path (right
    // before `run_link_and_finish` is invoked).
    expand_workspace_member_deps_with_transitives(
        &mut workspace_member_deps,
        &all_workspace_members,
    )?;

    // stats — filled by the speculation dispatcher drain.
    let spec_tracker = SpeculativeKeyTracker::default();

    //: shared fetch coordinator — serializes per-key fetch
    // work across the speculative dispatcher and the real fetch loop
    // now that the drain-wait between them is gone.
    let fetch_coord: Arc<FetchCoordinator> = Arc::new(FetchCoordinator::default());

    // Speculation handles are hoisted out of the fresh-resolve arm so
    // the main task drains them after the real fetch loop. Awaiting
    // the dispatcher early removes the resolve/fetch overlap.
    let mut speculation_join: Option<SpeculationJoin> = None;
    let mut fetch_overlap_join: Option<FetchOverlapJoin> = None;
    let mut npm_firewall_preflight_join: Option<NpmFirewallPreflightJoin> = None;
    let mut post_firewall_fetch_overlap_allowed = false;
    // Post-lockfile metadata: which resolver actually ran.
    // Stamped into `lpm.lock`'s `resolved-with` field at the cold-
    // write site below. Defaults to the greedy-fusion install default
    // (matches `Lockfile::new()`) and is overridden inside the fresh-
    // resolve dispatch branch when the legacy walker arm or the
    // PubGrub escape hatch fires. Previously this field was hardcoded
    // to "pubgrub" inside `Lockfile::new`, so every default install
    // post-v0.28.0 wrote a lie into the lockfile.
    let mut resolved_with: &'static str = "greedy-fusion";
    //: streaming-BFS observability counters. Shared Arc
    // between the resolver (incrementing inside `ensure_cached` +
    // `direct_fetch_and_cache`) and the JSON-output block that
    // snapshots the counts for `timing.resolve.streaming_bfs`.
    // Declared at outer scope because the JSON emit is outside the
    // fresh-resolve arm. Stays default-zero on the warm lockfile-
    // fast-path where the walker never runs.
    let streaming_metrics = lpm_resolver::StreamingBfsMetrics::new();

    //a — substage breakdown of cold-resolve wall-clock.
    // Captured here (outside the fresh/warm branch) so the JSON output
    // code path can surface a consistent shape whether the lockfile
    // fast path kicked in or not. Zeros on lockfile-fast-path;
    // populated from the resolver on fresh resolution.
    let mut initial_batch_ms: u128 = 0;
    let mut resolver_stage_timing = lpm_resolver::StageTiming::default();

    // — stash the parsed lockfile + `needs_binary_upgrade`
    // flag from the fast path so the writeback step at install-end
    // can patch + re-emit it. `None` on fresh-resolve branches (the
    // resolver builds its own lockfile via `resolved_to_install_packages`
    // and the writer at install-end already handles that case).
    let mut fast_path_lockfile: Option<lpm_lockfile::Lockfile> = None;
    let mut lockfile_peer_context_authoritative = false;
    let mut needs_binary_upgrade = false;

    // `route_table` is built upstream of this fork (
    // hoisted it above the lockfile-vs-resolve match so custom-
    // registry tarball auth + stale-tarball invalidation work on both
    // arms; hoisted it further to above the empty-deps
    // short-circuit so TLS overrides + `strict-ssl=false` security
    // warning surface for empty-deps installs too).
    let wf_setup_ms = start.elapsed().as_millis();
    let (mut packages, resolve_ms, used_lockfile, mut platform_skipped, latest_stable_versions) =
        match lockfile_result {
            Some(fast_path) => {
                if !json_output {
                    output::info(&format!(
                        "Using lockfile ({} packages)",
                        fast_path.packages.len().to_string().bold()
                    ));
                }
                lockfile_peer_context_authoritative = fast_path.lockfile.metadata.lockfile_version
                    >= MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE;
                fast_path_lockfile = Some(fast_path.lockfile);
                needs_binary_upgrade = fast_path.needs_binary_upgrade;
                // Fast path doesn't run the resolver, so we have no
                // registry metadata — the `+` list's "(vX.Y.Z available)"
                // hint is suppressed in this branch. Honest > guessing.
                (fast_path.packages, 0u128, true, 0usize, HashMap::new())
            }
            None => {
                let resolve_start = Instant::now();
                // The persistent `› Resolving …` phase line above already
                // narrates that resolution is in flight — no spinner needed.

                // route_table is constructed above the lockfile match
                // () — we just borrow/clone it here.

                // **Default flip .** Greedy-fusion is now the
                // global install default. The fused dispatcher
                // (`resolve_greedy_fused`) skips the walker spawn entirely
                // and IS the metadata fetch dispatcher.
                //
                // Resolver dispatch matrix:
                //
                // | LPM_RESOLVER | LPM_GREEDY_FUSION | Result |
                // |-----------------|-------------------|-------------------------|
                // | unset (default) | unset / non-"0" | greedy-fusion (new) |
                // | unset (default) | "0" | greedy + legacy walker |
                // | "greedy" | unset / non-"0" | greedy-fusion |
                // | "greedy" | "0" | greedy + legacy walker |
                // | "pubgrub" | (any) | PubGrub + legacy walker |
                //
                // Escape hatches:
                // - `LPM_RESOLVER=pubgrub` — full opt-out to the previous
                // install default (PubGrub-with-split-retry + walker).
                // Use only if you hit a greedy-fusion edge case in the
                // wild and need a tested fallback while we land a fix.
                // - `LPM_GREEDY_FUSION=0` — opt-out from the fused
                // dispatcher to the legacy walker arm ( // orchestration: walker + dispatcher +
                // resolver_with_shared_cache in parallel) while still
                // using the greedy resolver. Useful for debugging
                // dispatcher-specific issues with greedy-resolver
                // behavior held constant.
                //
                // Reference n=20 bench (median, bench/fixture-large):
                // greedy-stream (walker) 4,521 ms total
                // greedy-fusion 918 ms total
                // -3,603 ms median delta, paired t = -23.27. The default-
                // flip preserves these numbers (now reachable without the
                // `LPM_RESOLVER=greedy` opt-in env var).
                // `pubgrub_opt_out` and `auto_install_peers`
                // are computed at the top of `run_with_options` (above
                // the lockfile fast-path call) so the v1-lockfile gate
                // and the pubgrub-mismatch warning fire even on warm
                // installs that take the lockfile fast path. The two
                // values are reused unchanged here.
                let fusion_disabled = std::env::var("LPM_GREEDY_FUSION").as_deref() == Ok("0");
                let fusion_enabled_local = !pubgrub_opt_out && !fusion_disabled;

                // Stamp `lpm.lock`'s `resolved-with` field with the arm
                // that's about to run. Mirrors the dispatch matrix in the
                // comment block above. Read by the cold-resolve writer
                // at the bottom of `run_with_options`.
                resolved_with = if pubgrub_opt_out {
                    "pubgrub"
                } else if fusion_disabled {
                    "greedy"
                } else {
                    "greedy-fusion"
                };
                let speculation_deps: HashMap<String, String> = if omit_policy.dev {
                    deps.iter()
                        .filter(|(name, _)| production_dependency_names.contains(*name))
                        .map(|(name, range)| (name.clone(), range.clone()))
                        .collect()
                } else {
                    deps.clone()
                };

                let (resolve_res, initial_batch_ms_measured): (
                    Result<lpm_resolver::ResolveResult, LpmError>,
                    u128,
                ) = if fusion_enabled_local {
                    // ── FUSION PATH ─────────────────────────────────────
                    let fetch_overlap_allowed_local =
                        fetch_overlap_enabled(fusion_enabled_local, force, omit_policy.dev);
                    let preflight_disables_tarball_prefetch = npm_firewall_mode
                        .disables_tarball_prefetch()
                        || policy_extensions_disable_tarball_prefetch(&policy_extension_configs);
                    let fetch_overlap_downloads_during_resolve =
                        fetch_overlap_allowed_local && !preflight_disables_tarball_prefetch;
                    if preflight_disables_tarball_prefetch && fetch_overlap_allowed_local {
                        post_firewall_fetch_overlap_allowed = true;
                    }
                    let npm_fanout = positive_usize_env_or_default(
                        "LPM_NPM_FANOUT",
                        default_fusion_npm_fanout(
                            fetch_overlap_downloads_during_resolve,
                            resolver_min_age_secs,
                        ),
                    );
                    let speculation_permits = positive_usize_env_or_default(
                        ENV_FUSION_SPECULATION_PERMITS,
                        DEFAULT_FUSION_SPECULATION_PERMITS,
                    );

                    let shared_cache: lpm_resolver::SharedCache = Arc::new(dashmap::DashMap::new());
                    seed_workspace_resolver_cache(&shared_cache, &all_workspace_members)?;
                    let (spec_tx, spec_rx) =
                        tokio::sync::mpsc::channel::<(String, SpeculativePackageMetadata)>(512);
                    let (dispatcher_handle, dispatcher_counters) = spawn_speculation_dispatcher(
                        spec_rx,
                        arc_client.clone(),
                        route_table.clone(),
                        store.clone(),
                        fetch_semaphore.clone(),
                        Some(Arc::new(Semaphore::new(speculation_permits))),
                        fetch_coord.clone(),
                        if npm_firewall_mode.disables_tarball_prefetch()
                            || policy_extensions_disable_tarball_prefetch(&policy_extension_configs)
                        {
                            HashMap::new()
                        } else {
                            speculation_deps
                        },
                        spec_tracker.clone(),
                        store_v2_handle.clone(),
                        fetch_extract_limiter.clone(),
                    );
                    let selected_package_fetch_overlap_allowed = fetch_overlap_allowed_local
                        && !policy_extensions_disable_tarball_prefetch(&policy_extension_configs);
                    let selected_package_tx = if selected_package_fetch_overlap_allowed {
                        if npm_firewall_mode.is_enabled() {
                            let (selected_tx, selected_rx) = tokio::sync::mpsc::unbounded_channel();
                            let (fetch_tx, fetch_rx) = tokio::sync::mpsc::unbounded_channel();
                            fetch_overlap_join = Some(spawn_fetch_overlap_dispatcher(
                                fetch_rx,
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
                                1,
                            ));
                            npm_firewall_preflight_join =
                                Some(spawn_chunked_npm_firewall_preflight(
                                    selected_rx,
                                    fetch_tx,
                                    arc_client.clone(),
                                    NpmFirewallChunkedPreflightConfig {
                                        route_table: route_table.clone(),
                                        mode: npm_firewall_mode,
                                        lookup_mode: npm_firewall_lookup_mode,
                                        offline,
                                        chunk_size: npm_firewall_chunk_size,
                                    },
                                ));
                            Some(selected_tx)
                        } else {
                            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                            fetch_overlap_join = Some(spawn_fetch_overlap_dispatcher(
                                rx,
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
                                fetch_overlap_min_selected(),
                            ));
                            Some(tx)
                        }
                    } else {
                        None
                    };
                    let res = lpm_resolver::resolve_greedy_fused_with_cache_options_policy_and_selected_events(
                        arc_client.clone(),
                        deps.clone(),
                        override_set.clone(),
                        route_table.clone(),
                        npm_fanout,
                        Some(spec_tx),
                        shared_cache,
                        auto_install_peers,
                        !omit_policy.optional,
                        resolver_policy.clone(),
                        selected_package_tx,
                    )
                    .await
                    .map_err(crate::resolver_error::resolver_error_to_lpm);

                    // initial_batch_ms is meaningless under fusion (no
                    // walker → no roots-ready boundary); 0 reads as
                    // "lockfile fast path" in --json which is technically
                    // wrong but harmless — the real story is in
                    // `timing.resolve.dispatcher.*` (W1 plumbing).
                    speculation_join = Some(SpeculationJoin {
                        producer: None,
                        dispatcher: dispatcher_handle,
                        dispatched: dispatcher_counters.dispatched,
                        completed: dispatcher_counters.completed,
                        task_ms_sum: dispatcher_counters.task_ms_sum,
                        transitive_dispatched: dispatcher_counters.transitive_dispatched,
                        max_depth_reached: dispatcher_counters.max_depth_reached,
                        no_version_match: dispatcher_counters.no_version_match,
                        unresolved_parked: dispatcher_counters.unresolved_parked,
                        failed: dispatcher_counters.failed,
                        skipped_no_permit: dispatcher_counters.skipped_no_permit,
                        skipped_auth: dispatcher_counters.skipped_auth,
                    });
                    (res, 0u128)
                } else {
                    // ── LEGACY PATH (walker + spec dispatcher) ──
                    let dep_names: Vec<String> = deps.keys().cloned().collect();

                    // orchestration (design): spawn walker +
                    // dispatcher; resolve concurrently waiting on roots_ready.
                    // Walker is the manifest producer; the dispatcher is the
                    // pure consumer of the existing `(name, SpeculativePackageMetadata)`
                    // mpsc. The three run in parallel — walker fetches,
                    // dispatcher speculates tarballs, resolver waits on
                    // roots_ready_rx then solves against the shared cache.
                    //
                    // Critically: walker + dispatcher `JoinHandle`s are NOT
                    // awaited here. They're bundled into `SpeculationJoin` below
                    // and drained at the existing post-fetch drain point —
                    // preserving the speculation overlap and
                    // matching design's "tail drains post-fetch, not
                    // aborted" invariant.
                    use lpm_resolver::{BfsWalker, NotifyMap, SharedCache, WalkerDone};
                    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
                    seed_workspace_resolver_cache(&shared_cache, &all_workspace_members)?;
                    let notify_map: NotifyMap = Arc::new(dashmap::DashMap::new());
                    // wait-loop shutdown handshake: the walker stores
                    // `true` (Release) and broadcasts `notify_waiters()` across
                    // every notify_map entry at the end of its `run()`. The
                    // resolver's wait-loop in `ensure_cached` checks this flag
                    // after `Notified::enable()` and short-circuits to the
                    // escape-hatch fetch in microseconds, instead of burning
                    // the full `fetch_wait_timeout` for keys the walker decided
                    // not to fetch. Same Arc on both sides — must be allocated
                    // before either is constructed.
                    let walker_done: WalkerDone =
                        Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let (spec_tx, spec_rx) =
                        tokio::sync::mpsc::channel::<(String, SpeculativePackageMetadata)>(512);
                    let (roots_ready_tx, roots_ready_rx) = tokio::sync::oneshot::channel::<()>();

                    let batch_start = Instant::now();

                    // Walker — metadata producer.
                    let walker_handle = if dep_names.is_empty() {
                        // No deps → fire roots_ready immediately + flip the
                        // walker_done flag so any (vacuously-empty) wait-loop
                        // sleeper short-circuits, then spawn a no-op task so
                        // the `SpeculationJoin` shape stays uniform.
                        let _ = roots_ready_tx.send(());
                        walker_done.store(true, std::sync::atomic::Ordering::Release);
                        tokio::spawn(async { Ok(lpm_resolver::WalkerSummary::default()) })
                    } else {
                        tokio::spawn(
                            BfsWalker::new(
                                arc_client.clone(),
                                shared_cache.clone(),
                                notify_map.clone(),
                                walker_done.clone(),
                                spec_tx,
                                roots_ready_tx,
                                dep_names.clone(),
                                route_table.clone(),
                            )
                            .run(),
                        )
                    };

                    // Dispatcher — speculation consumer.
                    let (dispatcher_handle, dispatcher_counters) = spawn_speculation_dispatcher(
                        spec_rx,
                        arc_client.clone(),
                        route_table.clone(),
                        store.clone(),
                        fetch_semaphore.clone(),
                        None,
                        fetch_coord.clone(),
                        if npm_firewall_mode.disables_tarball_prefetch()
                            || policy_extensions_disable_tarball_prefetch(&policy_extension_configs)
                        {
                            HashMap::new()
                        } else {
                            speculation_deps
                        },
                        spec_tracker.clone(),
                        store_v2_handle.clone(),
                        fetch_extract_limiter.clone(),
                    );

                    // Resolver — awaits roots_ready then solves against the
                    // shared cache. `fetch_wait_timeout` = 5s is the design
                    // default: the provider waits on the per-canonical
                    // Notify for up to 5s before falling through to its
                    // escape-hatch fetch.
                    let resolve_client = arc_client.clone();
                    let resolve_deps = deps.clone();
                    let resolve_overrides = override_set.clone();
                    let shared_cache_for_resolve = shared_cache.clone();
                    let notify_map_for_resolve = notify_map.clone();
                    let walker_done_for_resolve = walker_done.clone();
                    //: clone the outer-scope metrics Arc for the
                    // resolver's ownership; the outer `streaming_metrics`
                    // stays readable by the JSON-emit block via its own Arc
                    // handle.
                    let streaming_metrics_for_resolve = streaming_metrics.clone();
                    // `initial_batch_ms` captures the time from
                    // orchestration start to the moment the resolver could
                    // begin solving — i.e. roots-ready fire. This is the
                    // new-shape analog of the pre-49 "batch prefetch done"
                    // timestamp. Measuring it at the end of resolve (as the
                    // previously code did) lumped in PubGrub wall-clock, which
                    // made the JSON output internally inconsistent — PubGrub
                    // timing is already reported separately by
                    // `resolver_stage_timing.pubgrub_ms`.
                    let (resolve_res_legacy, batch_ms): (
                        Result<lpm_resolver::ResolveResult, LpmError>,
                        u128,
                    ) = async {
                        let _ = roots_ready_rx.await;
                        let roots_ready_at = batch_start.elapsed().as_millis();
                        let w2_resolve_start = Instant::now();
                        let result = lpm_resolver::resolve_with_shared_cache_options_and_policy(
                            resolve_client,
                            resolve_deps,
                            resolve_overrides,
                            shared_cache_for_resolve,
                            notify_map_for_resolve,
                            walker_done_for_resolve,
                            std::time::Duration::from_secs(5),
                            route_table.clone(),
                            streaming_metrics_for_resolve,
                            auto_install_peers,
                            !omit_policy.optional,
                            resolver_policy.clone(),
                        )
                        .await
                        .map_err(crate::resolver_error::resolver_error_to_lpm);
                        tracing::debug!(
                            "perf.w2_resolve_after_roots ms={}",
                            w2_resolve_start.elapsed().as_millis()
                        );
                        (result, roots_ready_at)
                    }
                    .await;

                    speculation_join = Some(SpeculationJoin {
                        producer: Some(walker_handle),
                        dispatcher: dispatcher_handle,
                        dispatched: dispatcher_counters.dispatched,
                        completed: dispatcher_counters.completed,
                        task_ms_sum: dispatcher_counters.task_ms_sum,
                        transitive_dispatched: dispatcher_counters.transitive_dispatched,
                        max_depth_reached: dispatcher_counters.max_depth_reached,
                        no_version_match: dispatcher_counters.no_version_match,
                        unresolved_parked: dispatcher_counters.unresolved_parked,
                        failed: dispatcher_counters.failed,
                        skipped_no_permit: dispatcher_counters.skipped_no_permit,
                        skipped_auth: dispatcher_counters.skipped_auth,
                    });

                    (resolve_res_legacy, batch_ms)
                };
                initial_batch_ms = initial_batch_ms_measured;

                let resolve_result = resolve_res?;

                // The speculation join drains after fetch so downloads
                // dispatched during resolution can overlap the authoritative
                // fetch phase without being awaited early.
                let ms = resolve_start.elapsed().as_millis();

                // Post-resolution peer dependency check: warn about unmet peers
                // using each package's actual selected version (not a union).
                //
                // Peer rules from `package.json > lpm.peerDependencyRules`
                // (translated from `pnpm.peerDependencyRules` by `lpm migrate`)
                // are compiled once and applied inside the warning loop.
                // `ignore_missing` suppresses missing-peer warnings,
                // `allow_any` suppresses version-mismatch warnings, and
                // `allowed_versions` widens the accepted range as a fallback.
                //
                // Compile is **fail-closed** — any unparseable selector key
                // or version range in `allowed_versions` aborts the install
                // before any further work. Mirrors the `OverrideSet::parse`
                // posture for `lpm.overrides`. Hand-authored typos surface
                // here rather than silently no-op'ing the rule.
                let peer_rules_cfg = pkg.lpm.as_ref().map(|l| &l.peer_dependency_rules);
                let compiled_peer_rules = match peer_rules_cfg {
                    Some(r) => CompiledPeerRules::compile(
                        &r.ignore_missing,
                        &r.allowed_versions,
                        &r.allow_any,
                    )
                    .map_err(|e| {
                        LpmError::Script(format!("invalid lpm.peerDependencyRules: {e}"))
                    })?,
                    None => CompiledPeerRules::default(),
                };
                peer_warnings = check_unmet_peers(
                    &resolve_result.packages,
                    &resolve_result.cache,
                    &compiled_peer_rules,
                );
                if !peer_warnings.is_empty() && !json_output {
                    for w in &peer_warnings {
                        output::warn(&format!("peer dep: {w}"));
                    }
                }

                // capture the override apply trace
                // from this fresh resolution. We surface it to the install
                // summary, the JSON output, and `.lpm/overrides-state.json`.
                applied_overrides = resolve_result.applied_overrides.clone();

                //capture best-effort peer-conflict reports. Drained
                // alongside applied_overrides so the JSON envelope below
                // can serialize them whether or not the user is running
                // with `--json`. Cloned (not moved) because
                // `resolve_result` is consumed by `resolved_to_install_packages`
                // a few lines down.
                peer_conflicts = resolve_result.peer_conflicts.clone();

                if strict_peer_dependencies
                    && let Some(err) = strict_peer_dependency_error(&peer_warnings, &peer_conflicts)
                {
                    return Err(err);
                }

                if peer_conflict_auto_isolation_allowed {
                    auto_isolated_peer_conflicts = !peer_conflicts.is_empty();
                    linker_mode = if auto_isolated_peer_conflicts {
                        if matches!(configured_linker_mode, lpm_linker::LinkerMode::Hoisted)
                            && !json_output
                        {
                            output::info(
                                "Peer conflicts detected; using isolated linker for this install.",
                            );
                        }
                        lpm_linker::LinkerMode::Isolated
                    } else {
                        configured_linker_mode
                    };
                }

                // — capture the platform-filtered optional
                // skip count. Surfaced as `timing.resolve.platform_skipped`
                // in `--json` output.
                let platform_skipped = resolve_result.platform_skipped;

                // capture the resolver substage
                // breakdown. Combined with the `initial_batch_ms`
                // measurement above, these feed the cold-resolve
                // observability story in `timing.resolve.*`.
                resolver_stage_timing = resolve_result.stage_timing;

                // clone the ambient peer install set BEFORE we
                // hand `resolve_result` off to `resolved_to_install_packages`
                // (which only borrows it). Persisted to the lockfile far
                // below at the cold-resolve write site so warm reinstalls
                // reproduce the same top-level node_modules layout.
                ambient_peer_installs_for_lockfile = resolve_result.ambient_peer_installs.clone();

                let mut packages = resolved_to_install_packages_with_workspace_members(
                    &resolve_result.packages,
                    &deps,
                    &resolve_result.root_aliases,
                    &resolve_result.ambient_peer_installs,
                    &resolve_result.cache,
                    &route_table,
                    &all_workspace_members,
                    project_dir,
                );

                // Snapshot the resolver's metadata cache as
                // `canonical_name → latest stable version`. The map drives
                // the post-install `+` list's `(vX.Y.Z available)` hint
                // when a direct dep was pinned to an older version than
                // the registry's current `latest` stable release.
                let latest_stable = build_latest_stable_versions(&resolve_result.cache);

                // + (manifest wiring): merge
                // in the non-registry InstallPackages produced by
                // `pre_resolve_non_registry_deps`. They were fetched +
                // extracted before the resolver ran (so the source-aware
                // fast-path will mark them cached on the next iteration),
                // but they aren't part of the resolver's output — append
                // them here so the install loop sees the full set.
                packages.extend(tarball_url_install_pkgs.iter().cloned());

                // (-transitive): post-resolve fix-up.
                // Now that BOTH the resolver output AND the non-registry
                // InstallPackages are in `packages`, populate each
                // directory/link InstallPackage's `dependencies` field
                // from its stashed source-deps. Resolver-agnostic per
                // plan — runs once after the merge regardless of
                // PubGrub vs fusion.
                apply_post_resolve_directory_link_fixup(&mut packages, &non_registry_source_deps);
                enforce_registry_integrity_policy(&packages, strict_integrity, json_output)?;

                if !json_output {
                    // Persistent second phase line. Sub-second resolves don't
                    // need their own "Resolved in Xms" beat — the count is
                    // the signal, the timing lands in the verbose footer.
                    let reported_install_count = requested_add_count.unwrap_or(packages.len());
                    let firewall_active = npm_firewall_mode.is_enabled()
                        && npm_firewall_has_packages(
                            &packages,
                            &route_table,
                            arc_client.as_ref(),
                            npm_firewall_lookup_mode,
                        );
                    let install_message = format!(
                        "Installing {} {}",
                        reported_install_count.to_string().bold(),
                        install_ui::packages_word(reported_install_count),
                    );
                    install_ui::phase(&install_ui::with_firewall_badge(
                        install_message,
                        firewall_active,
                    ));
                    //surface best-effort peer-conflict reports as
                    // warnings so the user knows which transitive
                    // consumers got a peer version outside their declared
                    // range. Mirrors npm v7+'s unconditional `npm WARN`
                    // behavior. Suppressed under `--json` to keep
                    // machine-readable output clean; `--json` consumers
                    // get the same data on the always-present
                    // `peer_conflicts` array in the install JSON envelope
                    // (constructed below).
                    for report in &resolve_result.peer_conflicts {
                        let unsatisfied_str = report
                            .unsatisfied_consumers
                            .iter()
                            .map(|(c, r)| format!("{c} wants {r}"))
                            .collect::<Vec<_>>()
                            .join("; ");
                        output::warn(&format!(
                            "peer {} pinned to {} but {} unsatisfied consumer(s): {}",
                            report.canonical.bold(),
                            report.chosen_version,
                            report.unsatisfied_consumers.len(),
                            unsatisfied_str,
                        ));
                    }
                }
                (packages, ms, false, platform_skipped, latest_stable)
            }
        };
    let wf_resolve_end_ms = start.elapsed().as_millis();

    if requested_v2_mode && !v2_workspace_root_pre_resolve.install_pkgs.is_empty() {
        packages.extend(v2_workspace_root_pre_resolve.install_pkgs.iter().cloned());
        apply_post_resolve_directory_link_fixup(
            &mut packages,
            &v2_workspace_root_pre_resolve.source_deps,
        );
    }
    dedupe_install_packages_by_identity(&mut packages);

    let packages_for_lockfile = packages.clone();
    if omit_policy.dev {
        filter_dev_packages(&mut packages, &production_dependency_names);
    }
    platform_skipped += filter_platform_packages(&mut packages)?;

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
        run_npm_firewall_preflight(
            npm_firewall_mode,
            npm_firewall_lookup_mode,
            &arc_client,
            &route_table,
            &packages,
            offline,
            json_output,
        )
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
    if !json_output && !no_skills {
        let lpm_packages: Vec<String> = packages
            .iter()
            .filter(|p| p.is_lpm && p.is_direct)
            .map(|p| p.name.clone())
            .collect();

        if !lpm_packages.is_empty() {
            install_skills_for_packages(&arc_client, &lpm_packages, project_dir, no_editor_setup)
                .await;
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

    if json_output {
        let metadata_http_versions = lpm_registry::timing::snapshot_metadata_http_versions();
        let timing_metadata_detail = if timing_detail_mode.enabled() {
            Some(metadata_detail_snapshots())
        } else {
            None
        };
        let resolve_wall_ms = wf_resolve_end_ms.saturating_sub(wf_setup_ms);
        let fetch_wall_ms = wf_fetch_end_ms.saturating_sub(wf_fetch_start_ms);
        let pkg_list: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "direct": p.is_direct,
                })
            })
            .collect();

        let mut json = serde_json::json!({
                   "schema_version": crate::json_contract::INSTALL_JSON_SCHEMA_VERSION,
                   "success": true,
                   "packages": pkg_list,
                   "count": packages.len(),
                   "downloaded": downloaded,
                   "cached": cached,
                   "linked": link_result.linked,
                   "symlinked": link_result.symlinked,
                   "used_lockfile": used_lockfile,
                   "duration_ms": elapsed.as_millis() as u64,
                   "timing": {
                       "resolve_ms": resolve_ms,
                       "firewall_batch_ms": npm_firewall_stats.batch_ms,
                       "firewall": npm_firewall_stats.to_json(),
                       "fetch_ms": fetch_ms,
                       "link_ms": link_ms,
                       "total_ms": elapsed.as_millis(),
                       "waterfall": {
                           "setup_ms": wf_setup_ms,
                           "resolve_ms": wf_resolve_end_ms.saturating_sub(wf_setup_ms),
                           "pre_fetch_ms": wf_fetch_start_ms.saturating_sub(wf_resolve_end_ms),
                           "fetch_ms": wf_fetch_end_ms.saturating_sub(wf_fetch_start_ms),
                           "pre_link_ms": wf_link_start_ms.saturating_sub(wf_fetch_end_ms),
                           "link_ms": wf_link_end_ms.saturating_sub(wf_link_start_ms),
                           "link_await_ms": wf_link_await_ms,
                           "link_finalize_ms": wf_link_finalize_ms,
                           "tail_ms": elapsed.as_millis().saturating_sub(wf_link_end_ms),
                           "total_ms": elapsed.as_millis(),
                       },
        // Nested resolver breakdown:
        //
        // seeded this object with `platform_skipped`.
        // grows with the cold-resolve substage
        // breakdown so consumers can attribute `resolve_ms`
        // to a specific contributor before work starts on
        // (deeper worker walk) / (parallel follow-
        // ups) /d (slim batch response).
        //
        // Field shape:
        // platform_skipped — optional deps filtered by os/cpu ()
        // initial_batch_ms — wall-clock from
        // orchestration start to the
        // moment the resolver could begin
        // solving (walker's roots_ready
        // signal). The new-shape analog
        // of the pre-49 "batch prefetch
        // done" timestamp. On
        // lockfile-fast-path, zero.
        // Does NOT include PubGrub
        // wall-clock (reported separately
        // as `pubgrub_ms`).
        // followup_rpc_ms — metadata RPCs fired by the
        // resolver's PubGrub callbacks
        // (theb/ lever).
        // followup_rpc_count — count of those follow-up RPCs.
        // parse_ndjson_ms — serde_json CPU time for
        // follow-up batches ( lever).
        // pubgrub_ms — wall-clock inside
        // `pubgrub::resolve()` (includes
        // provider callbacks).
        //
        // `resolve_ms` stays as a top-level scalar for
        // backwards compatibility; the substages inside
        // `resolve` are additive observability.
                       "resolve": {
                           "platform_skipped": platform_skipped,
                           "initial_batch_ms": initial_batch_ms,
                           "followup_rpc_ms": resolver_stage_timing.followup_rpc_ms,
                           "followup_rpc_count": resolver_stage_timing.followup_rpc_count,
        // A1 — split formerly-conflated count into
        // walker-driven and escape-hatch buckets so
        // operators can tell whether the walker covered the
        // tree or the resolver picked up slack via direct
        // fetches. Sum of these two equals followup_rpc_count.
        //
        // zero on the fused dispatcher arm
        // (`LPM_GREEDY_FUSION=1`); see `dispatcher.*`
        // below. Retained for one release; removed in.
                           "walker_rpc_count": resolver_stage_timing.walker_rpc_count,
                           "escape_hatch_rpc_count": resolver_stage_timing.escape_hatch_rpc_count,
                           "parse_ndjson_ms": resolver_stage_timing.parse_ndjson_ms,
                           "pubgrub_ms": resolver_stage_timing.pubgrub_ms,
                           "metadata_http_versions": {
                               "http_09": metadata_http_versions.http_09,
                               "http_10": metadata_http_versions.http_10,
                               "http_11": metadata_http_versions.http_11,
                               "http_2": metadata_http_versions.http_2,
                               "http_3": metadata_http_versions.http_3,
                               "unknown": metadata_http_versions.unknown,
                           },
        // — fused metadata-dispatcher counters. Zero on
        // the walker arm; populated under greedy fusion.
        // Field shape:
        // rpc_count — total metadata RPCs the
        // dispatcher fired
        // (replaces walker +
        // escape_hatch on fusion).
        // inflight_high_water — peak in-flight metadata
        // fetches; approaching the
        // configured fanout means the
        // semaphore is binding.
        // parked_max_depth — peak Vec length in the
        // per-canonical park map;
        // healthy values are O(few),
        // hundreds = stalled CDN
        // pin on one package.
        // tarball_dispatched — speculative tarball
        // metadata frames emitted
        // by resolver arms that
        // enable CLI speculation.
        // Fusion leaves this at 0
        // by default and lets the
        // exact graph feed fetch.
        // peer_prefetch_count — speculative
        // peer-manifest fetches
        // dispatched concurrent with
        // the regular dep walk.
        // Each such fetch saved one
        // sequential round-trip from
        // the post-loop drain pass.
                           "dispatcher": {
                               "rpc_count": resolver_stage_timing.dispatcher_rpc_count,
                               "inflight_high_water":
                                   resolver_stage_timing.dispatcher_inflight_high_water,
                               "parked_max_depth": resolver_stage_timing.parked_max_depth,
                               "tarball_dispatched":
                                   resolver_stage_timing.tarball_dispatched_count,
                               "peer_prefetch_count":
                                   resolver_stage_timing.peer_prefetch_count,
                           },
        //: streaming-BFS observability per
        // design. Null on warm lockfile-fast-path
        // installs (walker never ran). Field shape:
        // walk_ms — walker's metadata-producer
        // window (from
        // `WalkerSummary::walker_wall_ms`).
        // manifests_fetched — count of packages the walker
        // inserted into SharedCache.
        // cache_hits — count of names skipped because
        // SharedCache already held them
        // (walker's cache-hit path).
        // cache_waits — provider-side: PubGrub callbacks
        // that entered the wait-loop on
        // a cache miss (fast-path cache
        // hits NOT counted). NOT equal to
        // installed package count —
        // ensure_cached is called from
        // multiple sites and may re-enter
        // across split retries. Treat
        // qualitatively: "how many times
        // did PubGrub wait on the walker."
        // cache_wait_timeouts — provider-side: wait-loop exits
        // by `fetch_wait_timeout`
        // firing. Healthy 0; non-zero
        // means a sleeper waited the
        // full timeout without the
        // walker either inserting or
        // flipping `walker_done`
        // (pre-49 wait-loop shape, or
        // a regression of the
        // shutdown handshake).
        // cache_wait_walker_done_shortcuts
        // — provider-side: wait-loop
        // exits *early* because the
        // walker terminated without
        // inserting this key. The
        // healthy outcome of the
        // shutdown handshake:
        // a transient walker gap
        // (e.g. older-version dep
        // missed by newest-only
        // expansion) routes to the
        // escape-hatch in micros
        // rather than burning the
        // 5s timeout.
        // escape_hatch_fetches — provider-side: non-root fetches
        // that bypassed the wait-loop.
        // Healthy 0 when walker attached
        // and keeps ahead of PubGrub.
        // Non-zero = walker gap OR no
        // walker (pre-shape with
        // fetch_wait_timeout == ZERO).
        // Compare against
        // `cache_wait_walker_done_shortcuts`
        // to distinguish "walker had a
        // gap, recovered cheaply" (good)
        // from "walker isn't attached"
        // (no waits at all).
        // spec_tx_send_wait_ms — walker time blocked on
        // `spec_tx.send().await`
        // (dispatcher backpressure
        // canary per design).
        // max_depth — deepest BFS level the walker
        // walked (0 = roots only).
                           "streaming_bfs": walker_summary_final.as_ref().map(|s| {
        // Per-BFS-level three-phase wall breakdown. `total_ms − fetch_ms` per level is the
        // inter-fetch dead time that's
        // continuous-stream walker is designed to eliminate.
        // Empty when the walker did zero levels (warm-cache
        // full hit). Built outside the outer json! macro so
        // its expansion doesn't blow recursion_limit.
                               let levels: Vec<serde_json::Value> = s
                                   .levels
                                   .iter()
                                   .map(|l| serde_json::json!({
                                       "depth": l.depth,
                                       "seeded_count": l.seeded_count,
                                       "cache_hit_count": l.cache_hit_count,
                                       "npm_fetch_count": l.npm_fetch_count,
                                       "lpm_fetch_count": l.lpm_fetch_count,
                                       "setup_ms": l.setup_ms,
                                       "fetch_ms": l.fetch_ms,
                                       "commit_ms": l.commit_ms,
                                       "total_ms": l.total_ms,
                                   }))
                                   .collect();
                               serde_json::json!({
                                   "walk_ms": s.walker_wall_ms,
                                   "manifests_fetched": s.manifests_fetched,
                                   "cache_hits": s.cache_hits,
                                   "cache_waits": streaming_metrics.cache_waits(),
                                   "cache_wait_timeouts": streaming_metrics.cache_wait_timeouts(),
                                   "cache_wait_walker_done_shortcuts":
                                       streaming_metrics.cache_wait_walker_done_shortcuts(),
                                   "escape_hatch_fetches": streaming_metrics.escape_hatch_fetches(),
                                   "spec_tx_send_wait_ms": s.spec_tx_send_wait_ms,
                                   "max_depth": s.max_depth,
                                   "levels": levels,
                               })
                           }),
                       },
        //: sub-stage breakdown of the fetch pool. Zeroed
        // when everything is already in the store (lockfile fast path
        // with warm cache). Field shape is the `FetchBreakdown` JSON
        // contract documented on that struct.
                       "fetch_breakdown": fetch_breakdown.to_json(),
        // — lockfile-cached URL gate telemetry. All
        // counters zero when every stored URL passed (common
        // case in steady state). `origin_mismatch > 0` is
        // expected after `LPM_REGISTRY_URL` switches;
        // `shape_mismatch > 0` is a BUG signal — the writer
        // should never emit a gate-rejectable URL.
                       "tarball_url_gate": gate_stats.to_json(),
        // speculative-fetch stats. Zero when every
        // root is already in the store before the metadata RPC
        // starts, or on the lockfile-fast-path. Field shape
        // documented on `SpeculativeStats`.
                       "speculative": spec_stats.to_json(),
                   },
                   "warnings": [],
                   "errors": [],
                   "peer_conflicts": [],
                   "peer_issues": peer_issues_json_value(&[], &[]),
               });
        json["security"] = serde_json::json!({
            "firewall": npm_firewall_stats.to_json(),
            "policy_extensions": policy_extension_stats.to_json(),
        });
        json["timing"]["policy_extensions"] = policy_extension_stats.to_json();
        if timing_detail_mode.enabled() {
            let build_state_write_timing = crate::build_state::snapshot_write_timing();
            let metadata_snapshots = timing_metadata_detail.as_deref().unwrap_or(&[]);
            let mut detail = serde_json::json!({
                "setup": {
                    "install_state_ms": wf_setup_install_state_ms,
                    "route_table_ms": wf_setup_route_table_ms,
                    "other_ms": wf_setup_ms.saturating_sub(
                        wf_setup_install_state_ms.saturating_add(wf_setup_route_table_ms),
                    ),
                },
                "metadata": metadata_detail_json_from_snapshots(
                    metadata_snapshots,
                    timing_detail_mode,
                ),
                "resolve": resolve_detail_json(
                    resolve_wall_ms,
                    initial_batch_ms,
                    &resolver_stage_timing,
                    metadata_snapshots,
                    timing_detail_mode,
                ),
                "fetch": fetch_stage_timings.to_json(
                    fetch_wall_ms,
                    packages.len(),
                    cached,
                    downloaded,
                    fetch_breakdown,
                ),
                "security": {
                    "firewall": npm_firewall_stats.to_json(),
                    "policy_extensions": policy_extension_stats.to_json(),
                    "registry_signatures": registry_signature_timings
                        .as_ref()
                        .map_or(serde_json::Value::Null, |timings| timings.to_json()),
                    "provenance": provenance_timings
                        .as_ref()
                        .map_or(serde_json::Value::Null, |timings| timings.to_json()),
                },
                "link": {
                    "reconcile_ms": wf_link_reconcile_ms,
                    "root_symlinks_ms": wf_link_root_symlinks_ms,
                    "compatibility_ms": wf_link_compatibility_ms,
                    "bin_shims_ms": wf_link_bin_shims_ms,
                    "v2_one": v2_link_task_timings.to_json(wf_link_await_ms),
                },
                "tail": {
                    "blocked_metadata_ms": wf_tail_blocked_metadata_ms,
                    "trust_snapshot_ms": wf_tail_trust_snapshot_ms,
                    "lockfile_write_ms": wf_tail_lockfile_write_ms,
                    "lockfile_write_count": wf_tail_lockfile_write_count,
                    "build_state_write_ms": build_state_write_timing.write_ms,
                    "build_state_write_count": build_state_write_timing.write_count,
                    "audit_after_install_ms": wf_tail_audit_after_install_ms,
                    "other_ms": elapsed
                        .as_millis()
                        .saturating_sub(wf_link_end_ms)
                        .saturating_sub(wf_tail_blocked_metadata_ms)
                        .saturating_sub(wf_tail_trust_snapshot_ms)
                        .saturating_sub(wf_tail_lockfile_write_ms)
                        .saturating_sub(build_state_write_timing.write_ms as u128)
                        .saturating_sub(wf_tail_audit_after_install_ms),
                },
            });
            if timing_detail_mode.trace() {
                let mut slow_packages = slow_package_timings.to_json();
                if let serde_json::Value::Object(slow_packages) = &mut slow_packages {
                    slow_packages.insert(
                        "provenance_verify".to_string(),
                        provenance_timings.as_ref().map_or_else(
                            || serde_json::Value::Array(Vec::new()),
                            crate::provenance_fetch::ProvenanceTimings::slow_verify_json,
                        ),
                    );
                }
                detail["trace"] = serde_json::json!({
                    "slow_packages": slow_packages,
                });
            }
            json["timing"]["detail"] = detail;
        }
        if !emit_timing && let Some(obj) = json.as_object_mut() {
            obj.remove("timing");
        }
        // surface workspace target set for agents.
        // None for legacy/standalone callers; Some(...) for the filtered path.
        if let Some(targets) = target_set {
            json["target_set"] =
                serde_json::Value::Array(targets.iter().map(|s| serde_json::json!(s)).collect());
        }
        // invariant: surface workspace member deps that
        // were linked locally instead of going through the registry.
        if !workspace_member_deps.is_empty() {
            json["workspace_members"] = serde_json::Value::Array(
                workspace_member_deps
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name,
                            "version": m.version,
                            "source_dir": m.source_dir.display().to_string(),
                        })
                    })
                    .collect(),
            );
        }
        // surface the override apply trace. Empty
        // when no overrides were declared OR when the lockfile fast
        // path was taken (in which case the persisted state file holds
        // the most recent trace from a fresh resolve).
        if !applied_overrides.is_empty() {
            json["applied_overrides"] = serde_json::Value::Array(
                applied_overrides
                    .iter()
                    .map(|h| {
                        serde_json::json!({
                            "raw_key": h.raw_key,
                            "source": h.source,
                            "package": h.package,
                            "from_version": h.from_version,
                            "to_version": h.to_version,
                            "via_parent": h.via_parent,
                        })
                    })
                    .collect(),
            );
        }
        json["overrides_count"] = serde_json::json!(override_set.len());
        json["overrides_fingerprint"] =
            fingerprint_json_value(override_set.len(), override_set.fingerprint());

        // best-effort peer-
        // conflict reports as an ALWAYS-PRESENT array. Empty when the
        // peer graph is clean OR on the lockfile fast path (no fresh
        // resolve produces no fresh conflict trace). Field is
        // unconditional so machine consumers can rely on its
        // existence — same shape contract as `applied_patches`.
        json["peer_conflicts"] = serde_json::Value::Array(
            peer_conflicts
                .iter()
                .map(peer_conflict_json_value)
                .collect(),
        );
        json["peer_issues"] = peer_issues_json_value(&peer_warnings, &peer_conflicts);

        // surface the patch apply trace + counts.
        // invariant : filter to entries that ACTUALLY did
        // work this run via `touched_anything()`. A no-op idempotent
        // rerun where every file already had the expected post-patch
        // bytes will report an empty `applied_patches` array — that's
        // the correct per-run signal. The patches are still in effect
        // (the state file still records them), but we did no work, so
        // we don't claim we did. Always emitted so agents can rely on
        // the field's existence.
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|a| a.touched_anything())
            .collect();
        json["applied_patches"] = applied_patches_to_json(&applied_patches_summary, project_dir);
        json["patches_count"] = serde_json::json!(current_patches.len());
        json["patches_fingerprint"] =
            fingerprint_json_value(current_patches.len(), current_patch_fingerprint);

        // surface the install-time blocked set so
        // agents and CI can drive `lpm approve-scripts` without re-scanning.
        json["blocked_count"] = serde_json::json!(blocked_capture.state.blocked_packages.len());
        json["blocked_set_changed"] = serde_json::json!(blocked_capture.should_emit_warning);
        json["blocked_set_fingerprint"] = fingerprint_json_value(
            blocked_capture.state.blocked_packages.len(),
            blocked_capture.state.blocked_set_fingerprint.clone(),
        );
        // + per-entry shape now
        // includes `static_tier` () and `version_diff` () via
        // the shared `version_diff::blocked_to_json_with_provenance`
        // helper, which is also the source of truth for the
        // approve-scripts JSON emitter. Both sides cannot drift on
        // the entry shape.
        //
        // `version_diff` is `null` when no prior binding for the
        // package name exists (first-time review). When a prior
        // exists, the structured object is documented on
        // `version_diff::version_diff_to_json`.
        //
        // The per-package `provenance.verified` block emits when
        // the drift gate captured a `ProvenanceStatus` for this
        // `(name, version)` pair. Sparse — only packages with a
        // rich-form `trustedDependencies` binding triggered a
        // fetch.
        let trusted_for_json = read_trusted_deps_from_manifest(project_dir).unwrap_or_default();
        json["blocked_packages"] = serde_json::Value::Array(
            blocked_capture
                .state
                .blocked_packages
                .iter()
                .map(|bp| {
                    crate::version_diff::blocked_to_json_with_provenance(
                        bp,
                        &trusted_for_json,
                        Some(&install_provenance_status_map),
                    )
                })
                .collect(),
        );
        if !blocked_capture.state.blocked_packages.is_empty() {
            json["next_steps"] = crate::json_contract::command_next_steps(
                "Review blocked lifecycle scripts",
                "lpm approve-scripts",
            );
        }
        if let Some(counts) = &audit_summary_for_envelope {
            json["audit_summary"] = serde_json::to_value(counts).unwrap_or(serde_json::Value::Null);
        }
        crate::security_floor::attach_security_posture(&mut json, force_security_floor);
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        // print the override apply summary BEFORE
        // the success line so it doesn't get lost at the bottom of the
        // output. Only emit on the fresh-resolution path; the lockfile
        // fast path already had the summary printed during the
        // resolution that produced the lockfile, so re-emitting it
        // would be misleading ("Applied N overrides" implies we just
        // applied them).
        if !applied_overrides.is_empty() {
            println!();
            output::info(&format!(
                "Applied {} override{}:",
                applied_overrides.len().to_string().bold(),
                if applied_overrides.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ));
            for hit in &applied_overrides {
                let source_ref = hit.source_display();
                let parent_suffix = match &hit.via_parent {
                    Some(p) => format!(", reached through {}", p.bold()),
                    None => String::new(),
                };
                println!(
                    "   {} {} → {} (via {}{})",
                    hit.package.bold(),
                    hit.from_version.dimmed(),
                    hit.to_version.bold(),
                    source_ref,
                    parent_suffix,
                );
            }
        }

        // summary of applied patches. Mirrors
        // the override summary above. **invariant :** filter
        // to entries that ACTUALLY did work this run (`touched_anything`)
        // so a no-op idempotent rerun doesn't print "Applied 1 patch"
        // with zero files. The patches are still in effect on disk
        // (the state file still records them), but if we did no work
        // we don't claim we did.
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|a| a.touched_anything())
            .collect();
        if !applied_patches_summary.is_empty() {
            println!();
            output::info(&format!(
                "Applied {} patch{}:",
                applied_patches_summary.len().to_string().bold(),
                if applied_patches_summary.len() == 1 {
                    ""
                } else {
                    "es"
                }
            ));
            for a in &applied_patches_summary {
                let rel_patch = a
                    .patch_path
                    .strip_prefix(project_dir)
                    .unwrap_or(&a.patch_path);
                let total = a.files_modified + a.files_added + a.files_deleted;
                println!(
                    "   {}@{} ({}, {} file{})",
                    a.name.bold(),
                    a.version.dimmed(),
                    rel_patch.display(),
                    total,
                    if total == 1 { "" } else { "s" },
                );
            }
        }

        // Diff direct deps against the pre-install lockfile snapshot.
        // Only deps whose resolved version CHANGED in this run land in
        // the `+ pkg@version` list — a no-op refresh prints no list,
        // `lpm i react` prints just `+ react@…`, and a hand-edited
        // manifest prints exactly the diff. The resolver's `is_direct`
        // flag scopes the diff to top-level deps so transitives never
        // pollute the list.
        //
        // Inlined silent variant of [`collect_direct_versions`]. The
        // canonical helper emits a `tracing::warn!` on duplicate
        // `is_direct = true` entries — useful as a diagnostic for the
        // `lpm i <pkg>` finalize path, but a latent resolver bug
        // occasionally double-marks deps like `chalk` / `ora` when
        // peer-rule auto-installs collide with their declared positions.
        // Surfacing that warning on every bare install of a typical
        // project would look broken. Silent last-wins instead.
        let post_direct_versions: HashMap<String, lpm_semver::Version> = packages
            .iter()
            .filter(|p| p.is_direct)
            .filter_map(|p| {
                lpm_semver::Version::parse(&p.version)
                    .ok()
                    .map(|v| (p.name.clone(), v))
            })
            .collect();
        let mut changed_direct: Vec<(String, String)> = Vec::new();
        for (name, post_v) in &post_direct_versions {
            let post_str = post_v.to_string();
            match pre_install_direct_versions.get(name) {
                Some(pre_v) if pre_v == &post_str => continue,
                _ => changed_direct.push((name.clone(), post_str)),
            }
        }
        changed_direct.sort();

        if !changed_direct.is_empty() {
            eprintln!();
            for (name, version) in &changed_direct {
                // Annotate with `(vX.Y.Z available)` when the
                // resolver's metadata cache has a stable release newer
                // than the version we just installed. Suppressed for:
                // * lockfile fast-path (no cache → empty map),
                // * non-registry sources (filtered out of `cache`),
                // * unparseable / equal / older latest versions.
                let hint = latest_stable_versions.get(name).and_then(|latest| {
                    let installed = lpm_semver::Version::parse(version).ok()?;
                    let candidate = lpm_semver::Version::parse(latest).ok()?;
                    (candidate > installed).then(|| format!("(v{latest} available)"))
                });
                install_ui::plus(name, version, hint.as_deref());
            }
        }

        // Verified-via-Sigstore counter. Drift gate populates this map
        // per package; `Verified` is the only state that earns the
        // green checkmark line. `Unverified` (operator-skipped) and
        // entries absent from the map are not counted — we only assert
        // the strong signal here, never inflate it.
        let verified_count = install_provenance_status_map
            .values()
            .filter(|s| matches!(s, lpm_common::ProvenanceStatus::Verified(_)))
            .count();

        let reported_count = if is_add_invocation {
            changed_direct.len()
        } else {
            packages.len()
        };
        let action = if is_add_invocation {
            "added"
        } else {
            "installed"
        };
        let duration_str = install_ui::format_duration(elapsed);
        let pkg_word = install_ui::packages_word(reported_count);
        eprintln!();
        install_ui::done(&format!(
            "Done · {action} {} {pkg_word} in {}",
            install_ui::bold(&reported_count.to_string()),
            install_ui::green(&duration_str),
        ));
        if verified_count > 0 {
            install_ui::done(&format!(
                "{verified_count} of {} {} verified via Sigstore",
                packages.len(),
                install_ui::packages_word(packages.len()),
            ));
        }

        // Audit-after-install advisory. Yellow `!` line; vulnerability
        // count goes red when non-zero. Computed above before the
        // human/JSON branch split so both surfaces agree.
        if let Some(counts) = &audit_summary_for_envelope {
            install_ui::warn(&install_ui::format_audit_advisory(
                counts.packages_audited,
                counts.vulnerabilities,
                counts.suspicious,
                counts.elapsed_ms,
            ));
        }

        if verbose {
            eprintln!(
                "  {}",
                format!("resolve: {resolve_ms}ms  fetch: {fetch_ms}ms  link: {link_ms}ms").dimmed()
            );
            let lockb_path = lockfile_path.with_extension("lockb");
            let lockb_size = std::fs::metadata(&lockb_path).map_or(0, |m| m.len());
            let lockfile_pkg_count = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
                .map_or(packages.len(), |lf| lf.packages.len());
            eprintln!(
                "  {}",
                format!(
                    "lpm.lock ({lockfile_pkg_count} {}) + lpm.lockb ({})",
                    install_ui::packages_word(lockfile_pkg_count),
                    lpm_common::format_bytes(lockb_size),
                )
                .dimmed()
            );
            eprintln!(
                "  {}",
                format!(
                    "{} linked, {} symlinked",
                    link_result.linked, link_result.symlinked,
                )
                .dimmed()
            );
        }
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
    write_post_install_hash(project_dir, linker_mode, object_integrity_policy);

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
