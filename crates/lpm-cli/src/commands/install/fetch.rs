use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Mutex as AsyncMutex;

use super::*;

pub(super) type FetchLock = Arc<AsyncMutex<()>>;
pub(super) type FetchExtractLimiter = Option<Arc<tokio::sync::Semaphore>>;

const ENV_FETCH_EXTRACT_PERMITS: &str = "LPM_FETCH_EXTRACT_PERMITS";
const ENV_EXPERIMENTAL_RESOLVER: &str = "LPM_EXPERIMENTAL_INSTALLER_SPIKE";
const DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS: usize = 10;

#[derive(Clone, Copy)]
pub(super) enum TarballNotFoundRecovery {
    DeleteProjectLockfiles,
    PreserveProjectLockfiles,
}

#[derive(Default)]
pub(super) struct FetchCoordinator {
    pub(super) locks: AsyncMutex<HashMap<String, FetchLock>>,
}

impl FetchCoordinator {
    pub(super) async fn lock_for(&self, key: String) -> FetchLock {
        let mut map = self.locks.lock().await;
        map.entry(key)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }
}

/// Default concurrent-tarball-download pool size. Overridable per-invocation
/// via `LPM_CONCURRENT_DOWNLOADS=N` for future network-condition A/B.
///
/// Default bumped 16 → 24 on after the concurrency
/// A/B matrix (/ × 16/24/32 permits, 11-run medians each). Key finding:
/// root-only speculation + 16 permits forced transitive downloads to
/// queue behind the speculation drain. 24 permits keeps the tail
/// parallel without HTTP/1.1 connection thrash. 32 went backwards
/// (CDN-side contention or local socket overhead). See install-source plan
/// doc for the full matrix.
pub(super) const DEFAULT_MAX_CONCURRENT_DOWNLOADS: usize = 24;

/// Read `LPM_CONCURRENT_DOWNLOADS` from the environment. Valid values are
/// integers in `1..=256`. Anything else (unparseable, zero, > 256) falls back
/// to `DEFAULT_MAX_CONCURRENT_DOWNLOADS` AFTER emitting a stderr warning so
/// users notice their override silently didn't apply. Unset → default,
/// silently.
pub(super) fn max_concurrent_downloads() -> usize {
    let Some(raw) = std::env::var("LPM_CONCURRENT_DOWNLOADS").ok() else {
        return DEFAULT_MAX_CONCURRENT_DOWNLOADS;
    };
    match raw.parse::<usize>() {
        Ok(n) if n > 0 && n <= 256 => n,
        _ => {
            crate::output::warn(&format!(
                "LPM_CONCURRENT_DOWNLOADS={raw:?} is not a valid integer in 1..=256 \
                 — falling back to default ({DEFAULT_MAX_CONCURRENT_DOWNLOADS})"
            ));
            DEFAULT_MAX_CONCURRENT_DOWNLOADS
        }
    }
}

fn parse_fetch_extract_permits(value: &str) -> Option<usize> {
    value.trim().parse::<usize>().ok().filter(|&n| n > 0)
}

fn configured_fetch_extract_permits(
    explicit_permits: Option<&str>,
    experimental_resolver: Option<&str>,
    v2_store_active: bool,
) -> Option<usize> {
    match explicit_permits {
        Some(value) => parse_fetch_extract_permits(value),
        None if experimental_resolver == Some("1") => Some(DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS),
        None => platform_default_fetch_extract_permits(v2_store_active, cfg!(target_os = "macos")),
    }
}

fn platform_default_fetch_extract_permits(
    v2_store_active: bool,
    target_is_macos: bool,
) -> Option<usize> {
    (target_is_macos && v2_store_active).then_some(DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS)
}

pub(super) fn configured_fetch_extract_limiter(v2_store_active: bool) -> FetchExtractLimiter {
    let explicit_permits = std::env::var(ENV_FETCH_EXTRACT_PERMITS).ok();
    let experimental_resolver = std::env::var(ENV_EXPERIMENTAL_RESOLVER).ok();
    configured_fetch_extract_permits(
        explicit_permits.as_deref(),
        experimental_resolver.as_deref(),
        v2_store_active,
    )
    .map(tokio::sync::Semaphore::new)
    .map(Arc::new)
}

async fn acquire_fetch_extract_permit(
    limiter: &FetchExtractLimiter,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, LpmError> {
    match limiter {
        Some(limiter) => Ok(Some(limiter.clone().acquire_owned().await.map_err(
            |_| LpmError::Registry("fetch extract limiter closed unexpectedly".into()),
        )?)),
        None => Ok(None),
    }
}

pub(super) struct OnlineFetchPhaseInput<'a> {
    pub(super) start: Instant,
    pub(super) arc_client: Arc<RegistryClient>,
    pub(super) route_table: RouteTable,
    pub(super) project_dir: &'a Path,
    pub(super) packages: Vec<InstallPackage>,
    pub(super) packages_for_lockfile: Vec<InstallPackage>,
    pub(super) store: PackageStore,
    pub(super) store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    pub(super) fetch_semaphore: Arc<Semaphore>,
    pub(super) fetch_extract_limiter: FetchExtractLimiter,
    pub(super) fetch_coord: Arc<FetchCoordinator>,
    pub(super) speculation_join: Option<SpeculationJoin>,
    pub(super) fetch_overlap_join: Option<FetchOverlapJoin>,
    pub(super) spec_tracker: SpeculativeKeyTracker,
    pub(super) gate_stats: Arc<GateStats>,
    pub(super) current_patches: &'a HashMap<String, PatchedDependencyEntry>,
    pub(super) used_lockfile: bool,
    pub(super) lockfile_peer_context_authoritative: bool,
    pub(super) force: bool,
    pub(super) force_security_floor: bool,
    pub(super) allow_new: bool,
    pub(super) effective_min_age_secs: u64,
    pub(super) release_age_policy: crate::release_age_config::ReleaseAgePolicy,
    pub(super) minimum_release_age_exclude: &'a HashSet<String>,
    pub(super) drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    pub(super) verify_policy: crate::provenance_fetch::VerifyPolicy,
    pub(super) global_config: &'a crate::commands::config::GlobalConfig,
    pub(super) lpm_root: &'a lpm_common::LpmRoot,
    pub(super) provenance_timings: &'a Option<crate::provenance_fetch::ProvenanceTimings>,
    pub(super) json_output: bool,
    pub(super) streaming_fetch: bool,
    pub(super) timing_detail_mode: TimingDetailMode,
    pub(super) slow_package_timings: &'a mut SlowPackageTimings,
    pub(super) linker_mode: lpm_linker::LinkerMode,
    pub(super) compatibility_bin_names: &'a [String],
}

pub(super) struct OnlineFetchPhaseResult {
    pub(super) packages: Vec<InstallPackage>,
    pub(super) packages_for_lockfile: Vec<InstallPackage>,
    pub(super) link_targets: Vec<LinkTarget>,
    pub(super) event_driven_link: bool,
    pub(super) event_link_handles: Vec<LinkHandle>,
    pub(super) v2_mode: bool,
    pub(super) v2_event_driven: bool,
    pub(super) v2_plan: Option<Arc<lpm_linker::v2::LinkPlanV2>>,
    pub(super) v2_event_link_handles: Vec<V2LinkHandle>,
    pub(super) v2_link_task_timings: V2LinkTaskTimings,
    pub(super) fetch_ms: u128,
    pub(super) waterfall_start_ms: u128,
    pub(super) waterfall_end_ms: u128,
    pub(super) fetch_stage_timings: FetchStageTimings,
    pub(super) cached: usize,
    pub(super) downloaded: usize,
    pub(super) fetch_breakdown: FetchBreakdown,
    pub(super) walker_summary_final: Option<lpm_resolver::WalkerSummary>,
    pub(super) spec_stats: SpeculativeStats,
    pub(super) publish_ages: HashMap<(String, String), u64>,
    pub(super) min_release_age_secs: u64,
    pub(super) install_provenance_status_map:
        HashMap<(String, String), lpm_common::ProvenanceStatus>,
    pub(super) fresh_urls: HashMap<String, String>,
}

pub(super) async fn run_online_fetch_phase(
    input: OnlineFetchPhaseInput<'_>,
) -> Result<OnlineFetchPhaseResult, LpmError> {
    let OnlineFetchPhaseInput {
        start,
        arc_client,
        route_table,
        project_dir,
        mut packages,
        mut packages_for_lockfile,
        store,
        store_v2_handle,
        fetch_semaphore,
        fetch_extract_limiter,
        fetch_coord,
        mut speculation_join,
        mut fetch_overlap_join,
        spec_tracker,
        gate_stats,
        current_patches,
        used_lockfile,
        lockfile_peer_context_authoritative,
        force,
        force_security_floor,
        allow_new,
        effective_min_age_secs,
        release_age_policy,
        minimum_release_age_exclude,
        mut drift_ignore_policy,
        mut verify_policy,
        global_config,
        lpm_root,
        provenance_timings,
        json_output,
        streaming_fetch,
        timing_detail_mode,
        slow_package_timings,
        linker_mode,
        compatibility_bin_names,
    } = input;
    let mut spec_stats = SpeculativeStats::default();
    let mut walker_summary_final: Option<lpm_resolver::WalkerSummary> = None;
    // Step 3: Download & store (parallel).: `store` is
    // already bound above — speculative dispatcher writes into it
    // during resolve, so by the time we reach here the store may hold
    // tarballs the `has_package` loop below picks up as cache hits.
    let wf_fetch_start_ms = start.elapsed().as_millis();
    let fetch_start = Instant::now();
    let fetch_plan_start = Instant::now();
    let mut fetch_stage_timings = FetchStageTimings::default();
    let v2_link_task_timings = V2LinkTaskTimings::default();

    // Aggregation buffer for fetch writeback. Populated inside the fetch
    // block with final-URL pairs only when the final URL diverges from the
    // stored lockfile URL. Keyed on PackageKey so a registry react@19.0.0
    // and a tarball-URL react@19.0.0 don't clobber each other's writeback.
    let mut fresh_urls: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut integrity_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Pre-compute the per-target patch fingerprint map so each `LinkTarget`
    // carries its own `Some("p-…")` when patched. v2's GraphKey folds it in,
    // splitting patched installs into project-isolated link entries.
    let patch_fingerprints = compute_patch_fingerprints(current_patches, project_dir)?;

    // Build link targets up front so the event-driven path can start
    // per-package linking as each tarball lands.
    // `LinkTarget` fields don't depend on fetch completion — just on
    // resolver output — so building them here is safe. Reused by both
    // the event-driven and serial link paths.
    let source_index = Arc::new(source_dependency_index(&packages));
    let link_targets: Vec<LinkTarget> = packages
        .iter()
        .map(|p| -> Result<LinkTarget, LpmError> {
            // Typed-error path for the source-aware store path.
            // - Source::Tarball (https://) routes to the integrity-
            // keyed CAS.
            // - Source::Tarball (file:) routes to the local-CAS
            // ( follow-up).
            // - Source::Directory / Link routes to the source's
            // canonicalized realpath .
            // - Source::Registry routes to the
            // (name, version)-keyed slot.
            Ok(LinkTarget {
                name: p.name.clone(),
                version: p.version.clone(),
                store_path: p.store_path_or_err(&store, project_dir, None)?,
                dependencies: link_dependencies_for_package(p, &source_index)?,
                aliases: p.aliases.clone(),
                is_direct: p.is_direct,
                root_link_names: p.root_link_names.clone(),
                wrapper_id: p.wrapper_id_for_source(),
                materialization: p.materialization_for_source(),
                peers: p.peers.clone(),
                patch_fingerprint: patch_fingerprints
                    .get(&(p.name.clone(), p.version.clone()))
                    .cloned(),
            })
        })
        .collect::<Result<_, _>>()?;

    // Event-driven link mode runs per-package work inside the fetch pipeline,
    // parallel with sibling tarball downloads, then runs final project wiring
    // as one batch. `LPM_SERIAL_LINK=1` reverts to the single-shot
    // `link_packages` path. The hoisted linker uses the serial path because
    // it has a different layout model.
    let serial_link = std::env::var("LPM_SERIAL_LINK").is_ok_and(|v| v == "1");
    let v2_mode = store_v2_handle.is_some();
    if v2_mode {
        let store_v2 = store_v2_handle
            .as_deref()
            .expect("v2_mode implies v2 store handle is available");
        for target in &link_targets {
            if !matches!(
                target.materialization,
                lpm_linker::Materialization::DirectorySource
            ) {
                continue;
            }
            let sri = local_source_sri_for_target(target);
            store_v2.populate_object_from_local_source(&target.store_path, &sri)?;
        }
    }
    // Under v2 mode, `link_packages_v2` needs the full LinkTarget set in one
    // batch so the GraphKey pre-pass can resolve cross-references. The v2
    // event-driven path below uses a separate prepare/one/finalize split.
    let event_driven_link =
        !serial_link && !v2_mode && matches!(linker_mode, lpm_linker::LinkerMode::Isolated);

    // Collection of per-package link handles. Cached packages push into this
    // before the fetch loop; fetch tasks push as each tarball materializes.
    // Awaited during the link-finalize step below.
    let mut event_link_handles: Vec<LinkHandle> = Vec::new();

    // Predicate: the v2 plan can be precomputed BEFORE fetch iff every
    // CAS-backed target arrives with both
    // (a) a known SRI (`p.integrity = Some(_)`), and
    // (b) resolver-threaded peers (`LinkTarget.peers` populated, or
    // the package declares no peer dependencies).
    // Otherwise `link_v2_prepare` would silently produce an
    // empty-peer-context graph key for any target whose peers are
    // discovered post-fetch by reading `objects/<sri>/package.json`,
    // diverging from the serial path. On predicate failure we fall
    // through to today's serial v2 link at the link stage.
    //
    // Local-source targets now get synthetic v2 objects keyed by a
    // stable sha512 of their resolved source identity, so they stay in
    // the same target set as CAS-backed packages during GraphKey
    // derivation and link-entry population.
    //
    // Mode independence: `link_v2_prepare` / `link_v2_one` /
    // `link_v2_finalize` are linker-mode-agnostic for per-package
    // work. `linker_mode` feeds into `LinkerModeTag` which is folded
    // into graph-key derivation (Isolated vs Hoisted both produce
    // valid keys), and `link_v2_finalize` handles project-side
    // wiring identically across modes. So the gate does NOT require
    // Isolated — the post-Hoisted default is fully
    // supported.
    let v2_targets_pre: Vec<lpm_linker::v2::V2Target> = if v2_mode && !serial_link {
        let mut acc: Vec<lpm_linker::v2::V2Target> = Vec::with_capacity(link_targets.len());
        let mut all_have_sri = true;
        for (lt, p) in link_targets.iter().zip(packages.iter()) {
            match lt.materialization {
                lpm_linker::Materialization::CasBacked => match p.integrity.as_deref() {
                    Some(sri) => acc.push(v2_target(p, lt.clone(), sri.to_string())),
                    None => {
                        all_have_sri = false;
                        break;
                    }
                },
                lpm_linker::Materialization::DirectorySource => {
                    acc.push(v2_target(p, lt.clone(), local_source_sri_for_target(lt)));
                }
            }
        }
        if all_have_sri { acc } else { Vec::new() }
    } else {
        Vec::new()
    };
    // Why `v2_linking_can_prepare_before_fetch` instead of
    // `LinkPlanV2::all_targets_have_resolver_threaded_peers`:
    // `LinkTarget.peers` is empty for THREE reasons documented on the
    // field — (a) package declares no peer deps, (b) all declared
    // peers absent from install set, (c) an old lockfile fast-path
    // didn't thread peers. (a) + (b) are legitimate empty results
    // from a live resolver or a current-schema lockfile; (c) is the
    // actual hazard the gate must catch.
    // The library helper `all_targets_have_resolver_threaded_peers`
    // uses `peers.is_empty()` as its sole signal, which conflates
    // (a)+(b) with (c) and would reject most installs (any package
    // with no peer deps fails it). On a fresh resolution, the
    // resolver always traverses peer-context. On a current-schema
    // lockfile fast path, the `peers` field is authoritative: empty
    // means "no resolved peers", not "unknown". Older lockfiles
    // remain conservative and fall back to serial v2.
    let v2_event_driven = v2_linking_can_prepare_before_fetch(
        v2_mode,
        serial_link,
        !v2_targets_pre.is_empty(),
        used_lockfile,
        lockfile_peer_context_authoritative,
    );

    // Plan + per-key V2Target index — both shared across the cache-hit
    // dispatch loop and every per-pkg fetch task. `Arc<LinkPlanV2>`
    // because the plan is read-only after build and lives across many
    // blocking tasks. Empty on the !v2_event_driven path; the link
    // stage falls through to `link_packages_v2` unchanged.
    let v2_plan: Option<std::sync::Arc<lpm_linker::v2::LinkPlanV2>> = if v2_event_driven {
        let store_v2 = store_v2_handle
            .as_deref()
            .expect("v2_event_driven implies v2 store");
        let plan = if used_lockfile && lockfile_peer_context_authoritative {
            lpm_linker::v2::link_v2_prepare_with_authoritative_peer_context_and_compatibility_bin_names(
                project_dir,
                v2_targets_pre,
                store_v2,
                linker_mode,
                compatibility_bin_names,
            )?
        } else {
            lpm_linker::v2::link_v2_prepare_with_compatibility_bin_names(
                project_dir,
                v2_targets_pre,
                store_v2,
                linker_mode,
                compatibility_bin_names,
            )?
        };
        Some(std::sync::Arc::new(plan))
    } else {
        None
    };
    let v2_target_by_key: std::collections::HashMap<String, lpm_linker::v2::V2Target> =
        if v2_event_driven {
            packages
                .iter()
                .zip(link_targets.iter())
                .filter_map(|(p, lt)| {
                    let sri = match lt.materialization {
                        lpm_linker::Materialization::CasBacked => {
                            p.integrity.as_deref()?.to_string()
                        }
                        lpm_linker::Materialization::DirectorySource => {
                            local_source_sri_for_target(lt)
                        }
                    };
                    Some((install_pkg_key(p), v2_target(p, lt.clone(), sri)))
                })
                .collect()
        } else {
            std::collections::HashMap::new()
        };

    // Per-package v2 link handles populated by both the cache-hit
    // short-circuits below and the fetch tasks further down. Drained
    // at the link stage and folded into the LinkResult.
    let v2_link_task_semaphore = Arc::new(Semaphore::new(v2_link_task_concurrency(
        v2_target_by_key.len(),
    )));
    let mut v2_event_link_handles: Vec<V2LinkHandle> = Vec::new();
    fetch_stage_timings.plan_ms = fetch_plan_start.elapsed().as_millis();
    let v2_prevalidate_start = Instant::now();
    let v2_reusable_prevalidation = if !force && v2_mode {
        match store_v2_handle.as_ref() {
            Some(store_v2) => {
                prevalidate_v2_reusable_objects(&packages, std::sync::Arc::clone(store_v2)).await?
            }
            None => V2ReusablePrevalidation {
                hits: HashMap::new(),
                candidate_count: 0,
                concurrency: 0,
                validation_timings: V2ReusableValidationTimings::default(),
            },
        }
    } else {
        V2ReusablePrevalidation {
            hits: HashMap::new(),
            candidate_count: 0,
            concurrency: 0,
            validation_timings: V2ReusableValidationTimings::default(),
        }
    };
    fetch_stage_timings.v2_reusable_prevalidate_ms = v2_prevalidate_start.elapsed().as_millis();
    fetch_stage_timings.v2_reusable_candidate_count =
        v2_reusable_prevalidation.candidate_count as u64;
    fetch_stage_timings.v2_reusable_concurrency = v2_reusable_prevalidation.concurrency as u64;
    fetch_stage_timings.v2_reusable_hit_count = v2_reusable_prevalidation.hits.len() as u64;
    fetch_stage_timings.v2_reusable_validation = v2_reusable_prevalidation.validation_timings;
    let v2_reusable_objects = v2_reusable_prevalidation.hits;

    // Stale-entry cleanup runs once, up front. It must happen before any
    // per-package link spawn touches `.lpm/` so the `read_dir` scan sees a
    // stable snapshot.
    //
    // Under v2 event-driven linking, `link_v2_prepare` already ran
    // `cleanup_v1_state`, so this v1-shaped cleanup is skipped. Running it
    // would wipe node_modules a second time with no benefit.
    if event_driven_link {
        lpm_linker::cleanup_stale_entries(project_dir, &link_targets)?;
    }

    let mut to_download = Vec::new();
    let mut cached = 0usize;
    let cache_classify_start = Instant::now();
    let fetch_detail_timing_enabled = timing_detail_mode.enabled();

    for p in &packages {
        // --force: re-download everything to verify integrity against registry,
        // even if the store already has it. The store's extract-to-temp + atomic
        // rename handles the case where the existing entry is valid.
        //
        // Use a source-aware existence check. For Source::Tarball, this consults the
        // integrity-keyed CAS layout — a coincidentally-named
        // registry copy in the legacy `(name, version)` slot does
        // NOT satisfy the tarball dependency. Trust-on-first-use Source::Tarball
        // (no recorded integrity) returns false → fetch runs.
        //
        // — under v2 mode, a hit in v1's
        // `<HOME>/.lpm/store/v1/` does NOT mean v2's
        // `objects/<sri>/` is populated. Force a fetch so the v2
        // path repopulates the object. (follow-up:
        // detect-and-translate v1 → v2 to skip re-download for
        // already-extracted bytes.)
        //
        // Per-source carve-out: local sources (`Source::Directory`
        // / `Source::Link`) still skip the fetch loop, but under v2
        // they now flow through pre-populated synthetic objects
        // instead of a project-root-only post-link step.
        let is_local_source = matches!(
            p.source_kind(),
            Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
        );
        if is_local_source {
            fetch_stage_timings.local_source_count += 1;
        }

        if v2_mode && is_local_source {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            cached += 1;
            if v2_event_driven
                && let Some(plan) = v2_plan.as_ref()
                && let Some(target) = v2_target_by_key.get(&install_pkg_key(p)).cloned()
            {
                let link_dispatch_start = timing_detail_start(fetch_detail_timing_enabled);
                let plan_arc = std::sync::Arc::clone(plan);
                let store_arc = std::sync::Arc::clone(
                    store_v2_handle
                        .as_ref()
                        .expect("v2_event_driven implies v2 store"),
                );
                fetch_stage_timings.link_dispatch_count += 1;
                v2_event_link_handles.push(spawn_v2_link_task(
                    plan_arc,
                    target,
                    store_arc,
                    Arc::clone(&v2_link_task_semaphore),
                ));
                record_timing_detail_ms(
                    &mut fetch_stage_timings.cache_classify_link_dispatch_ms,
                    link_dispatch_start,
                );
            }
            record_timing_detail_ms(
                &mut fetch_stage_timings.cache_classify_local_source_ms,
                classification_start,
            );
            continue;
        }

        // When v2 mode is active AND the v2 object dir for this
        // package's SRI already exists (populated by a prior install
        // OR by the speculative pre-fetcher earlier in this install),
        // skip the fetch entirely. The v2 link dispatch reads
        // `objects/<sri>/` directly, so no per-package linker hint
        // is needed here — same shape as the v1 cache-hit gate
        // below.
        //
        // The v2 fetch path is idempotent (`extract_object_from_bytes`
        // short-circuits on object hits), so a duplicate fetch is safe but
        // wastes network on every package. Mock-registry workflow tests also
        // expect one tarball request per package.
        let package_key = install_pkg_key(p);
        if !force
            && v2_mode
            && !is_local_source
            && let Some(reusable_object) = v2_reusable_objects.get(&package_key)
        {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            cached += 1;
            spec_tracker.mark_consumed_if_completed(&package_key);
            // The v2 object is already populated, so the link entry's
            // clonefile pass can run on the blocking pool in parallel with
            // sibling fetches. Awaited at the link stage below.
            if v2_event_driven
                && let Some(plan) = v2_plan.as_ref()
                && let Some(target) = v2_target_by_key.get(&package_key).cloned()
            {
                let link_dispatch_start = timing_detail_start(fetch_detail_timing_enabled);
                let mut target = target;
                target.verified_object_integrity = Some(reusable_object.object_integrity.clone());
                let plan_arc = std::sync::Arc::clone(plan);
                let store_arc = std::sync::Arc::clone(
                    store_v2_handle
                        .as_ref()
                        .expect("v2_event_driven implies v2 store"),
                );
                fetch_stage_timings.link_dispatch_count += 1;
                v2_event_link_handles.push(spawn_v2_link_task(
                    plan_arc,
                    target,
                    store_arc,
                    Arc::clone(&v2_link_task_semaphore),
                ));
                record_timing_detail_ms(
                    &mut fetch_stage_timings.cache_classify_link_dispatch_ms,
                    link_dispatch_start,
                );
            }
            record_timing_detail_ms(
                &mut fetch_stage_timings.cache_classify_v2_reusable_hit_ms,
                classification_start,
            );
            continue;
        }

        // — v1 → v2 cache-hit translation.
        //
        // When we're under v2 mode AND v1 already has the extracted
        // bytes for this package AND we know the SRI (lockfile-fast-
        // path or prior install populated `p.integrity`), copy the
        // bytes from `~/.lpm/store/v1/<name>/<version>/` into
        // `~/.lpm/store/v2/objects/<sri>/` instead of forcing a fresh
        // tarball download. The translation is bounded by a single
        // `copy_dir_recursively` (kernel CoW reflink on supporting
        // filesystems, plain copy elsewhere) — cheaper than the
        // network + extract round-trip.
        //
        // After translation, this package falls into the same
        // `cached += 1; continue;` slot as the v1 cache-hit gate
        // below, because the v2 link dispatch (around L5325) reads
        // `~/.lpm/store/v2/objects/<sri>/` directly and the object
        // is now populated.
        //
        // Falls through to the regular fetch path on any error — the
        // re-download is the correct fallback and matches pre- // behavior under v2 mode.
        if !force
            && v2_mode
            && !is_local_source
            && let Some(v2_store) = store_v2_handle.as_deref()
            && let Some(sri) = p.integrity.as_deref()
            && p.store_has_source_aware(&store, project_dir)
            && let Ok(v1_pkg_dir) = p.store_path_or_err(&store, project_dir, None)
        {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            match v2_store.populate_object_from_v1(&v1_pkg_dir, sri) {
                Ok(_) => {
                    fetch_stage_timings.v1_to_v2_translate_count += 1;
                    cached += 1;
                    // Translation populated `objects/<sri>/`, so dispatch the
                    // v2 link entry immediately.
                    if v2_event_driven
                        && let Some(plan) = v2_plan.as_ref()
                        && let Some(target) = v2_target_by_key.get(&install_pkg_key(p)).cloned()
                    {
                        let link_dispatch_start = timing_detail_start(fetch_detail_timing_enabled);
                        let plan_arc = std::sync::Arc::clone(plan);
                        let store_arc = std::sync::Arc::clone(
                            store_v2_handle
                                .as_ref()
                                .expect("v2_event_driven implies v2 store"),
                        );
                        fetch_stage_timings.link_dispatch_count += 1;
                        v2_event_link_handles.push(spawn_v2_link_task(
                            plan_arc,
                            target,
                            store_arc,
                            Arc::clone(&v2_link_task_semaphore),
                        ));
                        record_timing_detail_ms(
                            &mut fetch_stage_timings.cache_classify_link_dispatch_ms,
                            link_dispatch_start,
                        );
                    }
                    record_timing_detail_ms(
                        &mut fetch_stage_timings.cache_classify_v1_to_v2_translate_ms,
                        classification_start,
                    );
                    continue;
                }
                Err(e) => {
                    fetch_stage_timings.v1_to_v2_translate_failure_count += 1;
                    record_timing_detail_ms(
                        &mut fetch_stage_timings.cache_classify_v1_to_v2_translate_ms,
                        classification_start,
                    );
                    tracing::debug!(
                        "v1→v2 translation for {}@{} failed: {e} (falling back to fetch)",
                        p.name,
                        p.version
                    );
                }
            }
        }

        if !force && !v2_mode && p.store_has_source_aware(&store, project_dir) {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            cached += 1;
            fetch_stage_timings.v1_cache_hit_count += 1;
            spec_tracker.mark_consumed_if_completed(&package_key);
            // Spawn per-package link task immediately. This package is already
            // materialized in the store, so linking can run in parallel with
            // the fetch loop below.
            if event_driven_link {
                // Source-aware store path keeps the linker pointed at
                // the correct slot (tarball CAS for remote tarballs,
                // tarball-local CAS for file: tarballs, source
                // realpath for directory/link deps, registry CAS for
                // Registry). `store_has_source_aware()` returned true
                // above, so the SRI / source-path invariant holds —
                // `store_path_or_err` can't fail.
                let store_path = p.store_path_or_err(&store, project_dir, None)?;
                let target = LinkTarget {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    store_path,
                    dependencies: link_dependencies_for_package(p, &source_index)?,
                    aliases: p.aliases.clone(),
                    is_direct: p.is_direct,
                    root_link_names: p.root_link_names.clone(),
                    wrapper_id: p.wrapper_id_for_source(),
                    materialization: p.materialization_for_source(),
                    peers: p.peers.clone(),
                    patch_fingerprint: patch_fingerprints
                        .get(&(p.name.clone(), p.version.clone()))
                        .cloned(),
                };
                let pd = project_dir.to_path_buf();
                let force_flag = force;
                let link_dispatch_start = timing_detail_start(fetch_detail_timing_enabled);
                fetch_stage_timings.link_dispatch_count += 1;
                event_link_handles.push(tokio::task::spawn_blocking(move || {
                    lpm_linker::link_one_package(&pd, &target, force_flag)
                }));
                record_timing_detail_ms(
                    &mut fetch_stage_timings.cache_classify_link_dispatch_ms,
                    link_dispatch_start,
                );
            }
            record_timing_detail_ms(
                &mut fetch_stage_timings.cache_classify_v1_cache_hit_ms,
                classification_start,
            );
        } else {
            let classification_start = timing_detail_start(fetch_detail_timing_enabled);
            to_download.push(p.clone());
            record_timing_detail_ms(
                &mut fetch_stage_timings.cache_classify_download_candidate_ms,
                classification_start,
            );
        }
    }
    fetch_stage_timings.cache_classify_ms = cache_classify_start.elapsed().as_millis();

    let policy_gate_start = Instant::now();
    let drift_ignore_packages: Vec<String> = match &drift_ignore_policy {
        crate::provenance_fetch::DriftIgnorePolicy::IgnoreNames(names) => {
            let mut values: Vec<_> = names.iter().cloned().collect();
            values.sort();
            values
        }
        _ => Vec::new(),
    };
    let drift_ignore_unlock_authorized = if !matches!(
        drift_ignore_policy,
        crate::provenance_fetch::DriftIgnorePolicy::EnforceAll
    ) {
        crate::security_approval::ensure_project_unlock(
            crate::security_approval::ApprovalScope::ProvenanceIgnoreDrift,
            project_dir,
            json_output,
            crate::security_approval::ApprovalSource::CliFlag,
            "This install waives provenance drift checks for this project.",
            None,
            &drift_ignore_packages,
        )?;
        true
    } else {
        false
    };
    if force_security_floor
        && !matches!(
            drift_ignore_policy,
            crate::provenance_fetch::DriftIgnorePolicy::EnforceAll
        )
        && !drift_ignore_unlock_authorized
    {
        let requested = match &drift_ignore_policy {
            crate::provenance_fetch::DriftIgnorePolicy::EnforceAll => "enforce-all".to_string(),
            crate::provenance_fetch::DriftIgnorePolicy::IgnoreAll => "ignore-all".to_string(),
            crate::provenance_fetch::DriftIgnorePolicy::IgnoreNames(names) => {
                let mut values: Vec<_> = names.iter().cloned().collect();
                values.sort();
                values.join(",")
            }
        };
        crate::security_floor::record_suppression(
            crate::security_floor::SuppressionRecord::new(
                crate::security_floor::GuardedControl::ProvenanceDriftWaiver,
                crate::security_floor::SuppressionSource::Cli,
                requested,
                "enforce-all",
            ),
            json_output,
        );
        drift_ignore_policy = crate::provenance_fetch::DriftIgnorePolicy::EnforceAll;
    }
    let (_resolved_runtime_sigstore, runtime_sigstore_source) =
        crate::provenance_fetch::EnforceMode::resolve_from_chain(
            std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
            || global_config.get_sigstore_verify(),
        );
    crate::security_approval::ensure_runtime_sigstore_posture(
        project_dir,
        json_output,
        verify_policy.enforce,
        runtime_sigstore_source,
    )?;
    let unverified_provenance_packages: Vec<String> = match &verify_policy.skip {
        crate::provenance_fetch::SkipPolicy::Names(names) => {
            let mut values: Vec<_> = names.iter().cloned().collect();
            values.sort();
            values
        }
        _ => Vec::new(),
    };
    let unverified_provenance_unlock_authorized = if !matches!(
        verify_policy.skip,
        crate::provenance_fetch::SkipPolicy::None
    ) && !matches!(
        verify_policy.enforce,
        crate::provenance_fetch::EnforceMode::Off
    ) {
        crate::security_approval::ensure_project_unlock(
            crate::security_approval::ApprovalScope::ProvenanceUnverified,
            project_dir,
            json_output,
            crate::security_approval::ApprovalSource::CliFlag,
            "This install skips Sigstore verification for one or more packages in this project.",
            None,
            &unverified_provenance_packages,
        )?;
        true
    } else {
        false
    };
    if force_security_floor
        && !matches!(
            verify_policy.skip,
            crate::provenance_fetch::SkipPolicy::None
        )
        && !matches!(
            verify_policy.enforce,
            crate::provenance_fetch::EnforceMode::Off
        )
        && !unverified_provenance_unlock_authorized
    {
        let requested = match &verify_policy.skip {
            crate::provenance_fetch::SkipPolicy::None => "none".to_string(),
            crate::provenance_fetch::SkipPolicy::All => "all".to_string(),
            crate::provenance_fetch::SkipPolicy::Names(names) => {
                let mut values: Vec<_> = names.iter().cloned().collect();
                values.sort();
                values.join(",")
            }
        };
        crate::security_floor::record_suppression(
            crate::security_floor::SuppressionRecord::new(
                crate::security_floor::GuardedControl::UnverifiedProvenance,
                crate::security_floor::SuppressionSource::Cli,
                requested,
                "none",
            ),
            json_output,
        );
        verify_policy.skip = crate::provenance_fetch::SkipPolicy::None;
    }
    let cooldown_policy = lpm_security::SecurityPolicy::with_resolved_min_age(
        &project_dir.join("package.json"),
        effective_min_age_secs,
    );

    let publish_ages: HashMap<(String, String), u64> = if cooldown_policy.minimum_release_age_secs
        > 0
        && (!used_lockfile || release_age_policy.is_strict())
    {
        publish_ages_from_resolved_metadata(&packages)
    } else {
        HashMap::new()
    };

    // Enforce minimumReleaseAge: block recently published packages unless --allow-new.
    // The default policy checks direct packages on fresh resolution only; strict mode
    // also revalidates lockfile replay from stored registry-published-at timestamps.
    if !allow_new
        && cooldown_policy.minimum_release_age_secs > 0
        && (!used_lockfile || release_age_policy.is_strict())
    {
        let mut too_new = Vec::new();
        for p in &packages {
            if !release_age_policy_applies_to_install_package(release_age_policy, p) {
                continue;
            }
            if minimum_release_age_exclude.contains(&p.name) {
                continue;
            }
            let key = (p.name.clone(), p.version.clone());
            let age_secs = publish_ages.get(&key).copied();
            // Use the existing `check_release_age` semantics:
            // `None` age = no timestamp available → no warning
            // (matches pre-46b behaviour). Below-threshold age =
            // warning carrying the time-remaining info. Match the
            // existing ts-string-based API by re-running it; the
            // `publish_ages` map only carries successful parses, so
            // missing entries collapse to the `None` case here.
            if age_secs.is_none() {
                continue;
            }
            // Reconstruct a synthetic check by hand: if the age is
            // below the threshold, build a warning with the same
            // shape the helper would have returned. Keeps the
            // user-visible message identical.
            let age = age_secs.unwrap();
            if age < cooldown_policy.minimum_release_age_secs {
                let remaining = cooldown_policy.minimum_release_age_secs.saturating_sub(age);
                let hours = remaining / 3600;
                let minutes = (remaining % 3600) / 60;
                too_new.push((p.name.clone(), p.version.clone(), hours, minutes));
            }
        }

        if !too_new.is_empty() {
            if !json_output {
                output::warn(&format!(
                    "{} package(s) blocked by minimumReleaseAge ({}s):",
                    too_new.len(),
                    cooldown_policy.minimum_release_age_secs,
                ));
                for (name, version, hours, minutes) in &too_new {
                    eprintln!(
                        "    {}@{} — {}h {}m remaining",
                        name, version, hours, minutes
                    );
                }
                //: three override paths, ordered narrowest
                // to broadest persistence:
                // (1) --min-release-age=0 per-install, numeric
                // (2) --allow-new per-install, blanket bypass
                // (3) package.json persistent, repo-wide
                eprintln!(
                    "  To override: {} for one package, {} or {} (this install), or set {} in package.json.",
                    "--min-release-age-exclude <pkg>".bold(),
                    "--min-release-age=0".bold(),
                    "--allow-new".bold(),
                    "\"lpm\": { \"minimumReleaseAge\": 0 }".dimmed(),
                );
            }
            return Err(LpmError::Registry(format!(
                "{} package(s) published too recently (minimumReleaseAge={}s). Use --min-release-age-exclude <pkg>, --allow-new, or --min-release-age=<dur> to override.",
                too_new.len(),
                cooldown_policy.minimum_release_age_secs,
            )));
        }
    }

    // provenance-drift gate.
    //
    // For every resolved package with a prior approval that captured
    // `provenance_at_approval`, fetch the candidate version's
    // Sigstore attestation and compare identities. Block on
    // "provenance dropped" (axios signal) or "identity changed"
    // (publisher rotation without explicit re-approval).
    //
    // **Gating:** fires only on fresh resolution — lockfile fast-path
    // is skipped by design (the lockfile locks integrity, not
    // attestation identity). `--allow-new`
    // does NOT bypass this gate because provenance and cooldown
    // are orthogonal signals, and the cooldown override doesn't
    // imply acknowledgement of publisher drift. The caller wires the
    // `--ignore-provenance-drift[-all]` override below.
    //
    // **Performance:** sequential fetches per package. The fetcher's
    // 7-day cache under `cache/metadata/attestations/` makes repeat
    // installs O(1) per package. Revisit concurrency if sequential
    // round-trips on first install prove too costly in practice.
    //
    // **Override short-circuit:** `--ignore-provenance-drift-all`
    // skips the entire gate (no trusted-dependencies read, no
    // per-package fetch). `--ignore-provenance-drift <pkg>` skips
    // the per-package fetch for the named entries. Both paths emit a
    // concise advisory to stderr so the waived drift is auditable
    // (users explicitly asked for the opt-out; silent skip would
    // hide that they're accepting a non-zero-risk identity).
    if !used_lockfile && drift_ignore_policy.ignores_all() && !json_output {
        output::warn(
            "provenance-drift check waived for this install by --ignore-provenance-drift-all",
        );
    }
    // Per-package `ProvenanceStatus` map for the install --json
    // envelope. Declared at this scope (rather than inside the
    // `if has_rich_approvals` block) so the JSON emission below at
    // the `blocked_packages` enumeration can consume it. Sparse —
    // only packages the drift gate fetched for are present; the
    // `blocked_to_json_with_provenance` helper omits the
    // `provenance` block when the key is absent.
    let mut install_provenance_status_map: HashMap<(String, String), lpm_common::ProvenanceStatus> =
        HashMap::new();
    if !used_lockfile && !drift_ignore_policy.ignores_all() {
        let trusted =
            lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"))
                .trusted_dependencies;

        // Short-circuit the whole gate when there's no rich-form
        // approval to compare against. Projects with only legacy approvals
        // (or no `trustedDependencies` at all) skip the gate entirely: zero
        // network cost.
        let has_rich_approvals = matches!(
            &trusted,
            lpm_workspace::TrustedDependencies::Rich(map) if !map.is_empty()
        );

        if has_rich_approvals {
            let cache_root = lpm_root.cache_metadata_attestations();
            let http = reqwest::Client::new();

            // (name, version, verdict, approved_version, approved_snapshot)
            let mut drifted: Vec<(
                String,
                String,
                lpm_security::provenance::DriftVerdict,
                String,
                Option<lpm_workspace::ProvenanceSnapshot>,
            )> = Vec::new();

            for p in &packages {
                let Some((approved_version, reference_binding)) =
                    trusted.provenance_reference_for_candidate(&p.name, &p.version)
                else {
                    continue;
                };

                // Per-package override: user explicitly waived this
                // name. Emit a one-line advisory so the opt-out is
                // visible in the install log, then skip the fetch +
                // compare.
                if drift_ignore_policy.ignores_name(&p.name) {
                    if !json_output {
                        output::warn(&format!(
                            "{}@{} — provenance-drift check waived by \
                             --ignore-provenance-drift (approved reference: v{approved_version})",
                            p.name, p.version,
                        ));
                    }
                    continue;
                }
                let approved_snapshot = reference_binding.provenance_at_approval.as_ref();

                // Extract the candidate version's attestation ref
                // from the resolver's TTL cache (same pattern as the
                // cooldown gate above).
                let attestation_ref = if p.is_lpm {
                    match lpm_common::PackageName::parse(&p.name) {
                        Ok(pkg_name) => lpm_registry::timing::with_metadata_purpose(
                            lpm_registry::timing::MetadataPurpose::ProvenanceDrift,
                            arc_client.get_package_metadata(&pkg_name),
                        )
                        .await
                        .ok()
                        .and_then(|meta| {
                            meta.versions
                                .get(&p.version)
                                .and_then(|v| v.dist.as_ref())
                                .and_then(|d| d.attestations.clone())
                        }),
                        Err(_) => None,
                    }
                } else {
                    // follow-up: route via RouteTable so
                    // the provenance-drift gate doesn't fall through to
                    // public npm for a custom-registry package.
                    let route = route_table.route_for_package(&p.name);
                    lpm_registry::timing::with_metadata_purpose(
                        lpm_registry::timing::MetadataPurpose::ProvenanceDrift,
                        arc_client.get_npm_metadata_routed(&p.name, route),
                    )
                    .await
                    .ok()
                    .and_then(|meta| {
                        meta.versions
                            .get(&p.version)
                            .and_then(|v| v.dist.as_ref())
                            .and_then(|d| d.attestations.clone())
                    })
                };

                // When the operator skip-listed this name (CLI
                // `--unverified-provenance`) OR set the fleet-wide
                // enforce mode to `Off` (env / config), route the
                // fetch through the `Unverified` path — bytes
                // through the legacy identity-only parser, no
                // cryptographic checks. The drift gate still gets
                // a populated snapshot so publisher / workflow_path
                // identity drift is detected even when the operator
                // opted out of crypto.
                let now_snapshot: Option<lpm_workspace::ProvenanceSnapshot> = if verify_policy
                    .should_skip_verification_for(&p.name)
                {
                    let raw = crate::provenance_fetch::fetch_unverified_snapshot(
                        &http,
                        &p.name,
                        &p.version,
                        attestation_ref.as_ref(),
                    )
                    .await;
                    // Re-label `Unverified` → `Disabled` when fleet-
                    // wide `EnforceMode::Off` was the trigger, so the
                    // JSON envelope distinguishes wholesale opt-out
                    // (`"disabled"`) from per-package CLI carve-out
                    // (`"skipped"`). Logic shared with the batch
                    // caller in `provenance_fetch.rs` so the two
                    // sites cannot drift on the labeling rule.
                    let status = crate::provenance_fetch::relabel_skip_status_for_enforce_mode(
                        raw,
                        verify_policy.enforce,
                    );
                    // Record for the install --json envelope
                    // before consuming for the drift gate.
                    install_provenance_status_map
                        .insert((p.name.clone(), p.version.clone()), status.clone());
                    // Projection: `Unverified(snap)` / `Disabled(snap)`
                    // → Some(snap), `Absent` → Some(present:false),
                    // `TransportDegraded` → None. `VerificationRejected`
                    // is unreachable on the skip path (the verifier
                    // didn't run).
                    status.into_snapshot_for_binding(&p.name, &p.version)?
                } else {
                    let raw = crate::provenance_fetch::fetch_provenance_snapshot(
                        &http,
                        &cache_root,
                        &p.name,
                        &p.version,
                        attestation_ref.as_ref(),
                        provenance_timings.as_ref(),
                    )
                    .await;
                    // Branch arms:
                    // - `Ok(Some(snap))`: Verified (snap.present)
                    // or Absent (registry served no attestation).
                    // - `Ok(None)`: transport-degraded; drift
                    // comparator absorbs as NoDrift.
                    // - `Err(ProvenanceVerification)`: policy
                    // decision per `verify_policy.enforce`.
                    // Warn degrades to None + loud log; Deny
                    // propagates the typed error and `?`
                    // refuses the install.
                    // - `Err(other)`: infrastructure failure
                    // (cache unwritable, etc.) — propagate
                    // as-is so the user sees a real diagnostic,
                    // not a silent degrade.
                    let (snapshot_for_drift, status_for_map) = match raw {
                        Ok(Some(snap)) if snap.present => {
                            let status = lpm_common::ProvenanceStatus::Verified(snap.clone());
                            (Some(snap), status)
                        }
                        Ok(Some(_)) => (
                            Some(lpm_workspace::ProvenanceSnapshot {
                                present: false,
                                ..Default::default()
                            }),
                            lpm_common::ProvenanceStatus::Absent,
                        ),
                        Ok(None) => (None, lpm_common::ProvenanceStatus::TransportDegraded),
                        Err(lpm_common::LpmError::ProvenanceVerification(reason)) => {
                            let status = lpm_common::ProvenanceStatus::VerificationRejected {
                                reason: reason.clone(),
                            };
                            let snapshot = match verify_policy.enforce {
                                crate::provenance_fetch::EnforceMode::Warn => {
                                    if !json_output {
                                        crate::output::warn(&format!(
                                            "provenance verification FAILED for {pkg}@{ver}: {reason}\n  \
                                             LPM_PROVENANCE_ENFORCE=warn — install proceeds without \
                                             verified provenance for this package. Re-run with \
                                             LPM_PROVENANCE_ENFORCE=deny (default) to refuse, or pass \
                                             `--unverified-provenance {pkg}` to opt out explicitly.",
                                            pkg = p.name,
                                            ver = p.version,
                                        ));
                                    }
                                    tracing::warn!(
                                        target = "lpm::provenance",
                                        pkg = %p.name,
                                        version = %p.version,
                                        reason = %reason,
                                        enforce_mode = "warn",
                                        "install drift gate: verifier rejected bundle \
                                         under warn enforce-mode — degrading to NoDrift",
                                    );
                                    None
                                }
                                // `Off` short-circuits the verifier
                                // upstream via `should_skip_verification_for`,
                                // so the verifier-rejection path is
                                // unreachable in `Off` mode. Defensive
                                // arm to keep the match exhaustive if
                                // a future refactor accidentally
                                // bypasses the skip-route — degrade
                                // identically to Warn so the install
                                // doesn't fail on a state that the
                                // operator already declared "fleet-wide
                                // off".
                                crate::provenance_fetch::EnforceMode::Off => None,
                                crate::provenance_fetch::EnforceMode::Deny => {
                                    // Surface the status in the map before
                                    // returning so a `--json` consumer that
                                    // tees stderr can correlate the failure
                                    // with the per-package envelope.
                                    install_provenance_status_map
                                        .insert((p.name.clone(), p.version.clone()), status);
                                    return Err(LpmError::ProvenanceVerification(reason));
                                }
                            };
                            (snapshot, status)
                        }
                        Err(other) => return Err(other),
                    };
                    install_provenance_status_map
                        .insert((p.name.clone(), p.version.clone()), status_for_map);
                    snapshot_for_drift
                };

                let verdict = lpm_security::provenance::check_provenance_drift(
                    approved_snapshot,
                    now_snapshot.as_ref(),
                );

                if !matches!(verdict, lpm_security::provenance::DriftVerdict::NoDrift) {
                    drifted.push((
                        p.name.clone(),
                        p.version.clone(),
                        verdict,
                        approved_version.to_string(),
                        reference_binding.provenance_at_approval.clone(),
                    ));
                }
            }

            if !drifted.is_empty() {
                // UX. extends the footer with the
                // `--ignore-provenance-drift` override suggestion.
                if !json_output {
                    output::warn(&format!(
                        "{} package(s) blocked by provenance drift:",
                        drifted.len(),
                    ));
                    for (name, version, verdict, approved_version, approved_snap) in &drifted {
                        let kind = match verdict {
                            lpm_security::provenance::DriftVerdict::ProvenanceDropped => {
                                "provenance dropped"
                            }
                            lpm_security::provenance::DriftVerdict::IdentityChanged => {
                                "publisher identity changed"
                            }
                            lpm_security::provenance::DriftVerdict::NoDrift => {
                                unreachable!("NoDrift is filtered out above")
                            }
                        };
                        // Registry- and lockfile-supplied identifiers
                        // pass through `sanitize_for_terminal` before
                        // hitting the TTY so a crafted name like
                        // `\x1b]8;;file:///etc/passwd\x07evil\x1b]8;;\x07`
                        // can't render as a clickable hyperlink or
                        // mutate the clipboard via OSC 52.
                        let name_safe = lpm_common::sanitize_for_terminal(name);
                        let version_safe = lpm_common::sanitize_for_terminal(version);
                        let approved_version_safe =
                            lpm_common::sanitize_for_terminal(approved_version);
                        eprintln!("    {}@{} — {}", name_safe, version_safe, kind);
                        let identity = approved_snap.as_ref().and_then(|s| {
                            match (s.publisher.as_deref(), s.workflow_path.as_deref()) {
                                (Some(pub_), Some(path)) => Some(format!(
                                    "{} / {}",
                                    lpm_common::sanitize_for_terminal(pub_),
                                    lpm_common::sanitize_for_terminal(path),
                                )),
                                (Some(pub_), None) => Some(lpm_common::sanitize_for_terminal(pub_)),
                                _ => None,
                            }
                        });
                        let ref_hint = approved_snap
                            .as_ref()
                            .and_then(|s| s.workflow_ref.as_deref())
                            .map(|r| format!(" (ref: {})", lpm_common::sanitize_for_terminal(r)))
                            .unwrap_or_default();
                        match identity {
                            Some(ident) => eprintln!(
                                "      last approved: v{approved_version_safe} via {ident}{ref_hint}",
                            ),
                            None => eprintln!(
                                "      last approved: v{approved_version_safe} with attestation{ref_hint}",
                            ),
                        }
                        if matches!(
                            verdict,
                            lpm_security::provenance::DriftVerdict::ProvenanceDropped
                        ) {
                            eprintln!("      this version: (no provenance attestation)");
                        }
                    }
                    eprintln!();
                    eprintln!(
                        "  This pattern was seen in the axios 1.14.1 compromise (March 2026).",
                    );
                    // narrowest-to-broadest
                    // recovery paths. Prefer re-approval (captures
                    // the new identity and tightens the subsequent
                    // gate). Per-package override for single-case
                    // acknowledged migrations. Blanket override for
                    // users consciously suspending the entire check
                    // — listed last on purpose.
                    eprintln!(
                        "  Recovery: re-approve via {}; or opt out with {} / {}.",
                        "lpm approve-scripts".bold(),
                        "--ignore-provenance-drift <pkg>".bold(),
                        "--ignore-provenance-drift-all".bold(),
                    );
                }
                return Err(LpmError::Registry(format!(
                    "{} package(s) blocked by provenance drift. Review the identity change and re-approve via `lpm approve-scripts`, or opt out per-package via `--ignore-provenance-drift <pkg>` / blanket via `--ignore-provenance-drift-all`.",
                    drifted.len(),
                )));
            }
        }
    }
    fetch_stage_timings.policy_gate_ms = policy_gate_start.elapsed().as_millis();

    let downloaded = to_download.len();
    //: accumulate per-task timings across the parallel pool so we
    // can emit a proper fetch-stage breakdown in `lpm install --json`. Empty
    // breakdown on the cached-everything path; filled in below when work runs.
    let mut fetch_breakdown = FetchBreakdown::default();
    spec_stats.completed_before_fetch = spec_tracker.completed_count();
    if !to_download.is_empty() {
        let download_wall_start = Instant::now();
        let overall = ProgressBar::new(to_download.len() as u64);
        overall.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} Downloading [{bar:30.cyan/dim}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("━╸─"),
        );
        overall.enable_steady_tick(std::time::Duration::from_millis(80));

        //: share the hoisted `fetch_semaphore` so speculative
        // dispatches (pre-resolve) and real fetches (post-resolve) draw
        // from the same 24-permit pool.
        let semaphore = fetch_semaphore.clone();
        let mut handles = Vec::new();

        for p in to_download {
            let sem = semaphore.clone();
            let client = arc_client.clone();
            let store_ref = store.clone();
            // Clone the optional v2 handle into the per-package spawn.
            // `Option::clone` is a Some/None match and `Arc::clone` is a
            // refcount bump.
            let store_v2_ref = store_v2_handle.clone();
            let coord = fetch_coord.clone();
            let overall = overall.clone();
            let force_flag = force;
            // Per-task link scheduling captures.
            let event_link = event_driven_link;
            let project_dir_buf = project_dir.to_path_buf();
            // Shared gate/retry counters for the stale-URL recovery path
            // in `fetch_and_store_*`.
            let gate_stats_c = gate_stats.clone();
            // `.npmrc`-derived routing carried into the per-package fetch
            // task. Cheap clone: Arc ref-bump for the inner NpmrcConfig.
            let route_table_c = route_table.clone();
            // Per-task v2 event-driven link captures. `v2_plan_arc` is None
            // on the !v2_event_driven path; `v2_target_for_pkg` resolves here
            // once so the per-task closure doesn't carry the whole index map.
            let v2_plan_arc = v2_plan.as_ref().map(std::sync::Arc::clone);
            let v2_target_for_pkg = if v2_event_driven {
                v2_target_by_key.get(&install_pkg_key(&p)).cloned()
            } else {
                None
            };
            let v2_link_task_semaphore_c = Arc::clone(&v2_link_task_semaphore);
            let spec_tracker_c = spec_tracker.clone();
            // Resolve this package's patch fingerprint outside the move
            // closure so the closure doesn't carry the whole map. `None` for
            // the common case where the package has no
            // `lpm.patchedDependencies` entry.
            let patch_fingerprint_for_pkg = patch_fingerprints
                .get(&(p.name.clone(), p.version.clone()))
                .cloned();
            let source_index_for_pkg = Arc::clone(&source_index);
            let trace_slow_packages = timing_detail_mode.trace();
            let fetch_extract_limiter_c = fetch_extract_limiter.clone();

            handles.push(tokio::spawn(async move {
                // v2-shaped link handle. Mutually exclusive with `LinkHandle`
                // at runtime: under v2_mode,
                // `event_link` is false (so `LinkHandle` is always None);
                // under !v2_mode, `v2_plan_arc` is None (so this is
                // always None).
                type FetchTaskResult = (
                    String,
                    Option<String>,
                    String,
                    TaskTimings,
                    Option<LinkHandle>,
                    Option<V2LinkHandle>,
                    Option<String>,
                );

                // timing: spawn→key-lock→permit captures the full time this
                // task sat queued. It also covers the FetchCoordinator wait:
                // if a speculation is mid-fetch for the same `(name, ver)`,
                // we wait on the per-key lock and short-circuit via the
                // store-hit check below.
                let queue_start = std::time::Instant::now();
                let package_display =
                    trace_slow_packages.then(|| format!("{}@{}", p.name, p.version));
                let package_key = install_pkg_key(&p);

                //: per-key fetch coordination. Acquired BEFORE
                // the download permit — if a sibling (speculation) is
                // already fetching this key, we wait here without consuming
                // a permit. On wake, `has_package` is true and we skip the
                // real fetch entirely (zero bandwidth, zero CPU).
                let key_lock = coord.lock_for(package_key.clone()).await;
                let _key_guard = key_lock.lock().await;

                // Spawn the per-pkg link task once the tarball is in the
                // store. Used in both the sibling-skip path and the normal
                // fetch path — in either case the package is materialized
                // by the time we call `link_one_package`.
                //
                // The closure takes an optional sri_override so the post-fetch
                // path can pass the freshly-computed SRI before it
                // reaches `p.integrity`. Source-aware store_path
                // routes Source::Tarball to the integrity-keyed CAS,
                // never to the registry-keyed path.
                let spawn_link = |p: &InstallPackage,
                                  sri_override: Option<&str>|
                 -> Result<Option<LinkHandle>, LpmError> {
                    if !event_link {
                        return Ok(None);
                    }
                    // (reviewed): store_path_or_err
                    // surfaces the missing-SRI invariant violation
                    // as a typed error with full package context
                    // instead of panicking. Reachable only on a
                    // malformed lockfile that bypassed the
                    // writer guard — should never fire in practice.
                    let store_path =
                        p.store_path_or_err(&store_ref, &project_dir_buf, sri_override)?;
                    let target = LinkTarget {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        store_path,
                        dependencies: link_dependencies_for_package(p, &source_index_for_pkg)?,
                        aliases: p.aliases.clone(),
                        is_direct: p.is_direct,
                        root_link_names: p.root_link_names.clone(),
                        wrapper_id: p.wrapper_id_for_source(),
                        materialization: p.materialization_for_source(),
                        peers: p.peers.clone(),
                        patch_fingerprint: patch_fingerprint_for_pkg.clone(),
                    };
                    let pd = project_dir_buf.clone();
                    Ok(Some(tokio::task::spawn_blocking(move || {
                        lpm_linker::link_one_package(&pd, &target, force_flag)
                    })))
                };

                if !force_flag
                    && let (Some(store_v2), Some(expected_sri)) =
                        (store_v2_ref.as_ref(), p.integrity.clone())
                {
                    let sri_for_result = expected_sri.clone();
                    let store_v2_check = std::sync::Arc::clone(store_v2);
                    let reusable_object = tokio::task::spawn_blocking(move || {
                        store_v2_check.reusable_object(&expected_sri)
                    })
                    .await
                    .map_err(|e| {
                        LpmError::Registry(format!("v2 cache check task panicked: {e}"))
                    })??;
                    if let Some(reusable_object) = reusable_object {
                        let v2_link_h: Option<V2LinkHandle> =
                            if let (Some(plan), Some(target), Some(store_v2)) = (
                                v2_plan_arc.as_ref(),
                                v2_target_for_pkg.as_ref(),
                                store_v2_ref.as_ref(),
                            ) {
                                let plan_c = std::sync::Arc::clone(plan);
                                let mut target_c = target.clone();
                                target_c.verified_object_integrity =
                                    Some(reusable_object.object_integrity);
                                let store_c = std::sync::Arc::clone(store_v2);
                                Some(spawn_v2_link_task(
                                    plan_c,
                                    target_c,
                                    store_c,
                                    Arc::clone(&v2_link_task_semaphore_c),
                                ))
                            } else {
                                None
                            };
                        overall.inc(1);
                        spec_tracker_c.mark_consumed_if_completed(&package_key);
                        return Ok::<FetchTaskResult, LpmError>((
                            package_key,
                            package_display,
                            sri_for_result,
                            TaskTimings {
                                queue_wait_ms: queue_start.elapsed().as_millis(),
                                ..Default::default()
                            },
                            None,
                            v2_link_h,
                            None,
                        ));
                    }
                }

                // Only honour the store-hit short-circuit when not in
                // `--force` mode. `--force` is the "re-verify
                // integrity against registry" path: the user explicitly
                // wants every tarball re-downloaded and re-hashed, even if
                // the store already has a valid copy. Without this gate, a
                // sibling task (or a prior install) making the store hot
                // would neuter `--force`.
                //
                // Source-aware existence check: a registry-CAS hit must NOT
                // satisfy a Source::Tarball pkg with the same
                // (name, version).
                let store_path_pre_fetch = (!force_flag)
                    .then(|| p.store_path_source_aware(&store_ref, &project_dir_buf, None))
                    .flatten();
                if !force_flag
                    && p.store_has_source_aware(&store_ref, &project_dir_buf)
                    && let Some(existing_path) = store_path_pre_fetch
                {
                    // A sibling completed the fetch while we waited on the
                    // key lock. Use the stored SRI for lockfile output;
                    // task_timings stays at defaults (no download work done
                    // on THIS task's critical path — the sibling's timings
                    // covered it). `None` for `final_url` here
                    // because THIS task didn't hit the registry — the
                    // sibling's task already reported the URL it used
                    // (via its own return value) and will be folded into
                    // the writeback aggregator. Reporting `None` avoids
                    // double-counting a divergence or conflicting on the
                    // URL value.
                    let sri = lpm_store::read_stored_integrity(&existing_path).unwrap_or_default();
                    let link_h = spawn_link(&p, None)?;
                    // The v2 object dir was populated by the sibling's fetch
                    // task. The per-key fetch lock above ensures we observe
                    // the post-extract state, so dispatch the v2 link entry in
                    // the same shape as the post-fetch path below.
                    let v2_link_h: Option<V2LinkHandle> =
                        if let (Some(plan), Some(target), Some(store_v2)) = (
                            v2_plan_arc.as_ref(),
                            v2_target_for_pkg.as_ref(),
                            store_v2_ref.as_ref(),
                        ) {
                            let plan_c = std::sync::Arc::clone(plan);
                            let target_c = target.clone();
                            let store_c = std::sync::Arc::clone(store_v2);
                            Some(spawn_v2_link_task(
                                plan_c,
                                target_c,
                                store_c,
                                Arc::clone(&v2_link_task_semaphore_c),
                            ))
                        } else {
                            None
                        };
                    overall.inc(1);
                    spec_tracker_c.mark_consumed_if_completed(&package_key);
                    return Ok::<FetchTaskResult, LpmError>((
                        package_key,
                        package_display,
                        sri,
                        TaskTimings {
                            queue_wait_ms: queue_start.elapsed().as_millis(),
                            ..Default::default()
                        },
                        link_h,
                        v2_link_h,
                        None,
                    ));
                }

                // W6a — `acquire_owned` so the permit can be
                // *moved* into the fetch fn and dropped between
                // download and extract. The fn drops it as soon as
                // bytes are on the heap (streaming) or on temp disk
                // (legacy), letting the next download start while this
                // task continues with extract on the blocking pool.
                let permit = sem
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| LpmError::Registry("download semaphore closed".into()))?;
                let queue_wait_ms = queue_start.elapsed().as_millis();

                overall.set_message(format!("{}@{}", p.name, p.version));

                // — Source::Tarball install packages
                // bypass the registry-routed legacy/streaming paths
                // entirely. The URL is the source identity; the
                // store path is content-addressable by integrity.
                let is_tarball_source =
                    matches!(p.source_kind(), Ok(lpm_lockfile::Source::Tarball { .. }));
                let store_v2_arg = store_v2_ref.as_deref();
                let (computed_sri, task_timings, final_url, fresh_object) = if is_tarball_source {
                    fetch_and_store_tarball_url(
                        &client,
                        &store_ref,
                        store_v2_arg,
                        &p,
                        queue_wait_ms,
                        permit,
                        &fetch_extract_limiter_c,
                    )
                    .await?
                } else if streaming_fetch {
                    fetch_and_store_streaming(
                        &client,
                        &route_table_c,
                        &store_ref,
                        store_v2_arg,
                        &p,
                        queue_wait_ms,
                        &project_dir_buf,
                        TarballNotFoundRecovery::DeleteProjectLockfiles,
                        &gate_stats_c,
                        permit,
                        &fetch_extract_limiter_c,
                    )
                    .await?
                } else {
                    fetch_and_store_legacy(
                        &client,
                        &route_table_c,
                        &store_ref,
                        store_v2_arg,
                        &p,
                        queue_wait_ms,
                        &project_dir_buf,
                        TarballNotFoundRecovery::DeleteProjectLockfiles,
                        &gate_stats_c,
                        permit,
                        &fetch_extract_limiter_c,
                    )
                    .await?
                };
                // Spawn per-pkg link immediately; the package is
                // now materialized. Runs on the blocking pool in parallel
                // with sibling fetch tasks still downloading.
                //
                // Pass the freshly-computed SRI as override so Source::Tarball
                // packages link from the integrity-keyed CAS path
                // (the freshly-stored content), not the legacy
                // registry slot. Registry sources ignore the override.
                let link_h = spawn_link(&p, Some(&computed_sri))?;

                // Dispatch v2 link entry materialization on the blocking pool now that the
                // tarball is extracted into `objects/<sri>/`. Runs in
                // parallel with sibling fetch tasks still downloading
                // and (importantly) cuts the post-fetch link-stage tail.
                let v2_link_h: Option<V2LinkHandle> =
                    if let (Some(plan), Some(target), Some(store_v2)) = (
                        v2_plan_arc.as_ref(),
                        v2_target_for_pkg.as_ref(),
                        store_v2_ref.as_ref(),
                    ) {
                        let plan_c = std::sync::Arc::clone(plan);
                        let mut target_c = target.clone();
                        if let Some(object) = fresh_object {
                            target_c.source_sri = computed_sri.clone();
                            target_c.fresh_object = Some(object);
                        }
                        let store_c = std::sync::Arc::clone(store_v2);
                        Some(spawn_v2_link_task(
                            plan_c,
                            target_c,
                            store_c,
                            Arc::clone(&v2_link_task_semaphore_c),
                        ))
                    } else {
                        None
                    };

                overall.inc(1);
                spec_tracker_c.mark_duplicated_if_failed(&package_key);
                Ok::<FetchTaskResult, LpmError>((
                    package_key,
                    package_display,
                    computed_sri,
                    task_timings,
                    link_h,
                    v2_link_h,
                    Some(final_url),
                ))
            }));
        }

        // Collect computed integrity hashes and fold per-task timings into
        // the aggregate breakdown. `fresh_urls` aggregates
        // the URL that actually served bytes for each (name, version),
        // so the writeback step at install-end can detect divergence
        // from the stored lockfile URL (stale-URL recovery) or from
        // `None` (origin-mismatch rebase that on-demand-resolved a
        // fresh URL).
        for handle in handles {
            let (pkg_key, package_display, sri, timings, link_h, v2_link_h, final_url) = handle
                .await
                .map_err(|e| LpmError::Registry(format!("download task panicked: {e}")))??;
            integrity_map.insert(pkg_key.clone(), sri);
            fetch_breakdown.record(timings);
            if let Some(package_display) = package_display.as_deref() {
                slow_package_timings.record_fetch(package_display, timings);
            }
            if let Some(lh) = link_h {
                event_link_handles.push(lh);
            }
            // Funnel v2 link handles emitted by the fetch tasks into the same
            // drain queue the cache-hit branches above feed.
            if let Some(lh) = v2_link_h {
                v2_event_link_handles.push(lh);
            }
            if let Some(url) = final_url {
                fresh_urls.insert(pkg_key, url);
            }
        }

        overall.finish_and_clear();
        fetch_stage_timings.download_wall_ms = download_wall_start.elapsed().as_millis();
    }

    if let Some(join) = fetch_overlap_join.take() {
        let drain = join.drain().await?;
        fetch_stage_timings.overlap = drain.stats;
        for outcome in drain.outcomes {
            if let Some(sri) = outcome.computed_sri {
                integrity_map.entry(outcome.key.clone()).or_insert(sri);
            }
            if let Some(timings) = outcome.timings {
                slow_package_timings.record_fetch(&outcome.package_display, timings);
            }
            if let Some(url) = outcome.final_url {
                fresh_urls.entry(outcome.key).or_insert(url);
            }
        }
    }

    let apply_fetch_writebacks = |packages: &mut [InstallPackage]| {
        for p in packages {
            let key = install_pkg_key(p);
            if let Some(sri) = integrity_map.get(&key) {
                p.integrity = Some(sri.clone());
            }
            if let Some(url) = fresh_urls.get(&key) {
                p.tarball_url = Some(url.clone());
            }
        }
    };
    apply_fetch_writebacks(&mut packages);
    apply_fetch_writebacks(&mut packages_for_lockfile);

    let fetch_ms = fetch_start.elapsed().as_millis();
    let wf_fetch_end_ms = start.elapsed().as_millis();

    // Drain any speculation tail after the authoritative fetch phase.
    // This preserves resolve/fetch overlap while making completed
    // speculation visible in the JSON counters.
    //
    // The walker summary is folded into
    // `timing.resolve.streaming_bfs` in the JSON-output block below.
    // `None` on warm lockfile-fast-path installs (walker never ran).
    if let Some(join) = speculation_join.take() {
        let summary = join.drain(&mut spec_stats).await;
        tracing::debug!(
            "walker summary: manifests_fetched={} cache_hits={} max_depth={} spec_tx_send_wait_ms={} walker_wall_ms={}",
            summary.manifests_fetched,
            summary.cache_hits,
            summary.max_depth,
            summary.spec_tx_send_wait_ms,
            summary.walker_wall_ms,
        );
        walker_summary_final = Some(summary);
    }
    let final_graph_keys: HashSet<String> = packages.iter().map(install_pkg_key).collect();
    spec_stats.consumed_by_fetch = spec_tracker.consumed_count();
    spec_stats.duplicated_with_fetch = spec_tracker.duplicated_count();
    spec_stats.failed = spec_tracker.failed_count();
    spec_stats.wasted = spec_tracker.wasted_count(&final_graph_keys);

    // Fetch / cache-hit counters are recorded into `fetch_ms` etc. and
    // surfaced via the verbose footer and JSON envelope. The default
    // human output is intentionally quiet here — the persistent
    // `› Installing N packages` line above already narrates this phase.

    Ok(OnlineFetchPhaseResult {
        packages,
        packages_for_lockfile,
        link_targets,
        event_driven_link,
        event_link_handles,
        v2_mode,
        v2_event_driven,
        v2_plan,
        v2_event_link_handles,
        v2_link_task_timings,
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
        min_release_age_secs: cooldown_policy.minimum_release_age_secs,
        install_provenance_status_map,
        fresh_urls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fetch_extract_permits_accepts_only_positive_integers() {
        assert_eq!(parse_fetch_extract_permits("4"), Some(4));
        assert_eq!(parse_fetch_extract_permits(" 2 "), Some(2));
        assert_eq!(parse_fetch_extract_permits("0"), None);
        assert_eq!(parse_fetch_extract_permits(""), None);
        assert_eq!(parse_fetch_extract_permits("nope"), None);
    }

    #[test]
    fn fetch_extract_permits_stay_unbounded_when_unset_without_experimental_installer() {
        assert_eq!(configured_fetch_extract_permits(None, None, false), None);
    }

    #[test]
    fn fetch_extract_permits_default_to_bounded_value_for_experimental_installer() {
        assert_eq!(
            configured_fetch_extract_permits(None, Some("1"), false),
            Some(DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS)
        );
    }

    #[test]
    fn fetch_extract_permits_explicit_value_overrides_experimental_default() {
        assert_eq!(
            configured_fetch_extract_permits(Some("8"), Some("1"), true),
            Some(8)
        );
    }

    #[test]
    fn fetch_extract_permits_invalid_explicit_value_keeps_existing_unbounded_escape_hatch() {
        assert_eq!(
            configured_fetch_extract_permits(Some("0"), Some("1"), true),
            None
        );
    }

    #[test]
    fn fetch_extract_permits_default_to_bounded_value_for_macos_v2_installs() {
        assert_eq!(
            platform_default_fetch_extract_permits(true, true),
            Some(DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS)
        );
    }

    #[test]
    fn fetch_extract_permits_stay_unbounded_for_macos_v1_installs() {
        assert_eq!(platform_default_fetch_extract_permits(false, true), None);
    }

    #[test]
    fn fetch_extract_permits_stay_unbounded_for_non_macos_v2_installs() {
        assert_eq!(platform_default_fetch_extract_permits(true, false), None);
    }
}

/// Pick the highest version in a slim speculation packument that
/// satisfies the given npm range string. Returns the concrete
/// `(version, tarball_url, integrity)` tuple so the caller can dispatch
/// a speculative download without waiting for PubGrub.
///
/// This is the lightweight analog of what PubGrub does in the conflict-
/// free case: pick the newest range-satisfying version. Mismatches with
/// PubGrub's final pick (~5% of real-world trees, higher in workspaces
/// with tight peer constraints) produce a wasted tarball in the store
/// — cheap to absorb, GC reclaims later.
///
/// npm dist-tags (e.g. `range = "latest"`) resolve via `dist-tags` first,
/// short-circuiting range parsing. Invalid ranges return `None` and the
/// dispatcher skips the package.
pub(super) fn pick_speculative_version(
    meta: &SpeculativePackageMetadata,
    range_str: &str,
) -> Option<(String, String, Option<String>)> {
    // dist-tag path (e.g. "latest", "next", "beta")
    if let Some(pinned) = meta.dist_tags.get(range_str)
        && let Some(dist) = meta.info.dist.get(pinned)
        && let Some(url) = dist.tarball_url.as_deref()
    {
        return Some((pinned.clone(), url.to_string(), dist.integrity.clone()));
    }

    let range = lpm_resolver::NpmRange::parse(range_str).ok()?;
    let version = meta
        .info
        .versions
        .iter()
        .find(|version| range.satisfies(version))?;
    let v_str = version.to_string();
    let dist = meta.info.dist.get(&v_str)?;
    let url = dist.tarball_url.clone()?;
    let integrity = dist.integrity.clone();
    Some((v_str, url, integrity))
}

pub(super) fn push_regular_speculative_dependencies(
    meta: &SpeculativePackageMetadata,
    version: &str,
    next_depth: u32,
    work_queue: &mut Vec<(String, String, u32, bool)>,
) {
    let Some(deps) = meta.info.deps.get(version) else {
        return;
    };
    let optional = meta.info.optional_dep_names.get(version);
    let aliases = meta.info.aliases.get(version);
    for (dep_name, dep_range) in deps {
        if optional.is_some_and(|names| names.contains(dep_name)) {
            continue;
        }
        let target_name = aliases
            .and_then(|map| map.get(dep_name))
            .map_or(dep_name.as_str(), String::as_str);
        work_queue.push((
            target_name.to_string(),
            dep_range.clone(),
            next_depth,
            false,
        ));
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum SpeculativeFetchOutcome {
    Stored,
    AlreadyPresent,
    SkippedNoPermit,
}

pub(super) fn registry_install_pkg_key(
    name: &str,
    version: &str,
    route_table: &RouteTable,
    integrity: Option<&str>,
) -> String {
    let registry_url = registry_source_url_for(name, route_table);
    let source = format!("registry+{registry_url}");
    install_pkg_key_parts(name, version, &source, integrity)
}

/// /: stream metadata AND dispatch speculative
/// downloads in parallel with NDJSON arrival. Returns the same complete
/// metadata `HashMap` that `batch_metadata_deep` would — callers are
/// semantically identical to the non-speculative path.
///
/// Dispatched downloads write directly into the real package store, so
/// the post-resolve real-fetch loop sees them as plain
/// `store.has_package()` hits. Mismatches (resolver picks a different
/// version than our naive range-match) cost one wasted tarball each;
/// the wrong version sits in the store until GC reclaims it.
///
/// transitive speculation. Roots seed a
/// work queue; as each package's manifest arrives, its chosen version's
/// dependencies are expanded onto the queue (capped at
/// [`SPECULATION_MAX_DEPTH`]). Conflict-free trees (95%+ of real-world
/// shape per npm data) see every downloaded package match what PubGrub
/// ultimately picks. Pathological cases that mismatch still converge
/// correctly via the real fetch loop.
/// Bundles the still-live metadata producer, dispatcher `JoinHandle`,
/// and dispatcher's atomic counters so `drain` at the post-fetch point
/// folds speculation stats into the report shape.
///
/// Invariant: all handles are unawaited at construction. Awaiting any
/// before `drain()` consumes the handle and makes the post-fetch drain
/// a no-op.
pub(super) struct SpeculationJoin {
    pub(super) producer: Option<
        tokio::task::JoinHandle<Result<lpm_resolver::WalkerSummary, lpm_resolver::WalkerError>>,
    >,
    pub(super) dispatcher: tokio::task::JoinHandle<()>,
    pub(super) dispatched: Arc<std::sync::atomic::AtomicU64>,
    pub(super) completed: Arc<std::sync::atomic::AtomicU64>,
    pub(super) task_ms_sum: Arc<std::sync::atomic::AtomicU64>,
    pub(super) transitive_dispatched: Arc<std::sync::atomic::AtomicU64>,
    pub(super) max_depth_reached: Arc<std::sync::atomic::AtomicU64>,
    pub(super) no_version_match: Arc<std::sync::atomic::AtomicU64>,
    pub(super) unresolved_parked: Arc<std::sync::atomic::AtomicU64>,
    pub(super) failed: Arc<std::sync::atomic::AtomicU64>,
    pub(super) skipped_no_permit: Arc<std::sync::atomic::AtomicU64>,
    pub(super) skipped_auth: Arc<std::sync::atomic::AtomicU64>,
}

impl SpeculationJoin {
    /// Await producer + dispatcher tails and fold dispatcher counters
    /// into `stats`. Consumes `self` so the handles can only be
    /// drained once.
    ///
    /// `stats.streaming_batch_ms` is read from the walker's
    /// own self-measured `walker_wall_ms` (captured inside the walker
    /// task from `run()` entry to its return). Using `started_at.elapsed()`
    /// at drain-call time measures "spawn → drain," which includes
    /// any post-walker fetch-overlap tail — not the metadata-producer
    /// window the field is documented as. The walker-owned measurement
    /// is invariant to when the caller chooses to `.await` the handle.
    /// Fusion has no separate walker, so it reports the default summary
    /// while still folding dispatcher counters.
    pub(super) async fn drain(self, stats: &mut SpeculativeStats) -> lpm_resolver::WalkerSummary {
        use std::sync::atomic::Ordering::Relaxed;
        let producer_res = match self.producer {
            Some(producer) => Some(producer.await),
            None => None,
        };
        let _dispatcher_res = self.dispatcher.await;
        stats.dispatched = self.dispatched.load(Relaxed);
        stats.completed = self.completed.load(Relaxed);
        stats.task_ms_sum = self.task_ms_sum.load(Relaxed) as u128;
        stats.transitive_dispatched = self.transitive_dispatched.load(Relaxed);
        stats.max_depth_reached = self.max_depth_reached.load(Relaxed);
        stats.no_version_match = self.no_version_match.load(Relaxed);
        stats.unresolved_parked = self.unresolved_parked.load(Relaxed);
        stats.failed = self.failed.load(Relaxed);
        stats.skipped_no_permit = self.skipped_no_permit.load(Relaxed);
        stats.skipped_auth = self.skipped_auth.load(Relaxed);
        let summary = match producer_res {
            Some(Ok(Ok(summary))) => summary,
            Some(Ok(Err(e))) => {
                tracing::warn!("metadata producer finished with error: {e}");
                lpm_resolver::WalkerSummary::default()
            }
            Some(Err(join_err)) => {
                tracing::warn!("metadata producer task join failed: {join_err}");
                lpm_resolver::WalkerSummary::default()
            }
            None => lpm_resolver::WalkerSummary::default(),
        };
        stats.streaming_batch_ms = summary.walker_wall_ms;
        summary
    }
}

/// Bundle of dispatcher atomic counters. split-out: the walker
/// owns roots-ready signalling; the dispatcher owns speculation counters.
pub(super) struct DispatcherCounters {
    pub(super) dispatched: Arc<std::sync::atomic::AtomicU64>,
    pub(super) completed: Arc<std::sync::atomic::AtomicU64>,
    pub(super) task_ms_sum: Arc<std::sync::atomic::AtomicU64>,
    pub(super) transitive_dispatched: Arc<std::sync::atomic::AtomicU64>,
    pub(super) max_depth_reached: Arc<std::sync::atomic::AtomicU64>,
    pub(super) no_version_match: Arc<std::sync::atomic::AtomicU64>,
    pub(super) unresolved_parked: Arc<std::sync::atomic::AtomicU64>,
    pub(super) failed: Arc<std::sync::atomic::AtomicU64>,
    pub(super) skipped_no_permit: Arc<std::sync::atomic::AtomicU64>,
    pub(super) skipped_auth: Arc<std::sync::atomic::AtomicU64>,
}

/// spawn the speculation dispatcher as a standalone task.
/// Consumes `(name, SpeculativePackageMetadata)` frames from `rx` (fed by the
/// walker) and issues tarball prefetches against the work queue + root
/// range set. Extraction is refactor-only vs pre-49
/// `run_deep_batch_with_speculation` — the dispatcher body is
/// unchanged except that the `roots_ready_tx` logic is gone (walker
/// fires roots-ready now; the dispatcher is just a pure consumer).
#[allow(clippy::too_many_arguments)] // design-level: dispatcher takes the full per-install state
pub(super) fn spawn_speculation_dispatcher(
    rx: tokio::sync::mpsc::Receiver<(String, SpeculativePackageMetadata)>,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    store: PackageStore,
    semaphore: Arc<Semaphore>,
    speculation_semaphore: Option<Arc<Semaphore>>,
    coord: Arc<FetchCoordinator>,
    deps: HashMap<String, String>,
    spec_tracker: SpeculativeKeyTracker,
    // — under v2 mode the dispatcher routes downloaded
    // bytes through `v2::Store::extract_object_from_bytes` instead of
    // v1's per-`(name, version)` slot. `None` keeps the legacy v1 path
    // for callers running with the env var unset (and for the migration-
    // window code paths that still write v1 alongside).
    store_v2: Option<Arc<lpm_store::v2::Store>>,
    fetch_extract_limiter: FetchExtractLimiter,
) -> (tokio::task::JoinHandle<()>, DispatcherCounters) {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    let deps_for_spec = deps;
    let client_spec = client;
    let route_table_spec = route_table;
    let store_spec = store;
    let sem_spec = semaphore;
    let speculation_sem_spec = speculation_semaphore;
    let coord_spec = coord;
    let spec_tracker_spec = spec_tracker;
    let store_v2_spec = store_v2;
    let fetch_extract_limiter_spec = fetch_extract_limiter;

    let dispatched = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let task_ms_sum = Arc::new(AtomicU64::new(0));
    let transitive_dispatched = Arc::new(AtomicU64::new(0));
    let max_depth_reached = Arc::new(AtomicU64::new(0));
    let no_version_match = Arc::new(AtomicU64::new(0));
    let unresolved_parked = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let skipped_no_permit = Arc::new(AtomicU64::new(0));
    let skipped_auth = Arc::new(AtomicU64::new(0));

    let dispatched_c = dispatched.clone();
    let completed_c = completed.clone();
    let task_ms_c = task_ms_sum.clone();
    let transitive_c = transitive_dispatched.clone();
    let max_depth_c = max_depth_reached.clone();
    let no_match_c = no_version_match.clone();
    let parked_c = unresolved_parked.clone();
    let failed_c = failed.clone();
    let skipped_no_permit_c = skipped_no_permit.clone();
    let skipped_auth_c = skipped_auth.clone();

    let mut rx = rx;
    let handle = tokio::spawn(async move {
        // — under v2 mode the dispatcher writes to
        // v2's `objects/<sri>/` via `extract_object_from_bytes`. The
        // store handle threads through `speculative_download_and_store`
        // below; when `store_v2_spec` is `Some`, the spec download
        // collects bytes (rather than streaming straight to disk) and
        // hands them to the v2 store's idempotent extract. The legacy
        // v1 path runs when `store_v2_spec` is `None`.
        //
        // Pre-this branch drained the channel as a no-op,
        // forcing the real fetch loop to do all download work — v2
        // installs paid full per-package fetch latency on the hot
        // path. With this wired, v2 cold installs match v1's
        // pipelined-fetch shape.

        // Work queue items: (package_name, range_string, depth, is_root).
        // Depth is 1 for roots, N+1 for each transitive hop. Capped at
        // SPECULATION_MAX_DEPTH.
        let mut work_queue: Vec<(String, String, u32, bool)> = Vec::new();
        // Packages whose manifest has arrived.
        let mut metadata: HashMap<String, SpeculativePackageMetadata> = HashMap::new();
        // Ranges waiting on a specific package's manifest to arrive.
        // Keyed by package name; values are (range, depth, is_root).
        let mut parked: HashMap<String, Vec<(String, u32, bool)>> = HashMap::new();
        // "name@version" that have already been dispatched; dedups
        // re-asks for the same pinned version from multiple parents.
        let mut already_dispatched: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut spec_tasks = Vec::new();

        // Seed roots.
        for (name, range) in &deps_for_spec {
            work_queue.push((name.clone(), range.clone(), 1, true));
        }

        // Process-one-item helper. Inlined so it can mutate the
        // dispatcher-local state without awkward borrow splits.
        let process_item =
            |name: String,
             range: String,
             depth: u32,
             is_root: bool,
             metadata: &HashMap<String, SpeculativePackageMetadata>,
             parked: &mut HashMap<String, Vec<(String, u32, bool)>>,
             already_dispatched: &mut std::collections::HashSet<String>,
             work_queue: &mut Vec<(String, String, u32, bool)>,
             spec_tasks: &mut Vec<tokio::task::JoinHandle<()>>| {
                let Some(meta) = metadata.get(&name) else {
                    parked
                        .entry(name)
                        .or_default()
                        .push((range, depth, is_root));
                    return;
                };

                let Some((version, url, integrity)) = pick_speculative_version(meta, &range) else {
                    // Range didn't match any arrived version — count it so we
                    // can tell "dispatcher worked but range was too tight"
                    // apart from "dispatcher never saw this package".
                    no_match_c.fetch_add(1, Relaxed);
                    return;
                };

                let key = format!("{name}@{version}");
                if !already_dispatched.insert(key) {
                    return;
                }
                let package_key = registry_install_pkg_key(
                    &name,
                    &version,
                    &route_table_spec,
                    integrity.as_deref(),
                );

                let skip_auth_bearing_custom_speculation = matches!(
                    route_table_spec.route_for_package(&name),
                    UpstreamRoute::Custom { auth: Some(_), .. }
                );

                let already_present = if let (Some(store_v2), Some(sri)) =
                    (store_v2_spec.as_deref(), integrity.as_deref())
                {
                    store_v2
                        .reusable_object_dir(sri)
                        .is_ok_and(|object_dir| object_dir.is_some())
                } else {
                    store_spec.has_package(&name, &version)
                };
                if already_present {
                    return;
                }

                // Record depth high-water mark + transitive flag.
                let current_max = max_depth_c.load(Relaxed);
                if depth as u64 > current_max {
                    max_depth_c.store(depth as u64, Relaxed);
                }
                dispatched_c.fetch_add(1, Relaxed);
                if !is_root {
                    transitive_c.fetch_add(1, Relaxed);
                }

                // Expand transitive deps onto the work queue (bounded by
                // SPECULATION_MAX_DEPTH). Speculation follows regular deps
                // only; optional deps are left to the authoritative fetch
                // path, matching the previous raw-manifest payload.
                if depth < SPECULATION_MAX_DEPTH {
                    push_regular_speculative_dependencies(meta, &version, depth + 1, work_queue);
                }

                // Skip tarball speculation for auth-bearing custom
                // registries. The real fetch loop already owns
                // correctness and user-facing failures; speculative
                // requests here only duplicate authenticated traffic
                // against private mirrors.
                if skip_auth_bearing_custom_speculation {
                    skipped_auth_c.fetch_add(1, Relaxed);
                    return;
                }

                // Spawn the download.
                let c = client_spec.clone();
                let rt = route_table_spec.clone();
                let s = store_spec.clone();
                let sem = sem_spec.clone();
                let spec_sem = speculation_sem_spec.clone();
                let coord = coord_spec.clone();
                let completed_task = completed_c.clone();
                let task_ms_task = task_ms_c.clone();
                let failed_task = failed_c.clone();
                let skipped_no_permit_task = skipped_no_permit_c.clone();
                let spec_tracker_task = spec_tracker_spec.clone();
                let store_v2_task = store_v2_spec.clone();
                let fetch_extract_limiter_task = fetch_extract_limiter_spec.clone();
                spec_tasks.push(tokio::spawn(async move {
                    let task_start = std::time::Instant::now();
                    match speculative_download_and_store(
                        &c,
                        &rt,
                        &s,
                        store_v2_task.as_deref(),
                        &sem,
                        spec_sem.as_ref(),
                        &coord,
                        &name,
                        &version,
                        &url,
                        integrity.as_deref(),
                        &fetch_extract_limiter_task,
                    )
                    .await
                    {
                        Ok(SpeculativeFetchOutcome::Stored) => {
                            completed_task.fetch_add(1, Relaxed);
                            spec_tracker_task.record_completed(package_key);
                        }
                        Ok(SpeculativeFetchOutcome::AlreadyPresent) => {
                            completed_task.fetch_add(1, Relaxed);
                            spec_tracker_task.record_completed(package_key);
                        }
                        Ok(SpeculativeFetchOutcome::SkippedNoPermit) => {
                            skipped_no_permit_task.fetch_add(1, Relaxed);
                        }
                        Err(e) => {
                            failed_task.fetch_add(1, Relaxed);
                            spec_tracker_task.record_failed(package_key);
                            tracing::debug!(
                                "speculative download {name}@{version} failed (real fetch remains authoritative): {e}"
                            );
                        }
                    }
                    task_ms_task.fetch_add(task_start.elapsed().as_millis() as u64, Relaxed);
                }));
            };

        // Main interleave loop: drain the work queue, then wait for the
        // next manifest, unpark any pending ranges that were keyed on
        // it, and repeat.
        loop {
            while let Some((name, range, depth, is_root)) = work_queue.pop() {
                process_item(
                    name,
                    range,
                    depth,
                    is_root,
                    &metadata,
                    &mut parked,
                    &mut already_dispatched,
                    &mut work_queue,
                    &mut spec_tasks,
                );
            }

            match rx.recv().await {
                Some((name, meta)) => {
                    metadata.insert(name.clone(), meta);
                    // the roots-ready signal is owned by
                    // the walker now — the dispatcher is a pure
                    // consumer of `(name, SpeculativePackageMetadata)` frames.
                    if let Some(pending) = parked.remove(&name) {
                        for (range, depth, is_root) in pending {
                            work_queue.push((name.clone(), range, depth, is_root));
                        }
                    }
                }
                None => break, // sender dropped → walker complete
            }
        }

        // Drain any remaining work (possible if a manifest arrived
        // immediately before the sender dropped).
        while let Some((name, range, depth, is_root)) = work_queue.pop() {
            process_item(
                name,
                range,
                depth,
                is_root,
                &metadata,
                &mut parked,
                &mut already_dispatched,
                &mut work_queue,
                &mut spec_tasks,
            );
        }

        // Packages still parked here were expected by some parent but
        // their manifest never arrived in the batch — the worker's
        // deep-walk didn't reach them. Report so we can tune the
        // server-side cap if this becomes common.
        let orphan_count: u64 = parked.values().map(|v| v.len() as u64).sum();
        parked_c.fetch_add(orphan_count, Relaxed);

        // Wait for all dispatched speculations to either complete or
        // drop — ensures store visibility for the real fetch loop's
        // `has_package` check. Losing a race to the real loop is fine:
        // the store's atomic-rename protects against corruption.
        futures::future::join_all(spec_tasks).await;
    });

    // caller owns the tx side of the mpsc channel and the
    // walker task; we return the dispatcher's `JoinHandle` +
    // counters. The dispatcher's `rx.recv()` loop exits when the
    // walker drops its `tx` sender — same channel-close termination
    // shape the pre-49 streaming batch path used.
    (
        handle,
        DispatcherCounters {
            dispatched,
            completed,
            task_ms_sum,
            transitive_dispatched,
            max_depth_reached,
            no_version_match,
            unresolved_parked,
            failed,
            skipped_no_permit,
            skipped_auth,
        },
    )
}

///: one speculative download — stream tarball → store,
/// identical to `fetch_and_store_streaming` but without the
/// `InstallPackage`-shaped plumbing or `TaskTimings` accounting. Errors
/// are swallowed by the dispatcher (best-effort speculation); the real
/// fetch loop remains the authority.
#[allow(clippy::too_many_arguments)]
pub(super) async fn speculative_download_and_store(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    store: &PackageStore,
    // — when `Some`, route the downloaded bytes through
    // v2's `extract_object_from_bytes` (idempotent on object hits)
    // instead of v1's `stream_and_store_package`. Each spec task
    // gets its own clone of the `Arc<Store>`.
    store_v2: Option<&lpm_store::v2::Store>,
    semaphore: &Arc<Semaphore>,
    speculation_semaphore: Option<&Arc<Semaphore>>,
    coord: &Arc<FetchCoordinator>,
    name: &str,
    version: &str,
    url: &str,
    integrity: Option<&str>,
    fetch_extract_limiter: &FetchExtractLimiter,
) -> Result<SpeculativeFetchOutcome, LpmError> {
    use futures::stream::TryStreamExt;
    use tokio_util::io::{StreamReader, SyncIoBridge};

    // + ( completion) — per-key
    // fetch lock keyed by `(name, version, source_id)`. Speculation
    // only fires for registry-source packages, so we derive the
    // registry URL through the same route table the install
    // pipeline uses (`registry_source_url_for`). That keeps the
    // speculation lock and the real fetch loop's lock for the SAME
    // registry package matching even when `.npmrc` redirects the
    // package to a private mirror. Tarball-URL packages have a
    // different source_id and naturally don't share locks with
    // speculation — that's correct (speculation never targets them).
    let speculation_key = registry_install_pkg_key(name, version, route_table, integrity);
    let key_lock = coord.lock_for(speculation_key).await;
    let _key_guard = key_lock.lock().await;

    // — store-hit short-circuit, layout-aware. Under v2
    // mode the SRI determines the object dir; if the SRI is
    // unavailable (TOFU resolution path) we fall back to v1's
    // `(name, version)` check, which is harmless under v2 (it just
    // misses an opportunity to skip).
    let already_present = if let Some(v2) = store_v2 {
        match integrity {
            Some(sri) => v2
                .reusable_object_dir(sri)
                .is_ok_and(|object_dir| object_dir.is_some()),
            None => store.has_package(name, version),
        }
    } else {
        store.has_package(name, version)
    };
    if already_present {
        return Ok(SpeculativeFetchOutcome::AlreadyPresent);
    }

    let _speculation_permit = match speculation_semaphore {
        Some(limiter) => match limiter.try_acquire() {
            Ok(permit) => Some(permit),
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                return Ok(SpeculativeFetchOutcome::SkippedNoPermit);
            }
            Err(tokio::sync::TryAcquireError::Closed) => {
                return Err(LpmError::Registry(
                    "speculation limiter semaphore closed".into(),
                ));
            }
        },
        None => None,
    };

    // Speculation must never queue ahead of the authoritative fetch loop.
    // If all shared download permits are busy, skip this best-effort
    // prefetch and let the real fetch path own the network slot.
    let permit = match semaphore.try_acquire() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            return Ok(SpeculativeFetchOutcome::SkippedNoPermit);
        }
        Err(tokio::sync::TryAcquireError::Closed) => {
            return Err(LpmError::Registry("spec semaphore closed".into()));
        }
    };

    // Keep speculative downloads on the auth-aware route so custom registries
    // use the same credentials and origin checks as authoritative fetches.
    let response = client
        .download_tarball_streaming_routed(route_table, name, url)
        .await?;

    if let Some(v2) = store_v2 {
        // v2 path: collect bytes, extract via v2 store. Streaming-to-
        // disk into v2 is a future optimization; for
        // speculation the in-memory shape is fine because spec sets
        // are bounded (a few hundred packages parallel, each typically
        // <500 KB compressed). The semaphore upstream caps the
        // concurrent allocator pressure.
        let body = response.bytes().await.map_err(|e| {
            LpmError::Registry(format!("spec body fetch failed for {name}@{version}: {e}"))
        })?;
        drop(permit);
        let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
        let v2_clone = v2.clone();
        let bytes = body.to_vec();
        let integrity_c = integrity.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || {
            v2_clone
                .extract_object_from_bytes(&bytes, integrity_c.as_deref())
                .map(|_| ())
        })
        .await
        .map_err(|e| LpmError::Registry(format!("spec v2 blocking task: {e}")))??;
        return Ok(SpeculativeFetchOutcome::Stored);
    }

    // v1 path: streaming straight to the per-`(name, version)` slot.
    let byte_stream = response.bytes_stream().map_err(std::io::Error::other);
    let async_reader = StreamReader::new(byte_stream);
    let name_c = name.to_string();
    let version_c = version.to_string();
    let integrity_c = integrity.map(|s| s.to_string());
    let store_owned = store.clone();

    let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
    tokio::task::spawn_blocking(move || {
        let sync_reader = SyncIoBridge::new(async_reader);
        store_owned
            .stream_and_store_package(
                &name_c,
                &version_c,
                sync_reader,
                integrity_c.as_deref(),
                lpm_registry::MAX_COMPRESSED_TARBALL_SIZE,
            )
            .map(|_| ())
    })
    .await
    .map_err(|e| LpmError::Registry(format!("spec blocking task: {e}")))??;
    Ok(SpeculativeFetchOutcome::Stored)
}

pub(super) struct ResolvedRegistryTarballUrl {
    pub(super) url: String,
}

fn tarball_file_prefix(name: &str) -> Option<&str> {
    name.rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

fn npm_compatible_canonical_tarball_url(
    registry_base_url: &str,
    name: &str,
    version: &str,
) -> Option<String> {
    let file_prefix = tarball_file_prefix(name)?;
    let registry_base_url = registry_base_url.trim_end_matches('/');
    let mut url = String::with_capacity(
        registry_base_url.len() + 1 + name.len() + 3 + file_prefix.len() + 1 + version.len() + 4,
    );
    url.push_str(registry_base_url);
    url.push('/');
    url.push_str(name);
    url.push_str("/-/");
    url.push_str(file_prefix);
    url.push('-');
    url.push_str(version);
    url.push_str(".tgz");
    Some(url)
}

fn lpm_canonical_tarball_url(base_url: &str, name: &str, version: &str) -> Option<String> {
    let package = lpm_common::PackageName::parse(name).ok()?;
    let base_url = base_url.trim_end_matches('/');
    let api_prefix = "/api/registry/";
    let lpm_scope = "@lpm.dev/";
    let mut url = String::with_capacity(
        base_url.len()
            + api_prefix.len()
            + lpm_scope.len()
            + package.owner.len()
            + 1
            + package.name.len()
            + 3
            + package.name.len()
            + 1
            + version.len()
            + 4,
    );
    url.push_str(base_url);
    url.push_str(api_prefix);
    url.push_str(lpm_scope);
    url.push_str(&package.owner);
    url.push('.');
    url.push_str(&package.name);
    url.push_str("/-/");
    url.push_str(&package.name);
    url.push('-');
    url.push_str(version);
    url.push_str(".tgz");
    Some(url)
}

pub(super) fn canonical_cached_registry_tarball_url(
    client: &RegistryClient,
    route_table: &RouteTable,
    name: &str,
    version: &str,
    is_lpm: bool,
) -> Option<String> {
    if is_lpm {
        return lpm_canonical_tarball_url(client.base_url(), name, version);
    }

    match route_table.route_for_package(name) {
        UpstreamRoute::Custom { target, .. } => {
            npm_compatible_canonical_tarball_url(&target.base_url, name, version)
        }
        UpstreamRoute::NpmDirect | UpstreamRoute::LpmWorker => {
            npm_compatible_canonical_tarball_url(client.npm_registry_url(), name, version)
        }
    }
}

pub(super) async fn metadata_tarball_url_for_package(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    name: &str,
    version: &str,
    is_lpm: bool,
) -> Result<(String, lpm_registry::PackageMetadata), LpmError> {
    let metadata = if is_lpm {
        let pkg =
            lpm_common::PackageName::parse(name).map_err(|e| LpmError::Registry(e.to_string()))?;
        client.get_package_metadata(&pkg).await?
    } else {
        let route = route_table.route_for_package(name);
        client.get_npm_metadata_routed(name, route).await?
    };
    let ver_meta = metadata
        .version(version)
        .ok_or_else(|| LpmError::NotFound(format!("{name}@{version} not found in metadata")))?;
    let url = ver_meta
        .tarball_url()
        .ok_or_else(|| LpmError::NotFound(format!("no tarball URL for {name}@{version}")))?
        .to_string();
    Ok((url, metadata))
}

/// Resolve the tarball URL for a registry package. Lockfile-provided
/// registry tarball hints are cache hints: use the route's canonical tarball
/// URL without a metadata round trip when it matches, otherwise bind the hint
/// back to the package version's current registry metadata.
///
/// Non-LPM metadata lookups route through `route_table`, so custom registry
/// hints are validated against the same registry that resolved them.
pub(super) async fn resolve_tarball_url(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    name: &str,
    version: &str,
    is_lpm: bool,
    cached_url: Option<&str>,
    metadata_checked_for_tarball: bool,
) -> Result<ResolvedRegistryTarballUrl, LpmError> {
    if let Some(url) = cached_url {
        if metadata_checked_for_tarball {
            return Ok(ResolvedRegistryTarballUrl {
                url: url.to_string(),
            });
        }
        if canonical_cached_registry_tarball_url(client, route_table, name, version, is_lpm)
            .as_deref()
            == Some(url)
        {
            return Ok(ResolvedRegistryTarballUrl {
                url: url.to_string(),
            });
        }
        let (metadata_url, _metadata) = lpm_registry::timing::with_metadata_purpose(
            lpm_registry::timing::MetadataPurpose::TarballUrlLookup,
            metadata_tarball_url_for_package(client, route_table, name, version, is_lpm),
        )
        .await?;
        if url != metadata_url {
            return Err(LpmError::Registry(format!(
                "registry lockfile tarball for {name}@{version} does not match registry metadata \
                 dist.tarball; refusing lockfile hint"
            )));
        }
        return Ok(ResolvedRegistryTarballUrl {
            url: url.to_string(),
        });
    }
    if metadata_checked_for_tarball {
        return Err(LpmError::NotFound(format!(
            "no tarball URL for {name}@{version}"
        )));
    }
    let (url, _metadata) = lpm_registry::timing::with_metadata_purpose(
        lpm_registry::timing::MetadataPurpose::TarballUrlLookup,
        metadata_tarball_url_for_package(client, route_table, name, version, is_lpm),
    )
    .await?;
    Ok(ResolvedRegistryTarballUrl { url })
}

/// Invalidate metadata cache for a package, routing through the
/// custom-registry-aware path when the package is served from a
/// `.npmrc`-declared registry. added
/// [`RegistryClient::invalidate_custom_metadata_cache`]; this helper
/// is the install-path consumer that the route-table invariant requires
/// was missing.
pub(super) fn invalidate_metadata_routed(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    name: &str,
    version: &str,
) {
    match route_table.route_for_package(name) {
        UpstreamRoute::Custom { target, auth } => {
            client.invalidate_custom_metadata_cache(&target.base_url, name, auth.as_ref());
        }
        _ => {
            client.invalidate_metadata_cache(name);
            client.invalidate_npm_version_metadata_cache(name, version);
        }
    }
}

/// Shared 404-handling: invalidate stale metadata and return the user-facing
/// error message the caller should surface. Authoritative fetches also remove
/// lockfiles so the next `lpm install` re-resolves; best-effort overlap fetches
/// preserve project state.
///
/// `project_dir` is the project root, not necessarily the current process CWD.
pub(super) fn handle_tarball_not_found_with_recovery(
    client: &Arc<RegistryClient>,
    name: &str,
    version: &str,
    project_dir: &Path,
    recovery: TarballNotFoundRecovery,
) -> LpmError {
    client.invalidate_metadata_cache(name);
    client.invalidate_npm_version_metadata_cache(name, version);
    if matches!(recovery, TarballNotFoundRecovery::DeleteProjectLockfiles) {
        let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
        if lock_path.exists() {
            let _ = std::fs::remove_file(&lock_path);
        }
        let lockb_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
        if lockb_path.exists() {
            let _ = std::fs::remove_file(&lockb_path);
        }
    }
    LpmError::NotFound(format!(
        "{name}@{version} tarball not found (possibly unpublished). \
         Cache cleared — run `lpm install` again to re-resolve."
    ))
}

/// Legacy fetch path — download to temp file, reopen, extract. Returns
/// `(computed_sri, TaskTimings)`. Called from the per-task closure under
/// a held download semaphore permit. Kept as the default while the
/// streaming path is validated.
///
/// `project_dir` + `gate_stats` are threaded in
/// for the CWD-safe `handle_tarball_not_found` (which deletes
/// lockfiles relative to the project root, not CWD) and the
/// stale-URL same-run retry telemetry. See the design doc §
/// Change 2 for the full retry semantics.
// See the docs on `fetch_and_store_streaming` for why the permit drop
// happens between download and extract. Same shape applies on the legacy
// spool path.
#[allow(clippy::too_many_arguments)] // design-level: install-fetch orchestration takes the full surface
pub(super) async fn fetch_and_store_legacy(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    store: &PackageStore,
    // — see [`fetch_and_store_streaming`] for the
    // contract. None → v1 (default + every release).
    store_v2: Option<&lpm_store::v2::Store>,
    p: &InstallPackage,
    queue_wait_ms: u128,
    project_dir: &Path,
    not_found_recovery: TarballNotFoundRecovery,
    gate_stats: &Arc<GateStats>,
    permit: tokio::sync::OwnedSemaphorePermit,
    fetch_extract_limiter: &FetchExtractLimiter,
) -> Result<
    (
        String,
        TaskTimings,
        String,
        Option<lpm_store::v2::ExtractedObject>,
    ),
    LpmError,
> {
    use std::sync::atomic::Ordering;

    // — explicit URL resolution + download so we can
    // distinguish a metadata 404 (truly unpublished, no retry) from
    // a download 404 on a stored URL (stale cached URL, try
    // recovery). Return tuple's final `String` is the URL that
    // served bytes (equal to `initial_url` on the happy path, the
    // retry's `fresh_url` on stale-URL recovery). Driver post-
    // aggregates any divergence from `p.tarball_url` into the
    // writeback `fresh_urls` map.
    let url_lookup_start = std::time::Instant::now();
    let initial_resolution = match resolve_tarball_url(
        client,
        route_table,
        &p.name,
        &p.version,
        p.is_lpm,
        p.tarball_url.as_deref(),
        p.metadata_checked_for_tarball,
    )
    .await
    {
        Ok(u) => u,
        Err(LpmError::NotFound(_)) => {
            // Metadata 404 — package/version genuinely gone.
            // Nothing to retry.
            return Err(handle_tarball_not_found_with_recovery(
                client,
                &p.name,
                &p.version,
                project_dir,
                not_found_recovery,
            ));
        }
        Err(e) => return Err(e),
    };
    let mut url_lookup_ms = url_lookup_start.elapsed().as_millis();
    let initial_url = initial_resolution.url.clone();
    let mut final_url = initial_url.clone();

    let download_start = std::time::Instant::now();
    let downloaded = match client
        .download_tarball_routed(route_table, &p.name, &initial_url)
        .await
    {
        Ok(r) => r,
        Err(LpmError::NotFound(_)) if p.tarball_url.is_some() => {
            // Stored URL went stale — package was republished, or
            // upstream migrated paths. Invalidate metadata + retry
            // ONCE with a freshly-resolved URL.
            invalidate_metadata_routed(client, route_table, &p.name, &p.version);
            let retry_lookup_start = std::time::Instant::now();
            let fresh_resolution = match resolve_tarball_url(
                client,
                route_table,
                &p.name,
                &p.version,
                p.is_lpm,
                None,
                false,
            )
            .await
            {
                Ok(u) => u,
                Err(_) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found_with_recovery(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                        not_found_recovery,
                    ));
                }
            };
            url_lookup_ms += retry_lookup_start.elapsed().as_millis();
            let fresh_url = fresh_resolution.url.clone();
            if fresh_url == initial_url {
                // Loop guard — metadata still points at the same
                // stale URL. Tarball is really gone, not just moved.
                gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                return Err(handle_tarball_not_found_with_recovery(
                    client,
                    &p.name,
                    &p.version,
                    project_dir,
                    not_found_recovery,
                ));
            }
            match client
                .download_tarball_routed(route_table, &p.name, &fresh_url)
                .await
            {
                Ok(r) => {
                    gate_stats.stale_recovery.fetch_add(1, Ordering::Relaxed);
                    final_url = fresh_url;
                    r
                }
                Err(LpmError::NotFound(_)) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found_with_recovery(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                        not_found_recovery,
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Err(LpmError::NotFound(_)) => {
            // On-demand path (no stored URL) 404 — really gone.
            return Err(handle_tarball_not_found_with_recovery(
                client,
                &p.name,
                &p.version,
                project_dir,
                not_found_recovery,
            ));
        }
        Err(e) => return Err(e),
    };
    // — `download_ms` measures just the GET + temp-file
    // write. URL-lookup costs (initial + optional retry) are
    // accumulated into `url_lookup_ms` above.
    let download_ms = download_start.elapsed().as_millis();

    // Drop the permit now that bytes are on disk.
    // Integrity verification + extract that follow are CPU+I/O bound
    // and don't need the download throttle; sibling downloads can
    // proceed while this task finishes its post-download work.
    drop(permit);

    let computed_sri = downloaded.sri.clone();

    // Verify integrity before storing. SHA-512 is the common case: computed
    // during download, so match is a string compare. Non-sha512 expected
    // values stream-verify from the temp file in 64 KB chunks.
    let integrity_start = std::time::Instant::now();
    if let Some(ref integrity) = p.integrity {
        if computed_sri != *integrity
            && let Err(e) = lpm_extractor::verify_integrity_file(downloaded.file.path(), integrity)
        {
            return Err(LpmError::Registry(format!(
                "integrity verification failed for {}@{}: {e}",
                p.name, p.version
            )));
        }
    } else {
        tracing::warn!(
            "no integrity hash for {}@{} — skipping verification",
            p.name,
            p.version
        );
    }
    let integrity_ms = integrity_start.elapsed().as_millis();

    let extract_permit_wait_start = std::time::Instant::now();
    let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
    let extract_permit_wait_ms = extract_permit_wait_start.elapsed().as_millis();

    let (stage, fresh_object, result_sri) = if let Some(store_v2) = store_v2 {
        // — v2 path. Read the on-disk tarball into
        // memory and route through `extract_object_from_bytes`. The
        // legacy fetch path's whole point is to spool the download
        // to a temp file (vs the streaming path's in-memory body), so
        // we incur the read-to-bytes cost here rather than refactor
        // the streaming abstraction; the perf delta is bounded by
        // tarball size which already passed the size limit upstream.
        let bytes = std::fs::read(downloaded.file.path()).map_err(|e| {
            LpmError::Registry(format!(
                "v2 store: failed to re-read downloaded tarball at {}: {e}",
                downloaded.file.path().display()
            ))
        })?;
        let (object, sri, timings) = store_v2
            .extract_object_from_bytes_with_fresh_integrity(&bytes, p.integrity.as_deref())?;
        (timings, Some(object), sri)
    } else {
        let (_, stage) = store.store_package_from_file_timed(
            &p.name,
            &p.version,
            downloaded.file.path(),
            &computed_sri,
        )?;
        (stage, None, computed_sri)
    };

    Ok((
        result_sri,
        TaskTimings::from_stage(
            queue_wait_ms,
            url_lookup_ms,
            download_ms,
            integrity_ms,
            extract_permit_wait_ms,
            stage,
        ),
        final_url,
        fresh_object,
    ))
}

/// fetch + store path for
/// `Source::Tarball` packages.
///
/// Distinct from [`fetch_and_store_legacy`] / [`fetch_and_store_streaming`]
/// in three structural ways:
/// 1. **No URL resolution.** The tarball URL is the dep specifier;
///    it's already in `p.tarball_url`. No registry metadata
///    round-trip, no `route_table` lookup, no `resolve_tarball_url`.
/// 2. **No registry-routed download.** Uses
///    [`RegistryClient::download_tarball_with_integrity`] which
///    fetches an arbitrary URL and verifies an optional pre-declared
///    SRI. Trust-on-first-use when `p.integrity` is `None`; hard
///    error on mismatch when `Some`.
/// 3. **Content-addressable store path.** Extraction lands at
///    [`PackageStore::store_tarball_at_cas_path`] (keyed by the
///    computed SRI), NOT the `(name, version)`-keyed
///    [`PackageStore::package_dir`]. identity: the URL +
///    integrity is the source identity, distinct from any registry
///    package that happens to share the same `name@version`.
///
/// Returns `(computed_sri, task_timings, final_url)` matching the
/// other fetch paths' shape so the install loop can aggregate the
/// three uniformly.
pub(super) async fn fetch_and_store_tarball_url(
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    // — see [`fetch_and_store_streaming`] for the
    // contract. None → v1 (default + every release).
    store_v2: Option<&lpm_store::v2::Store>,
    p: &InstallPackage,
    queue_wait_ms: u128,
    permit: tokio::sync::OwnedSemaphorePermit,
    fetch_extract_limiter: &FetchExtractLimiter,
) -> Result<
    (
        String,
        TaskTimings,
        String,
        Option<lpm_store::v2::ExtractedObject>,
    ),
    LpmError,
> {
    // The dispatch site only routes here when source_kind() returned
    // Source::Tarball, so this unwrap is contract-protected. A
    // missing URL at this point is a programmer error in the
    // resolver's InstallPackage construction, not a runtime input
    // bug.
    let url = p.tarball_url.as_deref().ok_or_else(|| {
        LpmError::Registry(format!(
            "install-source internal error: Source::Tarball install package {:?}@{} has no tarball_url",
            p.name, p.version,
        ))
    })?;

    let download_start = std::time::Instant::now();
    let (data, computed_sri) = client
        .download_tarball_with_integrity(url, p.integrity.as_deref())
        .await?;
    let download_ms = download_start.elapsed().as_millis();
    drop(permit);

    // download_tarball_with_integrity already verified the SRI when
    // p.integrity was Some; on trust-on-first-use it returned the
    // computed SRI we need to record. integrity_ms folds into
    // download_ms because the verify is a single string compare.
    let integrity_ms = 0;

    let extract_permit_wait_start = std::time::Instant::now();
    let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
    let extract_permit_wait_ms = extract_permit_wait_start.elapsed().as_millis();

    let (stage, fresh_object, result_sri) = if let Some(store_v2) = store_v2 {
        // — v2 path. The Source::Tarball case
        // already has bytes + SRI in hand; route them straight into
        // `extract_object_from_bytes`. The downloader returns the
        // declaration's algorithm when one was supplied, while v2
        // objects are keyed by the extractor's canonical sha512 SRI.
        let (object, sri, stage) =
            store_v2.extract_object_from_bytes_with_fresh_integrity(&data, Some(&computed_sri))?;
        (stage, Some(object), sri)
    } else {
        let extract_start = std::time::Instant::now();
        let _store_path = store.store_tarball_at_cas_path(&computed_sri, &data)?;
        (
            lpm_store::StageTimings {
                extract_ms: extract_start.elapsed().as_millis(),
                ..Default::default()
            },
            None,
            computed_sri,
        )
    };

    let timings = TaskTimings::from_stage(
        queue_wait_ms,
        0, // No registry metadata round-trip.
        download_ms,
        integrity_ms,
        extract_permit_wait_ms,
        stage,
    );

    Ok((result_sri, timings, url.to_string(), fresh_object))
}

/// streaming fetch path — bytes flow from reqwest directly
/// into the store's extractor via `StreamReader` + `SyncIoBridge`. No
/// temp file spool, no re-read. Hash computed inline as bytes flow.
///
/// Because download + decode + extract + hash happen in one interleaved
/// pipeline, `download_ms` and `integrity_ms` collapse into
/// `extract_ms` — the breakdown stays shape-compatible with the legacy
/// path but pushes mass into one bucket. That's the whole point of:
/// eliminate the temp-file hop that today forces sequential download →
/// reopen → extract.
#[allow(clippy::too_many_arguments)] // design-level: install-fetch orchestration takes the full surface
pub(super) async fn fetch_and_store_streaming(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    store: &PackageStore,
    // — when `Some`, the install pipeline is running
    // under `LPM_STORE_VERSION=v2`. Bytes flow into the v2
    // `objects/<sri>/` path instead of v1's `<name>@<version>/`. None
    // → v1 path (today's default + every release).
    store_v2: Option<&lpm_store::v2::Store>,
    p: &InstallPackage,
    queue_wait_ms: u128,
    project_dir: &Path,
    not_found_recovery: TarballNotFoundRecovery,
    gate_stats: &Arc<GateStats>,
    permit: tokio::sync::OwnedSemaphorePermit,
    fetch_extract_limiter: &FetchExtractLimiter,
) -> Result<
    (
        String,
        TaskTimings,
        String,
        Option<lpm_store::v2::ExtractedObject>,
    ),
    LpmError,
> {
    use std::sync::atomic::Ordering;

    // URL resolution — times this into `url_lookup_ms` and
    // distinguishes metadata 404 (truly unpublished, no retry) from
    // a download 404 on a stored URL (stale cache, try recovery).
    let url_lookup_start = std::time::Instant::now();
    let initial_resolution = match resolve_tarball_url(
        client,
        route_table,
        &p.name,
        &p.version,
        p.is_lpm,
        p.tarball_url.as_deref(),
        p.metadata_checked_for_tarball,
    )
    .await
    {
        Ok(u) => u,
        Err(LpmError::NotFound(_)) => {
            return Err(handle_tarball_not_found_with_recovery(
                client,
                &p.name,
                &p.version,
                project_dir,
                not_found_recovery,
            ));
        }
        Err(e) => return Err(e),
    };
    let mut url_lookup_ms = url_lookup_start.elapsed().as_millis();
    let initial_url = initial_resolution.url.clone();
    let mut final_url = initial_url.clone();

    let response = match client
        .download_tarball_streaming_routed(route_table, &p.name, &initial_url)
        .await
    {
        Ok(r) => r,
        Err(LpmError::NotFound(_)) if p.tarball_url.is_some() => {
            // Stored URL stale — retry ONCE with fresh metadata.
            // See `fetch_and_store_legacy` for the full semantics;
            // this branch mirrors that retry logic byte-for-byte
            // (minus the streaming-specific response handling).
            invalidate_metadata_routed(client, route_table, &p.name, &p.version);
            let retry_lookup_start = std::time::Instant::now();
            let fresh_resolution = match resolve_tarball_url(
                client,
                route_table,
                &p.name,
                &p.version,
                p.is_lpm,
                None,
                false,
            )
            .await
            {
                Ok(u) => u,
                Err(_) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found_with_recovery(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                        not_found_recovery,
                    ));
                }
            };
            url_lookup_ms += retry_lookup_start.elapsed().as_millis();
            let fresh_url = fresh_resolution.url.clone();
            if fresh_url == initial_url {
                gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                return Err(handle_tarball_not_found_with_recovery(
                    client,
                    &p.name,
                    &p.version,
                    project_dir,
                    not_found_recovery,
                ));
            }
            match client
                .download_tarball_streaming_routed(route_table, &p.name, &fresh_url)
                .await
            {
                Ok(r) => {
                    gate_stats.stale_recovery.fetch_add(1, Ordering::Relaxed);
                    final_url = fresh_url;
                    r
                }
                Err(LpmError::NotFound(_)) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found_with_recovery(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                        not_found_recovery,
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Err(LpmError::NotFound(_)) => {
            return Err(handle_tarball_not_found_with_recovery(
                client,
                &p.name,
                &p.version,
                project_dir,
                not_found_recovery,
            ));
        }
        Err(e) => return Err(e),
    };

    // Collect the entire compressed tarball into memory
    // BEFORE releasing the download permit, then release the permit
    // BEFORE the spawn_blocking extract. When the permit covers
    // download + extract end-to-end, long extract tails serialize
    // sibling download permit hand-off. Releasing it here lets the next
    // download start as soon as bytes are on the heap; extract no
    // longer holds a download slot and can be coordinated separately.
    //
    // Bounded memory: `download_tarball_streaming` already enforces
    // `MAX_COMPRESSED_TARBALL_SIZE` (500 MB) via `Content-Length`, and
    // `Bytes::clone` is a refcount bump so the move into spawn_blocking
    // doesn't realloc. Average tarball on fixture-large is ~50-500 KB;
    // 24-permit peak is ~12 MB resident.
    let download_start = std::time::Instant::now();
    let body = response
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("tarball stream failed: {e}")))?;
    let download_ms = download_start.elapsed().as_millis();
    drop(permit); // release for sibling downloads before extract starts.

    let name = p.name.clone();
    let version = p.version.clone();
    let expected_integrity = p.integrity.clone();
    let store_owned = store.clone();
    // — capture the Optional v2 handle into the
    // blocking task. Cloning an `Option<Store>` is cheap (the inner
    // `Store` derives Clone over a single PathBuf), and `None` keeps
    // the existing v1 path byte-for-byte.
    let store_v2_owned = store_v2.cloned();

    let extract_permit_wait_start = std::time::Instant::now();
    let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
    let extract_permit_wait_ms = extract_permit_wait_start.elapsed().as_millis();

    // Everything below runs on the blocking pool — frees the tokio async
    // workers to keep driving network reads. No download permit is held.
    let extract_start = std::time::Instant::now();
    let (computed_sri, stage, fresh_object) = tokio::task::spawn_blocking(
        move || -> Result<
            (
                String,
                lpm_store::StageTimings,
                Option<lpm_store::v2::ExtractedObject>,
            ),
            LpmError,
        > {
            if let Some(store_v2) = store_v2_owned {
                // — v2 path. Bytes flow through
                // `extract_object_from_bytes`: SHA-512 hash → integrity
                // verify → extract into `objects/<sri>/` → security
                // analysis → atomic rename. SizeLimit is enforced
                // upstream by `download_tarball_streaming`'s
                // Content-Length check (same as the v1 streaming path's
                // `SizeLimitedReader`), so the buffered `body` is
                // already bounded.
                let (object, sri, timings) = store_v2
                    .extract_object_from_bytes_with_fresh_integrity(
                        &body,
                        expected_integrity.as_deref(),
                    )?;
                Ok((sri, timings, Some(object)))
            } else {
                let cursor = std::io::Cursor::new(body);
                store_owned
                    .stream_and_store_package(
                        &name,
                        &version,
                        cursor,
                        expected_integrity.as_deref(),
                        lpm_registry::MAX_COMPRESSED_TARBALL_SIZE,
                    )
                    .map(|(_path, sri, timings)| (sri, timings, None))
            }
        },
    )
    .await
    .map_err(|e| LpmError::Registry(format!("streaming extract task panicked: {e}")))??;
    let pipeline_ms = extract_start.elapsed().as_millis();

    // `pipeline_ms` is the spawn_blocking wall-clock; we prefer the
    // store's inner `stage.extract_ms` for the breakdown because it
    // excludes join overhead.
    let _ = pipeline_ms;

    Ok((
        computed_sri,
        TaskTimings::from_stage(
            queue_wait_ms,
            url_lookup_ms,
            download_ms,
            0,
            extract_permit_wait_ms,
            stage,
        ),
        final_url,
        fresh_object,
    ))
}
