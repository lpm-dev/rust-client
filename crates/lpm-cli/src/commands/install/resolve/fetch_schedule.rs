use super::super::*;
use super::ExperimentalResolverStats;
use super::PackageIdentity;
use super::graph::{PackageDraft, package_should_materialize};

pub(super) type FetchHandle = tokio::task::JoinHandle<Result<FetchOutcome, LpmError>>;

#[derive(Debug)]
pub(super) struct FetchOutcome {
    pub(super) key: String,
    pub(super) package_display: String,
    pub(super) computed_sri: Option<String>,
    pub(super) timings: Option<TaskTimings>,
    pub(super) cached: bool,
}

pub(super) fn lockfile_fetch_schedule(packages: &[InstallPackage]) -> Vec<InstallPackage> {
    let mut scheduled = packages.to_vec();
    prioritize_fetch_schedule(&mut scheduled);
    scheduled
}

pub(in crate::commands::install) fn prioritize_fetch_schedule(packages: &mut [InstallPackage]) {
    packages.sort_by(fetch_schedule_order);
}

fn fetch_schedule_order(a: &InstallPackage, b: &InstallPackage) -> std::cmp::Ordering {
    b.is_direct
        .cmp(&a.is_direct)
        .then_with(|| b.dependencies.len().cmp(&a.dependencies.len()))
        .then_with(|| b.peers.len().cmp(&a.peers.len()))
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.version.cmp(&b.version))
        .then_with(|| a.source.cmp(&b.source))
}

fn streaming_candidate_order(a: &InstallPackage, b: &InstallPackage) -> std::cmp::Ordering {
    b.unpacked_size
        .cmp(&a.unpacked_size)
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.version.cmp(&b.version))
        .then_with(|| a.source.cmp(&b.source))
}

pub(in crate::commands::install) async fn reserve_v2_streaming_candidate(
    packages: &[InstallPackage],
    coordinator: &FetchCoordinator,
) -> Option<(String, tokio::sync::OwnedMutexGuard<()>)> {
    let mut locks = coordinator.locks.lock().await;
    let mut selected: Option<(&InstallPackage, String, tokio::sync::OwnedMutexGuard<()>)> = None;
    for package in packages {
        if package.unpacked_size.is_none()
            || package.integrity.is_none()
            || !matches!(
                package.source_kind(),
                Ok(lpm_lockfile::Source::Registry { .. })
            )
            || selected
                .as_ref()
                .is_some_and(|(current, _, _)| !streaming_candidate_order(package, current).is_lt())
        {
            continue;
        }
        let key = install_pkg_key(package);
        let lock = locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())));
        // Keep ownership until the authoritative task starts so speculation
        // cannot consume the selected package and strand the streaming lane.
        if let Ok(guard) = Arc::clone(lock).try_lock_owned() {
            selected = Some((package, key, guard));
        }
    }
    selected.map(|(_, key, guard)| (key, guard))
}

pub(in crate::commands::install) fn promote_fetch_candidate(
    packages: &mut [InstallPackage],
    candidate_key: &str,
) {
    let Some(index) = packages
        .iter()
        .position(|package| install_pkg_key(package) == candidate_key)
    else {
        return;
    };
    packages[..=index].rotate_right(1);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_missing_fetches_for_drafts(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    fetch_queue: &Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    install_accounting: ManagedInstallAccounting,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut ExperimentalResolverStats,
) -> Result<(), LpmError> {
    for draft in packages.values() {
        let package = &draft.package;
        if fetch_handles.contains_key(&install_pkg_key(package)) {
            continue;
        }
        if package_should_materialize(package)? {
            maybe_spawn_fetch(
                package.clone(),
                store,
                store_v2_handle.clone(),
                project_dir,
                Arc::clone(client),
                route_table.clone(),
                Arc::clone(fetch_queue),
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                install_accounting,
                ArtifactSelection::FreshResolution,
                fetch_handles,
                stats,
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_fetches_for_packages(
    packages: &[InstallPackage],
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    fetch_queue: &Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    install_accounting: ManagedInstallAccounting,
    artifact_selection: ArtifactSelection,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut ExperimentalResolverStats,
) -> Result<(), LpmError> {
    for package in packages {
        if package_should_materialize(package)? {
            maybe_spawn_fetch(
                package.clone(),
                store,
                store_v2_handle.clone(),
                project_dir,
                Arc::clone(client),
                route_table.clone(),
                Arc::clone(fetch_queue),
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                install_accounting,
                artifact_selection,
                fetch_handles,
                stats,
            );
        } else {
            stats.platform_pre_skipped += 1;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn maybe_spawn_fetch(
    package: InstallPackage,
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    fetch_queue: Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    install_accounting: ManagedInstallAccounting,
    artifact_selection: ArtifactSelection,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut ExperimentalResolverStats,
) {
    let key = install_pkg_key(&package);
    if fetch_handles.contains_key(&key) {
        return;
    }
    let insert_key = key.clone();
    let package_display = format!("{}@{}", package.name, package.version);
    stats.fetch_dispatched += 1;
    let store = store.clone();
    let project_dir = project_dir.to_path_buf();
    let handle = tokio::spawn(async move {
        if is_local_source_package(&package) {
            if package.store_has_source_aware(&store, &project_dir) {
                return Ok(FetchOutcome {
                    key,
                    package_display,
                    computed_sri: package.integrity.clone(),
                    timings: None,
                    cached: true,
                });
            }
            package.store_path_or_err(&store, &project_dir, None)?;
            return Err(LpmError::Registry(format!(
                "local source package {}@{} is missing package.json",
                package.name, package.version
            )));
        }

        if !force
            && package.store_has_for_install_layout(
                &store,
                store_v2_handle.as_deref(),
                &project_dir,
            )
        {
            return Ok(FetchOutcome {
                key,
                package_display,
                computed_sri: package.integrity.clone(),
                timings: None,
                cached: true,
            });
        }

        let queue_start = Instant::now();
        let permit = fetch_queue
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| LpmError::Registry("experimental resolver queue closed".into()))?;
        let queue_wait_ms = queue_start.elapsed().as_millis();
        let (computed_sri, timings, _, _) = fetch_and_store_streaming(
            &client,
            &route_table,
            &store,
            store_v2_handle.as_deref(),
            &package,
            queue_wait_ms,
            artifact_selection,
            &gate_stats,
            permit,
            &fetch_extract_limiter,
            install_accounting,
            V2StreamingEligibility::Disabled,
            None,
        )
        .await?;
        Ok(FetchOutcome {
            key,
            package_display,
            computed_sri: Some(computed_sri),
            timings: Some(timings),
            cached: false,
        })
    });
    fetch_handles.insert(insert_key, handle);
}

fn is_local_source_package(package: &InstallPackage) -> bool {
    matches!(
        package.source_kind(),
        Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, unpacked_size: Option<u64>) -> InstallPackage {
        InstallPackage {
            instance_id: None,
            name: name.to_string(),
            version: "1.0.0".to_string(),
            source: "registry+https://registry.npmjs.org".to_string(),
            dependencies: Vec::new(),
            dependency_targets: HashMap::new(),
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct: false,
            is_lpm: false,
            peers: Vec::new(),
            peer_targets: HashMap::new(),
            integrity: Some("sha512-test".to_string()),
            unpacked_size: unpacked_size.and_then(std::num::NonZeroU64::new),
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine: None,
            optional: false,
            tarball_url: Some(format!(
                "https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"
            )),
            metadata_checked_for_tarball: true,
            manifest_fingerprint: None,
        }
    }

    #[tokio::test]
    async fn streaming_candidate_is_largest_known_registry_package_in_any_input_order() {
        let next = package("next", Some(184_624_992));
        let react_dom = package("react-dom", Some(7_319_407));
        let server_only = package("server-only", Some(611));
        let unknown = package("unknown", None);
        let expected = install_pkg_key(&next);

        let permutations = [
            vec![
                next.clone(),
                react_dom.clone(),
                server_only.clone(),
                unknown.clone(),
            ],
            vec![
                unknown.clone(),
                server_only.clone(),
                next.clone(),
                react_dom.clone(),
            ],
            vec![react_dom, next, unknown, server_only],
        ];
        for packages in permutations {
            let selected = reserve_v2_streaming_candidate(&packages, &FetchCoordinator::default())
                .await
                .map(|(key, _)| key);
            assert_eq!(selected.as_deref(), Some(expected.as_str()));
            assert_eq!(
                packages
                    .iter()
                    .filter(|package| selected.as_deref() == Some(install_pkg_key(package).as_str()))
                    .count(),
                1
            );
        }
    }

    #[tokio::test]
    async fn streaming_candidate_ties_are_resolved_by_stable_package_identity() {
        let alpha = package("alpha", Some(1024));
        let zeta = package("zeta", Some(1024));
        assert_eq!(
            reserve_v2_streaming_candidate(&[zeta, alpha.clone()], &FetchCoordinator::default())
                .await
                .map(|(key, _)| key)
                .as_deref(),
            Some(install_pkg_key(&alpha).as_str())
        );
    }

    #[tokio::test]
    async fn streaming_candidate_skips_packages_already_being_fetched() {
        let largest = package("largest", Some(4096));
        let available = package("available", Some(2048));
        let coordinator = FetchCoordinator::default();
        let lock = coordinator.lock_for(install_pkg_key(&largest)).await;
        let _in_flight = lock.lock_owned().await;

        let selected = reserve_v2_streaming_candidate(&[largest, available.clone()], &coordinator)
            .await
            .map(|(key, _)| key);

        assert_eq!(
            selected.as_deref(),
            Some(install_pkg_key(&available).as_str())
        );
    }

    #[tokio::test]
    async fn streaming_candidate_reservation_retains_only_the_selected_package_lock() {
        let smaller = package("smaller", Some(1024));
        let largest = package("largest", Some(4096));
        let coordinator = FetchCoordinator::default();
        let (_, reservation) =
            reserve_v2_streaming_candidate(&[smaller.clone(), largest.clone()], &coordinator)
                .await
                .unwrap();
        let selected_lock = coordinator.lock_for(install_pkg_key(&largest)).await;
        let other_lock = coordinator.lock_for(install_pkg_key(&smaller)).await;

        assert!(selected_lock.try_lock().is_err());
        assert!(other_lock.try_lock().is_ok());
        drop(reservation);
        assert!(selected_lock.try_lock().is_ok());
    }

    #[tokio::test]
    async fn streaming_candidate_returns_none_without_waiting_when_all_keys_are_busy() {
        let package = package("busy", Some(4096));
        let coordinator = FetchCoordinator::default();
        let lock = coordinator.lock_for(install_pkg_key(&package)).await;
        let _in_flight = lock.lock_owned().await;

        let selected = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reserve_v2_streaming_candidate(&[package], &coordinator),
        )
        .await
        .expect("candidate selection must not wait for an occupied package");

        assert!(selected.is_none());
    }

    #[tokio::test]
    async fn streaming_candidate_excludes_unknown_unverified_and_non_registry_artifacts() {
        let unknown = package("unknown", None);
        let mut unverified = package("unverified", Some(4096));
        unverified.integrity = None;
        let mut tarball = package("tarball", Some(8192));
        tarball.source = "tarball+https://example.invalid/tarball.tgz".to_string();

        assert!(
            reserve_v2_streaming_candidate(
                &[unknown, unverified, tarball],
                &FetchCoordinator::default()
            )
            .await
            .is_none()
        );
    }

    #[test]
    fn background_fetch_schedule_is_independent_of_registry_size_hints() {
        let mut direct_small = package("direct-small", Some(1024));
        direct_small.is_direct = true;
        let large = package("large", Some(1_000_000));
        let unknown = package("unknown", None);
        let mut packages = vec![unknown, direct_small, large];

        prioritize_fetch_schedule(&mut packages);

        assert_eq!(packages[0].name, "direct-small");
        assert_eq!(packages[1].name, "large");
        assert_eq!(packages[2].name, "unknown");
    }

    #[tokio::test]
    async fn streaming_candidate_moves_first_without_reordering_background_fetches() {
        let mut direct = package("direct", Some(1024));
        direct.is_direct = true;
        let small = package("small", Some(2048));
        let candidate = package("candidate", Some(1_000_000));
        let unknown = package("unknown", None);
        let mut packages = vec![unknown, candidate.clone(), small, direct];

        prioritize_fetch_schedule(&mut packages);
        let background_order = packages
            .iter()
            .filter(|package| package.name != candidate.name)
            .map(|package| package.name.clone())
            .collect::<Vec<_>>();
        let (candidate_key, _guard) =
            reserve_v2_streaming_candidate(&packages, &FetchCoordinator::default())
                .await
                .unwrap();
        promote_fetch_candidate(&mut packages, &candidate_key);

        assert_eq!(packages[0].name, candidate.name);
        assert_eq!(
            packages[1..]
                .iter()
                .map(|package| package.name.clone())
                .collect::<Vec<_>>(),
            background_order
        );
    }
}
