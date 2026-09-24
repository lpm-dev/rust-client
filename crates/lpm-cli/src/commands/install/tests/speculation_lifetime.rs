use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn cancelled_v1_speculation_retains_capacity_until_cooperative_body_cleanup() {
    let body = build_test_tarball();
    let integrity = lpm_common::integrity::Integrity::from_bytes(
        lpm_common::integrity::HashAlgorithm::Sha512,
        &body,
    )
    .to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let resume = Arc::new(tokio::sync::Notify::new());
    let server_resume = Arc::clone(&resume);
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
        }
        socket
            .get_mut()
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let split = body.len() / 2;
        socket.get_mut().write_all(&body[..split]).await.unwrap();
        server_resume.notified().await;
        let _ = socket.get_mut().write_all(&body[split..]).await;
    });
    let root = tempfile::tempdir().unwrap();
    let store = PackageStore::at(root.path());
    let inspect_store = store.clone();
    let downloads = Arc::new(Semaphore::new(1));
    let extraction = Arc::new(Semaphore::new(1));
    let limiter = Some(fetch_extract_limiter_with_semaphore(
        Arc::clone(&extraction),
        1,
    ));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let coordinator = Arc::new(FetchCoordinator {
        v1_stream_gate: Some(Arc::new(super::super::test_support::BlockingExtractGate {
            started: Mutex::new(Some(started_tx)),
            resume: Mutex::new(resume_rx),
            finished: Mutex::new(Some(finished_tx)),
        })),
        ..Default::default()
    });
    let client = Arc::new(RegistryClient::new().with_npm_registry_url(format!("http://{address}")));
    let route = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let key = registry_install_pkg_key("test-tarball-pkg", "1.0.0", &route, &client);
    let key_lock = coordinator.lock_for(key).await;
    let download_slots = Arc::clone(&downloads);
    let task = tokio::spawn(async move {
        speculative_download_and_store(
            &client,
            &route,
            &store,
            None,
            &download_slots,
            None,
            &coordinator,
            "test-tarball-pkg",
            "1.0.0",
            &format!("http://{address}/package.tgz"),
            Some(&integrity),
            None,
            None,
            &limiter,
            ManagedInstallAccounting,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let retained_download = downloads.available_permits() == 0;
    let retained_extraction = extraction.available_permits() == 0;
    let retained_key = key_lock.try_lock().is_err();
    resume_tx.send(()).unwrap();
    let cleanup = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let _key = key_lock.lock().await;
        let _extraction = extraction.acquire().await.unwrap();
        let _download = downloads.acquire().await.unwrap();
    })
    .await;
    let cleaned_without_server_eof = cleanup.is_ok();
    resume.notify_one();
    server.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), finished_rx)
        .await
        .unwrap()
        .unwrap();
    let _key = key_lock.lock().await;
    let _extraction = extraction.acquire().await.unwrap();
    let _download = downloads.acquire().await.unwrap();
    assert!(
        retained_download,
        "download capacity escaped the gated live-body worker"
    );
    assert!(retained_extraction && retained_key);
    assert!(
        cleaned_without_server_eof,
        "cancelled reader waited for the server to finish"
    );
    assert!(!inspect_store.has_package("test-tarball-pkg", "1.0.0"));
}

#[tokio::test]
async fn dropping_speculation_dispatcher_cancels_its_active_downloads() {
    dispatcher_body_lifetime(false, false).await;
}

#[tokio::test]
async fn aborting_speculation_dispatcher_cancels_its_active_downloads() {
    dispatcher_body_lifetime(true, false).await;
}

#[tokio::test]
async fn closing_metadata_normally_waits_for_speculative_body_and_publishes_verified_object() {
    dispatcher_body_lifetime(false, true).await;
}

async fn dispatcher_body_lifetime(abort: bool, complete: bool) {
    let body = build_test_tarball();
    let integrity = lpm_common::integrity::Integrity::from_bytes(
        lpm_common::integrity::HashAlgorithm::Sha512,
        &body,
    )
    .to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let body_started = Arc::clone(&started);
    let server_resume = Arc::clone(&resume);
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
        }
        socket
            .get_mut()
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let split = body.len() / 2;
        socket.get_mut().write_all(&body[..split]).await.unwrap();
        body_started.notify_one();
        server_resume.notified().await;
        let _ = socket.get_mut().write_all(&body[split..]).await;
    });

    let root = tempfile::tempdir().unwrap();
    let store_v2 = Arc::new(lpm_store::v2::Store::at(root.path().join("objects")));
    let inspect_store = Arc::clone(&store_v2);
    let downloads = Arc::new(Semaphore::new(1));
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let (dispatcher, counters) = spawn_speculation_dispatcher(
        rx,
        Arc::new(RegistryClient::new().with_npm_registry_url(format!("http://{address}"))),
        RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        PackageStore::at(root.path()),
        Arc::clone(&downloads),
        None,
        Arc::new(FetchCoordinator::default()),
        HashMap::from([("test-tarball-pkg".to_owned(), "1.0.0".to_owned())]),
        Arc::new(crate::engine_check::prepare_dependency_policy(root.path(), true, true).unwrap()),
        None,
        SpeculativeKeyTracker::default(),
        Some(store_v2),
        None,
        ManagedInstallAccounting,
    );
    tx.send((
        "test-tarball-pkg".to_owned(),
        SpeculativePackageMetadata::from(registry_metadata(
            serde_json::json!({"name":"test-tarball-pkg","versions":{"1.0.0":{
                "name":"test-tarball-pkg","version":"1.0.0",
                "dist":{"tarball":format!("http://{address}/package.tgz"),"integrity":integrity}
            }}}),
        )),
    ))
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
        .await
        .expect("the actual speculative HTTP route must start");
    assert_eq!(downloads.available_permits(), 0);
    if complete {
        drop(tx);
        let mut dispatcher = Box::pin(dispatcher);
        assert!(futures::poll!(dispatcher.as_mut()).is_pending());
        assert!(
            inspect_store
                .reusable_object_dir(&integrity)
                .unwrap()
                .is_none()
        );
        resume.notify_one();
        server.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), dispatcher)
            .await
            .unwrap()
            .unwrap();
        assert!(
            inspect_store
                .reusable_object_dir(&integrity)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            counters
                .completed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            counters.failed.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(downloads.available_permits(), 1);
        return;
    }
    if abort {
        dispatcher.abort();
        assert!(dispatcher.await.unwrap_err().is_cancelled());
    } else {
        drop(dispatcher);
    }
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        Arc::clone(&downloads).acquire_owned(),
    )
    .await;
    let stopped_before_body_completion = cancelled.is_ok();
    drop(cancelled);
    let published_after_cancellation = inspect_store
        .reusable_object_dir(&integrity)
        .unwrap()
        .is_some();

    // Release the server before assertions so an unfixed client cannot strand teardown.
    drop(tx);
    resume.notify_one();
    server.await.unwrap();
    let _released = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        Arc::clone(&downloads).acquire_owned(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        stopped_before_body_completion,
        "owner cancellation must stop active download work"
    );
    assert!(!published_after_cancellation);
}

fn speculation_join_for_test(
    producer: Option<
        tokio::task::JoinHandle<Result<lpm_resolver::WalkerSummary, lpm_resolver::WalkerError>>,
    >,
    dispatcher: tokio::task::JoinHandle<()>,
) -> SpeculationJoin {
    SpeculationJoin {
        producer: producer.map(tokio_util::task::AbortOnDropHandle::new),
        dispatcher: tokio_util::task::AbortOnDropHandle::new(dispatcher),
        dispatched: Default::default(),
        completed: Default::default(),
        task_ms_sum: Default::default(),
        transitive_dispatched: Default::default(),
        max_depth_reached: Default::default(),
        no_version_match: Default::default(),
        unresolved_parked: Default::default(),
        failed: Default::default(),
        skipped_no_permit: Default::default(),
        skipped_auth: Default::default(),
    }
}

#[tokio::test]
async fn cancelling_speculation_drain_aborts_the_pending_producer_and_dispatcher() {
    cancelling_speculation_drain(true).await;
}

#[tokio::test]
async fn cancelling_speculation_drain_aborts_the_pending_dispatcher_without_a_producer() {
    cancelling_speculation_drain(false).await;
}

async fn cancelling_speculation_drain(with_producer: bool) {
    let producer_cancelled = tokio_util::sync::CancellationToken::new();
    let dispatcher_cancelled = tokio_util::sync::CancellationToken::new();
    let producer_guard = producer_cancelled.clone().drop_guard();
    let dispatcher_guard = dispatcher_cancelled.clone().drop_guard();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let producer = with_producer.then(|| {
        tokio::spawn(async move {
            let _guard = producer_guard;
            futures::future::pending().await
        })
    });
    let dispatcher = tokio::spawn(async move {
        let _guard = dispatcher_guard;
        let _ = started_tx.send(());
        futures::future::pending::<()>().await;
    });
    let producer_abort = producer.as_ref().map(|handle| handle.abort_handle());
    let dispatcher_abort = dispatcher.abort_handle();
    started_rx.await.unwrap();
    let join = speculation_join_for_test(producer, dispatcher);
    let mut stats = SpeculativeStats::default();
    let mut drain = Box::pin(join.drain(&mut stats));
    assert!(futures::poll!(drain.as_mut()).is_pending());
    drop(drain);
    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        if with_producer {
            producer_cancelled.cancelled().await;
        }
        dispatcher_cancelled.cancelled().await;
    })
    .await
    .is_ok();
    if let Some(producer) = producer_abort {
        producer.abort();
    }
    dispatcher_abort.abort();
    assert!(
        cancelled,
        "cancelling drain must not detach either pending task"
    );
}

fn task_probe_dispatcher(
    root: &Path,
    coordinator: Arc<FetchCoordinator>,
    dependencies: HashMap<String, String>,
) -> (
    tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>,
    tokio_util::task::AbortOnDropHandle<()>,
    super::super::fetch::DispatcherCounters,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let (dispatcher, counters) = spawn_speculation_dispatcher(
        rx,
        Arc::new(RegistryClient::new()),
        RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        PackageStore::at(root),
        Arc::new(Semaphore::new(1)),
        Some(Arc::new(Semaphore::new(0))),
        coordinator,
        dependencies,
        Arc::new(crate::engine_check::prepare_dependency_policy(root, true, true).unwrap()),
        None,
        SpeculativeKeyTracker::default(),
        None,
        None,
        ManagedInstallAccounting,
    );
    (tx, dispatcher, counters)
}

fn task_probe_metadata(
    name: &str,
    dependencies: serde_json::Value,
) -> (String, SpeculativePackageMetadata) {
    (
        name.to_owned(),
        SpeculativePackageMetadata::from(registry_metadata(serde_json::json!({
            "name": name, "versions":{"1.0.0":{
                "name": name, "version":"1.0.0", "dependencies":dependencies,
                "dist":{"tarball":"http://127.0.0.1:1/package.tgz"}
            }}
        }))),
    )
}

#[tokio::test]
async fn speculation_reaps_completed_tasks_while_metadata_sender_remains_open() {
    let root = tempfile::tempdir().unwrap();
    let (probe_tx, mut probe_rx) = tokio::sync::watch::channel(Default::default());
    let coordinator = Arc::new(FetchCoordinator {
        speculation_task_probe: Some(probe_tx),
        ..Default::default()
    });
    let (tx, dispatcher, counters) = task_probe_dispatcher(
        root.path(),
        coordinator,
        HashMap::from([("root".to_owned(), "1.0.0".to_owned())]),
    );
    tx.send(task_probe_metadata("root", serde_json::json!({})))
        .await
        .unwrap();
    let reaped = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        probe_rx.wait_for(|snapshot| snapshot.spawned == 1 && snapshot.retained == 0),
    )
    .await
    .is_ok();
    let skipped = counters
        .skipped_no_permit
        .load(std::sync::atomic::Ordering::Relaxed);
    drop(tx);
    dispatcher.await.unwrap();
    assert_eq!(skipped, 1);
    assert!(
        reaped,
        "completed tasks must be reaped before metadata channel closure"
    );
}

#[tokio::test]
async fn speculation_bounds_package_lock_waiters_without_blocking_metadata_or_child_discovery() {
    let root = tempfile::tempdir().unwrap();
    let (probe_tx, mut probe_rx) = tokio::sync::watch::channel(Default::default());
    let coordinator = Arc::new(FetchCoordinator {
        speculation_task_probe: Some(probe_tx),
        ..Default::default()
    });
    let client = RegistryClient::new();
    let route = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let mut locks = Vec::with_capacity(140);
    let mut dependencies = HashMap::with_capacity(141);
    for index in 0..140 {
        let name = format!("root-{index}");
        let key = registry_install_pkg_key(&name, "1.0.0", &route, &client);
        locks.push(coordinator.lock_for(key).await.lock_owned().await);
        dependencies.insert(name, "1.0.0".to_owned());
    }
    dependencies.insert("sentinel".to_owned(), "2.0.0".to_owned());
    let (tx, dispatcher, counters) = task_probe_dispatcher(root.path(), coordinator, dependencies);
    tx.send(task_probe_metadata("child", serde_json::json!({})))
        .await
        .unwrap();
    for index in 0..140 {
        let children = if index == 139 {
            serde_json::json!({"child":"1.0.0"})
        } else {
            serde_json::json!({})
        };
        tx.send(task_probe_metadata(&format!("root-{index}"), children))
            .await
            .unwrap();
    }
    tx.send(task_probe_metadata("sentinel", serde_json::json!({})))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while counters
            .no_version_match
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("metadata consumption must continue while package locks are held");
    let peak = probe_rx.borrow_and_update().peak;
    let dispatched = counters
        .dispatched
        .load(std::sync::atomic::Ordering::Relaxed);
    let transitive = counters
        .transitive_dispatched
        .load(std::sync::atomic::Ordering::Relaxed);
    dispatcher.abort();
    let _ = dispatcher.await;
    drop((tx, locks));
    assert_eq!(dispatched, 141);
    assert_eq!(transitive, 1, "overflow must not suppress child discovery");
    assert!(
        peak <= super::super::fetch::MAX_RETAINED_SPECULATIVE_TASKS,
        "retained {peak} tasks behind package locks"
    );
}

#[tokio::test]
async fn cancelling_fused_resolution_aborts_speculation_before_tail_handoff() {
    assert_online_phase_cancellation(false).await;
}

#[tokio::test]
async fn cancelling_legacy_resolution_aborts_speculation_before_tail_handoff() {
    assert_online_phase_cancellation(true).await;
}

async fn assert_online_phase_cancellation(pubgrub_opt_out: bool) {
    let _env = crate::test_env::ScopedEnv::set([("LPM_GREEDY_FUSION", "1".into())]);
    let body = build_test_tarball();
    let integrity = lpm_common::integrity::Integrity::from_bytes(
        lpm_common::integrity::HashAlgorithm::Sha512,
        &body,
    )
    .to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body_started = Arc::new(tokio::sync::Notify::new());
    let started = Arc::clone(&body_started);
    let resume = tokio_util::sync::CancellationToken::new();
    let server_resume = resume.clone();
    let root_metadata = serde_json::to_vec(&serde_json::json!({
        "name":"test-tarball-pkg","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{
            "name":"test-tarball-pkg","version":"1.0.0","dependencies":{"child":"^1.0.0"},
            "dist":{"tarball":format!("http://{address}/package.tgz"),"integrity":integrity}
        }}
    }))
    .unwrap();
    let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut handlers = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let root_metadata = root_metadata.clone();
            let body = body.clone();
            let resume = server_resume.clone();
            let started = Arc::clone(&body_started);
            handlers.spawn(async move {
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                socket.read_line(&mut line).await.unwrap();
                let path = line.split_whitespace().nth(1).unwrap().to_owned();
                loop {
                    line.clear();
                    if socket.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" { break; }
                }
                if path.starts_with("/child") {
                    resume.cancelled().await;
                    return;
                }
                let tarball = path == "/package.tgz";
                let bytes = if tarball { body } else { root_metadata };
                let _ = socket.get_mut().write_all(format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).as_bytes()).await;
                if tarball {
                    let split = bytes.len() / 2;
                    let _ = socket.get_mut().write_all(&bytes[..split]).await;
                    started.notify_one();
                    resume.cancelled().await;
                    let _ = socket.get_mut().write_all(&bytes[split..]).await;
                } else {
                    let _ = socket.get_mut().write_all(&bytes).await;
                }
            });
        }
    }));
    let root = tempfile::tempdir().unwrap();
    let client = Arc::new(RegistryClient::new().with_npm_registry_url(format!("http://{address}")));
    let route = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let coordinator = Arc::new(FetchCoordinator::default());
    let downloads = Arc::new(Semaphore::new(1));
    let key = registry_install_pkg_key("test-tarball-pkg", "1.0.0", &route, &client);
    let key_lock = coordinator.lock_for(key).await;
    let mut dependencies = HashMap::from([("test-tarball-pkg".to_owned(), "^1.0.0".to_owned())]);
    let package = lpm_workspace::PackageJson {
        dependencies: dependencies.clone(),
        ..Default::default()
    };
    let pre_resolve = V2WorkspaceRootPreResolveResult::default();
    let mut workspace_dependencies = Vec::new();
    let no_names = HashSet::new();
    let policy =
        Arc::new(crate::engine_check::prepare_dependency_policy(root.path(), true, true).unwrap());
    let mut phase = Box::pin(run_online_resolution_phase(OnlineResolutionPhaseInput {
        start: Instant::now(),
        lockfile_result: None,
        arc_client: client,
        install_accounting: ManagedInstallAccounting,
        route_table: route,
        project_dir: root.path(),
        deps: &mut dependencies,
        pkg: &package,
        requested_add_count: None,
        json_output: true,
        requested_v2_mode: true,
        v2_workspace_root_pre_resolve: &pre_resolve,
        workspace_member_deps: &mut workspace_dependencies,
        all_workspace_members: &[],
        store: PackageStore::at(root.path()),
        store_v2_handle: Some(Arc::new(lpm_store::v2::Store::at(
            root.path().join("objects"),
        ))),
        fetch_semaphore: Arc::clone(&downloads),
        fetch_extract_limiter: None,
        v2_streaming_lane: Arc::new(V2StreamingLane::default()),
        fetch_coord: coordinator,
        gate_stats: Arc::new(GateStats::default()),
        npm_firewall_mode: Default::default(),
        npm_firewall_lookup_mode: Default::default(),
        npm_firewall_policy_profile: Default::default(),
        npm_firewall_chunk_size: 64,
        policy_extension_configs: &[],
        force: true,
        offline: false,
        omit_policy: Default::default(),
        root_optional_dependency_names: &no_names,
        production_dependency_names: &no_names,
        pubgrub_opt_out,
        auto_install_peers: false,
        resolver_policy: Default::default(),
        resolver_min_age_secs: 0,
        override_set: OverrideSet::empty(),
        strict_peer_dependencies: false,
        peer_conflict_auto_isolation_allowed: false,
        configured_linker_mode: Default::default(),
        auto_isolated_peer_conflicts: false,
        linker_mode: Default::default(),
        strict_integrity: false,
        streaming_fetch: false,
        dependency_engine_policy: policy,
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            _ = started.notified() => {},
            result = phase.as_mut() => panic!("resolution returned before speculative body: {:?}", result.err()),
        }
    }).await.expect("the phase must dispatch a root tarball before its child resolves");
    assert_eq!(downloads.available_permits(), 0);
    drop(phase);
    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let _download = downloads.acquire().await.unwrap();
        let _key = key_lock.lock().await;
    })
    .await
    .is_ok();
    resume.cancel();
    drop(server);
    assert!(
        cancelled,
        "phase cancellation before tail handoff must stop speculative work"
    );
}
