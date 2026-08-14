use super::*;

fn route(host: &str, upstream_port: u16) -> Route {
    Route {
        host: host.to_string(),
        upstream_port,
        project_dir: PathBuf::from("/tmp/app"),
        service: Some("web".to_string()),
    }
}

#[cfg(unix)]
fn route_for_project(host: &str, upstream_port: u16, project_dir: &Path) -> Route {
    Route {
        host: host.to_string(),
        upstream_port,
        project_dir: project_dir.to_path_buf(),
        service: Some("web".to_string()),
    }
}

#[cfg(all(unix, debug_assertions))]
fn cert_env_lock() -> &'static tokio::sync::Mutex<()> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(all(unix, debug_assertions))]
fn initialize_cert_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    // SAFETY: cert tests serialize this helper with `cert_env_lock`, so
    // process-wide environment mutation cannot race another cert test here.
    unsafe {
        std::env::set_var("HOME", home.path());
        std::env::set_var(
            "LPM_CERT_TEST_TRUST_STORE_DIR",
            home.path().join("trust-store"),
        );
        std::env::set_var("LPM_CERT_AUDIT_DIR", home.path().join("audit"));
        std::env::set_var(
            "LPM_CERT_PROJECTS_INDEX",
            home.path().join("cert-projects.json"),
        );
        std::env::set_var("LPM_CERT_GRACE_FILE", home.path().join("cert-grace.json"));
    }
    home
}

#[cfg(all(unix, debug_assertions))]
pub(crate) fn setup_cert_home() -> (tempfile::TempDir, tokio::sync::MutexGuard<'static, ()>) {
    let guard = cert_env_lock().blocking_lock();
    (initialize_cert_home(), guard)
}

#[cfg(all(unix, debug_assertions))]
pub(crate) async fn setup_cert_home_async()
-> (tempfile::TempDir, tokio::sync::MutexGuard<'static, ()>) {
    let guard = cert_env_lock().lock().await;
    (initialize_cert_home(), guard)
}

fn status(host: &str, upstream_port: u16, lease_id: u64) -> RouteStatus {
    RouteStatus {
        host: host.to_string(),
        upstream_port,
        project_dir: PathBuf::from("/tmp/app"),
        service: Some("web".to_string()),
        lease_id: RouteLeaseId(lease_id),
        owner_pid: 123,
    }
}

#[cfg(unix)]
fn forwarder_state(pid: u32, tls_addr: Option<String>) -> ProxyDaemonState {
    ProxyDaemonState {
        pid,
        endpoint: Some("/tmp/lpm-proxy.sock".to_string()),
        http_addr: None,
        http_redirect_addr: None,
        tls_addr,
        routes: Vec::new(),
    }
}

#[test]
fn bind_error_adds_low_port_permission_hint() {
    let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let message = format_loopback_bind_error("TLS proxy", 443, &err);

    assert!(message.contains("bind TLS proxy on 127.0.0.1:443"));
    assert!(message.contains("requires privileged bind rights"));
    assert!(message.contains("proxy install --privileged-ports"));
    assert!(message.contains("set `proxy.port` to a high port"));
    assert!(!message.contains("not wired yet"));
    assert!(!message.contains("sudo"));
}

#[test]
fn bind_error_omits_privileged_hint_for_high_ports() {
    let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let message = format_loopback_bind_error("TLS proxy", 9443, &err);

    assert!(message.contains("bind TLS proxy on 127.0.0.1:9443"));
    assert!(!message.contains("privileged bind rights"));
}

#[test]
fn tcp_forwarder_rule_rejects_non_loopback_listener() {
    let err = TcpForwarderRule::new(
        "0.0.0.0:443".parse().unwrap(),
        "127.0.0.1:9443".parse().unwrap(),
    )
    .unwrap_err();

    assert!(err.to_string().contains("listen address must be loopback"));
}

#[test]
fn tcp_forwarder_rule_rejects_privileged_backend_port() {
    let err = TcpForwarderRule::new(
        "127.0.0.1:443".parse().unwrap(),
        "127.0.0.1:443".parse().unwrap(),
    )
    .unwrap_err();

    assert!(err.to_string().contains("target port must be >=1024"));
}

#[tokio::test]
async fn tcp_forwarder_relays_bytes_to_loopback_backend() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend_listener.accept().await.unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    let rule = TcpForwarderRule::new("127.0.0.1:0".parse().unwrap(), backend_addr).unwrap();
    let forwarder = start_tcp_forwarder(rule).await.unwrap();

    let mut client = tokio::net::TcpStream::connect(forwarder.addr())
        .await
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    client.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    backend_task.await.unwrap();
    forwarder.shutdown();
}

#[tokio::test]
async fn control_response_times_out_when_the_client_does_not_read() {
    let (mut server, _client) = tokio::io::duplex(1);
    let response = ProxyResponse::Error {
        message: "x".repeat(1024),
    };

    let error = tokio::time::timeout(
        IPC_REQUEST_TIMEOUT + Duration::from_millis(500),
        write_response(&mut server, &response),
    )
    .await
    .expect("control response remained blocked past the frame deadline")
    .unwrap_err();

    assert!(error.to_string().contains("timed out"), "got {error}");
}

#[cfg(unix)]
#[test]
fn unix_forwarder_guard_validates_current_user_live_state() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("proxy.json");
    let backend_addr = "127.0.0.1:9443".parse().unwrap();
    write_state_file(
        &state_path,
        &forwarder_state(std::process::id(), Some(format!("https://{backend_addr}"))),
    )
    .unwrap();
    let guard =
        UnixForwarderGuard::new(&state_path, current_effective_uid(), backend_addr).unwrap();

    guard.validate().unwrap();
}

#[cfg(unix)]
#[test]
fn unix_forwarder_guard_rejects_world_accessible_state_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("proxy.json");
    let backend_addr = "127.0.0.1:9443".parse().unwrap();
    write_state_file(
        &state_path,
        &forwarder_state(std::process::id(), Some(format!("https://{backend_addr}"))),
    )
    .unwrap();
    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let guard =
        UnixForwarderGuard::new(&state_path, current_effective_uid(), backend_addr).unwrap();

    let err = guard.validate().unwrap_err();

    assert!(
        err.to_string()
            .contains("must not be group/world accessible")
    );
}

#[cfg(unix)]
#[test]
fn validate_forwarder_daemon_state_rejects_unadvertised_backend() {
    let state = forwarder_state(std::process::id(), Some("https://127.0.0.1:9443".into()));
    let err = validate_forwarder_daemon_state(
        &state,
        current_effective_uid(),
        "127.0.0.1:9444".parse().unwrap(),
        |_| true,
        |_| Some(current_effective_uid()),
    )
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("does not advertise backend listener")
    );
}

#[cfg(unix)]
#[test]
fn validate_forwarder_daemon_state_rejects_stale_pid() {
    let state = forwarder_state(424_242, Some("https://127.0.0.1:9443".into()));
    let err = validate_forwarder_daemon_state(
        &state,
        current_effective_uid(),
        "127.0.0.1:9443".parse().unwrap(),
        |_| false,
        |_| Some(current_effective_uid()),
    )
    .unwrap_err();

    assert!(err.to_string().contains("is not running"));
}

#[cfg(unix)]
#[test]
fn validate_forwarder_daemon_state_rejects_process_uid_mismatch() {
    let uid = current_effective_uid();
    let other_uid = if uid == u32::MAX { uid - 1 } else { uid + 1 };
    let state = forwarder_state(std::process::id(), Some("https://127.0.0.1:9443".into()));
    let err = validate_forwarder_daemon_state(
        &state,
        uid,
        "127.0.0.1:9443".parse().unwrap(),
        |_| true,
        |_| Some(other_uid),
    )
    .unwrap_err();

    assert!(err.to_string().contains("expected UID"));
}

#[cfg(unix)]
#[tokio::test]
async fn guarded_tcp_forwarder_relays_only_when_user_daemon_state_matches() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("proxy.json");
    write_state_file(
        &state_path,
        &forwarder_state(std::process::id(), Some(format!("https://{backend_addr}"))),
    )
    .unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend_listener.accept().await.unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    let rule = TcpForwarderRule::new("127.0.0.1:0".parse().unwrap(), backend_addr).unwrap();
    let guard =
        UnixForwarderGuard::new(&state_path, current_effective_uid(), backend_addr).unwrap();
    let forwarder = start_guarded_tcp_forwarder(rule, guard).await.unwrap();

    let mut client = tokio::net::TcpStream::connect(forwarder.addr())
        .await
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    client.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, b"pong");
    backend_task.await.unwrap();
    forwarder.shutdown();
}

#[cfg(target_os = "linux")]
#[test]
fn parse_linux_status_effective_uid_reads_second_uid_column() {
    let status = "Name:\tnode\nUid:\t501\t502\t503\t504\n";

    assert_eq!(parse_linux_status_effective_uid(status), Some(502));
}

#[test]
fn canonical_host_from_header_strips_port_and_lowercases() {
    let host = canonical_host_from_header(" App.Localhost:443 ").unwrap();

    assert_eq!(host, "app.localhost");
}

#[test]
fn canonical_host_from_header_rejects_ip_literals() {
    let err = canonical_host_from_header("[::1]:443").unwrap_err();

    assert!(err.to_string().contains("IP literal"), "got {err}");
}

#[test]
fn canonical_host_rejects_single_label_hosts() {
    let err = canonical_host("localhost").unwrap_err();

    assert!(err.to_string().contains("multi-label"), "got {err}");
}

#[test]
fn register_routes_rejects_empty_route_set() {
    let mut registry = RouteRegistry::new();

    let err = registry.register_routes(123, Vec::new()).unwrap_err();

    assert_eq!(err, ProxyError::EmptyRouteSet);
}

#[test]
fn fresh_proxy_daemons_do_not_reuse_lease_ids() {
    let first = RouteRegistry::new().register_lease(std::process::id());
    let second = RouteRegistry::new().register_lease(std::process::id());

    assert_ne!(
        first, second,
        "a stale release from a previous daemon could target a new daemon's lease"
    );
}

#[test]
fn register_routes_rejects_duplicate_hosts_in_one_request() {
    let mut registry = RouteRegistry::new();

    let err = registry
        .register_routes(
            123,
            vec![route("app.localhost", 3000), route("APP.localhost", 3001)],
        )
        .unwrap_err();

    assert_eq!(
        err,
        ProxyError::DuplicateHostInRouteSet {
            host: "app.localhost".to_string()
        }
    );
}

#[test]
fn register_routes_rejects_host_owned_by_another_lease() {
    let mut registry = RouteRegistry::new();
    let first = registry
        .register_routes(111, vec![route("app.localhost", 3000)])
        .unwrap();

    let err = registry
        .register_routes(222, vec![route("APP.localhost", 4000)])
        .unwrap_err();

    assert_eq!(
        err,
        ProxyError::HostAlreadyRegistered {
            host: "app.localhost".to_string(),
            lease_id: first,
            owner_pid: 111,
        }
    );
}

#[test]
fn lookup_host_header_returns_registered_route_without_open_proxy_fallback() {
    let mut registry = RouteRegistry::new();
    registry
        .register_routes(111, vec![route("app.localhost", 3000)])
        .unwrap();

    assert_eq!(
        registry
            .lookup_host_header("app.localhost:443")
            .unwrap()
            .upstream_port,
        3000
    );
    assert!(registry.lookup_host_header("example.com").is_none());
}

#[test]
fn replace_routes_allows_same_lease_to_move_host() {
    let mut registry = RouteRegistry::new();
    let lease = registry
        .register_routes(111, vec![route("app.localhost", 3000)])
        .unwrap();

    registry
        .replace_routes(lease, vec![route("app.localhost", 3001)])
        .unwrap();

    assert_eq!(
        registry.lookup_host("app.localhost").unwrap().upstream_port,
        3001
    );
}

#[test]
fn replace_routes_rejects_unknown_lease() {
    let mut registry = RouteRegistry::new();

    let err = registry
        .replace_routes(RouteLeaseId(99), vec![route("app.localhost", 3000)])
        .unwrap_err();

    assert_eq!(err, ProxyError::UnknownLease(RouteLeaseId(99)));
}

#[test]
fn release_removes_only_routes_owned_by_that_lease() {
    let mut registry = RouteRegistry::new();
    let first = registry
        .register_routes(111, vec![route("app.localhost", 3000)])
        .unwrap();
    registry
        .register_routes(222, vec![route("api.localhost", 4000)])
        .unwrap();

    let removed = registry.release(first);

    assert_eq!(removed, 1);
    assert!(registry.lookup_host("app.localhost").is_none());
    assert!(registry.lookup_host("api.localhost").is_some());
}

#[test]
fn prune_dead_leases_removes_routes_for_dead_owner_only() {
    let mut registry = RouteRegistry::new();
    registry
        .register_routes(111, vec![route("app.localhost", 3000)])
        .unwrap();
    registry
        .register_routes(222, vec![route("api.localhost", 4000)])
        .unwrap();

    let removed = registry.prune_leases_with(|pid| pid == 222);

    assert_eq!(removed, 1);
    assert!(registry.lookup_host("app.localhost").is_none());
    assert!(registry.lookup_host("api.localhost").is_some());
}

#[test]
fn statuses_are_sorted_by_host() {
    let mut registry = RouteRegistry::new();
    registry
        .register_routes(
            111,
            vec![route("web.localhost", 3000), route("api.localhost", 4000)],
        )
        .unwrap();

    let hosts: Vec<String> = registry
        .statuses()
        .into_iter()
        .map(|status| status.host)
        .collect();

    assert_eq!(hosts, vec!["api.localhost", "web.localhost"]);
}

#[test]
fn read_status_from_path_reports_not_running_when_state_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.json");

    let status = read_status_from_path(&path).unwrap();

    assert_eq!(status, ProxyStatus::not_running());
}

#[test]
fn read_status_from_path_treats_persisted_state_as_stale_without_ipc() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.json");
    let state = ProxyDaemonState {
        pid: 42,
        endpoint: None,
        http_addr: None,
        http_redirect_addr: None,
        tls_addr: None,
        routes: vec![status("app.localhost", 3000, 1)],
    };
    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();

    let status = read_status_from_path(&path).unwrap();

    assert_eq!(
        status,
        ProxyStatus {
            running: false,
            pid: Some(42),
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: None,
            routes: Vec::new(),
            stale: true,
            state_error: None,
        }
    );
}

#[test]
fn read_status_from_path_reports_corrupt_state_as_stale() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.json");
    std::fs::write(&path, b"{not json").unwrap();

    let status = read_status_from_path(&path).unwrap();

    assert!(status.stale);
    assert!(
        status
            .state_error
            .as_deref()
            .is_some_and(|e| e.contains("key"))
    );
}

#[cfg(unix)]
#[test]
fn write_state_file_sets_private_unix_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("lpm-home");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = root.join("proxy.json");
    let state = ProxyDaemonState {
        pid: 42,
        endpoint: Some(root.join("proxy.sock").display().to_string()),
        http_addr: None,
        http_redirect_addr: None,
        tls_addr: None,
        routes: Vec::new(),
    };

    write_state_file(&path, &state).unwrap();

    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn validate_unix_peer_uid_rejects_other_users() {
    let uid = current_effective_uid();
    let other_uid = if uid == u32::MAX { uid - 1 } else { uid + 1 };

    let err = validate_unix_peer_uid(Some(other_uid), uid).unwrap_err();

    assert!(
        matches!(err, ProxyError::Ipc(message) if message.contains("reject control connection"))
    );
    assert!(validate_unix_peer_uid(Some(uid), uid).is_ok());
    assert!(validate_unix_peer_uid(None, uid).is_ok());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn unix_control_peer_uid_reports_current_user_for_socket_pair() {
    let (stream, _peer) = tokio::net::UnixStream::pair().unwrap();

    assert_eq!(
        unix_control_peer_uid(&stream).unwrap(),
        Some(current_effective_uid())
    );
    validate_unix_control_peer(&stream).unwrap();
}

#[test]
fn proxy_request_round_trips_register_routes() {
    let request = ProxyRequest::Register {
        owner_pid: 123,
        routes: vec![route("app.localhost", 3000)],
    };

    let decoded: ProxyRequest =
        serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();

    assert_eq!(decoded, request);
}

#[test]
fn proxy_response_round_trips_status() {
    let response = ProxyResponse::Status {
        status: ProxyStatus {
            running: false,
            pid: None,
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: None,
            routes: Vec::new(),
            stale: false,
            state_error: None,
        },
    };

    let decoded: ProxyResponse =
        serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();

    assert_eq!(decoded, response);
}

#[test]
#[cfg(all(unix, debug_assertions))]
fn tls_cert_store_loads_project_leaf_for_registered_host() {
    let (_home, _guard) = setup_cert_home();
    let project = tempfile::tempdir().unwrap();
    prepare_project_cert(project.path(), &["app.localhost"]);
    let store = TlsCertificateStore::default();
    refresh_tls_cert_store(
        &store,
        &[RouteStatus {
            host: "app.localhost".to_string(),
            upstream_port: 3000,
            project_dir: project.path().to_path_buf(),
            service: Some("web".to_string()),
            lease_id: RouteLeaseId(1),
            owner_pid: 123,
        }],
    )
    .unwrap();

    assert!(store.get("APP.localhost").is_some());
    assert!(store.get("api.localhost").is_none());
}

#[test]
#[cfg(all(unix, debug_assertions))]
fn failed_tls_cert_store_refresh_retains_the_previous_complete_store() {
    let (_home, _guard) = setup_cert_home();
    let project = tempfile::tempdir().unwrap();
    prepare_project_cert(project.path(), &["app.localhost"]);
    let store = TlsCertificateStore::default();
    let routes = [RouteStatus {
        host: "app.localhost".to_string(),
        upstream_port: 3000,
        project_dir: project.path().to_path_buf(),
        service: Some("web".to_string()),
        lease_id: RouteLeaseId(1),
        owner_pid: 123,
    }];
    refresh_tls_cert_store(&store, &routes).unwrap();
    assert!(store.get("app.localhost").is_some());

    std::fs::remove_file(project.path().join(".lpm").join("certs").join("key.pem")).unwrap();
    assert!(refresh_tls_cert_store(&store, &routes).is_err());

    assert!(
        store.get("app.localhost").is_some(),
        "an incomplete refresh replaced the previously valid TLS certificate store"
    );
}

#[cfg(all(unix, debug_assertions))]
#[test]
fn tls_cert_store_refresh_rejects_a_linked_project_certificate() {
    use std::os::unix::fs::symlink;

    let (_home, _guard) = setup_cert_home();
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    prepare_project_cert(project.path(), &["app.localhost"]);
    let cert_path = project.path().join(".lpm/certs/cert.pem");
    let outside_cert = outside.path().join("cert.pem");
    std::fs::rename(&cert_path, &outside_cert).unwrap();
    symlink(&outside_cert, &cert_path).unwrap();
    let store = TlsCertificateStore::default();

    let error = refresh_tls_cert_store(
        &store,
        &[RouteStatus {
            host: "app.localhost".to_string(),
            upstream_port: 3000,
            project_dir: project.path().to_path_buf(),
            service: Some("web".to_string()),
            lease_id: RouteLeaseId(1),
            owner_pid: 123,
        }],
    )
    .unwrap_err();

    assert!(error.to_string().contains("linked project certificate"));
    assert!(store.get("app.localhost").is_none());
}

#[cfg(all(unix, debug_assertions))]
#[test]
fn tls_cert_store_refresh_rejects_a_leaf_from_an_unrelated_root() {
    let (_home, _guard) = setup_cert_home();
    let project = tempfile::tempdir().unwrap();
    prepare_project_cert(project.path(), &["app.localhost"]);
    let (unrelated_root, unrelated_key) =
        lpm_cert::ca::generate_ca_with_options(lpm_cert::ca::CaOptions::default()).unwrap();
    let (leaf, key) = lpm_cert::cert::generate_project_cert_with_constrained_intermediate(
        &unrelated_root,
        &unrelated_key,
        &["app.localhost".to_string()],
        &[],
    )
    .unwrap();
    let cert_dir = project.path().join(".lpm/certs");
    std::fs::write(cert_dir.join("cert.pem"), leaf).unwrap();
    lpm_cert::write_key_file(&cert_dir.join("key.pem"), key.as_bytes()).unwrap();
    let store = TlsCertificateStore::default();

    let error = refresh_tls_cert_store(
        &store,
        &[RouteStatus {
            host: "app.localhost".to_string(),
            upstream_port: 3000,
            project_dir: project.path().to_path_buf(),
            service: Some("web".to_string()),
            lease_id: RouteLeaseId(1),
            owner_pid: 123,
        }],
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("project certificate chain signatures are invalid"),
        "{error}"
    );
    assert!(store.get("app.localhost").is_none());
}

#[cfg(all(unix, debug_assertions))]
#[test]
fn published_tls_key_retains_its_certificate_generation_until_the_last_clone_drops() {
    let (_home, _guard) = setup_cert_home();
    let project = tempfile::tempdir().unwrap();
    prepare_project_cert(project.path(), &["app.localhost"]);
    let store = TlsCertificateStore::default();
    refresh_tls_cert_store(
        &store,
        &[RouteStatus {
            host: "app.localhost".to_string(),
            upstream_port: 3000,
            project_dir: project.path().to_path_buf(),
            service: Some("web".to_string()),
            lease_id: RouteLeaseId(1),
            owner_pid: 123,
        }],
    )
    .unwrap();
    let published_key = store.get("app.localhost").unwrap();
    store.replace(HashMap::new()).unwrap();

    let error = lpm_cert::rotate::rotate(lpm_cert::rotate::RotateOptions::default()).unwrap_err();
    assert!(error.to_string().contains("active TLS runtime"), "{error}");

    drop(published_key);
    assert!(
        lpm_cert::rotate::rotate(lpm_cert::rotate::RotateOptions::default())
            .unwrap()
            .success
    );
}

#[cfg(all(unix, debug_assertions))]
#[tokio::test]
async fn failed_state_write_restores_the_previous_tls_certificate_store() {
    let (_home, _guard) = setup_cert_home_async().await;
    let previous_project = tempfile::tempdir().unwrap();
    prepare_project_cert(previous_project.path(), &["app.localhost"]);
    let next_project = tempfile::tempdir().unwrap();
    prepare_project_cert(next_project.path(), &["api.localhost"]);
    let store = TlsCertificateStore::default();
    refresh_tls_cert_store(
        &store,
        &[RouteStatus {
            host: "app.localhost".to_string(),
            upstream_port: 3000,
            project_dir: previous_project.path().to_path_buf(),
            service: Some("web".to_string()),
            lease_id: RouteLeaseId(1),
            owner_pid: 123,
        }],
    )
    .unwrap();
    let mut registry = RouteRegistry::new();
    registry
        .register_routes(
            123,
            vec![Route {
                host: "api.localhost".to_string(),
                upstream_port: 4000,
                project_dir: next_project.path().to_path_buf(),
                service: Some("api".to_string()),
            }],
        )
        .unwrap();
    let registry = tokio::sync::Mutex::new(registry);
    let state_write_lock = tokio::sync::Mutex::new(());
    let state_path_parent = tempfile::tempdir().unwrap();
    let state_path = state_path_parent.path().join("proxy.json");
    std::fs::create_dir(&state_path).unwrap();

    crate::control::write_current_state(
        &registry,
        &state_write_lock,
        &state_path,
        "test-endpoint".to_string(),
        crate::control::ProxyListenerAddrs::default(),
        Some(&store),
    )
    .await
    .unwrap_err();

    assert!(store.get("app.localhost").is_some());
    assert!(store.get("api.localhost").is_none());
}

#[cfg(all(unix, debug_assertions))]
#[tokio::test]
async fn tls_control_daemon_prepares_project_leaf_when_route_registers() {
    let (_home, _guard) = setup_cert_home_async().await;
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("app");
    std::fs::create_dir_all(&project_dir).unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path_with_options(
            &server_socket_path,
            &server_state_path,
            ProxyDaemonOptions {
                tls_port: Some(0),
                ..ProxyDaemonOptions::default()
            },
        )
        .await
    });
    wait_for_control_server(&socket_path).await;

    let cert_path = project_dir.join(".lpm").join("certs").join("cert.pem");
    assert!(!cert_path.exists());
    let registered = send_request_to_path(
        &socket_path,
        ProxyRequest::Register {
            owner_pid: std::process::id(),
            routes: vec![route_for_project("app.localhost", 3000, &project_dir)],
        },
    )
    .await
    .unwrap();

    assert!(
        matches!(registered, ProxyResponse::Registered { .. }),
        "expected daemon-side cert preparation to allow route registration, got {registered:?}"
    );
    assert!(cert_path.exists());
    assert!(cert_covers_hostname(&cert_path, "app.localhost").unwrap());
    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[test]
fn proxy_pipe_name_for_root_is_stable_and_path_normalized() {
    let backslash = proxy_pipe_name_for_root(Path::new(r"C:\Users\Ada\.lpm"));
    let slash = proxy_pipe_name_for_root(Path::new("c:/users/ada/.lpm"));

    assert_eq!(backslash, slash);
    assert!(backslash.starts_with(r"\\.\pipe\lpm-proxy-"));
}

#[cfg(unix)]
#[tokio::test]
async fn control_server_reports_registered_routes_until_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let registered = send_request_to_path(
        &socket_path,
        ProxyRequest::Register {
            owner_pid: std::process::id(),
            routes: vec![route("app.localhost", 3000)],
        },
    )
    .await
    .unwrap();
    let lease_id = match registered {
        ProxyResponse::Registered { lease_id } => lease_id,
        other => panic!("expected registered response, got {other:?}"),
    };

    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    match listed {
        ProxyResponse::Routes { routes } => {
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].host, "app.localhost");
            assert_eq!(routes[0].lease_id, lease_id);
        }
        other => panic!("expected routes response, got {other:?}"),
    }

    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
    assert!(!socket_path.exists());
    assert!(!state_path.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn control_server_caps_silent_connections() {
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();
    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let mut silent = Vec::with_capacity(CONTROL_CONNECTION_LIMIT);
    for _ in 0..CONTROL_CONNECTION_LIMIT {
        silent.push(tokio::net::UnixStream::connect(&socket_path).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut excess = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
    let mut byte = [0u8; 1];

    let read = tokio::time::timeout(Duration::from_millis(250), excess.read(&mut byte))
        .await
        .expect("control server retained more than its silent-connection limit")
        .unwrap();
    assert_eq!(read, 0);

    drop(silent);
    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn control_server_rejects_cross_lease_host_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let owner_pid = std::process::id();
    let registered = send_request_to_path(
        &socket_path,
        ProxyRequest::Register {
            owner_pid,
            routes: vec![route("app.localhost", 3000)],
        },
    )
    .await
    .unwrap();
    let first_lease = match registered {
        ProxyResponse::Registered { lease_id } => lease_id,
        other => panic!("expected registered response, got {other:?}"),
    };

    let conflicted = send_request_to_path(
        &socket_path,
        ProxyRequest::Register {
            owner_pid,
            routes: vec![route("APP.localhost", 4000)],
        },
    )
    .await
    .unwrap();

    match conflicted {
        ProxyResponse::Error { message } => {
            assert!(message.contains("already registered"), "got {message}");
            assert!(message.contains("app.localhost"), "got {message}");
        }
        other => panic!("expected conflict error response, got {other:?}"),
    }

    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    match listed {
        ProxyResponse::Routes { routes } => {
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].host, "app.localhost");
            assert_eq!(routes[0].upstream_port, 3000);
            assert_eq!(routes[0].lease_id, first_lease);
        }
        other => panic!("expected routes response, got {other:?}"),
    }

    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn route_lease_release_removes_registered_routes() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let registered = send_request_to_path(
        &socket_path,
        ProxyRequest::Register {
            owner_pid: std::process::id(),
            routes: vec![route("app.localhost", 3000)],
        },
    )
    .await
    .unwrap();
    let lease_id = match registered {
        ProxyResponse::Registered { lease_id } => lease_id,
        other => panic!("expected registered response, got {other:?}"),
    };
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: None,
        pending_operation: None,
        socket_path: Some(socket_path.clone()),
    };

    let removed = lease.release().await.unwrap();

    assert_eq!(removed, 1);
    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    assert_eq!(listed, ProxyResponse::Routes { routes: Vec::new() });
    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn route_lease_replaces_and_releases_routes_on_its_control_stream() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let (lease_id, stream) =
        register_lease_to_path(&socket_path, vec![route("app.localhost", 3000)])
            .await
            .unwrap();
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(stream)),
        pending_operation: None,
        socket_path: Some(socket_path.clone()),
    };

    lease
        .replace_routes(vec![route("app.localhost", 4000)])
        .await
        .unwrap();
    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    let ProxyResponse::Routes { routes } = listed else {
        panic!("expected proxy routes after replacement");
    };
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].upstream_port, 4000);

    let removed = lease.release().await.unwrap();

    assert_eq!(removed, 1);
    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    assert_eq!(listed, ProxyResponse::Routes { routes: Vec::new() });
    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn connection_backed_route_lease_can_clear_and_republish_its_routes() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();
    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;
    let (lease_id, stream) =
        register_lease_to_path(&socket_path, vec![route("app.localhost", 3000)])
            .await
            .unwrap();
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(stream)),
        pending_operation: None,
        socket_path: Some(socket_path.clone()),
    };

    lease.replace_routes(Vec::new()).await.unwrap();
    assert_eq!(
        send_request_to_path(&socket_path, ProxyRequest::List)
            .await
            .unwrap(),
        ProxyResponse::Routes { routes: Vec::new() }
    );
    lease
        .replace_routes(vec![route("app.localhost", 4000)])
        .await
        .unwrap();
    let ProxyResponse::Routes { routes } = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap()
    else {
        panic!("expected proxy routes after republishing");
    };
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].upstream_port, 4000);

    lease.release().await.unwrap();
    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn staged_route_lease_publishes_only_an_acknowledged_commit() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let (lease_id, stream) = crate::client::register_staged_lease_to_path(&socket_path)
        .await
        .unwrap();
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(stream)),
        pending_operation: None,
        socket_path: Some(socket_path.clone()),
    };

    lease
        .stage_routes(1, vec![route("app.localhost", 3000)])
        .await
        .unwrap();
    assert_eq!(
        send_request_to_path(&socket_path, ProxyRequest::List)
            .await
            .unwrap(),
        ProxyResponse::Routes { routes: Vec::new() }
    );
    let staged_state: ProxyDaemonState =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert!(staged_state.routes.is_empty());

    lease.commit_routes(1).await.unwrap();
    let ProxyResponse::Routes { routes } = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap()
    else {
        panic!("expected committed proxy routes");
    };
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].upstream_port, 3000);

    lease
        .stage_routes(2, vec![route("app.localhost", 4000)])
        .await
        .unwrap();
    lease.rollback_routes(2).await.unwrap();
    let ProxyResponse::Routes { routes } = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap()
    else {
        panic!("expected original proxy routes after rollback");
    };
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].upstream_port, 3000);

    assert_eq!(lease.release().await.unwrap(), 1);
    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn ambiguous_staged_commit_releases_the_lease_before_returning() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let lease_id = RouteLeaseId::from_raw(7);
    let (client_stream, mut lease_server) = tokio::net::UnixStream::pair().unwrap();
    let server = tokio::spawn(async move {
        let ProxyRequest::Commit {
            lease_id: committed_lease,
            publication_id,
        } = read_proxy_request(&mut lease_server).await.unwrap()
        else {
            panic!("expected staged publication commit");
        };
        assert_eq!(committed_lease, lease_id);
        assert_eq!(publication_id, 11);
        drop(lease_server);

        let (mut release_stream, _) = listener.accept().await.unwrap();
        let ProxyRequest::Release {
            lease_id: released_lease,
        } = read_proxy_request(&mut release_stream).await.unwrap()
        else {
            panic!("expected failed-closed lease release");
        };
        assert_eq!(released_lease, lease_id);
        write_response(&mut release_stream, &ProxyResponse::Released { removed: 1 })
            .await
            .unwrap();
    });
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(client_stream)),
        pending_operation: None,
        socket_path: Some(socket_path),
    };

    let error = lease.commit_routes(11).await.unwrap_err();

    assert!(matches!(error, ProxyError::IpcProtocol(_)));
    assert!(lease.lease_id().is_none());
    assert!(lease.connection.is_none());
    server.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn ambiguous_staged_commit_keeps_the_lease_active_when_release_is_unconfirmed() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let lease_id = RouteLeaseId::from_raw(7);
    let (client_stream, mut lease_server) = tokio::net::UnixStream::pair().unwrap();
    let server = tokio::spawn(async move {
        let ProxyRequest::Commit {
            lease_id: committed_lease,
            publication_id,
        } = read_proxy_request(&mut lease_server).await.unwrap()
        else {
            panic!("expected staged publication commit");
        };
        assert_eq!(committed_lease, lease_id);
        assert_eq!(publication_id, 11);
        drop(lease_server);

        let (mut release_stream, _) = listener.accept().await.unwrap();
        let ProxyRequest::Release {
            lease_id: released_lease,
        } = read_proxy_request(&mut release_stream).await.unwrap()
        else {
            panic!("expected failed-closed lease release");
        };
        assert_eq!(released_lease, lease_id);
    });
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(client_stream)),
        pending_operation: None,
        socket_path: Some(socket_path),
    };

    let error = lease.commit_routes(11).await.unwrap_err();

    assert!(error.to_string().contains("lease release also failed"));
    assert_eq!(lease.lease_id(), Some(lease_id));
    assert!(lease.connection.is_none());
    lease.lease_id = None;
    server.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn unconfirmed_lease_cleanup_rejects_new_route_publication() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let lease_id = RouteLeaseId::from_raw(7);
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: None,
        pending_operation: None,
        socket_path: Some(socket_path),
    };

    let error = lease
        .replace_routes(vec![route("app.localhost", 4000)])
        .await
        .unwrap_err();

    assert!(error.to_string().contains("cleanup is unconfirmed"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "route mutation reached the endpoint while lease cleanup was ambiguous"
    );
    lease.lease_id = None;
}

#[cfg(unix)]
#[tokio::test]
async fn cancelled_route_replacement_finishes_before_the_next_replacement() {
    let (client_stream, mut server_stream) = tokio::net::UnixStream::pair().unwrap();
    let lease_id = RouteLeaseId::from_raw(7);
    let (first_applied_tx, first_applied_rx) = tokio::sync::oneshot::channel();
    let (allow_first_response_tx, allow_first_response_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let ProxyRequest::Replace { routes, .. } =
            read_proxy_request(&mut server_stream).await.unwrap()
        else {
            panic!("expected first route replacement");
        };
        assert_eq!(routes[0].upstream_port, 4000);
        first_applied_tx.send(()).unwrap();
        allow_first_response_rx.await.unwrap();
        write_response(&mut server_stream, &ProxyResponse::Replaced)
            .await
            .unwrap();

        let ProxyRequest::Replace { routes, .. } =
            read_proxy_request(&mut server_stream).await.unwrap()
        else {
            panic!("expected second route replacement");
        };
        assert_eq!(routes[0].upstream_port, 5000);
        write_response(&mut server_stream, &ProxyResponse::Replaced)
            .await
            .unwrap();
    });
    let lease = Arc::new(tokio::sync::Mutex::new(RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(client_stream)),
        pending_operation: None,
        socket_path: None,
    }));
    let first_lease = Arc::clone(&lease);
    let first = tokio::spawn(async move {
        first_lease
            .lock()
            .await
            .replace_routes(vec![route("app.localhost", 4000)])
            .await
    });
    first_applied_rx.await.unwrap();
    first.abort();
    let _ = first.await;
    allow_first_response_tx.send(()).unwrap();

    lease
        .lock()
        .await
        .replace_routes(vec![route("app.localhost", 5000)])
        .await
        .unwrap();

    server.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_a_cancelled_route_replacement_releases_the_lease_via_the_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let lease_id = RouteLeaseId::from_raw(7);
    let (client_stream, mut lease_server) = tokio::net::UnixStream::pair().unwrap();
    let (applied_tx, applied_rx) = tokio::sync::oneshot::channel();
    let persistent_server = tokio::spawn(async move {
        let ProxyRequest::Replace {
            lease_id: replaced_lease,
            ..
        } = read_proxy_request(&mut lease_server).await.unwrap()
        else {
            panic!("expected route replacement");
        };
        assert_eq!(replaced_lease, lease_id);
        applied_tx.send(()).unwrap();
        let mut byte = [0_u8; 1];
        let _ = tokio::io::AsyncReadExt::read(&mut lease_server, &mut byte).await;
    });
    let release_server = tokio::spawn(async move {
        let (mut release_stream, _) = listener.accept().await.unwrap();
        let ProxyRequest::Release {
            lease_id: released_lease,
        } = read_proxy_request(&mut release_stream).await.unwrap()
        else {
            panic!("expected endpoint lease release");
        };
        assert_eq!(released_lease, lease_id);
        write_response(&mut release_stream, &ProxyResponse::Released { removed: 1 })
            .await
            .unwrap();
    });
    let lease = Arc::new(tokio::sync::Mutex::new(RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(client_stream)),
        pending_operation: None,
        socket_path: Some(socket_path),
    }));
    let replacement_lease = Arc::clone(&lease);
    let replacement = tokio::spawn(async move {
        replacement_lease
            .lock()
            .await
            .replace_routes(vec![route("app.localhost", 4000)])
            .await
    });
    applied_rx.await.unwrap();
    replacement.abort();
    let _ = replacement.await;

    drop(Arc::try_unwrap(lease).unwrap().into_inner());

    tokio::time::timeout(Duration::from_secs(1), release_server)
        .await
        .expect("dropping the cancelled lease did not request endpoint cleanup")
        .unwrap();
    persistent_server.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn connection_backed_commit_failure_removes_the_committed_routes() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let (lease_id, stream) = crate::client::register_staged_lease_to_path(&socket_path)
        .await
        .unwrap();
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(stream)),
        pending_operation: None,
        socket_path: Some(dir.path().join("missing-proxy.sock")),
    };
    lease
        .stage_routes(1, vec![route("app.localhost", 3000)])
        .await
        .unwrap();

    std::fs::remove_file(&state_path).unwrap();
    std::fs::create_dir(&state_path).unwrap();
    lease.commit_routes(1).await.unwrap_err();
    std::fs::remove_dir(&state_path).unwrap();

    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    assert_eq!(listed, ProxyResponse::Routes { routes: Vec::new() });

    lease.lease_id = None;
    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn route_lease_release_falls_back_when_control_connection_stalls() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let registered = send_request_to_path(
        &socket_path,
        ProxyRequest::Register {
            owner_pid: std::process::id(),
            routes: vec![route("app.localhost", 3000)],
        },
    )
    .await
    .unwrap();
    let lease_id = match registered {
        ProxyResponse::Registered { lease_id } => lease_id,
        other => panic!("expected registered response, got {other:?}"),
    };
    let (stream, _stalled_peer) = tokio::net::UnixStream::pair().unwrap();
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: Some(LeaseConnection::Unix(stream)),
        pending_operation: None,
        socket_path: Some(socket_path.clone()),
    };

    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    match listed {
        ProxyResponse::Routes { routes } => assert_eq!(routes.len(), 1),
        other => panic!("expected routes response, got {other:?}"),
    }

    let removed = lease.release().await.unwrap();

    assert!(removed <= 1);
    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    assert_eq!(listed, ProxyResponse::Routes { routes: Vec::new() });
    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn connection_backed_lease_releases_routes_when_control_stream_closes() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("proxy.sock");
    let state_path = dir.path().join("proxy.json");
    let server_socket_path = socket_path.clone();
    let server_state_path = state_path.clone();

    let server = tokio::spawn(async move {
        serve_control_at_path(&server_socket_path, &server_state_path).await
    });
    wait_for_control_server(&socket_path).await;

    let (lease_id, stream) =
        register_lease_to_path(&socket_path, vec![route("app.localhost", 3000)])
            .await
            .unwrap();
    let listed = send_request_to_path(&socket_path, ProxyRequest::List)
        .await
        .unwrap();
    match listed {
        ProxyResponse::Routes { routes } => {
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].lease_id, lease_id);
        }
        other => panic!("expected routes response, got {other:?}"),
    }

    drop(stream);

    wait_for_empty_control_routes(&socket_path).await;
    let stopped = send_request_to_path(&socket_path, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn named_pipe_control_server_reports_registered_routes_until_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let pipe_name = proxy_pipe_name_for_root(dir.path());
    let state_path = dir.path().join("proxy.json");
    let server_pipe_name = pipe_name.clone();
    let server_state_path = state_path.clone();

    let server =
        tokio::spawn(
            async move { serve_control_at_pipe(&server_pipe_name, &server_state_path).await },
        );
    wait_for_control_pipe_server(&pipe_name).await;

    let registered = send_request_to_pipe(
        &pipe_name,
        ProxyRequest::Register {
            owner_pid: std::process::id(),
            routes: vec![route("app.localhost", 3000)],
        },
    )
    .await
    .unwrap();
    let lease_id = match registered {
        ProxyResponse::Registered { lease_id } => lease_id,
        other => panic!("expected registered response, got {other:?}"),
    };

    let listed = send_request_to_pipe(&pipe_name, ProxyRequest::List)
        .await
        .unwrap();
    match listed {
        ProxyResponse::Routes { routes } => {
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].host, "app.localhost");
            assert_eq!(routes[0].lease_id, lease_id);
        }
        other => panic!("expected routes response, got {other:?}"),
    }

    let stopped = send_request_to_pipe(&pipe_name, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
    assert!(!state_path.exists());
}

#[cfg(windows)]
#[tokio::test]
async fn named_pipe_route_lease_release_removes_registered_routes() {
    let dir = tempfile::tempdir().unwrap();
    let pipe_name = proxy_pipe_name_for_root(dir.path());
    let state_path = dir.path().join("proxy.json");
    let server_pipe_name = pipe_name.clone();
    let server_state_path = state_path.clone();

    let server =
        tokio::spawn(
            async move { serve_control_at_pipe(&server_pipe_name, &server_state_path).await },
        );
    wait_for_control_pipe_server(&pipe_name).await;

    let registered = send_request_to_pipe(
        &pipe_name,
        ProxyRequest::Register {
            owner_pid: std::process::id(),
            routes: vec![route("app.localhost", 3000)],
        },
    )
    .await
    .unwrap();
    let lease_id = match registered {
        ProxyResponse::Registered { lease_id } => lease_id,
        other => panic!("expected registered response, got {other:?}"),
    };
    let mut lease = RouteLease {
        lease_id: Some(lease_id),
        connection: None,
        pending_operation: None,
        pipe_name: Some(pipe_name.clone()),
    };

    let removed = lease.release().await.unwrap();

    assert_eq!(removed, 1);
    let listed = send_request_to_pipe(&pipe_name, ProxyRequest::List)
        .await
        .unwrap();
    assert_eq!(listed, ProxyResponse::Routes { routes: Vec::new() });
    let stopped = send_request_to_pipe(&pipe_name, ProxyRequest::Stop)
        .await
        .unwrap();
    assert_eq!(stopped, ProxyResponse::Stopped);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn http_proxy_routes_registered_host_to_upstream() {
    let upstream_port = spawn_echo_upstream().await;
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    registry
        .lock()
        .await
        .register_routes(123, vec![route("app.localhost", upstream_port)])
        .unwrap();
    let proxy = start_http_proxy(Arc::clone(&registry), 0).await.unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/hello?x=1", proxy.port()))
        .header("host", "app.localhost")
        .body("payload")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_eq!(
        body,
        "POST /hello?x=1 payload host=app.localhost proto=http"
    );
    proxy.shutdown();
}

#[tokio::test]
async fn http_frontend_forwards_any_local_host_to_the_resolved_upstream() {
    let upstream_port = spawn_echo_upstream().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, upstream_port);
    let frontend = start_http_frontend_on_listener(listener, upstream).unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/network", frontend.port()))
        .header("host", format!("192.0.2.10:{}", frontend.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("GET /network"));
    assert!(body.contains("proto=http"));
    frontend.shutdown();
}

#[tokio::test]
async fn http_proxy_times_out_when_upstream_never_sends_response_headers() {
    use tokio::io::AsyncReadExt;

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        std::future::pending::<()>().await;
    });
    let state = HttpProxyState::for_upstream(
        FrontendUpstream::new(lpm_common::LocalTarget::loopback(
            lpm_common::LocalScheme::Http,
            upstream_port,
        ))
        .unwrap(),
        "http",
    )
    .with_test_limits(Duration::from_millis(50), 1);
    let request = axum::http::Request::builder()
        .uri("/health")
        .header("host", "localhost")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = tokio::time::timeout(
        Duration::from_millis(250),
        proxy_http_request_inner(Arc::new(state), request),
    )
    .await
    .expect("proxy retained a request after its upstream-header deadline")
    .unwrap_err();

    assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
    upstream_task.abort();
}

#[tokio::test]
async fn http_proxy_rejects_an_upgrade_when_the_tunnel_limit_is_exhausted() {
    let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = unavailable.local_addr().unwrap().port();
    drop(unavailable);
    let state = HttpProxyState::for_upstream(
        FrontendUpstream::new(lpm_common::LocalTarget::loopback(
            lpm_common::LocalScheme::Http,
            upstream_port,
        ))
        .unwrap(),
        "http",
    )
    .with_test_limits(Duration::from_millis(50), 0);
    let request = axum::http::Request::builder()
        .uri("/hmr")
        .header("host", "localhost")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = proxy_http_request_inner(Arc::new(state), request)
        .await
        .unwrap_err();

    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn http_frontend_caps_idle_connections_and_closes_them_on_shutdown() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const EXPECTED_CONNECTION_CAP: usize = 64;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let frontend = start_http_frontend_on_listener(
        listener,
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 1),
    )
    .unwrap();
    let mut stalled = Vec::with_capacity(EXPECTED_CONNECTION_CAP);
    for _ in 0..EXPECTED_CONNECTION_CAP {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", frontend.port()))
            .await
            .unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        stalled.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut excess = tokio::net::TcpStream::connect(("127.0.0.1", frontend.port()))
        .await
        .unwrap();
    excess
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut byte = [0u8; 1];

    assert!(
        tokio::time::timeout(Duration::from_millis(250), excess.read(&mut byte))
            .await
            .is_err(),
        "plain HTTP frontend accepted more than {EXPECTED_CONNECTION_CAP} idle connections"
    );

    frontend.shutdown();
    for mut stream in stalled {
        let closed = tokio::time::timeout(Duration::from_millis(250), stream.read(&mut byte))
            .await
            .expect("HTTP frontend shutdown left an idle connection task running")
            .unwrap();
        assert_eq!(closed, 0);
    }
}

#[tokio::test]
async fn http_frontend_switches_to_a_republished_child_endpoint() {
    let upstream_port = spawn_echo_upstream().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let initial = lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, upstream_port)
        .with_base_path("/before");
    let frontend = start_http_frontend_on_listener(listener, initial).unwrap();
    let url = format!("http://127.0.0.1:{}/check", frontend.port());

    let before = reqwest::get(&url).await.unwrap().text().await.unwrap();
    frontend
        .update_upstream(
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, upstream_port)
                .with_base_path("/after"),
        )
        .unwrap();
    let after = reqwest::get(&url).await.unwrap().text().await.unwrap();

    assert!(before.contains("GET /before/check"));
    assert!(after.contains("GET /after/check"));
    frontend.shutdown();
}

#[tokio::test]
async fn shared_frontends_switch_to_one_republished_child_atomically() {
    let upstream_port = spawn_echo_upstream().await;
    let upstream = FrontendUpstream::new(
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, upstream_port)
            .with_base_path("/before"),
    )
    .unwrap();
    let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first =
        start_http_frontend_on_listener_with_upstream(first_listener, upstream.clone()).unwrap();
    let second =
        start_http_frontend_on_listener_with_upstream(second_listener, upstream.clone()).unwrap();
    let urls = [
        format!("http://127.0.0.1:{}/check", first.port()),
        format!("http://127.0.0.1:{}/check", second.port()),
    ];

    for url in &urls {
        assert!(
            reqwest::get(url)
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
                .contains("GET /before/check")
        );
    }
    upstream
        .update(
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, upstream_port)
                .with_base_path("/after"),
        )
        .unwrap();
    for url in &urls {
        assert!(
            reqwest::get(url)
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
                .contains("GET /after/check")
        );
    }

    first.shutdown();
    second.shutdown();
}

#[tokio::test]
async fn http_frontend_forwards_to_an_ipv6_loopback_upstream() {
    use axum::Router;
    use axum::routing::any;

    let upstream_listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let app = Router::new().fallback(any(echo_upstream));
    tokio::spawn(async move {
        axum::serve(upstream_listener, app).await.unwrap();
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = lpm_common::LocalTarget {
        scheme: lpm_common::LocalScheme::Http,
        address: std::net::Ipv6Addr::LOCALHOST.into(),
        port: upstream_port,
        base_path: "/".to_string(),
    };
    let frontend = start_http_frontend_on_listener(listener, upstream).unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/ipv6", frontend.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    frontend.shutdown();
}

#[tokio::test]
async fn http_proxy_rejects_unknown_host_without_open_proxy_fallback() {
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    let proxy = start_http_proxy(Arc::clone(&registry), 0).await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/", proxy.port()))
        .header("host", "example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::MISDIRECTED_REQUEST);
    proxy.shutdown();
}

#[tokio::test]
async fn http_redirect_rewrites_registered_host_to_https_without_open_redirect() {
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    registry
        .lock()
        .await
        .register_routes(123, vec![route("app.localhost", 3000)])
        .unwrap();
    let redirect = start_http_redirect(Arc::clone(&registry), 0, 9443)
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let response = client
        .get(format!("http://127.0.0.1:{}/hello?x=1", redirect.port()))
        .header("host", "app.localhost")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://app.localhost:9443/hello?x=1")
    );

    let unknown = client
        .get(format!("http://127.0.0.1:{}/", redirect.port()))
        .header("host", "example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), reqwest::StatusCode::MISDIRECTED_REQUEST);
    redirect.shutdown();
}

#[cfg(all(unix, debug_assertions))]
#[tokio::test]
async fn tls_proxy_routes_registered_host_to_upstream_and_marks_https() {
    let (_home, _guard) = setup_cert_home_async().await;
    let project = tempfile::tempdir().unwrap();
    prepare_project_cert(project.path(), &["app.localhost"]);
    let upstream_port = spawn_echo_upstream().await;
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    registry
        .lock()
        .await
        .register_routes(
            123,
            vec![Route {
                host: "app.localhost".to_string(),
                upstream_port,
                project_dir: project.path().to_path_buf(),
                service: Some("web".to_string()),
            }],
        )
        .unwrap();
    let cert_store = TlsCertificateStore::default();
    refresh_tls_cert_store(&cert_store, &registry.lock().await.statuses()).unwrap();
    let proxy = start_tls_proxy(Arc::clone(&registry), cert_store, 0)
        .await
        .unwrap();

    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(
            "app.localhost",
            SocketAddr::from(([127, 0, 0, 1], proxy.port())),
        )
        .build()
        .unwrap()
        .post(format!("https://app.localhost:{}/hello", proxy.port()))
        .body("payload")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert_eq!(
        body,
        format!(
            "POST /hello payload host=app.localhost:{} proto=https",
            proxy.port()
        )
    );
    proxy.shutdown();
}

#[tokio::test]
async fn tls_frontend_terminates_https_for_a_plain_http_upstream() {
    let project = tempfile::tempdir().unwrap();
    write_project_cert(project.path(), &["localhost"]);
    let upstream_port = spawn_echo_upstream().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cert_dir = project.path().join(".lpm").join("certs");
    let frontend = start_tls_frontend_on_listener(
        listener,
        &cert_dir.join("cert.pem"),
        &cert_dir.join("key.pem"),
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, upstream_port),
    )
    .await
    .unwrap();

    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("https://localhost:{}/secure", frontend.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("GET /secure"));
    assert!(body.contains("proto=https"));
    frontend.shutdown();
}

#[tokio::test]
async fn tls_frontend_shutdown_closes_a_client_stalled_before_client_hello() {
    use tokio::io::AsyncReadExt;

    let project = tempfile::tempdir().unwrap();
    write_project_cert(project.path(), &["localhost"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cert_dir = project.path().join(".lpm").join("certs");
    let frontend = start_tls_frontend_on_listener(
        listener,
        &cert_dir.join("cert.pem"),
        &cert_dir.join("key.pem"),
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 3000),
    )
    .await
    .unwrap();
    let mut stalled = tokio::net::TcpStream::connect(("127.0.0.1", frontend.port()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;

    frontend.shutdown();

    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_millis(250), stalled.read(&mut byte))
        .await
        .expect("TLS frontend shutdown left an accepted handshake task running")
        .unwrap();
    assert_eq!(closed, 0);
}

#[tokio::test]
async fn tls_frontend_times_out_a_client_that_never_sends_client_hello() {
    use tokio::io::AsyncReadExt;

    let project = tempfile::tempdir().unwrap();
    write_project_cert(project.path(), &["localhost"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cert_dir = project.path().join(".lpm").join("certs");
    let frontend = start_tls_frontend_on_listener(
        listener,
        &cert_dir.join("cert.pem"),
        &cert_dir.join("key.pem"),
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 3000),
    )
    .await
    .unwrap();
    let mut stalled = tokio::net::TcpStream::connect(("127.0.0.1", frontend.port()))
        .await
        .unwrap();

    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_millis(5_500), stalled.read(&mut byte))
        .await
        .expect("TLS handshake remained open beyond its deadline")
        .unwrap();
    assert_eq!(closed, 0);
    frontend.shutdown();
}

#[tokio::test]
async fn tls_frontend_times_out_an_idle_http_header_after_handshake() {
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::io::AsyncReadExt;

    let (ca_cert_pem, ca_key_pem) =
        lpm_cert::ca::generate_ca_with_options(lpm_cert::ca::CaOptions::default()).unwrap();
    let (cert_pem, key_pem) = lpm_cert::cert::generate_project_cert(
        &ca_cert_pem,
        &ca_key_pem,
        &["localhost".to_string()],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let frontend = start_tls_frontend_on_listener_with_pem(
        listener,
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 3000),
    )
    .await
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            pem::parse(ca_cert_pem).unwrap().contents().to_vec(),
        ))
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", frontend.port()))
        .await
        .unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap().to_owned(), tcp)
        .await
        .unwrap();

    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_millis(10_500), tls.read(&mut byte))
        .await
        .expect("TLS HTTP connection remained open beyond its header deadline");
    match closed {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) => {}
        other => panic!("unexpected TLS header-timeout read result: {other:?}"),
    }
    frontend.shutdown();
}

#[tokio::test]
async fn tls_frontend_caps_concurrent_handshakes_and_recovers_capacity() {
    const EXPECTED_CONNECTION_CAP: usize = 64;

    let project = tempfile::tempdir().unwrap();
    write_project_cert(project.path(), &["localhost"]);
    let upstream_port = spawn_echo_upstream().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cert_dir = project.path().join(".lpm").join("certs");
    let frontend = start_tls_frontend_on_listener(
        listener,
        &cert_dir.join("cert.pem"),
        &cert_dir.join("key.pem"),
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, upstream_port),
    )
    .await
    .unwrap();
    let mut stalled = Vec::with_capacity(EXPECTED_CONNECTION_CAP);
    for _ in 0..EXPECTED_CONNECTION_CAP {
        stalled.push(
            tokio::net::TcpStream::connect(("127.0.0.1", frontend.port()))
                .await
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(250))
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/capacity", frontend.port());

    let saturated = client.get(&url).send().await;
    assert!(
        saturated.is_err(),
        "TLS frontend accepted more than {EXPECTED_CONNECTION_CAP} concurrent handshakes"
    );

    stalled.pop();
    let recovered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(response) = client.get(&url).send().await {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("TLS frontend did not recover capacity after a stalled client disconnected");
    assert_eq!(recovered.status(), reqwest::StatusCode::OK);

    drop(stalled);
    frontend.shutdown();
}

#[tokio::test]
async fn http_proxy_tunnels_websocket_upgrade_bytes_to_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (upstream_port, upstream_task) = spawn_upgrade_echo_upstream().await;
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    registry
        .lock()
        .await
        .register_routes(123, vec![route("app.localhost", upstream_port)])
        .unwrap();
    let proxy = start_http_proxy(Arc::clone(&registry), 0).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port()))
        .await
        .unwrap();
    stream
        .write_all(
            b"GET /hmr?token=1 HTTP/1.1\r\n\
              host: app.localhost\r\n\
              connection: Upgrade, x-remove-me\r\n\
              upgrade: websocket\r\n\
              x-remove-me: secret\r\n\
              sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              sec-websocket-version: 13\r\n\
              \r\n",
        )
        .await
        .unwrap();

    let response_head = read_raw_http_head(&mut stream).await;
    let response_head = String::from_utf8_lossy(&response_head);
    assert!(
        response_head.starts_with("HTTP/1.1 101"),
        "got {response_head:?}"
    );
    assert!(
        response_head
            .to_ascii_lowercase()
            .contains("upgrade: websocket"),
        "got {response_head:?}"
    );
    assert!(
        !response_head
            .to_ascii_lowercase()
            .contains("x-remove-response"),
        "got {response_head:?}"
    );
    assert!(
        response_head
            .to_ascii_lowercase()
            .contains("x-keep-response: visible"),
        "got {response_head:?}"
    );

    stream.write_all(b"ping\n").await.unwrap();
    let mut response = [0u8; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong\n");
    drop(stream);

    upstream_task.await.unwrap();
    proxy.shutdown();
}

#[tokio::test]
async fn http_proxy_preserves_a_declined_upgrade_response_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0u8; 2048];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 14\r\nConnection: close\r\n\r\nupgrade denied",
            )
            .await
            .unwrap();
    });
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    registry
        .lock()
        .await
        .register_routes(123, vec![route("app.localhost", upstream_port)])
        .unwrap();
    let proxy = start_http_proxy(Arc::clone(&registry), 0).await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/hmr", proxy.port()))
        .header("host", "app.localhost")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();

    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(body, "upgrade denied");
    upstream_task.await.unwrap();
    proxy.shutdown();
}

#[tokio::test]
async fn http_proxy_strips_headers_named_by_the_connection_header() {
    use axum::Router;
    use axum::routing::any;

    async fn inspect_headers(request: axum::extract::Request) -> String {
        format!(
            "removed={} kept={}",
            request.headers().contains_key("x-remove-me"),
            request.headers().contains_key("x-keep-me")
        )
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(inspect_headers)))
            .await
            .unwrap();
    });
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    registry
        .lock()
        .await
        .register_routes(123, vec![route("app.localhost", upstream_port)])
        .unwrap();
    let proxy = start_http_proxy(Arc::clone(&registry), 0).await.unwrap();

    let body = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/headers", proxy.port()))
        .header("host", "app.localhost")
        .header("connection", "keep-alive, x-remove-me")
        .header("x-remove-me", "secret")
        .header("x-keep-me", "visible")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(body, "removed=false kept=true");
    proxy.shutdown();
    upstream_task.abort();
}

#[tokio::test]
async fn http_proxy_strips_response_headers_named_by_the_connection_header() {
    use axum::Router;
    use axum::http::{HeaderValue, header};
    use axum::routing::any;

    async fn response_with_connection_header() -> axum::response::Response {
        let mut response = axum::response::Response::new(axum::body::Body::from("ok"));
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("x-remove-me"));
        response
            .headers_mut()
            .insert("x-remove-me", HeaderValue::from_static("secret"));
        response
            .headers_mut()
            .insert("x-keep-me", HeaderValue::from_static("visible"));
        response
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(response_with_connection_header)),
        )
        .await
        .unwrap();
    });
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    registry
        .lock()
        .await
        .register_routes(123, vec![route("app.localhost", upstream_port)])
        .unwrap();
    let proxy = start_http_proxy(Arc::clone(&registry), 0).await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/headers", proxy.port()))
        .header("host", "app.localhost")
        .send()
        .await
        .unwrap();

    assert!(!response.headers().contains_key("x-remove-me"));
    assert_eq!(response.headers()["x-keep-me"], "visible");
    proxy.shutdown();
    upstream_task.abort();
}

async fn spawn_echo_upstream() -> u16 {
    use axum::Router;
    use axum::routing::any;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().fallback(any(echo_upstream));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

fn write_project_cert(project_dir: &Path, hosts: &[&str]) {
    let (ca_cert_pem, ca_key_pem) =
        lpm_cert::ca::generate_ca_with_options(lpm_cert::ca::CaOptions::default()).unwrap();
    let extra_hostnames = hosts
        .iter()
        .map(|host| (*host).to_string())
        .collect::<Vec<_>>();
    let (cert_pem, key_pem) =
        lpm_cert::cert::generate_project_cert(&ca_cert_pem, &ca_key_pem, &extra_hostnames).unwrap();
    let cert_dir = lpm_cert::paths::project_cert_dir(project_dir).unwrap();
    std::fs::create_dir_all(&cert_dir).unwrap();
    std::fs::write(cert_dir.join("cert.pem"), cert_pem).unwrap();
    lpm_cert::write_key_file(&cert_dir.join("key.pem"), key_pem.as_bytes()).unwrap();
}

#[cfg(all(unix, debug_assertions))]
pub(crate) fn prepare_project_cert(project_dir: &Path, hosts: &[&str]) {
    let hosts = hosts
        .iter()
        .map(|host| (*host).to_string())
        .collect::<Vec<_>>();
    lpm_cert::ensure_https_with_consent(project_dir, &hosts, lpm_cert::TrustStoreConsent::Decline)
        .unwrap();
}

async fn echo_upstream(request: axum::extract::Request) -> String {
    let host = request
        .headers()
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-");
    let host = host.to_string();
    let proto = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-");
    let proto = proto.to_string();
    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_string(), |path| path.as_str().to_string());
    let body = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .unwrap();
    format!(
        "{method} {path} {} host={host} proto={proto}",
        String::from_utf8_lossy(&body)
    )
}

async fn spawn_upgrade_echo_upstream() -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request_head = read_raw_http_head(&mut stream).await;
        let request_head = String::from_utf8_lossy(&request_head);
        assert!(
            request_head.starts_with("GET /hmr?token=1 HTTP/1.1"),
            "got {request_head:?}"
        );
        assert!(
            request_head
                .to_ascii_lowercase()
                .contains("x-forwarded-host: app.localhost"),
            "got {request_head:?}"
        );
        assert!(
            request_head
                .to_ascii_lowercase()
                .contains("upgrade: websocket"),
            "got {request_head:?}"
        );
        assert!(
            !request_head.to_ascii_lowercase().contains("x-remove-me"),
            "got {request_head:?}"
        );
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  connection: upgrade, x-remove-response\r\n\
                  upgrade: websocket\r\n\
                  x-remove-response: secret\r\n\
                  x-keep-response: visible\r\n\
                  sec-websocket-accept: test\r\n\
                  \r\n",
            )
            .await
            .unwrap();
        let mut request = [0u8; 5];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping\n");
        stream.write_all(b"pong\n").await.unwrap();
    });
    (port, handle)
}

async fn read_raw_http_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 128];
    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "connection closed before HTTP head");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_header_end(&buffer) {
            buffer.truncate(index + 4);
            return buffer;
        }
    }
}

#[cfg(unix)]
async fn wait_for_control_server(socket_path: &Path) {
    for _ in 0..50 {
        if let Ok(ProxyResponse::Status { .. }) =
            send_request_to_path(socket_path, ProxyRequest::Status).await
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("control server did not become ready");
}

#[cfg(unix)]
async fn wait_for_empty_control_routes(socket_path: &Path) {
    for _ in 0..50 {
        if let Ok(ProxyResponse::Routes { routes }) =
            send_request_to_path(socket_path, ProxyRequest::List).await
            && routes.is_empty()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("control server did not release connection-backed routes");
}

#[cfg(windows)]
async fn wait_for_control_pipe_server(pipe_name: &str) {
    for _ in 0..50 {
        if let Ok(ProxyResponse::Status { .. }) =
            send_request_to_pipe(pipe_name, ProxyRequest::Status).await
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("control server did not become ready");
}
