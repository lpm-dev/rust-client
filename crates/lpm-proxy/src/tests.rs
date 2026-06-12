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

#[cfg(unix)]
async fn cert_env_guard() -> tokio::sync::MutexGuard<'static, ()> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[cfg(unix)]
async fn setup_cert_home() -> (tempfile::TempDir, tokio::sync::MutexGuard<'static, ()>) {
    let guard = cert_env_guard().await;
    let home = tempfile::tempdir().unwrap();
    // SAFETY: cert tests serialize this helper with `cert_env_guard`, so
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
    (home, guard)
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
fn tls_cert_store_loads_project_leaf_for_registered_host() {
    let project = tempfile::tempdir().unwrap();
    write_project_cert(project.path(), &["app.localhost"]);
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
    );

    assert!(store.get("APP.localhost").is_some());
    assert!(store.get("api.localhost").is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn tls_control_daemon_prepares_project_leaf_when_route_registers() {
    let (_home, _guard) = setup_cert_home().await;
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
async fn route_lease_release_uses_connection_backed_control_stream() {
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

#[tokio::test]
async fn tls_proxy_routes_registered_host_to_upstream_and_marks_https() {
    let project = tempfile::tempdir().unwrap();
    write_project_cert(project.path(), &["app.localhost"]);
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
    refresh_tls_cert_store(&cert_store, &registry.lock().await.statuses());
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
              connection: Upgrade\r\n\
              upgrade: websocket\r\n\
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

    stream.write_all(b"ping\n").await.unwrap();
    let mut response = [0u8; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong\n");
    drop(stream);

    upstream_task.await.unwrap();
    proxy.shutdown();
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
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  connection: upgrade\r\n\
                  upgrade: websocket\r\n\
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
