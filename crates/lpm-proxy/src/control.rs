use super::*;

#[derive(Debug, Clone, Default)]
pub(crate) struct ProxyListenerAddrs {
    pub(crate) http_addr: Option<String>,
    pub(crate) http_redirect_addr: Option<String>,
    pub(crate) tls_addr: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ControlStreamContext {
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    state_write_lock: Arc<tokio::sync::Mutex<()>>,
    state_path: PathBuf,
    endpoint: String,
    listener_addrs: ProxyListenerAddrs,
    tls_cert_store: Option<TlsCertificateStore>,
}

#[cfg(unix)]
pub async fn serve_control_default() -> Result<(), ProxyError> {
    serve_control_default_with_options(ProxyDaemonOptions::default()).await
}

#[cfg(unix)]
pub async fn serve_control_default_with_options(
    options: ProxyDaemonOptions,
) -> Result<(), ProxyError> {
    let root =
        lpm_common::LpmRoot::from_env().map_err(|err| ProxyError::StatePath(err.to_string()))?;
    ensure_lpm_root(root.root())?;
    serve_control_at_path_with_options(&root.proxy_socket(), &root.proxy_state(), options).await
}

#[cfg(windows)]
pub async fn serve_control_default() -> Result<(), ProxyError> {
    serve_control_default_with_options(ProxyDaemonOptions::default()).await
}

#[cfg(windows)]
pub async fn serve_control_default_with_options(
    options: ProxyDaemonOptions,
) -> Result<(), ProxyError> {
    let root =
        lpm_common::LpmRoot::from_env().map_err(|err| ProxyError::StatePath(err.to_string()))?;
    ensure_lpm_root(root.root())?;
    let pipe_name = proxy_pipe_name_for_root(root.root());
    serve_control_at_pipe_with_options(&pipe_name, &root.proxy_state(), options).await
}

#[cfg(not(any(unix, windows)))]
pub async fn serve_control_default() -> Result<(), ProxyError> {
    Err(ProxyError::IpcUnsupported)
}

#[cfg(not(any(unix, windows)))]
pub async fn serve_control_default_with_options(
    _options: ProxyDaemonOptions,
) -> Result<(), ProxyError> {
    Err(ProxyError::IpcUnsupported)
}

#[cfg(unix)]
pub async fn serve_control_at_path(
    socket_path: &Path,
    state_path: &Path,
) -> Result<(), ProxyError> {
    serve_control_at_path_with_options(socket_path, state_path, ProxyDaemonOptions::default()).await
}

#[cfg(unix)]
pub async fn serve_control_at_path_with_options(
    socket_path: &Path,
    state_path: &Path,
    options: ProxyDaemonOptions,
) -> Result<(), ProxyError> {
    use tokio::net::UnixListener;

    if let Some(parent) = socket_path.parent() {
        ensure_lpm_root(parent)?;
    }
    if socket_path.exists() {
        match send_request_to_path(socket_path, ProxyRequest::Status).await {
            Ok(_) => {
                return Err(ProxyError::Ipc(format!(
                    "local proxy daemon already owns {}",
                    socket_path.display()
                )));
            }
            Err(ProxyError::IpcUnavailable(_)) => {
                std::fs::remove_file(socket_path)
                    .map_err(|err| ProxyError::Ipc(format!("remove stale socket: {err}")))?;
            }
            Err(err) => return Err(err),
        }
    }

    let listener = UnixListener::bind(socket_path)
        .map_err(|err| ProxyError::Ipc(format!("bind {}: {err}", socket_path.display())))?;
    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    let state_write_lock = Arc::new(tokio::sync::Mutex::new(()));
    let tls_cert_store = options.tls_port.map(|_| TlsCertificateStore::default());
    let tls_proxy = match (options.tls_port, tls_cert_store.clone()) {
        (Some(port), Some(cert_store)) => {
            Some(start_tls_proxy(Arc::clone(&registry), cert_store, port).await?)
        }
        _ => None,
    };
    let http_proxy = match options.http_port {
        Some(port) => Some(start_http_proxy(Arc::clone(&registry), port).await?),
        None => None,
    };
    let http_redirect_proxy = match (options.http_redirect_port, tls_proxy.as_ref()) {
        (Some(port), Some(tls_proxy)) => {
            Some(start_http_redirect(Arc::clone(&registry), port, tls_proxy.port()).await?)
        }
        (Some(_), None) => {
            return Err(ProxyError::Http(
                "HTTP redirect listener requires a TLS listener".into(),
            ));
        }
        (None, _) => None,
    };
    let listener_addrs = ProxyListenerAddrs {
        http_addr: http_proxy
            .as_ref()
            .map(|handle| format!("http://{}", handle.addr())),
        http_redirect_addr: http_redirect_proxy
            .as_ref()
            .map(|handle| format!("http://{}", handle.addr())),
        tls_addr: tls_proxy
            .as_ref()
            .map(|handle| format!("https://{}", handle.addr())),
    };
    write_state_file(
        state_path,
        &ProxyDaemonState {
            pid: std::process::id(),
            endpoint: Some(socket_path.display().to_string()),
            http_addr: listener_addrs.http_addr.clone(),
            http_redirect_addr: listener_addrs.http_redirect_addr.clone(),
            tls_addr: listener_addrs.tls_addr.clone(),
            routes: Vec::new(),
        },
    )?;

    let result = serve_unix_listener(
        listener,
        Arc::clone(&registry),
        state_write_lock,
        state_path,
        socket_path,
        listener_addrs,
        tls_cert_store,
    )
    .await;
    drop(http_redirect_proxy);
    drop(tls_proxy);
    drop(http_proxy);
    let _ = std::fs::remove_file(socket_path);
    let _ = std::fs::remove_file(state_path);
    result
}

#[cfg(windows)]
pub async fn serve_control_at_pipe(pipe_name: &str, state_path: &Path) -> Result<(), ProxyError> {
    serve_control_at_pipe_with_options(pipe_name, state_path, ProxyDaemonOptions::default()).await
}

#[cfg(windows)]
pub async fn serve_control_at_pipe_with_options(
    pipe_name: &str,
    state_path: &Path,
    options: ProxyDaemonOptions,
) -> Result<(), ProxyError> {
    match send_request_to_pipe(pipe_name, ProxyRequest::Status).await {
        Ok(_) => {
            return Err(ProxyError::Ipc(format!(
                "local proxy daemon already owns {pipe_name}"
            )));
        }
        Err(ProxyError::IpcUnavailable(_)) => {}
        Err(err) => return Err(err),
    }

    let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
    let state_write_lock = Arc::new(tokio::sync::Mutex::new(()));
    let tls_cert_store = options.tls_port.map(|_| TlsCertificateStore::default());
    let tls_proxy = match (options.tls_port, tls_cert_store.clone()) {
        (Some(port), Some(cert_store)) => {
            Some(start_tls_proxy(Arc::clone(&registry), cert_store, port).await?)
        }
        _ => None,
    };
    let http_proxy = match options.http_port {
        Some(port) => Some(start_http_proxy(Arc::clone(&registry), port).await?),
        None => None,
    };
    let http_redirect_proxy = match (options.http_redirect_port, tls_proxy.as_ref()) {
        (Some(port), Some(tls_proxy)) => {
            Some(start_http_redirect(Arc::clone(&registry), port, tls_proxy.port()).await?)
        }
        (Some(_), None) => {
            return Err(ProxyError::Http(
                "HTTP redirect listener requires a TLS listener".into(),
            ));
        }
        (None, _) => None,
    };
    let listener_addrs = ProxyListenerAddrs {
        http_addr: http_proxy
            .as_ref()
            .map(|handle| format!("http://{}", handle.addr())),
        http_redirect_addr: http_redirect_proxy
            .as_ref()
            .map(|handle| format!("http://{}", handle.addr())),
        tls_addr: tls_proxy
            .as_ref()
            .map(|handle| format!("https://{}", handle.addr())),
    };
    write_state_file(
        state_path,
        &ProxyDaemonState {
            pid: std::process::id(),
            endpoint: Some(pipe_name.to_string()),
            http_addr: listener_addrs.http_addr.clone(),
            http_redirect_addr: listener_addrs.http_redirect_addr.clone(),
            tls_addr: listener_addrs.tls_addr.clone(),
            routes: Vec::new(),
        },
    )?;

    let result = serve_named_pipe_listener(
        pipe_name,
        Arc::clone(&registry),
        state_write_lock,
        state_path,
        listener_addrs,
        tls_cert_store,
    )
    .await;
    drop(http_redirect_proxy);
    drop(tls_proxy);
    drop(http_proxy);
    let _ = std::fs::remove_file(state_path);
    result
}

#[cfg(unix)]
async fn serve_unix_listener(
    listener: tokio::net::UnixListener,
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    state_write_lock: Arc<tokio::sync::Mutex<()>>,
    state_path: &Path,
    socket_path: &Path,
    listener_addrs: ProxyListenerAddrs,
    tls_cert_store: Option<TlsCertificateStore>,
) -> Result<(), ProxyError> {
    let mut prune_interval = tokio::time::interval(Duration::from_secs(5));
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|err| ProxyError::Ipc(format!("accept control connection: {err}")))?;
                if validate_unix_control_peer(&stream).is_err() {
                    continue;
                }
                let context = ControlStreamContext {
                    registry: Arc::clone(&registry),
                    state_write_lock: Arc::clone(&state_write_lock),
                    state_path: state_path.to_path_buf(),
                    endpoint: socket_path.display().to_string(),
                    listener_addrs: listener_addrs.clone(),
                    tls_cert_store: tls_cert_store.clone(),
                };
                let stop_tx = stop_tx.clone();
                tokio::spawn(async move {
                    if matches!(
                        handle_control_stream(
                            stream,
                            context,
                        )
                        .await,
                        Ok(true)
                    ) {
                        let _ = stop_tx.send(());
                    }
                });
            }
            _ = prune_interval.tick() => {
                let removed = registry.lock().await.prune_dead_leases();
                if removed > 0 {
                    write_current_state(&registry, &state_write_lock, state_path, socket_path.display().to_string(), listener_addrs.clone(), tls_cert_store.as_ref()).await?;
                }
            }
            _ = stop_rx.recv() => return Ok(()),
        }
    }
}

#[cfg(windows)]
async fn serve_named_pipe_listener(
    pipe_name: &str,
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    state_write_lock: Arc<tokio::sync::Mutex<()>>,
    state_path: &Path,
    listener_addrs: ProxyListenerAddrs,
    tls_cert_store: Option<TlsCertificateStore>,
) -> Result<(), ProxyError> {
    let expected_client_sid = current_user_sid_sddl()?;
    let mut server = create_named_pipe_server(pipe_name, true, &expected_client_sid)?;
    let mut prune_interval = tokio::time::interval(Duration::from_secs(5));
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    loop {
        tokio::select! {
            connected = server.connect() => {
                connected.map_err(|err| ProxyError::Ipc(format!("accept control pipe connection: {err}")))?;
                let stream = server;
                server = create_named_pipe_server(pipe_name, false, &expected_client_sid)?;
                let context = ControlStreamContext {
                    registry: Arc::clone(&registry),
                    state_write_lock: Arc::clone(&state_write_lock),
                    state_path: state_path.to_path_buf(),
                    endpoint: pipe_name.to_string(),
                    listener_addrs: listener_addrs.clone(),
                    tls_cert_store: tls_cert_store.clone(),
                };
                let stop_tx = stop_tx.clone();
                let expected_client_sid = expected_client_sid.clone();
                tokio::spawn(async move {
                    if matches!(
                        handle_windows_control_stream(
                            stream,
                            context,
                            expected_client_sid,
                        )
                        .await,
                        Ok(true)
                    ) {
                        let _ = stop_tx.send(());
                    }
                });
            }
            _ = prune_interval.tick() => {
                let removed = registry.lock().await.prune_dead_leases();
                if removed > 0 {
                    write_current_state(&registry, &state_write_lock, state_path, pipe_name.to_string(), listener_addrs.clone(), tls_cert_store.as_ref()).await?;
                }
            }
            _ = stop_rx.recv() => return Ok(()),
        }
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) async fn handle_control_stream<S>(
    mut stream: S,
    context: ControlStreamContext,
) -> Result<bool, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = match read_proxy_request(&mut stream).await {
        Ok(request) => request,
        Err(ProxyError::IpcProtocol(message)) if message == EMPTY_CONTROL_FRAME_MESSAGE => {
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    handle_control_request(&mut stream, request, context).await
}

pub(crate) async fn handle_control_request<S>(
    stream: &mut S,
    request: ProxyRequest,
    context: ControlStreamContext,
) -> Result<bool, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let ProxyRequest::RegisterLease { owner_pid, routes } = request {
        return handle_connection_backed_lease_stream(stream, owner_pid, routes, context).await;
    }
    let (response, should_stop) = handle_request(
        &context.registry,
        request,
        context.listener_addrs.clone(),
        context.tls_cert_store.as_ref(),
    )
    .await;
    if !should_stop {
        write_current_state(
            &context.registry,
            &context.state_write_lock,
            &context.state_path,
            context.endpoint.clone(),
            context.listener_addrs.clone(),
            context.tls_cert_store.as_ref(),
        )
        .await?;
    }
    write_response(stream, &response).await?;
    Ok(should_stop)
}

pub(crate) async fn handle_connection_backed_lease_stream<S>(
    stream: &mut S,
    owner_pid: u32,
    routes: Vec<Route>,
    context: ControlStreamContext,
) -> Result<bool, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Err(err) =
        prepare_tls_certificates_if_enabled(context.tls_cert_store.as_ref(), &routes).await
    {
        write_response(
            stream,
            &ProxyResponse::Error {
                message: err.to_string(),
            },
        )
        .await?;
        return Ok(false);
    }

    let lease_id = {
        let mut registry = context.registry.lock().await;
        registry.prune_dead_leases();
        match registry.register_routes(owner_pid, routes) {
            Ok(lease_id) => lease_id,
            Err(err) => {
                write_response(
                    stream,
                    &ProxyResponse::Error {
                        message: err.to_string(),
                    },
                )
                .await?;
                return Ok(false);
            }
        }
    };
    write_current_state(
        &context.registry,
        &context.state_write_lock,
        &context.state_path,
        context.endpoint.clone(),
        context.listener_addrs.clone(),
        context.tls_cert_store.as_ref(),
    )
    .await?;
    write_response(stream, &ProxyResponse::Registered { lease_id }).await?;

    loop {
        let request = match read_proxy_request(stream).await {
            Ok(request) => request,
            Err(ProxyError::IpcProtocol(message)) if message == EMPTY_CONTROL_FRAME_MESSAGE => {
                release_connection_backed_lease(&context, lease_id).await?;
                return Ok(false);
            }
            Err(err) => {
                release_connection_backed_lease(&context, lease_id).await?;
                return Err(err);
            }
        };

        match request {
            ProxyRequest::Release {
                lease_id: requested,
            } if requested == lease_id => {
                let removed = context.registry.lock().await.release(lease_id);
                write_current_state(
                    &context.registry,
                    &context.state_write_lock,
                    &context.state_path,
                    context.endpoint.clone(),
                    context.listener_addrs.clone(),
                    context.tls_cert_store.as_ref(),
                )
                .await?;
                write_response(stream, &ProxyResponse::Released { removed }).await?;
                return Ok(false);
            }
            ProxyRequest::Replace {
                lease_id: requested,
                routes,
            } if requested == lease_id => {
                if let Err(err) =
                    prepare_tls_certificates_if_enabled(context.tls_cert_store.as_ref(), &routes)
                        .await
                {
                    write_response(
                        stream,
                        &ProxyResponse::Error {
                            message: err.to_string(),
                        },
                    )
                    .await?;
                    continue;
                }

                let response = {
                    let mut registry = context.registry.lock().await;
                    registry.prune_dead_leases();
                    match registry.replace_routes(lease_id, routes) {
                        Ok(()) => ProxyResponse::Replaced,
                        Err(err) => ProxyResponse::Error {
                            message: err.to_string(),
                        },
                    }
                };
                write_current_state(
                    &context.registry,
                    &context.state_write_lock,
                    &context.state_path,
                    context.endpoint.clone(),
                    context.listener_addrs.clone(),
                    context.tls_cert_store.as_ref(),
                )
                .await?;
                write_response(stream, &response).await?;
            }
            ProxyRequest::Release { .. } | ProxyRequest::Replace { .. } => {
                write_response(
                    stream,
                    &ProxyResponse::Error {
                        message: format!("lease {lease_id} is bound to this control connection"),
                    },
                )
                .await?;
            }
            ProxyRequest::Register { .. } | ProxyRequest::RegisterLease { .. } => {
                write_response(
                    stream,
                    &ProxyResponse::Error {
                        message: "control connection already owns a lease".to_string(),
                    },
                )
                .await?;
            }
            ProxyRequest::Stop => {
                context.registry.lock().await.release(lease_id);
                write_response(stream, &ProxyResponse::Stopped).await?;
                return Ok(true);
            }
            request => {
                let (response, should_stop) = handle_request(
                    &context.registry,
                    request,
                    context.listener_addrs.clone(),
                    context.tls_cert_store.as_ref(),
                )
                .await;
                if !should_stop {
                    write_current_state(
                        &context.registry,
                        &context.state_write_lock,
                        &context.state_path,
                        context.endpoint.clone(),
                        context.listener_addrs.clone(),
                        context.tls_cert_store.as_ref(),
                    )
                    .await?;
                }
                write_response(stream, &response).await?;
                if should_stop {
                    context.registry.lock().await.release(lease_id);
                    return Ok(true);
                }
            }
        }
    }
}

pub(crate) async fn release_connection_backed_lease(
    context: &ControlStreamContext,
    lease_id: RouteLeaseId,
) -> Result<(), ProxyError> {
    context.registry.lock().await.release(lease_id);
    write_current_state(
        &context.registry,
        &context.state_write_lock,
        &context.state_path,
        context.endpoint.clone(),
        context.listener_addrs.clone(),
        context.tls_cert_store.as_ref(),
    )
    .await
}

pub(crate) async fn write_current_state(
    registry: &tokio::sync::Mutex<RouteRegistry>,
    state_write_lock: &tokio::sync::Mutex<()>,
    state_path: &Path,
    endpoint: String,
    listener_addrs: ProxyListenerAddrs,
    tls_cert_store: Option<&TlsCertificateStore>,
) -> Result<(), ProxyError> {
    let _write_guard = state_write_lock.lock().await;
    let routes = registry.lock().await.statuses();
    if let Some(cert_store) = tls_cert_store {
        refresh_tls_cert_store(cert_store, &routes);
    }
    write_state_file(
        state_path,
        &ProxyDaemonState {
            pid: std::process::id(),
            endpoint: Some(endpoint),
            http_addr: listener_addrs.http_addr,
            http_redirect_addr: listener_addrs.http_redirect_addr,
            tls_addr: listener_addrs.tls_addr,
            routes,
        },
    )
}

pub(crate) async fn handle_request(
    registry: &tokio::sync::Mutex<RouteRegistry>,
    request: ProxyRequest,
    listener_addrs: ProxyListenerAddrs,
    tls_cert_store: Option<&TlsCertificateStore>,
) -> (ProxyResponse, bool) {
    match request {
        ProxyRequest::Status => {
            let mut registry = registry.lock().await;
            registry.prune_dead_leases();
            let routes = registry.statuses();
            (
                ProxyResponse::Status {
                    status: ProxyStatus {
                        running: true,
                        pid: Some(std::process::id()),
                        http_addr: listener_addrs.http_addr,
                        http_redirect_addr: listener_addrs.http_redirect_addr,
                        tls_addr: listener_addrs.tls_addr,
                        routes,
                        stale: false,
                        state_error: None,
                    },
                },
                false,
            )
        }
        ProxyRequest::List => {
            let mut registry = registry.lock().await;
            registry.prune_dead_leases();
            let routes = registry.statuses();
            (ProxyResponse::Routes { routes }, false)
        }
        ProxyRequest::Register { owner_pid, routes }
        | ProxyRequest::RegisterLease { owner_pid, routes } => {
            if let Err(err) = prepare_tls_certificates_if_enabled(tls_cert_store, &routes).await {
                return (
                    ProxyResponse::Error {
                        message: err.to_string(),
                    },
                    false,
                );
            }
            let mut registry = registry.lock().await;
            registry.prune_dead_leases();
            match registry.register_routes(owner_pid, routes) {
                Ok(lease_id) => (ProxyResponse::Registered { lease_id }, false),
                Err(err) => (
                    ProxyResponse::Error {
                        message: err.to_string(),
                    },
                    false,
                ),
            }
        }
        ProxyRequest::Replace { lease_id, routes } => {
            if let Err(err) = prepare_tls_certificates_if_enabled(tls_cert_store, &routes).await {
                return (
                    ProxyResponse::Error {
                        message: err.to_string(),
                    },
                    false,
                );
            }
            let mut registry = registry.lock().await;
            registry.prune_dead_leases();
            match registry.replace_routes(lease_id, routes) {
                Ok(()) => (ProxyResponse::Replaced, false),
                Err(err) => (
                    ProxyResponse::Error {
                        message: err.to_string(),
                    },
                    false,
                ),
            }
        }
        ProxyRequest::Release { lease_id } => {
            let mut registry = registry.lock().await;
            let removed = registry.release(lease_id);
            (ProxyResponse::Released { removed }, false)
        }
        ProxyRequest::Stop => (ProxyResponse::Stopped, true),
    }
}
