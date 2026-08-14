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
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel::<()>(1);
    let capacity = Arc::new(tokio::sync::Semaphore::new(CONTROL_CONNECTION_LIMIT));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|err| ProxyError::Ipc(format!("accept control connection: {err}")))?;
                if validate_unix_control_peer(&stream).is_err() {
                    continue;
                }
                let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
                    continue;
                };
                let context = ControlStreamContext {
                    registry: Arc::clone(&registry),
                    state_write_lock: Arc::clone(&state_write_lock),
                    state_path: state_path.to_path_buf(),
                    endpoint: socket_path.display().to_string(),
                    listener_addrs: listener_addrs.clone(),
                    tls_cert_store: tls_cert_store.clone(),
                };
                let stop_tx = stop_tx.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if matches!(
                        handle_control_stream(
                            stream,
                            context,
                        )
                        .await,
                        Ok(true)
                    ) {
                        let _ = stop_tx.try_send(());
                    }
                });
            }
            _ = prune_interval.tick() => {
                let removed = registry.lock().await.prune_dead_leases();
                if removed > 0 {
                    write_current_state(&registry, &state_write_lock, state_path, socket_path.display().to_string(), listener_addrs.clone(), tls_cert_store.as_ref()).await?;
                }
            }
            _ = stop_rx.recv() => break,
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
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
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel::<()>(1);
    let capacity = Arc::new(tokio::sync::Semaphore::new(CONTROL_CONNECTION_LIMIT));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        tokio::select! {
            connected = server.connect() => {
                connected.map_err(|err| ProxyError::Ipc(format!("accept control pipe connection: {err}")))?;
                let stream = server;
                server = create_named_pipe_server(pipe_name, false, &expected_client_sid)?;
                let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
                    continue;
                };
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
                connections.spawn(async move {
                    let _permit = permit;
                    if matches!(
                        handle_windows_control_stream(
                            stream,
                            context,
                            expected_client_sid,
                        )
                        .await,
                        Ok(true)
                    ) {
                        let _ = stop_tx.try_send(());
                    }
                });
            }
            _ = prune_interval.tick() => {
                let removed = registry.lock().await.prune_dead_leases();
                if removed > 0 {
                    write_current_state(&registry, &state_write_lock, state_path, pipe_name.to_string(), listener_addrs.clone(), tls_cert_store.as_ref()).await?;
                }
            }
            _ = stop_rx.recv() => break,
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) async fn handle_control_stream<S>(
    mut stream: S,
    context: ControlStreamContext,
) -> Result<bool, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = match read_proxy_request_with_timeout(&mut stream).await {
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
    match request {
        ProxyRequest::RegisterLease { owner_pid, routes } => {
            return handle_connection_backed_lease_stream(stream, owner_pid, routes, context).await;
        }
        ProxyRequest::RegisterStagedLease { owner_pid } => {
            return handle_connection_backed_staged_lease_stream(stream, owner_pid, context).await;
        }
        request @ (ProxyRequest::Register { .. }
        | ProxyRequest::Replace { .. }
        | ProxyRequest::Release { .. }) => {
            return handle_transactional_request(stream, request, context).await;
        }
        request => {
            let (response, should_stop) =
                handle_request(&context.registry, request, context.listener_addrs.clone()).await;
            write_response(stream, &response).await?;
            Ok(should_stop)
        }
    }
}

async fn handle_transactional_request<S>(
    stream: &mut S,
    request: ProxyRequest,
    context: ControlStreamContext,
) -> Result<bool, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let routes = match &request {
        ProxyRequest::Register { routes, .. } | ProxyRequest::Replace { routes, .. } => {
            Some(routes.as_slice())
        }
        ProxyRequest::Release { .. } => None,
        _ => {
            return Err(ProxyError::IpcProtocol(
                "unsupported transactional control request".to_string(),
            ));
        }
    };
    if let Some(routes) = routes
        && let Err(error) =
            prepare_tls_certificates_if_enabled(context.tls_cert_store.as_ref(), routes).await
    {
        write_response(
            stream,
            &ProxyResponse::Error {
                message: error.to_string(),
            },
        )
        .await?;
        return Ok(false);
    }

    let _write_guard = context.state_write_lock.lock().await;
    let previous_registry = context.registry.lock().await.clone();
    let previous_certificates = context
        .tls_cert_store
        .as_ref()
        .map(TlsCertificateStore::snapshot)
        .transpose()?;
    let (response, should_stop) =
        handle_request(&context.registry, request, context.listener_addrs.clone()).await;
    if matches!(response, ProxyResponse::Error { .. }) {
        write_response(stream, &response).await?;
        return Ok(should_stop);
    }

    if let Err(write_error) = write_current_state_locked(
        &context.registry,
        &context.state_path,
        &context.endpoint,
        &context.listener_addrs,
        context.tls_cert_store.as_ref(),
    )
    .await
    {
        *context.registry.lock().await = previous_registry;
        if let (Some(cert_store), Some(previous_certificates)) =
            (context.tls_cert_store.as_ref(), previous_certificates)
            && let Err(restore_error) = cert_store.replace(previous_certificates)
        {
            return Err(ProxyError::StateWrite(format!(
                "{write_error}; restoring the previous TLS certificate store also failed: {restore_error}"
            )));
        }
        write_response(
            stream,
            &ProxyResponse::Error {
                message: write_error.to_string(),
            },
        )
        .await?;
        return Ok(false);
    }

    if let Err(response_error) = write_response(stream, &response).await {
        *context.registry.lock().await = previous_registry;
        if let (Some(cert_store), Some(previous_certificates)) =
            (context.tls_cert_store.as_ref(), previous_certificates)
            && let Err(restore_error) = cert_store.replace(previous_certificates)
        {
            return Err(ProxyError::Ipc(format!(
                "{response_error}; restoring the previous TLS certificate store also failed: {restore_error}"
            )));
        }
        if let Err(restore_error) = write_current_state_locked(
            &context.registry,
            &context.state_path,
            &context.endpoint,
            &context.listener_addrs,
            context.tls_cert_store.as_ref(),
        )
        .await
        {
            return Err(ProxyError::Ipc(format!(
                "{response_error}; restoring the previous proxy state also failed: {restore_error}"
            )));
        }
        return Err(response_error);
    }
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
    handle_connection_backed_lease_stream_inner(stream, owner_pid, Some(routes), context).await
}

async fn handle_connection_backed_staged_lease_stream<S>(
    stream: &mut S,
    owner_pid: u32,
    context: ControlStreamContext,
) -> Result<bool, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    handle_connection_backed_lease_stream_inner(stream, owner_pid, None, context).await
}

async fn handle_connection_backed_lease_stream_inner<S>(
    stream: &mut S,
    owner_pid: u32,
    initial_routes: Option<Vec<Route>>,
    context: ControlStreamContext,
) -> Result<bool, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Some(routes) = initial_routes.as_deref()
        && let Err(err) =
            prepare_tls_certificates_if_enabled(context.tls_cert_store.as_ref(), routes).await
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
        let registration = match initial_routes {
            Some(routes) => registry.register_routes(owner_pid, routes),
            None => Ok(registry.register_lease(owner_pid)),
        };
        match registration {
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
    let result = async {
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

        let mut staged_routes = None::<(u64, Vec<Route>)>;
        loop {
        let request = match read_proxy_request_after_activity(stream).await {
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
            ProxyRequest::Stage {
                lease_id: requested,
                publication_id,
                routes,
            } if requested == lease_id => {
                if staged_routes.is_some() {
                    write_response(
                        stream,
                        &ProxyResponse::Error {
                            message: "a proxy route publication is already staged".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }
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
                let validation = {
                    let mut registry = context.registry.lock().await;
                    registry.prune_dead_leases();
                    registry.validate_replacement(lease_id, &routes)
                };
                match validation {
                    Ok(()) => {
                        staged_routes = Some((publication_id, routes));
                        write_response(stream, &ProxyResponse::Staged { publication_id }).await?;
                    }
                    Err(err) => {
                        write_response(
                            stream,
                            &ProxyResponse::Error {
                                message: err.to_string(),
                            },
                        )
                        .await?;
                    }
                }
            }
            ProxyRequest::Commit {
                lease_id: requested,
                publication_id,
            } if requested == lease_id => {
                let Some((staged_id, _)) = staged_routes.as_ref() else {
                    write_response(
                        stream,
                        &ProxyResponse::Error {
                            message: "no proxy route publication is staged".to_string(),
                        },
                    )
                    .await?;
                    continue;
                };
                if *staged_id != publication_id {
                    write_response(
                        stream,
                        &ProxyResponse::Error {
                            message: format!(
                                "proxy route publication {publication_id} does not match staged publication {staged_id}"
                            ),
                        },
                    )
                    .await?;
                    continue;
                }
                let Some((_, routes)) = staged_routes.as_ref() else {
                    continue;
                };
                let routes = routes.clone();
                let response =
                    match commit_connection_backed_routes(&context, lease_id, routes).await {
                        Ok(()) => {
                            staged_routes = None;
                            ProxyResponse::Committed { publication_id }
                        }
                        Err(err) => ProxyResponse::Error {
                            message: err.to_string(),
                        },
                    };
                write_response(stream, &response).await?;
            }
            ProxyRequest::Rollback {
                lease_id: requested,
                publication_id,
            } if requested == lease_id => {
                let matches = staged_routes
                    .as_ref()
                    .is_some_and(|(staged_id, _)| *staged_id == publication_id);
                if matches {
                    staged_routes = None;
                    write_response(stream, &ProxyResponse::RolledBack { publication_id }).await?;
                } else {
                    write_response(
                        stream,
                        &ProxyResponse::Error {
                            message: format!(
                                "proxy route publication {publication_id} is not staged"
                            ),
                        },
                    )
                    .await?;
                }
            }
            ProxyRequest::Release {
                lease_id: requested,
            } if requested == lease_id => {
                match commit_connection_backed_release(&context, lease_id).await {
                    Ok(removed) => {
                        write_response(stream, &ProxyResponse::Released { removed }).await?;
                        return Ok(false);
                    }
                    Err(error) => {
                        write_response(
                            stream,
                            &ProxyResponse::Error {
                                message: error.to_string(),
                            },
                        )
                        .await?;
                    }
                }
            }
            ProxyRequest::Replace {
                lease_id: requested,
                routes,
            } if requested == lease_id => {
                if !routes.is_empty()
                    && let Err(err) = prepare_tls_certificates_if_enabled(
                        context.tls_cert_store.as_ref(),
                        &routes,
                    )
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

                let response = match commit_connection_backed_routes(&context, lease_id, routes)
                    .await
                {
                    Ok(()) => ProxyResponse::Replaced,
                    Err(err) => ProxyResponse::Error {
                        message: err.to_string(),
                    },
                };
                write_response(stream, &response).await?;
            }
            ProxyRequest::Release { .. }
            | ProxyRequest::Replace { .. }
            | ProxyRequest::Stage { .. }
            | ProxyRequest::Commit { .. }
            | ProxyRequest::Rollback { .. } => {
                write_response(
                    stream,
                    &ProxyResponse::Error {
                        message: format!("lease {lease_id} is bound to this control connection"),
                    },
                )
                .await?;
            }
            ProxyRequest::Register { .. }
            | ProxyRequest::RegisterLease { .. }
            | ProxyRequest::RegisterStagedLease { .. } => {
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
                )
                .await;
                write_response(stream, &response).await?;
                if should_stop {
                    context.registry.lock().await.release(lease_id);
                    return Ok(true);
                }
            }
        }
    }
    }
    .await;
    let cleanup = release_connection_backed_lease(&context, lease_id).await;
    match (result, cleanup) {
        (Ok(should_stop), Ok(())) => Ok(should_stop),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(ProxyError::Ipc(format!(
            "connection-backed proxy lease failed: {error}; lease cleanup also failed: {cleanup_error}"
        ))),
    }
}

async fn commit_connection_backed_routes(
    context: &ControlStreamContext,
    lease_id: RouteLeaseId,
    routes: Vec<Route>,
) -> Result<(), ProxyError> {
    let _write_guard = context.state_write_lock.lock().await;
    let mut registry = context.registry.lock().await;
    registry.prune_dead_leases();
    let previous_routes = registry.routes_for_lease(lease_id);
    let previous_certificates = context
        .tls_cert_store
        .as_ref()
        .map(TlsCertificateStore::snapshot)
        .transpose()?;
    if routes.is_empty() {
        registry.restore_routes_for_lease(lease_id, routes)?;
    } else {
        registry.replace_routes(lease_id, routes)?;
    }
    let published_routes = registry.statuses();
    if let Some(cert_store) = context.tls_cert_store.as_ref()
        && let Err(refresh_error) = refresh_tls_cert_store(cert_store, &published_routes)
    {
        if let Err(restore_error) = registry.restore_routes_for_lease(lease_id, previous_routes) {
            return Err(ProxyError::Tls(format!(
                "{refresh_error}; restoring the previous routes also failed: {restore_error}"
            )));
        }
        return Err(refresh_error);
    }
    let write_result = write_state_file(
        &context.state_path,
        &ProxyDaemonState {
            pid: std::process::id(),
            endpoint: Some(context.endpoint.clone()),
            http_addr: context.listener_addrs.http_addr.clone(),
            http_redirect_addr: context.listener_addrs.http_redirect_addr.clone(),
            tls_addr: context.listener_addrs.tls_addr.clone(),
            routes: published_routes,
        },
    );
    if let Err(write_error) = write_result {
        if let Err(restore_error) = registry.restore_routes_for_lease(lease_id, previous_routes) {
            return Err(ProxyError::StateWrite(format!(
                "{write_error}; restoring the previous in-memory routes also failed: {restore_error}"
            )));
        }
        if let (Some(cert_store), Some(previous_certificates)) =
            (context.tls_cert_store.as_ref(), previous_certificates)
            && let Err(restore_error) = cert_store.replace(previous_certificates)
        {
            return Err(ProxyError::StateWrite(format!(
                "{write_error}; restoring the previous TLS certificate store also failed: {restore_error}"
            )));
        }
        return Err(write_error);
    }
    Ok(())
}

async fn commit_connection_backed_release(
    context: &ControlStreamContext,
    lease_id: RouteLeaseId,
) -> Result<usize, ProxyError> {
    let _write_guard = context.state_write_lock.lock().await;
    let mut registry = context.registry.lock().await;
    let previous_registry = registry.clone();
    let previous_certificates = context
        .tls_cert_store
        .as_ref()
        .map(TlsCertificateStore::snapshot)
        .transpose()?;
    let removed = registry.release(lease_id);
    let published_routes = registry.statuses();
    if let Some(cert_store) = context.tls_cert_store.as_ref()
        && let Err(refresh_error) = refresh_tls_cert_store(cert_store, &published_routes)
    {
        *registry = previous_registry;
        return Err(refresh_error);
    }
    let write_result = write_state_file(
        &context.state_path,
        &ProxyDaemonState {
            pid: std::process::id(),
            endpoint: Some(context.endpoint.clone()),
            http_addr: context.listener_addrs.http_addr.clone(),
            http_redirect_addr: context.listener_addrs.http_redirect_addr.clone(),
            tls_addr: context.listener_addrs.tls_addr.clone(),
            routes: published_routes,
        },
    );
    if let Err(write_error) = write_result {
        *registry = previous_registry;
        if let (Some(cert_store), Some(previous_certificates)) =
            (context.tls_cert_store.as_ref(), previous_certificates)
            && let Err(restore_error) = cert_store.replace(previous_certificates)
        {
            return Err(ProxyError::StateWrite(format!(
                "{write_error}; restoring the previous TLS certificate store also failed: {restore_error}"
            )));
        }
        return Err(write_error);
    }
    Ok(removed)
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
    let previous_certificates = tls_cert_store
        .map(TlsCertificateStore::snapshot)
        .transpose()?;
    let write_result = write_current_state_locked(
        registry,
        state_path,
        &endpoint,
        &listener_addrs,
        tls_cert_store,
    )
    .await;
    if let Err(write_error) = write_result {
        if let (Some(cert_store), Some(previous_certificates)) =
            (tls_cert_store, previous_certificates)
            && let Err(restore_error) = cert_store.replace(previous_certificates)
        {
            return Err(ProxyError::StateWrite(format!(
                "{write_error}; restoring the previous TLS certificate store also failed: {restore_error}"
            )));
        }
        return Err(write_error);
    }
    Ok(())
}

async fn write_current_state_locked(
    registry: &tokio::sync::Mutex<RouteRegistry>,
    state_path: &Path,
    endpoint: &str,
    listener_addrs: &ProxyListenerAddrs,
    tls_cert_store: Option<&TlsCertificateStore>,
) -> Result<(), ProxyError> {
    let routes = registry.lock().await.statuses();
    if let Some(cert_store) = tls_cert_store {
        refresh_tls_cert_store(cert_store, &routes)?;
    }
    write_state_file(
        state_path,
        &ProxyDaemonState {
            pid: std::process::id(),
            endpoint: Some(endpoint.to_string()),
            http_addr: listener_addrs.http_addr.clone(),
            http_redirect_addr: listener_addrs.http_redirect_addr.clone(),
            tls_addr: listener_addrs.tls_addr.clone(),
            routes,
        },
    )
}

pub(crate) async fn handle_request(
    registry: &tokio::sync::Mutex<RouteRegistry>,
    request: ProxyRequest,
    listener_addrs: ProxyListenerAddrs,
) -> (ProxyResponse, bool) {
    match request {
        ProxyRequest::Status => {
            let registry = registry.lock().await;
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
            let registry = registry.lock().await;
            let routes = registry.statuses();
            (ProxyResponse::Routes { routes }, false)
        }
        ProxyRequest::Register { owner_pid, routes }
        | ProxyRequest::RegisterLease { owner_pid, routes } => {
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
        ProxyRequest::RegisterStagedLease { owner_pid } => {
            let mut registry = registry.lock().await;
            registry.prune_dead_leases();
            let lease_id = registry.register_lease(owner_pid);
            (ProxyResponse::Registered { lease_id }, false)
        }
        ProxyRequest::Replace { lease_id, routes } => {
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
        ProxyRequest::Stage { .. }
        | ProxyRequest::Commit { .. }
        | ProxyRequest::Rollback { .. } => (
            ProxyResponse::Error {
                message: "staged proxy publications require their lease connection".to_string(),
            },
            false,
        ),
        ProxyRequest::Stop => (ProxyResponse::Stopped, true),
    }
}

#[cfg(test)]
mod connection_cleanup_tests {
    use super::*;

    #[tokio::test]
    async fn failed_registration_response_releases_the_connection_backed_lease() {
        let temp = tempfile::tempdir().unwrap();
        let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
        let context = ControlStreamContext {
            registry: Arc::clone(&registry),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path: temp.path().join("proxy.json"),
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: None,
        };
        let (mut server, client) = tokio::io::duplex(1024);
        drop(client);
        let routes = vec![Route {
            host: "app.localhost".to_string(),
            upstream_port: 3000,
            project_dir: temp.path().to_path_buf(),
            service: Some("web".to_string()),
        }];

        handle_connection_backed_lease_stream(&mut server, std::process::id(), routes, context)
            .await
            .unwrap_err();

        assert!(registry.lock().await.statuses().is_empty());
    }

    #[tokio::test]
    async fn failed_legacy_registration_state_write_restores_the_registry() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("proxy.json");
        std::fs::create_dir(&state_path).unwrap();
        let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
        let context = ControlStreamContext {
            registry: Arc::clone(&registry),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path,
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: None,
        };
        let (mut server, _client) = tokio::io::duplex(1024);

        let _ = handle_control_request(
            &mut server,
            ProxyRequest::Register {
                owner_pid: std::process::id(),
                routes: vec![Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 3000,
                    project_dir: temp.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
            context,
        )
        .await;

        assert!(registry.lock().await.statuses().is_empty());
    }

    #[tokio::test]
    async fn failed_legacy_replace_state_write_restores_the_previous_routes() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("proxy.json");
        std::fs::create_dir(&state_path).unwrap();
        let mut initial = RouteRegistry::new();
        let lease_id = initial
            .register_routes(
                std::process::id(),
                vec![Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 3000,
                    project_dir: temp.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            )
            .unwrap();
        let registry = Arc::new(tokio::sync::Mutex::new(initial));
        let context = ControlStreamContext {
            registry: Arc::clone(&registry),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path,
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: None,
        };
        let (mut server, _client) = tokio::io::duplex(1024);

        let _ = handle_control_request(
            &mut server,
            ProxyRequest::Replace {
                lease_id,
                routes: vec![Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 4000,
                    project_dir: temp.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
            context,
        )
        .await;

        assert_eq!(
            registry
                .lock()
                .await
                .lookup_host("app.localhost")
                .unwrap()
                .upstream_port,
            3000
        );
    }

    #[tokio::test]
    async fn failed_legacy_registration_response_restores_registry_and_state() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("proxy.json");
        let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
        let context = ControlStreamContext {
            registry: Arc::clone(&registry),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path: state_path.clone(),
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: None,
        };
        let (mut server, _client) = tokio::io::duplex(1);

        handle_control_request(
            &mut server,
            ProxyRequest::Register {
                owner_pid: std::process::id(),
                routes: vec![Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 3000,
                    project_dir: temp.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
            context,
        )
        .await
        .unwrap_err();

        assert!(registry.lock().await.statuses().is_empty());
        let persisted: ProxyDaemonState =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert!(persisted.routes.is_empty());
    }

    #[tokio::test]
    async fn failed_connection_replace_keeps_the_previous_published_routes() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("proxy.json");
        let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
        let context = ControlStreamContext {
            registry: Arc::clone(&registry),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path: state_path.clone(),
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: None,
        };
        let (server, mut client) = tokio::io::duplex(4096);
        let handler = tokio::spawn(handle_control_stream(server, context));
        let registered = send_request_on_stream_ref(
            &mut client,
            ProxyRequest::RegisterLease {
                owner_pid: std::process::id(),
                routes: vec![Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 3000,
                    project_dir: temp.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
        )
        .await
        .unwrap();
        let ProxyResponse::Registered { lease_id } = registered else {
            panic!("expected registered response, got {registered:?}");
        };
        std::fs::remove_file(&state_path).unwrap();
        std::fs::create_dir(&state_path).unwrap();

        let response = send_request_on_stream_ref(
            &mut client,
            ProxyRequest::Replace {
                lease_id,
                routes: vec![Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 4000,
                    project_dir: temp.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
        )
        .await;

        assert!(matches!(response, Ok(ProxyResponse::Error { .. })));
        assert_eq!(
            registry
                .lock()
                .await
                .lookup_host("app.localhost")
                .unwrap()
                .upstream_port,
            3000
        );
        handler.abort();
    }

    #[tokio::test]
    async fn failed_connection_release_keeps_the_lease_published() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("proxy.json");
        let registry = Arc::new(tokio::sync::Mutex::new(RouteRegistry::new()));
        let context = ControlStreamContext {
            registry: Arc::clone(&registry),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path: state_path.clone(),
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: None,
        };
        let (server, mut client) = tokio::io::duplex(4096);
        let handler = tokio::spawn(handle_control_stream(server, context));
        let registered = send_request_on_stream_ref(
            &mut client,
            ProxyRequest::RegisterLease {
                owner_pid: std::process::id(),
                routes: vec![Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 3000,
                    project_dir: temp.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
        )
        .await
        .unwrap();
        let ProxyResponse::Registered { lease_id } = registered else {
            panic!("expected registered response, got {registered:?}");
        };
        std::fs::remove_file(&state_path).unwrap();
        std::fs::create_dir(&state_path).unwrap();

        let response =
            send_request_on_stream_ref(&mut client, ProxyRequest::Release { lease_id }).await;

        assert!(matches!(response, Ok(ProxyResponse::Error { .. })));
        assert!(registry.lock().await.lookup_host("app.localhost").is_some());
        handler.abort();
    }

    #[tokio::test]
    async fn control_stream_times_out_before_an_initial_frame() {
        let temp = tempfile::tempdir().unwrap();
        let context = ControlStreamContext {
            registry: Arc::new(tokio::sync::Mutex::new(RouteRegistry::new())),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path: temp.path().join("proxy.json"),
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: None,
        };
        let (server, _silent_client) = tokio::io::duplex(64);

        let error = tokio::time::timeout(
            IPC_REQUEST_TIMEOUT + Duration::from_millis(500),
            handle_control_stream(server, context),
        )
        .await
        .expect("control stream retained a client past the initial-frame deadline")
        .unwrap_err();

        assert!(error.to_string().contains("timed out"), "got {error}");
    }

    #[tokio::test]
    async fn lease_stream_times_out_after_a_partial_control_frame() {
        use tokio::io::AsyncWriteExt;

        let temp = tempfile::tempdir().unwrap();
        let context = ControlStreamContext {
            registry: Arc::new(tokio::sync::Mutex::new(RouteRegistry::new())),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path: temp.path().join("proxy.json"),
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: None,
        };
        let (server, mut client) = tokio::io::duplex(1024);
        let handler = tokio::spawn(handle_control_stream(server, context));
        let registered = send_request_on_stream_ref(
            &mut client,
            ProxyRequest::RegisterStagedLease {
                owner_pid: std::process::id(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(registered, ProxyResponse::Registered { .. }));
        client.write_all(b"{").await.unwrap();

        let error = tokio::time::timeout(IPC_REQUEST_TIMEOUT + Duration::from_millis(500), handler)
            .await
            .expect("lease stream retained a partial control frame past its deadline")
            .unwrap()
            .unwrap_err();

        assert!(error.to_string().contains("timed out"), "got {error}");
    }

    #[cfg(all(unix, debug_assertions))]
    #[tokio::test]
    async fn failed_commit_certificate_refresh_restores_routes_and_tls_store() {
        let (_home, _guard) = crate::tests::setup_cert_home_async().await;
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        crate::tests::prepare_project_cert(&project, &["app.localhost"]);
        let mut initial_registry = RouteRegistry::new();
        let lease_id = initial_registry
            .register_routes(
                std::process::id(),
                vec![Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 3000,
                    project_dir: project.clone(),
                    service: Some("web".to_string()),
                }],
            )
            .unwrap();
        let tls_cert_store = TlsCertificateStore::default();
        refresh_tls_cert_store(&tls_cert_store, &initial_registry.statuses()).unwrap();
        std::fs::remove_file(project.join(".lpm/certs/key.pem")).unwrap();
        let registry = Arc::new(tokio::sync::Mutex::new(initial_registry));
        let context = ControlStreamContext {
            registry: Arc::clone(&registry),
            state_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            state_path: temp.path().join("proxy.json"),
            endpoint: "test-endpoint".to_string(),
            listener_addrs: ProxyListenerAddrs::default(),
            tls_cert_store: Some(tls_cert_store.clone()),
        };

        commit_connection_backed_routes(
            &context,
            lease_id,
            vec![Route {
                host: "app.localhost".to_string(),
                upstream_port: 4000,
                project_dir: project,
                service: Some("web".to_string()),
            }],
        )
        .await
        .unwrap_err();

        let routes = registry.lock().await.statuses();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].upstream_port, 3000);
        assert!(tls_cert_store.get("app.localhost").is_some());
    }
}
