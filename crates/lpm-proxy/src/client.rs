use super::*;

#[derive(Debug)]
pub(crate) enum LeaseConnection {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    NamedPipe(tokio::net::windows::named_pipe::NamedPipeClient),
}

#[derive(Debug)]
pub struct RouteLease {
    pub(crate) lease_id: Option<RouteLeaseId>,
    pub(crate) connection: Option<LeaseConnection>,
    #[cfg(unix)]
    pub(crate) socket_path: Option<PathBuf>,
    #[cfg(windows)]
    pub(crate) pipe_name: Option<String>,
}

impl RouteLease {
    pub fn lease_id(&self) -> Option<RouteLeaseId> {
        self.lease_id
    }

    pub async fn release(&mut self) -> Result<usize, ProxyError> {
        let Some(lease_id) = self.lease_id else {
            return Ok(0);
        };
        let result = if let Some(mut connection) = self.connection.take() {
            match tokio::time::timeout(
                CONTROL_CONNECTION_RELEASE_TIMEOUT,
                release_lease_on_connection(&mut connection, lease_id),
            )
            .await
            {
                Err(_) => match self.release_via_endpoint(lease_id).await {
                    Ok(removed) => Ok(removed),
                    Err(endpoint_err) => Err(ProxyError::Ipc(format!(
                        "connection release timed out; endpoint release failed: {endpoint_err}"
                    ))),
                },
                Ok(Ok(removed)) => Ok(removed),
                Ok(Err(connection_err)) => match self.release_via_endpoint(lease_id).await {
                    Ok(removed) => Ok(removed),
                    Err(endpoint_err) => Err(ProxyError::Ipc(format!(
                        "connection release failed: {connection_err}; endpoint release failed: {endpoint_err}"
                    ))),
                },
            }
        } else {
            self.release_via_endpoint(lease_id).await
        };
        if result.is_ok() {
            self.lease_id = None;
        }
        result
    }

    async fn release_via_endpoint(&self, lease_id: RouteLeaseId) -> Result<usize, ProxyError> {
        #[cfg(unix)]
        if let Some(socket_path) = self.socket_path.as_deref() {
            return release_lease_to_path(socket_path, lease_id).await;
        }
        #[cfg(windows)]
        if let Some(pipe_name) = self.pipe_name.as_deref() {
            return release_lease_to_pipe(pipe_name, lease_id).await;
        }
        release_lease(lease_id).await
    }
}

impl Drop for RouteLease {
    fn drop(&mut self) {
        let Some(lease_id) = self.lease_id.take() else {
            return;
        };
        if self.connection.take().is_some() {
            return;
        }
        #[cfg(unix)]
        let socket_path = self.socket_path.clone();
        #[cfg(not(unix))]
        let socket_path = None;
        #[cfg(windows)]
        let pipe_name = self.pipe_name.clone();
        #[cfg(not(windows))]
        let pipe_name = None;
        release_lease_best_effort(lease_id, socket_path, pipe_name);
    }
}

pub async fn status() -> Result<ProxyStatus, ProxyError> {
    match send_request(ProxyRequest::Status).await {
        Ok(ProxyResponse::Status { status }) => Ok(status),
        Ok(ProxyResponse::Error { message }) => {
            Ok(ProxyStatus::stale(None, None, None, None, Some(message)))
        }
        Ok(other) => Err(ProxyError::IpcProtocol(format!(
            "expected status response, got {other:?}"
        ))),
        Err(ProxyError::IpcUnavailable(_)) | Err(ProxyError::IpcUnsupported) => read_status(),
        Err(err) => Err(err),
    }
}

pub async fn register(routes: Vec<Route>) -> Result<RouteLease, ProxyError> {
    #[cfg(unix)]
    {
        let socket_path = proxy_socket_path_from_env()?;
        let (lease_id, stream) = register_lease_to_path(&socket_path, routes).await?;
        Ok(RouteLease {
            lease_id: Some(lease_id),
            connection: Some(LeaseConnection::Unix(stream)),
            socket_path: Some(socket_path),
        })
    }

    #[cfg(windows)]
    {
        let pipe_name = proxy_pipe_name_from_env()?;
        let (lease_id, client) = register_lease_to_pipe(&pipe_name, routes).await?;
        Ok(RouteLease {
            lease_id: Some(lease_id),
            connection: Some(LeaseConnection::NamedPipe(client)),
            pipe_name: Some(pipe_name),
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = routes;
        Err(ProxyError::IpcUnsupported)
    }
}

pub(crate) async fn release_lease(lease_id: RouteLeaseId) -> Result<usize, ProxyError> {
    match send_request(ProxyRequest::Release { lease_id }).await? {
        ProxyResponse::Released { removed } => Ok(removed),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected release response, got {other:?}"
        ))),
    }
}

#[cfg(unix)]
pub(crate) async fn release_lease_to_path(
    socket_path: &Path,
    lease_id: RouteLeaseId,
) -> Result<usize, ProxyError> {
    match send_request_to_path(socket_path, ProxyRequest::Release { lease_id }).await? {
        ProxyResponse::Released { removed } => Ok(removed),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected release response, got {other:?}"
        ))),
    }
}

#[cfg(windows)]
pub(crate) async fn release_lease_to_pipe(
    pipe_name: &str,
    lease_id: RouteLeaseId,
) -> Result<usize, ProxyError> {
    match send_request_to_pipe(pipe_name, ProxyRequest::Release { lease_id }).await? {
        ProxyResponse::Released { removed } => Ok(removed),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected release response, got {other:?}"
        ))),
    }
}

#[cfg(unix)]
pub(crate) async fn register_lease_to_path(
    socket_path: &Path,
    routes: Vec<Route>,
) -> Result<(RouteLeaseId, tokio::net::UnixStream), ProxyError> {
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| ipc_connect_error(err, socket_path))?;
    register_lease_on_stream(stream, routes).await
}

#[cfg(windows)]
pub(crate) async fn register_lease_to_pipe(
    pipe_name: &str,
    routes: Vec<Route>,
) -> Result<
    (
        RouteLeaseId,
        tokio::net::windows::named_pipe::NamedPipeClient,
    ),
    ProxyError,
> {
    let client = connect_named_pipe_client(pipe_name).await?;
    register_lease_on_stream(client, routes).await
}

pub(crate) async fn register_lease_on_stream<S>(
    mut stream: S,
    routes: Vec<Route>,
) -> Result<(RouteLeaseId, S), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let response = send_request_on_stream_ref(
        &mut stream,
        ProxyRequest::RegisterLease {
            owner_pid: std::process::id(),
            routes,
        },
    )
    .await?;
    match response {
        ProxyResponse::Registered { lease_id } => Ok((lease_id, stream)),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected register response, got {other:?}"
        ))),
    }
}

pub(crate) async fn release_lease_on_connection(
    connection: &mut LeaseConnection,
    lease_id: RouteLeaseId,
) -> Result<usize, ProxyError> {
    match connection {
        #[cfg(unix)]
        LeaseConnection::Unix(stream) => release_lease_on_stream(stream, lease_id).await,
        #[cfg(windows)]
        LeaseConnection::NamedPipe(client) => release_lease_on_stream(client, lease_id).await,
    }
}

pub(crate) async fn release_lease_on_stream<S>(
    stream: &mut S,
    lease_id: RouteLeaseId,
) -> Result<usize, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match send_request_on_stream_ref(stream, ProxyRequest::Release { lease_id }).await? {
        ProxyResponse::Released { removed } => Ok(removed),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected release response, got {other:?}"
        ))),
    }
}

pub(crate) fn release_lease_best_effort(
    lease_id: RouteLeaseId,
    socket_path: Option<PathBuf>,
    pipe_name: Option<String>,
) {
    #[cfg(not(unix))]
    let _ = &socket_path;
    #[cfg(not(windows))]
    let _ = &pipe_name;

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            #[cfg(unix)]
            if let Some(socket_path) = socket_path {
                let _ = release_lease_to_path(&socket_path, lease_id).await;
                return;
            }
            #[cfg(windows)]
            if let Some(pipe_name) = pipe_name {
                let _ = release_lease_to_pipe(&pipe_name, lease_id).await;
                return;
            }
            let _ = release_lease(lease_id).await;
        });
        return;
    }

    let _ = std::thread::Builder::new()
        .name("lpm-proxy-release".to_string())
        .spawn(move || {
            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                #[cfg(unix)]
                if let Some(socket_path) = socket_path {
                    let _ = runtime.block_on(release_lease_to_path(&socket_path, lease_id));
                    return;
                }
                #[cfg(windows)]
                if let Some(pipe_name) = pipe_name {
                    let _ = runtime.block_on(release_lease_to_pipe(&pipe_name, lease_id));
                    return;
                }
                let _ = runtime.block_on(release_lease(lease_id));
            }
        });
}

pub async fn send_request(request: ProxyRequest) -> Result<ProxyResponse, ProxyError> {
    #[cfg(unix)]
    {
        return send_request_to_path(&proxy_socket_path_from_env()?, request).await;
    }

    #[cfg(windows)]
    {
        return send_request_to_pipe(&proxy_pipe_name_from_env()?, request).await;
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = request;
        Err(ProxyError::IpcUnsupported)
    }
}

#[cfg(unix)]
pub async fn send_request_to_path(
    socket_path: &Path,
    request: ProxyRequest,
) -> Result<ProxyResponse, ProxyError> {
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| ipc_connect_error(err, socket_path))?;
    send_request_on_stream(stream, request).await
}

#[cfg(windows)]
pub async fn send_request_to_pipe(
    pipe_name: &str,
    request: ProxyRequest,
) -> Result<ProxyResponse, ProxyError> {
    let client = connect_named_pipe_client(pipe_name).await?;
    send_request_on_stream(client, request).await
}
