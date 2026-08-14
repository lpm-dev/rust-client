use super::*;

#[derive(Debug)]
pub(crate) enum LeaseConnection {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    NamedPipe(tokio::net::windows::named_pipe::NamedPipeClient),
}

#[derive(Debug)]
pub(crate) struct PendingConnectionOperation {
    lease_id: RouteLeaseId,
    task: tokio::task::JoinHandle<(LeaseConnection, Result<(), ProxyError>)>,
}

#[derive(Debug)]
pub struct RouteLease {
    pub(crate) lease_id: Option<RouteLeaseId>,
    pub(crate) connection: Option<LeaseConnection>,
    pub(crate) pending_operation: Option<PendingConnectionOperation>,
    #[cfg(unix)]
    pub(crate) socket_path: Option<PathBuf>,
    #[cfg(windows)]
    pub(crate) pipe_name: Option<String>,
}

impl RouteLease {
    pub fn lease_id(&self) -> Option<RouteLeaseId> {
        self.lease_id
    }

    pub async fn replace_routes(&mut self, routes: Vec<Route>) -> Result<(), ProxyError> {
        self.finish_pending_operation().await?;
        let lease_id = self.lease_id.ok_or_else(|| {
            ProxyError::RequestRejected("proxy route lease is no longer active".to_string())
        })?;
        if let Some(mut connection) = self.connection.take() {
            self.pending_operation = Some(PendingConnectionOperation {
                lease_id,
                task: tokio::spawn(async move {
                    let result =
                        replace_lease_on_connection(&mut connection, lease_id, routes).await;
                    (connection, result)
                }),
            });
            return self.finish_pending_operation().await;
        }
        let _ = routes;
        Err(ProxyError::Ipc(
            "proxy route lease cleanup is unconfirmed; release the lease before publishing more routes"
                .to_string(),
        ))
    }

    pub async fn stage_routes(
        &mut self,
        publication_id: u64,
        routes: Vec<Route>,
    ) -> Result<(), ProxyError> {
        self.finish_pending_operation().await?;
        let lease_id = self.active_lease_id()?;
        let Some(mut connection) = self.connection.take() else {
            return Err(ProxyError::Ipc(
                "staged proxy publication lost its lease connection".to_string(),
            ));
        };
        self.pending_operation = Some(PendingConnectionOperation {
            lease_id,
            task: tokio::spawn(async move {
                let result =
                    stage_lease_on_connection(&mut connection, lease_id, publication_id, routes)
                        .await;
                (connection, result)
            }),
        });
        self.finish_pending_operation().await
    }

    pub async fn commit_routes(&mut self, publication_id: u64) -> Result<(), ProxyError> {
        self.finish_pending_operation().await?;
        let lease_id = self.active_lease_id()?;
        let Some(mut connection) = self.connection.take() else {
            return Err(ProxyError::Ipc(
                "staged proxy publication lost its lease connection".to_string(),
            ));
        };
        self.pending_operation = Some(PendingConnectionOperation {
            lease_id,
            task: tokio::spawn(async move {
                let result =
                    commit_lease_on_connection(&mut connection, lease_id, publication_id).await;
                (connection, result)
            }),
        });
        self.finish_pending_operation().await
    }

    pub async fn rollback_routes(&mut self, publication_id: u64) -> Result<(), ProxyError> {
        self.finish_pending_operation().await?;
        let lease_id = self.active_lease_id()?;
        let Some(mut connection) = self.connection.take() else {
            return Err(ProxyError::Ipc(
                "staged proxy publication lost its lease connection".to_string(),
            ));
        };
        self.pending_operation = Some(PendingConnectionOperation {
            lease_id,
            task: tokio::spawn(async move {
                let result =
                    rollback_lease_on_connection(&mut connection, lease_id, publication_id).await;
                (connection, result)
            }),
        });
        self.finish_pending_operation().await
    }

    fn active_lease_id(&self) -> Result<RouteLeaseId, ProxyError> {
        self.lease_id.ok_or_else(|| {
            ProxyError::RequestRejected("proxy route lease is no longer active".to_string())
        })
    }

    async fn finish_pending_operation(&mut self) -> Result<(), ProxyError> {
        let Some(pending) = self.pending_operation.as_mut() else {
            return Ok(());
        };
        let lease_id = pending.lease_id;
        let completed = (&mut pending.task).await;
        self.pending_operation = None;
        let (connection, result) = match completed {
            Ok(completed) => completed,
            Err(error) => {
                let release = self.release_via_endpoint(lease_id).await;
                return match release {
                    Ok(_) => {
                        self.lease_id = None;
                        Err(ProxyError::Ipc(format!(
                            "proxy publication task failed: {error}"
                        )))
                    }
                    Err(release_error) => Err(ProxyError::Ipc(format!(
                        "proxy publication task failed: {error}; confirming failed-closed lease release also failed: {release_error}"
                    ))),
                };
            }
        };
        if matches!(&result, Ok(()) | Err(ProxyError::RequestRejected(_))) {
            self.connection = Some(connection);
            return result;
        }
        drop(connection);
        let release = self.release_via_endpoint(lease_id).await;
        match release {
            Ok(_) => {
                self.lease_id = None;
                result
            }
            Err(release_error) => Err(ProxyError::Ipc(format!(
                "{result:?}; confirming failed-closed lease release also failed: {release_error}"
            ))),
        }
    }

    pub async fn release(&mut self) -> Result<usize, ProxyError> {
        let pending_error = self.finish_pending_operation().await.err();
        let Some(lease_id) = self.lease_id else {
            return pending_error.map_or(Ok(0), Err);
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
        match (pending_error, result) {
            (None, result) => result,
            (Some(error), Ok(_)) => Err(error),
            (Some(error), Err(release_error)) => Err(ProxyError::Ipc(format!(
                "pending proxy operation failed: {error}; lease release failed: {release_error}"
            ))),
        }
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
        if let Some(pending) = self.pending_operation.take() {
            pending.task.abort();
        } else if self.connection.take().is_some() {
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
            pending_operation: None,
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
            pending_operation: None,
            pipe_name: Some(pipe_name),
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = routes;
        Err(ProxyError::IpcUnsupported)
    }
}

pub async fn register_staged() -> Result<RouteLease, ProxyError> {
    #[cfg(unix)]
    {
        let socket_path = proxy_socket_path_from_env()?;
        let (lease_id, stream) = register_staged_lease_to_path(&socket_path).await?;
        Ok(RouteLease {
            lease_id: Some(lease_id),
            connection: Some(LeaseConnection::Unix(stream)),
            pending_operation: None,
            socket_path: Some(socket_path),
        })
    }

    #[cfg(windows)]
    {
        let pipe_name = proxy_pipe_name_from_env()?;
        let (lease_id, client) = register_staged_lease_to_pipe(&pipe_name).await?;
        Ok(RouteLease {
            lease_id: Some(lease_id),
            connection: Some(LeaseConnection::NamedPipe(client)),
            pending_operation: None,
            pipe_name: Some(pipe_name),
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
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

#[cfg(unix)]
pub(crate) async fn register_staged_lease_to_path(
    socket_path: &Path,
) -> Result<(RouteLeaseId, tokio::net::UnixStream), ProxyError> {
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| ipc_connect_error(err, socket_path))?;
    register_staged_lease_on_stream(stream).await
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

#[cfg(windows)]
async fn register_staged_lease_to_pipe(
    pipe_name: &str,
) -> Result<
    (
        RouteLeaseId,
        tokio::net::windows::named_pipe::NamedPipeClient,
    ),
    ProxyError,
> {
    let client = connect_named_pipe_client(pipe_name).await?;
    register_staged_lease_on_stream(client).await
}

pub(crate) async fn register_lease_on_stream<S>(
    stream: S,
    routes: Vec<Route>,
) -> Result<(RouteLeaseId, S), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    register_lease_on_stream_request(
        stream,
        ProxyRequest::RegisterLease {
            owner_pid: std::process::id(),
            routes,
        },
    )
    .await
}

async fn register_staged_lease_on_stream<S>(stream: S) -> Result<(RouteLeaseId, S), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    register_lease_on_stream_request(
        stream,
        ProxyRequest::RegisterStagedLease {
            owner_pid: std::process::id(),
        },
    )
    .await
}

async fn register_lease_on_stream_request<S>(
    mut stream: S,
    request: ProxyRequest,
) -> Result<(RouteLeaseId, S), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let response = send_request_on_stream_ref(&mut stream, request).await?;
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

async fn replace_lease_on_connection(
    connection: &mut LeaseConnection,
    lease_id: RouteLeaseId,
    routes: Vec<Route>,
) -> Result<(), ProxyError> {
    match connection {
        #[cfg(unix)]
        LeaseConnection::Unix(stream) => replace_lease_on_stream(stream, lease_id, routes).await,
        #[cfg(windows)]
        LeaseConnection::NamedPipe(client) => {
            replace_lease_on_stream(client, lease_id, routes).await
        }
    }
}

async fn stage_lease_on_connection(
    connection: &mut LeaseConnection,
    lease_id: RouteLeaseId,
    publication_id: u64,
    routes: Vec<Route>,
) -> Result<(), ProxyError> {
    match connection {
        #[cfg(unix)]
        LeaseConnection::Unix(stream) => {
            stage_lease_on_stream(stream, lease_id, publication_id, routes).await
        }
        #[cfg(windows)]
        LeaseConnection::NamedPipe(client) => {
            stage_lease_on_stream(client, lease_id, publication_id, routes).await
        }
    }
}

async fn commit_lease_on_connection(
    connection: &mut LeaseConnection,
    lease_id: RouteLeaseId,
    publication_id: u64,
) -> Result<(), ProxyError> {
    match connection {
        #[cfg(unix)]
        LeaseConnection::Unix(stream) => {
            commit_lease_on_stream(stream, lease_id, publication_id).await
        }
        #[cfg(windows)]
        LeaseConnection::NamedPipe(client) => {
            commit_lease_on_stream(client, lease_id, publication_id).await
        }
    }
}

async fn rollback_lease_on_connection(
    connection: &mut LeaseConnection,
    lease_id: RouteLeaseId,
    publication_id: u64,
) -> Result<(), ProxyError> {
    match connection {
        #[cfg(unix)]
        LeaseConnection::Unix(stream) => {
            rollback_lease_on_stream(stream, lease_id, publication_id).await
        }
        #[cfg(windows)]
        LeaseConnection::NamedPipe(client) => {
            rollback_lease_on_stream(client, lease_id, publication_id).await
        }
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

async fn replace_lease_on_stream<S>(
    stream: &mut S,
    lease_id: RouteLeaseId,
    routes: Vec<Route>,
) -> Result<(), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match send_request_on_stream_ref(stream, ProxyRequest::Replace { lease_id, routes }).await? {
        ProxyResponse::Replaced => Ok(()),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected replace response, got {other:?}"
        ))),
    }
}

async fn stage_lease_on_stream<S>(
    stream: &mut S,
    lease_id: RouteLeaseId,
    publication_id: u64,
    routes: Vec<Route>,
) -> Result<(), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match send_request_on_stream_ref(
        stream,
        ProxyRequest::Stage {
            lease_id,
            publication_id,
            routes,
        },
    )
    .await?
    {
        ProxyResponse::Staged {
            publication_id: staged,
        } if staged == publication_id => Ok(()),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected staged response for publication {publication_id}, got {other:?}"
        ))),
    }
}

async fn commit_lease_on_stream<S>(
    stream: &mut S,
    lease_id: RouteLeaseId,
    publication_id: u64,
) -> Result<(), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match send_request_on_stream_ref(
        stream,
        ProxyRequest::Commit {
            lease_id,
            publication_id,
        },
    )
    .await?
    {
        ProxyResponse::Committed {
            publication_id: committed,
        } if committed == publication_id => Ok(()),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected committed response for publication {publication_id}, got {other:?}"
        ))),
    }
}

async fn rollback_lease_on_stream<S>(
    stream: &mut S,
    lease_id: RouteLeaseId,
    publication_id: u64,
) -> Result<(), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match send_request_on_stream_ref(
        stream,
        ProxyRequest::Rollback {
            lease_id,
            publication_id,
        },
    )
    .await?
    {
        ProxyResponse::RolledBack {
            publication_id: rolled_back,
        } if rolled_back == publication_id => Ok(()),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected rolled-back response for publication {publication_id}, got {other:?}"
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
