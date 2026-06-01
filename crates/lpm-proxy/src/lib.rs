//! Shared local-domain proxy primitives.
//!
//! This crate owns the route-registry contract, control IPC, and loopback
//! HTTP forwarding core used by LPM's local-domain proxy. Certificate and
//! hosts-file side effects build on the conflict and lease semantics here.

use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

const IPC_LINE_CAP_BYTES: usize = 1024 * 1024;
const HTTP_HEAD_CAP_BYTES: usize = 64 * 1024;
const EMPTY_CONTROL_FRAME_MESSAGE: &str = "empty control frame";
const CONTROL_CONNECTION_RELEASE_TIMEOUT: Duration = Duration::from_secs(1);
type HttpHeaderPair = (axum::http::HeaderName, axum::http::HeaderValue);
type ParsedHttpResponseHead = (axum::http::StatusCode, Vec<HttpHeaderPair>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProxyError {
    #[error("proxy route set is empty")]
    EmptyRouteSet,
    #[error("invalid proxy host {host:?}: {reason}")]
    InvalidHost { host: String, reason: &'static str },
    #[error("proxy host {host:?} appears more than once in the route set")]
    DuplicateHostInRouteSet { host: String },
    #[error("proxy host {host:?} is already registered by lease {lease_id} (PID {owner_pid})")]
    HostAlreadyRegistered {
        host: String,
        lease_id: RouteLeaseId,
        owner_pid: u32,
    },
    #[error("proxy lease {0} is not registered")]
    UnknownLease(RouteLeaseId),
    #[error("could not resolve LPM proxy state path: {0}")]
    StatePath(String),
    #[error("could not read LPM proxy state: {0}")]
    StateRead(String),
    #[error("could not write LPM proxy state: {0}")]
    StateWrite(String),
    #[error("local proxy IPC is not supported on this platform yet")]
    IpcUnsupported,
    #[error("local proxy daemon is not running: {0}")]
    IpcUnavailable(String),
    #[error("local proxy IPC failed: {0}")]
    Ipc(String),
    #[error("local proxy IPC protocol error: {0}")]
    IpcProtocol(String),
    #[error("local proxy daemon rejected request: {0}")]
    RequestRejected(String),
    #[error("local proxy HTTP failed: {0}")]
    Http(String),
    #[error("local proxy TLS failed: {0}")]
    Tls(String),
    #[error("local proxy TCP forwarder failed: {0}")]
    Forwarder(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub host: String,
    pub upstream_port: u16,
    pub project_dir: PathBuf,
    pub service: Option<String>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RouteLeaseId(u64);

impl RouteLeaseId {
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RouteLeaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredRoute {
    pub host: String,
    pub upstream_port: u16,
    pub project_dir: PathBuf,
    pub service: Option<String>,
    pub lease_id: RouteLeaseId,
    pub owner_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteStatus {
    pub host: String,
    pub upstream_port: u16,
    pub project_dir: PathBuf,
    pub service: Option<String>,
    pub lease_id: RouteLeaseId,
    pub owner_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyDaemonState {
    pub pid: u32,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub http_addr: Option<String>,
    #[serde(default)]
    pub http_redirect_addr: Option<String>,
    #[serde(default)]
    pub tls_addr: Option<String>,
    #[serde(default)]
    pub routes: Vec<RouteStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub http_addr: Option<String>,
    pub http_redirect_addr: Option<String>,
    pub tls_addr: Option<String>,
    pub routes: Vec<RouteStatus>,
    pub stale: bool,
    pub state_error: Option<String>,
}

impl ProxyStatus {
    pub fn not_running() -> Self {
        Self {
            running: false,
            pid: None,
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: None,
            routes: Vec::new(),
            stale: false,
            state_error: None,
        }
    }

    fn stale(
        pid: Option<u32>,
        http_addr: Option<String>,
        http_redirect_addr: Option<String>,
        tls_addr: Option<String>,
        state_error: Option<String>,
    ) -> Self {
        Self {
            running: false,
            pid,
            http_addr,
            http_redirect_addr,
            tls_addr,
            routes: Vec::new(),
            stale: true,
            state_error,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct ProxyDaemonOptions {
    pub http_port: Option<u16>,
    pub http_redirect_port: Option<u16>,
    pub tls_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ProxyRequest {
    Status,
    List,
    Register {
        owner_pid: u32,
        routes: Vec<Route>,
    },
    RegisterLease {
        owner_pid: u32,
        routes: Vec<Route>,
    },
    Replace {
        lease_id: RouteLeaseId,
        routes: Vec<Route>,
    },
    Release {
        lease_id: RouteLeaseId,
    },
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ProxyResponse {
    Status { status: ProxyStatus },
    Routes { routes: Vec<RouteStatus> },
    Registered { lease_id: RouteLeaseId },
    Replaced,
    Released { removed: usize },
    Stopped,
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeaseInfo {
    owner_pid: u32,
}

#[derive(Debug, Default)]
pub struct RouteRegistry {
    next_lease_id: u64,
    routes: HashMap<String, RegisteredRoute>,
    leases: HashMap<RouteLeaseId, LeaseInfo>,
}

#[derive(Clone)]
pub struct HttpProxyState {
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        axum::body::Body,
    >,
    forwarded_proto: &'static str,
}

impl HttpProxyState {
    pub fn new(registry: Arc<tokio::sync::Mutex<RouteRegistry>>) -> Self {
        Self::with_forwarded_proto(registry, "http")
    }

    fn with_forwarded_proto(
        registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
        forwarded_proto: &'static str,
    ) -> Self {
        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        Self {
            registry,
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build(connector),
            forwarded_proto,
        }
    }
}

#[derive(Clone)]
struct HttpRedirectState {
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    https_port: u16,
}

#[derive(Debug, Clone, Default)]
struct ProxyListenerAddrs {
    http_addr: Option<String>,
    http_redirect_addr: Option<String>,
    tls_addr: Option<String>,
}

#[derive(Clone, Default)]
struct TlsCertificateStore {
    keys_by_host: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl TlsCertificateStore {
    fn replace(&self, keys_by_host: HashMap<String, Arc<CertifiedKey>>) {
        if let Ok(mut guard) = self.keys_by_host.write() {
            *guard = keys_by_host;
        }
    }

    fn get(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = canonical_host(host).ok()?;
        self.keys_by_host.read().ok()?.get(&host).cloned()
    }
}

#[derive(Clone)]
struct ControlStreamContext {
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    state_write_lock: Arc<tokio::sync::Mutex<()>>,
    state_path: PathBuf,
    endpoint: String,
    listener_addrs: ProxyListenerAddrs,
    tls_cert_store: Option<TlsCertificateStore>,
}

#[derive(Clone)]
struct TlsCertResolver {
    store: TlsCertificateStore,
}

impl fmt::Debug for TlsCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsCertResolver").finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for TlsCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.store.get(client_hello.server_name()?)
    }
}

pub struct HttpProxyHandle {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl HttpProxyHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl Drop for HttpProxyHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// Loopback TCP relay rule used by the privileged Unix low-port forwarder.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TcpForwarderRule {
    listen_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl TcpForwarderRule {
    /// Build a forwarder rule.
    ///
    /// The listener and target must both be loopback addresses, and the target
    /// port must be unprivileged so a user-scoped proxy daemon can own it.
    pub fn new(listen_addr: SocketAddr, target_addr: SocketAddr) -> Result<Self, ProxyError> {
        if !listen_addr.ip().is_loopback() {
            return Err(ProxyError::Forwarder(format!(
                "forwarder listen address must be loopback, got {listen_addr}"
            )));
        }
        if !target_addr.ip().is_loopback() {
            return Err(ProxyError::Forwarder(format!(
                "forwarder target address must be loopback, got {target_addr}"
            )));
        }
        if target_addr.port() < 1024 {
            return Err(ProxyError::Forwarder(format!(
                "forwarder target port must be >=1024, got {}",
                target_addr.port()
            )));
        }
        Ok(Self {
            listen_addr,
            target_addr,
        })
    }

    /// Address the forwarder should bind.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// User-daemon backend address that receives raw forwarded TCP.
    pub fn target_addr(&self) -> SocketAddr {
        self.target_addr
    }
}

/// Running TCP forwarder handle.
pub struct TcpForwarderHandle {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl TcpForwarderHandle {
    /// Bound listener address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop accepting new forwarded connections.
    pub fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl Drop for TcpForwarderHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// Unix-only guard for a root-owned low-port forwarder.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixForwarderGuard {
    state_path: PathBuf,
    expected_uid: u32,
    expected_addr: SocketAddr,
}

#[cfg(unix)]
impl UnixForwarderGuard {
    /// Build a guard that pins forwarded traffic to one user's proxy daemon.
    pub fn new(
        state_path: impl Into<PathBuf>,
        expected_uid: u32,
        expected_addr: SocketAddr,
    ) -> Result<Self, ProxyError> {
        if !expected_addr.ip().is_loopback() || expected_addr.port() < 1024 {
            return Err(ProxyError::Forwarder(format!(
                "forwarder guarded target must be loopback with port >=1024, got {expected_addr}"
            )));
        }
        Ok(Self {
            state_path: state_path.into(),
            expected_uid,
            expected_addr,
        })
    }

    /// Validate that the configured user daemon still owns the backend target.
    pub fn validate(&self) -> Result<(), ProxyError> {
        let state = read_forwarder_daemon_state(&self.state_path, self.expected_uid)?;
        validate_forwarder_daemon_state(
            &state,
            self.expected_uid,
            self.expected_addr,
            process_is_running,
            process_owner_uid,
        )
    }

    pub fn expected_addr(&self) -> SocketAddr {
        self.expected_addr
    }
}

#[cfg(not(unix))]
#[derive(Clone)]
struct UnixForwarderGuard;

#[derive(Debug)]
enum LeaseConnection {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    NamedPipe(tokio::net::windows::named_pipe::NamedPipeClient),
}

#[derive(Debug)]
pub struct RouteLease {
    lease_id: Option<RouteLeaseId>,
    connection: Option<LeaseConnection>,
    #[cfg(unix)]
    socket_path: Option<PathBuf>,
    #[cfg(windows)]
    pipe_name: Option<String>,
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

impl RouteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_routes(
        &mut self,
        owner_pid: u32,
        routes: Vec<Route>,
    ) -> Result<RouteLeaseId, ProxyError> {
        if routes.is_empty() {
            return Err(ProxyError::EmptyRouteSet);
        }

        let lease_id = self.allocate_lease_id();
        let prepared = self.prepare_routes(lease_id, owner_pid, routes)?;
        self.leases.insert(lease_id, LeaseInfo { owner_pid });
        for route in prepared {
            self.routes.insert(route.host.clone(), route);
        }
        Ok(lease_id)
    }

    pub fn replace_routes(
        &mut self,
        lease_id: RouteLeaseId,
        routes: Vec<Route>,
    ) -> Result<(), ProxyError> {
        if routes.is_empty() {
            return Err(ProxyError::EmptyRouteSet);
        }

        let owner_pid = self
            .leases
            .get(&lease_id)
            .ok_or(ProxyError::UnknownLease(lease_id))?
            .owner_pid;
        let prepared = self.prepare_routes(lease_id, owner_pid, routes)?;
        self.release_routes_for_lease(lease_id);
        for route in prepared {
            self.routes.insert(route.host.clone(), route);
        }
        Ok(())
    }

    pub fn release(&mut self, lease_id: RouteLeaseId) -> usize {
        let removed = self.release_routes_for_lease(lease_id);
        self.leases.remove(&lease_id);
        removed
    }

    pub fn lookup_host(&self, host: &str) -> Option<&RegisteredRoute> {
        let host = canonical_host(host).ok()?;
        self.routes.get(&host)
    }

    pub fn lookup_host_header(&self, host_header: &str) -> Option<&RegisteredRoute> {
        let host = canonical_host_from_header(host_header).ok()?;
        self.routes.get(&host)
    }

    pub fn statuses(&self) -> Vec<RouteStatus> {
        let mut statuses: Vec<RouteStatus> = self
            .routes
            .values()
            .map(|route| RouteStatus {
                host: route.host.clone(),
                upstream_port: route.upstream_port,
                project_dir: route.project_dir.clone(),
                service: route.service.clone(),
                lease_id: route.lease_id,
                owner_pid: route.owner_pid,
            })
            .collect();
        statuses.sort_by(|a, b| a.host.cmp(&b.host));
        statuses
    }

    pub fn prune_dead_leases(&mut self) -> usize {
        self.prune_leases_with(process_is_running)
    }

    fn allocate_lease_id(&mut self) -> RouteLeaseId {
        self.next_lease_id += 1;
        RouteLeaseId(self.next_lease_id)
    }

    fn prepare_routes(
        &self,
        lease_id: RouteLeaseId,
        owner_pid: u32,
        routes: Vec<Route>,
    ) -> Result<Vec<RegisteredRoute>, ProxyError> {
        let mut seen = HashSet::with_capacity(routes.len());
        let mut prepared = Vec::with_capacity(routes.len());

        for route in routes {
            let host = canonical_host(&route.host)?;
            if !seen.insert(host.clone()) {
                return Err(ProxyError::DuplicateHostInRouteSet { host });
            }
            if let Some(existing) = self.routes.get(&host)
                && existing.lease_id != lease_id
            {
                return Err(ProxyError::HostAlreadyRegistered {
                    host,
                    lease_id: existing.lease_id,
                    owner_pid: existing.owner_pid,
                });
            }
            prepared.push(RegisteredRoute {
                host,
                upstream_port: route.upstream_port,
                project_dir: route.project_dir,
                service: route.service,
                lease_id,
                owner_pid,
            });
        }

        Ok(prepared)
    }

    fn release_routes_for_lease(&mut self, lease_id: RouteLeaseId) -> usize {
        let before = self.routes.len();
        self.routes.retain(|_, route| route.lease_id != lease_id);
        before - self.routes.len()
    }

    fn prune_leases_with(&mut self, mut owner_is_alive: impl FnMut(u32) -> bool) -> usize {
        let dead_leases: Vec<RouteLeaseId> = self
            .leases
            .iter()
            .filter_map(|(lease_id, info)| (!owner_is_alive(info.owner_pid)).then_some(*lease_id))
            .collect();
        let mut removed = 0;
        for lease_id in dead_leases {
            removed += self.release_routes_for_lease(lease_id);
            self.leases.remove(&lease_id);
        }
        removed
    }
}

pub fn proxy_state_path_from_env() -> Result<PathBuf, ProxyError> {
    Ok(lpm_common::LpmRoot::from_env()
        .map_err(|err| ProxyError::StatePath(err.to_string()))?
        .proxy_state())
}

#[cfg(unix)]
pub fn proxy_socket_path_from_env() -> Result<PathBuf, ProxyError> {
    Ok(lpm_common::LpmRoot::from_env()
        .map_err(|err| ProxyError::StatePath(err.to_string()))?
        .proxy_socket())
}

#[cfg(windows)]
pub fn proxy_pipe_name_from_env() -> Result<String, ProxyError> {
    let root =
        lpm_common::LpmRoot::from_env().map_err(|err| ProxyError::StatePath(err.to_string()))?;
    Ok(proxy_pipe_name_for_root(root.root()))
}

pub fn proxy_pipe_name_for_root(root: &Path) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let normalized = root.to_string_lossy().replace('\\', "/").to_lowercase();
    let mut hash = FNV_OFFSET;
    for byte in normalized.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!(r"\\.\pipe\lpm-proxy-{hash:016x}")
}

pub fn read_status() -> Result<ProxyStatus, ProxyError> {
    read_status_from_path(&proxy_state_path_from_env()?)
}

pub fn read_status_from_path(path: &std::path::Path) -> Result<ProxyStatus, ProxyError> {
    let Some(bytes) =
        lpm_common::read_capped_state_file(path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|err| ProxyError::StateRead(err.to_string()))?
    else {
        return Ok(ProxyStatus::not_running());
    };

    match serde_json::from_slice::<ProxyDaemonState>(&bytes) {
        Ok(state) => Ok(ProxyStatus::stale(
            Some(state.pid),
            state.http_addr,
            state.http_redirect_addr,
            state.tls_addr,
            None,
        )),
        Err(err) => Ok(ProxyStatus::stale(
            None,
            None,
            None,
            None,
            Some(err.to_string()),
        )),
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

async fn release_lease(lease_id: RouteLeaseId) -> Result<usize, ProxyError> {
    match send_request(ProxyRequest::Release { lease_id }).await? {
        ProxyResponse::Released { removed } => Ok(removed),
        ProxyResponse::Error { message } => Err(ProxyError::RequestRejected(message)),
        other => Err(ProxyError::IpcProtocol(format!(
            "expected release response, got {other:?}"
        ))),
    }
}

#[cfg(unix)]
async fn release_lease_to_path(
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
async fn release_lease_to_pipe(
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
async fn register_lease_to_path(
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
async fn register_lease_to_pipe(
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

async fn register_lease_on_stream<S>(
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

async fn release_lease_on_connection(
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

async fn release_lease_on_stream<S>(
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

fn release_lease_best_effort(
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

/// Start a loopback TCP forwarder from the rule's listener to its target.
pub async fn start_tcp_forwarder(rule: TcpForwarderRule) -> Result<TcpForwarderHandle, ProxyError> {
    let listener = tokio::net::TcpListener::bind(rule.listen_addr())
        .await
        .map_err(|err| {
            ProxyError::Forwarder(format!(
                "bind TCP forwarder on {}: {err}",
                rule.listen_addr()
            ))
        })?;
    start_tcp_forwarder_on_listener_inner(listener, rule.target_addr(), None)
}

/// Start a loopback TCP forwarder from an already-bound listener.
pub fn start_tcp_forwarder_on_listener(
    listener: tokio::net::TcpListener,
    target_addr: SocketAddr,
) -> Result<TcpForwarderHandle, ProxyError> {
    start_tcp_forwarder_on_listener_inner(listener, target_addr, None)
}

/// Start a guarded Unix loopback TCP forwarder from the rule's listener.
#[cfg(unix)]
pub async fn start_guarded_tcp_forwarder(
    rule: TcpForwarderRule,
    guard: UnixForwarderGuard,
) -> Result<TcpForwarderHandle, ProxyError> {
    if rule.target_addr() != guard.expected_addr() {
        return Err(ProxyError::Forwarder(format!(
            "forwarder rule target {} does not match guarded target {}",
            rule.target_addr(),
            guard.expected_addr()
        )));
    }
    let listener = tokio::net::TcpListener::bind(rule.listen_addr())
        .await
        .map_err(|err| {
            ProxyError::Forwarder(format!(
                "bind TCP forwarder on {}: {err}",
                rule.listen_addr()
            ))
        })?;
    start_tcp_forwarder_on_listener_inner(listener, rule.target_addr(), Some(guard))
}

fn start_tcp_forwarder_on_listener_inner(
    listener: tokio::net::TcpListener,
    target_addr: SocketAddr,
    guard: Option<UnixForwarderGuard>,
) -> Result<TcpForwarderHandle, ProxyError> {
    if !target_addr.ip().is_loopback() || target_addr.port() < 1024 {
        return Err(ProxyError::Forwarder(format!(
            "forwarder target must be loopback with port >=1024, got {target_addr}"
        )));
    }
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Forwarder(format!("read TCP forwarder bind addr: {err}")))?;
    if !addr.ip().is_loopback() {
        return Err(ProxyError::Forwarder(format!(
            "forwarder listener must be loopback, got {addr}"
        )));
    }

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((inbound, _)) = accepted else {
                        continue;
                    };
                    tokio::spawn(forward_tcp_connection(inbound, target_addr, guard.clone()));
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }
    });

    Ok(TcpForwarderHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

async fn forward_tcp_connection(
    mut inbound: tokio::net::TcpStream,
    target_addr: SocketAddr,
    guard: Option<UnixForwarderGuard>,
) {
    if let Some(guard) = guard
        && !forwarder_guard_allows(guard).await
    {
        return;
    }
    let Ok(mut outbound) = tokio::net::TcpStream::connect(target_addr).await else {
        return;
    };
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
}

#[cfg(unix)]
async fn forwarder_guard_allows(guard: UnixForwarderGuard) -> bool {
    matches!(
        tokio::task::spawn_blocking(move || guard.validate()).await,
        Ok(Ok(()))
    )
}

#[cfg(not(unix))]
async fn forwarder_guard_allows(_guard: UnixForwarderGuard) -> bool {
    true
}

pub async fn start_http_proxy(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    port: u16,
) -> Result<HttpProxyHandle, ProxyError> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .map_err(|err| ProxyError::Http(format_loopback_bind_error("HTTP proxy", port, &err)))?;
    start_http_proxy_on_listener(registry, listener)
}

pub fn start_http_proxy_on_listener(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    listener: tokio::net::TcpListener,
) -> Result<HttpProxyHandle, ProxyError> {
    use axum::Router;
    use axum::routing::any;

    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Http(format!("read HTTP proxy bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new()
        .fallback(any(proxy_http_request))
        .with_state(HttpProxyState::new(registry));

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

async fn start_http_redirect(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    port: u16,
    https_port: u16,
) -> Result<HttpProxyHandle, ProxyError> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .map_err(|err| ProxyError::Http(format_loopback_bind_error("HTTP redirect", port, &err)))?;
    start_http_redirect_on_listener(registry, listener, https_port)
}

fn start_http_redirect_on_listener(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    listener: tokio::net::TcpListener,
    https_port: u16,
) -> Result<HttpProxyHandle, ProxyError> {
    use axum::Router;
    use axum::routing::any;

    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Http(format!("read HTTP redirect bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new()
        .fallback(any(redirect_http_request))
        .with_state(HttpRedirectState {
            registry,
            https_port,
        });

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

async fn start_tls_proxy(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    cert_store: TlsCertificateStore,
    port: u16,
) -> Result<HttpProxyHandle, ProxyError> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .map_err(|err| ProxyError::Tls(format_loopback_bind_error("TLS proxy", port, &err)))?;
    start_tls_proxy_on_listener(registry, cert_store, listener)
}

fn format_loopback_bind_error(listener: &str, port: u16, err: &std::io::Error) -> String {
    let mut message = format!("bind {listener} on 127.0.0.1:{port}: {err}");
    if port != 0 && port < 1024 && err.kind() == std::io::ErrorKind::PermissionDenied {
        message.push_str(
            ". Binding ports below 1024 requires privileged bind rights on macOS/Linux. Use `lpm proxy install --privileged-ports` for persistent Unix 80/443 forwarding, or set `proxy.port` to a high port such as 9443 for foreground starts.",
        );
    }
    message
}

fn start_tls_proxy_on_listener(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    cert_store: TlsCertificateStore,
    listener: tokio::net::TcpListener,
) -> Result<HttpProxyHandle, ProxyError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Tls(format!("read TLS proxy bind addr: {err}")))?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(TlsCertResolver { store: cert_store }));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let state = HttpProxyState::with_forwarded_proto(registry, "https");

    tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let state = state.clone();
                    tokio::spawn(async move {
                        serve_tls_http_connection(acceptor, stream, state).await;
                    });
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }
    });

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

async fn serve_tls_http_connection(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
    state: HttpProxyState,
) {
    let Ok(tls_stream) = acceptor.accept(stream).await else {
        return;
    };
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let service =
        hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let state = state.clone();
            async move {
                let request = request.map(axum::body::Body::new);
                let response = proxy_http_request_inner(state, request)
                    .await
                    .unwrap_or_else(|response| response);
                Ok::<_, Infallible>(response)
            }
        });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await;
}

fn refresh_tls_cert_store(cert_store: &TlsCertificateStore, routes: &[RouteStatus]) {
    let mut keys_by_host = HashMap::with_capacity(routes.len());
    for route in routes {
        if let Ok(Some(key)) = load_project_certified_key(&route.project_dir, &route.host) {
            keys_by_host.insert(route.host.clone(), key);
        }
    }
    cert_store.replace(keys_by_host);
}

async fn prepare_tls_certificates_if_enabled(
    tls_cert_store: Option<&TlsCertificateStore>,
    routes: &[Route],
) -> Result<(), ProxyError> {
    if tls_cert_store.is_some() {
        prepare_tls_certificates_for_routes(routes).await?;
    }
    Ok(())
}

async fn prepare_tls_certificates_for_routes(routes: &[Route]) -> Result<(), ProxyError> {
    let groups = group_tls_hosts_by_project(routes)?;
    tokio::task::spawn_blocking(move || prepare_tls_certificates_blocking(groups))
        .await
        .map_err(|err| ProxyError::Tls(format!("prepare TLS certificates: {err}")))?
}

fn group_tls_hosts_by_project(
    routes: &[Route],
) -> Result<BTreeMap<PathBuf, Vec<String>>, ProxyError> {
    if routes.is_empty() {
        return Err(ProxyError::EmptyRouteSet);
    }

    let mut groups: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    let mut seen = HashSet::with_capacity(routes.len());
    for route in routes {
        let host = canonical_host(&route.host)?;
        if !seen.insert(host.clone()) {
            return Err(ProxyError::DuplicateHostInRouteSet { host });
        }
        groups
            .entry(route.project_dir.clone())
            .or_default()
            .push(host);
    }

    for hosts in groups.values_mut() {
        hosts.sort_unstable();
        hosts.dedup();
    }
    Ok(groups)
}

fn prepare_tls_certificates_blocking(
    groups: BTreeMap<PathBuf, Vec<String>>,
) -> Result<(), ProxyError> {
    for (project_dir, hosts) in groups {
        if project_leaf_is_ready_for_hosts(&project_dir, &hosts).unwrap_or(false) {
            continue;
        }
        lpm_cert::ensure_https_with_consent(
            &project_dir,
            &hosts,
            lpm_cert::TrustStoreConsent::Decline,
        )
        .map_err(|err| {
            ProxyError::Tls(format!(
                "prepare project certificate for {}: {err}",
                project_dir.display()
            ))
        })?;
    }
    Ok(())
}

fn project_leaf_is_ready_for_hosts(
    project_dir: &Path,
    hosts: &[String],
) -> Result<bool, ProxyError> {
    let cert_dir = project_dir.join(".lpm").join("certs");
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    if !cert_path.is_file() || !key_path.is_file() {
        return Ok(false);
    }
    if lpm_cert::cert::needs_renewal(&cert_path).map_err(cert_error_to_tls)? {
        return Ok(false);
    }
    if !lpm_cert::cert::covers_requested_hostnames(&cert_path, hosts).map_err(cert_error_to_tls)? {
        return Ok(false);
    }
    if !hosts.is_empty()
        && !lpm_cert::cert::project_cert_has_intermediate(&cert_path).map_err(cert_error_to_tls)?
    {
        return Ok(false);
    }
    let ca_path = lpm_cert::paths::ca_cert_path().map_err(cert_error_to_tls)?;
    if !ca_path.is_file() {
        return Ok(false);
    }
    lpm_cert::cert::project_cert_chains_to_root(&cert_path, &ca_path).map_err(cert_error_to_tls)
}

fn cert_error_to_tls(err: lpm_common::LpmError) -> ProxyError {
    ProxyError::Tls(err.to_string())
}

fn load_project_certified_key(
    project_dir: &Path,
    host: &str,
) -> Result<Option<Arc<CertifiedKey>>, ProxyError> {
    let cert_dir = project_dir.join(".lpm").join("certs");
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    if !cert_path.is_file() || !key_path.is_file() {
        return Ok(None);
    }

    if !cert_covers_hostname(&cert_path, host)? {
        return Ok(None);
    }

    load_certified_key(&cert_path, &key_path).map(Some)
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>, ProxyError> {
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };

    let cert_pem = std::fs::read(cert_path)
        .map_err(|err| ProxyError::Tls(format!("read {}: {err}", cert_path.display())))?;
    let certs = pem::parse_many(cert_pem)
        .map_err(|err| ProxyError::Tls(format!("parse {}: {err}", cert_path.display())))?
        .into_iter()
        .filter(|pem| pem.tag() == "CERTIFICATE")
        .map(|pem| CertificateDer::from(pem.contents().to_vec()))
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(ProxyError::Tls(format!(
            "{} does not contain a certificate",
            cert_path.display()
        )));
    }

    let key_pem = std::fs::read(key_path)
        .map_err(|err| ProxyError::Tls(format!("read {}: {err}", key_path.display())))?;
    let key = pem::parse_many(key_pem)
        .map_err(|err| ProxyError::Tls(format!("parse {}: {err}", key_path.display())))?
        .into_iter()
        .find_map(|pem| match pem.tag() {
            "PRIVATE KEY" => Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                pem.contents().to_vec(),
            ))),
            "EC PRIVATE KEY" => Some(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
                pem.contents().to_vec(),
            ))),
            "RSA PRIVATE KEY" => Some(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
                pem.contents().to_vec(),
            ))),
            _ => None,
        })
        .ok_or_else(|| {
            ProxyError::Tls(format!(
                "{} does not contain a supported private key",
                key_path.display()
            ))
        })?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let certified_key = CertifiedKey::from_der(certs, key, &provider)
        .map_err(|err| ProxyError::Tls(format!("load TLS keypair: {err}")))?;
    Ok(Arc::new(certified_key))
}

fn cert_covers_hostname(cert_path: &Path, host: &str) -> Result<bool, ProxyError> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|err| ProxyError::Tls(format!("read {}: {err}", cert_path.display())))?;
    let pem = pem::parse(cert_pem)
        .map_err(|err| ProxyError::Tls(format!("parse {}: {err}", cert_path.display())))?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|err| ProxyError::Tls(format!("parse X.509 {}: {err}", cert_path.display())))?;
    let Some(san) = cert.subject_alternative_name().ok().flatten() else {
        return Ok(false);
    };
    Ok(san.value.general_names.iter().any(|name| {
        matches!(
            name,
            x509_parser::extensions::GeneralName::DNSName(name)
                if name.eq_ignore_ascii_case(host)
        )
    }))
}

async fn redirect_http_request(
    axum::extract::State(state): axum::extract::State<HttpRedirectState>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let Some(host_header) = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return (StatusCode::MISDIRECTED_REQUEST, "missing Host header").into_response();
    };
    let Some(route) = state
        .registry
        .lock()
        .await
        .lookup_host_header(&host_header)
        .cloned()
    else {
        return (StatusCode::MISDIRECTED_REQUEST, "unknown local proxy host").into_response();
    };

    let path = request.uri().path_and_query().map_or("/", |p| p.as_str());
    let host = if state.https_port == 443 {
        route.host
    } else {
        format!("{}:{}", route.host, state.https_port)
    };
    let location = format!("https://{host}{path}");
    axum::http::Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location)
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
}

async fn proxy_http_request(
    axum::extract::State(state): axum::extract::State<HttpProxyState>,
    request: axum::extract::Request,
) -> axum::response::Response {
    match proxy_http_request_inner(state, request).await {
        Ok(response) => response,
        Err(response) => response,
    }
}

async fn proxy_http_request_inner(
    state: HttpProxyState,
    request: axum::extract::Request,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let Some(host_header) = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return Err((StatusCode::MISDIRECTED_REQUEST, "missing Host header").into_response());
    };
    let Some(route) = state
        .registry
        .lock()
        .await
        .lookup_host_header(&host_header)
        .cloned()
    else {
        return Err((StatusCode::MISDIRECTED_REQUEST, "unknown local proxy host").into_response());
    };

    if is_upgrade_request(request.headers()) {
        return proxy_upgrade_request(request, route, host_header, state.forwarded_proto).await;
    }

    let (parts, body) = request.into_parts();
    let method = parts.method;
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let upstream_url = format!("http://127.0.0.1:{}{path}", route.upstream_port);
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(upstream_url);

    for (name, value) in &parts.headers {
        if is_forwardable_http_header(name.as_str()) {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    builder = builder
        .header(header::HOST, format!("127.0.0.1:{}", route.upstream_port))
        .header("x-forwarded-host", host_header)
        .header("x-forwarded-proto", state.forwarded_proto);

    let upstream_request = builder.body(body).map_err(|_| {
        (StatusCode::BAD_GATEWAY, "failed to build upstream request").into_response()
    })?;
    let upstream = state.client.request(upstream_request).await.map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "upstream dev server request failed",
        )
            .into_response()
    })?;

    let (upstream_parts, upstream_body) = upstream.into_parts();
    let mut response_builder = axum::http::Response::builder().status(upstream_parts.status);
    for (name, value) in &upstream_parts.headers {
        if is_forwardable_http_header(name.as_str()) {
            response_builder = response_builder.header(name.clone(), value.clone());
        }
    }
    response_builder
        .body(Body::new(upstream_body))
        .map_err(|_| (StatusCode::BAD_GATEWAY, "failed to build proxy response").into_response())
}

async fn proxy_upgrade_request(
    mut request: axum::extract::Request,
    route: RegisteredRoute,
    host_header: String,
    forwarded_proto: &'static str,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use tokio::io::AsyncWriteExt;

    let on_upgrade = hyper::upgrade::on(&mut request);
    let upstream_request =
        build_upgrade_request_bytes(&request, &route, &host_header, forwarded_proto);
    let mut upstream = tokio::net::TcpStream::connect(("127.0.0.1", route.upstream_port))
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "upstream dev server is not reachable",
            )
                .into_response()
        })?;
    upstream.write_all(&upstream_request).await.map_err(|_| {
        (StatusCode::BAD_GATEWAY, "upstream upgrade request failed").into_response()
    })?;

    let (head, leftover) = read_http_head(&mut upstream)
        .await
        .map_err(bad_gateway_response)?;
    let (status, headers) = parse_http_response_head(&head).map_err(bad_gateway_response)?;
    let mut response_builder = axum::http::Response::builder().status(status);
    for (name, value) in headers {
        if is_upgrade_response_header_forwardable(&name) {
            response_builder = response_builder.header(name, value);
        }
    }

    tokio::spawn(async move {
        let Ok(upgraded) = on_upgrade.await else {
            return;
        };
        let mut downstream = hyper_util::rt::TokioIo::new(upgraded);
        if !leftover.is_empty() && downstream.write_all(&leftover).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
    });

    response_builder
        .body(Body::empty())
        .map_err(|_| (StatusCode::BAD_GATEWAY, "failed to build upgrade response").into_response())
}

fn build_upgrade_request_bytes(
    request: &axum::extract::Request,
    route: &RegisteredRoute,
    host_header: &str,
    forwarded_proto: &str,
) -> Vec<u8> {
    use axum::http::header;

    let path = request.uri().path_and_query().map_or("/", |p| p.as_str());
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(request.method().as_str().as_bytes());
    bytes.extend_from_slice(b" ");
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\n");

    for (name, value) in request.headers() {
        if is_forwardable_upgrade_request_header(name.as_str()) {
            bytes.extend_from_slice(name.as_str().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
    }

    bytes.extend_from_slice(b"host: 127.0.0.1:");
    bytes.extend_from_slice(route.upstream_port.to_string().as_bytes());
    bytes.extend_from_slice(b"\r\nx-forwarded-host: ");
    bytes.extend_from_slice(host_header.as_bytes());
    bytes.extend_from_slice(b"\r\nx-forwarded-proto: ");
    bytes.extend_from_slice(forwarded_proto.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    if request.headers().get(header::CONNECTION).is_none() {
        bytes.extend_from_slice(b"connection: upgrade\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes
}

async fn read_http_head(
    stream: &mut tokio::net::TcpStream,
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    use tokio::io::AsyncReadExt;

    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| "upstream upgrade response failed")?;
        if read == 0 {
            return Err("upstream closed before upgrade response");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_header_end(&buffer) {
            let body_start = index + 4;
            let leftover = buffer[body_start..].to_vec();
            buffer.truncate(body_start);
            return Ok((buffer, leftover));
        }
        if buffer.len() > HTTP_HEAD_CAP_BYTES {
            return Err("upstream upgrade response headers are too large");
        }
    }
}

fn parse_http_response_head(head: &[u8]) -> Result<ParsedHttpResponseHead, &'static str> {
    use axum::http::{HeaderName, HeaderValue, StatusCode};

    let text =
        std::str::from_utf8(head).map_err(|_| "upstream upgrade response was not valid HTTP")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or("missing upstream upgrade status")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .ok_or("invalid upstream upgrade status")?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("invalid upstream upgrade header");
        };
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "invalid upstream upgrade header name")?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| "invalid upstream upgrade header value")?;
        headers.push((name, value));
    }
    Ok((status, headers))
}

fn bad_gateway_response(message: &'static str) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    (StatusCode::BAD_GATEWAY, message).into_response()
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_forwardable_http_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "x-forwarded-host"
            | "x-forwarded-proto"
    )
}

fn is_forwardable_upgrade_request_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "content-length" | "transfer-encoding" | "x-forwarded-host" | "x-forwarded-proto"
    )
}

fn is_upgrade_response_header_forwardable(name: &axum::http::HeaderName) -> bool {
    !matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "content-length" | "transfer-encoding"
    )
}

fn is_upgrade_request(headers: &axum::http::HeaderMap) -> bool {
    use axum::http::header;

    headers.get(header::UPGRADE).is_some()
        && headers
            .get_all(header::CONNECTION)
            .iter()
            .any(|value| value.to_str().is_ok_and(header_has_upgrade_token))
}

fn header_has_upgrade_token(value: &str) -> bool {
    value
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
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

#[cfg(windows)]
async fn connect_named_pipe_client(
    pipe_name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, ProxyError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let mut attempts = 0u8;
    loop {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempts < 40 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => return Err(ipc_pipe_connect_error(err, pipe_name)),
        }
    }
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
                if validate_windows_pipe_client(&server, &expected_client_sid).is_err() {
                    server = create_named_pipe_server(pipe_name, false, &expected_client_sid)?;
                    continue;
                }
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
                    write_current_state(&registry, &state_write_lock, state_path, pipe_name.to_string(), listener_addrs.clone(), tls_cert_store.as_ref()).await?;
                }
            }
            _ = stop_rx.recv() => return Ok(()),
        }
    }
}

#[cfg(windows)]
fn create_named_pipe_server(
    pipe_name: &str,
    first_instance: bool,
    allowed_user_sid: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, ProxyError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let security = WindowsPipeSecurity::for_user_sid(allowed_user_sid)?;
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    // SAFETY: `security` owns a SECURITY_ATTRIBUTES value and descriptor that
    // remain alive for the duration of the create call; Tokio copies the
    // resulting OS handle into the returned `NamedPipeServer`.
    unsafe {
        options
            .create_with_security_attributes_raw(pipe_name, security.as_ptr())
            .map_err(|err| ProxyError::Ipc(format!("create named pipe {pipe_name}: {err}")))
    }
}

async fn handle_control_stream<S>(
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
    if let ProxyRequest::RegisterLease { owner_pid, routes } = request {
        return handle_connection_backed_lease_stream(&mut stream, owner_pid, routes, context)
            .await;
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
    write_response(&mut stream, &response).await?;
    Ok(should_stop)
}

async fn handle_connection_backed_lease_stream<S>(
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

async fn release_connection_backed_lease(
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

async fn write_current_state(
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

async fn handle_request(
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

async fn send_request_on_stream<S>(
    mut stream: S,
    request: ProxyRequest,
) -> Result<ProxyResponse, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    send_request_on_stream_ref(&mut stream, request).await
}

async fn send_request_on_stream_ref<S>(
    stream: &mut S,
    request: ProxyRequest,
) -> Result<ProxyResponse, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_request(stream, &request).await?;
    let response_line = read_ipc_line(stream).await?;
    serde_json::from_slice::<ProxyResponse>(&response_line)
        .map_err(|err| ProxyError::IpcProtocol(err.to_string()))
}

async fn read_proxy_request<R>(reader: &mut R) -> Result<ProxyRequest, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let request_line = read_ipc_line(reader).await?;
    serde_json::from_slice::<ProxyRequest>(&request_line)
        .map_err(|err| ProxyError::IpcProtocol(err.to_string()))
}

async fn write_request<W>(writer: &mut W, request: &ProxyRequest) -> Result<(), ProxyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    write_line_json(writer, request).await
}

async fn write_response<W>(writer: &mut W, response: &ProxyResponse) -> Result<(), ProxyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    write_line_json(writer, response).await
}

async fn write_line_json<W, T>(writer: &mut W, value: &T) -> Result<(), ProxyError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    use tokio::io::AsyncWriteExt;

    let mut bytes = serde_json::to_vec(value).map_err(|err| ProxyError::Ipc(err.to_string()))?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|err| ProxyError::Ipc(format!("write control frame: {err}")))?;
    writer
        .flush()
        .await
        .map_err(|err| ProxyError::Ipc(format!("flush control frame: {err}")))?;
    Ok(())
}

async fn read_ipc_line<R>(reader: &mut R) -> Result<Vec<u8>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .await
            .map_err(|err| ProxyError::Ipc(format!("read control frame: {err}")))?;
        if read == 0 {
            if line.is_empty() {
                return Err(ProxyError::IpcProtocol(EMPTY_CONTROL_FRAME_MESSAGE.into()));
            }
            return Ok(line);
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        if line.len() >= IPC_LINE_CAP_BYTES {
            return Err(ProxyError::IpcProtocol(format!(
                "control frame exceeds {IPC_LINE_CAP_BYTES} bytes"
            )));
        }
        line.push(byte[0]);
    }
}

#[cfg(unix)]
fn ipc_connect_error(err: std::io::Error, socket_path: &Path) -> ProxyError {
    match err.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            ProxyError::IpcUnavailable(format!("{} ({err})", socket_path.display()))
        }
        _ => ProxyError::Ipc(format!("connect {}: {err}", socket_path.display())),
    }
}

#[cfg(windows)]
fn ipc_pipe_connect_error(err: std::io::Error, pipe_name: &str) -> ProxyError {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    match err.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            ProxyError::IpcUnavailable(format!("{pipe_name} ({err})"))
        }
        _ if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
            ProxyError::IpcUnavailable(format!("{pipe_name} ({err})"))
        }
        _ => ProxyError::Ipc(format!("connect {pipe_name}: {err}")),
    }
}

#[cfg(windows)]
struct WindowsPipeSecurity {
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl WindowsPipeSecurity {
    fn for_user_sid(user_sid: &str) -> Result<Self, ProxyError> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{user_sid})\0")
            .encode_utf16()
            .collect();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `sddl` is a nul-terminated UTF-16 buffer that lives for the
        // duration of the call, and `descriptor` is a valid out pointer.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(ProxyError::Ipc(
                "build current-user named-pipe ACL failed".to_string(),
            ));
        }

        Ok(Self {
            descriptor,
            attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: descriptor.cast(),
                bInheritHandle: 0,
            },
        })
    }

    fn as_ptr(&self) -> *mut std::ffi::c_void {
        std::ptr::from_ref(&self.attributes).cast_mut().cast()
    }
}

#[cfg(windows)]
struct WindowsTokenHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsTokenHandle {
    fn drop(&mut self) {
        // SAFETY: `WindowsTokenHandle` is only constructed after a Windows API
        // returns a non-null owned HANDLE; closing it once in Drop is required.
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn current_user_sid_sddl() -> Result<String, ProxyError> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns the process pseudo-handle and
    // `token` is a valid out pointer for `OpenProcessToken`.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return Err(ProxyError::Ipc(format!(
            "open process token: {}",
            std::io::Error::last_os_error()
        )));
    }
    let token = WindowsTokenHandle(token);

    token_user_sid_sddl(token.0, "process")
}

#[cfg(windows)]
fn current_thread_user_sid_sddl() -> Result<String, ProxyError> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: after successful named-pipe impersonation, the current thread
    // may expose an impersonation token; `token` is a valid out pointer.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    if opened == 0 || token.is_null() {
        return Err(ProxyError::Ipc(format!(
            "open impersonated thread token: {}",
            std::io::Error::last_os_error()
        )));
    }
    let token = WindowsTokenHandle(token);

    token_user_sid_sddl(token.0, "thread")
}

#[cfg(windows)]
fn token_user_sid_sddl(
    token: windows_sys::Win32::Foundation::HANDLE,
    token_kind: &str,
) -> Result<String, ProxyError> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};

    let mut needed = 0u32;
    // SAFETY: the first call intentionally passes a null buffer to ask Windows
    // for the required TokenUser byte length via `needed`.
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(ProxyError::Ipc(format!(
            "query {token_kind} token size: {}",
            std::io::Error::last_os_error()
        )));
    }

    let word_len = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; word_len];
    // SAFETY: `buffer` is sized from the byte count returned by Windows above
    // and is aligned to at least pointer width for the TOKEN_USER layout.
    let got_token = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if got_token == 0 {
        return Err(ProxyError::Ipc(format!(
            "query {token_kind} token user: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: a successful `GetTokenInformation(TokenUser, ...)` writes a
    // TOKEN_USER record at the beginning of the provided buffer.
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: `token_user.User.Sid` is supplied by Windows from the token and
    // `sid_string` is a valid out pointer for the allocated UTF-16 string.
    let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) };
    if converted == 0 || sid_string.is_null() {
        return Err(ProxyError::Ipc(format!(
            "convert {token_kind} token user SID: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut len = 0usize;
    // SAFETY: `sid_string` is nul-terminated by ConvertSidToStringSidW.
    unsafe {
        while *sid_string.add(len) != 0 {
            len += 1;
        }
    }
    // SAFETY: the slice covers the initialized UTF-16 code units before the
    // terminating nul and stays valid until LocalFree below.
    let sid = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, len)) };
    // SAFETY: `sid_string` was allocated by ConvertSidToStringSidW.
    unsafe {
        let _ = windows_sys::Win32::Foundation::LocalFree(sid_string.cast());
    }
    Ok(sid)
}

#[cfg(windows)]
fn validate_windows_pipe_client(
    stream: &tokio::net::windows::named_pipe::NamedPipeServer,
    expected_sid: &str,
) -> Result<(), ProxyError> {
    let client_sid = impersonated_pipe_client_sid_sddl(stream)?;
    if client_sid != expected_sid {
        return Err(ProxyError::Ipc(
            "reject control pipe connection from another Windows user".to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn impersonated_pipe_client_sid_sddl(
    stream: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<String, ProxyError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::RevertToSelf;
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;

    struct RevertGuard;
    impl Drop for RevertGuard {
        fn drop(&mut self) {
            // SAFETY: this Drop guard is created only after a successful
            // impersonation call and restores the thread token on scope exit.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }

    // SAFETY: `stream` is a connected named-pipe server handle; Windows owns
    // the impersonation semantics and reports failure through the return code.
    let impersonated = unsafe { ImpersonateNamedPipeClient(stream.as_raw_handle()) };
    if impersonated == 0 {
        return Err(ProxyError::Ipc(format!(
            "impersonate control pipe client: {}",
            std::io::Error::last_os_error()
        )));
    }
    let _guard = RevertGuard;

    current_thread_user_sid_sddl()
}

#[cfg(windows)]
impl Drop for WindowsPipeSecurity {
    fn drop(&mut self) {
        // SAFETY: `descriptor` is allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW and freed once.
        unsafe {
            let _ = windows_sys::Win32::Foundation::LocalFree(self.descriptor.cast());
        }
    }
}

fn ensure_lpm_root(path: &Path) -> Result<(), ProxyError> {
    std::fs::create_dir_all(path).map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_control_peer(stream: &tokio::net::UnixStream) -> Result<(), ProxyError> {
    validate_unix_peer_uid(unix_control_peer_uid(stream)?, current_effective_uid())
}

#[cfg(unix)]
fn validate_unix_peer_uid(peer_uid: Option<u32>, expected_uid: u32) -> Result<(), ProxyError> {
    if let Some(peer_uid) = peer_uid
        && peer_uid != expected_uid
    {
        return Err(ProxyError::Ipc(format!(
            "reject control connection from UID {peer_uid}; expected UID {expected_uid}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn current_effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() as u32 }
}

#[cfg(target_os = "linux")]
fn unix_control_peer_uid(stream: &tokio::net::UnixStream) -> Result<Option<u32>, ProxyError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` points to valid writable storage for `libc::ucred`,
    // `len` is initialized to that storage size, and the file descriptor belongs
    // to a live Unix domain socket accepted by Tokio.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(ProxyError::Ipc(format!(
            "read control connection peer credentials: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful `getsockopt(SO_PEERCRED)` initialized the `ucred`.
    let credentials = unsafe { credentials.assume_init() };
    Ok(Some(credentials.uid))
}

#[cfg(target_os = "macos")]
fn unix_control_peer_uid(stream: &tokio::net::UnixStream) -> Result<Option<u32>, ProxyError> {
    use std::os::fd::AsRawFd;

    let mut uid = 0 as libc::uid_t;
    let mut gid = 0 as libc::gid_t;
    // SAFETY: `uid` and `gid` are valid writable pointers and the file
    // descriptor belongs to a live Unix domain socket accepted by Tokio.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(ProxyError::Ipc(format!(
            "read control connection peer credentials: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(Some(uid as u32))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn unix_control_peer_uid(_stream: &tokio::net::UnixStream) -> Result<Option<u32>, ProxyError> {
    Ok(None)
}

#[cfg(unix)]
fn process_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 performs permission/existence checking only.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_is_running(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return false;
    }
    // SAFETY: OpenProcess validates the PID/access mask and returns null on
    // failure; a non-null handle is closed before returning.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let mut exit_code = 0;
    // SAFETY: `exit_code` is valid writable storage for the queried process
    // handle; Windows reports failure through the return code.
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) != 0 };
    // SAFETY: `handle` is a non-null process handle opened above.
    unsafe {
        CloseHandle(handle);
    }
    ok && exit_code == STILL_ACTIVE as u32
}

#[cfg(not(any(unix, windows)))]
fn process_is_running(_pid: u32) -> bool {
    true
}

#[cfg(unix)]
fn read_forwarder_daemon_state(
    path: &Path,
    expected_uid: u32,
) -> Result<ProxyDaemonState, ProxyError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            ProxyError::Forwarder(format!(
                "open guarded proxy state {}: {err}",
                path.display()
            ))
        })?;
    let metadata = file.metadata().map_err(|err| {
        ProxyError::Forwarder(format!(
            "read guarded proxy state metadata {}: {err}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state {} is owned by UID {}, expected UID {expected_uid}",
            path.display(),
            metadata.uid()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state {} must not be group/world accessible (mode {mode:o})",
            path.display()
        )));
    }

    let cap_u64 = lpm_common::STATE_FILE_SIZE_CAP_BYTES;
    let cap = usize::try_from(cap_u64).map_err(|_| {
        ProxyError::Forwarder("state file cap does not fit this platform".to_string())
    })?;
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(cap));
    file.by_ref()
        .take(cap_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| {
            ProxyError::Forwarder(format!(
                "read guarded proxy state {}: {err}",
                path.display()
            ))
        })?;
    if bytes.len() > cap {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state {} exceeds {cap} bytes",
            path.display()
        )));
    }
    serde_json::from_slice(&bytes).map_err(|err| {
        ProxyError::Forwarder(format!(
            "parse guarded proxy state {}: {err}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn validate_forwarder_daemon_state(
    state: &ProxyDaemonState,
    expected_uid: u32,
    expected_addr: SocketAddr,
    mut process_alive: impl FnMut(u32) -> bool,
    mut process_uid: impl FnMut(u32) -> Option<u32>,
) -> Result<(), ProxyError> {
    if !state_contains_listener_addr(state, expected_addr) {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy state does not advertise backend listener {expected_addr}"
        )));
    }
    if !process_alive(state.pid) {
        return Err(ProxyError::Forwarder(format!(
            "guarded proxy daemon PID {} is not running",
            state.pid
        )));
    }
    match process_uid(state.pid) {
        Some(uid) if uid == expected_uid => Ok(()),
        Some(uid) => Err(ProxyError::Forwarder(format!(
            "guarded proxy daemon PID {} is owned by UID {uid}, expected UID {expected_uid}",
            state.pid
        ))),
        None => Err(ProxyError::Forwarder(format!(
            "could not verify UID for guarded proxy daemon PID {}",
            state.pid
        ))),
    }
}

#[cfg(unix)]
fn state_contains_listener_addr(state: &ProxyDaemonState, expected_addr: SocketAddr) -> bool {
    [
        state.http_addr.as_deref(),
        state.http_redirect_addr.as_deref(),
        state.tls_addr.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|addr| parse_state_listener_addr(addr) == Some(expected_addr))
}

#[cfg(unix)]
fn parse_state_listener_addr(value: &str) -> Option<SocketAddr> {
    let raw = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .unwrap_or(value);
    raw.parse().ok()
}

#[cfg(target_os = "linux")]
fn process_owner_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_linux_status_effective_uid(&status)
}

#[cfg(target_os = "linux")]
fn parse_linux_status_effective_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn process_owner_uid(pid: u32) -> Option<u32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    // SAFETY: `info` points to writable storage sized for proc_bsdinfo, and
    // proc_pidinfo reports the number of bytes written.
    let written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if written != size as libc::c_int {
        return None;
    }
    // SAFETY: proc_pidinfo wrote a complete proc_bsdinfo when `written == size`.
    let info = unsafe { info.assume_init() };
    Some(info.pbi_uid)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn process_owner_uid(_pid: u32) -> Option<u32> {
    None
}

fn write_state_file(path: &Path, state: &ProxyDaemonState) -> Result<(), ProxyError> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        ProxyError::StateWrite(format!("state path has no parent: {}", path.display()))
    })?;
    ensure_lpm_root(parent)?;
    let tmp_path = parent.join(format!(".proxy.json.{}.tmp", std::process::id()));
    let bytes =
        serde_json::to_vec_pretty(state).map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    }
    file.write_all(&bytes)
        .map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    std::fs::rename(&tmp_path, path).map_err(|err| ProxyError::StateWrite(err.to_string()))?;
    Ok(())
}

pub fn canonical_host_from_header(host_header: &str) -> Result<String, ProxyError> {
    let trimmed = host_header.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidHost {
            host: host_header.to_string(),
            reason: "host header is empty",
        });
    }
    if trimmed.starts_with('[') {
        return Err(ProxyError::InvalidHost {
            host: host_header.to_string(),
            reason: "IP literal host headers are not local-domain routes",
        });
    }

    let host = match trimmed.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => trimmed,
    };
    canonical_host(host)
}

pub fn canonical_host(host: &str) -> Result<String, ProxyError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidHost {
            host: host.to_string(),
            reason: "host is empty",
        });
    }
    if trimmed.starts_with('.') || trimmed.contains("..") {
        return Err(ProxyError::InvalidHost {
            host: host.to_string(),
            reason: "host must be a bare multi-label hostname",
        });
    }
    if trimmed
        .bytes()
        .any(|b| b <= 0x20 || matches!(b, b'/' | b'\\' | b'@' | b'*' | 0x7f))
    {
        return Err(ProxyError::InvalidHost {
            host: host.to_string(),
            reason: "host contains forbidden characters",
        });
    }

    let host = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(ProxyError::InvalidHost {
            host,
            reason: "host is empty",
        });
    }
    if !host.contains('.') {
        return Err(ProxyError::InvalidHost {
            host,
            reason: "host must be a bare multi-label hostname",
        });
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(host: &str, upstream_port: u16) -> Route {
        Route {
            host: host.to_string(),
            upstream_port,
            project_dir: PathBuf::from("/tmp/app"),
            service: Some("web".to_string()),
        }
    }

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

        let server = tokio::spawn(async move {
            serve_control_at_pipe(&server_pipe_name, &server_state_path).await
        });
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

        let server = tokio::spawn(async move {
            serve_control_at_pipe(&server_pipe_name, &server_state_path).await
        });
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
            lpm_cert::cert::generate_project_cert(&ca_cert_pem, &ca_key_pem, &extra_hostnames)
                .unwrap();
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
}
