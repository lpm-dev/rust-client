use super::*;

/// Loopback TCP relay rule from one listener to one fixed backend.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TcpForwarderRule {
    listen_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl TcpForwarderRule {
    /// Build a forwarder rule.
    ///
    /// The listener and target must both be loopback addresses, and the target
    /// port must be unprivileged.
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

    /// Backend address that receives raw forwarded TCP.
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

/// The user-daemon listener that a privileged forwarder rule delivers to.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwarderTarget {
    /// The daemon's HTTPS listener.
    #[serde(rename = "https")]
    Https,
    /// The daemon's HTTP-to-HTTPS redirect listener.
    #[serde(rename = "httpRedirect")]
    HttpRedirect,
}

impl fmt::Display for ForwarderTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Https => "HTTPS",
            Self::HttpRedirect => "HTTP redirect",
        })
    }
}

/// Unix-only guard for a root-owned low-port forwarder.
///
/// The guard never stores a backend address. Each connection resolves it from
/// the user daemon's state file, so the daemon may bind any free loopback port
/// and the forwarder follows it across restarts.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixForwarderGuard {
    state_path: PathBuf,
    expected_uid: u32,
    target: ForwarderTarget,
}

#[cfg(unix)]
impl UnixForwarderGuard {
    /// Build a guard that delivers forwarded traffic only to one user's live proxy daemon.
    pub fn new(state_path: impl Into<PathBuf>, expected_uid: u32, target: ForwarderTarget) -> Self {
        Self {
            state_path: state_path.into(),
            expected_uid,
            target,
        }
    }

    /// Resolve the backend the configured user daemon currently advertises for
    /// this guard's listener, after checking that the state file and the daemon
    /// process both belong to the expected user.
    pub fn resolve(&self) -> Result<SocketAddr, ProxyError> {
        let state = read_forwarder_daemon_state(&self.state_path, self.expected_uid)?;
        validate_forwarder_daemon_state(
            &state,
            self.expected_uid,
            self.target,
            process_is_running,
            process_owner_uid,
        )
    }
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
    start_tcp_forwarder_on_listener(listener, rule.target_addr())
}

/// Serve a guarded Unix loopback forwarder on an already-bound listener.
///
/// Every accepted connection is relayed to the backend the guard resolves at
/// that moment, and dropped when the guard rejects the user daemon's state.
/// Taking a bound listener lets the privileged forwarder bind its low ports
/// as root and then give up root before it relays anything.
#[cfg(unix)]
pub fn start_guarded_tcp_forwarder(
    listener: tokio::net::TcpListener,
    guard: UnixForwarderGuard,
) -> Result<TcpForwarderHandle, ProxyError> {
    serve_tcp_forwarder(listener, move |inbound| {
        forward_guarded_tcp_connection(inbound, guard.clone())
    })
}

/// Start a loopback TCP forwarder from an already-bound listener.
pub fn start_tcp_forwarder_on_listener(
    listener: tokio::net::TcpListener,
    target_addr: SocketAddr,
) -> Result<TcpForwarderHandle, ProxyError> {
    if !target_addr.ip().is_loopback() || target_addr.port() < 1024 {
        return Err(ProxyError::Forwarder(format!(
            "forwarder target must be loopback with port >=1024, got {target_addr}"
        )));
    }
    serve_tcp_forwarder(listener, move |inbound| {
        forward_tcp_connection(inbound, target_addr)
    })
}

fn serve_tcp_forwarder<Forward, Forwarding>(
    listener: tokio::net::TcpListener,
    forward: Forward,
) -> Result<TcpForwarderHandle, ProxyError>
where
    Forward: Fn(tokio::net::TcpStream) -> Forwarding + Send + 'static,
    Forwarding: std::future::Future<Output = ()> + Send + 'static,
{
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Forwarder(format!("read TCP forwarder bind addr: {err}")))?;
    if !addr.ip().is_loopback() {
        return Err(ProxyError::Forwarder(format!(
            "forwarder listener must be loopback, got {addr}"
        )));
    }

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_FORWARDED_CONNECTIONS));
    tokio::spawn(async move {
        let mut retry_delay = ACCEPT_RETRY_INITIAL_DELAY;
        loop {
            let permit = tokio::select! {
                permit = Arc::clone(&connections).acquire_owned() => {
                    permit.expect("the forwarder never closes its connection semaphore")
                }
                _ = &mut shutdown_rx => break,
            };
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                _ = &mut shutdown_rx => break,
            };
            match accepted {
                Ok((inbound, _)) => {
                    retry_delay = ACCEPT_RETRY_INITIAL_DELAY;
                    let forwarding = forward(inbound);
                    tokio::spawn(async move {
                        forwarding.await;
                        drop(permit);
                    });
                }
                // Accept errors such as descriptor exhaustion persist; back off instead of spinning.
                Err(_) => {
                    drop(permit);
                    tokio::select! {
                        () = tokio::time::sleep(retry_delay) => {}
                        _ = &mut shutdown_rx => break,
                    }
                    retry_delay = (retry_delay * 2).min(ACCEPT_RETRY_MAX_DELAY);
                }
            }
        }
    });

    Ok(TcpForwarderHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

const MAX_FORWARDED_CONNECTIONS: usize = 1024;
const ACCEPT_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(10);
const ACCEPT_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);

async fn forward_tcp_connection(mut inbound: tokio::net::TcpStream, target_addr: SocketAddr) {
    let Ok(mut outbound) = tokio::net::TcpStream::connect(target_addr).await else {
        return;
    };
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
}

#[cfg(unix)]
async fn forward_guarded_tcp_connection(inbound: tokio::net::TcpStream, guard: UnixForwarderGuard) {
    let Ok(Ok(target_addr)) = tokio::task::spawn_blocking(move || guard.resolve()).await else {
        return;
    };
    forward_tcp_connection(inbound, target_addr).await;
}
