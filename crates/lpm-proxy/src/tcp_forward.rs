use super::*;

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
