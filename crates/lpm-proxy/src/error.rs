use super::*;

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
