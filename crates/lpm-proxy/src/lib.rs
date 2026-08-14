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
const CONTROL_CONNECTION_LIMIT: usize = 64;
const HTTP_HEAD_CAP_BYTES: usize = 64 * 1024;
const EMPTY_CONTROL_FRAME_MESSAGE: &str = "empty control frame";
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_CONNECTION_RELEASE_TIMEOUT: Duration = Duration::from_secs(1);

mod client;
mod control;
mod error;
mod host;
mod http;
mod paths;
mod platform;
mod protocol;
mod registry;
mod state_file;
mod tcp_forward;
#[cfg(test)]
mod tests;
mod tls;
mod types;
#[cfg(unix)]
mod unix_transport;
#[cfg(windows)]
mod windows_pipes;

#[cfg(unix)]
pub use client::send_request_to_path;
#[cfg(windows)]
pub use client::send_request_to_pipe;
pub use client::{RouteLease, register, register_staged, send_request, status};
#[cfg(unix)]
pub use control::{serve_control_at_path, serve_control_at_path_with_options};
#[cfg(windows)]
pub use control::{serve_control_at_pipe, serve_control_at_pipe_with_options};
pub use control::{serve_control_default, serve_control_default_with_options};
pub use error::ProxyError;
pub use host::{canonical_host, canonical_host_from_header};
pub use http::{
    FrontendUpstream, HttpProxyHandle, HttpProxyState, start_http_frontend_on_listener,
    start_http_frontend_on_listener_with_upstream, start_http_proxy, start_http_proxy_on_listener,
};
#[cfg(windows)]
pub use paths::proxy_pipe_name_from_env;
#[cfg(unix)]
pub use paths::proxy_socket_path_from_env;
pub use paths::{
    proxy_pipe_name_for_root, proxy_state_path_from_env, read_status, read_status_from_path,
};
pub use registry::RouteRegistry;
pub use tcp_forward::{
    TcpForwarderHandle, TcpForwarderRule, start_tcp_forwarder, start_tcp_forwarder_on_listener,
};
#[cfg(unix)]
pub use tcp_forward::{UnixForwarderGuard, start_guarded_tcp_forwarder};
pub use tls::{
    start_tls_frontend_on_listener, start_tls_frontend_on_listener_with_pem,
    start_tls_frontend_on_listener_with_pem_and_upstream,
};
pub use types::{
    ProxyDaemonOptions, ProxyDaemonState, ProxyRequest, ProxyResponse, ProxyStatus,
    RegisteredRoute, Route, RouteLeaseId, RouteStatus,
};

#[cfg(all(test, unix))]
pub(crate) use client::{LeaseConnection, register_lease_to_path};
#[cfg(test)]
pub(crate) use http::find_header_end;
pub(crate) use http::{format_loopback_bind_error, proxy_http_request_inner, start_http_redirect};
#[cfg(all(test, target_os = "linux"))]
pub(crate) use platform::parse_linux_status_effective_uid;
#[cfg(all(test, unix))]
pub(crate) use platform::{current_effective_uid, unix_control_peer_uid, validate_unix_peer_uid};
pub(crate) use platform::{ensure_lpm_root, process_is_running};
#[cfg(unix)]
pub(crate) use platform::{
    process_owner_uid, read_forwarder_daemon_state, validate_forwarder_daemon_state,
    validate_unix_control_peer,
};
#[cfg(test)]
pub(crate) use protocol::read_proxy_request;
pub(crate) use protocol::{
    read_proxy_request_after_activity, read_proxy_request_with_timeout, send_request_on_stream,
    send_request_on_stream_ref, write_response,
};
pub(crate) use state_file::write_state_file;
#[cfg(all(test, unix))]
pub(crate) use tls::cert_covers_hostname;
pub(crate) use tls::{
    TlsCertificateStore, prepare_tls_certificates_if_enabled, refresh_tls_cert_store,
    start_tls_proxy,
};
#[cfg(unix)]
pub(crate) use unix_transport::ipc_connect_error;
#[cfg(windows)]
pub(crate) use windows_pipes::{
    connect_named_pipe_client, create_named_pipe_server, current_user_sid_sddl,
    handle_windows_control_stream,
};
