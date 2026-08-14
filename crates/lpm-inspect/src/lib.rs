//! Local HTTP traffic inspector for LPM tunnel.
//!
//! Provides a browser-based UI at `http://127.0.0.1:{port}` for inspecting
//! all HTTP traffic flowing through an LPM tunnel. Features:
//!
//! - Real-time SSE streaming of captured requests
//! - REST API for historical request browsing, detail views, and replay
//! - Embedded web UI (compiled into the binary via `rust-embed`)
//! - Provider-aware webhook intelligence (Stripe, GitHub, Clerk, etc.)
//!
//! # Security
//!
//! The inspector binds exclusively to `127.0.0.1` (never `0.0.0.0`) and
//! enforces strict CORS to prevent exfiltration from malicious local pages.

pub mod api;
pub mod db;
pub mod diff;
pub mod export;
pub mod failure;
pub mod redact;
pub mod replay;
pub mod server;
pub mod snapshot;
pub mod sse;
pub mod state;
mod tests;
pub mod ui;

/// Suggested port for the inspector UI when the user passes `--inspect-port`
/// without a value, or for legacy callers that want to attempt a stable port.
///
/// **Default behavior is auto-pick (`port = 0`).** Callers should only use
/// this constant if they need a fixed port — see [`start`].
pub const DEFAULT_PORT: u16 = 4400;

/// Start the inspector server.
///
/// Pass `port = 0` to auto-pick a free ephemeral port (the recommended
/// default — race-free against any other service occupying a fixed port).
/// Pass a non-zero port to bind it strictly and fail loudly on
/// `AddrInUse` (the `--inspect-port N` contract).
///
/// The returned [`InspectorHandle`] reports the actually-bound port via
/// [`InspectorHandle::port`] and the matching `http://127.0.0.1:<port>` URL
/// via [`InspectorHandle::url`] — derive both from the handle, never from
/// the input port.
///
/// Returns a handle that can be used to stop the server gracefully.
/// The server runs in the background on a spawned tokio task.
pub async fn start(
    state: state::InspectorState,
    port: u16,
) -> Result<InspectorHandle, lpm_common::LpmError> {
    server::start(state, port).await
}

/// Handle to a running inspector server.
///
/// Call [`InspectorHandle::shutdown`] to wait for graceful shutdown and surface
/// any server failure.
pub struct InspectorHandle {
    pub port: u16,
    pub url: String,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<Result<(), lpm_common::LpmError>>,
}

impl InspectorHandle {
    /// Stop the server gracefully and wait until its listener is closed.
    pub async fn shutdown(mut self) -> Result<(), lpm_common::LpmError> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        self.server_task.await.map_err(|error| {
            lpm_common::LpmError::Tunnel(format!("inspector server task failed: {error}"))
        })?
    }
}
