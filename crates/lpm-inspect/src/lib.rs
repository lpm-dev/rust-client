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

/// Default port for the inspector UI.
pub const DEFAULT_PORT: u16 = 4400;

/// Start the inspector server.
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
/// Dropping the handle does NOT stop the server — call [`InspectorHandle::shutdown`]
/// explicitly for graceful shutdown.
pub struct InspectorHandle {
    pub port: u16,
    pub url: String,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl InspectorHandle {
    /// Signal the server to shut down gracefully.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}
