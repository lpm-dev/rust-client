//! axum HTTP server setup and lifecycle.
//!
//! Binds to `127.0.0.1:{port}` (never `0.0.0.0`) and serves:
//! - REST API at `/api/*`
//! - SSE stream at `/api/stream`
//! - Embedded web UI at `/*` (SPA fallback)
//!
//! # Security
//!
//! - Binds to loopback only — not accessible from other machines on the network.
//! - Strict CORS: only `http://127.0.0.1:{port}` and `http://localhost:{port}`
//!   origins are allowed. This prevents malicious websites from exfiltrating
//!   captured traffic via cross-origin requests.

use crate::InspectorHandle;
use crate::state::InspectorState;
use axum::Router;
use axum::routing::{get, post, put};
use lpm_common::LpmError;
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Start the inspector server on the given port.
///
/// Returns a handle for shutdown. The server runs in a background tokio task.
pub async fn start(state: InspectorState, port: u16) -> Result<InspectorHandle, LpmError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Strict CORS: only allow the inspector's own origin (both 127.0.0.1 and localhost).
    // This prevents malicious websites from reading captured traffic via fetch().
    let allowed_origins = [
        format!("http://127.0.0.1:{port}").parse().unwrap(),
        format!("http://localhost:{port}").parse().unwrap(),
    ];
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let app = Router::new()
        // API routes
        .route("/api/status", get(crate::api::status))
        .route("/api/requests", get(crate::api::list_requests))
        .route("/api/requests/{id}", get(crate::api::get_request))
        .route(
            "/api/requests/{id}/replay",
            post(crate::api::replay_request),
        )
        .route(
            "/api/requests/{id}/diagnose",
            get(crate::api::diagnose_request),
        )
        .route("/api/requests/{id}/curl", get(crate::api::export_curl))
        .route("/api/requests/{id}/export", get(crate::api::export_webhook))
        .route(
            "/api/requests/{id}/export/redacted",
            post(crate::api::export_redacted),
        )
        .route(
            "/api/requests/{id}/fixture",
            get(crate::api::export_fixture),
        )
        .route(
            "/api/requests/{id}/provider-cli",
            get(crate::api::export_provider_cli),
        )
        .route("/api/requests/{id}/tags", put(crate::api::update_tags))
        .route("/api/replay/sequence", post(crate::api::replay_sequence))
        .route("/api/snapshots", post(crate::api::create_snapshot))
        .route("/api/snapshots/import", post(crate::api::import_snapshot))
        .route("/api/diff/{id1}/{id2}", get(crate::api::diff_requests))
        .route("/api/failures/patterns", get(crate::api::failure_patterns))
        .route("/api/search", get(crate::api::search))
        .route("/api/sessions", get(crate::api::list_sessions))
        .route("/api/sessions/{id}", get(crate::api::get_session))
        .route(
            "/api/sessions/{id}/requests",
            get(crate::api::list_session_requests),
        )
        .route("/api/sessions/{id}/name", put(crate::api::rename_session))
        .route("/api/db/requests", get(crate::api::list_db_requests))
        .route("/api/stream", get(crate::sse::stream))
        .route("/api/ws/stream", get(crate::sse::ws_stream))
        .route("/api/ws/connections", get(crate::api::list_ws_connections))
        .route("/api/ws/connections/{id}", get(crate::api::list_ws_frames))
        // Static UI (SPA fallback)
        .fallback(get(crate::ui::serve_ui))
        .layer(cors)
        .with_state(state);

    // Bind to loopback ONLY — never 0.0.0.0
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            LpmError::Tunnel(format!(
                "inspector port {port} is already in use. Use --inspect-port to choose a different port"
            ))
        } else {
            LpmError::Tunnel(format!("failed to bind inspector to {addr}: {e}"))
        }
    })?;

    let url = format!("http://127.0.0.1:{port}");
    tracing::info!("inspector listening on {url}");

    // Spawn the server in a background task
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
                tracing::debug!("inspector server shutting down");
            })
            .await
            .ok();
    });

    Ok(InspectorHandle {
        port,
        url,
        shutdown_tx,
    })
}
