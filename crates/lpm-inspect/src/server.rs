//! axum HTTP server setup and lifecycle.
//!
//! Binds to `127.0.0.1:{port}` (never `0.0.0.0`) and serves the REST
//! API, SSE stream, and embedded web UI. Strict CORS pinned to the
//! actually-bound port; every `/api/*` route requires the per-process
//! auth token from `InspectorState`.

use crate::InspectorHandle;
use crate::state::InspectorState;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post, put};
use lpm_common::LpmError;
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Accepts the token via `Authorization: Bearer` or `?token=` (the
/// latter for `EventSource`, which cannot set headers). Cookies are
/// not accepted — they are host-scoped, not port-scoped, on `127.0.0.1`.
async fn require_auth_token(
    State(state): State<InspectorState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let expected = state.auth_token().as_bytes();

    let presented_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.as_bytes().to_vec());

    let presented_query = request.uri().query().and_then(|q| {
        for pair in q.split('&') {
            if let Some(v) = pair.strip_prefix("token=") {
                return Some(v.as_bytes().to_vec());
            }
        }
        None
    });

    let presented = presented_header.or(presented_query);

    let ok = presented
        .as_deref()
        .is_some_and(|p| p.len() == expected.len() && p.ct_eq(expected).into());

    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

/// Start the inspector server on the given port.
///
/// Pass `port = 0` to let the OS pick a free ephemeral port (preferred default
/// — race-free against any other service occupying a fixed port). Pass an
/// explicit non-zero port to bind that exact port and fail loudly if it's
/// already in use (the contract for `--inspect-port N`).
///
/// Returns a handle for shutdown. The server runs in a background tokio task.
pub async fn start(state: InspectorState, port: u16) -> Result<InspectorHandle, LpmError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Bind FIRST so we know the actual port (matters when `port == 0` and the
    // OS picks). CORS allowlist + advertised URL are derived from the bound
    // port — never from the requested port.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            LpmError::Tunnel(format!(
                "inspector port {port} is already in use. Pass `--inspect-port <N>` to choose another, or omit the flag to auto-pick a free port."
            ))
        } else {
            LpmError::Tunnel(format!("failed to bind inspector to {addr}: {e}"))
        }
    })?;

    let bound_port = listener
        .local_addr()
        .map_err(|e| LpmError::Tunnel(format!("failed to read inspector bound port: {e}")))?
        .port();

    // Strict CORS: only allow the inspector's own origin (both 127.0.0.1 and
    // localhost), at the ACTUALLY-BOUND port.
    let allowed_origins = [
        format!("http://127.0.0.1:{bound_port}").parse().unwrap(),
        format!("http://localhost:{bound_port}").parse().unwrap(),
    ];
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let api_routes = Router::new()
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth_token,
        ));

    // SPA fallback stays unauthenticated so the browser can fetch
    // HTML/JS/CSS; the injected bootstrap then carries the token on
    // every API call.
    let app = Router::new()
        .merge(api_routes)
        .fallback(get(crate::ui::serve_ui))
        .layer(cors)
        .with_state(state.clone());

    let url = format!(
        "http://127.0.0.1:{bound_port}/?token={}",
        state.auth_token()
    );
    tracing::info!(port = bound_port, "inspector listening on loopback");

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
        port: bound_port,
        url,
        shutdown_tx,
    })
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::state::InspectorState;

    /// `port = 0` must auto-pick a free ephemeral port; the handle reports the
    /// actually-bound port (never 0).
    #[tokio::test]
    async fn start_with_zero_port_auto_picks_free_ephemeral() {
        let state = InspectorState::new(0);
        let handle = start(state, 0).await.expect("inspector should bind");
        assert_ne!(handle.port, 0, "auto-picked port must not be 0");
        assert!(
            handle.port >= 1024,
            "OS-assigned ephemeral ports are typically >=1024, got {}",
            handle.port
        );
        let base = format!("http://127.0.0.1:{}/", handle.port);
        assert!(
            handle.url.starts_with(&base),
            "url {} does not start with bound base {}",
            handle.url,
            base,
        );
        assert!(
            handle.url.contains("?token="),
            "url {} should embed the auth token",
            handle.url
        );
        handle.shutdown();
    }

    /// Two simultaneous auto-pick starts must each get a distinct free port —
    /// proves there's no fixed-port race.
    #[tokio::test]
    async fn two_auto_picked_inspectors_get_distinct_ports() {
        let h1 = start(InspectorState::new(0), 0).await.unwrap();
        let h2 = start(InspectorState::new(0), 0).await.unwrap();
        assert_ne!(h1.port, h2.port);
        h1.shutdown();
        h2.shutdown();
    }

    /// Explicit non-zero port is bound exactly. Re-binding the same explicit
    /// port while the first listener is alive must fail with the
    /// already-in-use diagnostic.
    #[tokio::test]
    async fn explicit_port_strict_bind_and_addrinuse_message() {
        // Use the OS to find a free port we can then claim explicitly.
        let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let chosen = probe.local_addr().unwrap().port();
        drop(probe);

        let h1 = start(InspectorState::new(0), chosen)
            .await
            .expect("first explicit bind should succeed");
        assert_eq!(h1.port, chosen);

        let err = match start(InspectorState::new(0), chosen).await {
            Err(e) => e,
            Ok(handle) => {
                handle.shutdown();
                panic!("second explicit bind on same port must fail");
            }
        };
        let msg = err.to_string();
        assert!(
            msg.contains("already in use"),
            "expected 'already in use' diagnostic, got: {msg}"
        );
        assert!(
            msg.contains("--inspect-port") || msg.contains("auto-pick"),
            "expected remediation hint, got: {msg}"
        );

        h1.shutdown();
    }
}
