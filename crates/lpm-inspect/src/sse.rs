//! Server-Sent Events (SSE) endpoint for real-time request streaming.
//!
//! Browsers connect to `GET /api/stream` and receive a continuous stream of
//! captured requests as they flow through the tunnel. Uses `tokio::sync::broadcast`
//! so multiple browser tabs can subscribe independently.
//!
//! # Backpressure
//!
//! The broadcast channel has a bounded capacity (128 events). If a browser
//! falls behind (e.g., tab in background), it receives a `lagged` event
//! with the count of missed events, and should re-fetch via the REST API.

use crate::state::InspectorState;
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::Stream;
use std::convert::Infallible;

/// SSE stream handler.
///
/// Each connected browser gets an independent receiver from the broadcast channel.
/// Events are JSON-serialized `CapturedWebhook` objects.
pub async fn stream(
    State(state): State<InspectorState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.subscribe();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(webhook) => {
                    // Serialize the webhook as a compact JSON event
                    match serde_json::to_string(&*webhook) {
                        Ok(json) => {
                            yield Ok(Event::default().event("request").data(json));
                        }
                        Err(e) => {
                            tracing::warn!("failed to serialize SSE event: {e}");
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    // Browser fell behind — send a gap marker so it knows to re-fetch
                    let gap = serde_json::json!({ "missed": count });
                    yield Ok(Event::default().event("lagged").data(gap.to_string()));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    // Server is shutting down
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// SSE stream for WebSocket events.
pub async fn ws_stream(
    State(state): State<InspectorState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.subscribe_ws();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    match serde_json::to_string(&*event) {
                        Ok(json) => {
                            yield Ok(Event::default().event("ws_event").data(json));
                        }
                        Err(e) => {
                            tracing::warn!("failed to serialize WS SSE event: {e}");
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                    let gap = serde_json::json!({ "missed": count });
                    yield Ok(Event::default().event("ws_lagged").data(gap.to_string()));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}
