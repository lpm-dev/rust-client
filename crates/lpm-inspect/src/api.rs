//! REST API handlers for the inspector.
//!
//! All endpoints return JSON. The API is consumed by the embedded browser UI
//! and is also usable by external tools (curl, scripts).

use crate::state::InspectorState;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

/// `GET /api/requests` — list all captured requests (newest first).
///
/// Returns the in-memory buffer contents. For historical data beyond the
/// buffer capacity, a future SQLite backend will be queried.
pub async fn list_requests(State(state): State<InspectorState>) -> Json<ListRequestsResponse> {
    let requests = state.get_all().await;
    let total = requests.len();

    // Convert to summary format (no bodies) and reverse for newest-first
    let items: Vec<RequestSummary> = requests
        .into_iter()
        .rev()
        .map(RequestSummary::from)
        .collect();

    Json(ListRequestsResponse { total, items })
}

/// `GET /api/requests/:id` — get full detail for a single request.
///
/// Returns the complete request including headers and bodies.
pub async fn get_request(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
) -> Result<Json<RequestDetail>, StatusCode> {
    let webhook = state.get_by_id(&id).await.ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(RequestDetail::from(webhook)))
}

/// `GET /api/status` — inspector server status.
pub async fn status(State(state): State<InspectorState>) -> Json<StatusResponse> {
    let count = state.count().await;
    let tunnel_url = state.get_tunnel_url().await;

    Json(StatusResponse {
        inspector: true,
        local_port: state.local_port(),
        tunnel_url,
        captured_count: count,
    })
}

/// `GET /api/diff/:id1/:id2` — structural diff between two requests' bodies.
///
/// Parses both request bodies as JSON and produces a structural diff.
/// Falls back to comparing bodies as opaque strings if not valid JSON.
pub async fn diff_requests(
    State(state): State<InspectorState>,
    Path((id1, id2)): Path<(String, String)>,
) -> Result<Json<DiffResponse>, StatusCode> {
    let wh1 = state.get_by_id(&id1).await.ok_or(StatusCode::NOT_FOUND)?;
    let wh2 = state.get_by_id(&id2).await.ok_or(StatusCode::NOT_FOUND)?;

    // Diff request bodies
    let request_diff = diff_bodies(&wh1.request_body, &wh2.request_body);

    // Diff response bodies
    let response_diff = diff_bodies(&wh1.response_body, &wh2.response_body);

    // Diff request headers
    let header_diff = diff_headers(&wh1.request_headers, &wh2.request_headers);

    let request_summary = crate::diff::diff_summary(&request_diff);
    let response_summary = crate::diff::diff_summary(&response_diff);
    let header_summary = crate::diff::diff_summary(&header_diff);

    Ok(Json(DiffResponse {
        old_id: id1,
        new_id: id2,
        request_body: request_diff,
        request_body_summary: request_summary,
        response_body: response_diff,
        response_body_summary: response_summary,
        headers: header_diff,
        headers_summary: header_summary,
    }))
}

/// Diff two body byte slices. Attempts JSON structural diff first,
/// falls back to a single Changed entry if bodies aren't valid JSON.
fn diff_bodies(old: &[u8], new: &[u8]) -> Vec<crate::diff::DiffEntry> {
    if old == new {
        return Vec::new();
    }

    let old_json = serde_json::from_slice::<serde_json::Value>(old);
    let new_json = serde_json::from_slice::<serde_json::Value>(new);

    match (old_json, new_json) {
        (Ok(old_val), Ok(new_val)) => crate::diff::diff_json(&old_val, &new_val),
        _ => {
            // Not both valid JSON — report as a single opaque change
            let old_str = String::from_utf8_lossy(old);
            let new_str = String::from_utf8_lossy(new);
            if old_str == new_str {
                Vec::new()
            } else {
                vec![crate::diff::DiffEntry {
                    path: String::new(),
                    kind: crate::diff::DiffKind::Changed,
                    old: Some(serde_json::Value::String(old_str.into_owned())),
                    new: Some(serde_json::Value::String(new_str.into_owned())),
                }]
            }
        }
    }
}

/// Diff two header maps as JSON objects.
fn diff_headers(
    old: &std::collections::HashMap<String, String>,
    new: &std::collections::HashMap<String, String>,
) -> Vec<crate::diff::DiffEntry> {
    let old_val = serde_json::to_value(old).unwrap_or_default();
    let new_val = serde_json::to_value(new).unwrap_or_default();
    crate::diff::diff_json(&old_val, &new_val)
}

/// `POST /api/requests/:id/replay` — replay a single request with modifications.
///
/// Accepts a JSON body with optional overrides (path, method, headers, body).
/// Returns the replay result including comparison with the original response.
pub async fn replay_request(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
    Json(options): Json<crate::replay::ReplayOptions>,
) -> Result<Json<crate::replay::ReplayStudioResult>, StatusCode> {
    let webhook = state.get_by_id(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    let port = state.local_port();

    let result = crate::replay::replay_with_options(&webhook, &options, port)
        .await
        .map_err(|e| {
            tracing::warn!("replay failed for {id}: {e}");
            StatusCode::BAD_GATEWAY
        })?;

    Ok(Json(result))
}

/// `POST /api/replay/sequence` — replay a sequence of requests in order.
///
/// Accepts a JSON body with request IDs, delay, and optional port override.
/// Returns results for each request in the sequence.
pub async fn replay_sequence(
    State(state): State<InspectorState>,
    Json(options): Json<crate::replay::SequenceReplayOptions>,
) -> Result<Json<crate::replay::SequenceReplayResult>, StatusCode> {
    if options.ids.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if options.ids.len() > 50 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let port = state.local_port();

    let result = crate::replay::replay_sequence(&state, &options, port)
        .await
        .map_err(|e| {
            tracing::warn!("sequence replay failed: {e}");
            StatusCode::BAD_GATEWAY
        })?;

    Ok(Json(result))
}

/// `GET /api/requests/:id/diagnose` — diagnose a single failed request.
///
/// Returns failure classification, error extraction, and actionable guidance.
/// Returns 204 No Content for successful requests (status < 400).
pub async fn diagnose_request(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
) -> Result<axum::response::Response, StatusCode> {
    let webhook = state.get_by_id(&id).await.ok_or(StatusCode::NOT_FOUND)?;

    match crate::failure::diagnose(&webhook) {
        Some(diagnosis) => Ok(Json(diagnosis).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

/// `GET /api/failures/patterns` — detect failure patterns across recent requests.
///
/// Analyzes the in-memory buffer for related failure clusters.
pub async fn failure_patterns(
    State(state): State<InspectorState>,
) -> Json<Vec<crate::failure::FailurePattern>> {
    let requests = state.get_all().await;
    let patterns = crate::failure::detect_patterns(&requests);
    Json(patterns)
}

/// `GET /api/requests/:id/curl` — export a request as a runnable cURL command.
pub async fn export_curl(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
    Query(params): Query<CurlExportParams>,
) -> Result<String, StatusCode> {
    let webhook = state.get_by_id(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    Ok(crate::export::to_curl(&webhook, params.url.as_deref()))
}

/// `POST /api/requests/:id/export/redacted` — export with automatic redaction.
///
/// Accepts optional redaction rules in the body. If no body is provided,
/// default rules are applied.
pub async fn export_redacted(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
    body: Option<Json<crate::redact::RedactionRules>>,
) -> Result<Json<crate::redact::RedactionResult>, StatusCode> {
    let webhook = state.get_by_id(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    let export = crate::export::to_webhook_json(&webhook);
    let rules = body
        .map(|b| b.0)
        .unwrap_or_else(crate::redact::default_rules);
    let result = crate::redact::redact(&export, &rules);
    Ok(Json(result))
}

/// `GET /api/requests/:id/export` — export a request as a portable .lpm-webhook JSON.
pub async fn export_webhook(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
) -> Result<Json<crate::export::WebhookExport>, StatusCode> {
    let webhook = state.get_by_id(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(crate::export::to_webhook_json(&webhook)))
}

/// `GET /api/requests/:id/fixture` — export a request as a test fixture.
pub async fn export_fixture(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
) -> Result<String, StatusCode> {
    let webhook = state.get_by_id(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    Ok(crate::export::to_test_fixture(&webhook))
}

/// `GET /api/requests/:id/provider-cli` — export as a provider-specific CLI command.
pub async fn export_provider_cli(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
) -> Result<String, StatusCode> {
    let webhook = state.get_by_id(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    crate::export::to_provider_cli(&webhook).ok_or(StatusCode::NOT_FOUND)
}

/// `PUT /api/requests/:id/tags` — update tags for a request.
pub async fn update_tags(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateTagsBody>,
) -> Result<StatusCode, StatusCode> {
    let db = state.db().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // Validate tags
    if body.tags.len() > 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.tags.iter().any(|t| t.len() > 100) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let updated = db.update_tags(&id, &body.tags).await.map_err(|e| {
        tracing::warn!("tag update error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if updated {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
pub struct RenameSessionBody {
    pub name: String,
}

#[derive(Deserialize)]
pub struct CurlExportParams {
    pub url: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateTagsBody {
    pub tags: Vec<String>,
}

/// `POST /api/snapshots` — create a shareable snapshot from request IDs.
///
/// Applies redaction automatically. Returns the snapshot JSON that can be
/// saved as a `.lpm-webhook` file and shared with teammates.
pub async fn create_snapshot(
    State(state): State<InspectorState>,
    Json(options): Json<crate::snapshot::SnapshotOptions>,
) -> Result<Json<crate::snapshot::Snapshot>, StatusCode> {
    if options.ids.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if options.ids.len() > 100 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Collect webhooks by ID
    let mut webhooks = Vec::with_capacity(options.ids.len());
    for id in &options.ids {
        let wh = state.get_by_id(id).await.ok_or(StatusCode::NOT_FOUND)?;
        webhooks.push(wh);
    }

    let rules = options
        .redaction
        .unwrap_or_else(crate::redact::default_rules);

    let snapshot = crate::snapshot::create_snapshot(&webhooks, options.description, &rules);

    Ok(Json(snapshot))
}

/// `POST /api/snapshots/import` — import a snapshot and add webhooks to the inspector.
///
/// Parses the snapshot, validates it, and pushes each webhook into the
/// inspector state for browsing and replay.
pub async fn import_snapshot(
    State(state): State<InspectorState>,
    body: String,
) -> Result<Json<ImportSnapshotResponse>, StatusCode> {
    let snapshot = crate::snapshot::import_snapshot(&body).map_err(|e| {
        tracing::warn!("snapshot import failed: {e}");
        StatusCode::BAD_REQUEST
    })?;

    let mut imported = 0;
    for export in &snapshot.webhooks {
        let captured = crate::snapshot::snapshot_to_captured(export);
        state.push(captured).await;
        imported += 1;
    }

    Ok(Json(ImportSnapshotResponse {
        imported,
        description: snapshot.metadata.description,
        providers: snapshot.metadata.providers,
    }))
}

#[derive(Serialize)]
pub struct ImportSnapshotResponse {
    pub imported: usize,
    pub description: Option<String>,
    pub providers: Vec<String>,
}

/// `GET /api/ws/connections` — list active and recent WebSocket connections.
pub async fn list_ws_connections(
    State(state): State<InspectorState>,
) -> Json<Vec<WsConnectionSummary>> {
    let events = state.get_ws_events().await;

    // Group by connection_id
    let mut connections: std::collections::HashMap<String, WsConnectionSummary> =
        std::collections::HashMap::new();

    for event in &events {
        let id = event.connection_id().to_string();
        let entry = connections
            .entry(id.clone())
            .or_insert_with(|| WsConnectionSummary {
                connection_id: id,
                url: String::new(),
                started_at: String::new(),
                ended_at: None,
                frame_count: 0,
                inbound_frames: 0,
                outbound_frames: 0,
                total_bytes: 0,
            });

        match event {
            lpm_tunnel::ws_capture::WsEvent::Connected { url, timestamp, .. } => {
                entry.url = url.clone();
                entry.started_at = timestamp.clone();
            }
            lpm_tunnel::ws_capture::WsEvent::Frame {
                direction, size, ..
            } => {
                entry.frame_count += 1;
                entry.total_bytes += size;
                match direction {
                    lpm_tunnel::ws_capture::FrameDirection::Inbound => entry.inbound_frames += 1,
                    lpm_tunnel::ws_capture::FrameDirection::Outbound => entry.outbound_frames += 1,
                }
            }
            lpm_tunnel::ws_capture::WsEvent::Closed { timestamp, .. } => {
                entry.ended_at = Some(timestamp.clone());
            }
        }
    }

    let mut result: Vec<WsConnectionSummary> = connections.into_values().collect();
    result.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    Json(result)
}

/// `GET /api/ws/connections/:id` — list frames for a specific WebSocket connection.
pub async fn list_ws_frames(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
) -> Json<Vec<lpm_tunnel::ws_capture::WsEvent>> {
    let events = state.get_ws_connection_events(&id).await;
    Json(events)
}

#[derive(Serialize)]
pub struct WsConnectionSummary {
    pub connection_id: String,
    pub url: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub frame_count: usize,
    pub inbound_frames: usize,
    pub outbound_frames: usize,
    pub total_bytes: usize,
}

/// `GET /api/search?q=...&provider=...&status=...&limit=...` — full-text search.
///
/// Searches across request paths, summaries, and bodies using SQLite FTS5.
/// Returns empty results if persistence is not enabled.
pub async fn search(
    State(state): State<InspectorState>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse>, StatusCode> {
    let db = state.db().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let status_query = params.status.as_deref().and_then(parse_status_query);
    let limit = params.limit.unwrap_or(50).min(500);

    let results = db
        .search(
            params.q.as_deref().unwrap_or(""),
            params.provider.as_deref(),
            status_query,
            limit,
        )
        .await
        .map_err(|e| {
            tracing::warn!("search error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let items: Vec<RequestSummary> = results
        .into_iter()
        .map(RequestSummary::from_stored)
        .collect();
    let total = items.len();

    Ok(Json(SearchResponse { total, items }))
}

/// `GET /api/sessions` — list tunnel sessions.
pub async fn list_sessions(
    State(state): State<InspectorState>,
) -> Result<Json<Vec<SessionSummary>>, StatusCode> {
    let db = state.db().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let sessions = db.list_sessions(50).await.map_err(|e| {
        tracing::warn!("sessions query error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let items: Vec<SessionSummary> = sessions.into_iter().map(SessionSummary::from).collect();
    Ok(Json(items))
}

/// `GET /api/sessions/:id` — get session detail with summary stats.
pub async fn get_session(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
) -> Result<Json<SessionDetailResponse>, StatusCode> {
    let db = state.db().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let session = db
        .get_session(&id)
        .await
        .map_err(|e| {
            tracing::warn!("session query error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Compute duration from timestamps
    let duration_display =
        compute_session_duration(&session.started_at, session.ended_at.as_deref());

    // Collect provider names for this session's requests
    let requests = db
        .list_session_requests(&id, 500, 0)
        .await
        .unwrap_or_default();

    let mut providers: Vec<String> = requests.iter().filter_map(|r| r.provider.clone()).collect();
    providers.sort();
    providers.dedup();

    Ok(Json(SessionDetailResponse {
        id: session.id,
        name: session.name,
        domain: session.domain,
        local_port: session.local_port,
        started_at: session.started_at,
        ended_at: session.ended_at,
        request_count: session.request_count,
        failure_count: session.failure_count,
        providers,
        duration: duration_display,
    }))
}

/// `GET /api/sessions/:id/requests` — list requests for a specific session.
pub async fn list_session_requests(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListRequestsResponse>, StatusCode> {
    let db = state.db().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let limit = params.limit.unwrap_or(50).min(500);
    let offset = params.offset.unwrap_or(0);

    let requests = db
        .list_session_requests(&id, limit, offset)
        .await
        .map_err(|e| {
            tracing::warn!("session requests error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let total = requests.len();
    let items: Vec<RequestSummary> = requests
        .into_iter()
        .map(RequestSummary::from_stored)
        .collect();

    Ok(Json(ListRequestsResponse { total, items }))
}

/// `PUT /api/sessions/:id/name` — rename a session.
pub async fn rename_session(
    State(state): State<InspectorState>,
    Path(id): Path<String>,
    Json(body): Json<RenameSessionBody>,
) -> Result<StatusCode, StatusCode> {
    let db = state.db().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    if body.name.len() > 200 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let updated = db.rename_session(&id, &body.name).await.map_err(|e| {
        tracing::warn!("rename session error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if updated {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// `GET /api/db/requests` — list requests from persistent storage (paginated).
///
/// Unlike `/api/requests` (which reads from the in-memory ring buffer),
/// this endpoint queries SQLite and supports pagination beyond the buffer.
pub async fn list_db_requests(
    State(state): State<InspectorState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ListRequestsResponse>, StatusCode> {
    let db = state.db().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let limit = params.limit.unwrap_or(50).min(500);
    let offset = params.offset.unwrap_or(0);

    let results = db.list_requests(limit, offset).await.map_err(|e| {
        tracing::warn!("db list error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let total = db.count().await.unwrap_or(0);
    let items: Vec<RequestSummary> = results
        .into_iter()
        .map(RequestSummary::from_stored)
        .collect();

    Ok(Json(ListRequestsResponse { total, items }))
}

fn parse_status_query(s: &str) -> Option<crate::db::StatusQuery> {
    match s {
        "2xx" => Some(crate::db::StatusQuery::Class(2)),
        "3xx" => Some(crate::db::StatusQuery::Class(3)),
        "4xx" => Some(crate::db::StatusQuery::Class(4)),
        "5xx" => Some(crate::db::StatusQuery::Class(5)),
        "error" | "err" => Some(crate::db::StatusQuery::Error),
        other => other.parse::<u16>().ok().map(crate::db::StatusQuery::Exact),
    }
}

// ── Query parameter types ────────────────

#[derive(Deserialize)]
pub struct SearchParams {
    pub q: Option<String>,
    pub provider: Option<String>,
    pub status: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

// ── Response types ───────────────────────���────────────────────────────

#[derive(Serialize)]
pub struct ListRequestsResponse {
    pub total: usize,
    pub items: Vec<RequestSummary>,
}

/// Compact request summary (no bodies) for list views.
#[derive(Serialize)]
pub struct RequestSummary {
    pub id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub provider: Option<String>,
    pub summary: String,
    pub req_size: usize,
    pub res_size: usize,
    pub is_error: bool,
    pub has_signature_issue: bool,
}

/// Full request detail including headers and bodies.
#[derive(Serialize)]
pub struct RequestDetail {
    pub id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub provider: Option<String>,
    pub summary: String,
    pub signature_diagnostic: Option<String>,
    pub request_headers: std::collections::HashMap<String, String>,
    pub request_body: BodyPayload,
    pub request_body_size: usize,
    pub response_headers: std::collections::HashMap<String, String>,
    pub response_body: BodyPayload,
    pub response_body_size: usize,
}

/// Structured body payload that distinguishes text from binary content.
///
/// The UI receives a typed envelope instead of having to regex-split a
/// "base64:" prefix. Text bodies are returned as-is; binary bodies are
/// base64-encoded with a clear type discriminator.
///
/// ```json
/// { "type": "text", "data": "{\"event\":\"charge.succeeded\"}" }
/// { "type": "binary", "data": "/wCr..." }
/// { "type": "empty" }
/// ```
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BodyPayload {
    Text { data: String },
    Binary { data: String },
    Empty,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub inspector: bool,
    pub local_port: u16,
    pub tunnel_url: Option<String>,
    pub captured_count: usize,
}

#[derive(Serialize)]
pub struct DiffResponse {
    pub old_id: String,
    pub new_id: String,
    pub request_body: Vec<crate::diff::DiffEntry>,
    pub request_body_summary: crate::diff::DiffSummary,
    pub response_body: Vec<crate::diff::DiffEntry>,
    pub response_body_summary: crate::diff::DiffSummary,
    pub headers: Vec<crate::diff::DiffEntry>,
    pub headers_summary: crate::diff::DiffSummary,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub total: usize,
    pub items: Vec<RequestSummary>,
}

#[derive(Serialize)]
pub struct SessionSummary {
    pub id: String,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub local_port: u16,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub request_count: usize,
}

#[derive(Serialize)]
pub struct SessionDetailResponse {
    pub id: String,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub local_port: u16,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub request_count: usize,
    pub failure_count: usize,
    pub providers: Vec<String>,
    /// Human-readable duration (e.g., "23 minutes", "2 hours").
    pub duration: Option<String>,
}

// ── Conversions ───────────────────────────────────────────────────────

impl From<lpm_tunnel::webhook::CapturedWebhook> for RequestSummary {
    fn from(w: lpm_tunnel::webhook::CapturedWebhook) -> Self {
        Self {
            id: w.id,
            timestamp: w.timestamp,
            method: w.method,
            path: w.path,
            status: w.response_status,
            duration_ms: w.duration_ms,
            provider: w.provider.map(|p| p.to_string()),
            summary: w.summary,
            req_size: w.request_body.len(),
            res_size: w.response_body.len(),
            is_error: w.response_status >= 400,
            has_signature_issue: w.signature_diagnostic.is_some(),
        }
    }
}

impl From<lpm_tunnel::webhook::CapturedWebhook> for RequestDetail {
    fn from(w: lpm_tunnel::webhook::CapturedWebhook) -> Self {
        let req_size = w.request_body.len();
        let res_size = w.response_body.len();

        Self {
            id: w.id,
            timestamp: w.timestamp,
            method: w.method,
            path: w.path,
            status: w.response_status,
            duration_ms: w.duration_ms,
            provider: w.provider.map(|p| p.to_string()),
            summary: w.summary,
            signature_diagnostic: w.signature_diagnostic,
            request_headers: w.request_headers,
            request_body: BodyPayload::from_bytes(&w.request_body),
            request_body_size: req_size,
            response_headers: w.response_headers,
            response_body: BodyPayload::from_bytes(&w.response_body),
            response_body_size: res_size,
        }
    }
}

/// Compute a human-readable session duration from start/end timestamps.
fn compute_session_duration(started: &str, ended: Option<&str>) -> Option<String> {
    let end_str = ended?;
    let start = chrono::DateTime::parse_from_rfc3339(started).ok()?;
    let end = chrono::DateTime::parse_from_rfc3339(end_str).ok()?;
    let duration = end.signed_duration_since(start);

    let secs = duration.num_seconds();
    if secs < 0 {
        return None;
    }

    Some(if secs < 60 {
        format!("{secs} seconds")
    } else if secs < 3600 {
        let mins = secs / 60;
        format!("{mins} minute{}", if mins == 1 { "" } else { "s" })
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins == 0 {
            format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
        } else {
            format!("{hours}h {mins}m")
        }
    })
}

impl RequestSummary {
    /// Convert from a `StoredRequest` (SQLite row) to an API response.
    pub fn from_stored(r: crate::db::StoredRequest) -> Self {
        Self {
            is_error: r.status >= 400,
            id: r.id,
            timestamp: r.timestamp,
            method: r.method,
            path: r.path,
            status: r.status,
            duration_ms: r.duration_ms,
            provider: r.provider,
            summary: r.summary,
            req_size: r.req_size,
            res_size: r.res_size,
            has_signature_issue: r.has_signature_issue,
        }
    }
}

impl From<crate::db::StoredSession> for SessionSummary {
    fn from(s: crate::db::StoredSession) -> Self {
        Self {
            id: s.id,
            name: s.name,
            domain: s.domain,
            local_port: s.local_port,
            started_at: s.started_at,
            ended_at: s.ended_at,
            request_count: s.request_count,
        }
    }
}

impl BodyPayload {
    /// Convert raw bytes into a typed payload.
    ///
    /// - Empty body → `BodyPayload::Empty`
    /// - Valid UTF-8 → `BodyPayload::Text { data }`
    /// - Non-UTF-8 → `BodyPayload::Binary { data }` (base64-encoded)
    pub fn from_bytes(body: &[u8]) -> Self {
        if body.is_empty() {
            return Self::Empty;
        }
        match std::str::from_utf8(body) {
            Ok(s) => Self::Text {
                data: s.to_string(),
            },
            Err(_) => {
                use base64::Engine;
                Self::Binary {
                    data: base64::engine::general_purpose::STANDARD.encode(body),
                }
            }
        }
    }
}
