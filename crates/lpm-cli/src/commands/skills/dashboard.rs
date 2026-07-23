use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use lpm_common::LpmError;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::inventory::{self, DashboardAction, SkillInventoryKind};
use super::managed::{self, ManagedMutationPlan, ManagedUpdatePlan, Mutation};
use super::{AgentTarget, DashboardArgs};

const INDEX_HTML: &str = include_str!("dashboard/index.html");
const DASHBOARD_CSS: &str = include_str!("dashboard/assets/dashboard.css");
const DASHBOARD_JS: &str = include_str!("dashboard/assets/dashboard.js");
const PLAN_LIFETIME: Duration = Duration::from_secs(10 * 60);
const MAX_CACHED_PLANS: usize = 4;

#[derive(Clone)]
struct DashboardState {
    project_dir: Arc<PathBuf>,
    read_only: bool,
    auth_token: Arc<str>,
    allowed_hosts: Arc<[String; 2]>,
    allowed_origins: Arc<[String; 2]>,
    plans: Arc<tokio::sync::Mutex<HashMap<String, CachedPlan>>>,
}

struct CachedPlan {
    created_at: Instant,
    action: DashboardAction,
    skill_name: String,
    scope: String,
    plan: PendingPlan,
}

enum PendingPlan {
    Mutation(ManagedMutationPlan),
    Update(ManagedUpdatePlan),
}

pub(super) struct DashboardHandle {
    port: u16,
    display_url: String,
    launch_url: String,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl DashboardHandle {
    fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[derive(Debug, Deserialize)]
struct PreviewActionRequest {
    skill_id: String,
    action: DashboardAction,
    #[serde(default)]
    agents: Vec<AgentTarget>,
}

#[derive(Debug, Deserialize)]
struct ApplyActionRequest {
    plan_id: String,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "success": false,
                "error": self.message,
            })),
        )
            .into_response()
    }
}

pub(super) async fn run(
    project_dir: &Path,
    args: DashboardArgs,
    json_output: bool,
) -> Result<(), LpmError> {
    let port = args.port.unwrap_or(0);
    let handle = start(project_dir, args.read_only, port).await?;
    let should_open = !args.no_open && !json_output;
    let opened = should_open && open::that(&handle.launch_url).is_ok();

    if json_output {
        let output = serde_json::json!({
            "success": true,
            "url": handle.launch_url,
            "display_url": handle.display_url,
            "port": handle.port,
            "includes_global": true,
            "read_only": args.read_only,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(LpmError::Json)?
        );
        std::io::stdout().flush().map_err(LpmError::Io)?;
    } else {
        crate::install_ui::done_line(crate::install_ui::terminal_line!(
            "Skills dashboard: {}",
            crate::install_ui::url(&handle.display_url)
        ));
        if !opened {
            crate::install_ui::detail_line(crate::install_ui::terminal_line!(
                "  Open {}",
                crate::install_ui::url(&handle.launch_url)
            ));
        }
        crate::install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {}",
            crate::install_ui::dim("Press Ctrl+C to stop")
        ));
    }

    let signal_result = tokio::signal::ctrl_c().await;
    handle.shutdown();
    signal_result
        .map_err(|error| LpmError::Script(format!("skills dashboard signal error: {error}")))
}

async fn start(
    project_dir: &Path,
    read_only: bool,
    port: u16,
) -> Result<DashboardHandle, LpmError> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| dashboard_bind_error(port, error))?;
    let bound_port = listener.local_addr().map_err(LpmError::Io)?.port();
    let display_url = format!("http://127.0.0.1:{bound_port}/");
    let auth_token: Arc<str> = random_token().into();
    let launch_url = format!("{display_url}#token={auth_token}");
    let (allowed_hosts, allowed_origins) = loopback_authority_allowlists(bound_port);
    let state = DashboardState {
        project_dir: Arc::new(project_dir.to_path_buf()),
        read_only,
        auth_token,
        allowed_hosts: Arc::new(allowed_hosts),
        allowed_origins: Arc::new(allowed_origins),
        plans: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    };
    let api = Router::new()
        .route("/api/v1/inventory", get(get_inventory))
        .route("/api/v1/skills/{skill_id}", get(get_skill))
        .route("/api/v1/skills/{skill_id}/reveal", post(reveal_skill))
        .route("/api/v1/actions/preview", post(preview_action))
        .route("/api/v1/actions/apply", post(apply_action))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authorize_api_request,
        ));
    let app = Router::new()
        .route("/", get(index))
        .route("/assets/dashboard.css", get(stylesheet))
        .route("/assets/dashboard.js", get(script))
        .merge(api)
        .layer(middleware::from_fn(security_headers))
        .with_state(state);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
        {
            tracing::debug!("skills dashboard server stopped with an error: {error}");
        }
    });
    Ok(DashboardHandle {
        port: bound_port,
        display_url,
        launch_url,
        shutdown_tx,
    })
}

fn loopback_authority_allowlists(port: u16) -> ([String; 2], [String; 2]) {
    let port_suffix = if port == 80 {
        String::new()
    } else {
        format!(":{port}")
    };
    (
        [
            format!("127.0.0.1{port_suffix}"),
            format!("localhost{port_suffix}"),
        ],
        [
            format!("http://127.0.0.1{port_suffix}"),
            format!("http://localhost{port_suffix}"),
        ],
    )
}

fn dashboard_bind_error(port: u16, error: std::io::Error) -> LpmError {
    if error.kind() == std::io::ErrorKind::AddrInUse && port != 0 {
        LpmError::Script(format!(
            "skills dashboard port {port} is already in use; omit `--port` to select a free localhost port"
        ))
    } else {
        LpmError::Script(format!(
            "failed to bind skills dashboard to 127.0.0.1:{port}: {error}"
        ))
    }
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
}

async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        DASHBOARD_JS,
    )
}

async fn get_inventory(
    State(state): State<DashboardState>,
) -> Result<Json<inventory::InventorySnapshot>, ApiError> {
    let project_dir = Arc::clone(&state.project_dir);
    let read_only = state.read_only;
    let snapshot =
        tokio::task::spawn_blocking(move || inventory::collect(&project_dir, true, read_only))
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)?;
    Ok(Json(snapshot))
}

async fn get_skill(
    State(state): State<DashboardState>,
    AxumPath(skill_id): AxumPath<String>,
) -> Result<Json<inventory::SkillDetailSnapshot>, ApiError> {
    let skill = find_skill(&state, &skill_id)
        .await?
        .ok_or_else(|| ApiError::not_found("skill is no longer present"))?;
    let detail = tokio::task::spawn_blocking(move || inventory::detail(skill))
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(detail))
}

async fn reveal_skill(
    State(state): State<DashboardState>,
    AxumPath(skill_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let skill = find_skill(&state, &skill_id)
        .await?
        .ok_or_else(|| ApiError::not_found("skill is no longer present"))?;
    let path = skill
        .path
        .map(PathBuf::from)
        .ok_or_else(|| ApiError::bad_request("skill path is unavailable"))?;
    let revealed_path = path.display().to_string();
    tokio::task::spawn_blocking(move || reveal_in_file_manager(&path))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({
        "success": true,
        "skill_id": skill_id,
        "path": revealed_path,
    })))
}

async fn preview_action(
    State(state): State<DashboardState>,
    Json(request): Json<PreviewActionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if state.read_only {
        return Err(ApiError::forbidden("this dashboard is read-only"));
    }
    let skill = resolve_managed_skill(&state, &request).await?;
    let global = skill.scope == "global";
    let (plan, changes, updates, warning_count) = match request.action {
        DashboardAction::Update => {
            if !request.agents.is_empty() {
                return Err(ApiError::bad_request(
                    "managed skill updates cannot be restricted to one agent",
                ));
            }
            let plan =
                managed::plan_dashboard_update(&state.project_dir, skill.name.clone(), global)
                    .await
                    .map_err(ApiError::bad_request)?;
            let changes = plan.changes().to_vec();
            let updates = plan.summaries();
            let warning_count = plan.warning_count();
            (PendingPlan::Update(plan), changes, updates, warning_count)
        }
        DashboardAction::Enable | DashboardAction::Disable | DashboardAction::Remove => {
            let mutation = match request.action {
                DashboardAction::Enable => Mutation::Enable,
                DashboardAction::Disable => Mutation::Disable,
                DashboardAction::Remove => Mutation::Remove,
                DashboardAction::Update => {
                    return Err(ApiError::bad_request(
                        "managed skill updates require an update preview",
                    ));
                }
            };
            let project_dir = Arc::clone(&state.project_dir);
            let name = skill.name.clone();
            let agents = request.agents;
            let plan = tokio::task::spawn_blocking(move || {
                managed::plan_dashboard_mutation(&project_dir, name, global, agents, mutation)
            })
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::bad_request)?;
            let changes = plan.changes().to_vec();
            (PendingPlan::Mutation(plan), changes, Vec::new(), 0)
        }
    };
    let plan_id = cache_plan(
        &state,
        CachedPlan {
            created_at: Instant::now(),
            action: request.action,
            skill_name: skill.name.clone(),
            scope: skill.scope.clone(),
            plan,
        },
    )
    .await;
    Ok(Json(serde_json::json!({
        "success": true,
        "plan_id": plan_id,
        "expires_in_seconds": PLAN_LIFETIME.as_secs(),
        "action": request.action,
        "skill": skill.name,
        "scope": skill.scope,
        "changes": changes,
        "updates": updates,
        "security_warning_count": warning_count,
    })))
}

async fn apply_action(
    State(state): State<DashboardState>,
    Json(request): Json<ApplyActionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if state.read_only {
        return Err(ApiError::forbidden("this dashboard is read-only"));
    }
    let cached = take_plan(&state, &request.plan_id).await?;
    let action = cached.action;
    let skill_name = cached.skill_name;
    let scope = cached.scope;
    let changes = tokio::task::spawn_blocking(move || match cached.plan {
        PendingPlan::Mutation(plan) => managed::apply_mutation_plan(plan),
        PendingPlan::Update(plan) => managed::apply_update_plan(plan),
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::bad_request)?;
    Ok(Json(serde_json::json!({
        "success": true,
        "action": action,
        "skill": skill_name,
        "scope": scope,
        "changes": changes,
    })))
}

async fn resolve_managed_skill(
    state: &DashboardState,
    request: &PreviewActionRequest,
) -> Result<inventory::SkillInventoryItem, ApiError> {
    let skill = find_skill(state, &request.skill_id)
        .await?
        .ok_or_else(|| ApiError::bad_request("skill is no longer present"))?;
    if skill.kind != SkillInventoryKind::Managed {
        return Err(ApiError::bad_request(
            "only LPM-managed skills can be changed from the dashboard",
        ));
    }
    if !skill.actions.contains(&request.action) {
        return Err(ApiError::bad_request(format!(
            "{} is not currently available for this skill",
            request.action.slug()
        )));
    }
    for agent in &request.agents {
        if !skill
            .targets
            .iter()
            .any(|target| target.agent == agent.slug())
        {
            return Err(ApiError::bad_request(format!(
                "{} is not a recorded target for this skill",
                agent.label()
            )));
        }
    }
    Ok(skill)
}

async fn find_skill(
    state: &DashboardState,
    skill_id: &str,
) -> Result<Option<inventory::SkillInventoryItem>, ApiError> {
    if !valid_skill_id(skill_id) {
        return Err(ApiError::bad_request("invalid skill identifier"));
    }
    let project_dir = Arc::clone(&state.project_dir);
    let read_only = state.read_only;
    let snapshot =
        tokio::task::spawn_blocking(move || inventory::collect(&project_dir, true, read_only))
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)?;
    Ok(snapshot
        .skills
        .into_iter()
        .find(|skill| skill.id == skill_id))
}

fn valid_skill_id(skill_id: &str) -> bool {
    let Some((kind, digest)) = skill_id.split_once(':') else {
        return false;
    };
    matches!(kind, "package" | "managed" | "external")
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(target_os = "macos")]
fn reveal_in_file_manager(path: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "file manager exited with {status}"
        )))
    }
}

#[cfg(not(target_os = "macos"))]
fn reveal_in_file_manager(path: &Path) -> std::io::Result<()> {
    let target = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    open::that_detached(target)
}

async fn cache_plan(state: &DashboardState, plan: CachedPlan) -> String {
    let mut plans = state.plans.lock().await;
    purge_expired_plans(&mut plans);
    if plans.len() >= MAX_CACHED_PLANS
        && let Some(oldest) = plans
            .iter()
            .min_by_key(|(_, plan)| plan.created_at)
            .map(|(id, _)| id.clone())
    {
        plans.remove(&oldest);
    }
    let id = random_token();
    plans.insert(id.clone(), plan);
    id
}

async fn take_plan(state: &DashboardState, plan_id: &str) -> Result<CachedPlan, ApiError> {
    if plan_id.len() != 64 || !plan_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("invalid dashboard plan identifier"));
    }
    let mut plans = state.plans.lock().await;
    purge_expired_plans(&mut plans);
    plans
        .remove(plan_id)
        .ok_or_else(|| ApiError::bad_request("dashboard plan expired; preview the action again"))
}

fn purge_expired_plans(plans: &mut HashMap<String, CachedPlan>) {
    plans.retain(|_, plan| plan.created_at.elapsed() <= PLAN_LIFETIME);
}

async fn authorize_api_request(
    State(state): State<DashboardState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let host_matches = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| state.allowed_hosts.iter().any(|allowed| allowed == host));
    if !host_matches {
        return Err(StatusCode::FORBIDDEN);
    }
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let expected = state.auth_token.as_bytes();
    let authenticated = presented.is_some_and(|token| {
        token.len() == expected.len() && token.as_bytes().ct_eq(expected).into()
    });
    if !authenticated {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if request.method() != Method::GET {
        let origin_matches = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|origin| {
                state
                    .allowed_origins
                    .iter()
                    .any(|allowed| allowed == origin)
            });
        if !origin_matches {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(next.run(request).await)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_http_port_allowlists_canonical_browser_authorities() {
        let (hosts, origins) = loopback_authority_allowlists(80);

        assert_eq!(hosts, ["127.0.0.1", "localhost"]);
        assert_eq!(origins, ["http://127.0.0.1", "http://localhost"]);
    }

    #[test]
    fn non_default_http_port_allowlists_explicit_authorities() {
        let (hosts, origins) = loopback_authority_allowlists(43127);

        assert_eq!(hosts, ["127.0.0.1:43127", "localhost:43127"]);
        assert_eq!(
            origins,
            ["http://127.0.0.1:43127", "http://localhost:43127"]
        );
    }

    #[test]
    fn bundled_dashboard_uses_csp_compatible_external_assets() {
        assert!(INDEX_HTML.contains("src=\"./assets/dashboard.js\""));
        assert!(INDEX_HTML.contains("href=\"./assets/dashboard.css\""));
        assert!(!INDEX_HTML.contains("<style"));
        assert!(!DASHBOARD_CSS.is_empty());
        assert!(!DASHBOARD_JS.is_empty());
    }

    #[tokio::test]
    async fn automatic_port_avoids_an_existing_loopback_server() {
        let busy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let busy_port = busy.local_addr().unwrap().port();
        let project = tempfile::tempdir().unwrap();

        let handle = start(project.path(), true, 0).await.unwrap();

        assert_ne!(handle.port, busy_port);
        handle.shutdown();
    }

    #[tokio::test]
    async fn explicit_busy_port_fails_without_switching_ports() {
        let busy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let busy_port = busy.local_addr().unwrap().port();
        let project = tempfile::tempdir().unwrap();

        let error = start(project.path(), true, busy_port)
            .await
            .err()
            .expect("an explicitly occupied port must fail");

        assert!(error.to_string().contains(&busy_port.to_string()));
    }

    #[tokio::test]
    async fn inventory_api_rejects_requests_without_the_session_token() {
        let project = tempfile::tempdir().unwrap();
        let handle = start(project.path(), true, 0).await.unwrap();

        let response = reqwest::get(format!("{}api/v1/inventory", handle.display_url))
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        handle.shutdown();
    }

    #[tokio::test]
    async fn skill_detail_api_rejects_requests_without_the_session_token() {
        let project = tempfile::tempdir().unwrap();
        let handle = start(project.path(), true, 0).await.unwrap();
        let skill_id = format!("package:{}", "a".repeat(64));

        let response = reqwest::get(format!("{}api/v1/skills/{skill_id}", handle.display_url))
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        handle.shutdown();
    }

    #[tokio::test]
    async fn dashboard_page_disables_embedding_referrers_and_caching() {
        let project = tempfile::tempdir().unwrap();
        let handle = start(project.path(), true, 0).await.unwrap();

        let response = reqwest::get(&handle.display_url).await.unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("default-src 'none'")
        );
        handle.shutdown();
    }

    #[tokio::test]
    async fn mutation_api_rejects_foreign_browser_origins() {
        let project = tempfile::tempdir().unwrap();
        let handle = start(project.path(), false, 0).await.unwrap();
        let token = handle.launch_url.split("#token=").nth(1).unwrap();

        let response = reqwest::Client::new()
            .post(format!("{}api/v1/actions/preview", handle.display_url))
            .bearer_auth(token)
            .header(reqwest::header::ORIGIN, "https://malicious.example")
            .json(&serde_json::json!({
                "skill_id": "managed:missing",
                "action": "disable"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        handle.shutdown();
    }

    #[tokio::test]
    async fn read_only_dashboard_rejects_authenticated_mutations() {
        let project = tempfile::tempdir().unwrap();
        let handle = start(project.path(), true, 0).await.unwrap();
        let token = handle.launch_url.split("#token=").nth(1).unwrap();
        let origin = handle.display_url.trim_end_matches('/');

        let response = reqwest::Client::new()
            .post(format!("{}api/v1/actions/preview", handle.display_url))
            .bearer_auth(token)
            .header(reqwest::header::ORIGIN, origin)
            .json(&serde_json::json!({
                "skill_id": "managed:missing",
                "action": "disable"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        handle.shutdown();
    }

    #[tokio::test]
    async fn reveal_api_rejects_non_inventory_identifiers() {
        let project = tempfile::tempdir().unwrap();
        let handle = start(project.path(), true, 0).await.unwrap();
        let token = handle.launch_url.split("#token=").nth(1).unwrap();
        let origin = handle.display_url.trim_end_matches('/');

        let response = reqwest::Client::new()
            .post(format!(
                "{}api/v1/skills/private-tmp-secret/reveal",
                handle.display_url
            ))
            .bearer_auth(token)
            .header(reqwest::header::ORIGIN, origin)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        handle.shutdown();
    }

    #[tokio::test]
    async fn inventory_api_rejects_dns_rebinding_host_headers() {
        let project = tempfile::tempdir().unwrap();
        let handle = start(project.path(), true, 0).await.unwrap();
        let token = handle.launch_url.split("#token=").nth(1).unwrap();

        let response = reqwest::Client::new()
            .get(format!("{}api/v1/inventory", handle.display_url))
            .bearer_auth(token)
            .header(reqwest::header::HOST, "attacker.example")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        handle.shutdown();
    }

    #[tokio::test]
    async fn apply_api_rejects_malformed_plan_identifiers() {
        let project = tempfile::tempdir().unwrap();
        let handle = start(project.path(), false, 0).await.unwrap();
        let token = handle.launch_url.split("#token=").nth(1).unwrap();
        let origin = handle.display_url.trim_end_matches('/');

        let response = reqwest::Client::new()
            .post(format!("{}api/v1/actions/apply", handle.display_url))
            .bearer_auth(token)
            .header(reqwest::header::ORIGIN, origin)
            .json(&serde_json::json!({"plan_id": "not-hex"}))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        handle.shutdown();
    }
}
