//! The live view a standalone `lpm tunnel` keeps at the bottom of the
//! terminal: the session's details with its account usage, a tally of its
//! traffic, and its last few requests, redrawn in place as they change.

use super::{
    format_tunnel_detail, format_tunnel_footer, plural, style_http_method_fragment,
    style_http_status_fragment, tunnel_usage_detail,
};
use crate::install_ui::{self, TerminalLine};
use crate::live_region::LiveRegion;
use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

/// The most requests the panel lists; the inspector keeps them all.
const RECENT_REQUESTS: usize = 8;
/// Bursts of requests redraw at most this often.
const FRAME_INTERVAL: Duration = Duration::from_millis(50);
/// Columns a request row spends outside its path: indent, method, gaps,
/// status, and duration.
const REQUEST_ROW_FIXED_COLUMNS: usize = 4 + 7 + 1 + 2 + 3 + 2 + 7;
const MIN_PATH_COLUMNS: usize = 12;

/// What `Tunnel ready` lists about a session.
#[derive(Debug, Clone)]
pub(super) struct ReadyDetails {
    pub(super) public_url: String,
    pub(super) inspector_url: Option<String>,
    pub(super) plan: Option<String>,
    pub(super) limits: Option<String>,
    pub(super) session_id: String,
    pub(super) auto_ack: bool,
    pub(super) auth: Option<String>,
    pub(super) domain: String,
}

impl ReadyDetails {
    /// The detail rows, showing the usage and local endpoint as they are now.
    pub(super) fn rows(
        &self,
        usage: Option<&lpm_tunnel::TunnelUsageMetadata>,
        local_url: &str,
    ) -> Vec<TerminalLine> {
        let mut rows = Vec::with_capacity(10);
        rows.push(format_tunnel_detail("public URL", &self.public_url));
        if let Some(url) = &self.inspector_url {
            rows.push(format_tunnel_detail("inspector", url));
        }
        if let Some(plan) = &self.plan {
            rows.push(format_tunnel_detail("plan", plan));
        }
        if let Some(limits) = &self.limits {
            rows.push(format_tunnel_detail("limits", limits));
        }
        if let Some(usage) = tunnel_usage_detail(usage) {
            rows.push(crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim(&format!("{:<11}", "usage")),
                usage
            ));
        }
        rows.push(format_tunnel_detail("session", &self.session_id));
        rows.push(format_tunnel_detail("local", local_url));
        if self.auto_ack {
            rows.push(format_tunnel_detail(
                "auto-ack",
                "on (200 OK after durable capture on forwarding failure)",
            ));
        }
        if let Some(auth) = &self.auth {
            rows.push(format_tunnel_detail("auth", auth));
        }
        rows.push(format_tunnel_detail("domain", &self.domain));
        rows
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Listening,
    Reconnecting,
    Closed,
}

#[derive(Debug, Clone)]
struct RecentRequest {
    method: Cow<'static, str>,
    path: String,
    status: u16,
    duration_ms: Option<u64>,
}

impl RecentRequest {
    fn of(webhook: &lpm_tunnel::webhook::CapturedWebhook) -> Self {
        Self {
            method: known_method(&webhook.method).map_or_else(
                || Cow::Owned(lpm_common::sanitize_terminal_inline(&webhook.method).into_owned()),
                Cow::Borrowed,
            ),
            path: lpm_common::sanitize_terminal_inline(&webhook.path).into_owned(),
            status: webhook.response_status,
            duration_ms: Some(webhook.duration_ms),
        }
    }
}

#[derive(Debug)]
struct PanelState {
    details: Option<ReadyDetails>,
    usage: Option<lpm_tunnel::TunnelUsageMetadata>,
    phase: Phase,
    requests: u64,
    errors: u64,
    websockets: HashSet<String>,
    recent: VecDeque<RecentRequest>,
    has_inspector: bool,
}

impl PanelState {
    fn new(has_inspector: bool) -> Self {
        Self {
            details: None,
            usage: None,
            phase: Phase::Listening,
            requests: 0,
            errors: 0,
            websockets: HashSet::new(),
            recent: VecDeque::with_capacity(RECENT_REQUESTS),
            has_inspector,
        }
    }

    fn record_request(&mut self, webhook: &lpm_tunnel::webhook::CapturedWebhook) {
        self.requests += 1;
        if webhook.response_status >= 500 {
            self.errors += 1;
        }
        self.push_recent(RecentRequest::of(webhook));
    }

    fn push_recent(&mut self, request: RecentRequest) {
        if self.recent.len() == RECENT_REQUESTS {
            self.recent.pop_front();
        }
        self.recent.push_back(request);
    }
}

/// The panel and the region it draws in.
pub(super) struct TunnelPanel {
    region: Mutex<Option<LiveRegion>>,
    state: Mutex<PanelState>,
    local_target: Arc<RwLock<lpm_common::LocalTarget>>,
    changed: tokio::sync::Notify,
}

impl TunnelPanel {
    /// Opens the panel at the bottom of the terminal, or returns `None`
    /// where it can't be redrawn in place, and starts its renderer.
    pub(super) fn open(
        has_inspector: bool,
        local_target: Arc<RwLock<lpm_common::LocalTarget>>,
    ) -> Option<(Arc<Self>, tokio::task::JoinHandle<()>)> {
        let region = LiveRegion::open()?;
        let panel = Arc::new(Self {
            region: Mutex::new(Some(region)),
            state: Mutex::new(PanelState::new(has_inspector)),
            local_target,
            changed: tokio::sync::Notify::new(),
        });
        let renderer = tokio::spawn(Arc::clone(&panel).render_until_closed());
        Some((panel, renderer))
    }

    fn state(&self) -> MutexGuard<'_, PanelState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn update(&self, change: impl FnOnce(&mut PanelState)) {
        change(&mut self.state());
        self.changed.notify_one();
    }

    /// The tunnel (re)connected; WebSockets don't outlive the relay socket.
    pub(super) fn connected(&self, details: ReadyDetails) {
        self.update(|state| {
            state.details = Some(details);
            state.phase = Phase::Listening;
            state.websockets.clear();
        });
    }

    pub(super) fn reconnecting(&self) {
        self.update(|state| {
            if state.phase == Phase::Listening {
                state.phase = Phase::Reconnecting;
            }
        });
    }

    pub(super) fn usage(&self, usage: &lpm_tunnel::TunnelUsageMetadata) {
        self.update(|state| state.usage = Some(usage.clone()));
    }

    pub(super) fn request(&self, webhook: &lpm_tunnel::webhook::CapturedWebhook) {
        self.update(|state| state.record_request(webhook));
    }

    pub(super) fn websocket(&self, event: &lpm_tunnel::ws_capture::WsEvent) {
        use lpm_tunnel::ws_capture::WsEvent;
        match event {
            WsEvent::Connected {
                connection_id, url, ..
            } => {
                let request = RecentRequest {
                    method: Cow::Borrowed("WS"),
                    path: lpm_common::sanitize_terminal_inline(url).into_owned(),
                    status: 101,
                    duration_ms: None,
                };
                let connection_id = connection_id.clone();
                self.update(|state| {
                    state.websockets.insert(connection_id);
                    state.push_recent(request);
                });
            }
            WsEvent::Closed { connection_id, .. } => {
                self.update(|state| {
                    state.websockets.remove(connection_id);
                });
            }
            WsEvent::Frame { .. } => {}
        }
    }

    /// Draws again, as after the terminal resized.
    pub(super) fn redraw(&self) {
        self.changed.notify_one();
    }

    /// Draws the final frame and closes the region, so later output prints
    /// below it.
    pub(super) async fn close(&self, renderer: tokio::task::JoinHandle<()>) {
        self.update(|state| state.phase = Phase::Closed);
        let _ = renderer.await;
        self.region
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }

    async fn render_until_closed(self: Arc<Self>) {
        loop {
            self.changed.notified().await;
            let local_url = self
                .local_target
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .url();
            let (width, height) = crate::live_region::terminal_size();
            let (rows, closed) = {
                let state = self.state();
                (
                    render(&state, &local_url, width, height),
                    state.phase == Phase::Closed,
                )
            };
            if let Some(region) = self
                .region
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
            {
                region.draw(rows);
            }
            if closed {
                return;
            }
            tokio::time::sleep(FRAME_INTERVAL).await;
        }
    }
}

fn known_method(method: &str) -> Option<&'static str> {
    [
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE",
    ]
    .into_iter()
    .find(|known| *known == method)
}

/// The panel's rows for a terminal `width` × `height`: the request list
/// gives up rows first when the terminal is short.
fn render(state: &PanelState, local_url: &str, width: u16, height: u16) -> Vec<String> {
    let Some(details) = &state.details else {
        return Vec::new();
    };
    let mut rows: Vec<String> = Vec::with_capacity(16 + RECENT_REQUESTS);
    rows.push(install_ui::phase_row(&TerminalLine::new("Tunnel ready")));
    rows.extend(
        details
            .rows(state.usage.as_ref(), local_url)
            .into_iter()
            .map(|row| row.to_string()),
    );
    rows.push(String::new());
    rows.push(status_row(state));
    let footer = (state.phase != Phase::Closed)
        .then(|| format_tunnel_footer(state.has_inspector).to_string());

    let used: usize = rows
        .iter()
        .chain(&footer)
        .map(|row| crate::live_region::screen_rows(row, width))
        .sum();
    let window = state
        .recent
        .len()
        .min(usize::from(height).saturating_sub(used));
    rows.extend(
        state
            .recent
            .iter()
            .skip(state.recent.len() - window)
            .map(|request| request_row(request, width)),
    );
    rows.extend(footer);
    rows
}

fn status_row(state: &PanelState) -> String {
    let mut line = match state.phase {
        Phase::Listening if state.requests == 0 => TerminalLine::new("Listening for requests"),
        Phase::Listening => TerminalLine::new("Listening"),
        Phase::Reconnecting => TerminalLine::new("Reconnecting"),
        Phase::Closed => TerminalLine::new("Tunnel closed"),
    };
    if state.requests > 0 {
        line = line.text(" · ").field(&counted(state.requests, "request"));
    }
    if state.errors > 0 {
        line = line.text(" · ").red(&counted(state.errors, "error"));
    }
    if !state.websockets.is_empty() {
        line = line
            .text(" · ")
            .field(&counted(state.websockets.len() as u64, "websocket"));
    }
    match state.phase {
        Phase::Listening => install_ui::done_row(&line),
        Phase::Reconnecting => install_ui::warn_row(&line),
        Phase::Closed => install_ui::phase_row(&line),
    }
}

fn counted(count: u64, noun: &str) -> String {
    format!(
        "{} {}",
        lpm_common::format_count(count),
        plural(count, noun)
    )
}

/// `    GET     /path…    200    12ms`, fit within `width` columns so it
/// never wraps.
fn request_row(request: &RecentRequest, width: u16) -> String {
    let columns = usize::from(width).saturating_sub(1);
    let path_columns = columns
        .saturating_sub(REQUEST_ROW_FIXED_COLUMNS)
        .max(MIN_PATH_COLUMNS);
    let path = console::truncate_str(&request.path, path_columns, "…");
    let path_padding = path_columns.saturating_sub(console::measure_text_width(&path));
    let method = &*request.method;
    let method_padding = 7_usize.saturating_sub(console::measure_text_width(method));
    let duration = request.duration_ms.map_or_else(String::new, |ms| {
        install_ui::format_duration(Duration::from_millis(ms))
    });
    let row = crate::install_ui::terminal_line!(
        "    {}{} {}{}  {}  {}",
        style_http_method_fragment(method),
        " ".repeat(method_padding),
        install_ui::cyan(&path),
        " ".repeat(path_padding),
        style_http_status_fragment(request.status),
        install_ui::dim(&format!("{duration:>7}")),
    );
    console::truncate_str(&row, columns, "").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details() -> ReadyDetails {
        ReadyDetails {
            public_url: "https://tolga.lpm.fyi".into(),
            inspector_url: Some("http://127.0.0.1:49256/?token=abc".into()),
            plan: Some("pro".into()),
            limits: Some("3 tunnels · 20,000/min".into()),
            session_id: "573d2f7c".into(),
            auto_ack: false,
            auth: None,
            domain: "tolga.lpm.fyi".into(),
        }
    }

    fn usage(accepted: u64) -> lpm_tunnel::TunnelUsageMetadata {
        lpm_tunnel::TunnelUsageMetadata {
            accepted_requests: Some(accepted),
            included_requests: Some(100_000),
            overage_requests: Some(0),
            overage_enabled: Some(true),
            ..Default::default()
        }
    }

    fn webhook(
        method: &str,
        path: &str,
        status: u16,
        ms: u64,
    ) -> lpm_tunnel::webhook::CapturedWebhook {
        lpm_tunnel::webhook::CapturedWebhook {
            id: "req".into(),
            timestamp: "2026-10-30T00:00:00Z".into(),
            method: method.into(),
            path: path.into(),
            request_headers: std::collections::HashMap::new(),
            request_body: Vec::new(),
            response_status: status,
            response_headers: std::collections::HashMap::new(),
            response_body: Vec::new(),
            duration_ms: ms,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: false,
            response_body_incomplete: false,
        }
    }

    /// The rows as they read on screen, whatever the color setting.
    fn rendered(state: &PanelState, width: u16, height: u16) -> Vec<String> {
        render(state, "http://[::1]:4321/", width, height)
            .into_iter()
            .map(|row| console::strip_ansi_codes(&row).trim_end().to_owned())
            .collect()
    }

    fn connected_state() -> PanelState {
        let mut state = PanelState::new(true);
        state.details = Some(details());
        state.usage = Some(usage(1_245));
        state
    }

    #[test]
    fn nothing_is_drawn_before_the_tunnel_connects() {
        assert!(rendered(&PanelState::new(true), 80, 40).is_empty());
    }

    #[test]
    fn a_quiet_tunnel_shows_its_details_live_usage_and_keys() {
        assert_eq!(
            rendered(&connected_state(), 100, 40),
            [
                "› Tunnel ready",
                "    public URL  https://tolga.lpm.fyi",
                "    inspector   http://127.0.0.1:49256/?token=abc",
                "    plan        pro",
                "    limits      3 tunnels · 20,000/min",
                "    usage       1,245 / 100,000 requests  █░░░░░░░░░  overage on",
                "    session     573d2f7c",
                "    local       http://[::1]:4321/",
                "    domain      tolga.lpm.fyi",
                "",
                "✓ Listening for requests",
                "  press o to open inspector, q to quit",
            ]
        );
    }

    #[test]
    fn traffic_is_tallied_and_its_last_requests_listed_in_columns() {
        let mut state = connected_state();
        state.record_request(&webhook("GET", "/", 200, 12));
        state.record_request(&webhook("POST", "/hooks/stripe", 502, 1_530));
        state.websockets.insert("ws-1".into());

        let rows = rendered(&state, 60, 40);

        assert_eq!(
            rows[10..],
            [
                "✓ Listening · 2 requests · 1 error · 1 websocket",
                "    GET     /                                  200     12ms",
                "    POST    /hooks/stripe                      502    1.53s",
                "  press o to open inspector, q to quit",
            ]
        );
    }

    #[test]
    fn only_the_last_requests_are_listed() {
        let mut state = connected_state();
        for index in 0..12 {
            state.record_request(&webhook("GET", &format!("/{index}"), 200, 1));
        }

        let rows = rendered(&state, 60, 40);

        let listed: Vec<&str> = rows
            .iter()
            .filter(|row| row.starts_with("    GET"))
            .map(|row| row.split_whitespace().nth(1).unwrap())
            .collect();
        assert_eq!(listed, ["/4", "/5", "/6", "/7", "/8", "/9", "/10", "/11"]);
    }

    #[test]
    fn a_short_terminal_lists_fewer_requests_before_dropping_details() {
        let mut state = connected_state();
        for index in 0..8 {
            state.record_request(&webhook("GET", &format!("/{index}"), 200, 1));
        }

        let rows = rendered(&state, 100, 15);

        let listed: Vec<&str> = rows
            .iter()
            .filter(|row| row.starts_with("    GET"))
            .map(|row| row.split_whitespace().nth(1).unwrap())
            .collect();
        assert_eq!(rows.len(), 15);
        assert_eq!(rows[0], "› Tunnel ready");
        assert_eq!(listed, ["/5", "/6", "/7"]);
        assert_eq!(rows[14], "  press o to open inspector, q to quit");
    }

    #[test]
    fn a_long_path_is_cut_to_keep_the_row_on_one_line() {
        let mut state = connected_state();
        state.record_request(&webhook(
            "GET",
            &format!("/_image?href={}", "a".repeat(200)),
            200,
            4,
        ));

        let rows = rendered(&state, 50, 40);
        let row = &rows[11];

        assert!(console::measure_text_width(row) < 50, "{row}");
        assert!(row.contains("/_image?href=aaa"), "{row}");
        assert!(row.contains('…') && row.ends_with("200      4ms"), "{row}");
    }

    #[test]
    fn a_reconnecting_tunnel_says_so_and_the_closed_frame_drops_the_keys() {
        let mut state = connected_state();
        state.record_request(&webhook("GET", "/", 200, 12));
        state.phase = Phase::Reconnecting;
        let reconnecting = rendered(&state, 80, 40);
        state.phase = Phase::Closed;
        let closed = rendered(&state, 80, 40);

        assert_eq!(reconnecting[10], "! Reconnecting · 1 request");
        assert_eq!(closed[10], "› Tunnel closed · 1 request");
        assert!(!closed.last().unwrap().contains("press"));
    }

    #[test]
    fn a_request_cannot_inject_terminal_controls() {
        let request = RecentRequest::of(&webhook("G\u{1b}]0;x\u{7}", "/a\u{1b}[2Jb\nc", 200, 1));

        for field in [&*request.method, request.path.as_str()] {
            assert!(!field.chars().any(char::is_control), "{field:?}");
        }
    }
}
