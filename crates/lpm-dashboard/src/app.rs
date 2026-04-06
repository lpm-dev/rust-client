//! Dashboard application state.

use crate::log_buffer::LogBuffer;
use lpm_tunnel::webhook::CapturedWebhook;
use lpm_tunnel::webhook_buffer::WebhookBuffer;

/// Status of a service in the dashboard.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
    Starting,
    WaitingForDep(String),
    Ready,
    Crashed(String),
    Stopped,
}

impl ServiceStatus {
    pub fn icon(&self) -> &str {
        match self {
            ServiceStatus::Starting => "○",
            ServiceStatus::WaitingForDep(_) => "⟳",
            ServiceStatus::Ready => "●",
            ServiceStatus::Crashed(_) => "✖",
            ServiceStatus::Stopped => "■",
        }
    }

    pub fn label(&self) -> String {
        match self {
            ServiceStatus::Starting => "starting".into(),
            ServiceStatus::WaitingForDep(dep) => format!("waiting for {dep}"),
            ServiceStatus::Ready => "ready".into(),
            ServiceStatus::Crashed(msg) => format!("crashed: {msg}"),
            ServiceStatus::Stopped => "stopped".into(),
        }
    }
}

/// State for a single service in the dashboard.
pub struct ServiceState {
    pub name: String,
    pub port: Option<u16>,
    pub status: ServiceStatus,
    pub logs: LogBuffer,
}

/// Active tab in the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Service logs view (default).
    Services,
    /// Webhook inspector view.
    Webhooks,
}

/// The main dashboard application state.
pub struct DashboardApp {
    pub services: Vec<ServiceState>,
    pub selected_service: usize,
    pub scroll_offset: usize,
    pub tunnel_url: Option<String>,
    pub network_ip: Option<String>,
    pub https: bool,
    /// Active tab.
    pub active_tab: Tab,
    /// In-memory ring buffer of recent webhooks (last 100).
    pub webhooks: WebhookBuffer,
    /// Scroll offset for webhook list (0 = latest).
    pub webhook_scroll: usize,
    /// Selected webhook index for detail view (None = list mode).
    pub webhook_detail: Option<usize>,
}

impl DashboardApp {
    pub fn new(services: Vec<ServiceState>) -> Self {
        Self {
            services,
            selected_service: 0,
            scroll_offset: 0,
            tunnel_url: None,
            network_ip: None,
            https: false,
            active_tab: Tab::Services,
            webhooks: WebhookBuffer::new(100),
            webhook_scroll: 0,
            webhook_detail: None,
        }
    }

    pub fn select_next(&mut self) {
        if !self.services.is_empty() {
            self.selected_service = (self.selected_service + 1) % self.services.len();
            self.scroll_offset = 0;
        }
    }

    pub fn select_prev(&mut self) {
        if !self.services.is_empty() {
            self.selected_service = if self.selected_service == 0 {
                self.services.len() - 1
            } else {
                self.selected_service - 1
            };
            self.scroll_offset = 0;
        }
    }

    /// Scroll up = further back in history = increase offset from bottom.
    pub fn scroll_up(&mut self) {
        match self.active_tab {
            Tab::Services => {
                if let Some(svc) = self.services.get(self.selected_service) {
                    let max = svc.logs.len().saturating_sub(1);
                    self.scroll_offset = (self.scroll_offset + 1).min(max);
                }
            }
            Tab::Webhooks => {
                let max = self.webhooks.len().saturating_sub(1);
                self.webhook_scroll = (self.webhook_scroll + 1).min(max);
            }
        }
    }

    /// Scroll down = toward present = decrease offset (0 = latest).
    pub fn scroll_down(&mut self) {
        match self.active_tab {
            Tab::Services => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            Tab::Webhooks => {
                self.webhook_scroll = self.webhook_scroll.saturating_sub(1);
            }
        }
    }

    pub fn push_log(&mut self, service_index: usize, line: &str) {
        if let Some(svc) = self.services.get_mut(service_index) {
            let was_at_bottom = self.scroll_offset == 0;
            svc.logs.push(line.to_string());
            // If buffer overflowed and we were scrolled up, clamp offset
            if !was_at_bottom && service_index == self.selected_service {
                let max = svc.logs.len().saturating_sub(1);
                self.scroll_offset = self.scroll_offset.min(max);
            }
        }
    }

    /// Push a captured webhook into the in-memory buffer.
    pub fn push_webhook(&mut self, webhook: CapturedWebhook) {
        let was_at_bottom = self.webhook_scroll == 0;
        self.webhooks.push(webhook);
        if !was_at_bottom {
            let max = self.webhooks.len().saturating_sub(1);
            self.webhook_scroll = self.webhook_scroll.min(max);
        }
    }

    /// Toggle webhook detail view for the given index (0-based, newest first).
    pub fn toggle_webhook_detail(&mut self, index: usize) {
        if self.webhook_detail == Some(index) {
            self.webhook_detail = None;
        } else if index < self.webhooks.len() {
            self.webhook_detail = Some(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_buffer::LogBuffer;

    fn make_app(log_capacity: usize, num_lines: usize) -> DashboardApp {
        let mut logs = LogBuffer::new(log_capacity);
        for i in 0..num_lines {
            logs.push(format!("line {i}"));
        }
        DashboardApp::new(vec![ServiceState {
            name: "test".into(),
            port: Some(3000),
            status: ServiceStatus::Ready,
            logs,
        }])
    }

    #[test]
    fn scroll_up_increases_offset() {
        let mut app = make_app(100, 20);
        assert_eq!(app.scroll_offset, 0);
        app.scroll_up();
        assert_eq!(app.scroll_offset, 1);
        app.scroll_up();
        assert_eq!(app.scroll_offset, 2);
    }

    #[test]
    fn scroll_down_decreases_offset() {
        let mut app = make_app(100, 20);
        app.scroll_offset = 5;
        app.scroll_down();
        assert_eq!(app.scroll_offset, 4);
        app.scroll_down();
        assert_eq!(app.scroll_offset, 3);
    }

    #[test]
    fn scroll_down_at_zero_stays_at_zero() {
        let mut app = make_app(100, 20);
        assert_eq!(app.scroll_offset, 0);
        app.scroll_down();
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn scroll_up_clamped_to_max() {
        let mut app = make_app(100, 5);
        // Max should be 4 (len - 1)
        for _ in 0..20 {
            app.scroll_up();
        }
        assert_eq!(app.scroll_offset, 4);
    }

    #[test]
    fn push_log_clamps_stale_scroll_offset() {
        let mut app = make_app(5, 5);
        // Scroll up to offset 4
        app.scroll_offset = 4;
        // Push 3 more lines — buffer overflows, old lines dropped
        app.push_log(0, "new1");
        app.push_log(0, "new2");
        app.push_log(0, "new3");
        // scroll_offset should be clamped to valid range (max = len-1 = 4)
        assert!(app.scroll_offset <= app.services[0].logs.len().saturating_sub(1));
    }

    #[test]
    fn push_log_at_bottom_stays_at_bottom() {
        let mut app = make_app(5, 5);
        assert_eq!(app.scroll_offset, 0);
        app.push_log(0, "new line");
        assert_eq!(app.scroll_offset, 0);
    }

    // ── Webhook state management tests ──

    fn make_test_webhook(id: &str) -> CapturedWebhook {
        CapturedWebhook {
            id: id.to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/webhook".to_string(),
            request_headers: std::collections::HashMap::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: std::collections::HashMap::new(),
            response_body: Vec::new(),
            duration_ms: 10,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: false,
        }
    }

    #[test]
    fn push_webhook_adds_to_buffer() {
        let mut app = make_app(10, 0);
        assert!(app.webhooks.is_empty());

        app.push_webhook(make_test_webhook("wh-1"));
        app.push_webhook(make_test_webhook("wh-2"));
        assert_eq!(app.webhooks.len(), 2);
    }

    #[test]
    fn push_webhook_at_bottom_stays_at_bottom() {
        let mut app = make_app(10, 0);
        app.push_webhook(make_test_webhook("wh-1"));
        assert_eq!(app.webhook_scroll, 0);
        app.push_webhook(make_test_webhook("wh-2"));
        assert_eq!(app.webhook_scroll, 0);
    }

    #[test]
    fn webhook_scroll_up_down() {
        let mut app = make_app(10, 0);
        for i in 0..10 {
            app.push_webhook(make_test_webhook(&format!("wh-{i}")));
        }
        app.active_tab = Tab::Webhooks;

        app.scroll_up();
        assert_eq!(app.webhook_scroll, 1);
        app.scroll_up();
        assert_eq!(app.webhook_scroll, 2);
        app.scroll_down();
        assert_eq!(app.webhook_scroll, 1);
    }

    #[test]
    fn toggle_webhook_detail() {
        let mut app = make_app(10, 0);
        app.push_webhook(make_test_webhook("wh-1"));
        app.push_webhook(make_test_webhook("wh-2"));

        // Open detail
        app.toggle_webhook_detail(0);
        assert_eq!(app.webhook_detail, Some(0));

        // Toggle same index closes it
        app.toggle_webhook_detail(0);
        assert_eq!(app.webhook_detail, None);

        // Open different index
        app.toggle_webhook_detail(1);
        assert_eq!(app.webhook_detail, Some(1));
    }

    #[test]
    fn toggle_webhook_detail_out_of_range_ignored() {
        let mut app = make_app(10, 0);
        app.push_webhook(make_test_webhook("wh-1"));

        // Index 5 doesn't exist (only 1 webhook)
        app.toggle_webhook_detail(5);
        assert_eq!(app.webhook_detail, None);
    }

    #[test]
    fn tab_switching() {
        let mut app = make_app(10, 0);
        assert_eq!(app.active_tab, Tab::Services);

        app.active_tab = Tab::Webhooks;
        assert_eq!(app.active_tab, Tab::Webhooks);

        app.active_tab = Tab::Services;
        assert_eq!(app.active_tab, Tab::Services);
    }
}
