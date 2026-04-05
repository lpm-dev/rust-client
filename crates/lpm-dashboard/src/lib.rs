//! TUI dashboard for LPM dev server.
//!
//! Provides a rich terminal interface for viewing multiple service logs,
//! status indicators, and network info when running `lpm dev --dashboard`.

pub mod app;
pub mod log_buffer;
pub mod ui;

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;
use std::io;
use std::sync::mpsc;
use std::time::Duration;

pub use app::{DashboardApp, ServiceState, ServiceStatus, Tab};
pub use log_buffer::LogBuffer;

/// Events that the dashboard receives.
pub enum DashboardEvent {
    /// A line of output from a service.
    ServiceLog { index: usize, line: String },
    /// Service status changed.
    StatusChange { index: usize, status: ServiceStatus },
    /// A webhook was captured by the tunnel.
    WebhookCaptured(Box<lpm_tunnel::webhook::CapturedWebhook>),
}

/// Command from the dashboard back to the orchestrator.
pub enum DashboardCommand {
    RestartService(usize),
    StopService(usize),
    StopAll,
}

/// RAII guard that restores the terminal to normal state on drop.
///
/// This ensures the terminal is cleaned up even if a panic occurs during
/// rendering — prevents leaving the terminal in raw mode / alternate screen.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

/// Run the TUI dashboard.
///
/// Blocks until the user quits (q or Ctrl+C).
/// Returns `DashboardCommand::StopAll` when the user exits.
///
/// Service control commands (restart, stop) are sent directly to the orchestrator
/// via `command_tx` without exiting the TUI — the dashboard continues running.
///
/// Terminal is always cleaned up, even on panic (via Drop guard).
pub fn run_dashboard(
    services: Vec<ServiceState>,
    event_rx: mpsc::Receiver<DashboardEvent>,
    command_tx: Option<mpsc::Sender<DashboardCommand>>,
) -> io::Result<DashboardCommand> {
    // Setup terminal — TerminalGuard ensures cleanup on any exit path
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;

    let mut guard = TerminalGuard { terminal };
    let mut app = DashboardApp::new(services);

    loop {
        // Render
        guard.terminal.draw(|frame| ui::render(frame, &app))?;

        // Check for events (non-blocking with timeout)
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') => {
                    // Guard handles cleanup via Drop
                    return Ok(DashboardCommand::StopAll);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(DashboardCommand::StopAll);
                }
                // Tab switching: 'w' for webhooks, 's' for services
                KeyCode::Char('w') => {
                    app.active_tab = app::Tab::Webhooks;
                    app.webhook_detail = None;
                }
                KeyCode::Char('s') => {
                    app.active_tab = app::Tab::Services;
                }
                // Enter toggles detail view in webhook tab
                KeyCode::Enter if app.active_tab == app::Tab::Webhooks => {
                    // Detail for the item at current scroll position
                    let idx = app.webhook_scroll;
                    app.toggle_webhook_detail(idx);
                }
                // Escape closes detail view
                KeyCode::Esc if app.active_tab == app::Tab::Webhooks => {
                    app.webhook_detail = None;
                }
                KeyCode::Tab => app.select_next(),
                KeyCode::BackTab => app.select_prev(),
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let idx = c.to_digit(10).unwrap_or(0) as usize;
                    if idx > 0 && idx <= app.services.len() {
                        app.selected_service = idx - 1;
                        app.scroll_offset = 0;
                    }
                }
                KeyCode::Char('r') if app.active_tab == app::Tab::Services => {
                    // Send restart command to orchestrator without leaving the TUI
                    if let Some(ref tx) = command_tx {
                        let _ = tx.send(DashboardCommand::RestartService(app.selected_service));
                    }
                }
                KeyCode::Char('x') if app.active_tab == app::Tab::Services => {
                    // Send stop command for selected service without leaving the TUI
                    if let Some(ref tx) = command_tx {
                        let _ = tx.send(DashboardCommand::StopService(app.selected_service));
                    }
                }
                KeyCode::Up => app.scroll_up(),
                KeyCode::Down => app.scroll_down(),
                _ => {}
            }
        }

        // Drain service events
        while let Ok(event) = event_rx.try_recv() {
            match event {
                DashboardEvent::ServiceLog { index, line } => {
                    app.push_log(index, &line);
                }
                DashboardEvent::StatusChange { index, status } => {
                    if index < app.services.len() {
                        app.services[index].status = status;
                    }
                }
                DashboardEvent::WebhookCaptured(webhook) => {
                    app.push_webhook(*webhook);
                }
            }
        }
    }
}
