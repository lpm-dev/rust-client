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
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

const MAX_EVENTS_PER_TICK: usize = 256;

pub use app::{DashboardApp, ServiceState, ServiceStatus, Tab};
pub use log_buffer::LogBuffer;

/// Events that the dashboard receives.
pub enum DashboardEvent {
    /// A line of output from a service.
    ServiceLog { index: usize, line: String },
    /// Service status changed.
    StatusChange { index: usize, status: ServiceStatus },
    /// Final managed port assigned to a named service.
    PortAssigned { service: String, port: u16 },
    /// A webhook was captured by the tunnel.
    WebhookCaptured(Arc<lpm_tunnel::webhook::CapturedWebhook>),
    /// A fatal background error that must close the dashboard.
    FatalError(String),
    /// The service orchestrator stopped and the dashboard must close.
    Shutdown,
}

/// Command from the dashboard back to the orchestrator.
pub enum DashboardCommand {
    RestartService(usize),
    StopService(usize),
    StopAll,
}

/// Non-blocking sink for dashboard service-control commands.
pub type DashboardCommandSink = Arc<dyn Fn(DashboardCommand) + Send + Sync>;

#[derive(Debug, PartialEq, Eq)]
enum DashboardFlow {
    Continue,
    Stop,
}

fn apply_dashboard_event(
    app: &mut DashboardApp,
    event: DashboardEvent,
) -> io::Result<DashboardFlow> {
    match event {
        DashboardEvent::ServiceLog { index, line } => {
            app.push_log_owned(index, line);
        }
        DashboardEvent::StatusChange { index, status } => {
            if index < app.services.len() {
                app.services[index].status = status;
            }
        }
        DashboardEvent::PortAssigned { service, port } => {
            app.set_service_port(&service, port);
        }
        DashboardEvent::WebhookCaptured(webhook) => {
            app.push_shared_webhook(webhook);
        }
        DashboardEvent::FatalError(error) => return Err(io::Error::other(error)),
        DashboardEvent::Shutdown => return Ok(DashboardFlow::Stop),
    }
    Ok(DashboardFlow::Continue)
}

fn drain_dashboard_events(
    app: &mut DashboardApp,
    event_rx: &mpsc::Receiver<DashboardEvent>,
) -> io::Result<DashboardFlow> {
    for _ in 0..MAX_EVENTS_PER_TICK {
        let event = match event_rx.try_recv() {
            Ok(event) => event,
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => break,
        };
        if apply_dashboard_event(app, event)? == DashboardFlow::Stop {
            return Ok(DashboardFlow::Stop);
        }
    }
    Ok(DashboardFlow::Continue)
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
/// via `command_sink` without exiting the TUI — the dashboard continues running.
///
/// `inspector_url` is the live browser-inspector URL when `lpm dev --tunnel`
/// started one. When set, the `o` key opens it in the user's default browser
/// without leaving the TUI. `None` makes the `o` key a no-op.
///
/// Terminal is always cleaned up, even on panic (via Drop guard).
pub fn run_dashboard(
    services: Vec<ServiceState>,
    event_rx: mpsc::Receiver<DashboardEvent>,
    command_sink: Option<DashboardCommandSink>,
    inspector_url: Option<String>,
) -> io::Result<DashboardCommand> {
    // Setup terminal — TerminalGuard ensures cleanup on any exit path
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;

    let mut guard = TerminalGuard { terminal };
    let mut app = DashboardApp::new(services);
    app.inspector_url = inspector_url;

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
                    if let Some(ref sink) = command_sink {
                        sink(DashboardCommand::RestartService(app.selected_service));
                    }
                }
                KeyCode::Char('x') if app.active_tab == app::Tab::Services => {
                    // Send stop command for selected service without leaving the TUI
                    if let Some(ref sink) = command_sink {
                        sink(DashboardCommand::StopService(app.selected_service));
                    }
                }
                // `o` opens the live browser inspector in the user's default
                // browser. No-op when no inspector is running (e.g. running
                // `lpm dev` without `--tunnel`, or `--no-inspect`).
                KeyCode::Char('o') => {
                    if let Some(ref url) = app.inspector_url {
                        // Best-effort: a missing `xdg-open` / no-display CI
                        // shouldn't crash the TUI. The URL is also printed
                        // in the startup banner so the user can copy-paste.
                        let _ = open::that(url);
                    }
                }
                KeyCode::Up => app.scroll_up(),
                KeyCode::Down => app.scroll_down(),
                _ => {}
            }
        }

        // Drain service events
        if drain_dashboard_events(&mut app, &event_rx)? == DashboardFlow::Stop {
            return Ok(DashboardCommand::StopAll);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_event_stops_dashboard_without_keyboard_input() {
        let mut app = DashboardApp::new(Vec::new());

        let flow = apply_dashboard_event(&mut app, DashboardEvent::Shutdown).unwrap();

        assert_eq!(flow, DashboardFlow::Stop);
    }

    #[test]
    fn one_dashboard_tick_processes_a_bounded_event_batch() {
        let mut app = DashboardApp::new(Vec::new());
        let (tx, rx) = mpsc::channel();
        for _ in 0..=MAX_EVENTS_PER_TICK {
            tx.send(DashboardEvent::PortAssigned {
                service: "missing".to_string(),
                port: 3000,
            })
            .unwrap();
        }

        assert_eq!(
            drain_dashboard_events(&mut app, &rx).unwrap(),
            DashboardFlow::Continue
        );
        assert!(
            rx.try_recv().is_ok(),
            "one event must remain for the next tick"
        );
    }
}
