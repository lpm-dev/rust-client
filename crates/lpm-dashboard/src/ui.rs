//! TUI rendering with ratatui.

use crate::app::{DashboardApp, ServiceStatus};
use ratatui::prelude::*;
use ratatui::widgets::*;

/// Render the dashboard UI.
pub fn render(frame: &mut Frame, app: &DashboardApp) {
	let area = frame.area();

	// Responsive: hide sidebar if terminal too narrow
	if area.width < 80 {
		render_compact(frame, app, area);
		return;
	}

	// Split: left sidebar (30 cols) + right log panel
	let chunks = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([Constraint::Length(30), Constraint::Min(40)])
		.split(area);

	render_sidebar(frame, app, chunks[0]);
	render_logs(frame, app, chunks[1]);
}

/// Sidebar: service list + network info.
fn render_sidebar(frame: &mut Frame, app: &DashboardApp, area: Rect) {
	let chunks = Layout::default()
		.direction(Direction::Vertical)
		.constraints([Constraint::Min(5), Constraint::Length(6), Constraint::Length(1)])
		.split(area);

	// Service list
	let items: Vec<ListItem> = app
		.services
		.iter()
		.enumerate()
		.map(|(i, svc)| {
			let icon = svc.status.icon();
			let port_str = svc
				.port
				.map(|p| format!(":{p}"))
				.unwrap_or_else(|| "  —".into());

			let style = if i == app.selected_service {
				Style::default().bold().fg(Color::Cyan)
			} else {
				Style::default()
			};

			let status_color = match &svc.status {
				ServiceStatus::Ready => Color::Green,
				ServiceStatus::Crashed(_) => Color::Red,
				ServiceStatus::Starting | ServiceStatus::WaitingForDep(_) => Color::Yellow,
				ServiceStatus::Stopped => Color::DarkGray,
			};

			let line = Line::from(vec![
				Span::styled(format!(" {icon} "), Style::default().fg(status_color)),
				Span::styled(format!("{:<10}", svc.name), style),
				Span::styled(format!("{port_str:<6}"), Style::default().fg(Color::DarkGray)),
				Span::styled(
					svc.status.label(),
					Style::default().fg(status_color),
				),
			]);

			ListItem::new(line)
		})
		.collect();

	let services_block = Block::default()
		.title(" Services ")
		.borders(Borders::ALL)
		.border_style(Style::default().fg(Color::DarkGray));

	let list = List::new(items).block(services_block);
	frame.render_widget(list, chunks[0]);

	// Network info
	let mut info_lines = Vec::new();
	if app.https {
		info_lines.push(Line::from(vec![
			Span::styled(" HTTPS ", Style::default().fg(Color::Green)),
			Span::raw("enabled"),
		]));
	}
	if let Some(ref url) = app.tunnel_url {
		info_lines.push(Line::from(vec![
			Span::styled(" Tunnel ", Style::default().fg(Color::Green)),
			Span::raw(url.as_str()),
		]));
	}
	if let Some(ref ip) = app.network_ip {
		info_lines.push(Line::from(vec![
			Span::styled(" Network ", Style::default().fg(Color::Green)),
			Span::raw(ip.as_str()),
		]));
	}

	let info_block = Block::default()
		.title(" Network ")
		.borders(Borders::ALL)
		.border_style(Style::default().fg(Color::DarkGray));

	let info = Paragraph::new(info_lines).block(info_block);
	frame.render_widget(info, chunks[1]);

	// Bottom: key hints
	let hints = Paragraph::new(Line::from(vec![
		Span::styled(" [1-9]", Style::default().fg(Color::Cyan)),
		Span::raw(" switch "),
		Span::styled("[r]", Style::default().fg(Color::Cyan)),
		Span::raw("estart "),
		Span::styled("[q]", Style::default().fg(Color::Cyan)),
		Span::raw("uit"),
	]));
	frame.render_widget(hints, chunks[2]);
}

/// Log panel: shows output from selected service.
fn render_logs(frame: &mut Frame, app: &DashboardApp, area: Rect) {
	let svc = match app.services.get(app.selected_service) {
		Some(s) => s,
		None => return,
	};

	let title = format!(" Logs ({}) ", svc.name);
	let block = Block::default()
		.title(title)
		.borders(Borders::ALL)
		.border_style(Style::default().fg(Color::DarkGray));

	let inner = block.inner(area);
	let visible_height = inner.height as usize;

	// Get visible log lines (saturating math to prevent underflow)
	let total_lines = svc.logs.len();
	let max_scroll = total_lines.saturating_sub(visible_height);
	let effective_scroll = app.scroll_offset.min(max_scroll);
	let start = total_lines
		.saturating_sub(visible_height)
		.saturating_sub(effective_scroll);

	let log_lines: Vec<Line> = svc
		.logs
		.lines_from(start)
		.take(visible_height)
		.map(|line| Line::raw(line))
		.collect();

	let logs = Paragraph::new(log_lines)
		.block(block)
		.wrap(Wrap { trim: false });

	frame.render_widget(logs, area);
}

/// Compact mode: no sidebar, just logs with service prefix.
fn render_compact(frame: &mut Frame, app: &DashboardApp, area: Rect) {
	let svc = match app.services.get(app.selected_service) {
		Some(s) => s,
		None => return,
	};

	let title = format!(" {} (Tab to switch) ", svc.name);
	let block = Block::default()
		.title(title)
		.borders(Borders::ALL);

	let log_lines: Vec<Line> = svc
		.logs
		.lines()
		.map(|line| Line::raw(line))
		.collect();

	let logs = Paragraph::new(log_lines)
		.block(block)
		.wrap(Wrap { trim: false });

	frame.render_widget(logs, area);
}
