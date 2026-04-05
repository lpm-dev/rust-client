//! TUI rendering with ratatui.

use crate::app::{DashboardApp, ServiceStatus, Tab};
use ratatui::prelude::*;
use ratatui::widgets::*;

/// Render the dashboard UI.
pub fn render(frame: &mut Frame, app: &DashboardApp) {
    let area = frame.area();

    // Empty services: show helpful message
    if app.services.is_empty() && app.active_tab == Tab::Services {
        let msg = Paragraph::new("No services configured. Add services to lpm.json.")
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .title(" LPM Dashboard ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        frame.render_widget(msg, area);
        return;
    }

    // Tab bar at top (1 line) + content below
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);

    render_tab_bar(frame, app, outer[0]);
    let content_area = outer[1];

    match app.active_tab {
        Tab::Services => {
            // Responsive: hide sidebar if terminal too narrow
            if content_area.width < 80 {
                render_compact(frame, app, content_area);
            } else {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Length(30), Constraint::Min(40)])
                    .split(content_area);
                render_sidebar(frame, app, chunks[0]);
                render_logs(frame, app, chunks[1]);
            }
        }
        Tab::Webhooks => {
            render_webhooks(frame, app, content_area);
        }
    }
}

/// Tab bar showing [s]ervices and [w]ebhooks.
fn render_tab_bar(frame: &mut Frame, app: &DashboardApp, area: Rect) {
    let svc_style = if app.active_tab == Tab::Services {
        Style::default().fg(Color::Cyan).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let wh_style = if app.active_tab == Tab::Webhooks {
        Style::default().fg(Color::Cyan).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let webhook_count = app.webhooks.len();
    let wh_label = if webhook_count > 0 {
        format!(" [w] Webhooks ({webhook_count}) ")
    } else {
        " [w] Webhooks ".to_string()
    };

    let line = Line::from(vec![
        Span::styled(" [s] Services ", svc_style),
        Span::raw(" "),
        Span::styled(wh_label, wh_style),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// Sidebar: service list + network info.
fn render_sidebar(frame: &mut Frame, app: &DashboardApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(6),
            Constraint::Length(1),
        ])
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
                Span::styled(
                    format!("{port_str:<6}"),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(svc.status.label(), Style::default().fg(status_color)),
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
        Span::styled("[x]", Style::default().fg(Color::Cyan)),
        Span::raw(" stop "),
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
        .map(Line::raw)
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
    let block = Block::default().title(title).borders(Borders::ALL);

    let inner = block.inner(area);
    let visible_height = inner.height as usize;

    let total = svc.logs.len();
    let max_scroll = total.saturating_sub(visible_height);
    let effective_scroll = app.scroll_offset.min(max_scroll);
    let start = total
        .saturating_sub(visible_height)
        .saturating_sub(effective_scroll);

    let log_lines: Vec<Line> = svc
        .logs
        .lines_from(start)
        .take(visible_height)
        .map(Line::raw)
        .collect();

    let logs = Paragraph::new(log_lines)
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(logs, area);
}

// ── Webhook panel ─────────────────────────────────────────────────

/// Render the webhook inspector view.
fn render_webhooks(frame: &mut Frame, app: &DashboardApp, area: Rect) {
    if app.webhooks.is_empty() {
        let msg = Paragraph::new(
            "No webhooks captured yet.\nStart a tunnel with `lpm dev --tunnel` to capture webhooks.",
        )
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .title(" Webhooks ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        frame.render_widget(msg, area);
        return;
    }

    // If detail mode, show detail for selected webhook
    if let Some(detail_idx) = app.webhook_detail {
        render_webhook_detail(frame, app, area, detail_idx);
        return;
    }

    // List view: split into webhook list + key hints
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(1)])
        .split(area);

    let block = Block::default()
        .title(format!(" Webhooks ({}) ", app.webhooks.len()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(chunks[0]);
    let visible_height = inner.height as usize;

    // Build webhook lines in newest-first order.
    // Collect into Vec first because WebhookBuffer::iter() returns
    // impl Iterator which doesn't support .rev() directly.
    let webhooks: Vec<&lpm_tunnel::webhook::CapturedWebhook> = app.webhooks.iter().collect();
    let total = webhooks.len();
    let max_scroll = total.saturating_sub(visible_height);
    let effective_scroll = app.webhook_scroll.min(max_scroll);

    // Newest first: reverse the iterator
    let start_from_end = effective_scroll;
    let webhook_lines: Vec<Line> = webhooks
        .iter()
        .rev()
        .skip(start_from_end)
        .take(visible_height)
        .map(|wh| {
            let status_color = if wh.response_status >= 500 {
                Color::Red
            } else if wh.response_status >= 400 {
                Color::Yellow
            } else {
                Color::Green
            };

            let provider = wh
                .provider
                .map(|p: lpm_tunnel::webhook::WebhookProvider| p.to_string())
                .unwrap_or_default();

            let time = if wh.timestamp.len() >= 19 {
                &wh.timestamp[11..19]
            } else {
                &wh.timestamp
            };

            Line::from(vec![
                Span::styled(format!(" {time} "), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:<6}", wh.method), Style::default()),
                Span::styled(
                    format!("{:<30} ", truncate_path(&wh.path, 30)),
                    Style::default(),
                ),
                Span::styled(
                    format!("{:<4}", wh.response_status),
                    Style::default().fg(status_color),
                ),
                Span::styled(
                    format!("{:>5}ms  ", wh.duration_ms),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    if provider.is_empty() {
                        String::new()
                    } else {
                        format!("{provider}: ")
                    },
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(&wh.summary),
            ])
        })
        .collect();

    let list = Paragraph::new(webhook_lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(list, chunks[0]);

    // Key hints
    let hints = Paragraph::new(Line::from(vec![
        Span::styled(" [Enter]", Style::default().fg(Color::Cyan)),
        Span::raw(" detail "),
        Span::styled("[s]", Style::default().fg(Color::Cyan)),
        Span::raw("ervices "),
        Span::styled("[Up/Down]", Style::default().fg(Color::Cyan)),
        Span::raw(" scroll "),
        Span::styled("[q]", Style::default().fg(Color::Cyan)),
        Span::raw("uit"),
    ]));
    frame.render_widget(hints, chunks[1]);
}

/// Render detail view for a single webhook.
fn render_webhook_detail(frame: &mut Frame, app: &DashboardApp, area: Rect, index: usize) {
    let mut webhooks: Vec<&lpm_tunnel::webhook::CapturedWebhook> = app.webhooks.iter().collect();
    webhooks.reverse();
    let wh = match webhooks.get(index) {
        Some(w) => w,
        None => return,
    };

    let status_color = if wh.response_status >= 500 {
        Color::Red
    } else if wh.response_status >= 400 {
        Color::Yellow
    } else {
        Color::Green
    };

    let provider = wh
        .provider
        .map(|p| p.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let title = format!(
        " #{} — {} {} -> {} ",
        index + 1,
        wh.method,
        truncate_path(&wh.path, 40),
        wh.response_status
    );

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(status_color));

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Provider: ", Style::default().bold()),
            Span::raw(&provider),
            Span::raw("  "),
            Span::styled("Duration: ", Style::default().bold()),
            Span::raw(format!("{}ms", wh.duration_ms)),
            Span::raw("  "),
            Span::styled("Time: ", Style::default().bold()),
            Span::raw(&wh.timestamp),
        ]),
        Line::raw(""),
    ];

    // Request headers (first 10)
    if !wh.request_headers.is_empty() {
        lines.push(Line::styled("Request Headers:", Style::default().bold()));
        for (i, (key, value)) in wh.request_headers.iter().enumerate() {
            if i >= 10 {
                lines.push(Line::styled(
                    format!("  ... and {} more", wh.request_headers.len() - 10),
                    Style::default().fg(Color::DarkGray),
                ));
                break;
            }
            let k: &String = key;
            let v: &String = value;
            let display_val = if k.to_lowercase().contains("authorization")
                || k.to_lowercase().contains("secret")
            {
                format!("{}...", &v[..v.len().min(12)])
            } else {
                v.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {k}: "), Style::default().fg(Color::DarkGray)),
                Span::raw(display_val),
            ]));
        }
        lines.push(Line::raw(""));
    }

    // Request body preview
    if !wh.request_body.is_empty() {
        lines.push(Line::styled(
            format!("Request Body ({} bytes):", wh.request_body.len()),
            Style::default().bold(),
        ));
        let body_str = String::from_utf8_lossy(&wh.request_body);
        let display =
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&wh.request_body) {
                serde_json::to_string_pretty(&json).unwrap_or_else(|_| body_str.to_string())
            } else {
                body_str.to_string()
            };
        for line in display.lines().take(20) {
            lines.push(Line::raw(format!("  {line}")));
        }
        if display.lines().count() > 20 {
            lines.push(Line::styled("  ...", Style::default().fg(Color::DarkGray)));
        }
        lines.push(Line::raw(""));
    }

    // Signature diagnostic
    if let Some(ref diag) = wh.signature_diagnostic {
        lines.push(Line::styled(
            format!("Signature Issue: {diag}"),
            Style::default().fg(Color::Yellow).bold(),
        ));
        lines.push(Line::raw(""));
    }

    // Response status
    lines.push(Line::from(vec![
        Span::styled("Response: ", Style::default().bold()),
        Span::styled(
            format!("{}", wh.response_status),
            Style::default().fg(status_color),
        ),
    ]));

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("[Esc]", Style::default().fg(Color::Cyan)),
        Span::raw(" back to list"),
    ]));

    let detail = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(detail, area);
}

/// Truncate a path string with ellipsis if too long.
///
/// Uses `char_indices()` instead of byte-indexing to prevent panics
/// on paths containing multi-byte UTF-8 characters (emoji, CJK, etc.).
fn truncate_path(path: &str, max: usize) -> String {
    if path.chars().count() <= max {
        path.to_string()
    } else {
        let truncate_at = max.saturating_sub(3);
        let end = path
            .char_indices()
            .nth(truncate_at)
            .map(|(i, _)| i)
            .unwrap_or(path.len());
        format!("{}...", &path[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_path_unchanged() {
        assert_eq!(truncate_path("/api/health", 20), "/api/health");
    }

    #[test]
    fn truncate_long_path_adds_ellipsis() {
        let result = truncate_path("/very/long/path/to/some/endpoint", 15);
        assert!(result.ends_with("..."), "should end with ellipsis: {result}");
        assert!(
            result.chars().count() <= 15,
            "should not exceed max: {result}"
        );
    }

    #[test]
    fn truncate_path_exact_length_unchanged() {
        let path = "exactly10!";
        assert_eq!(truncate_path(path, 10), path);
    }

    #[test]
    fn truncate_path_utf8_multibyte_no_panic() {
        // This would panic with byte-indexing if truncation landed mid-character
        let path = "/api/日本語/endpoint/データ";
        let result = truncate_path(path, 10);
        assert!(result.ends_with("..."), "should end with ellipsis: {result}");
        // Should not panic — that's the main assertion
    }

    #[test]
    fn truncate_path_emoji_no_panic() {
        let path = "/🎉/🚀/📦/webhook/test";
        let result = truncate_path(path, 8);
        assert!(result.ends_with("..."), "should end with ellipsis: {result}");
    }

    #[test]
    fn truncate_path_max_3_or_less() {
        // Edge case: max is 3 or less, truncate_at would be 0
        let result = truncate_path("/api/test", 3);
        assert_eq!(result, "...");
    }
}
