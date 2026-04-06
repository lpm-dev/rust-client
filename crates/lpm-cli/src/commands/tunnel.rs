use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::Path;

/// Run the `lpm tunnel` command.
///
/// Actions:
///   (default) — start a tunnel to expose a local port
///   claim     — claim a domain (e.g., acme-api.lpm.llc)
///   unclaim   — release a claimed domain
///   list      — list claimed domains
///   domains   — list available base domains
///   inspect   — view captured webhooks
///   replay    — replay a captured webhook
///   log/logs  — browse webhook event log
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    action: &str,
    token: Option<&str>,
    port: u16,
    domain: Option<&str>,
    org: Option<&str>,
    json_output: bool,
    project_dir: &Path,
    extra_args: &[String],
    tunnel_auth: bool,
    no_inspect: bool,
    inspect_port: u16,
    auto_ack: bool,
    session_name: Option<&str>,
) -> Result<(), LpmError> {
    match action {
        "claim" => run_claim(client, domain, org, json_output).await,
        "unclaim" | "release" => run_unclaim(client, domain, org, json_output).await,
        "list" | "ls" => run_list(client, org, json_output).await,
        "domains" => run_domains(client, json_output).await,
        "inspect" => {
            // `lpm tunnel inspect --ui` opens the browser inspector on historical data
            if extra_args.contains(&"--ui".to_string()) {
                return run_inspect_ui(project_dir, inspect_port).await;
            }
            run_inspect(project_dir, extra_args, json_output).await
        }
        "replay" => run_replay(project_dir, extra_args, port).await,
        "log" | "logs" => run_log(project_dir, extra_args, json_output).await,
        "start" | "" => {
            run_start(
                token,
                port,
                domain,
                json_output,
                tunnel_auth,
                no_inspect,
                inspect_port,
                auto_ack,
                session_name,
            )
            .await
        }
        _ => {
            // If action looks like a port number, treat as start
            if let Ok(p) = action.parse::<u16>() {
                return run_start(
                    token,
                    p,
                    domain,
                    json_output,
                    tunnel_auth,
                    no_inspect,
                    inspect_port,
                    auto_ack,
                    session_name,
                )
                .await;
            }
            Err(LpmError::Tunnel(format!(
                "unknown action '{action}'. Available: claim, unclaim, list, domains, inspect, replay, log, or a port number"
            )))
        }
    }
}

/// Start a tunnel to expose a local port.
#[allow(clippy::too_many_arguments)]
async fn run_start(
    token: Option<&str>,
    port: u16,
    domain: Option<&str>,
    json_output: bool,
    tunnel_auth: bool,
    no_inspect: bool,
    inspect_port: u16,
    auto_ack: bool,
    session_name: Option<&str>,
) -> Result<(), LpmError> {
    let token = token.ok_or_else(|| {
        LpmError::Tunnel("authentication required. Run `lpm login` first.".into())
    })?;

    // Reject bare subdomain without base domain (e.g., "acme" instead of "acme.lpm.llc")
    if let Some(d) = domain
        && !d.contains('.')
    {
        output::warn("Missing base domain.");
        eprintln!("  Available: lpm.fyi, lpm.llc");
        eprintln!("  Example: lpm tunnel start --domain {d}.lpm.llc");
        return Err(LpmError::Tunnel("missing base domain".into()));
    }

    // Generate tunnel auth token if requested (random 32-byte hex, one per session)
    let tunnel_auth_token = if tunnel_auth {
        use rand::Rng;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Some(hex)
    } else {
        None
    };

    // Start the inspector server (unless --no-inspect)
    let project_dir = std::env::current_dir().map_err(LpmError::Io)?;
    let inspector_state = match lpm_inspect::db::InspectorDb::open(&project_dir) {
        Ok(db) => lpm_inspect::state::InspectorState::with_db(port, db),
        Err(e) => {
            if !json_output {
                output::warn(&format!("inspector db failed: {e} — using in-memory only"));
            }
            lpm_inspect::state::InspectorState::new(port)
        }
    };
    let inspector_handle = if !no_inspect {
        match lpm_inspect::start(inspector_state.clone(), inspect_port).await {
            Ok(handle) => Some(handle),
            Err(e) => {
                // Inspector failure is non-fatal — tunnel still works
                if !json_output {
                    output::warn(&format!("inspector failed to start: {e}"));
                }
                None
            }
        }
    } else {
        None
    };

    // Create webhook capture channel — feeds both the inspector and the JSONL logger
    let (webhook_tx, mut webhook_rx) =
        tokio::sync::mpsc::unbounded_channel::<lpm_tunnel::webhook::CapturedWebhook>();

    // Create WebSocket capture channel
    let (ws_tx, mut ws_rx) =
        tokio::sync::mpsc::unbounded_channel::<lpm_tunnel::ws_capture::WsEvent>();

    // Spawn webhook consumer: pushes to inspector state for real-time SSE streaming
    let inspector_state_consumer = inspector_state.clone();
    tokio::spawn(async move {
        while let Some(webhook) = webhook_rx.recv().await {
            inspector_state_consumer.push(webhook).await;
        }
    });

    // Spawn WS event consumer: pushes to inspector state
    let inspector_state_ws = inspector_state.clone();
    tokio::spawn(async move {
        while let Some(event) = ws_rx.recv().await {
            inspector_state_ws.push_ws_event(event).await;
        }
    });

    let options = lpm_tunnel::client::TunnelOptions {
        relay_url: lpm_tunnel::DEFAULT_RELAY_URL.to_string(),
        token: token.to_string(),
        local_port: port,
        domain: domain.map(|s| s.to_string()),
        tunnel_auth: tunnel_auth_token.clone(),
        webhook_tx: Some(webhook_tx),
        no_pin: false,
        auto_ack,
        ws_tx: Some(ws_tx),
    };

    if !json_output {
        output::info(&format!("connecting tunnel for localhost:{port}..."));
    }

    let tunnel_auth_display = tunnel_auth_token.clone();
    let inspector_url = inspector_handle.as_ref().map(|h| h.url.clone());
    let inspector_state_for_connect = inspector_state.clone();
    let session_name_owned = session_name.map(|s| s.to_string());

    lpm_tunnel::client::connect(
        &options,
        move |session| {
            // Update inspector state with the tunnel URL and start a session
            let url = session.tunnel_url.clone();
            let session_id = session.session_id.clone();
            let domain = Some(session.domain.clone());
            let local = session.local_port;
            let state = inspector_state_for_connect.clone();
            let name = session_name_owned.clone();
            tokio::spawn(async move {
                state.set_tunnel_url(url).await;
                state.start_session(session_id, domain, local, name).await;
            });

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "tunnel_url": session.tunnel_url,
                        "domain": session.domain,
                        "local_port": session.local_port,
                        "session_id": session.session_id,
                        "tunnel_auth": tunnel_auth_display,
                        "inspector_url": inspector_url,
                        "auto_ack": auto_ack,
                    })
                );
            } else {
                println!();
                println!(
                    "  {} {}",
                    "●".green(),
                    format!(
                        "Tunnel: {} → localhost:{}",
                        session.tunnel_url.bold(),
                        session.local_port
                    )
                    .green()
                );
                if let Some(ref url) = inspector_url {
                    println!(
                        "  {} {}",
                        "●".cyan(),
                        format!("Inspector: {}", url.bold()).cyan()
                    );
                }
                if auto_ack {
                    println!(
                        "  {} {}",
                        "●".yellow(),
                        "Auto-ack: ON — 200 OK returned when server is down".yellow()
                    );
                }
                if let Some(ref auth) = tunnel_auth_display {
                    println!(
                        "  {} Auth required: add header {}",
                        "🔒".dimmed(),
                        format!("X-Tunnel-Auth: {auth}").bold()
                    );
                    println!(
                        "  {} Browser: {}?__tunnel_auth={auth}",
                        " ".dimmed(),
                        session.tunnel_url,
                    );
                }
                println!();
                output::field("domain", &session.domain);
                output::field("session", &session.session_id);
                println!("  {}", "Press Ctrl+C to stop the tunnel".dimmed());
                println!();
            }
        },
        |msg| {
            if !json_output {
                output::warn(msg);
            }
        },
    )
    .await?;

    // End the session and gracefully shut down the inspector
    inspector_state.end_session().await;
    if let Some(handle) = inspector_handle {
        handle.shutdown();
    }

    Ok(())
}

/// Claim a tunnel domain (e.g., acme-api.lpm.llc).
async fn run_claim(
    client: &RegistryClient,
    domain: Option<&str>,
    org: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let domain = domain.ok_or_else(|| {
		LpmError::Tunnel(
			"missing domain. Usage: lpm tunnel claim <domain>\n  Example: lpm tunnel claim acme-api.lpm.llc".into(),
		)
	})?;

    // Validate: must be a valid full tunnel domain
    if !is_valid_tunnel_domain(domain) {
        if !domain.contains('.') {
            return Err(LpmError::Tunnel(format!(
                "'{domain}' is not a full domain. Use: {domain}.lpm.fyi or {domain}.lpm.llc\n  Run `lpm tunnel domains` to see available base domains"
            )));
        }
        return Err(LpmError::Tunnel(format!(
            "'{domain}' is not a valid tunnel domain.\n  Subdomain must be 3-32 lowercase alphanumeric chars or hyphens, no leading/trailing hyphen.\n  Example: my-app.lpm.llc"
        )));
    }

    let result = client.tunnel_claim(domain, org).await?;

    if json_output {
        println!("{result}");
    } else {
        let url = result["url"].as_str().unwrap_or("");
        output::success(&format!("claimed {}", url.bold()));
        if let Some(org_name) = org {
            output::field("org", org_name);
        }
    }

    Ok(())
}

/// Release a claimed tunnel domain.
async fn run_unclaim(
    client: &RegistryClient,
    domain: Option<&str>,
    org: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let domain = domain.ok_or_else(|| {
        LpmError::Tunnel("missing domain. Usage: lpm tunnel unclaim <domain>".into())
    })?;

    client.tunnel_unclaim(domain, org).await?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({ "success": true, "released": true, "domain": domain })
        );
    } else {
        output::success(&format!("released {}", domain.bold()));
    }

    Ok(())
}

/// List claimed tunnel domains.
async fn run_list(
    client: &RegistryClient,
    org: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let result = client.tunnel_list(org).await?;

    if json_output {
        println!("{result}");
        return Ok(());
    }

    let domains = result["domains"].as_array();
    let limit = result["limit"].as_u64().unwrap_or(0);
    let used = result["used"].as_u64().unwrap_or(0);

    if let Some(org_name) = org {
        output::header(&format!("Tunnel Domains — {org_name}"));
    } else {
        output::header("Tunnel Domains");
    }

    println!("  {} of {} used", used.to_string().bold(), limit);
    println!();

    match domains {
        Some(doms) if !doms.is_empty() => {
            for d in doms {
                let _domain = d["domain"].as_str().unwrap_or("?");
                let url = d["url"].as_str().unwrap_or("?");
                let base = d["baseDomain"].as_str().unwrap_or("?");
                println!(
                    "  {} {} {}",
                    "●".cyan(),
                    url.bold(),
                    format!("({base})").dimmed()
                );
            }
        }
        _ => {
            println!("  {}", "No domains claimed".dimmed());
            println!(
                "  {}",
                "Claim one with: lpm tunnel claim <name>.lpm.llc".dimmed()
            );
        }
    }

    println!();
    Ok(())
}

/// List available base domains.
async fn run_domains(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
    let result = client.tunnel_available_domains().await?;

    if json_output {
        println!("{result}");
        return Ok(());
    }

    output::header("Available Tunnel Domains");
    println!();

    if let Some(domains) = result["domains"].as_array() {
        for d in domains {
            let domain = d["domain"].as_str().unwrap_or("?");
            let plan = d["planRequired"].as_str().unwrap_or("?");
            let plan_badge = if plan == "free" {
                "free".green().to_string()
            } else {
                "pro".cyan().to_string()
            };
            println!("  {} {:<15} {}", "●".green(), domain, plan_badge);
        }
    }

    println!();
    Ok(())
}

// ── Inspector UI (standalone, no tunnel) ────────────────────────────

/// Launch the browser inspector UI on historical data (read-only, no tunnel).
///
/// Usage: `lpm tunnel inspect --ui`
async fn run_inspect_ui(_project_dir: &Path, inspect_port: u16) -> Result<(), LpmError> {
    let state = lpm_inspect::state::InspectorState::new(0);
    let handle = lpm_inspect::start(state, inspect_port).await?;

    output::success(&format!("Inspector: {}", handle.url.bold()));
    println!("  {}", "Press Ctrl+C to stop".dimmed());

    // Block until Ctrl+C
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| LpmError::Tunnel(format!("signal error: {e}")))?;

    handle.shutdown();
    Ok(())
}

// ── Webhook inspect command ─────────────────────────────────────────

/// Show captured webhooks. Supports listing and detail views.
///
/// Flags:
///   --last N / -n N    — show last N webhooks (default: 20)
///   --detail N / -d N  — show full detail for webhook #N
///   --filter <provider> — filter by provider (stripe, github, clerk, etc.)
///   --status <code>    — filter by status class (2xx, 4xx, 5xx, or exact code)
async fn run_inspect(
    project_dir: &Path,
    args: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    let logger = lpm_tunnel::webhook_log::WebhookLogger::new(project_dir);

    let last = parse_flag_usize(args, "--last", "-n").unwrap_or(20);
    let filter_provider = parse_flag_str(args, "--filter");
    let filter_status = parse_flag_str(args, "--status");
    let detail_index = parse_flag_usize(args, "--detail", "-d");

    if let Some(idx) = detail_index {
        if idx == 0 {
            output::warn("--detail uses 1-based indexing. Use --detail 1 for the first entry.");
            return Ok(());
        }
        // Detail mode: show full webhook by 1-based index
        let entries = logger.read_recent(idx + 1, None);
        if let Some(entry) = entries.get(idx.saturating_sub(1)) {
            if let Some(full) = logger.load_full(&entry.id) {
                print_webhook_detail(&full, idx);
            } else {
                output::warn("Webhook body data not found (may have been rotated)");
            }
        } else {
            output::warn(&format!("Webhook #{idx} not found"));
        }
        return Ok(());
    }

    // List mode
    let filter = build_filter(filter_provider.as_deref(), filter_status.as_deref());
    let entries = logger.read_recent(last, filter.as_ref());

    if entries.is_empty() {
        output::info("No webhooks captured yet. Start a tunnel with: lpm dev --tunnel");
        return Ok(());
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).unwrap_or_default()
        );
        return Ok(());
    }

    eprintln!("  Last {} webhooks:\n", entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let status_color = status_ansi_color(entry.status);
        let reset = "\x1b[0m";
        // Extract HH:MM:SS from ISO 8601 timestamp (safe: ts is always >=19 chars)
        let time = if entry.ts.len() >= 19 {
            &entry.ts[11..19]
        } else {
            &entry.ts
        };

        eprintln!(
            "  #{:<3} {} {:<35} {status_color}{}{reset}  {}ms  {}",
            i + 1,
            entry.method,
            entry.path,
            entry.status,
            entry.ms,
            time,
        );
        if !entry.summary.is_empty() {
            eprintln!("        {}", entry.summary.dimmed());
        }
    }
    eprintln!(
        "\n  {} webhooks. Use --detail N for full request/response.",
        entries.len()
    );

    Ok(())
}

// ── Webhook replay command ──────────────────────────────────────────

/// Replay a previously captured webhook against the local dev server.
///
/// Usage:
///   lpm tunnel replay 3          — replay webhook #3
///   lpm tunnel replay --last     — replay most recent webhook
///   lpm tunnel replay 3 --port 4000  — replay to a specific port
async fn run_replay(
    project_dir: &Path,
    args: &[String],
    default_port: u16,
) -> Result<(), LpmError> {
    let logger = lpm_tunnel::webhook_log::WebhookLogger::new(project_dir);
    let port = parse_flag_usize(args, "--port", "-p")
        .map(|p| p as u16)
        .unwrap_or(default_port);

    let is_last = args.contains(&"--last".to_string());
    let number = args
        .iter()
        .find(|a| a.parse::<usize>().is_ok())
        .and_then(|a| a.parse::<usize>().ok());

    // Only read as many entries as needed (1 for --last, n for index)
    let read_count = if is_last {
        1
    } else {
        number.unwrap_or_default()
    };
    let entries = logger.read_recent(read_count, None);

    let target_entry = if is_last {
        entries.first()
    } else if let Some(n) = number {
        entries.get(n.saturating_sub(1))
    } else {
        output::warn("Specify a webhook number or use --last");
        eprintln!("  Usage: lpm tunnel replay 3");
        eprintln!("         lpm tunnel replay --last");
        return Ok(());
    };

    let entry = target_entry.ok_or_else(|| LpmError::Tunnel("Webhook not found".into()))?;
    let webhook = logger
        .load_full(&entry.id)
        .ok_or_else(|| LpmError::Tunnel("Webhook body data not found".into()))?;

    let idx = number.unwrap_or(1);
    eprintln!("  Replaying #{}...", idx);
    eprintln!("  {} {} — {}", webhook.method, webhook.path, entry.summary);

    let replay_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|e| LpmError::Tunnel(format!("failed to create HTTP client: {e}")))?;
    let result = lpm_tunnel::webhook_replay::replay_webhook(&replay_client, &webhook, port).await?;

    let status_color = status_ansi_color(result.status);
    let ok_suffix = if result.status < 300 { " OK" } else { "" };
    eprintln!(
        "  -> {status_color}{}{ok_suffix}\x1b[0m ({}ms)",
        result.status, result.duration_ms
    );

    // Compare with original response to give actionable feedback
    if result.status < 400 && webhook.response_status >= 400 {
        output::success(&format!(
            "Fixed! Was {}, now {}.",
            webhook.response_status, result.status
        ));
    } else if result.status >= 400 && webhook.response_status >= 400 {
        eprintln!("  {} Still failing.", "x".red());
    }

    Ok(())
}

// ── Webhook log command ─────────────────────────────────────────────

/// Browse and manage the persistent webhook event log.
///
/// Flags:
///   --last N / -n N    — show last N entries (default: 50)
///   --filter <provider> — filter by provider
///   --status <code>    — filter by status class
///   --clear            — delete all webhook logs
async fn run_log(project_dir: &Path, args: &[String], json_output: bool) -> Result<(), LpmError> {
    let logger = lpm_tunnel::webhook_log::WebhookLogger::new(project_dir);

    if args.contains(&"--clear".to_string()) {
        logger
            .clear()
            .map_err(|e| LpmError::Tunnel(format!("failed to clear logs: {e}")))?;
        output::success("Webhook logs cleared");
        return Ok(());
    }

    let last = parse_flag_usize(args, "--last", "-n").unwrap_or(50);
    let filter_provider = parse_flag_str(args, "--filter");
    let filter_status = parse_flag_str(args, "--status");
    let filter = build_filter(filter_provider.as_deref(), filter_status.as_deref());

    let entries = logger.read_recent(last, filter.as_ref());

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).unwrap_or_default()
        );
        return Ok(());
    }

    if entries.is_empty() {
        output::info("No webhook events logged.");
        return Ok(());
    }

    eprintln!("  {} webhooks:\n", entries.len());
    for entry in &entries {
        let status_color = status_ansi_color(entry.status);
        let reset = "\x1b[0m";
        let time = if entry.ts.len() >= 19 {
            &entry.ts[11..19]
        } else {
            &entry.ts
        };

        eprintln!(
            "  {}  {} {:<35} {status_color}{}{reset}  {}ms  {}",
            time, entry.method, entry.path, entry.status, entry.ms, entry.summary,
        );
    }

    Ok(())
}

// ── Helper functions ────────────────────────────────────────────────

/// Parse a flag with a numeric value from the args list.
///
/// Supports both `--flag N` (two separate args) and `--flag=N` forms,
/// plus a short alias like `-n 5`.
fn parse_flag_usize(args: &[String], long: &str, short: &str) -> Option<usize> {
    for (i, arg) in args.iter().enumerate() {
        if (arg == long || arg == short) && i + 1 < args.len() {
            return args[i + 1].parse().ok();
        }
        // Handle --flag=value
        if let Some(val) = arg.strip_prefix(&format!("{long}=")) {
            return val.parse().ok();
        }
    }
    None
}

/// Parse a flag with a string value from the args list.
fn parse_flag_str(args: &[String], flag: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(val) = arg.strip_prefix(&format!("{flag}=")) {
            return Some(val.to_string());
        }
    }
    None
}

/// Build a webhook filter from optional provider and status strings.
fn build_filter(
    provider: Option<&str>,
    status: Option<&str>,
) -> Option<lpm_tunnel::webhook_log::WebhookFilter> {
    if provider.is_none() && status.is_none() {
        return None;
    }

    let status_filter = status.map(|s| {
        use lpm_tunnel::webhook_log::StatusFilter;
        match s {
            "2xx" => StatusFilter::Class(2),
            "3xx" => StatusFilter::Class(3),
            "4xx" => StatusFilter::Class(4),
            "5xx" => StatusFilter::Class(5),
            "error" | "err" => StatusFilter::Range(400, 599),
            _ => {
                // Try exact status code
                if let Ok(code) = s.parse::<u16>() {
                    StatusFilter::Exact(code)
                } else {
                    StatusFilter::Range(400, 599)
                }
            }
        }
    });

    // Provider filter is a case-insensitive string match in the logger
    let provider_filter = provider.map(|p| {
        // Capitalize first letter for consistent matching against Display output
        let mut s = p.to_lowercase();
        if let Some(first) = s.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        s
    });

    Some(lpm_tunnel::webhook_log::WebhookFilter {
        provider: provider_filter,
        status: status_filter,
    })
}

/// Print full detail for a single captured webhook (headers, body, response).
fn print_webhook_detail(webhook: &lpm_tunnel::webhook::CapturedWebhook, index: usize) {
    let status_color = status_ansi_color(webhook.response_status);
    let reset = "\x1b[0m";

    let provider_display = webhook
        .provider
        .map(|p| p.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    eprintln!();
    eprintln!("  {} Webhook #{index}", "━".repeat(40).dimmed());
    eprintln!();
    eprintln!(
        "  {} {} {}",
        "Request:".bold(),
        webhook.method,
        webhook.path,
    );
    eprintln!("  {} {}", "Provider:".dimmed(), provider_display);
    eprintln!(
        "  {} {status_color}{}{reset}",
        "Response:".bold(),
        webhook.response_status,
    );
    eprintln!("  {} {}ms", "Duration:".dimmed(), webhook.duration_ms);
    eprintln!("  {} {}", "Time:".dimmed(), webhook.timestamp);

    // Request headers
    if !webhook.request_headers.is_empty() {
        eprintln!();
        eprintln!("  {}", "Request Headers:".bold());
        for (key, value) in &webhook.request_headers {
            // Mask sensitive values (auth tokens, signatures)
            let lower_key = key.to_lowercase();
            let display_value =
                if lower_key.contains("authorization") || lower_key.contains("secret") {
                    format!("{}...", &value[..value.len().min(12)])
                } else {
                    value.clone()
                };
            eprintln!("    {}: {}", key.dimmed(), display_value);
        }
    }

    // Request body (truncated for large payloads)
    if !webhook.request_body.is_empty() {
        eprintln!();
        eprintln!("  {}", "Request Body:".bold());
        // Try interpreting as UTF-8 for display
        let body_str = String::from_utf8_lossy(&webhook.request_body);
        // Try pretty-printing JSON
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&webhook.request_body) {
            let pretty =
                serde_json::to_string_pretty(&json).unwrap_or_else(|_| body_str.to_string());
            let lines: Vec<&str> = pretty.lines().collect();
            let display_lines = if lines.len() > 40 {
                &lines[..40]
            } else {
                &lines
            };
            for line in display_lines {
                eprintln!("    {line}");
            }
            if lines.len() > 40 {
                eprintln!("    {} ({} more lines)", "...".dimmed(), lines.len() - 40);
            }
        } else if body_str.len() > 2000 {
            eprintln!("    {}", &body_str[..2000]);
            eprintln!(
                "    {} ({} bytes total)",
                "...".dimmed(),
                webhook.request_body.len()
            );
        } else {
            eprintln!("    {body_str}");
        }
    }

    // Signature diagnostic
    if let Some(ref diag) = webhook.signature_diagnostic {
        eprintln!();
        eprintln!("  {} {}", "Signature Issue:".yellow().bold(), diag);
    }

    eprintln!();
}

/// Validate a tunnel domain for claiming.
///
/// Valid format: `<subdomain>.<base>` where:
/// - subdomain is 3-32 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen
/// - base domain contains at least one dot (e.g., `lpm.fyi`, `lpm.llc`)
fn is_valid_tunnel_domain(domain: &str) -> bool {
    let Some((subdomain, base)) = domain.split_once('.') else {
        return false;
    };
    // Subdomain: 3-32 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen
    subdomain.len() >= 3
		&& subdomain.len() <= 32
		&& subdomain
			.chars()
			.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
		&& !subdomain.starts_with('-')
		&& !subdomain.ends_with('-')
		// Base domain: contains at least one dot (e.g., "lpm.fyi")
		&& base.contains('.')
}

/// Return ANSI color escape code for HTTP status codes.
fn status_ansi_color(status: u16) -> &'static str {
    if status >= 500 {
        "\x1b[31m" // red
    } else if status >= 400 {
        "\x1b[33m" // yellow
    } else {
        "\x1b[32m" // green
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tunnel domain validation ──

    #[test]
    fn valid_tunnel_domains() {
        assert!(is_valid_tunnel_domain("acme-api.lpm.llc"));
        assert!(is_valid_tunnel_domain("my-app.lpm.fyi"));
        assert!(is_valid_tunnel_domain("a1b2c3.lpm.fyi"));
    }

    #[test]
    fn invalid_tunnel_domain_uppercase() {
        assert!(!is_valid_tunnel_domain("ACME.lpm.llc"));
    }

    #[test]
    fn invalid_tunnel_domain_leading_hyphen() {
        assert!(!is_valid_tunnel_domain("-bad.lpm.llc"));
    }

    #[test]
    fn invalid_tunnel_domain_trailing_hyphen() {
        assert!(!is_valid_tunnel_domain("bad-.lpm.llc"));
    }

    #[test]
    fn invalid_tunnel_domain_too_short() {
        assert!(!is_valid_tunnel_domain("ab.lpm.llc"));
    }

    #[test]
    fn invalid_tunnel_domain_too_long() {
        let long = "a".repeat(33);
        assert!(!is_valid_tunnel_domain(&format!("{long}.lpm.llc")));
    }

    #[test]
    fn invalid_tunnel_domain_no_base() {
        assert!(!is_valid_tunnel_domain("no-base"));
    }

    #[test]
    fn invalid_tunnel_domain_single_level_base() {
        // "acme.com" — base is "com" which has no dot
        assert!(!is_valid_tunnel_domain("acme.com"));
    }

    // ── Flag parsing ──

    #[test]
    fn parse_flag_usize_long_form() {
        let args: Vec<String> = vec!["--last".into(), "25".into()];
        assert_eq!(parse_flag_usize(&args, "--last", "-n"), Some(25));
    }

    #[test]
    fn parse_flag_usize_short_form() {
        let args: Vec<String> = vec!["-n".into(), "10".into()];
        assert_eq!(parse_flag_usize(&args, "--last", "-n"), Some(10));
    }

    #[test]
    fn parse_flag_usize_equals_form() {
        let args: Vec<String> = vec!["--last=42".into()];
        assert_eq!(parse_flag_usize(&args, "--last", "-n"), Some(42));
    }

    #[test]
    fn parse_flag_usize_missing() {
        let args: Vec<String> = vec!["--filter".into(), "stripe".into()];
        assert_eq!(parse_flag_usize(&args, "--last", "-n"), None);
    }

    #[test]
    fn parse_flag_str_long_form() {
        let args: Vec<String> = vec!["--filter".into(), "stripe".into()];
        assert_eq!(parse_flag_str(&args, "--filter"), Some("stripe".into()));
    }

    #[test]
    fn parse_flag_str_equals_form() {
        let args: Vec<String> = vec!["--filter=github".into()];
        assert_eq!(parse_flag_str(&args, "--filter"), Some("github".into()));
    }

    #[test]
    fn parse_flag_str_missing() {
        let args: Vec<String> = vec!["--last".into(), "5".into()];
        assert_eq!(parse_flag_str(&args, "--filter"), None);
    }

    // ── Filter building ──

    #[test]
    fn build_filter_none_when_no_criteria() {
        assert!(build_filter(None, None).is_none());
    }

    #[test]
    fn build_filter_provider_only() {
        let filter = build_filter(Some("stripe"), None).unwrap();
        assert_eq!(filter.provider, Some("Stripe".to_string()));
        assert!(filter.status.is_none());
    }

    #[test]
    fn build_filter_status_class() {
        let filter = build_filter(None, Some("5xx")).unwrap();
        assert!(filter.provider.is_none());
        assert!(matches!(
            filter.status,
            Some(lpm_tunnel::webhook_log::StatusFilter::Class(5))
        ));
    }

    #[test]
    fn build_filter_status_exact() {
        let filter = build_filter(None, Some("404")).unwrap();
        assert!(matches!(
            filter.status,
            Some(lpm_tunnel::webhook_log::StatusFilter::Exact(404))
        ));
    }

    #[test]
    fn build_filter_status_error_alias() {
        let filter = build_filter(None, Some("error")).unwrap();
        assert!(matches!(
            filter.status,
            Some(lpm_tunnel::webhook_log::StatusFilter::Range(400, 599))
        ));
    }

    #[test]
    fn build_filter_provider_and_status() {
        let filter = build_filter(Some("github"), Some("2xx")).unwrap();
        assert_eq!(filter.provider, Some("Github".to_string()));
        assert!(matches!(
            filter.status,
            Some(lpm_tunnel::webhook_log::StatusFilter::Class(2))
        ));
    }
}
