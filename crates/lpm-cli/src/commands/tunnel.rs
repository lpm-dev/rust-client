use crate::install_ui;
use lpm_common::{LpmError, format_bytes};
use lpm_registry::RegistryClient;
use std::fmt::Display;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    inspect_port: Option<u16>,
    auto_ack: bool,
    session_name: Option<&str>,
    relay_url: Option<&str>,
) -> Result<(), LpmError> {
    // `Option<u16>` carries the user's intent through every layer: `None` →
    // auto-pick a free port via `bind(127.0.0.1:0)`, treat any failure as
    // non-fatal (the inspector is best-effort). `Some(n)` → bind exactly
    // that port and propagate `AddrInUse` as fatal — that's the documented
    // contract of `--inspect-port N`.
    match action {
        "claim" => run_claim(client, domain, org, json_output).await,
        "unclaim" | "release" => run_unclaim(client, domain, org, json_output).await,
        "list" | "ls" => run_list(client, org, json_output).await,
        "domains" => run_domains(client, json_output).await,
        "inspect" => {
            let local_args = local_action_args(domain, extra_args);
            // `lpm tunnel inspect --ui` opens the browser inspector on historical data
            if local_args.contains(&"--ui".to_string()) {
                return run_inspect_ui(project_dir, inspect_port).await;
            }
            run_inspect(project_dir, &local_args, json_output).await
        }
        "replay" => {
            let local_args = local_action_args(domain, extra_args);
            run_replay(project_dir, &local_args, port).await
        }
        "log" | "logs" => {
            let local_args = local_action_args(domain, extra_args);
            run_log(project_dir, &local_args, json_output).await
        }
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
                relay_url,
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
                    relay_url,
                )
                .await;
            }
            Err(LpmError::Tunnel(format!(
                "unknown action '{action}'. Available: claim, unclaim, list, domains, inspect, replay, log, or a port number"
            )))
        }
    }
}

fn local_action_args(second_positional: Option<&str>, extra_args: &[String]) -> Vec<String> {
    let mut normalized_args =
        Vec::with_capacity(extra_args.len() + usize::from(second_positional.is_some()));
    if let Some(value) = second_positional {
        normalized_args.push(value.to_string());
    }
    normalized_args.extend(extra_args.iter().cloned());
    normalized_args
}

/// Start a tunnel to expose a local port.
///
/// `inspect_port` carries the user's intent: `Some(n)` → bind that exact
/// port (fatal on `AddrInUse`); `None` → auto-pick a free ephemeral port
/// (best-effort, warns and continues without an inspector on the rare
/// failure).
#[allow(clippy::too_many_arguments)]
async fn run_start(
    token: Option<&str>,
    port: u16,
    domain: Option<&str>,
    json_output: bool,
    tunnel_auth: bool,
    no_inspect: bool,
    inspect_port: Option<u16>,
    auto_ack: bool,
    session_name: Option<&str>,
    relay_url: Option<&str>,
) -> Result<(), LpmError> {
    let token = token.ok_or_else(|| {
        LpmError::Tunnel("authentication required. Run `lpm login` first.".into())
    })?;

    // Reject bare subdomain without base domain (e.g., "acme" instead of "acme.lpm.llc")
    if let Some(d) = domain
        && !d.contains('.')
    {
        install_ui::warn("Missing base domain.");
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("Available:"),
            install_ui::yellow("lpm.fyi, lpm.llc")
        ));
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("Example:"),
            install_ui::yellow(&format!("lpm tunnel start --domain {d}.lpm.llc"))
        ));
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
                install_ui::warn_untrusted(&format!(
                    "inspector db failed: {e} — using in-memory only"
                ));
            }
            lpm_inspect::state::InspectorState::new(port)
        }
    };
    let inspector_handle = if no_inspect {
        None
    } else {
        // Strict-vs-best-effort split: an explicit `--inspect-port N` is a
        // user contract — fail loudly if we can't honor it. The default
        // (auto-pick) is best-effort — the tunnel itself is the load-bearing
        // surface, the inspector is a convenience.
        let (port_to_bind, strict) = match inspect_port {
            Some(n) => (n, true),
            None => (0, false),
        };
        match lpm_inspect::start(inspector_state.clone(), port_to_bind).await {
            Ok(handle) => Some(handle),
            Err(e) if strict => return Err(e),
            Err(e) => {
                if !json_output {
                    install_ui::warn_untrusted(&format!("inspector failed to start: {e}"));
                }
                None
            }
        }
    };

    // Create webhook capture channel — feeds both the inspector and the JSONL logger
    let (webhook_tx, mut webhook_rx) =
        tokio::sync::mpsc::unbounded_channel::<lpm_tunnel::webhook::CapturedWebhook>();

    // Create WebSocket capture channel
    let (ws_tx, mut ws_rx) =
        tokio::sync::mpsc::unbounded_channel::<lpm_tunnel::ws_capture::WsEvent>();

    // Spawn webhook consumer: pushes to inspector state for real-time SSE streaming
    let inspector_state_consumer = inspector_state.clone();
    let print_request_stream = !json_output;
    tokio::spawn(async move {
        while let Some(webhook) = webhook_rx.recv().await {
            if print_request_stream {
                print_tunnel_request(&webhook);
            }
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
        relay_url: relay_url.map_or_else(lpm_tunnel::resolve_relay_url, str::to_owned),
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
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Opening tunnel for {}",
            install_ui::yellow(&format!("localhost:{port}"))
        ));
    }

    let tunnel_auth_display = tunnel_auth_token.clone();
    let inspector_url = inspector_handle.as_ref().map(|h| h.url.clone());
    let control_inspector_url = inspector_url.clone();
    let inspector_state_for_connect = inspector_state.clone();
    let session_name_owned = session_name.map(|s| s.to_string());
    let latest_usage = Arc::new(Mutex::new(None::<lpm_tunnel::TunnelUsageMetadata>));
    let usage_for_connect = latest_usage.clone();
    let usage_for_notices = latest_usage.clone();

    let connect = lpm_tunnel::client::connect_with_usage(
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

            let usage = usage_for_connect
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "tunnel_url": session.tunnel_url,
                        "domain": session.domain,
                        "local_port": session.local_port,
                        "session_id": session.session_id,
                        "plan": session.plan,
                        "base_domain": session.base_domain,
                        "domain_kind": session.domain_kind,
                        "session_expires_at": session.session_expires_at,
                        "session_max_ms": session.session_max_ms,
                        "limits": session.limits,
                        "usage": usage,
                        "tunnel_auth": tunnel_auth_display,
                        "inspector_url": inspector_url,
                        "auto_ack": auto_ack,
                    })
                );
            } else {
                install_ui::phase("Tunnel ready");
                tunnel_detail("public URL", &session.tunnel_url);
                if let Some(ref url) = inspector_url {
                    tunnel_detail("inspector", url);
                }
                if let Some(plan) = session.plan.as_deref() {
                    tunnel_detail("plan", plan);
                }
                if let Some(expiry) = tunnel_session_expiry_summary(session) {
                    tunnel_detail("expires", expiry);
                }
                if let Some(limits) = tunnel_limit_summary(session.limits.as_ref()) {
                    tunnel_detail("limits", limits);
                }
                if let Some(usage) = tunnel_usage_summary(usage.as_ref()) {
                    tunnel_detail("usage", usage);
                }
                tunnel_detail("session", &session.session_id);
                tunnel_detail("local", format!("localhost:{}", session.local_port));
                if auto_ack {
                    tunnel_detail("auto-ack", "on (200 OK returned when server is down)");
                }
                if let Some(ref auth) = tunnel_auth_display {
                    tunnel_detail("auth", format!("X-Tunnel-Auth: {auth}"));
                    tunnel_detail(
                        "browser",
                        format!("{}?__tunnel_auth={auth}", session.tunnel_url),
                    );
                }
                tunnel_detail("domain", &session.domain);
                install_ui::detail("");
                install_ui::done("Listening for requests");
                if inspector_url.is_some() {
                    install_ui::detail_line(format_tunnel_footer(true));
                } else {
                    install_ui::detail_line(format_tunnel_footer(false));
                }
            }
        },
        |msg| {
            if !json_output {
                install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(msg));
            }
        },
        move |usage, initial| {
            *usage_for_notices
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(usage.clone());
            if !initial
                && !json_output
                && let Some(summary) = tunnel_usage_summary(Some(usage))
            {
                install_ui::warn_untrusted(&format!("Tunnel usage: {summary}"));
            }
        },
    );

    if json_output {
        connect.await?;
    } else {
        tokio::pin!(connect);
        tokio::select! {
            result = &mut connect => result?,
            result = wait_for_tunnel_controls(control_inspector_url) => result?,
        }
    }

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
        install_ui::done_line(crate::install_ui::terminal_line!(
            "claimed {}",
            install_ui::url(url)
        ));
        if let Some(org_name) = org {
            tunnel_detail("org", org_name);
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
        install_ui::done_line(crate::install_ui::terminal_line!(
            "released {}",
            install_ui::yellow(domain)
        ));
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

    let heading = org.map_or_else(
        || "Tunnel Domains".to_string(),
        |org_name| format!("Tunnel Domains · {}", install_ui::cyan(org_name)),
    );
    install_ui::phase_untrusted(&heading);

    tunnel_detail("used", format!("{used} of {limit}"));

    match domains {
        Some(doms) if !doms.is_empty() => {
            for d in doms {
                let _domain = d["domain"].as_str().unwrap_or("?");
                let url = d["url"].as_str().unwrap_or("?");
                let base = d["baseDomain"].as_str().unwrap_or("?");
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "    {} {}",
                    install_ui::url(url),
                    install_ui::dim(&format!("({base})"))
                ));
            }
        }
        _ => {
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "    {}",
                install_ui::dim("No domains claimed")
            ));
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim("Claim one with:"),
                install_ui::yellow("lpm tunnel claim <name>.lpm.llc")
            ));
        }
    }

    Ok(())
}

/// List available base domains.
async fn run_domains(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
    let result = client.tunnel_available_domains().await?;

    if json_output {
        println!("{result}");
        return Ok(());
    }

    install_ui::phase("Available tunnel domains");

    if let Some(domains) = result["domains"].as_array() {
        for d in domains {
            let domain = d["domain"].as_str().unwrap_or("?");
            let plan = d["planRequired"].as_str().unwrap_or("?");
            let plan_badge = if plan == "free" {
                install_ui::status_ok("free")
            } else {
                install_ui::cyan("pro")
            };
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "    {:<15} {}",
                install_ui::yellow(domain),
                plan_badge
            ));
        }
    }

    Ok(())
}

// ── Inspector UI (standalone, no tunnel) ────────────────────────────

/// Launch the browser inspector UI on historical data (read-only, no tunnel).
///
/// Usage: `lpm tunnel inspect --ui`
///
/// `inspect_port = None` auto-picks a free ephemeral port (default, race-free
/// against any other local service); `Some(n)` binds that exact port and
/// fails loudly on `AddrInUse`.
async fn run_inspect_ui(_project_dir: &Path, inspect_port: Option<u16>) -> Result<(), LpmError> {
    let state = lpm_inspect::state::InspectorState::new(0);
    let handle = lpm_inspect::start(state, inspect_port.unwrap_or(0)).await?;

    install_ui::done_line(crate::install_ui::terminal_line!(
        "Inspector: {}",
        install_ui::url(&handle.url)
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {}",
        install_ui::dim("Press Ctrl+C to stop")
    ));

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
            install_ui::warn("--detail uses 1-based indexing. Use --detail 1 for the first entry.");
            return Ok(());
        }
        // Detail mode: show full webhook by 1-based index
        let entries = logger.read_recent(idx + 1, None);
        if let Some(entry) = entries.get(idx.saturating_sub(1)) {
            if let Some(full) = logger.load_full(&entry.id) {
                print_webhook_detail(&full, idx);
            } else {
                install_ui::warn("Webhook body data not found (may have been rotated)");
            }
        } else {
            install_ui::warn_untrusted(&format!("Webhook #{idx} not found"));
        }
        return Ok(());
    }

    // List mode
    let filter = build_filter(filter_provider.as_deref(), filter_status.as_deref());
    let entries = logger.read_recent(last, filter.as_ref());

    if entries.is_empty() {
        install_ui::phase("No webhooks captured yet. Start a tunnel with: lpm dev --tunnel");
        return Ok(());
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).unwrap_or_default()
        );
        return Ok(());
    }

    install_ui::phase_untrusted(&format!("Last {} webhooks", entries.len()));
    for (i, entry) in entries.iter().enumerate() {
        install_ui::detail_line(format_tunnel_log_entry(Some(i + 1), entry, false));
        if !entry.summary.is_empty() {
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "        {}",
                install_ui::dim(&entry.summary)
            ));
        }
    }
    install_ui::detail("");
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {}",
        install_ui::status_ok(&entries.len().to_string()),
        install_ui::dim("webhooks. Use --detail N for full request/response.")
    ));

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
    let port = parse_flag_usize(args, "--port", "-p").map_or(default_port, |p| p as u16);

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
        install_ui::warn("Specify a webhook number or use --last");
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("Usage:"),
            install_ui::yellow("lpm tunnel replay 3")
        ));
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "         {}",
            install_ui::yellow("lpm tunnel replay --last")
        ));
        return Ok(());
    };

    let entry = target_entry.ok_or_else(|| LpmError::Tunnel("Webhook not found".into()))?;
    let webhook = logger
        .load_full(&entry.id)
        .ok_or_else(|| LpmError::Tunnel("Webhook body data not found".into()))?;

    let idx = number.unwrap_or(1);
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Replaying #{}",
        install_ui::yellow(&idx.to_string())
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {} — {}",
        style_http_method_fragment(&webhook.method),
        install_ui::cyan(&webhook.path),
        lpm_common::sanitize_for_terminal(&entry.summary)
    ));

    let replay_client = lpm_http::client_builder()
        .timeout(std::time::Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|e| LpmError::Tunnel(format!("failed to create HTTP client: {e}")))?;
    let result = lpm_tunnel::webhook_replay::replay_webhook(&replay_client, &webhook, port).await?;

    let status = style_http_status_fragment(result.status);
    let ok_suffix = if result.status < 300 { " OK" } else { "" };
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {}{} {}",
        install_ui::dim("->"),
        status,
        ok_suffix,
        install_ui::dim(&format!("({}ms)", result.duration_ms))
    ));

    // Compare with original response to give actionable feedback
    if result.status < 400 && webhook.response_status >= 400 {
        install_ui::done_untrusted(&format!(
            "Fixed! Was {}, now {}.",
            webhook.response_status, result.status
        ));
    } else if result.status >= 400 && webhook.response_status >= 400 {
        install_ui::failed("Still failing.");
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
        install_ui::done("Webhook logs cleared");
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
        install_ui::phase("No webhook events logged.");
        return Ok(());
    }

    install_ui::phase_untrusted(&format!("{} webhooks", entries.len()));
    for entry in &entries {
        install_ui::detail_line(format_tunnel_log_entry(None, entry, true));
    }

    Ok(())
}

// ── Helper functions ────────────────────────────────────────────────

fn tunnel_detail(label: &'static str, value: impl Display) {
    install_ui::detail_line(format_tunnel_detail(label, value));
}

pub(crate) fn tunnel_session_expiry_summary(session: &lpm_tunnel::TunnelSession) -> Option<String> {
    session
        .session_expires_at
        .map(|expires_at_ms| format_tunnel_expiry_at(expires_at_ms, current_time_millis()))
}

pub(crate) fn tunnel_limit_summary(
    limits: Option<&lpm_tunnel::TunnelLimitMetadata>,
) -> Option<String> {
    let limits = limits?;
    let mut parts = Vec::with_capacity(5);

    if let Some(max_concurrent) = limits.max_concurrent {
        parts.push(format!(
            "{max_concurrent} {}",
            plural(max_concurrent, "tunnel")
        ));
    }

    if let Some(rate) = limits.request_rate_limit_per_minute {
        if rate == 0 {
            parts.push("requests unlimited".to_string());
        } else {
            parts.push(format!("{rate}/min"));
        }
    }

    if let Some(max_body_bytes) = limits.max_request_body_bytes {
        parts.push(format!("{} body", format_bytes(max_body_bytes)));
    }

    if let Some(max_custom_domains) = limits.max_custom_domains {
        parts.push(format!(
            "{max_custom_domains} custom {}",
            plural(max_custom_domains, "domain")
        ));
    }

    if let Some(per_ip_rate) = limits.per_ip_rate_limit_per_minute {
        if per_ip_rate == 0 {
            parts.push("per-IP unlimited".to_string());
        } else {
            parts.push(format!("{per_ip_rate}/min/IP"));
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" · "))
    }
}

pub(crate) fn tunnel_usage_summary(
    usage: Option<&lpm_tunnel::TunnelUsageMetadata>,
) -> Option<String> {
    let usage = usage?;
    let accepted = usage.accepted_requests?;
    let included = usage.included_requests?;
    let mut summary = format!("{accepted} / {included} requests");
    if usage.overage_requests.unwrap_or_default() > 0 {
        summary.push_str(&format!(
            " · {} overage",
            usage.overage_requests.unwrap_or_default()
        ));
    }
    summary.push_str(if usage.overage_enabled.unwrap_or(false) {
        " · overage on"
    } else {
        " · hard stop"
    });
    Some(summary)
}

fn format_tunnel_detail(label: &'static str, value: impl Display) -> install_ui::TerminalLine {
    let value = style_tunnel_detail_value(label, &value.to_string());
    crate::install_ui::terminal_line!("    {} {}", install_ui::dim(&format!("{label:<11}")), value)
}

fn style_tunnel_detail_value(label: &str, value: &str) -> install_ui::TerminalFragment {
    match label {
        "public URL" | "inspector" | "browser" => install_ui::url(value),
        "local" => install_ui::yellow(value),
        _ => install_ui::field(value),
    }
}

fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn format_tunnel_expiry_at(expires_at_ms: u64, now_ms: u64) -> String {
    if expires_at_ms <= now_ms {
        return "now".to_string();
    }
    format!(
        "in {}",
        format_duration_compact_ms(expires_at_ms.saturating_sub(now_ms))
    )
}

fn format_duration_compact_ms(ms: u64) -> String {
    let seconds = ms.saturating_add(999) / 1000;
    if seconds >= 3600 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        if minutes > 0 {
            format!("{hours}h {minutes}m")
        } else {
            format!("{hours}h")
        }
    } else if seconds >= 60 {
        let minutes = seconds / 60;
        let remaining_seconds = seconds % 60;
        if remaining_seconds > 0 {
            format!("{minutes}m {remaining_seconds}s")
        } else {
            format!("{minutes}m")
        }
    } else {
        format!("{seconds}s")
    }
}

fn plural(count: u64, singular: &str) -> String {
    if count == 1 {
        singular.to_string()
    } else {
        format!("{singular}s")
    }
}

fn format_tunnel_footer(has_inspector: bool) -> install_ui::TerminalLine {
    if has_inspector {
        crate::install_ui::terminal_line!(
            "  press {} to open inspector, {} to quit",
            install_ui::yellow("o"),
            install_ui::yellow("q")
        )
    } else {
        crate::install_ui::terminal_line!("  press {} to quit", install_ui::yellow("q"))
    }
}

async fn wait_for_tunnel_controls(inspector_url: Option<String>) -> Result<(), LpmError> {
    if !std::io::stdin().is_terminal() {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| LpmError::Tunnel(format!("signal error: {e}")))?;
        return Ok(());
    }

    let _raw_mode = TunnelRawModeGuard::enter()?;
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|e| LpmError::Tunnel(format!("signal error: {e}")))?;
                return Ok(());
            }
            control = read_tunnel_control() => {
                match control? {
                    TunnelControl::Quit => return Ok(()),
                    TunnelControl::OpenInspector => {
                        if let Some(url) = inspector_url.as_deref()
                            && let Err(e) = open::that(url)
                        {
                            install_ui::warn_untrusted(&format!("failed to open inspector: {e}"));
                        }
                    }
                    TunnelControl::Ignore => {}
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelControl {
    Quit,
    OpenInspector,
    Ignore,
}

struct TunnelRawModeGuard;

impl TunnelRawModeGuard {
    fn enter() -> Result<Self, LpmError> {
        crossterm::terminal::enable_raw_mode()
            .map_err(|e| LpmError::Tunnel(format!("terminal input error: {e}")))?;
        Ok(Self)
    }
}

impl Drop for TunnelRawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

async fn read_tunnel_control() -> Result<TunnelControl, LpmError> {
    tokio::task::spawn_blocking(|| {
        if !crossterm::event::poll(Duration::from_millis(100))
            .map_err(|e| LpmError::Tunnel(format!("terminal input error: {e}")))?
        {
            return Ok(TunnelControl::Ignore);
        }

        match crossterm::event::read()
            .map_err(|e| LpmError::Tunnel(format!("terminal input error: {e}")))?
        {
            crossterm::event::Event::Key(event) => Ok(tunnel_control_from_key(event)),
            _ => Ok(TunnelControl::Ignore),
        }
    })
    .await
    .map_err(|e| LpmError::Tunnel(format!("terminal input task failed: {e}")))?
}

fn tunnel_control_from_key(event: crossterm::event::KeyEvent) -> TunnelControl {
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

    if event.kind != KeyEventKind::Press {
        return TunnelControl::Ignore;
    }

    match event.code {
        KeyCode::Char('q' | 'Q') => TunnelControl::Quit,
        KeyCode::Char('c' | 'C') if event.modifiers.contains(KeyModifiers::CONTROL) => {
            TunnelControl::Quit
        }
        KeyCode::Char('o' | 'O') => TunnelControl::OpenInspector,
        _ => TunnelControl::Ignore,
    }
}

fn print_tunnel_request(webhook: &lpm_tunnel::webhook::CapturedWebhook) {
    install_ui::detail_line(format_tunnel_request(webhook));
}

fn format_tunnel_request(
    webhook: &lpm_tunnel::webhook::CapturedWebhook,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "  {} {} {} {} {}",
        install_ui::dim("→"),
        style_http_method_fragment(&webhook.method),
        install_ui::cyan(&webhook.path),
        style_http_status_fragment(webhook.response_status),
        install_ui::dim(&format!("{}ms", webhook.duration_ms)),
    )
}

fn format_tunnel_log_entry(
    index: Option<usize>,
    entry: &lpm_tunnel::webhook_log::WebhookLogEntry,
    include_summary: bool,
) -> install_ui::TerminalLine {
    let time = tunnel_entry_time(&entry.ts);
    let prefix = index.map_or_else(
        || crate::install_ui::terminal_line!("  {} ", install_ui::dim(time)),
        |idx| crate::install_ui::terminal_line!("  #{:<3}", idx),
    );
    let summary = if include_summary {
        crate::install_ui::terminal_line!("  {}", lpm_common::sanitize_for_terminal(&entry.summary))
    } else {
        install_ui::TerminalLine::new("")
    };
    crate::install_ui::terminal_line!(
        "{} {} {:<35} {}  {}{}",
        prefix,
        style_http_method_fragment(&entry.method),
        install_ui::cyan(&entry.path),
        style_http_status_fragment(entry.status),
        install_ui::dim(&format!("{}ms", entry.ms)),
        summary
    )
}

fn tunnel_entry_time(ts: &str) -> &str {
    if ts.len() >= 19 { &ts[11..19] } else { ts }
}

fn style_http_method_fragment(method: &str) -> install_ui::TerminalFragment {
    match method {
        "GET" => install_ui::url(method),
        "POST" => install_ui::yellow(method),
        _ => install_ui::field(method),
    }
}

fn format_untrusted_block_line(indent: &str, line: &str) -> String {
    format!("{indent}{}", lpm_common::sanitize_terminal_inline(line))
}

fn style_http_status(status: u16) -> String {
    style_http_status_fragment(status).to_string()
}

fn style_http_status_fragment(status: u16) -> install_ui::TerminalFragment {
    let status = status.to_string();
    match status.as_bytes().first() {
        Some(b'2') | Some(b'3') => install_ui::status_ok(&status),
        Some(b'4') | Some(b'5') => install_ui::red(&status),
        _ => install_ui::yellow(&status),
    }
}

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
    let status = style_http_status(webhook.response_status);

    let provider_display = webhook
        .provider
        .map_or_else(|| "unknown".to_string(), |p| p.to_string());

    install_ui::detail("");
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Webhook #{}",
        install_ui::yellow(&index.to_string())
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {} {}",
        install_ui::section("Request:"),
        style_http_method_fragment(&webhook.method),
        install_ui::cyan(&webhook.path),
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim("Provider:"),
        install_ui::yellow(&provider_display)
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {}",
        install_ui::section("Response:"),
        status,
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim("Duration:"),
        install_ui::dim(&format!("{}ms", webhook.duration_ms))
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim("Time:"),
        install_ui::dim(&webhook.timestamp.to_string())
    ));

    // Request headers
    if !webhook.request_headers.is_empty() {
        install_ui::detail("");
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {}",
            install_ui::section("Request Headers:")
        ));
        for (key, value) in &webhook.request_headers {
            // Mask sensitive values (auth tokens, signatures)
            let lower_key = key.to_lowercase();
            let display_value =
                if lower_key.contains("authorization") || lower_key.contains("secret") {
                    format!("{}...", &value[..value.len().min(12)])
                } else {
                    value.clone()
                };
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "    {}: {}",
                install_ui::dim(key),
                lpm_common::sanitize_for_terminal(&display_value)
            ));
        }
    }

    // Request body (truncated for large payloads)
    if !webhook.request_body.is_empty() {
        install_ui::detail("");
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {}",
            install_ui::section("Request Body:")
        ));
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
                install_ui::detail_untrusted(&format_untrusted_block_line("    ", line));
            }
            if lines.len() > 40 {
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "    {}",
                    install_ui::dim(&format!("... ({} more lines)", lines.len() - 40))
                ));
            }
        } else if body_str.len() > 2000 {
            let preview_end = body_str
                .char_indices()
                .nth(2000)
                .map_or(body_str.len(), |(index, _)| index);
            for line in body_str[..preview_end].lines() {
                install_ui::detail_untrusted(&format_untrusted_block_line("    ", line));
            }
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "    {}",
                install_ui::dim(&format!("... ({} bytes total)", webhook.request_body.len()))
            ));
        } else {
            for line in body_str.lines() {
                install_ui::detail_untrusted(&format_untrusted_block_line("    ", line));
            }
        }
    }

    // Signature diagnostic
    if let Some(ref diag) = webhook.signature_diagnostic {
        install_ui::detail("");
        install_ui::warn_untrusted(&format!(
            "Signature issue: {}",
            lpm_common::sanitize_terminal_inline(diag)
        ));
    }

    install_ui::detail("");
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
    fn tunnel_request_line_renders_method_path_status_and_duration() {
        lpm_common::color::set_enabled(false);
        let webhook = lpm_tunnel::webhook::CapturedWebhook {
            id: "req_1".to_string(),
            timestamp: "2026-05-31T00:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/hooks/stripe".to_string(),
            request_headers: std::collections::HashMap::new(),
            request_body: Vec::new(),
            response_status: 201,
            response_headers: std::collections::HashMap::new(),
            response_body: Vec::new(),
            duration_ms: 42,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: false,
        };

        assert_eq!(
            format_tunnel_request(&webhook).to_string(),
            "  → POST /hooks/stripe 201 42ms"
        );
    }

    #[test]
    fn tunnel_status_formatter_plain_content_is_stable() {
        assert_eq!(
            console::strip_ansi_codes(&style_http_status(200)).into_owned(),
            "200"
        );
        assert_eq!(
            console::strip_ansi_codes(&style_http_status(404)).into_owned(),
            "404"
        );
        assert_eq!(
            console::strip_ansi_codes(&style_http_status(500)).into_owned(),
            "500"
        );
    }

    #[test]
    fn tunnel_log_entry_formats_as_slim_detail_row() {
        lpm_common::color::set_enabled(false);
        let entry = lpm_tunnel::webhook_log::WebhookLogEntry {
            id: "wh_1".to_string(),
            ts: "2026-05-31T12:34:56Z".to_string(),
            method: "POST".to_string(),
            path: "/hooks".to_string(),
            status: 500,
            ms: 37,
            provider: Some("Stripe".to_string()),
            summary: "Stripe: payment".to_string(),
            req_size: 10,
            res_size: 20,
        };

        assert_eq!(
            console::strip_ansi_codes(format_tunnel_log_entry(Some(2), &entry, true).as_ref())
                .into_owned(),
            "  #2   POST /hooks                              500  37ms  Stripe: payment"
        );
    }

    #[test]
    fn tunnel_footer_names_open_and_quit_keys() {
        lpm_common::color::set_enabled(false);

        assert_eq!(
            format_tunnel_footer(true).to_string(),
            "  press o to open inspector, q to quit"
        );
        assert_eq!(format_tunnel_footer(false).to_string(), "  press q to quit");
    }

    #[test]
    fn tunnel_controls_map_keys_to_actions() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        assert_eq!(
            tunnel_control_from_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)),
            TunnelControl::Quit
        );
        assert_eq!(
            tunnel_control_from_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE)),
            TunnelControl::OpenInspector
        );
        assert_eq!(
            tunnel_control_from_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            TunnelControl::Quit
        );
        assert_eq!(
            tunnel_control_from_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            TunnelControl::Ignore
        );
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

    #[test]
    fn tunnel_detail_rows_match_slim_ready_block_spacing() {
        lpm_common::color::set_enabled(false);

        assert_eq!(
            format_tunnel_detail("public URL", "https://acme-api.lpm.fyi").to_string(),
            "    public URL  https://acme-api.lpm.fyi"
        );
        assert_eq!(
            format_tunnel_detail("inspector", "http://127.0.0.1:4512").to_string(),
            "    inspector   http://127.0.0.1:4512"
        );
        assert_eq!(
            format_tunnel_detail("session", "stripe-test").to_string(),
            "    session     stripe-test"
        );
    }

    #[test]
    fn tunnel_fields_and_multiline_blocks_cannot_inject_terminal_controls() {
        lpm_common::color::set_enabled(false);
        let malicious = "safe\nforged\rrewritten\u{8}\u{1b}[2J\u{1b}]52;c;AAAA\u{7}end";

        assert_eq!(
            format_tunnel_detail("session", malicious).to_string(),
            "    session     safe?forged?rewritten?end"
        );
        assert_eq!(
            format_untrusted_block_line("    ", malicious),
            "    safe?forged?rewritten?end"
        );
        assert_eq!(
            style_http_method_fragment(malicious).to_string(),
            "safe?forged?rewritten?end"
        );
    }

    #[test]
    fn tunnel_limit_summary_includes_account_and_relay_caps() {
        let limits = lpm_tunnel::TunnelLimitMetadata {
            max_concurrent: Some(1),
            request_rate_limit_per_minute: Some(4_000),
            per_ip_rate_limit_per_minute: Some(600),
            max_request_body_bytes: Some(10 * 1024 * 1024),
            max_custom_domains: Some(0),
            tunnel_auth_available: Some(false),
        };

        assert_eq!(
            tunnel_limit_summary(Some(&limits)).as_deref(),
            Some("1 tunnel · 4000/min · 10.0 MB body · 0 custom domains · 600/min/IP")
        );
    }

    #[test]
    fn tunnel_limit_summary_displays_unlimited_request_rate() {
        let limits = lpm_tunnel::TunnelLimitMetadata {
            max_concurrent: Some(3),
            request_rate_limit_per_minute: Some(20_000),
            per_ip_rate_limit_per_minute: Some(600),
            max_request_body_bytes: Some(100 * 1024 * 1024),
            max_custom_domains: Some(3),
            tunnel_auth_available: Some(true),
        };

        assert_eq!(
            tunnel_limit_summary(Some(&limits)).as_deref(),
            Some("3 tunnels · 20000/min · 100.0 MB body · 3 custom domains · 600/min/IP")
        );
    }

    #[test]
    fn tunnel_usage_summary_shows_hard_stop_and_overage() {
        let usage = lpm_tunnel::TunnelUsageMetadata {
            accepted_requests: Some(100_250),
            included_requests: Some(100_000),
            overage_requests: Some(250),
            overage_enabled: Some(true),
            ..Default::default()
        };
        assert_eq!(
            tunnel_usage_summary(Some(&usage)).as_deref(),
            Some("100250 / 100000 requests · 250 overage · overage on")
        );
    }

    #[test]
    fn tunnel_expiry_formatter_shows_whole_hours() {
        assert_eq!(format_tunnel_expiry_at(3_600_000, 0), "in 1h");
    }

    #[test]
    fn tunnel_expiry_formatter_shows_remaining_minutes() {
        assert_eq!(format_tunnel_expiry_at(3_660_000, 0), "in 1h 1m");
    }

    #[test]
    fn tunnel_expiry_formatter_marks_past_expiry_as_now() {
        assert_eq!(format_tunnel_expiry_at(5_000, 10_000), "now");
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

    #[test]
    fn local_action_args_prepends_second_positional_before_trailing_args() {
        let args: Vec<String> = vec!["--port".into(), "4100".into()];
        assert_eq!(
            local_action_args(Some("3"), &args),
            vec!["3".to_string(), "--port".to_string(), "4100".to_string()]
        );
    }

    #[test]
    fn local_action_args_preserves_trailing_args_when_second_positional_missing() {
        let args: Vec<String> = vec!["--last".into(), "5".into()];
        assert_eq!(local_action_args(None, &args), args);
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
