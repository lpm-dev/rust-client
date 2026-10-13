use crate::install_ui;
use lpm_common::{LpmError, format_bytes};
use lpm_registry::RegistryClient;
use std::fmt::Display;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
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
    port: Option<u16>,
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
        "claim" => {
            reject_local_options(action, extra_args)?;
            run_claim(client, domain, org, json_output).await
        }
        "unclaim" | "release" => {
            reject_local_options(action, extra_args)?;
            run_unclaim(client, domain, org, json_output).await
        }
        "list" | "ls" => {
            reject_local_options(action, extra_args)?;
            run_list(client, org, json_output).await
        }
        "domains" => {
            reject_local_options(action, extra_args)?;
            run_domains(client, json_output).await
        }
        "inspect" => {
            let local_args = normalized_local_action_args(domain, extra_args);
            validate_local_action_args(action, &local_args)?;
            let ui = local_args.iter().any(|arg| arg == "--ui");
            if inspect_port.is_some() && !ui {
                return Err(LpmError::Tunnel(
                    "`--inspect-port` is not valid without `inspect --ui`".into(),
                ));
            }
            if ui && json_output {
                return Err(LpmError::Tunnel(
                    "`--json` is not valid with `inspect --ui`".into(),
                ));
            }
            // `lpm tunnel inspect --ui` opens the browser inspector on historical data
            if local_args.contains(&"--ui".to_string()) {
                return run_inspect_ui(project_dir, inspect_port).await;
            }
            run_inspect(project_dir, &local_args, json_output).await
        }
        "replay" => {
            let local_args = normalized_local_action_args(domain, extra_args);
            validate_local_action_args(action, &local_args)?;
            run_replay(project_dir, &local_args, port, json_output).await
        }
        "log" | "logs" => {
            let local_args = normalized_local_action_args(domain, extra_args);
            validate_local_action_args(action, &local_args)?;
            run_log(project_dir, &local_args, json_output).await
        }
        "start" | "" => {
            reject_local_options("start", extra_args)?;
            let local_target = resolve_local_target(port)?;
            let effective_relay_url =
                relay_url.map_or_else(lpm_tunnel::resolve_relay_url, str::to_owned);
            let token_provider =
                crate::tunnel_session_auth::refresh_backed_provider(client, &effective_relay_url)?;
            run_start(
                token,
                local_target,
                domain,
                json_output,
                project_dir,
                tunnel_auth,
                no_inspect,
                inspect_port,
                auto_ack,
                session_name,
                Some(&effective_relay_url),
                token_provider,
                !json_output,
                None,
            )
            .await
        }
        _ => {
            // If action looks like a port number, treat as start
            if let Ok(p) = action.parse::<u16>() {
                reject_local_options("start", extra_args)?;
                let local_target = resolve_local_target(Some(p))?;
                let effective_relay_url =
                    relay_url.map_or_else(lpm_tunnel::resolve_relay_url, str::to_owned);
                let token_provider = crate::tunnel_session_auth::refresh_backed_provider(
                    client,
                    &effective_relay_url,
                )?;
                return run_start(
                    token,
                    local_target,
                    domain,
                    json_output,
                    project_dir,
                    tunnel_auth,
                    no_inspect,
                    inspect_port,
                    auto_ack,
                    session_name,
                    Some(&effective_relay_url),
                    token_provider,
                    !json_output,
                    None,
                )
                .await;
            }
            Err(LpmError::Tunnel(format!(
                "unknown action '{action}'. Available: claim, unclaim, list, domains, inspect, replay, log, or a port number"
            )))
        }
    }
}

fn resolve_local_target(port: Option<u16>) -> Result<lpm_common::LocalTarget, LpmError> {
    if let Some(port) = port {
        if port == 0 {
            return Err(LpmError::Tunnel(
                "port must be between 1 and 65535".to_string(),
            ));
        }
        return Ok(lpm_common::LocalTarget::loopback(
            lpm_common::LocalScheme::Http,
            port,
        ));
    }
    let sessions = lpm_runner::dev_session::discover_active_sessions()?;
    select_active_target(&sessions)
}

fn select_active_target(
    sessions: &[lpm_runner::dev_session::ActiveDevSession],
) -> Result<lpm_common::LocalTarget, LpmError> {
    match sessions {
        [session] => Ok(session.target.clone()),
        [] => Err(LpmError::Tunnel(
            "no active `lpm dev` endpoint found; pass a port, for example `lpm tunnel 5173`"
                .to_string(),
        )),
        _ => Err(LpmError::Tunnel(format!(
            "multiple active `lpm dev` endpoints found ({}); pass the intended port explicitly",
            sessions
                .iter()
                .map(|session| session.target.port.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
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

fn normalized_local_action_args(
    second_positional: Option<&str>,
    extra_args: &[String],
) -> Vec<String> {
    let args = local_action_args(second_positional, extra_args);
    let mut normalized = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let raw = &args[index];
        let (flag, inline) = raw
            .split_once('=')
            .map_or((raw.as_str(), None), |(flag, value)| (flag, Some(value)));
        let flag = match flag {
            "-n" => "--last",
            "-d" => "--detail",
            "-p" => "--port",
            other => other,
        };
        if matches!(
            flag,
            "--last" | "--detail" | "--port" | "--filter" | "--status"
        ) {
            if let Some(value) = inline {
                normalized.push(format!("{flag}={value}"));
            } else if let Some(value) = args.get(index + 1).filter(|value| !value.starts_with('-'))
            {
                normalized.push(format!("{flag}={value}"));
                index += 1;
            } else {
                normalized.push(flag.to_string());
            }
        } else {
            normalized.push(raw.clone());
        }
        index += 1;
    }
    normalized
}

fn reject_local_options(action: &str, args: &[String]) -> Result<(), LpmError> {
    if args.is_empty() {
        return Ok(());
    }
    Err(LpmError::Tunnel(format!(
        "capture-history options are not valid with `lpm tunnel {action}`"
    )))
}

fn validate_local_action_args(action: &str, args: &[String]) -> Result<(), LpmError> {
    let mut index = 0;
    let mut replay_index_seen = false;

    while index < args.len() {
        let raw = &args[index];
        if !raw.starts_with('-') {
            if action == "replay"
                && !replay_index_seen
                && raw.parse::<usize>().is_ok_and(|value| value > 0)
            {
                replay_index_seen = true;
                index += 1;
                continue;
            }
            return Err(LpmError::Tunnel(format!(
                "unexpected positional argument for `lpm tunnel {action}`"
            )));
        }

        let (spelling, inline_value) = raw
            .split_once('=')
            .map_or((raw.as_str(), None), |(flag, value)| (flag, Some(value)));
        let safe_spelling = lpm_common::sanitize_terminal_inline(spelling);
        let flag = match spelling {
            "-n" => "--last",
            "-d" => "--detail",
            "-p" => "--port",
            other => other,
        };
        let allowed = match action {
            "inspect" => matches!(
                flag,
                "--ui" | "--last" | "--detail" | "--filter" | "--status"
            ),
            "replay" => matches!(flag, "--last" | "--port"),
            "log" | "logs" => matches!(flag, "--last" | "--filter" | "--status" | "--clear"),
            _ => false,
        };
        if !allowed {
            return Err(LpmError::Tunnel(format!(
                "option `{safe_spelling}` is not valid with `lpm tunnel {action}`"
            )));
        }

        if matches!(flag, "--ui" | "--clear") {
            if inline_value.is_some() {
                return Err(LpmError::Tunnel(format!(
                    "option `{safe_spelling}` does not take a value"
                )));
            }
            index += 1;
            continue;
        }

        if flag == "--last" && action == "replay" {
            if inline_value.is_some() {
                return Err(LpmError::Tunnel(
                    "`lpm tunnel replay --last` does not take a value".to_string(),
                ));
            }
            index += 1;
            continue;
        }

        let value = match inline_value {
            Some(value) if !value.is_empty() => value,
            Some(_) => {
                return Err(LpmError::Tunnel(format!(
                    "option `{safe_spelling}` requires a value"
                )));
            }
            None => args
                .get(index + 1)
                .filter(|value| !value.starts_with('-'))
                .map(String::as_str)
                .ok_or_else(|| {
                    LpmError::Tunnel(format!("option `{safe_spelling}` requires a value"))
                })?,
        };

        match flag {
            "--last" | "--detail" => {
                if !value.parse::<usize>().is_ok_and(|value| value > 0) {
                    return Err(LpmError::Tunnel(format!(
                        "option `{safe_spelling}` requires a positive integer"
                    )));
                }
            }
            "--port" => {
                if !value.parse::<u16>().is_ok_and(|value| value > 0) {
                    return Err(LpmError::Tunnel(
                        "replay port must be between 1 and 65535".to_string(),
                    ));
                }
            }
            "--status" => {
                let named = matches!(value, "2xx" | "3xx" | "4xx" | "5xx" | "error" | "err");
                let exact = value
                    .parse::<u16>()
                    .is_ok_and(|status| (100..=599).contains(&status));
                if !named && !exact {
                    let safe_value = lpm_common::sanitize_terminal_inline(value);
                    return Err(LpmError::Tunnel(format!(
                        "invalid status filter `{safe_value}`; use 2xx, 3xx, 4xx, 5xx, error, or an HTTP status code"
                    )));
                }
            }
            "--filter" => {}
            _ => unreachable!("allowed local action flags are handled above"),
        }

        index += if inline_value.is_some() { 1 } else { 2 };
    }

    let has = |flag: &str| args.iter().any(|arg| arg.split('=').next() == Some(flag));
    if has("--ui") && args.len() != 1 {
        return Err(LpmError::Tunnel(
            "cannot combine `--ui` with capture selection options".into(),
        ));
    }
    if has("--clear") && args.len() != 1 {
        return Err(LpmError::Tunnel(
            "cannot combine `--clear` with capture filters or limits".into(),
        ));
    }
    if has("--detail") && has("--last") {
        return Err(LpmError::Tunnel(
            "cannot combine `--detail` and `--last`".into(),
        ));
    }
    if action == "replay" {
        if replay_index_seen && has("--last") {
            return Err(LpmError::Tunnel(
                "cannot combine a webhook number and `--last`".into(),
            ));
        }
        if !replay_index_seen && !has("--last") {
            return Err(LpmError::Tunnel(
                "specify a webhook number or use --last".into(),
            ));
        }
    }
    Ok(())
}

fn tunnel_ready_json(
    session: &lpm_tunnel::TunnelSession,
    local_url: &str,
    usage: Option<&lpm_tunnel::TunnelUsageMetadata>,
    tunnel_auth: Option<&str>,
    inspector_url: Option<&str>,
    auto_ack: bool,
) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "tunnel_url": session.tunnel_url,
        "domain": session.domain,
        "local_port": session.local_port,
        "local_url": local_url,
        "session_id": session.session_id,
        "plan": session.plan,
        "base_domain": session.base_domain,
        "domain_kind": session.domain_kind,
        "session_expires_at": session.session_expires_at,
        "session_max_ms": session.session_max_ms,
        "limits": session.limits,
        "usage": usage,
        "tunnel_auth": tunnel_auth,
        "inspector_url": inspector_url,
        "auto_ack": auto_ack,
    })
}

/// Start a tunnel to expose a local port.
///
/// `inspect_port` carries the user's intent: `Some(n)` → bind that exact
/// port (fatal on `AddrInUse`); `None` → auto-pick a free ephemeral port
/// (best-effort, warns and continues without an inspector on the rare
/// failure).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_start(
    token: Option<&str>,
    local_target: lpm_common::LocalTarget,
    domain: Option<&str>,
    json_output: bool,
    project_dir: &Path,
    tunnel_auth: bool,
    no_inspect: bool,
    inspect_port: Option<u16>,
    auto_ack: bool,
    session_name: Option<&str>,
    relay_url: Option<&str>,
    token_provider: Option<lpm_tunnel::client::TunnelTokenProvider>,
    show_capture_warning: bool,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
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
            install_ui::yellow(&format!("lpm tunnel start {d}.lpm.llc"))
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

    let inspector_db = open_inspector_db(project_dir)?;
    let store = CaptureStore::of(&inspector_db);
    let inspector_state =
        lpm_inspect::state::InspectorState::with_db_for_target(local_target.clone(), inspector_db);
    warn_capture_persistence(project_dir, store, show_capture_warning).await;
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

    // Create webhook capture channel.
    let (webhook_tx, mut webhook_rx) =
        tokio::sync::mpsc::channel::<lpm_tunnel::client::CapturedWebhookEvent>(8);

    // Create WebSocket capture channel
    let (ws_tx, mut ws_rx) = tokio::sync::mpsc::channel::<lpm_tunnel::ws_capture::WsEvent>(256);

    // Spawn webhook consumer: pushes to inspector state for real-time SSE streaming
    let inspector_state_consumer = inspector_state.clone();
    let print_request_stream = !json_output;
    let webhook_consumer = tokio::spawn(async move {
        while let Some(captured) = webhook_rx.recv().await {
            let webhook = Arc::clone(&captured.webhook);
            if print_request_stream {
                print_tunnel_request(&webhook);
            }
            inspector_state_consumer.push_captured(captured).await;
        }
    });

    // Spawn WS event consumer: pushes to inspector state
    let inspector_state_ws = inspector_state.clone();
    let ws_consumer = tokio::spawn(async move {
        while let Some(event) = ws_rx.recv().await {
            inspector_state_ws.push_ws_event(event).await;
        }
    });

    let tunnel_cancel = tokio_util::sync::CancellationToken::new();
    let options = lpm_tunnel::client::TunnelOptions {
        relay_url: relay_url.map_or_else(lpm_tunnel::resolve_relay_url, str::to_owned),
        token: token.to_string(),
        token_provider,
        pin_provider: Some(crate::relay_trust::pin_provider()),
        local_target: local_target.clone(),
        live_local_target: None,
        domain: domain.map(|s| s.to_string()),
        tunnel_auth: tunnel_auth_token.clone(),
        webhook_tx: Some(webhook_tx),
        no_pin: false,
        auto_ack,
        ws_tx: Some(ws_tx),
        forwarding_admission: None,
        shutdown: Some(tunnel_cancel.clone()),
    };

    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Opening tunnel for {}",
            install_ui::yellow(&local_target.url())
        ));
    }

    let tunnel_auth_display = tunnel_auth_token.clone();
    let inspector_url = inspector_handle.as_ref().map(|h| h.url.clone());
    let control_inspector_url = inspector_url.clone();
    let inspector_state_for_connect = inspector_state.clone();
    let session_name_owned = session_name.map(|s| s.to_string());
    let local_target_url = local_target.url();
    let latest_usage = Arc::new(Mutex::new(None::<lpm_tunnel::TunnelUsageMetadata>));
    let usage_for_connect = latest_usage.clone();
    let usage_for_notices = latest_usage.clone();

    let connect = lpm_tunnel::client::connect_with_usage_fallible(
        &options,
        move |session| {
            // Update inspector state with the tunnel URL and start a session
            let url = session.tunnel_url.clone();
            let session_id = session.session_id.clone();
            let domain = Some(session.domain.clone());
            let local = session.local_port;
            let state = inspector_state_for_connect.clone();
            let name = session_name_owned.clone();
            state
                .start_session_immediate(session_id, domain, local, name)
                .map_err(|error| inspector_write_error("persist inspector session start", error))?;
            tokio::spawn(async move {
                state.set_tunnel_url(url).await;
            });

            let usage = usage_for_connect
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&tunnel_ready_json(
                        session,
                        &local_target_url,
                        usage.as_ref(),
                        tunnel_auth_display.as_deref(),
                        inspector_url.as_deref(),
                        auto_ack,
                    ))
                    .unwrap()
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
                tunnel_detail("local", &local_target_url);
                if auto_ack {
                    tunnel_detail(
                        "auto-ack",
                        "on (200 OK after durable capture on forwarding failure)",
                    );
                }
                if let Some(ref auth) = tunnel_auth_display {
                    tunnel_detail(
                        "auth",
                        tunnel_auth_header_summary(auth, std::io::stderr().is_terminal()),
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
            Ok(())
        },
        |msg| {
            if json_output {
                let event = serde_json::json!({
                    "schema_version": 1,
                    "success": false,
                    "event": "retry",
                    "error_code": "tunnel_retry",
                    "error": lpm_common::sanitize_terminal_inline(msg),
                    "retrying": true,
                });
                println!("{event:#}");
            } else {
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

    let connect_result = if json_output {
        tokio::pin!(connect);
        if let Some(mut shutdown) = shutdown {
            tokio::select! {
                result = &mut connect => result,
                _ = &mut shutdown => {
                    tunnel_cancel.cancel();
                    connect.await
                }
            }
        } else {
            connect.await
        }
    } else {
        tokio::pin!(connect);
        if let Some(mut shutdown) = shutdown {
            tokio::select! {
                result = &mut connect => result,
                control_result = wait_for_tunnel_controls(control_inspector_url) => {
                    tunnel_cancel.cancel();
                    compose_tunnel_control_and_connect(control_result, connect.await)
                },
                _ = &mut shutdown => {
                    tunnel_cancel.cancel();
                    connect.await
                }
            }
        } else {
            tokio::select! {
                result = &mut connect => result,
                control_result = wait_for_tunnel_controls(control_inspector_url) => {
                    tunnel_cancel.cancel();
                    compose_tunnel_control_and_connect(control_result, connect.await)
                },
            }
        }
    };

    drop(options);
    let webhook_result = webhook_consumer
        .await
        .map_err(|error| LpmError::Tunnel(format!("capture task failed: {error}")));
    let websocket_result = ws_consumer
        .await
        .map_err(|error| LpmError::Tunnel(format!("WebSocket capture task failed: {error}")));
    let (session_result, flush_result) = finish_capture_session(&inspector_state).await;
    let inspector_result = match inspector_handle {
        Some(handle) => handle.shutdown().await,
        None => Ok(()),
    };

    let cleanup_result = webhook_result
        .and(websocket_result)
        .and(session_result)
        .and(flush_result)
        .and(inspector_result);
    match (connect_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(cleanup_error)) => {
            tracing::warn!("tunnel capture cleanup failed: {cleanup_error}");
            Err(primary)
        }
    }
}

/// Warns that captures persist, and says how git treats them.
pub(crate) async fn warn_capture_persistence(
    project_dir: &Path,
    store: CaptureStore,
    show_human_warning: bool,
) {
    let state = capture_git_state(project_dir).await;
    for warning in capture_warnings(state.as_ref(), ignore_file_git_skips(project_dir), store) {
        capture_warning(&warning, show_human_warning);
    }
}

/// The capture warnings: that captures persist, kept out of git only where
/// git confirms it ignores them; files a repository tracks, which an ignore
/// rule can't keep from being committed, with the command for each
/// repository; and files git neither tracks nor ignores.
fn capture_warnings(
    state: Option<&CaptureGitState>,
    ignore_file_skipped: bool,
    store: CaptureStore,
) -> Vec<String> {
    let kept_out = state.is_some_and(CaptureGitState::kept_out);
    let access = match store {
        CaptureStore::OwnerOnly => "owner-only on Unix; project ACLs on Windows",
        CaptureStore::OpenToOthers => {
            "open to other users, as this filesystem's file modes don't keep them out"
        }
    };
    let mut warnings = vec![format!(
        "tunnel webhook capture persists full request/response bodies and headers \
         (incl. Authorization, Cookie, *-Signature) in .lpm/inspector.db ({access}){}",
        if kept_out { "; git ignores it" } else { "" }
    )];
    let Some(state) = state else {
        return warnings;
    };
    for repository in &state.unanswered {
        warnings.push(
            match repository {
                CaptureRepository::Project => {
                    "git didn't answer for the project's repository (it couldn't run, refused, \
                     or took over 2 s), so check that it doesn't track .lpm/inspector.db*"
                }
                CaptureRepository::Lpm => {
                    "git didn't answer in .lpm (it couldn't run or took over 2 s), so check \
                     that git ignores and doesn't track .lpm/inspector.db*"
                }
            }
            .to_string(),
        );
    }
    if state.lpm_unasked {
        warnings.push(
            "git couldn't be asked about .lpm, so check that git ignores and doesn't \
             track inspector.db*"
                .to_string(),
        );
    }
    if !state.project_tracked.is_empty() || !state.lpm_tracked.is_empty() {
        let tracked: Vec<String> = state
            .project_tracked
            .iter()
            .cloned()
            .chain(state.lpm_tracked.iter().map(|name| format!(".lpm/{name}")))
            .collect();
        let commands: Vec<String> = [
            (
                &state.project_tracked,
                CaptureRepository::Project,
                state.project_spelling_unknown,
            ),
            (&state.lpm_tracked, CaptureRepository::Lpm, false),
        ]
        .into_iter()
        .filter(|(names, _, _)| !names.is_empty())
        .map(|(names, repository, spelling_unknown)| {
            format!(
                "`{}`",
                if spelling_unknown {
                    untrack_every_capture(repository)
                } else {
                    untrack_command(names, repository)
                }
            )
        })
        .collect();
        warnings.push(format!(
            "git tracks {}, so captures there can be committed and stay in its history; \
             run {}, commit, and rotate any credentials they held",
            listed(&tracked),
            commands.join(" and ")
        ));
    }
    if !state.unignored.is_empty() {
        let unignored: Vec<String> = state
            .unignored
            .iter()
            .map(|name| format!(".lpm/{name}"))
            .collect();
        warnings.push(format!(
            "git doesn't ignore {}; {}",
            listed(&unignored),
            if ignore_file_skipped {
                "replace .lpm/.gitignore, which git doesn't read as a file of the \
                 project's, with a file that holds `inspector.db*`"
            } else {
                "add `inspector.db*` to .lpm/.gitignore"
            }
        ));
    }
    warnings
}

/// Whether git skips `.lpm/.gitignore`: a link, which git doesn't follow,
/// or an entry that isn't a regular file, such as a directory.
fn ignore_file_git_skips(project_dir: &Path) -> bool {
    std::fs::symlink_metadata(project_dir.join(".lpm/.gitignore"))
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
}

/// The human warning, or the same text on the log when it isn't shown, so
/// it isn't printed twice.
fn capture_warning(message: &str, show_human_warning: bool) {
    if show_human_warning {
        install_ui::warn_untrusted(message);
    } else {
        tracing::warn!(
            target: "lpm_cli::tunnel",
            "{}",
            lpm_common::sanitize_terminal_inline(message)
        );
    }
}

/// Who the capture database a writer opened lets read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureStore {
    OwnerOnly,
    /// On a filesystem whose file modes don't keep other users out, which
    /// no replacement improves: one without Unix modes, or on macOS one
    /// that ignores ownership.
    OpenToOthers,
}

impl CaptureStore {
    pub(crate) fn of(db: &lpm_inspect::db::InspectorDb) -> Self {
        if db.open_to_others() {
            Self::OpenToOthers
        } else {
            Self::OwnerOnly
        }
    }
}

/// Capture files a git query listed as tracked, and as neither tracked nor
/// ignored, by name relative to the directory it was asked in, or to its
/// repository's top with `--full-name`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CaptureGitFiles {
    tracked: Vec<String>,
    unignored: Vec<String>,
}

/// How git treats the capture files.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CaptureGitState {
    /// Those the project's repository tracks, by name in the project.
    project_tracked: Vec<String>,
    /// Whether `project_tracked` is spelled as git in `.lpm` lists it, when
    /// the project's query didn't answer: the index may spell the directory
    /// otherwise, as an upstream `.LPM/` on a case-insensitive disk.
    project_spelling_unknown: bool,
    /// Those a repository of `.lpm`'s own tracks, by name in `.lpm`.
    lpm_tracked: Vec<String>,
    /// Those git neither tracks nor ignores, by name in `.lpm`.
    unignored: Vec<String>,
    /// Whether git refused to answer for `.lpm`, as for one that looks like a
    /// bare repository.
    lpm_unasked: bool,
    /// The repositories whose query couldn't run, was refused in a
    /// repository, or didn't answer in time, so what the other found stands
    /// but git's ignoring the files isn't confirmed.
    unanswered: Vec<CaptureRepository>,
}

impl CaptureGitState {
    fn kept_out(&self) -> bool {
        !self.lpm_unasked
            && self.unanswered.is_empty()
            && self.project_tracked.is_empty()
            && self.lpm_tracked.is_empty()
            && self.unignored.is_empty()
    }
}

/// The repository whose index a tracked capture file is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureRepository {
    Project,
    Lpm,
}

const CAPTURES_PATHSPEC: &str = ":(glob,icase)inspector.db*";

const PROJECT_CAPTURES_PATHSPEC: &str = ":(glob,icase).lpm/inspector.db*";

const CAPTURE_GIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Why git didn't say how it treats the capture files.
#[derive(Debug, PartialEq, Eq)]
enum CaptureGitFailure {
    /// Git ran and found no repository it would use there.
    NoRepository,
    /// Git ran and refused, for a repository it won't use, such as one
    /// another user owns.
    Refused,
    /// Git couldn't be run, or didn't answer in time.
    Unavailable,
}

/// What git says, with `LC_ALL=C`, where it finds no repository: none at
/// all, none before a filesystem boundary, or a `.git` file that doesn't
/// point at one, which no git command there gets past.
const NO_REPOSITORY_MESSAGES: [&str; 3] = [
    "not a git repository",
    "invalid gitfile format",
    "no path in gitfile",
];

fn capture_git_failure(stderr: &[u8]) -> CaptureGitFailure {
    let message = String::from_utf8_lossy(stderr);
    if NO_REPOSITORY_MESSAGES
        .iter()
        .any(|pattern| message.contains(pattern))
    {
        CaptureGitFailure::NoRepository
    } else {
        CaptureGitFailure::Refused
    }
}

/// A git query of the capture files: the directory it runs in, its
/// pathspec, whether it lists files neither tracked nor ignored too, and
/// whether it names them from their repository's top.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CaptureGitQuery {
    directory: PathBuf,
    pathspec: &'static str,
    unignored: bool,
    full_name: bool,
}

/// How git treats the capture files in `project_dir`, matching their names
/// without regard to case, as a case-insensitive disk does. Two queries run
/// at once: the project's repository, for the capture files its index holds
/// whatever the case of their directory; and git in `.lpm`, for those
/// neither tracked nor ignored there, and for those a repository of `.lpm`'s
/// own tracks, such as a submodule, whose files the project's index doesn't
/// list. Git names the files in `.lpm` from their repository's top, so a
/// name without a directory is one a repository of `.lpm`'s own tracks.
/// What one query confirms stands when the other doesn't answer in time.
/// None when neither answers: neither is a repository, git can't be run, or
/// it doesn't answer in time.
async fn capture_git_state(project_dir: &Path) -> Option<CaptureGitState> {
    capture_git_state_by(project_dir, |query| {
        capture_git_output(capture_git_command(&query), CAPTURE_GIT_TIMEOUT)
    })
    .await
}

async fn capture_git_state_by<Ask, Answer>(project_dir: &Path, ask: Ask) -> Option<CaptureGitState>
where
    Ask: Fn(CaptureGitQuery) -> Answer,
    Answer: std::future::Future<Output = Result<CaptureGitFiles, CaptureGitFailure>>,
{
    let lpm_dir = project_dir.join(".lpm");
    let lpm_exists = lpm_dir.is_dir();
    let project = ask(CaptureGitQuery {
        directory: project_dir.to_path_buf(),
        pathspec: PROJECT_CAPTURES_PATHSPEC,
        unignored: false,
        full_name: false,
    });
    let inside = async {
        if lpm_exists {
            Some(
                ask(CaptureGitQuery {
                    directory: lpm_dir.clone(),
                    pathspec: CAPTURES_PATHSPEC,
                    unignored: true,
                    full_name: true,
                })
                .await,
            )
        } else {
            None
        }
    };
    let (project, inside) = tokio::join!(project, inside);

    let mut state = CaptureGitState::default();
    // Whether git found a repository the project is in; only where git
    // didn't run or answer is that read from the `.git` entries.
    let in_repository = match &project {
        Ok(_) | Err(CaptureGitFailure::Refused) => true,
        Err(CaptureGitFailure::NoRepository) => false,
        Err(CaptureGitFailure::Unavailable) => project_dir
            .ancestors()
            .any(|directory| marks_a_repository(&directory.join(".git"))),
    };
    let project_answered = match project {
        Ok(files) => {
            state.project_tracked = files.tracked;
            true
        }
        // In a repository, a query that fails is no answer, git refusing
        // included, as for one another user owns, run as root.
        Err(_) if in_repository => {
            state.unanswered.push(CaptureRepository::Project);
            false
        }
        Err(_) => false,
    };
    let inside_answered = match inside {
        Some(Ok(files)) => {
            let (own, project_files): (Vec<String>, Vec<String>) = files
                .tracked
                .into_iter()
                .partition(|name| !name.contains('/'));
            state.lpm_tracked = own;
            // Git in `.lpm` lists what the project's repository tracks
            // there, which the project's query has when it answers; when it
            // doesn't, they're what's known of them.
            if !project_answered {
                state.project_tracked = project_files
                    .iter()
                    .map(|name| format!(".lpm/{}", file_name(name)))
                    .collect();
                state.project_spelling_unknown = !state.project_tracked.is_empty();
            }
            state.unignored = files
                .unignored
                .iter()
                .map(|name| file_name(name).to_owned())
                .collect();
            true
        }
        // Git in `.lpm` stopped short of the project's repository, as at a
        // filesystem boundary, so whether it ignores the files there isn't
        // known.
        Some(Err(CaptureGitFailure::NoRepository)) => {
            if in_repository {
                state.unanswered.push(CaptureRepository::Lpm);
            }
            false
        }
        Some(Err(CaptureGitFailure::Refused)) => {
            state.lpm_unasked = true;
            false
        }
        Some(Err(CaptureGitFailure::Unavailable)) => {
            state.unanswered.push(CaptureRepository::Lpm);
            false
        }
        None => false,
    };
    let own_repository = lpm_exists && marks_a_repository(&lpm_dir.join(".git"));
    (project_answered || inside_answered || in_repository || own_repository).then_some(state)
}

/// The part of a name git lists after its last directory.
fn file_name(name: &str) -> &str {
    name.rsplit_once('/').map_or(name, |(_, file)| file)
}

/// Whether a `.git` entry looks like a repository's, for when git itself
/// can't be asked: a directory, or a link to one, holding `HEAD`, or a file
/// pointing at one as git writes it (`gitdir: …`). An empty directory or
/// another file doesn't, as git looks past them.
fn marks_a_repository(git: &Path) -> bool {
    match std::fs::metadata(git) {
        Ok(metadata) if metadata.is_dir() => git.join("HEAD").is_file(),
        Ok(metadata) if metadata.is_file() => {
            let mut start = [0_u8; 8];
            lpm_common::open_nofollow(git)
                .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut start))
                .is_ok_and(|()| &start == b"gitdir: ")
        }
        _ => false,
    }
}

fn capture_git_command(query: &CaptureGitQuery) -> tokio::process::Command {
    let mut args = vec!["ls-files", "-z", "-t", "--cached"];
    if query.unignored {
        args.extend(["--others", "--exclude-standard"]);
    }
    if query.full_name {
        args.push("--full-name");
    }
    args.extend(["--", query.pathspec]);
    tokio::process::Command::from(crate::commands::npmrc::hardened_git_command(
        &query.directory,
        &args,
    ))
}

/// Runs a capture query's git command, giving up after `timeout` and
/// killing it, so a slow repository delays the tunnel's start by that much
/// at most.
async fn capture_git_output(
    mut command: tokio::process::Command,
    timeout: std::time::Duration,
) -> Result<CaptureGitFiles, CaptureGitFailure> {
    command
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| CaptureGitFailure::Unavailable)?
        .map_err(|_| CaptureGitFailure::Unavailable)?;
    if !output.status.success() {
        return Err(capture_git_failure(&output.stderr));
    }
    Ok(parse_capture_git_files(&output.stdout))
}

fn parse_capture_git_files(stdout: &[u8]) -> CaptureGitFiles {
    let mut files = CaptureGitFiles::default();
    for record in stdout.split(|byte| *byte == 0) {
        // `-t` tags each name: `?` for one git neither tracks nor ignores,
        // a letter for one it tracks.
        let (Some(&tag), Some(name)) = (record.first(), record.get(2..)) else {
            continue;
        };
        let name = String::from_utf8_lossy(name).into_owned();
        // A conflicted file is listed once for each stage, one after another.
        let list = if tag == b'?' {
            &mut files.unignored
        } else {
            &mut files.tracked
        };
        if list.last() != Some(&name) {
            list.push(name);
        }
    }
    files
}

const LISTED_FILES: usize = 5;

/// Whether a name holds only characters no shell treats specially and no
/// terminal reads as anything but text, so it can go into the warning and
/// its command as it is.
fn is_plain(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '_' | '-'))
}

/// At most `LISTED_FILES` plain names, quoted; other names are only
/// counted, so text from the repository can't read as part of the warning.
fn listed(names: &[String]) -> String {
    let shown: Vec<String> = names
        .iter()
        .filter(|name| is_plain(name))
        .take(LISTED_FILES)
        .map(|name| format!("'{name}'"))
        .collect();
    let rest = names.len() - shown.len();
    match (shown.is_empty(), rest) {
        (true, 1) => "1 capture file".to_string(),
        (true, count) => format!("{count} capture files"),
        (false, 0) => shown.join(", "),
        (false, count) => format!("{} and {count} more", shown.join(", ")),
    }
}

/// The command, run in the project directory, that stops `repository`
/// tracking `tracked`: their names when the warning can list them all, and
/// otherwise the repository's capture pathspec, which every shell reads
/// alike in double quotes.
fn untrack_command(tracked: &[String], repository: CaptureRepository) -> String {
    if tracked.len() <= LISTED_FILES && tracked.iter().all(|name| is_plain(name)) {
        format!("{} {}", untrack_prefix(repository), tracked.join(" "))
    } else {
        untrack_every_capture(repository)
    }
}

/// The command that stops `repository` tracking every capture file, by the
/// capture pathspec, matched without regard to case.
fn untrack_every_capture(repository: CaptureRepository) -> String {
    let pathspec = match repository {
        CaptureRepository::Project => PROJECT_CAPTURES_PATHSPEC,
        CaptureRepository::Lpm => CAPTURES_PATHSPEC,
    };
    format!("{} \"{pathspec}\"", untrack_prefix(repository))
}

fn untrack_prefix(repository: CaptureRepository) -> &'static str {
    match repository {
        CaptureRepository::Project => "git rm --cached --",
        CaptureRepository::Lpm => "git -C .lpm rm --cached --",
    }
}

fn compose_tunnel_control_and_connect(
    control_result: Result<(), LpmError>,
    connect_result: Result<(), LpmError>,
) -> Result<(), LpmError> {
    match (control_result, connect_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(control_error), Err(connect_error)) => Err(LpmError::Tunnel(format!(
            "{control_error}; tunnel shutdown also failed: {connect_error}"
        ))),
    }
}

pub(crate) fn tunnel_auth_header_summary(auth: &str, reveal: bool) -> String {
    if reveal {
        format!("X-Tunnel-Auth: {auth}")
    } else {
        "X-Tunnel-Auth: <hidden in non-interactive output>".to_string()
    }
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
async fn run_inspect_ui(project_dir: &Path, inspect_port: Option<u16>) -> Result<(), LpmError> {
    let state = project_inspector_state(project_dir, true)?;
    let handle = lpm_inspect::start(state, inspect_port.unwrap_or(0)).await?;
    if let Err(error) = open::that(&handle.url) {
        install_ui::warn_untrusted(&format!("failed to open inspector in browser: {error}"));
    }

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

    handle.shutdown().await
}

fn project_inspector_state(
    project_dir: &Path,
    show_human_warning: bool,
) -> Result<lpm_inspect::state::InspectorState, LpmError> {
    let db = open_inspector_db_for_review(project_dir, show_human_warning)?;
    let sessions = lpm_runner::dev_session::discover_active_sessions()?;
    let local_target = observer_replay_target(&sessions);
    Ok(lpm_inspect::state::InspectorState::with_db_observer_for_target(local_target, db))
}

fn observer_replay_target(
    sessions: &[lpm_runner::dev_session::ActiveDevSession],
) -> lpm_common::LocalTarget {
    match sessions {
        [session] => session.target.clone(),
        _ => lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 0),
    }
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
    let db = open_inspector_db_for_review(project_dir, !json_output)?;

    let last = parse_flag_usize(args, "--last", "-n").unwrap_or(20);
    let filter_provider = parse_flag_str(args, "--filter");
    let filter_status = parse_flag_str(args, "--status");
    let detail_index = parse_flag_usize(args, "--detail", "-d");
    let filter = build_filter(filter_provider.as_deref(), filter_status.as_deref());

    if let Some(idx) = detail_index {
        if idx == 0 {
            if json_output {
                return Err(LpmError::Tunnel(
                    "--detail uses 1-based indexing; use --detail 1".to_string(),
                ));
            }
            install_ui::warn("--detail uses 1-based indexing. Use --detail 1 for the first entry.");
            return Ok(());
        }
        let entries = read_capture_entries(&db, idx, filter.as_ref()).await?;
        if let Some(entry) = entries.get(idx.saturating_sub(1)) {
            if let Some(full) = db
                .get_webhook(&entry.id)
                .await
                .map_err(inspector_query_error)?
            {
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&full)
                            .map_err(|error| LpmError::Tunnel(error.to_string()))?
                    );
                    return Ok(());
                }
                print_webhook_detail(&full, idx);
            } else {
                return Err(LpmError::Tunnel(
                    "captured request body data was not found in .lpm/inspector.db".to_string(),
                ));
            }
        } else {
            return Err(LpmError::Tunnel(format!("Webhook #{idx} not found")));
        }
        return Ok(());
    }

    let entries = read_capture_entries(&db, last, filter.as_ref()).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries)
                .map_err(|error| LpmError::Tunnel(error.to_string()))?
        );
        return Ok(());
    }

    if entries.is_empty() {
        install_ui::phase("No webhooks captured yet. Start a tunnel with: lpm dev --tunnel");
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
    default_port: Option<u16>,
    json_output: bool,
) -> Result<(), LpmError> {
    let db = open_inspector_db_for_review(project_dir, !json_output)?;
    let local_target = match parse_flag_u16(args, "--port", "-p")? {
        Some(port) => lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, port),
        None => resolve_local_target(default_port)?,
    };

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
    let entries = read_capture_entries(&db, read_count, None).await?;

    let target_entry = if is_last {
        entries.first()
    } else if let Some(n) = number {
        entries.get(n.saturating_sub(1))
    } else {
        if json_output {
            return Err(LpmError::Tunnel(
                "specify a webhook number or use --last".to_string(),
            ));
        }
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
    let webhook = db
        .get_webhook(&entry.id)
        .await
        .map_err(inspector_query_error)?
        .ok_or_else(|| LpmError::Tunnel("Webhook body data not found".into()))?;

    let idx = number.unwrap_or(1);
    if !json_output {
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
    }

    let replay_client = lpm_http::client_builder()
        .timeout(std::time::Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|e| LpmError::Tunnel(format!("failed to create HTTP client: {e}")))?;
    let result =
        lpm_tunnel::webhook_replay::replay_webhook(&replay_client, &webhook, &local_target).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "id": webhook.id,
                "status": result.status,
                "original_status": webhook.response_status,
                "duration_ms": result.duration_ms,
            }))
            .map_err(|error| LpmError::Tunnel(error.to_string()))?
        );
        return Ok(());
    }

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
    let db = open_inspector_db_for_review(project_dir, !json_output)?;

    if args.contains(&"--clear".to_string()) {
        clear_captures(&db).await?;
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "success": true,
                    "cleared": true,
                    "store": ".lpm/inspector.db"
                })
            );
        } else {
            install_ui::done("Tunnel capture history cleared");
        }
        return Ok(());
    }

    let last = parse_flag_usize(args, "--last", "-n").unwrap_or(50);
    let filter_provider = parse_flag_str(args, "--filter");
    let filter_status = parse_flag_str(args, "--status");
    let filter = build_filter(filter_provider.as_deref(), filter_status.as_deref());

    let entries = read_capture_entries(&db, last, filter.as_ref()).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries)
                .map_err(|error| LpmError::Tunnel(error.to_string()))?
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

/// Opens the project's capture database to record captures.
pub(crate) fn open_inspector_db(
    project_dir: &Path,
) -> Result<lpm_inspect::db::InspectorDb, LpmError> {
    lpm_inspect::db::InspectorDb::open(project_dir).map_err(inspector_open_error)
}

/// Opens the project's capture database to read and manage the captures it
/// holds, warning when other users could open it.
fn open_inspector_db_for_review(
    project_dir: &Path,
    show_human_warning: bool,
) -> Result<lpm_inspect::db::InspectorDb, LpmError> {
    let db =
        lpm_inspect::db::InspectorDb::open_for_review(project_dir).map_err(inspector_open_error)?;
    if let Some(warning) = review_warning(db.open_to_others(), db.ownership_ignored()) {
        capture_warning(warning, show_human_warning);
    }
    Ok(db)
}

/// What a review tells of a capture database other users could open, and
/// whether a capture writer's run can change it.
fn review_warning(open_to_others: bool, ownership_ignored: bool) -> Option<&'static str> {
    if !open_to_others {
        None
    } else if ownership_ignored {
        Some(CAPTURES_ON_A_SHARED_VOLUME)
    } else {
        Some(CAPTURES_OPEN_TO_OTHERS)
    }
}

const CAPTURES_OPEN_TO_OTHERS: &str = ".lpm/inspector.db is open to other users, so they may \
     read its captures; an `lpm tunnel` or `lpm dev --tunnel` run in this project makes it \
     owner-only where file modes keep other users out";

const CAPTURES_ON_A_SHARED_VOLUME: &str = ".lpm/inspector.db is open to other users, so they \
     may read its captures: its volume ignores ownership, so every user owns its files whatever \
     their mode; keep the project on a volume that keeps ownership";

/// The capture database's open failures are local, so they're reported as
/// such, not as a tunnel's; each says what to do.
fn inspector_open_error(error: lpm_inspect::db::OpenError) -> LpmError {
    LpmError::Io(std::io::Error::new(
        error.kind(),
        format!("failed to open this project's .lpm/inspector.db: {error}"),
    ))
}

/// A failure writing `.lpm/inspector.db`, which is the disk's, not the
/// tunnel connection's.
pub(crate) fn inspector_write_error(what: &str, error: impl Display) -> LpmError {
    LpmError::Io(std::io::Error::other(format!("failed to {what}: {error}")))
}

fn inspector_query_error(error: impl Display) -> LpmError {
    LpmError::Io(std::io::Error::other(format!(
        "failed to read .lpm/inspector.db: {error}"
    )))
}

async fn clear_captures(db: &lpm_inspect::db::InspectorDb) -> Result<(), LpmError> {
    db.clear_history()
        .await
        .map_err(|error| inspector_write_error("clear .lpm/inspector.db", error))
}

/// Ends the inspector session and commits the captures still queued: the
/// session end's result, then the commit's.
pub(crate) async fn finish_capture_session(
    state: &lpm_inspect::state::InspectorState,
) -> (Result<(), LpmError>, Result<(), LpmError>) {
    let ended = state
        .end_session()
        .await
        .map_err(|error| inspector_write_error("persist inspector session end", error));
    let committed = state
        .flush()
        .await
        .map_err(|error| inspector_write_error("commit captures to .lpm/inspector.db", error));
    (ended, committed)
}

async fn read_capture_entries(
    db: &lpm_inspect::db::InspectorDb,
    count: usize,
    filter: Option<&lpm_tunnel::webhook_log::WebhookFilter>,
) -> Result<Vec<lpm_tunnel::webhook_log::WebhookLogEntry>, LpmError> {
    use lpm_inspect::db::StatusQuery;
    use lpm_tunnel::webhook_log::StatusFilter;

    let provider = filter.and_then(|value| value.provider.as_deref());
    let status = filter
        .and_then(|value| value.status.as_ref())
        .map(|value| match value {
            StatusFilter::Exact(code) => StatusQuery::Exact(*code),
            StatusFilter::Class(class) => StatusQuery::Class(*class),
            StatusFilter::Range(_, _) => StatusQuery::Error,
        });
    let requests = db
        .search("", provider, status, count)
        .await
        .map_err(inspector_query_error)?;

    Ok(requests
        .into_iter()
        .map(|request| lpm_tunnel::webhook_log::WebhookLogEntry {
            id: request.id,
            ts: request.timestamp,
            method: request.method,
            path: request.path,
            status: request.status,
            ms: request.duration_ms,
            provider: request.provider,
            summary: request.summary,
            req_size: request.req_size,
            res_size: request.res_size,
        })
        .collect())
}

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

fn parse_flag_u16(args: &[String], long: &str, short: &str) -> Result<Option<u16>, LpmError> {
    for (index, arg) in args.iter().enumerate() {
        let value = if arg == long || arg == short {
            args.get(index + 1).map(String::as_str).ok_or_else(|| {
                LpmError::Tunnel(format!("{arg} requires a port between 1 and 65535"))
            })?
        } else if let Some(value) = arg.strip_prefix(&format!("{long}=")) {
            value
        } else {
            continue;
        };
        let port = value
            .parse::<u16>()
            .map_err(|_| LpmError::Tunnel(format!("{long} must be a port between 1 and 65535")))?;
        if port == 0 {
            return Err(LpmError::Tunnel(format!(
                "{long} must be a port between 1 and 65535"
            )));
        }
        return Ok(Some(port));
    }
    Ok(None)
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

    fn git(directory: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(directory)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}: {output:?}");
    }

    fn capture_project(files: &[&str]) -> tempfile::TempDir {
        let project = tempfile::tempdir().unwrap();
        git(project.path(), &["init", "--quiet"]);
        // The check runs git with the user's own configuration, so a global
        // ignore file mustn't hide the files these tests make.
        let no_excludes = project.path().join(".git/no-excludes");
        std::fs::write(&no_excludes, b"").unwrap();
        git(
            project.path(),
            &["config", "core.excludesFile", no_excludes.to_str().unwrap()],
        );
        for name in files {
            let path = project.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"x").unwrap();
        }
        project
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[tokio::test]
    async fn tells_capture_files_git_tracks_from_those_it_neither_tracks_nor_ignores() {
        let project = capture_project(&[
            ".lpm/inspector.db",
            ".lpm/inspector.db-wal",
            ".lpm/inspector.db-shm",
            ".lpm/added-sources.json",
            ".lpm/inspector.db.d/notes.md",
        ]);
        git(
            project.path(),
            &["add", ".lpm/inspector.db", ".lpm/added-sources.json"],
        );

        let state = capture_git_state(project.path()).await.unwrap();

        assert_eq!(state.project_tracked, names(&[".lpm/inspector.db"]));
        assert!(state.lpm_tracked.is_empty());
        let mut unignored = state.unignored;
        unignored.sort();
        assert_eq!(unignored, names(&["inspector.db-shm", "inspector.db-wal"]));
    }

    #[tokio::test]
    async fn finds_capture_files_ignored_by_lpm_gitignore_kept_out() {
        let project = capture_project(&[".lpm/inspector.db", ".lpm/inspector.db-wal"]);
        std::fs::write(project.path().join(".lpm/.gitignore"), "inspector.db*\n").unwrap();

        let state = capture_git_state(project.path()).await.unwrap();

        assert_eq!(state, CaptureGitState::default());
        assert!(state.kept_out());
    }

    #[tokio::test]
    async fn names_tracked_capture_files_whatever_their_case() {
        let project = capture_project(&[".lpm/Inspector.DB"]);
        git(project.path(), &["add", ".lpm/Inspector.DB"]);

        let state = capture_git_state(project.path()).await.unwrap();

        assert_eq!(state.project_tracked, names(&[".lpm/Inspector.DB"]));
    }

    #[tokio::test]
    async fn names_a_capture_the_project_tracks_under_another_case_of_lpm() {
        // As a repository committed on a case-insensitive disk carries it.
        let project = capture_project(&[".LPM/inspector.db"]);
        git(project.path(), &["add", ".LPM/inspector.db"]);

        let state = capture_git_state(project.path()).await.unwrap();

        assert_eq!(state.project_tracked, names(&[".LPM/inspector.db"]));
        assert!(!state.kept_out());
    }

    #[tokio::test]
    async fn asks_a_repository_inside_lpm_about_the_files_it_keeps() {
        let project = capture_project(&[".lpm/inspector.db"]);
        let lpm_dir = project.path().join(".lpm");
        git(&lpm_dir, &["init", "--quiet"]);
        git(&lpm_dir, &["add", "inspector.db"]);

        let state = capture_git_state(project.path()).await.unwrap();

        assert!(state.project_tracked.is_empty());
        assert_eq!(state.lpm_tracked, names(&["inspector.db"]));
        assert_eq!(
            untrack_command(&state.lpm_tracked, CaptureRepository::Lpm),
            "git -C .lpm rm --cached -- inspector.db"
        );
    }

    #[tokio::test]
    async fn names_the_project_s_capture_and_a_repository_inside_lpm_s_alike() {
        let project = capture_project(&[".lpm/inspector.db"]);
        git(project.path(), &["add", ".lpm/inspector.db"]);
        let lpm_dir = project.path().join(".lpm");
        git(&lpm_dir, &["init", "--quiet"]);
        git(&lpm_dir, &["add", "inspector.db"]);

        let state = capture_git_state(project.path()).await.unwrap();

        assert_eq!(state.project_tracked, names(&[".lpm/inspector.db"]));
        assert_eq!(state.lpm_tracked, names(&["inspector.db"]));
        let warnings = capture_warnings(Some(&state), false, CaptureStore::OwnerOnly);
        assert!(
            warnings[1].contains(
                "run `git rm --cached -- .lpm/inspector.db` and \
                 `git -C .lpm rm --cached -- inspector.db`"
            ),
            "{warnings:?}"
        );
    }

    #[tokio::test]
    async fn names_a_capture_the_project_tracks_when_lpm_points_git_elsewhere() {
        let project = capture_project(&[".lpm/inspector.db"]);
        git(project.path(), &["add", ".lpm/inspector.db"]);
        // As a downloaded archive can carry: git inside `.lpm` uses the
        // project's repository with `.lpm` as its working tree.
        std::fs::write(project.path().join(".lpm/.git"), "gitdir: ../.git\n").unwrap();

        let state = capture_git_state(project.path()).await.unwrap();

        assert_eq!(state.project_tracked, names(&[".lpm/inspector.db"]));
        assert!(!state.kept_out());
    }

    #[tokio::test]
    async fn lists_a_capture_once_when_lpm_holds_an_empty_git_directory() {
        let project = capture_project(&[".lpm/inspector.db"]);
        git(project.path(), &["add", ".lpm/inspector.db"]);
        std::fs::create_dir(project.path().join(".lpm/.git")).unwrap();

        let state = capture_git_state(project.path()).await.unwrap();

        assert_eq!(state.project_tracked, names(&[".lpm/inspector.db"]));
        assert!(state.lpm_tracked.is_empty(), "{state:?}");
        assert!(state.unanswered.is_empty(), "{state:?}");
    }

    #[tokio::test]
    async fn says_nothing_of_git_entries_git_takes_for_no_repository() {
        for entry in ["empty directory", "gitdir:../elsewhere/.git\n"] {
            let project = tempfile::tempdir().unwrap();
            std::fs::create_dir(project.path().join(".lpm")).unwrap();
            std::fs::write(project.path().join(".lpm/inspector.db"), b"x").unwrap();
            let git_entry = project.path().join(".git");
            if entry == "empty directory" {
                std::fs::create_dir(&git_entry).unwrap();
            } else {
                std::fs::write(&git_entry, entry).unwrap();
            }

            assert_eq!(capture_git_state(project.path()).await, None, "{entry:?}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn says_when_git_refuses_to_answer_for_lpm() {
        let project = capture_project(&[".lpm/inspector.db"]);
        git(project.path(), &["add", ".lpm/inspector.db"]);
        // An `.lpm` that looks like a bare repository, which the check's
        // git refuses to use.
        let lpm_dir = project.path().join(".lpm");
        for directory in ["objects", "refs"] {
            std::fs::create_dir(lpm_dir.join(directory)).unwrap();
        }
        std::fs::write(lpm_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();

        let state = capture_git_state(project.path()).await.unwrap();

        assert!(state.lpm_unasked);
        assert_eq!(state.project_tracked, names(&[".lpm/inspector.db"]));
        assert!(!state.kept_out());
    }

    #[tokio::test]
    async fn says_nothing_of_git_outside_a_repository() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        std::fs::write(project.path().join(".lpm/inspector.db"), b"x").unwrap();

        assert_eq!(capture_git_state(project.path()).await, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runs_no_fsmonitor_program_from_the_repository() {
        let project = capture_project(&[".lpm/inspector.db"]);
        let marker = project.path().join("fsmonitor-ran");
        git(
            project.path(),
            &[
                "config",
                "core.fsmonitor",
                &format!("touch '{}'; false", marker.display()),
            ],
        );

        capture_git_state(project.path()).await;

        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_a_bare_repository_a_project_carries() {
        let project = tempfile::tempdir().unwrap();
        let web = project.path().join("web");
        for directory in ["objects", "refs", ".lpm"] {
            std::fs::create_dir_all(web.join(directory)).unwrap();
        }
        std::fs::write(web.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let marker = project.path().join("fsmonitor-ran");
        std::fs::write(
            web.join("config"),
            format!(
                "[core]\n\tbare = false\n\tworktree = .\n\tfsmonitor = touch '{}'; false\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::write(web.join(".lpm/inspector.db"), b"x").unwrap();

        // Git without `safe.bareRepository=explicit` would use it, so its
        // refusal here leaves the files unconfirmed.
        let state = capture_git_state(&web).await.unwrap();
        assert_eq!(state.unanswered, vec![CaptureRepository::Project]);
        assert!(state.lpm_unasked);
        assert!(!marker.exists());
    }

    /// Asks with canned answers, by whether a query is the project's,
    /// recording each query.
    async fn state_from_answers(
        project_dir: &Path,
        project: Result<CaptureGitFiles, CaptureGitFailure>,
        inside: Result<CaptureGitFiles, CaptureGitFailure>,
    ) -> (Option<CaptureGitState>, Vec<CaptureGitQuery>) {
        let answers = std::sync::Mutex::new((Some(project), Some(inside)));
        let asked = std::sync::Mutex::new(Vec::new());
        let state = capture_git_state_by(project_dir, |query| {
            let answer = {
                let mut answers = answers.lock().unwrap();
                if query.unignored {
                    answers.1.take()
                } else {
                    answers.0.take()
                }
            }
            .unwrap();
            asked.lock().unwrap().push(query);
            async move { answer }
        })
        .await;
        (state, asked.into_inner().unwrap())
    }

    fn files(tracked: &[&str], unignored: &[&str]) -> CaptureGitFiles {
        CaptureGitFiles {
            tracked: names(tracked),
            unignored: names(unignored),
        }
    }

    #[tokio::test]
    async fn asks_the_project_s_index_and_git_in_lpm_together() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();

        let (state, mut asked) = state_from_answers(
            project.path(),
            Ok(files(&[".lpm/inspector.db"], &[])),
            Ok(files(&[".lpm/inspector.db"], &[".lpm/inspector.db-wal"])),
        )
        .await;

        asked.sort_by_key(|query| query.unignored);
        assert_eq!(
            asked,
            vec![
                CaptureGitQuery {
                    directory: project.path().to_path_buf(),
                    pathspec: PROJECT_CAPTURES_PATHSPEC,
                    unignored: false,
                    full_name: false,
                },
                CaptureGitQuery {
                    directory: lpm_dir,
                    pathspec: CAPTURES_PATHSPEC,
                    unignored: true,
                    full_name: true,
                },
            ]
        );
        // Git in `.lpm` names the project's files from its top, and the
        // project's query has them.
        assert_eq!(
            state,
            Some(CaptureGitState {
                project_tracked: names(&[".lpm/inspector.db"]),
                project_spelling_unknown: false,
                lpm_tracked: Vec::new(),
                unignored: names(&["inspector.db-wal"]),
                lpm_unasked: false,
                unanswered: Vec::new(),
            })
        );
    }

    #[tokio::test]
    async fn keeps_the_project_s_names_for_its_tracked_files_when_both_answer() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();

        let (state, _) = state_from_answers(
            project.path(),
            Ok(files(&[".LPM/inspector.db"], &[])),
            Ok(files(&[".LPM/inspector.db"], &[])),
        )
        .await;

        assert_eq!(
            state.unwrap().project_tracked,
            names(&[".LPM/inspector.db"])
        );
    }

    #[tokio::test]
    async fn counts_what_a_repository_of_lpm_s_own_tracks() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();

        let (state, _) = state_from_answers(
            project.path(),
            Err(CaptureGitFailure::NoRepository),
            Ok(files(&["inspector.db"], &["inspector.db-wal"])),
        )
        .await;

        let state = state.unwrap();
        assert_eq!(state.lpm_tracked, names(&["inspector.db"]));
        assert!(state.project_tracked.is_empty());
        assert_eq!(state.unignored, names(&["inspector.db-wal"]));
        assert!(state.unanswered.is_empty());
    }

    #[tokio::test]
    async fn says_nothing_of_git_outside_a_repository_when_neither_query_answers() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();

        for (project_answer, inside_answer) in [
            (
                Err(CaptureGitFailure::Unavailable),
                Err(CaptureGitFailure::Unavailable),
            ),
            (
                Err(CaptureGitFailure::NoRepository),
                Err(CaptureGitFailure::Unavailable),
            ),
            (
                Err(CaptureGitFailure::NoRepository),
                Err(CaptureGitFailure::NoRepository),
            ),
            (
                Err(CaptureGitFailure::NoRepository),
                Err(CaptureGitFailure::Refused),
            ),
        ] {
            let (state, _) =
                state_from_answers(project.path(), project_answer, inside_answer).await;
            assert_eq!(state, None);
        }

        // Git in `.lpm` answered, so only the project's query went unanswered,
        // and outside a repository there was nothing for it to find.
        let (answered, _) = state_from_answers(
            project.path(),
            Err(CaptureGitFailure::Unavailable),
            Ok(CaptureGitFiles::default()),
        )
        .await;
        let answered = answered.unwrap();
        assert!(answered.unanswered.is_empty(), "{answered:?}");
        assert!(answered.kept_out());
    }

    #[tokio::test]
    async fn names_lpm_s_own_repository_when_git_there_doesn_t_answer() {
        let project = tempfile::tempdir().unwrap();
        repository_entry(&project.path().join(".lpm"));

        let (state, _) = state_from_answers(
            project.path(),
            Err(CaptureGitFailure::NoRepository),
            Err(CaptureGitFailure::Unavailable),
        )
        .await;

        let state = state.unwrap();
        assert_eq!(state.unanswered, vec![CaptureRepository::Lpm]);
        let warnings = warnings_for(Some(state), false);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.starts_with("git didn't answer in .lpm")),
            "{warnings:?}"
        );
    }

    #[tokio::test]
    async fn names_each_query_a_repository_leaves_unanswered_even_when_neither_answers() {
        let project = tempfile::tempdir().unwrap();
        repository_entry(project.path());
        std::fs::create_dir(project.path().join(".lpm")).unwrap();

        // As for a repository another user owns, run as root.
        let (refused, _) = state_from_answers(
            project.path(),
            Err(CaptureGitFailure::Refused),
            Err(CaptureGitFailure::Refused),
        )
        .await;
        let refused = refused.unwrap();
        assert_eq!(refused.unanswered, vec![CaptureRepository::Project]);
        assert!(refused.lpm_unasked);
        let warnings = warnings_for(Some(refused), false);
        assert!(
            warnings.iter().any(|warning| warning
                .starts_with("git didn't answer for the project's repository (it couldn't run, refused, or took over 2 s)")),
            "{warnings:?}"
        );

        let (slow, _) = state_from_answers(
            project.path(),
            Err(CaptureGitFailure::Unavailable),
            Err(CaptureGitFailure::Unavailable),
        )
        .await;
        let slow = slow.unwrap();
        assert_eq!(
            slow.unanswered,
            vec![CaptureRepository::Project, CaptureRepository::Lpm]
        );
        assert!(!slow.kept_out());
        let warnings = warnings_for(Some(slow), false);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.starts_with("git didn't answer in .lpm")),
            "{warnings:?}"
        );
    }

    #[tokio::test]
    async fn takes_a_project_inside_a_repository_s_subdirectory_as_in_that_repository() {
        let repository = tempfile::tempdir().unwrap();
        repository_entry(repository.path());
        let project = repository.path().join("packages/app");
        std::fs::create_dir_all(project.join(".lpm")).unwrap();

        // Git didn't run, so the `.git` entries are what's known.
        let (state, _) = state_from_answers(
            &project,
            Err(CaptureGitFailure::Unavailable),
            Err(CaptureGitFailure::Refused),
        )
        .await;

        assert_eq!(state.unwrap().unanswered, vec![CaptureRepository::Project]);
    }

    #[tokio::test]
    async fn takes_whose_index_a_capture_is_in_from_the_name_git_gives_it() {
        let project = tempfile::tempdir().unwrap();
        // Git looks past an empty `.git` directory, whatever it holds.
        std::fs::create_dir_all(project.path().join(".lpm/.git")).unwrap();

        for (listed, own) in [
            ("inspector.db", true),
            (".lpm/inspector.db", false),
            ("apps/web/.lpm/inspector.db", false),
        ] {
            let (state, _) = state_from_answers(
                project.path(),
                Err(CaptureGitFailure::Unavailable),
                Ok(files(&[listed], &[])),
            )
            .await;
            let state = state.unwrap();
            let (lpm_tracked, project_tracked) = if own {
                (names(&["inspector.db"]), Vec::new())
            } else {
                (Vec::new(), names(&[".lpm/inspector.db"]))
            };
            assert_eq!(
                (state.lpm_tracked, state.project_tracked),
                (lpm_tracked, project_tracked),
                "{listed}"
            );
        }
    }

    #[tokio::test]
    async fn names_lpm_unanswered_where_git_there_stops_short_of_the_project_s_repository() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();

        // As at a filesystem boundary between the project and `.lpm`.
        let (state, _) = state_from_answers(
            project.path(),
            Ok(CaptureGitFiles::default()),
            Err(CaptureGitFailure::NoRepository),
        )
        .await;

        let state = state.unwrap();
        assert_eq!(state.unanswered, vec![CaptureRepository::Lpm]);
        assert!(!state.lpm_unasked);
        assert!(!state.kept_out());
    }

    /// Makes `directory/.git` as `git init` leaves its `HEAD`.
    fn repository_entry(directory: &Path) {
        std::fs::create_dir_all(directory.join(".git")).unwrap();
        std::fs::write(directory.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    #[test]
    fn takes_a_git_entry_for_a_repository_s_only_as_git_would() {
        let directory = tempfile::tempdir().unwrap();
        let git = directory.path().join(".git");

        for (contents, repository) in [
            ("", false),
            ("not a pointer\n", false),
            ("gitdir:../elsewhere/.git\n", false),
            ("gitdir: ../elsewhere/.git\n", true),
        ] {
            std::fs::write(&git, contents).unwrap();
            assert_eq!(marks_a_repository(&git), repository, "{contents:?}");
        }
        std::fs::remove_file(&git).unwrap();

        std::fs::create_dir(&git).unwrap();
        assert!(!marks_a_repository(&git));
        repository_entry(directory.path());
        assert!(marks_a_repository(&git));

        #[cfg(unix)]
        {
            let linked = directory.path().join("linked");
            std::fs::create_dir(&linked).unwrap();
            std::os::unix::fs::symlink(&git, linked.join(".git")).unwrap();
            assert!(marks_a_repository(&linked.join(".git")));
        }
        assert!(!marks_a_repository(&directory.path().join("gone/.git")));
    }

    #[test]
    fn reads_git_s_failure_as_no_repository_only_where_it_says_so() {
        for (stderr, failure) in [
            (
                "fatal: not a git repository (or any of the parent directories): .git\n",
                CaptureGitFailure::NoRepository,
            ),
            (
                "fatal: not a git repository (or any parent up to mount point /mnt)\n\
                 Stopping at filesystem boundary (GIT_DISCOVERY_ACROSS_FILESYSTEM not set).\n",
                CaptureGitFailure::NoRepository,
            ),
            (
                "fatal: invalid gitfile format: /work/app/.git\n",
                CaptureGitFailure::NoRepository,
            ),
            (
                "fatal: no path in gitfile: /work/app/.git\n",
                CaptureGitFailure::NoRepository,
            ),
            (
                "fatal: detected dubious ownership in repository at '/work/app'\n",
                CaptureGitFailure::Refused,
            ),
            (
                "fatal: cannot use bare repository '/work/app' (safe.bareRepository is 'explicit')\n",
                CaptureGitFailure::Refused,
            ),
            ("", CaptureGitFailure::Refused),
        ] {
            assert_eq!(capture_git_failure(stderr.as_bytes()), failure, "{stderr}");
        }
    }

    #[tokio::test]
    async fn keeps_what_one_query_confirms_when_the_other_doesn_t_answer_in_time() {
        let project = tempfile::tempdir().unwrap();
        repository_entry(project.path());
        std::fs::create_dir(project.path().join(".lpm")).unwrap();

        let (tracked, _) = state_from_answers(
            project.path(),
            Ok(files(&[".lpm/inspector.db"], &[])),
            Err(CaptureGitFailure::Unavailable),
        )
        .await;
        let (quiet, _) = state_from_answers(
            project.path(),
            Err(CaptureGitFailure::Unavailable),
            Ok(CaptureGitFiles::default()),
        )
        .await;

        let tracked = tracked.unwrap();
        assert_eq!(tracked.project_tracked, names(&[".lpm/inspector.db"]));
        let warnings = warnings_for(Some(tracked), false);
        assert!(warnings[0].ends_with(")"), "{warnings:?}");
        assert!(
            warnings.iter().any(
                |warning| warning.starts_with("git tracks '.lpm/inspector.db'")
                    && warning.contains("git rm --cached")
            ),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.starts_with("git didn't answer in .lpm")),
            "{warnings:?}"
        );
        let quiet = warnings_for(quiet, false);
        assert!(!quiet[0].contains("git ignores it"), "{quiet:?}");
        assert!(
            quiet.iter().any(
                |warning| warning.starts_with("git didn't answer for the project's repository")
            )
        );
    }

    #[tokio::test]
    async fn reports_what_git_in_lpm_finds_tracked_when_the_project_s_query_doesn_t_answer() {
        let project = tempfile::tempdir().unwrap();
        repository_entry(project.path());
        std::fs::create_dir(project.path().join(".lpm")).unwrap();

        let (state, _) = state_from_answers(
            project.path(),
            Err(CaptureGitFailure::Unavailable),
            Ok(files(&[".lpm/inspector.db"], &[])),
        )
        .await;

        let state = state.unwrap();
        assert_eq!(state.project_tracked, names(&[".lpm/inspector.db"]));
        assert_eq!(state.unanswered, vec![CaptureRepository::Project]);
        assert!(state.project_spelling_unknown);
        let warnings = warnings_for(Some(state), false);
        // Git in `.lpm` may spell the directory otherwise than the index, so
        // the command matches every capture file without regard to case.
        let command = format!("`git rm --cached -- \"{PROJECT_CAPTURES_PATHSPEC}\"`");
        assert!(
            warnings.iter().any(
                |warning| warning.starts_with("git tracks '.lpm/inspector.db'")
                    && warning.contains(&command)
            ),
            "{warnings:?}"
        );

        let (own, _) = state_from_answers(
            project.path(),
            Err(CaptureGitFailure::Unavailable),
            Ok(files(&["inspector.db"], &[])),
        )
        .await;

        let own = own.unwrap();
        assert!(own.project_tracked.is_empty(), "{own:?}");
        assert_eq!(own.lpm_tracked, names(&["inspector.db"]));
    }

    #[test]
    fn a_review_says_whether_a_tunnel_run_can_make_the_database_owner_only() {
        assert_eq!(review_warning(false, false), None);
        assert_eq!(review_warning(false, true), None);
        assert!(
            review_warning(true, false)
                .unwrap()
                .ends_with("makes it owner-only where file modes keep other users out")
        );
        let shared = review_warning(true, true).unwrap();
        assert!(
            shared.contains("its volume ignores ownership")
                && !shared.contains("makes it owner-only"),
            "{shared}"
        );
    }

    fn warnings_for(state: Option<CaptureGitState>, ignore_file_skipped: bool) -> Vec<String> {
        capture_warnings(state.as_ref(), ignore_file_skipped, CaptureStore::OwnerOnly)
    }

    fn state(
        project_tracked: &[&str],
        lpm_tracked: &[&str],
        unignored: &[&str],
    ) -> CaptureGitState {
        CaptureGitState {
            project_tracked: names(project_tracked),
            project_spelling_unknown: false,
            lpm_tracked: names(lpm_tracked),
            unignored: names(unignored),
            lpm_unasked: false,
            unanswered: Vec::new(),
        }
    }

    #[test]
    fn says_git_ignores_captures_only_when_every_query_says_so() {
        assert!(warnings_for(Some(state(&[], &[], &[])), false)[0].ends_with("; git ignores it"));
        for unconfirmed in [
            None,
            Some(CaptureGitState {
                lpm_unasked: true,
                unanswered: Vec::new(),
                ..state(&[], &[], &[])
            }),
            Some(state(&[".lpm/inspector.db"], &[], &[])),
            Some(state(&[], &["inspector.db"], &[])),
            Some(state(&[], &[], &["inspector.db-wal"])),
            Some(CaptureGitState {
                unanswered: vec![CaptureRepository::Project],
                ..state(&[], &[], &[])
            }),
            Some(CaptureGitState {
                unanswered: vec![CaptureRepository::Lpm],
                ..state(&[], &[], &[])
            }),
        ] {
            assert!(
                !warnings_for(unconfirmed.clone(), false)[0].contains("git ignores it"),
                "{unconfirmed:?}"
            );
        }
    }

    #[test]
    fn says_when_git_couldnt_be_asked_about_lpm() {
        let warnings = warnings_for(
            Some(CaptureGitState {
                lpm_unasked: true,
                unanswered: Vec::new(),
                ..state(&[], &[], &[])
            }),
            false,
        );

        assert_eq!(warnings.len(), 2);
        assert!(warnings[1].starts_with("git couldn't be asked about .lpm"));
        assert_eq!(warnings_for(Some(state(&[], &[], &[])), false).len(), 1);
        assert_eq!(warnings_for(None, false).len(), 1);
    }

    #[test]
    fn names_tracked_captures_and_the_command_that_stops_tracking_them() {
        let warnings = warnings_for(Some(state(&[".lpm/inspector.db"], &[], &[])), false);

        assert_eq!(warnings.len(), 2);
        assert_eq!(
            warnings[1],
            "git tracks '.lpm/inspector.db', so captures there can be committed and stay in \
             its history; run `git rm --cached -- .lpm/inspector.db`, commit, and rotate any \
             credentials they held"
        );
    }

    #[test]
    fn advises_on_captures_git_neither_tracks_nor_ignores() {
        let added = warnings_for(Some(state(&[], &[], &["inspector.db-wal"])), false);
        let replaced = warnings_for(Some(state(&[], &[], &["inspector.db-wal"])), true);

        assert_eq!(
            added[1],
            "git doesn't ignore '.lpm/inspector.db-wal'; add `inspector.db*` to .lpm/.gitignore"
        );
        assert_eq!(
            replaced[1],
            "git doesn't ignore '.lpm/inspector.db-wal'; replace .lpm/.gitignore, which git \
             doesn't read as a file of the project's, with a file that holds `inspector.db*`"
        );
    }

    #[test]
    fn reports_a_capture_database_it_cant_open_yet_as_busy_with_its_own_advice() {
        let error = inspector_open_error(lpm_inspect::db::OpenError::Files(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            "inspector.db is open to other users, and another process has it open; retry",
        )));

        let LpmError::Io(error) = error else {
            panic!("{error:?}");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::ResourceBusy);
        assert_eq!(
            error.to_string(),
            "failed to open this project's .lpm/inspector.db: inspector.db is open to other \
             users, and another process has it open; retry"
        );
    }

    #[test]
    fn the_capture_warning_says_when_the_filesystem_leaves_captures_open_to_others() {
        let open = capture_warnings(None, false, CaptureStore::OpenToOthers);
        let owner_only = capture_warnings(None, false, CaptureStore::OwnerOnly);

        assert!(
            open[0].contains(
                "(open to other users, as this filesystem's file modes don't keep them out)"
            ),
            "{open:?}"
        );
        assert!(!open[0].contains("owner-only"), "{open:?}");
        assert!(owner_only[0].contains("(owner-only on Unix; project ACLs on Windows)"));
    }

    #[tokio::test]
    async fn reports_a_failed_clear_as_a_write() {
        let project = tempfile::tempdir().unwrap();
        let db = lpm_inspect::db::InspectorDb::open(project.path()).unwrap();
        rusqlite::Connection::open(project.path().join(".lpm/inspector.db"))
            .unwrap()
            .execute_batch("DROP TABLE requests_fts;")
            .unwrap();

        let error = clear_captures(&db).await.unwrap_err();

        assert_eq!(error.error_code(), "io");
        assert!(
            error
                .to_string()
                .contains("failed to clear .lpm/inspector.db: no such table: requests_fts"),
            "{error}"
        );
    }

    #[test]
    fn reports_inspector_database_reads_as_disk_errors() {
        let error = inspector_query_error("database disk image is malformed");

        assert_eq!(error.error_code(), "io");
        assert!(
            error
                .to_string()
                .contains("failed to read .lpm/inspector.db: database disk image is malformed")
        );
    }

    #[test]
    fn reports_inspector_database_writes_as_disk_errors() {
        let error = inspector_write_error("commit captures to .lpm/inspector.db", "disk I/O error");

        assert_eq!(error.error_code(), "io");
        assert!(
            error
                .to_string()
                .contains("failed to commit captures to .lpm/inspector.db: disk I/O error")
        );
    }

    #[test]
    fn lists_at_most_five_names_quoted() {
        let many: Vec<String> = (0..7)
            .map(|index| format!(".lpm/inspector.db{index}"))
            .collect();

        assert_eq!(
            listed(&many),
            "'.lpm/inspector.db0', '.lpm/inspector.db1', '.lpm/inspector.db2', \
             '.lpm/inspector.db3', '.lpm/inspector.db4' and 2 more"
        );
    }

    #[test]
    fn lists_names_with_other_characters_only_by_count() {
        assert_eq!(
            listed(&names(&[
                ".lpm/inspector.db",
                ".lpm/inspector.db\u{202e}bd.x",
                ".lpm/it\u{2019}s.db",
            ])),
            "'.lpm/inspector.db' and 2 more"
        );
        assert_eq!(listed(&names(&[".lpm/inspector db"])), "1 capture file");
        assert_eq!(
            listed(&names(&[".lpm/inspector db", ".lpm/inspector\u{200b}.db"])),
            "2 capture files"
        );
    }

    #[test]
    fn untracks_listed_names_or_every_capture_file_past_the_list() {
        let names = |count: usize, prefix: &str| -> Vec<String> {
            (0..count)
                .map(|index| format!("{prefix}inspector.db{index}"))
                .collect()
        };

        assert_eq!(
            untrack_command(&names(5, ".lpm/"), CaptureRepository::Project),
            "git rm --cached -- .lpm/inspector.db0 .lpm/inspector.db1 \
             .lpm/inspector.db2 .lpm/inspector.db3 .lpm/inspector.db4"
        );
        assert_eq!(
            untrack_command(&names(6, ".lpm/"), CaptureRepository::Project),
            "git rm --cached -- \":(glob,icase).lpm/inspector.db*\""
        );
        assert_eq!(
            untrack_command(&names(6, ""), CaptureRepository::Lpm),
            "git -C .lpm rm --cached -- \":(glob,icase)inspector.db*\""
        );
    }

    #[test]
    fn untracks_every_capture_file_when_a_name_has_other_characters() {
        for name in [
            "inspector db",
            "inspector\u{201d}.db",
            "inspector\u{2019}.db",
            "!'$(touch x)'.db",
            "inspector\".db",
            "%PATH%.db",
            "",
        ] {
            assert_eq!(
                untrack_command(&names(&["inspector.db", name]), CaptureRepository::Lpm),
                "git -C .lpm rm --cached -- \":(glob,icase)inspector.db*\"",
                "{name:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn tells_an_lpm_gitignore_git_skips_from_one_it_reads() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        assert!(!ignore_file_git_skips(project.path()));

        std::fs::write(lpm_dir.join(".gitignore"), "skills/\n").unwrap();
        assert!(!ignore_file_git_skips(project.path()));

        std::fs::remove_file(lpm_dir.join(".gitignore")).unwrap();
        std::fs::create_dir(lpm_dir.join(".gitignore")).unwrap();
        assert!(ignore_file_git_skips(project.path()));

        std::fs::remove_dir(lpm_dir.join(".gitignore")).unwrap();
        std::os::unix::fs::symlink(project.path().join("elsewhere"), lpm_dir.join(".gitignore"))
            .unwrap();
        assert!(ignore_file_git_skips(project.path()));
    }

    #[test]
    fn lists_a_conflicted_capture_file_once() {
        let files = parse_capture_git_files(
            b"M inspector.db\0M inspector.db\0M inspector.db\0? inspector.db-wal\0",
        );

        assert_eq!(files.tracked, names(&["inspector.db"]));
        assert_eq!(files.unignored, names(&["inspector.db-wal"]));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn gives_up_on_a_slow_repository_and_stops_its_git() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("pid");
        let started = std::time::Instant::now();
        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg("echo $$ > \"$1\"; exec sleep 5")
            .arg("sh")
            .arg(&pid_file);

        let state = capture_git_output(command, std::time::Duration::from_millis(300)).await;

        assert_eq!(state, Err(CaptureGitFailure::Unavailable));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        let stopped = |pid: &str| {
            let output = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", pid.trim()])
                .output()
                .unwrap();
            let status = String::from_utf8_lossy(&output.stdout);
            // Gone, or killed and not yet reaped.
            status.trim().is_empty() || status.trim_start().starts_with('Z')
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !stopped(&pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(stopped(&pid), "the slow command is still running");
    }

    #[test]
    fn non_interactive_tunnel_auth_output_never_contains_the_secret() {
        let output = tunnel_auth_header_summary("super-secret", false);

        assert!(!output.contains("super-secret"));
        assert!(!output.contains("http://"));
        assert!(!output.contains("https://"));
    }

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
            response_body_incomplete: false,
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
    fn replay_port_parser_rejects_values_outside_the_tcp_port_range() {
        for invalid in ["0", "-1", "70000"] {
            let error =
                parse_flag_u16(&["--port".to_string(), invalid.to_string()], "--port", "-p")
                    .unwrap_err();
            assert!(
                error.to_string().contains("between 1 and 65535"),
                "unexpected error for {invalid}: {error}"
            );
        }
    }

    #[test]
    fn replay_port_parser_accepts_the_complete_tcp_port_range() {
        assert_eq!(
            parse_flag_u16(&["--port=1".to_string()], "--port", "-p").unwrap(),
            Some(1)
        );
        assert_eq!(
            parse_flag_u16(&["-p".to_string(), "65535".to_string()], "--port", "-p").unwrap(),
            Some(65535)
        );
    }

    #[test]
    fn local_action_validation_rejects_missing_and_unknown_flags() {
        let missing = validate_local_action_args("inspect", &["--last".to_string()]).unwrap_err();
        assert!(missing.to_string().contains("requires a value"));

        let unknown =
            validate_local_action_args("inspect", &["--not-a-real-flag".to_string()]).unwrap_err();
        assert!(unknown.to_string().contains("not valid"));
    }

    #[test]
    fn local_action_validation_preserves_replay_last_without_a_value() {
        validate_local_action_args(
            "replay",
            &[
                "--last".to_string(),
                "--port".to_string(),
                "4000".to_string(),
            ],
        )
        .unwrap();
    }

    #[test]
    fn active_dev_target_selection_requires_exactly_one_session() {
        let session = |port| lpm_runner::dev_session::ActiveDevSession {
            lpm_pid: 1,
            owner_pid: Some(2),
            project_dir: std::path::PathBuf::from(format!("/project-{port}")),
            service: None,
            target: lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, port),
        };

        let none = select_active_target(&[]).unwrap_err();
        assert!(none.to_string().contains("no active `lpm dev` endpoint"));

        let one = select_active_target(&[session(5173)]).unwrap();
        assert_eq!(one.port, 5173);

        let multiple = select_active_target(&[session(5173), session(5174)]).unwrap_err();
        assert!(multiple.to_string().contains("multiple active"));
        assert!(multiple.to_string().contains("5173, 5174"));
    }

    #[test]
    fn inspector_observer_uses_the_only_active_dev_target() {
        let session = |port| lpm_runner::dev_session::ActiveDevSession {
            lpm_pid: 1,
            owner_pid: Some(2),
            project_dir: std::path::PathBuf::from(format!("/project-{port}")),
            service: None,
            target: lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, port),
        };

        assert_eq!(observer_replay_target(&[]).port, 0);
        assert_eq!(observer_replay_target(&[session(5173)]).port, 5173);
        assert_eq!(
            observer_replay_target(&[session(5173), session(5174)]).port,
            0
        );
    }

    #[test]
    fn explicit_tunnel_target_rejects_port_zero() {
        let error = resolve_local_target(Some(0)).unwrap_err();
        assert!(error.to_string().contains("between 1 and 65535"));
    }

    #[test]
    fn tunnel_ready_json_preserves_the_complete_local_endpoint() {
        let session = lpm_tunnel::TunnelSession {
            tunnel_url: "https://orange-moon.lpm.fyi".to_string(),
            domain: "orange-moon.lpm.fyi".to_string(),
            session_id: "session-1".to_string(),
            local_port: 5173,
            plan: Some("free".to_string()),
            base_domain: Some("lpm.fyi".to_string()),
            domain_kind: Some("random".to_string()),
            session_expires_at: Some(1_800_000),
            session_max_ms: Some(3_600_000),
            limits: None,
        };

        let output = tunnel_ready_json(
            &session,
            "http://[::1]:5173/app/",
            None,
            None,
            Some("http://127.0.0.1:4400/?token=redacted"),
            false,
        );

        assert_eq!(output["local_port"], 5173);
        assert_eq!(output["local_url"], "http://[::1]:5173/app/");
        insta::assert_json_snapshot!(output, @r###"
        {
          "success": true,
          "tunnel_url": "https://orange-moon.lpm.fyi",
          "domain": "orange-moon.lpm.fyi",
          "local_port": 5173,
          "local_url": "http://[::1]:5173/app/",
          "session_id": "session-1",
          "plan": "free",
          "base_domain": "lpm.fyi",
          "domain_kind": "random",
          "session_expires_at": 1800000,
          "session_max_ms": 3600000,
          "limits": null,
          "usage": null,
          "tunnel_auth": null,
          "inspector_url": "http://127.0.0.1:4400/?token=redacted",
          "auto_ack": false
        }
        "###);
    }

    #[tokio::test]
    async fn numeric_tunnel_action_rejects_port_zero_before_starting() {
        let temp = tempfile::tempdir().unwrap();
        let error = run(
            &lpm_registry::RegistryClient::new(),
            "0",
            None,
            None,
            None,
            None,
            false,
            temp.path(),
            &[],
            false,
            true,
            None,
            false,
            None,
            None,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("between 1 and 65535"));
    }

    #[tokio::test]
    async fn inspect_ui_state_opens_the_selected_project_database() {
        let project = tempfile::tempdir().unwrap();
        let writer = lpm_inspect::state::InspectorState::with_db(
            3000,
            lpm_inspect::db::InspectorDb::open(project.path()).unwrap(),
        );
        let webhook = lpm_tunnel::webhook::CapturedWebhook {
            id: "selected-project".to_string(),
            timestamp: "2026-07-26T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/selected".to_string(),
            request_headers: std::collections::HashMap::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: std::collections::HashMap::new(),
            response_body: Vec::new(),
            duration_ms: 1,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: false,
            response_body_incomplete: false,
        };
        writer.push(webhook.clone()).await;
        writer.flush().await.unwrap();

        let observer = project_inspector_state(project.path(), false).unwrap();
        let mut observed = observer.get_all_persisted().await.unwrap();

        assert_eq!(
            observer.db().unwrap().db_path,
            project.path().join(".lpm/inspector.db")
        );
        assert_eq!(observed.len(), 1);
        assert_eq!(observed.pop().unwrap().id, webhook.id);
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
