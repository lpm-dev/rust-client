use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Run the `lpm dev` command with zero-config detection.
///
/// Auto-detects features from lpm.json: tunnel.domain, services.
/// Auto-installs dependencies if stale. Auto-copies .env.example.
/// Opens browser after services are ready.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    https: bool,
    tunnel: bool,
    network: bool,
    port: Option<u16>,
    host: Option<&str>,
    token: Option<&str>,
    tunnel_domain: Option<&str>,
    tunnel_source: Option<&str>,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_open: bool,
    no_install: bool,
    quiet: bool,
    dashboard: bool,
    pre_parsed_config: Option<lpm_runner::lpm_json::LpmJsonConfig>,
    tunnel_auth: bool,
) -> Result<(), LpmError> {
    let port = port.unwrap_or(3000);

    // Warn about privileged ports that may require elevated permissions
    if is_privileged_port(port) {
        output::warn(&format!(
            "Port {} is privileged. You may need elevated permissions (sudo) on Linux.",
            port
        ));
    }

    let mut extra_env: Vec<(String, String)> = Vec::new();

    // ── Collect startup info for banner ─────────────────────────────
    let mut startup = StartupInfo {
        deps_status: String::new(),
        env_status: None,
        https_active: false,
        tunnel_url: None,
        tunnel_source: None,
        network_addr: None,
        node_version: None,
    };

    // ── Run independent detection steps in parallel ──────────────────
    // Steps that can run concurrently:
    //   - auto_install_if_stale (async, potentially slow — runs `lpm install`)
    //   - auto_copy_env_example (sync file I/O — wrap in spawn_blocking)
    //   - HTTPS cert setup (sync, may generate certs — wrap in spawn_blocking)
    //   - ensure_runtime (async, may download node — potentially slow)
    //
    // Network display and tunnel setup depend on HTTPS result (cert env vars),
    // so they run after the parallel batch.

    let install_dir = project_dir.to_path_buf();
    let env_dir = project_dir.to_path_buf();
    let https_dir = project_dir.to_path_buf();
    let runtime_dir = project_dir.to_path_buf();
    let host_owned = host.map(|h| h.to_string());

    // Pre-compute network info once (used for both cert SANs and display)
    let network_info = if network {
        Some(lpm_network::get_network_info(port, https)?)
    } else {
        None
    };

    // Clone for the spawn_blocking closure (cert SANs need the IP list)
    let network_info_for_cert = network_info.clone();

    let node_version_handle = tokio::task::spawn_blocking(|| {
        std::process::Command::new("node")
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout).ok()
                } else {
                    None
                }
            })
            .map(|v| v.trim().to_string())
    });

    let (install_result, env_result, https_result, _runtime_result, node_version_result) = tokio::join!(
        async {
            if !no_install {
                auto_install_if_stale(client, &install_dir).await
            } else {
                Ok("skipped (--no-install)".to_string())
            }
        },
        async {
            let dir = env_dir.clone();
            tokio::task::spawn_blocking(move || auto_copy_env_example(&dir))
                .await
                .unwrap_or(None)
        },
        async {
            if https {
                let dir = https_dir.clone();
                let host_clone = host_owned.clone();
                let net_info = network_info_for_cert;
                let setup = tokio::task::spawn_blocking(move || {
                    let mut extra_hostnames: Vec<String> = Vec::new();
                    if let Some(h) = host_clone {
                        extra_hostnames.push(h);
                    }
                    // If network mode, add network IPs to the cert SANs
                    if let Some(ref info) = net_info {
                        for addr in &info.addresses {
                            if !addr.is_ipv6 {
                                extra_hostnames.push(addr.ip.clone());
                            }
                        }
                    }
                    lpm_cert::ensure_https(&dir, &extra_hostnames)
                })
                .await
                .map_err(|e| LpmError::Script(format!("HTTPS setup panicked: {e}")))?;
                Ok::<_, LpmError>(Some(setup?))
            } else {
                Ok::<_, LpmError>(None)
            }
        },
        async {
            super::run::ensure_runtime(&runtime_dir).await;
        },
        async { node_version_handle.await.unwrap_or(None) },
    );

    // Process parallel results
    startup.deps_status = install_result?;
    startup.env_status = env_result;
    startup.node_version = node_version_result;

    let https_setup: Option<lpm_cert::HttpsSetup> = https_result?;
    if let Some(setup) = https_setup {
        if setup.ca_freshly_installed {
            output::success("root CA generated and installed to trust store");
        }
        if setup.cert_freshly_generated {
            output::success("project certificate generated");
        }
        extra_env.extend(setup.env_vars);
        startup.https_active = true;
    }

    // ── Network info (reuse pre-computed result) ────────────────────
    if let Some(ref net_info) = network_info {
        let scheme = if https { "https" } else { "http" };

        if let Some(ref primary) = net_info.primary {
            let addr_str = if primary.is_ipv6 {
                format!("[{}]:{port}", primary.ip)
            } else {
                format!("{}:{port}", primary.ip)
            };
            startup.network_addr = Some(addr_str);

            println!();
            let url = if primary.is_ipv6 {
                format!("{scheme}://[{}]:{port}", primary.ip)
            } else {
                format!("{scheme}://{}:{port}", primary.ip)
            };
            println!(
                "  {} {} {}",
                "●".green(),
                format!("Network: {}", url.bold()).green(),
                format!("({})", primary.interface_type).dimmed()
            );

            // Show additional addresses
            for addr in &net_info.addresses {
                if !addr.is_preferred {
                    let url = if addr.is_ipv6 {
                        format!("{scheme}://[{}]:{port}", addr.ip)
                    } else {
                        format!("{scheme}://{}:{port}", addr.ip)
                    };
                    println!("    {} ({})", url, addr.interface_type.to_string().dimmed());
                }
            }
        } else {
            output::warn("no network interfaces found");
        }

        // QR code
        if !net_info.qr_code.is_empty() {
            println!();
            print!("{}", net_info.qr_code);
        }

        // Warnings
        for warning in &net_info.warnings {
            output::warn(warning);
        }

        // CA install instructions for mobile
        // Spawn a lightweight CA certificate server on port+1 for mobile device setup.
        // Serves the root CA at / with the correct content type to trigger the
        // iOS/Android "install profile" flow.
        if https
            && let Some(ref primary) = net_info.primary
            && let Ok(ca_cert_path) = lpm_cert::paths::ca_cert_path()
            && ca_cert_path.exists()
        {
            let ca_cert_data = std::fs::read(&ca_cert_path).unwrap_or_default();
            if !ca_cert_data.is_empty() {
                let ca_port = port + 1;
                tokio::spawn(serve_ca_cert(ca_port, ca_cert_data));
                println!();
                println!(
                    "  {} First time on mobile? Visit {} to install the CA certificate",
                    "📱".dimmed(),
                    format!("http://{}:{ca_port}", primary.ip).bold()
                );
            }
        }

        // Inject HMR host for framework
        if let Some(ref primary) = net_info.primary {
            extra_env.push(("HOSTNAME".to_string(), "0.0.0.0".to_string()));

            // Detect framework for HMR-specific vars
            let framework = lpm_cert::framework::detect_framework(project_dir);
            if framework == lpm_cert::framework::Framework::Vite {
                extra_env.push(("VITE_HMR_HOST".to_string(), primary.ip.clone()));
            }
        }

        println!();
    }

    // ── Dashboard event channel ─────────────────────────────────────
    // When --dashboard is active, orchestrator events and webhook events
    // are forwarded through this channel to the TUI.
    let (dashboard_event_tx, dashboard_event_rx) = if dashboard {
        let (tx, rx) = std::sync::mpsc::channel::<lpm_dashboard::DashboardEvent>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // ── Tunnel setup ───────────────────────────────────────────────────
    let mut tunnel_handle: Option<tokio::task::JoinHandle<()>> = None;
    if tunnel {
        let token = token.ok_or_else(|| {
            LpmError::Tunnel("authentication required for tunnel. Run `lpm login` first.".into())
        })?;

        // Tunnel source for banner (resolved in main.rs: "lpm.json", "--domain", "--tunnel")
        startup.tunnel_source = tunnel_source.map(|s| s.to_string());

        // Proactive guidance for configured domains
        if let Some(domain) = tunnel_domain
            && !quiet
        {
            output::info(&format!("tunnel domain: {domain}"));
        }

        // Create webhook capture channel and logger
        let (webhook_tx, mut webhook_rx) =
            tokio::sync::mpsc::unbounded_channel::<lpm_tunnel::webhook::CapturedWebhook>();
        let webhook_logger = lpm_tunnel::webhook_log::WebhookLogger::new(project_dir);

        // Dashboard webhook channel: when --dashboard is active, webhooks are
        // forwarded to the dashboard TUI via a std::sync channel.
        let dashboard_webhook_tx: Option<std::sync::mpsc::Sender<lpm_dashboard::DashboardEvent>> =
            if dashboard {
                Some(
                    dashboard_event_tx
                        .clone()
                        .expect("dashboard_event_tx must be set when --dashboard is active"),
                )
            } else {
                None
            };

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

        let options = lpm_tunnel::client::TunnelOptions {
            relay_url: lpm_tunnel::DEFAULT_RELAY_URL.to_string(),
            token: token.to_string(),
            local_port: port,
            domain: tunnel_domain.map(|s| s.to_string()),
            tunnel_auth: tunnel_auth_token.clone(),
            webhook_tx: Some(webhook_tx),
            no_pin: false,
            auto_ack: false,
            ws_tx: None,
        };

        // Spawn webhook consumer: persists to disk, forwards to dashboard,
        // and prints inline summaries for mutation requests (POST/PUT/PATCH/DELETE).
        tokio::spawn(async move {
            while let Some(webhook) = webhook_rx.recv().await {
                // Always persist to JSONL log (non-blocking best-effort)
                let _ = webhook_logger.append(&webhook);

                // Forward to dashboard if active
                if let Some(ref tx) = dashboard_webhook_tx {
                    let _ = tx.send(lpm_dashboard::DashboardEvent::WebhookCaptured(Box::new(
                        webhook.clone(),
                    )));
                }

                // Inline display: skip when dashboard is active (dashboard shows its own view),
                // skip GET/HEAD/OPTIONS (health checks, browsers), and respect --quiet flag
                if dashboard || quiet {
                    continue;
                }
                let method_upper = webhook.method.to_uppercase();
                if method_upper == "GET" || method_upper == "HEAD" || method_upper == "OPTIONS" {
                    continue;
                }

                let status_indicator = if webhook.response_status >= 400 {
                    " !"
                } else {
                    ""
                };
                let status_color = if webhook.response_status >= 500 {
                    "\x1b[31m"
                } else if webhook.response_status >= 400 {
                    "\x1b[33m"
                } else {
                    "\x1b[32m"
                };
                let reset = "\x1b[0m";

                eprintln!(
                    "  {} {} {} -> {status_color}{}{reset} ({}ms) — {}{}",
                    "[tunnel]".dimmed(),
                    webhook.method,
                    webhook.path,
                    webhook.response_status,
                    webhook.duration_ms,
                    webhook.summary,
                    status_indicator,
                );

                // Show signature diagnostic if present
                if let Some(ref diag) = webhook.signature_diagnostic {
                    eprintln!("           {}", format!("! {diag}").yellow());
                }
            }
        });

        // Start tunnel in background task, storing the handle for clean shutdown
        let options_clone = options.clone();
        let tunnel_auth_display = tunnel_auth_token.clone();
        tunnel_handle = Some(tokio::spawn(async move {
            let _ = lpm_tunnel::client::connect(
                &options_clone,
                |session| {
                    println!(
                        "  {} {}",
                        "●".green(),
                        format!(
                            "Tunnel: {} → localhost:{}",
                            session.tunnel_url.bold(),
                            session.local_port,
                        )
                        .green()
                    );
                    if let Some(ref auth) = tunnel_auth_display {
                        println!(
                            "  {} {}",
                            "🔒".dimmed(),
                            format!("Auth required: add header X-Tunnel-Auth: {auth}").dimmed()
                        );
                        println!(
                            "  {} {}",
                            " ".dimmed(),
                            format!("Browser: {}?__tunnel_auth={auth}", session.tunnel_url)
                                .dimmed()
                        );
                    }
                },
                |msg| {
                    eprintln!("  {} {}", "⚠".yellow(), msg);
                    // Provide actionable hints based on Worker error messages
                    if msg.contains("not claimed") {
                        eprintln!("    Run: lpm tunnel claim <domain>");
                    } else if msg.contains("Pro plan") || msg.contains("plan_required") {
                        eprintln!("    Upgrade at: https://lpm.dev/pricing");
                    } else if msg.contains("concurrent") {
                        eprintln!("    Close other tunnels first, or upgrade your plan");
                    }
                },
            )
            .await;
        }));
    }

    // ── Print startup banner ────────────────────────────────────────
    print_startup_banner(&startup, project_dir);

    // ── Check for multi-service orchestration ──────────────────────────
    // Reuse pre-parsed config from main.rs if available, avoiding a second file read
    let lpm_config = if let Some(cfg) = pre_parsed_config {
        Some(cfg)
    } else {
        lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?
    };

    let has_services = lpm_config
        .as_ref()
        .map(|c| !c.services.is_empty())
        .unwrap_or(false);

    if has_services {
        let services = &lpm_config.as_ref().unwrap().services;

        let open_browser = should_open_browser(true, no_open, is_ci());
        let open_url = if https {
            format!("https://localhost:{port}")
        } else {
            format!("http://localhost:{port}")
        };

        // Bridge orchestrator events to the dashboard when --dashboard is active.
        // The orchestrator sends OrchestratorEvent, the dashboard receives DashboardEvent.
        let orchestrator_event_tx = dashboard_event_tx.as_ref().map(|dash_tx| {
            let (orch_tx, orch_rx) =
                std::sync::mpsc::channel::<lpm_runner::orchestrator::OrchestratorEvent>();
            let dash_tx = dash_tx.clone();
            std::thread::spawn(move || {
                while let Ok(event) = orch_rx.recv() {
                    let dash_event = match event {
                        lpm_runner::orchestrator::OrchestratorEvent::ServiceLog {
                            service_index,
                            line,
                            ..
                        } => lpm_dashboard::DashboardEvent::ServiceLog {
                            index: service_index,
                            line,
                        },
                        lpm_runner::orchestrator::OrchestratorEvent::StatusChange {
                            service_index,
                            status,
                        } => lpm_dashboard::DashboardEvent::StatusChange {
                            index: service_index,
                            status: convert_service_status(&status),
                        },
                    };
                    if dash_tx.send(dash_event).is_err() {
                        break;
                    }
                }
            });
            orch_tx
        });

        // Create command channel for dashboard → orchestrator communication
        let (orch_cmd_tx, orch_cmd_rx) = if dashboard {
            let (tx, rx) =
                std::sync::mpsc::channel::<lpm_runner::orchestrator::OrchestratorCommand>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let options = lpm_runner::orchestrator::OrchestratorOptions {
            https,
            filter: extra_args.to_vec(), // lpm dev web api → filter to web + api
            extra_envs: extra_env.clone(),
            event_tx: orchestrator_event_tx,
            command_rx: orch_cmd_rx,
            on_all_ready: if open_browser {
                Some(Box::new(move || {
                    let _ = open::that(&open_url);
                }))
            } else {
                None
            },
        };

        if dashboard {
            // Dashboard mode: run orchestrator in a background thread,
            // launch the TUI dashboard on the current thread (it blocks until quit).
            //
            // The dashboard sends DashboardCommand via command_tx when the user
            // presses [r]estart or [x] stop. A bridge thread converts these to
            // OrchestratorCommand and forwards them. The dashboard stays in the TUI
            // the entire time — no exit/re-enter cycle.
            let project_dir_owned = project_dir.to_path_buf();
            let services_owned = services.clone();
            let orch_handle = std::thread::spawn(move || {
                let _ = lpm_runner::orchestrator::run_services(
                    &project_dir_owned,
                    &services_owned,
                    options,
                );
            });

            // Dashboard → orchestrator command bridge
            let orch_cmd_tx =
                orch_cmd_tx.expect("orch_cmd_tx must be set when --dashboard is active");
            // Keep a clone so we can send StopAll when the dashboard exits
            let orch_cmd_tx_for_shutdown = orch_cmd_tx.clone();
            let (dash_cmd_tx, dash_cmd_rx) =
                std::sync::mpsc::channel::<lpm_dashboard::DashboardCommand>();
            std::thread::spawn(move || {
                while let Ok(cmd) = dash_cmd_rx.recv() {
                    let orch_cmd = match cmd {
                        lpm_dashboard::DashboardCommand::RestartService(idx) => {
                            lpm_runner::orchestrator::OrchestratorCommand::RestartService(idx)
                        }
                        lpm_dashboard::DashboardCommand::StopService(idx) => {
                            lpm_runner::orchestrator::OrchestratorCommand::StopService(idx)
                        }
                        lpm_dashboard::DashboardCommand::StopAll => {
                            lpm_runner::orchestrator::OrchestratorCommand::StopAll
                        }
                    };
                    if orch_cmd_tx.send(orch_cmd).is_err() {
                        break;
                    }
                }
            });

            // Build dashboard service state from config (sorted by name for stable ordering)
            let mut service_names: Vec<&String> = services.keys().collect();
            service_names.sort();
            let dashboard_services: Vec<lpm_dashboard::ServiceState> = service_names
                .iter()
                .map(|name| {
                    let svc = &services[*name];
                    lpm_dashboard::ServiceState {
                        name: (*name).clone(),
                        port: svc.port,
                        status: lpm_dashboard::ServiceStatus::Starting,
                        logs: lpm_dashboard::LogBuffer::new(5000),
                    }
                })
                .collect();

            // Helper: signal the orchestrator to shut down gracefully and wait for
            // it to clean up child processes (reverse-topological SIGTERM, then SIGKILL).
            // Without this, the process would exit immediately and the OS would kill
            // children ungracefully — skipping the orchestrator's ordered shutdown.
            let graceful_shutdown = move || {
                let _ = orch_cmd_tx_for_shutdown
                    .send(lpm_runner::orchestrator::OrchestratorCommand::StopAll);
                // Wait for orchestrator to finish cleanup (bounded to avoid hanging)
                let _ = orch_handle.join();
            };

            let result = if let Some(rx) = dashboard_event_rx {
                match lpm_dashboard::run_dashboard(dashboard_services, rx, Some(dash_cmd_tx)) {
                    Ok(_) => {
                        graceful_shutdown();
                        Ok(())
                    }
                    Err(e) => {
                        graceful_shutdown();
                        Err(LpmError::Script(e.to_string()))
                    }
                }
            } else {
                graceful_shutdown();
                Ok(())
            };

            // Clean shutdown: await tunnel task if it was started
            if let Some(handle) = tunnel_handle {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
            }

            return result;
        }

        return lpm_runner::orchestrator::run_services(project_dir, services, options);
    }

    // ── Single service: start dev server ────────────────────────────
    let scheme = if https { "https" } else { "http" };
    let url = format!("{scheme}://localhost:{port}");
    println!("  {} {}", "●".cyan(), format!("Local: {url}").cyan());
    println!();

    // Start readiness check + browser open in background thread (non-blocking)
    {
        let open_url = url.clone();
        let port_check = port;
        let open_browser = should_open_browser(true, no_open, is_ci());
        std::thread::spawn(move || {
            // Wait for port to be ready (up to 30s)
            match lpm_runner::ready::wait_for_port(port_check, 30) {
                Ok(duration) => {
                    eprintln!("  {} ready ({})", "✔".green(), format_duration(duration));
                }
                Err(msg) => {
                    output::warn(&format!(
                        "Service not ready after 30s — opening browser anyway\n  {msg}"
                    ));
                }
            }
            // Open browser regardless of readiness outcome — on timeout the user
            // sees the warning above and the browser shows the error page, which is
            // more actionable than nothing happening at all.
            if open_browser {
                let _ = open::that(&open_url);
            }
        });
    }

    // Run the "dev" script with extra env vars injected safely (no unsafe set_var)
    lpm_runner::script::run_script_with_envs(project_dir, "dev", extra_args, env_mode, &extra_env)?;

    // Clean shutdown: await tunnel task if it was started
    if let Some(handle) = tunnel_handle {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
    }

    Ok(())
}

// ── Startup info ────────────────────────────────────────────────────

struct StartupInfo {
    /// "up to date (2ms)" or "installed 847 packages in 3.2s" or "skipped (--no-install)"
    deps_status: String,
    /// "loaded" or "created from .env.example" or None (no .env.example)
    env_status: Option<String>,
    /// Whether HTTPS certificate was set up
    https_active: bool,
    /// Tunnel URL once connected (may not be known yet at banner time)
    tunnel_url: Option<String>,
    /// Where the tunnel config came from: "lpm.json", "--domain", "--tunnel"
    tunnel_source: Option<String>,
    /// Network address (e.g. "192.168.1.42:3000")
    network_addr: Option<String>,
    /// Node.js version string (e.g. "v20.11.0"), pre-fetched in parallel
    node_version: Option<String>,
}

fn print_startup_banner(info: &StartupInfo, project_dir: &Path) {
    println!();

    // Node version (pre-fetched in parallel)
    if let Some(ref version) = info.node_version {
        // Check for .nvmrc / .node-version to show source
        let source = if project_dir.join(".nvmrc").exists() {
            "from .nvmrc"
        } else if project_dir.join(".node-version").exists() {
            "from .node-version"
        } else {
            "system"
        };
        let node_label = format!("Node     {version}");
        let source_str = format!("({source})");
        println!("  {} {node_label}  {}", "●".cyan(), source_str.dimmed());
    }

    // Deps status
    if !info.deps_status.is_empty() {
        println!("  {} Deps  {}", "●".cyan(), info.deps_status.dimmed());
    }

    // Env status
    if let Some(ref status) = info.env_status {
        println!("  {} Env  {}", "●".cyan(), status.dimmed());
    }

    // HTTPS
    if info.https_active {
        println!("  {} HTTPS  {}", "●".cyan(), "certificate valid".dimmed());
    }

    // Tunnel
    if let Some(ref source) = info.tunnel_source {
        if let Some(ref url) = info.tunnel_url {
            let tunnel_label = format!("Tunnel   {url}");
            let source_str = format!("({source})");
            println!("  {} {tunnel_label}  {}", "●".cyan(), source_str.dimmed());
        } else {
            println!(
                "  {} Tunnel  {}",
                "●".cyan(),
                format!("connecting... ({source})").dimmed()
            );
        }
    }

    // Network
    if let Some(ref addr) = info.network_addr {
        println!("  {} {}", "●".cyan(), format!("Network  {addr}").dimmed());
    }

    println!();
}

// ── Zero-config helpers ──────────────────────────────────────────────

/// Check if dependencies are up to date by comparing install hash.
///
/// Phase 34.1: delegates to the shared `install_state::check_install_state()`
/// which has the stronger semantics (lockfile required, mtime check).
///
/// Returns `(needs_install, computed_hash)`. The hash is `None` only when
/// there is no `package.json` (nothing to install). Returning the hash
/// avoids re-reading package.json and lockfile when install is needed.
fn needs_install(project_dir: &std::path::Path) -> (bool, Option<String>) {
    let state = crate::install_state::check_install_state(project_dir);
    match state.hash {
        // No package.json → nothing to install (not stale, just absent)
        None => (false, None),
        Some(hash) => (!state.up_to_date, Some(hash)),
    }
}

/// Auto-install dependencies if the install hash doesn't match.
///
/// Compares sha256(package.json + lockfile) against `.lpm/install-hash`.
/// If different or missing, runs `lpm install`. ~2ms when up-to-date.
///
/// Returns a status string for the startup banner.
async fn auto_install_if_stale(
    client: &lpm_registry::RegistryClient,
    project_dir: &std::path::Path,
) -> Result<String, LpmError> {
    let pkg_json = project_dir.join("package.json");
    if !pkg_json.exists() {
        return Ok("no package.json".to_string());
    }

    let start = std::time::Instant::now();

    let (stale, hash) = needs_install(project_dir);
    if !stale {
        let elapsed = start.elapsed();
        return Ok(format!("up to date ({})", format_duration(elapsed)));
    }

    // Hash was already computed by needs_install — reuse it
    let current_hash = hash.unwrap();
    let hash_file = project_dir.join(".lpm").join("install-hash");

    output::info("Dependencies out of date, installing...");

    // Phase 35 Step 6 fix: use the injected client. Pre-fix this
    // built a fresh `RegistryClient::new()` with no token, so any
    // `@lpm.dev` package required by the dev project would have been
    // unauthenticated.
    match crate::commands::install::run_with_options(
        client,
        project_dir,
        false,                                                 // json_output
        false,                                                 // offline
        false,                                                 // force
        false,                                                 // allow_new
        None,                                                  // linker_override
        false,                                                 // no_skills
        false,                                                 // no_editor_setup
        true,                                                  // no_security_summary
        false,                                                 // auto_build
        None,                                                  // target_set: dev is single-project
        None, // direct_versions_out: dev does not finalize Phase 33 placeholders
        None, // script_policy_override: `lpm dev` does not expose policy flags
        None, // min_release_age_override: `lpm dev` uses the chain
        crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm dev` enforces drift
    )
    .await
    {
        Ok(()) => {
            // Write install hash so the next `lpm dev` skips install if deps are unchanged
            if let Err(e) = std::fs::create_dir_all(project_dir.join(".lpm")) {
                output::warn(&format!(
                    "Could not create .lpm directory: {e}\n    Dependency check will re-run next time."
                ));
            }
            if let Err(e) = std::fs::write(&hash_file, &current_hash) {
                output::warn(&format!(
                    "Could not save install hash: {e}\n    Dependency check will re-run next time."
                ));
            }
            let elapsed = start.elapsed();
            Ok(format!("installed in {}", format_duration(elapsed)))
        }
        Err(e) => Err(LpmError::Script(format!(
            "auto-install failed: {e}\n    Use --no-install to skip dependency installation."
        ))),
    }
}

/// Auto-copy .env.example → .env if .env doesn't exist.
///
/// Uses `create_new(true)` for atomic file creation to avoid TOCTOU races
/// where a concurrent process could create .env between the exists() check
/// and the copy, potentially clobbering the other process's file.
///
/// Returns a status string for the startup banner, or None if no .env.example.
fn auto_copy_env_example(project_dir: &std::path::Path) -> Option<String> {
    use std::fs::OpenOptions;
    use std::io;

    let env_file = project_dir.join(".env");
    let example_file = project_dir.join(".env.example");

    if !example_file.exists() {
        return None;
    }

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&env_file)
    {
        Ok(mut dest) => {
            // File created atomically — now copy contents from .env.example
            match std::fs::File::open(&example_file) {
                Ok(mut src) => {
                    if let Err(e) = io::copy(&mut src, &mut dest) {
                        output::warn(&format!(
                            "Created .env but failed to copy from .env.example: {e}\n    Fill in .env manually or delete it and retry."
                        ));
                        return Some("created (copy failed, fill manually)".to_string());
                    }
                }
                Err(e) => {
                    output::warn(&format!(
                        "Created .env but could not read .env.example: {e}\n    Fill in .env manually."
                    ));
                    return Some("created (empty, could not read .env.example)".to_string());
                }
            }
            output::warn("No .env file found. Created from .env.example");
            eprintln!("    Review .env and fill in missing values");
            eprintln!(
                "    Or use {} to store secrets in the vault",
                "lpm env vars set".cyan()
            );
            Some("created from .env.example".to_string())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // .env already exists
            Some(".env loaded".to_string())
        }
        Err(e) => {
            output::warn(&format!(
                "Could not create .env file: {e}\n    Create it manually or check directory permissions."
            ));
            None
        }
    }
}

/// Format a Duration as human-readable (e.g. "42ms" or "3.2s").
fn format_duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

/// Check if a port number is in the privileged range (< 1024).
///
/// On Linux, binding to ports below 1024 requires root or `CAP_NET_BIND_SERVICE`.
/// macOS is more lenient but we still warn to avoid confusion.
fn is_privileged_port(port: u16) -> bool {
    port < 1024
}

/// Convert orchestrator's `ServiceStatus` to dashboard's `ServiceStatus`.
///
/// The two enums are structurally similar but live in different crates.
fn convert_service_status(
    status: &lpm_runner::orchestrator::ServiceStatus,
) -> lpm_dashboard::ServiceStatus {
    match status {
        lpm_runner::orchestrator::ServiceStatus::Pending
        | lpm_runner::orchestrator::ServiceStatus::Starting => {
            lpm_dashboard::ServiceStatus::Starting
        }
        lpm_runner::orchestrator::ServiceStatus::WaitingForDep(dep) => {
            lpm_dashboard::ServiceStatus::WaitingForDep(dep.clone())
        }
        lpm_runner::orchestrator::ServiceStatus::Ready => lpm_dashboard::ServiceStatus::Ready,
        lpm_runner::orchestrator::ServiceStatus::Crashed(code) => {
            lpm_dashboard::ServiceStatus::Crashed(format!("exit code {code}"))
        }
        lpm_runner::orchestrator::ServiceStatus::Stopped => lpm_dashboard::ServiceStatus::Stopped,
    }
}

/// Determine whether the browser should be opened after readiness check.
///
/// Returns `true` only when the service is ready, the user hasn't disabled
/// browser opening (`--no-open`), and we're not running in CI.
fn should_open_browser(ready: bool, no_open: bool, is_ci: bool) -> bool {
    ready && !no_open && !is_ci
}

/// Detect if running in CI environment.
fn is_ci() -> bool {
    std::env::var("CI").is_ok()
        || std::env::var("CONTINUOUS_INTEGRATION").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
}

/// Lightweight HTTP server that serves the root CA certificate for mobile device setup.
///
/// Listens on the given port and responds to any request with the CA certificate
/// in PEM format with `Content-Type: application/x-pem-file`. This triggers the
/// certificate install flow on iOS and Android when visited from a mobile browser.
///
/// Runs until the dev server shuts down (task is dropped).
async fn serve_ca_cert(port: u16, ca_cert_data: Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::debug!("CA cert server failed to bind on port {port}: {e}");
            return;
        }
    };

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => break,
        };

        let cert_data = ca_cert_data.clone();
        tokio::spawn(async move {
            // Read the request (we don't need to parse it, just drain the headers)
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/x-pem-file\r\n\
                 Content-Disposition: attachment; filename=\"lpm-ca.pem\"\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-store\r\n\
                 Connection: close\r\n\
                 \r\n",
                cert_data.len()
            );

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&cert_data).await;
            let _ = stream.flush().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_state::compute_install_hash;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn privileged_port_detection() {
        assert!(is_privileged_port(80));
        assert!(is_privileged_port(443));
        assert!(is_privileged_port(1));
        assert!(is_privileged_port(1023));
        assert!(!is_privileged_port(1024));
        assert!(!is_privileged_port(3000));
        assert!(!is_privileged_port(8080));
    }

    #[test]
    fn is_ci_detects_ci_env() {
        // Verify the function exists and returns bool — value depends on environment
        let _result: bool = is_ci();
    }

    #[test]
    fn auto_copy_env_example_creates_env() {
        let dir = TempDir::new().unwrap();
        let example = dir.path().join(".env.example");
        fs::write(&example, "KEY=value\n").unwrap();

        auto_copy_env_example(dir.path());

        let env_content = fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(env_content, "KEY=value\n");
    }

    #[test]
    fn auto_copy_env_example_no_overwrite() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "EXISTING=yes\n").unwrap();
        fs::write(dir.path().join(".env.example"), "KEY=value\n").unwrap();

        auto_copy_env_example(dir.path());

        let env_content = fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(env_content, "EXISTING=yes\n"); // Not overwritten
    }

    #[test]
    fn auto_copy_env_example_no_example_file() {
        let dir = TempDir::new().unwrap();
        auto_copy_env_example(dir.path());
        assert!(!dir.path().join(".env").exists()); // Nothing created
    }

    #[test]
    fn format_duration_ms() {
        let d = std::time::Duration::from_millis(42);
        assert_eq!(format_duration(d), "42ms");
    }

    #[test]
    fn format_duration_secs() {
        let d = std::time::Duration::from_millis(3200);
        assert_eq!(format_duration(d), "3.2s");
    }

    #[test]
    fn auto_copy_env_example_returns_status() {
        let dir = TempDir::new().unwrap();
        let example = dir.path().join(".env.example");
        fs::write(&example, "KEY=value\n").unwrap();

        let status = auto_copy_env_example(dir.path());
        assert_eq!(status, Some("created from .env.example".to_string()));
    }

    #[test]
    fn auto_copy_env_example_existing_returns_loaded() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "EXISTING=yes\n").unwrap();
        fs::write(dir.path().join(".env.example"), "KEY=value\n").unwrap();

        let status = auto_copy_env_example(dir.path());
        assert_eq!(status, Some(".env loaded".to_string()));
    }

    #[test]
    fn auto_copy_env_example_no_example_returns_none() {
        let dir = TempDir::new().unwrap();
        let status = auto_copy_env_example(dir.path());
        assert_eq!(status, None);
    }

    // ── compute_install_hash tests ───────────��─────────────────────────

    #[test]
    fn compute_install_hash_deterministic() {
        let h1 = compute_install_hash("pkg", "lock");
        let h2 = compute_install_hash("pkg", "lock");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_install_hash_different_inputs() {
        let h1 = compute_install_hash("pkg1", "lock");
        let h2 = compute_install_hash("pkg2", "lock");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_install_hash_different_lockfile() {
        let h1 = compute_install_hash("pkg", "lock-v1");
        let h2 = compute_install_hash("pkg", "lock-v2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_install_hash_is_hex_sha256() {
        let h = compute_install_hash("test", "data");
        // SHA-256 hex digest is always 64 hex chars
        assert_eq!(h.len(), 64, "expected 64-char hex digest, got {}", h.len());
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "hash should be hex: {h}"
        );
    }

    // ── needs_install tests ───────��──────────────────────────────────���─

    #[test]
    fn needs_install_no_package_json() {
        let dir = TempDir::new().unwrap();
        assert!(!needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_no_hash_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"test"}"#).unwrap();
        assert!(needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_hash_matches_but_no_node_modules() {
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::write(dir.path().join("lpm.lock"), "").unwrap();

        let hash = compute_install_hash(pkg, "");
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), &hash).unwrap();

        assert!(needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_hash_matches_with_node_modules() {
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::write(dir.path().join("lpm.lock"), "").unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();

        let hash = compute_install_hash(pkg, "");
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), &hash).unwrap();

        assert!(!needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_hash_mismatch() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"test","version":"2.0"}"#,
        )
        .unwrap();
        fs::write(dir.path().join("lpm.lock"), "").unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();

        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), "old_hash_value").unwrap();

        assert!(needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_missing_lockfile() {
        // Phase 34.1: the unified predicate now requires lockfile existence
        // (stronger semantics from install.rs). A missing lockfile means
        // deps aren't properly installed, so needs_install returns true.
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();

        let hash = compute_install_hash(pkg, "");
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), &hash).unwrap();

        assert!(needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_lockfile_changed() {
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();

        let old_hash = compute_install_hash(pkg, "old-lock-content");
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), &old_hash).unwrap();

        fs::write(dir.path().join("lpm.lock"), "new-lock-content").unwrap();

        assert!(needs_install(dir.path()).0);
    }

    // ── Finding #3: domain separator prevents ambiguous concatenation ──

    #[test]
    fn compute_install_hash_domain_separator() {
        // "ab" + "cd" must differ from "abc" + "d" — the null separator prevents collision
        let h1 = compute_install_hash("ab", "cd");
        let h2 = compute_install_hash("abc", "d");
        assert_ne!(
            h1, h2,
            "domain separator should prevent 'ab'+'cd' == 'abc'+'d'"
        );
    }

    // ── Finding #5: needs_install returns hash ──

    #[test]
    fn needs_install_returns_hash() {
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();

        let (stale, hash) = needs_install(dir.path());
        assert!(stale);
        assert!(
            hash.is_some(),
            "hash should be returned when package.json exists"
        );
        assert_eq!(hash.as_ref().unwrap().len(), 64, "should be SHA-256 hex");
    }

    #[test]
    fn needs_install_no_package_json_returns_none_hash() {
        let dir = TempDir::new().unwrap();
        let (stale, hash) = needs_install(dir.path());
        assert!(!stale);
        assert!(hash.is_none());
    }

    // ── Finding #1: should_open_browser logic ──

    #[test]
    fn should_open_browser_ready_and_allowed() {
        assert!(should_open_browser(true, false, false));
    }

    #[test]
    fn should_open_browser_not_ready() {
        assert!(!should_open_browser(false, false, false));
        assert!(!should_open_browser(false, true, false));
        assert!(!should_open_browser(false, false, true));
        assert!(!should_open_browser(false, true, true));
    }

    #[test]
    fn should_open_browser_no_open_flag() {
        assert!(!should_open_browser(true, true, false));
    }

    #[test]
    fn should_open_browser_ci_env() {
        assert!(!should_open_browser(true, false, true));
    }

    // ── convert_service_status tests ────────────────────────────────

    #[test]
    fn convert_pending_to_starting() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Pending);
        assert_eq!(result, lpm_dashboard::ServiceStatus::Starting);
    }

    #[test]
    fn convert_starting_to_starting() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Starting);
        assert_eq!(result, lpm_dashboard::ServiceStatus::Starting);
    }

    #[test]
    fn convert_ready() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Ready);
        assert_eq!(result, lpm_dashboard::ServiceStatus::Ready);
    }

    #[test]
    fn convert_crashed() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Crashed(1));
        assert_eq!(
            result,
            lpm_dashboard::ServiceStatus::Crashed("exit code 1".to_string())
        );
    }

    #[test]
    fn convert_waiting_for_dep() {
        let result = convert_service_status(
            &lpm_runner::orchestrator::ServiceStatus::WaitingForDep("db".to_string()),
        );
        assert_eq!(
            result,
            lpm_dashboard::ServiceStatus::WaitingForDep("db".to_string())
        );
    }

    #[test]
    fn convert_stopped() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Stopped);
        assert_eq!(result, lpm_dashboard::ServiceStatus::Stopped);
    }

    // ── Dashboard event bridge test ─────────────────────────────────

    #[test]
    fn orchestrator_events_bridge_to_dashboard_events() {
        use lpm_runner::orchestrator::OrchestratorEvent;

        let (dash_tx, dash_rx) = std::sync::mpsc::channel::<lpm_dashboard::DashboardEvent>();
        let (orch_tx, orch_rx) = std::sync::mpsc::channel::<OrchestratorEvent>();

        // Spawn the bridge thread (same pattern as dev.rs)
        let dash_tx_clone = dash_tx.clone();
        std::thread::spawn(move || {
            while let Ok(event) = orch_rx.recv() {
                let dash_event = match event {
                    OrchestratorEvent::ServiceLog {
                        service_index,
                        line,
                        ..
                    } => lpm_dashboard::DashboardEvent::ServiceLog {
                        index: service_index,
                        line,
                    },
                    OrchestratorEvent::StatusChange {
                        service_index,
                        status,
                    } => lpm_dashboard::DashboardEvent::StatusChange {
                        index: service_index,
                        status: convert_service_status(&status),
                    },
                };
                if dash_tx_clone.send(dash_event).is_err() {
                    break;
                }
            }
        });

        // Send orchestrator events
        orch_tx
            .send(OrchestratorEvent::ServiceLog {
                service_index: 0,
                line: "server started".to_string(),
                is_stderr: false,
            })
            .unwrap();
        orch_tx
            .send(OrchestratorEvent::StatusChange {
                service_index: 1,
                status: lpm_runner::orchestrator::ServiceStatus::Ready,
            })
            .unwrap();
        drop(orch_tx); // Close the channel

        // Verify dashboard receives converted events
        let event1 = dash_rx.recv().unwrap();
        match event1 {
            lpm_dashboard::DashboardEvent::ServiceLog { index, line } => {
                assert_eq!(index, 0);
                assert_eq!(line, "server started");
            }
            _ => panic!("expected ServiceLog"),
        }

        let event2 = dash_rx.recv().unwrap();
        match event2 {
            lpm_dashboard::DashboardEvent::StatusChange { index, status } => {
                assert_eq!(index, 1);
                assert_eq!(status, lpm_dashboard::ServiceStatus::Ready);
            }
            _ => panic!("expected StatusChange"),
        }
    }

    // ── Dashboard command bridge test ──────────────────────────────

    #[test]
    fn dashboard_command_bridge_forwards_restart_and_stop() {
        use lpm_runner::orchestrator::OrchestratorCommand;

        let (orch_cmd_tx, orch_cmd_rx) = std::sync::mpsc::channel::<OrchestratorCommand>();
        let (dash_cmd_tx, dash_cmd_rx) =
            std::sync::mpsc::channel::<lpm_dashboard::DashboardCommand>();

        // Spawn the bridge thread (same pattern as dev.rs)
        std::thread::spawn(move || {
            while let Ok(cmd) = dash_cmd_rx.recv() {
                let orch_cmd = match cmd {
                    lpm_dashboard::DashboardCommand::RestartService(idx) => {
                        OrchestratorCommand::RestartService(idx)
                    }
                    lpm_dashboard::DashboardCommand::StopService(idx) => {
                        OrchestratorCommand::StopService(idx)
                    }
                    lpm_dashboard::DashboardCommand::StopAll => OrchestratorCommand::StopAll,
                };
                if orch_cmd_tx.send(orch_cmd).is_err() {
                    break;
                }
            }
        });

        // Send commands from dashboard side
        dash_cmd_tx
            .send(lpm_dashboard::DashboardCommand::RestartService(2))
            .unwrap();
        dash_cmd_tx
            .send(lpm_dashboard::DashboardCommand::StopService(0))
            .unwrap();
        dash_cmd_tx
            .send(lpm_dashboard::DashboardCommand::StopAll)
            .unwrap();

        // Verify orchestrator receives them in order
        let cmd1 = orch_cmd_rx.recv().unwrap();
        assert!(
            matches!(cmd1, OrchestratorCommand::RestartService(2)),
            "first command should be RestartService(2)"
        );
        let cmd2 = orch_cmd_rx.recv().unwrap();
        assert!(
            matches!(cmd2, OrchestratorCommand::StopService(0)),
            "second command should be StopService(0)"
        );
        let cmd3 = orch_cmd_rx.recv().unwrap();
        assert!(
            matches!(cmd3, OrchestratorCommand::StopAll),
            "third command should be StopAll"
        );
    }

    #[test]
    fn webhook_event_forwarded_to_dashboard() {
        let (dash_tx, dash_rx) = std::sync::mpsc::channel::<lpm_dashboard::DashboardEvent>();

        let webhook = lpm_tunnel::webhook::CapturedWebhook {
            id: "wh-test".to_string(),
            timestamp: "2026-04-04T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/webhook".to_string(),
            request_headers: std::collections::HashMap::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: std::collections::HashMap::new(),
            response_body: Vec::new(),
            duration_ms: 42,
            provider: None,
            summary: "test".to_string(),
            signature_diagnostic: None,
            auto_acked: false,
        };

        // Send webhook event (same pattern as dev.rs consumer)
        dash_tx
            .send(lpm_dashboard::DashboardEvent::WebhookCaptured(Box::new(
                webhook,
            )))
            .unwrap();

        // Verify dashboard receives it
        let event = dash_rx.recv().unwrap();
        match event {
            lpm_dashboard::DashboardEvent::WebhookCaptured(wh) => {
                assert_eq!(wh.id, "wh-test");
                assert_eq!(wh.method, "POST");
                assert_eq!(wh.response_status, 200);
            }
            _ => panic!("expected WebhookCaptured"),
        }
    }
}
