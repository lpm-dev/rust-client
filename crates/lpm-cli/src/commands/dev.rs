use super::dev_ui;
use crate::install_ui;
use lpm_common::color::Painted;
use lpm_common::{LocalScheme, LocalTarget, LpmError};
use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

struct LocalProxyRuntime {
    lease: lpm_proxy::RouteLease,
    bridges: Vec<lpm_proxy::HttpProxyHandle>,
}

type ProxyLeaseSlot = Arc<Mutex<Option<LocalProxyRuntime>>>;

fn show_tunnel_notice(message: &str) {
    dev_ui::warn(message);
    if message.contains("not claimed") {
        dev_ui::hint_line("Run: lpm tunnel claim <domain>");
    } else if message.contains("Pro plan") || message.contains("plan_required") {
        dev_ui::hint_line("Upgrade at: https://lpm.dev/pricing");
    } else if message.contains("concurrent") {
        dev_ui::hint_line("Close other tunnels first, or upgrade your plan");
    }
}

struct DevCertSetup {
    setup: lpm_cert::HttpsSetup,
    inject_env: bool,
}

struct DevFrontends {
    local_target: LocalTarget,
    network_port: Option<u16>,
    handles: Vec<lpm_proxy::HttpProxyHandle>,
}

impl DevFrontends {
    fn update_child_target(&mut self, child_target: LocalTarget) -> Result<(), LpmError> {
        for handle in &self.handles {
            handle
                .update_upstream(child_target.clone())
                .map_err(|error| {
                    LpmError::Script(format!("update LPM dev frontend upstream: {error}"))
                })?;
        }
        if self.handles.is_empty() {
            self.local_target = child_target;
        } else {
            self.local_target.base_path = child_target.base_path;
        }
        Ok(())
    }
}

/// Build the consent value for `ensure_https_with_consent` based on the dev flags.
///
/// - `--yes` → PreApproved.
/// - Otherwise → Prompt(callback). The callback enforces the TTY requirement
///   only when consent is actually needed; if the CA is already trusted, the
///   callback is never invoked and non-TTY contexts proceed cleanly.
/// - The callback errors on decline so `lpm dev --https` aborts cleanly instead
///   of silently continuing with an untrusted cert (which would make the dev
///   server's HTTPS effectively useless).
fn build_consent(yes: bool) -> lpm_cert::TrustStoreConsent<'static> {
    if yes {
        return lpm_cert::TrustStoreConsent::PreApproved;
    }
    lpm_cert::TrustStoreConsent::Prompt(Box::new(|req| {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Cert(
                "non-interactive shell: pass `--yes` to consent to the trust-store install, or run `lpm cert trust` first".into(),
            ));
        }
        println!();
        println!(
            "  {}",
            "LPM needs to install a local Certificate Authority into your".bold()
        );
        println!(
            "  {}",
            "system trust store to serve trusted HTTPS for development.".bold()
        );
        println!();
        print_cert_prompt_field("Subject:", "LPM Local Development CA");
        print_cert_prompt_field("Fingerprint:", &req.fingerprint);
        print_cert_prompt_field("Expires:", &req.expires);
        print_cert_prompt_field("Permitted:", &req.permitted_names.join(", "));
        if !req.name_constraints_enabled {
            println!(
                "    {}",
                "Note: NameConstraints disabled — set LPM_CERT_NAME_CONSTRAINTS=1 to scope the CA"
                    .dimmed()
            );
        }
        println!();
        println!("  You can remove it at any time with `lpm cert uninstall`.");
        println!();
        let answer = cliclack::confirm("Install now?")
            .initial_value(false)
            .interact()
            .map_err(crate::prompt::prompt_err)?;
        if !answer {
            return Err(LpmError::Cert(
                "trust-store install declined; aborting `lpm dev --https`. Run `lpm cert trust` when you're ready, or pass `--yes` to skip the prompt.".into(),
            ));
        }
        Ok(true)
    }))
}

fn print_cert_prompt_field(label: &'static str, value: &str) {
    println!("{}", format_cert_prompt_field(label, value));
}

fn format_cert_prompt_field(label: &'static str, value: &str) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!("    {} {}", install_ui::dim(&format!("{label:<12}")), value,)
}

/// Run the `lpm dev` command with zero-config detection.
///
/// Auto-detects features from lpm.json: tunnel.domain, services.
/// Auto-installs dependencies if stale. Auto-copies .env.example.
/// Opens browser after services are ready.
///
/// `inspect_port`: `Some(n)` binds the inspector to that exact port and
/// fails loudly on `AddrInUse`. `None` auto-picks a free ephemeral port.
/// `no_inspect` skips the inspector entirely. All three are no-ops when
/// `tunnel` is false.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    detected_runtimes: Vec<lpm_runtime::detect::DetectedRuntimeVersion>,
    https: bool,
    tunnel: bool,
    network: bool,
    port: Option<u16>,
    host: Option<&str>,
    token: Option<&str>,
    tunnel_relay_url: Option<&str>,
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
    no_inspect: bool,
    inspect_port: Option<u16>,
    yes: bool,
    allow_ca_bootstrap: bool,
) -> Result<(), LpmError> {
    let mut extra_env: Vec<(String, String)> = Vec::new();

    let lpm_config = if let Some(cfg) = pre_parsed_config {
        Some(cfg)
    } else {
        lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?
    };
    let has_services = lpm_config.as_ref().is_some_and(|c| !c.services.is_empty());
    let requested_port = port;
    let port = resolve_dev_port(port, has_services);

    // Warn about privileged ports that may require elevated permissions
    if is_privileged_port(port) {
        dev_ui::warn(&format!(
            "Port {} is privileged. You may need elevated permissions (sudo) on Linux.",
            port
        ));
    }

    let local_domain_hostnames = lpm_config
        .as_ref()
        .map(lpm_runner::local_domains::configured_hostnames)
        .unwrap_or_default();
    let cert_extra_permitted_dns = lpm_config
        .as_ref()
        .map(lpm_runner::lpm_json::validated_cert_extra_permitted_dns)
        .transpose()
        .map_err(LpmError::Script)?
        .map(|entries| lpm_cert::name_constraints::dns_subtrees_from_entries(&entries))
        .unwrap_or_default();
    let startup_proxy_lines = lpm_config
        .as_ref()
        .map(startup_proxy_lines_from_config)
        .unwrap_or_default();
    if !local_domain_hostnames.is_empty() {
        ensure_local_proxy_running(project_dir).await?;
    }

    // ── Collect startup info for banner ─────────────────────────────
    let mut startup = StartupInfo {
        deps_status: String::new(),
        env_status: None,
        https_active: false,
        tunnel_url: None,
        tunnel_source: None,
        network_addr: None,
        node_version: None,
        inspector_url: None,
        proxy_lines: startup_proxy_lines,
    };

    // ── Run independent detection steps in parallel ──────────────────
    // Steps that can run concurrently:
    //   - auto_install_if_stale (async, potentially slow — runs `lpm install`)
    //   - auto_copy_env_example (sync file I/O — wrap in spawn_blocking)
    //   - HTTPS cert setup (sync, may generate certs — wrap in spawn_blocking)
    //   - ensure_detected_runtimes (async, may download node — potentially slow)
    //
    // Network display and tunnel setup depend on HTTPS result (cert env vars),
    // so they run after the parallel batch.

    let install_dir = project_dir.to_path_buf();
    let env_dir = project_dir.to_path_buf();
    let https_dir = project_dir.to_path_buf();
    let host_owned = host.map(|h| h.to_string());
    let local_display_host = host.unwrap_or("localhost").to_string();

    // Pre-compute network info once (used for both cert SANs and display)
    let network_info = if network {
        Some(lpm_network::get_network_info(port, https)?)
    } else {
        None
    };

    // Clone for the spawn_blocking closure (cert SANs need the IP list)
    let network_info_for_cert = network_info.clone();
    let local_domain_hostnames_for_cert = local_domain_hostnames.clone();
    let cert_extra_permitted_dns_for_cert = cert_extra_permitted_dns.clone();

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
    let dev_entrypoint_compatibility_bins = dev_entrypoint_compatibility_bins(project_dir);

    let (install_result, env_result, https_result, runtime_hint, node_version_result) = tokio::join!(
        async {
            if !no_install {
                auto_install_if_stale(client, &install_dir, &dev_entrypoint_compatibility_bins)
                    .await
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
            if https || !local_domain_hostnames_for_cert.is_empty() {
                let dir = https_dir.clone();
                let host_clone = host_owned.clone();
                let net_info = network_info_for_cert;
                let yes_local = yes;
                let inject_env = false;
                let setup = tokio::task::spawn_blocking(move || {
                    let mut extra_hostnames: Vec<String> = Vec::new();
                    if let Some(h) = host_clone {
                        push_unique_hostname(&mut extra_hostnames, h);
                    }
                    extend_unique_hostnames(&mut extra_hostnames, local_domain_hostnames_for_cert);
                    if let Some(ref info) = net_info {
                        for addr in &info.addresses {
                            if !addr.is_ipv6 {
                                push_unique_hostname(&mut extra_hostnames, addr.ip.clone());
                            }
                        }
                    }
                    let consent = build_consent(yes_local);
                    lpm_cert::ensure_https_with_consent_and_permitted_dns(
                        &dir,
                        &extra_hostnames,
                        &cert_extra_permitted_dns_for_cert,
                        consent,
                    )
                })
                .await
                .map_err(|e| LpmError::Script(format!("HTTPS setup panicked: {e}")))?;
                Ok::<_, LpmError>(Some(DevCertSetup {
                    setup: setup?,
                    inject_env,
                }))
            } else {
                Ok::<_, LpmError>(None)
            }
        },
        async { super::run::ensure_detected_runtimes(detected_runtimes).await },
        async { node_version_handle.await.unwrap_or(None) },
    );

    // Process parallel results
    startup.deps_status = install_result?;
    startup.env_status = env_result;
    startup.node_version = node_version_result;

    let https_setup: Option<DevCertSetup> = https_result?;
    if let Some(cert_setup) = https_setup {
        let setup = cert_setup.setup;
        if setup.ca_freshly_installed {
            dev_ui::done("root CA generated and installed to trust store");
        }
        if setup.cert_freshly_generated {
            dev_ui::done("project certificate generated");
        }
        if cert_setup.inject_env {
            extra_env.extend(setup.env_vars);
        }
    }
    startup.https_active = https;

    // The public HMR hostname can differ from the loopback child endpoint.
    if let Some(ref net_info) = network_info
        && let Some(ref primary) = net_info.primary
    {
        let framework = lpm_cert::framework::detect_framework(project_dir);
        if framework == lpm_cert::framework::Framework::Vite {
            extra_env.push(("VITE_HMR_HOST".to_string(), primary.ip.clone()));
        }
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
    let mut tunnel_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>> = None;
    let mut capture_consumer_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut inspector_handle: Option<lpm_inspect::InspectorHandle> = None;
    let mut multi_inspector_state = None;
    let (mut multi_tunnel_target_tx, mut multi_tunnel_target_rx) = if tunnel && has_services {
        let (tx, rx) = tokio::sync::oneshot::channel::<LocalTarget>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let multi_tunnel_live_target = (tunnel && has_services)
        .then(|| Arc::new(RwLock::new(LocalTarget::loopback(LocalScheme::Http, port))));
    if tunnel && has_services {
        let token = token.ok_or_else(|| {
            LpmError::Tunnel("authentication required for tunnel. Run `lpm login` first.".into())
        })?;

        // Tunnel source for banner (resolved in main.rs: "lpm.json", "--domain", "--tunnel")
        startup.tunnel_source = tunnel_source.map(|s| s.to_string());

        // Proactive guidance for configured domains
        if let Some(domain) = tunnel_domain
            && !quiet
        {
            dev_ui::trusted_detail("Tunnel domain", &install_ui::cyan(domain));
        }

        // ── Inspector startup (paired with tunnel) ──────────────────
        // The browser inspector is the same surface as `lpm tunnel
        // inspect --ui` — real-time webhook capture, replay, snapshots.
        // It runs alongside the dashboard's webhook tab (which is
        // text-only) so the user can pick whichever fits the moment.
        // Quiet by default — we never auto-open a browser tab here.
        let inspector_db = lpm_inspect::db::InspectorDb::open(project_dir).map_err(|error| {
            LpmError::Tunnel(format!(
                "failed to open this project's .lpm/inspector.db: {error}. \
                 Repair or move the corrupt database and retry"
            ))
        })?;
        let inspector_state = lpm_inspect::state::InspectorState::with_db_pending(inspector_db);
        multi_inspector_state = Some(inspector_state.clone());
        if !no_inspect {
            // `Some(n)` → strict bind, fatal on AddrInUse (matches the
            // `--inspect-port N` user contract). `None` → auto-pick a
            // free ephemeral port; failure is best-effort.
            let (port_to_bind, strict) = match inspect_port {
                Some(n) => (n, true),
                None => (0, false),
            };
            match lpm_inspect::start(inspector_state.clone(), port_to_bind).await {
                Ok(handle) => {
                    startup.inspector_url = Some(handle.url.clone());
                    inspector_handle = Some(handle);
                }
                Err(e) if strict => return Err(e),
                Err(e) => {
                    if !quiet {
                        dev_ui::warn(&format!("inspector failed to start: {e}"));
                    }
                }
            }
        }

        // Create webhook capture channel.
        let (webhook_tx, mut webhook_rx) =
            tokio::sync::mpsc::unbounded_channel::<lpm_tunnel::webhook::CapturedWebhook>();

        tracing::warn!(
            target: "lpm_cli::dev",
            "tunnel webhook capture persists full request/response bodies and headers \
             (incl. Authorization, Cookie, *-Signature) in .lpm/inspector.db — the \
             database is 0o600 locally but survives commits / backups / IDE indexing. \
             Add `.lpm/inspector.db*` to .gitignore if you haven't already."
        );
        if !quiet {
            dev_ui::warn(
                "tunnel webhook capture persists full request/response bodies and headers \
                 in .lpm/inspector.db. Add `.lpm/inspector.db*` to .gitignore.",
            );
        }

        // Dashboard webhook channel: when --dashboard is active, webhooks are
        // forwarded to the dashboard TUI via a std::sync channel.
        let dashboard_webhook_tx: Option<std::sync::mpsc::Sender<lpm_dashboard::DashboardEvent>> =
            dashboard_event_tx.clone();

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
            relay_url: tunnel_relay_url.map_or_else(lpm_tunnel::resolve_relay_url, str::to_owned),
            token: token.to_string(),
            local_target: LocalTarget::loopback(LocalScheme::Http, port),
            live_local_target: None,
            domain: tunnel_domain.map(|s| s.to_string()),
            tunnel_auth: tunnel_auth_token.clone(),
            webhook_tx: Some(webhook_tx),
            no_pin: false,
            auto_ack: false,
            ws_tx: None,
        };

        let inspector_state_for_consumer = inspector_state.clone();
        capture_consumer_handle = Some(tokio::spawn(async move {
            while let Some(webhook) = webhook_rx.recv().await {
                inspector_state_for_consumer.push(webhook.clone()).await;

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

                install_ui::detail_line(format_dev_webhook_line(
                    &webhook.method,
                    &webhook.path,
                    webhook.response_status,
                    webhook.duration_ms,
                    &webhook.summary,
                ));

                // Show signature diagnostic if present
                if let Some(ref diag) = webhook.signature_diagnostic {
                    install_ui::detail_line(crate::install_ui::terminal_line!(
                        "           {} {}",
                        install_ui::yellow("!"),
                        lpm_common::sanitize_for_terminal(diag)
                    ));
                }
            }
        }));

        // Start tunnel in background task, storing the handle for clean shutdown
        let mut options_clone = options;
        let live_local_target = multi_tunnel_live_target.clone().ok_or_else(|| {
            LpmError::Tunnel("multi-service tunnel live endpoint was not initialized".to_string())
        })?;
        let target_rx = multi_tunnel_target_rx.take().ok_or_else(|| {
            LpmError::Tunnel(
                "multi-service tunnel endpoint channel was not initialized".to_string(),
            )
        })?;
        let tunnel_auth_display = tunnel_auth_token;
        // Mirror commands/tunnel.rs: hand the connect callback a clone of the
        // inspector state so the live tunnel URL + session id are pushed to
        // the inspector UI as soon as the relay returns ServerHello.
        let inspector_state_for_connect = inspector_state.clone();
        let latest_usage = Arc::new(Mutex::new(None::<lpm_tunnel::TunnelUsageMetadata>));
        let usage_for_connect = latest_usage.clone();
        let usage_for_notices = latest_usage;
        tunnel_handle = Some(tokio::spawn(async move {
            let Ok(local_target) = target_rx.await else {
                return;
            };
            let local_target_url = local_target.url();
            options_clone.local_target = local_target.clone();
            *live_local_target
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = local_target;
            options_clone.live_local_target = Some(live_local_target);
            let result = lpm_tunnel::client::connect_with_usage(
                &options_clone,
                move |session| {
                    let url = session.tunnel_url.clone();
                    let session_id = session.session_id.clone();
                    let domain = Some(session.domain.clone());
                    let local = session.local_port;
                    let state = inspector_state_for_connect.clone();
                    state.start_session_immediate(session_id, domain, local, None);
                    tokio::spawn(async move {
                        state.set_tunnel_url(url).await;
                    });

                    dev_ui::trusted_detail_line(
                        "Tunnel",
                        install_ui::terminal_line!(
                            "{} → {}",
                            install_ui::url(&session.tunnel_url),
                            local_target_url,
                        ),
                    );
                    if let Some(expiry) =
                        crate::commands::tunnel::tunnel_session_expiry_summary(session)
                    {
                        dev_ui::hint_line(&format!("Tunnel expires {expiry}"));
                    }
                    if let Some(limits) =
                        crate::commands::tunnel::tunnel_limit_summary(session.limits.as_ref())
                    {
                        dev_ui::hint_line(&format!("Tunnel limits: {limits}"));
                    }
                    let usage = usage_for_connect
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    if let Some(usage) =
                        crate::commands::tunnel::tunnel_usage_summary(usage.as_ref())
                    {
                        dev_ui::hint_line(&format!("Tunnel usage: {usage}"));
                    }
                    if let Some(ref auth) = tunnel_auth_display {
                        dev_ui::hint_line(&format!(
                            "Auth required: add header X-Tunnel-Auth: {auth}"
                        ));
                        dev_ui::hint_line(&format!(
                            "Browser: {}?__tunnel_auth={auth}",
                            session.tunnel_url
                        ));
                    }
                },
                show_tunnel_notice,
                move |usage, initial| {
                    *usage_for_notices
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(usage.clone());
                    if !initial
                        && let Some(summary) =
                            crate::commands::tunnel::tunnel_usage_summary(Some(usage))
                    {
                        show_tunnel_notice(&format!("Tunnel usage: {summary}"));
                    }
                },
            )
            .await;
            if let Err(error) = result {
                show_tunnel_notice(&format!("Tunnel failed: {error}"));
            }
        }));
    }

    // ── Check for multi-service orchestration ──────────────────────────
    if has_services {
        print_startup_banner(&startup, project_dir);
        let config = lpm_config.as_ref().ok_or_else(|| {
            LpmError::Script("multi-service configuration disappeared before startup".to_string())
        })?;
        let services = &config.services;
        let primary_service = primary_proxy_service_for_display(config).map(str::to_string);
        if primary_service.is_none() && (requested_port.is_some() || https || network || tunnel) {
            return Err(LpmError::Script(
                "multi-service dev features require exactly one service marked `primary`"
                    .to_string(),
            ));
        }
        let open_browser = primary_service.is_some() && should_open_browser(true, no_open, is_ci());
        let frontend_slot = Arc::new(Mutex::new(None::<DevFrontends>));
        let dev_session_slot =
            Arc::new(Mutex::new(None::<lpm_runner::dev_session::DevSessionLease>));
        let service_endpoint_slot = Arc::new(Mutex::new(
            lpm_runner::orchestrator::ServiceEndpointMap::new(),
        ));
        let multi_started = std::time::Instant::now();

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

        let proxy_lease = Arc::new(Mutex::new(None));
        let dashboard_ports_tx = dashboard_event_tx.clone();
        let on_ports_assigned = dashboard_ports_tx.map(|tx| {
            Box::new(move |ports: &lpm_runner::orchestrator::ServicePortMap| {
                for (service, port) in ports {
                    let _ = tx.send(lpm_dashboard::DashboardEvent::PortAssigned {
                        service: service.clone(),
                        port: *port,
                    });
                }
                Ok(())
            }) as lpm_runner::orchestrator::PortsAssignedCallback
        });

        let manage_primary_endpoint = primary_service.is_some();
        let register_local_proxy = !local_domain_hostnames.is_empty();
        let on_all_ready = (manage_primary_endpoint || register_local_proxy).then(|| {
            let primary_service = primary_service.clone();
            let project_dir = project_dir.to_path_buf();
            let proxy_config = config.clone();
            let proxy_lease = Arc::clone(&proxy_lease);
            let runtime_handle = tokio::runtime::Handle::current();
            let frontend_slot = Arc::clone(&frontend_slot);
            let dev_session_slot = Arc::clone(&dev_session_slot);
            let inspector_state = multi_inspector_state.clone();
            let tunnel_target_tx = multi_tunnel_target_tx.take();
            let tunnel_live_target = multi_tunnel_live_target.clone();
            let local_display_host = local_display_host.clone();
            let service_endpoint_slot = Arc::clone(&service_endpoint_slot);
            Box::new(
                move |mut endpoints: lpm_runner::orchestrator::ServiceEndpointMap| {
                    *service_endpoint_slot.lock().map_err(|_| {
                        LpmError::Script("service endpoint state is poisoned".to_string())
                    })? = endpoints.clone();
                    if register_local_proxy {
                        let final_targets = endpoints
                            .iter()
                            .map(|(service, endpoint)| {
                                (service.clone(), endpoint.target.clone())
                            })
                            .collect();
                        let plan = lpm_runner::local_domains::plan_multi_service_routes(
                            &proxy_config,
                            &final_targets,
                        )
                        .map_err(LpmError::Script)?;
                        runtime_handle.block_on(register_proxy_route_plan(
                            &project_dir,
                            plan.routes,
                            Arc::clone(&proxy_lease),
                        ))?;
                    }

                    let Some(primary_service) = primary_service else {
                        return Ok(());
                    };
                    let endpoint = endpoints.remove(&primary_service).ok_or_else(|| {
                        LpmError::Script(format!(
                            "primary service `{primary_service}` did not open its assigned local endpoint"
                        ))
                    })?;
                    let child_target = endpoint.target;
                    let active_frontends = runtime_handle.block_on(
                        start_single_service_frontends(
                            &project_dir,
                            child_target.clone(),
                            endpoint.owner_pid,
                            https,
                            network,
                            requested_port,
                        ),
                    )?;
                    let local_target = active_frontends.local_target.clone();

                    if let Some(network_port) = active_frontends.network_port {
                        let network_info =
                            lpm_network::get_network_info(network_port, local_target.scheme == LocalScheme::Https)?;
                        runtime_handle.block_on(display_network_access(
                            &network_info,
                            network_port,
                            local_target.scheme == LocalScheme::Https,
                            &local_target.base_path,
                            allow_ca_bootstrap,
                        ))?;
                    }

                    let local_url = format!(
                        "{}://{}:{}{}",
                        local_target.scheme,
                        local_display_host,
                        local_target.port,
                        local_target.base_path
                    );
                    dev_ui::trusted_detail("Local", &install_ui::url(&local_url));
                    dev_ui::blank_line();
                    dev_ui::done_ready("Local server", multi_started.elapsed());

                    if let Some(ref state) = inspector_state {
                        state.set_local_target(child_target.clone());
                    }
                    if let Some(ref target) = tunnel_live_target {
                        *target
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                            child_target.clone();
                    }
                    let session_lease = lpm_runner::dev_session::DevSessionLease::register(
                        &project_dir,
                        child_target.clone(),
                        endpoint.owner_pid,
                        Some(primary_service.clone()),
                    )?;
                    *dev_session_slot.lock().map_err(|_| {
                        LpmError::Script("dev session state is poisoned".to_string())
                    })? = Some(session_lease);
                    *frontend_slot.lock().map_err(|_| {
                        LpmError::Script("dev frontend state is poisoned".to_string())
                    })? = Some(active_frontends);

                    if let Some(sender) = tunnel_target_tx {
                        sender.send(child_target).map_err(|_| {
                            LpmError::Tunnel(
                                "tunnel stopped before the primary service became ready".to_string(),
                            )
                        })?;
                    }
                    if open_browser {
                        let _ = open::that(local_url);
                    }
                    Ok(())
                },
            ) as lpm_runner::orchestrator::AllReadyCallback
        });

        let on_endpoint_changed = (manage_primary_endpoint || register_local_proxy).then(|| {
            let primary_service = primary_service.clone();
            let project_dir = project_dir.to_path_buf();
            let proxy_config = config.clone();
            let proxy_lease = Arc::clone(&proxy_lease);
            let runtime_handle = tokio::runtime::Handle::current();
            let frontend_slot = Arc::clone(&frontend_slot);
            let dev_session_slot = Arc::clone(&dev_session_slot);
            let service_endpoint_slot = Arc::clone(&service_endpoint_slot);
            let inspector_state = multi_inspector_state.clone();
            let tunnel_live_target = multi_tunnel_live_target.clone();
            Box::new(move |endpoint: lpm_runner::dev_endpoint::DevEndpoint| {
                let service = endpoint.service.clone().ok_or_else(|| {
                    LpmError::Script(
                        "restarted service endpoint is missing its service name".to_string(),
                    )
                })?;
                let final_targets = {
                    let mut endpoints = service_endpoint_slot.lock().map_err(|_| {
                        LpmError::Script("service endpoint state is poisoned".to_string())
                    })?;
                    endpoints.insert(service.clone(), endpoint.clone());
                    endpoints
                        .iter()
                        .map(|(name, endpoint)| (name.clone(), endpoint.target.clone()))
                        .collect()
                };

                if register_local_proxy {
                    let plan = lpm_runner::local_domains::plan_multi_service_routes(
                        &proxy_config,
                        &final_targets,
                    )
                    .map_err(LpmError::Script)?;
                    runtime_handle.block_on(replace_proxy_route_plan(
                        &project_dir,
                        plan.routes,
                        Arc::clone(&proxy_lease),
                    ))?;
                }

                if primary_service.as_deref() != Some(service.as_str()) {
                    return Ok(());
                }

                frontend_slot
                    .lock()
                    .map_err(|_| LpmError::Script("dev frontend state is poisoned".to_string()))?
                    .as_mut()
                    .ok_or_else(|| {
                        LpmError::Script("dev frontend state is not initialized".to_string())
                    })?
                    .update_child_target(endpoint.target.clone())?;
                if let Some(ref state) = inspector_state {
                    state.set_local_target(endpoint.target.clone());
                }
                if let Some(ref target) = tunnel_live_target {
                    *target
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = endpoint.target.clone();
                }

                let session_lease = lpm_runner::dev_session::DevSessionLease::register(
                    &project_dir,
                    endpoint.target,
                    endpoint.owner_pid,
                    Some(service),
                )?;
                *dev_session_slot
                    .lock()
                    .map_err(|_| LpmError::Script("dev session state is poisoned".to_string()))? =
                    Some(session_lease);
                Ok(())
            }) as lpm_runner::orchestrator::EndpointChangedCallback
        });

        let options = lpm_runner::orchestrator::OrchestratorOptions {
            https: false,
            filter: extra_args.to_vec(), // lpm dev web api → filter to web + api
            extra_envs: extra_env.clone(),
            event_tx: orchestrator_event_tx,
            command_rx: orch_cmd_rx,
            on_ports_assigned,
            on_all_ready,
            on_endpoint_changed,
            primary_port: requested_port.filter(|_| !https),
            manage_primary_endpoint,
            reserved_frontend_port: requested_port.filter(|_| https),
        };

        let hosts_file_lease = prepare_local_hosts_file(project_dir, &local_domain_hostnames, yes)?;

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
            let dashboard_failure_tx = dashboard_event_tx.clone();
            let orch_handle = std::thread::spawn(move || {
                let result = lpm_runner::orchestrator::run_services(
                    &project_dir_owned,
                    &services_owned,
                    options,
                );
                if let Err(error) = &result
                    && let Some(tx) = dashboard_failure_tx
                {
                    let _ = tx.send(lpm_dashboard::DashboardEvent::FatalError(error.to_string()));
                }
                result
            });

            // Dashboard → orchestrator command bridge
            let orch_cmd_tx = orch_cmd_tx.ok_or_else(|| {
                LpmError::Script("dashboard command channel was not initialized".to_string())
            })?;
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
                        hosts: dashboard_service_hosts(config, name),
                        status: lpm_dashboard::ServiceStatus::Starting,
                        logs: lpm_dashboard::LogBuffer::new(5000),
                    }
                })
                .collect();

            // Signal the orchestrator to shut down and preserve its result after
            // the dashboard exits.
            let graceful_shutdown = move || {
                let _ = orch_cmd_tx_for_shutdown
                    .send(lpm_runner::orchestrator::OrchestratorCommand::StopAll);
                orch_handle.join().unwrap_or_else(|_| {
                    Err(LpmError::Script(
                        "service orchestrator panicked".to_string(),
                    ))
                })
            };

            let inspector_url_for_dashboard = inspector_handle.as_ref().map(|h| h.url.clone());

            let dashboard_result = if let Some(rx) = dashboard_event_rx {
                lpm_dashboard::run_dashboard(
                    dashboard_services,
                    rx,
                    Some(dash_cmd_tx),
                    inspector_url_for_dashboard,
                )
                .map(|_| ())
                .map_err(|error| LpmError::Script(error.to_string()))
            } else {
                Ok(())
            };
            let result = graceful_shutdown().and(dashboard_result);

            let result = release_multi_service_runtime(result, &frontend_slot, &dev_session_slot);
            let result = release_proxy_lease_after(result, &proxy_lease).await;
            let result = release_hosts_file_after(result, hosts_file_lease);

            return shutdown_multi_service_tunnel_after(
                result,
                tunnel_handle,
                capture_consumer_handle,
                multi_inspector_state,
                inspector_handle,
            )
            .await;
        }

        let result = lpm_runner::orchestrator::run_services(project_dir, services, options);
        let result = release_multi_service_runtime(result, &frontend_slot, &dev_session_slot);
        let result = release_proxy_lease_after(result, &proxy_lease).await;
        let result = release_hosts_file_after(result, hosts_file_lease);
        return shutdown_multi_service_tunnel_after(
            result,
            tunnel_handle,
            capture_consumer_handle,
            multi_inspector_state,
            inspector_handle,
        )
        .await;
    }

    // ── Single service: start dev server ────────────────────────────
    let proxy_lease = Arc::new(Mutex::new(None));
    let hosts_file_lease = prepare_local_hosts_file(project_dir, &local_domain_hostnames, yes)?;
    let mut script_env = extra_env.clone();
    let child_requested_port = requested_port.filter(|_| !https);
    let child_port_hint = if https {
        find_internal_dev_port(port)?
    } else {
        port
    };
    upsert_extra_env(&mut script_env, "PORT", child_port_hint.to_string());
    let mut script_args = extra_args.to_vec();
    if let Some(requested_port) = child_requested_port {
        let command = lpm_runner::script::script_command(project_dir, "dev")?;
        script_args.extend(lpm_cert::framework::explicit_port_args_for_command(
            project_dir,
            &command,
            requested_port,
        ));
    }

    let (endpoint_tx, endpoint_rx) = tokio::sync::oneshot::channel();
    let script_project_dir = project_dir.to_path_buf();
    let script_env_mode = env_mode.map(str::to_string);
    let script_runtime_hint = runtime_hint.clone();
    let startup_started = std::time::Instant::now();
    let script_stop_requested = Arc::new(AtomicBool::new(false));
    let script_stop_for_runner = Arc::clone(&script_stop_requested);
    let mut script_handle = tokio::task::spawn_blocking(move || {
        lpm_runner::script::run_dev_script_with_envs(
            &script_project_dir,
            &script_args,
            script_env_mode.as_deref(),
            &script_env,
            &script_runtime_hint,
            lpm_runner::script::DevScriptEndpointOptions {
                requested_port: child_requested_port,
                stop_requested: script_stop_for_runner,
                on_endpoint: Box::new(move |result| {
                    let _ = endpoint_tx.send(result);
                }),
            },
        )
    });

    let endpoint_result = tokio::select! {
        endpoint = endpoint_rx => endpoint.ok(),
        script_result = &mut script_handle => {
            let script_result = script_result
                .map_err(|error| LpmError::Script(format!("dev script task panicked: {error}")))?;
            let result = release_proxy_lease_after(script_result, &proxy_lease).await;
            return release_hosts_file_after(result, hosts_file_lease);
        }
    };

    let endpoint = match endpoint_result {
        Some(Ok(Some(endpoint))) => Some(endpoint),
        Some(Ok(None)) | None => None,
        Some(Err(error)) => {
            let _ = script_handle.await;
            let result =
                release_proxy_lease_after(Err(LpmError::Script(error)), &proxy_lease).await;
            return release_hosts_file_after(result, hosts_file_lease);
        }
    };

    let setup_result = async {
        let mut frontends = None;
        let mut dev_session_lease = None;
        if let Some(endpoint) = endpoint {
            let endpoint_owner_pid = endpoint.owner_pid;
            let child_target = endpoint.target;
            let active_frontends = start_single_service_frontends(
                project_dir,
                child_target.clone(),
                endpoint_owner_pid,
                https,
                network,
                requested_port,
            )
            .await?;
            let target = active_frontends.local_target.clone();
            if tunnel {
                let tunnel_token = token
                    .ok_or_else(|| {
                        LpmError::Tunnel(
                            "authentication required for tunnel. Run `lpm login` first.".into(),
                        )
                    })?
                    .to_string();
                let tunnel_project_dir = project_dir.to_path_buf();
                let tunnel_domain = tunnel_domain.map(str::to_string);
                let tunnel_relay_url = tunnel_relay_url.map(str::to_string);
                let tunnel_target = child_target.clone();
                let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
                tunnel_shutdown_tx = Some(shutdown_tx);
                startup.tunnel_source = tunnel_source.map(str::to_string);
                if let Some(domain) = tunnel_domain.as_deref()
                    && !quiet
                {
                    dev_ui::trusted_detail("Tunnel domain", &install_ui::cyan(domain));
                }
                tunnel_handle = Some(tokio::spawn(async move {
                    let result = crate::commands::tunnel::run_start(
                        Some(&tunnel_token),
                        tunnel_target,
                        tunnel_domain.as_deref(),
                        false,
                        &tunnel_project_dir,
                        tunnel_auth,
                        no_inspect,
                        inspect_port,
                        false,
                        None,
                        tunnel_relay_url.as_deref(),
                        Some(shutdown_rx),
                    )
                    .await;
                    if let Err(error) = result {
                        show_tunnel_notice(&format!("Tunnel failed: {error}"));
                    }
                }));
            }
            if let Some(network_port) = active_frontends.network_port {
                let current_network_info = lpm_network::get_network_info(network_port, https)?;
                startup.network_addr = display_network_access(
                    &current_network_info,
                    network_port,
                    https,
                    &target.base_path,
                    allow_ca_bootstrap,
                )
                .await?;
            }
            print_startup_banner(&startup, project_dir);
            let url = format!(
                "{}://{}:{}{}",
                target.scheme, local_display_host, target.port, target.base_path
            );
            dev_ui::trusted_detail("Local", &install_ui::url(&url));
            dev_ui::blank_line();
            dev_ui::done_ready("Local server", startup_started.elapsed());

            if let Some(config) = lpm_config.as_ref()
                && let Some(plan) = lpm_runner::local_domains::plan_single_service_route(
                    config,
                    child_target.clone(),
                )
            {
                register_proxy_route_plan(project_dir, plan.routes, Arc::clone(&proxy_lease))
                    .await?;
            }

            dev_session_lease = Some(lpm_runner::dev_session::DevSessionLease::register(
                project_dir,
                child_target,
                endpoint_owner_pid,
                None,
            )?);
            if should_open_browser(true, no_open, is_ci()) {
                let _ = open::that(&url);
            }
            frontends = Some(active_frontends);
        } else {
            print_startup_banner(&startup, project_dir);
        }
        Ok::<_, LpmError>((frontends, dev_session_lease))
    }
    .await;

    let (frontends, dev_session_lease) = match setup_result {
        Ok(runtime) => runtime,
        Err(error) => {
            script_stop_requested.store(true, Ordering::Release);
            let _ = script_handle.await;
            let result = release_proxy_lease_after(Err(error), &proxy_lease).await;
            let result = release_hosts_file_after(result, hosts_file_lease);
            shutdown_spawned_tunnel(tunnel_handle.take(), tunnel_shutdown_tx.take()).await;
            if let Some(handle) = inspector_handle.take() {
                handle.shutdown();
            }
            return result;
        }
    };

    let script_result = script_handle
        .await
        .map_err(|error| LpmError::Script(format!("dev script task panicked: {error}")))?;
    drop(frontends);
    drop(dev_session_lease);
    let result = release_proxy_lease_after(script_result, &proxy_lease).await;
    let result = release_hosts_file_after(result, hosts_file_lease);

    // Clean shutdown: tunnel first, then inspector (lets in-flight webhook
    // pushes drain into the inspector state before the server closes).
    shutdown_spawned_tunnel(tunnel_handle, tunnel_shutdown_tx).await;
    if let Some(handle) = inspector_handle {
        handle.shutdown();
    }

    result
}

fn startup_proxy_lines_from_config(
    config: &lpm_runner::lpm_json::LpmJsonConfig,
) -> Vec<StartupProxyLine> {
    let mut lines = Vec::new();

    if config.services.is_empty() {
        if let Some(host) = config.proxy.as_ref().and_then(|proxy| proxy.host.as_ref()) {
            push_startup_proxy_line(&mut lines, host, None);
        }
        return lines;
    }

    let mut service_names: Vec<&String> = config.services.keys().collect();
    service_names.sort();
    for service_name in service_names {
        let service = &config.services[service_name];
        if let Some(host) = service.host.as_ref() {
            push_startup_proxy_line(&mut lines, host, Some(service_name.clone()));
        }
    }

    if let Some(host) = config.proxy.as_ref().and_then(|proxy| proxy.host.as_ref()) {
        match primary_proxy_service_for_display(config) {
            Some(service_name) => {
                if config.services.contains_key(service_name) {
                    push_startup_proxy_line(&mut lines, host, Some(service_name.to_string()));
                }
            }
            None => lines.push(StartupProxyLine {
                host: host.clone(),
                target: "primary service required".to_string(),
                service: None,
            }),
        }
    }

    lines
}

fn dashboard_service_hosts(
    config: &lpm_runner::lpm_json::LpmJsonConfig,
    service_name: &str,
) -> Vec<String> {
    let mut hosts = Vec::new();
    if let Some(service) = config.services.get(service_name)
        && let Some(host) = service.host.as_ref()
    {
        push_unique_hostname(&mut hosts, host.clone());
    }
    if let Some(proxy_host) = config.proxy.as_ref().and_then(|proxy| proxy.host.as_ref())
        && primary_proxy_service_for_display(config) == Some(service_name)
    {
        push_unique_hostname(&mut hosts, proxy_host.clone());
    }
    hosts
}

fn primary_proxy_service_for_display(config: &lpm_runner::lpm_json::LpmJsonConfig) -> Option<&str> {
    let mut primary = config
        .services
        .iter()
        .filter(|(_, service)| service.primary)
        .map(|(name, _)| name.as_str());
    if let Some(name) = primary.next() {
        return primary.next().is_none().then_some(name);
    }

    if config.services.len() == 1 {
        return config.services.keys().next().map(String::as_str);
    }

    None
}

fn push_startup_proxy_line(lines: &mut Vec<StartupProxyLine>, host: &str, service: Option<String>) {
    if lines
        .iter()
        .any(|line| line.host.eq_ignore_ascii_case(host))
    {
        return;
    }
    lines.push(StartupProxyLine {
        host: host.to_string(),
        target: "resolving endpoint".to_string(),
        service,
    });
}

async fn ensure_local_proxy_running(project_dir: &Path) -> Result<(), LpmError> {
    let status = match lpm_proxy::status().await {
        Ok(status) if status.running => status,
        Ok(_) => {
            let start = crate::commands::proxy::ensure_detached_started_for_project(project_dir)
                .await
                .map_err(|err| {
                    LpmError::Script(format!(
                        "local proxy auto-start failed: {err}. Start it with `{}` before using `host` in lpm.json.",
                        local_proxy_https_start_command()
                    ))
                })?;
            if start.started {
                dev_ui::done("local proxy control daemon started in the background");
            }
            start.status
        }
        Err(err) => {
            return Err(LpmError::Script(format!(
                "local proxy status check failed: {err}"
            )));
        }
    };

    if status.running && status.tls_addr.is_some() {
        return Ok(());
    }

    let listener_hint = if status.http_addr.is_some() {
        " A plain HTTP listener is not enough for the HTTPS local-domain front door."
    } else {
        ""
    };
    Err(LpmError::Script(format!(
        "local proxy is running without an HTTPS listener.{listener_hint} Restart it with `{}` before using `host` in lpm.json.",
        local_proxy_https_start_command()
    )))
}

fn prepare_local_hosts_file(
    project_dir: &Path,
    hostnames: &[String],
    yes: bool,
) -> Result<Option<lpm_runner::local_domains::ManagedHostsFile>, LpmError> {
    let Some(plan) = lpm_runner::local_domains::plan_hosts_file_update(project_dir, hostnames)
        .map_err(|err| LpmError::Script(format!("local hosts file planning failed: {err}")))?
    else {
        return Ok(None);
    };

    confirm_hosts_file_update(&plan, yes)?;
    let lease = crate::commands::hosts::apply_hosts_file_plan_with_permission(&plan).map_err(|err| {
        LpmError::Script(format!(
            "local hosts file update failed for {}: {err}. Run `lpm dev` with permission to edit the hosts file (sudo on Unix, Administrator on Windows), or use `.localhost` hosts that do not need a hosts-file entry.",
            plan.path.display()
        ))
    })?;
    if lease.changed() {
        dev_ui::done("hosts file updated for local domains");
    }
    Ok(Some(lease))
}

fn confirm_hosts_file_update(
    plan: &lpm_runner::local_domains::HostsFilePlan,
    yes: bool,
) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Script(format!(
            "non-interactive shell: pass `--yes` to consent to updating the hosts file for local domains ({})",
            plan.hosts.join(", ")
        )));
    }

    println!();
    println!(
        "  {}",
        "LPM needs to update your hosts file for local domains.".bold()
    );
    println!();
    print_cert_prompt_field("Hosts file:", &plan.path.display().to_string());
    print_cert_prompt_field("Backup:", &plan.backup_path.display().to_string());
    print_cert_prompt_field("Hosts:", &plan.hosts.join(", "));
    println!();
    let answer = cliclack::confirm("Update hosts file now?")
        .initial_value(false)
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    if !answer {
        return Err(LpmError::Script(
            "hosts file update declined; aborting `lpm dev`. Use `.localhost` hosts, or pass `--yes` when you're ready.".into(),
        ));
    }
    Ok(())
}

async fn register_proxy_route_plan(
    project_dir: &Path,
    routes: Vec<lpm_runner::local_domains::LocalDomainRoute>,
    proxy_lease: ProxyLeaseSlot,
) -> Result<(), LpmError> {
    if routes.is_empty() {
        return Ok(());
    }

    let (proxy_routes, bridges) = prepare_proxy_routes(project_dir, &routes).await?;
    let lease = register_proxy_routes(proxy_routes.clone()).await?;
    store_proxy_lease(proxy_lease, LocalProxyRuntime { lease, bridges })?;
    print_registered_proxy_routes(&routes);
    Ok(())
}

async fn replace_proxy_route_plan(
    project_dir: &Path,
    routes: Vec<lpm_runner::local_domains::LocalDomainRoute>,
    proxy_lease: ProxyLeaseSlot,
) -> Result<(), LpmError> {
    if routes.is_empty() {
        return Ok(());
    }

    let (proxy_routes, bridges) = prepare_proxy_routes(project_dir, &routes).await?;
    let mut runtime = proxy_lease
        .lock()
        .map_err(|_| LpmError::Script("local proxy lease state is poisoned".into()))?
        .take()
        .ok_or_else(|| LpmError::Script("local proxy route lease is not initialized".into()))?;
    let replace_result = runtime
        .lease
        .replace_routes(proxy_routes)
        .await
        .map_err(map_proxy_register_error);
    if replace_result.is_ok() {
        runtime.bridges = bridges;
    }
    *proxy_lease
        .lock()
        .map_err(|_| LpmError::Script("local proxy lease state is poisoned".into()))? =
        Some(runtime);
    replace_result
}

async fn prepare_proxy_routes(
    project_dir: &Path,
    routes: &[lpm_runner::local_domains::LocalDomainRoute],
) -> Result<(Vec<lpm_proxy::Route>, Vec<lpm_proxy::HttpProxyHandle>), LpmError> {
    let mut proxy_routes = Vec::with_capacity(routes.len());
    let mut bridges = Vec::with_capacity(routes.len());
    for route in routes {
        if route.upstream.scheme != LocalScheme::Http {
            return Err(LpmError::Script(format!(
                "local-domain proxy host `{}` requires a plain HTTP child, but service {} reported {}; disable framework HTTPS and let the LPM proxy terminate TLS",
                route.host,
                route.service.as_deref().unwrap_or("dev"),
                route.upstream.url(),
            )));
        }
        let upstream_port = if proxy_can_reach_target_directly(&route.upstream) {
            route.upstream.port
        } else {
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|error| {
                    LpmError::Script(format!(
                        "bind local proxy bridge for `{}`: {error}",
                        route.host
                    ))
                })?;
            let bridge =
                lpm_proxy::start_http_frontend_on_listener(listener, route.upstream.clone())
                    .map_err(|error| {
                        LpmError::Script(format!(
                            "start local proxy bridge for `{}`: {error}",
                            route.host
                        ))
                    })?;
            let port = bridge.port();
            bridges.push(bridge);
            port
        };
        proxy_routes.push(lpm_proxy::Route {
            host: route.host.clone(),
            upstream_port,
            project_dir: project_dir.to_path_buf(),
            service: route.service.clone(),
        });
    }
    Ok((proxy_routes, bridges))
}

fn proxy_can_reach_target_directly(target: &LocalTarget) -> bool {
    target.scheme == LocalScheme::Http
        && target.address == IpAddr::V4(Ipv4Addr::LOCALHOST)
        && target.base_path == "/"
}

fn store_proxy_lease(
    proxy_lease: ProxyLeaseSlot,
    runtime: LocalProxyRuntime,
) -> Result<(), LpmError> {
    let mut guard = proxy_lease
        .lock()
        .map_err(|_| LpmError::Script("local proxy lease state is poisoned".into()))?;
    *guard = Some(runtime);
    Ok(())
}

async fn register_proxy_routes(
    routes: Vec<lpm_proxy::Route>,
) -> Result<lpm_proxy::RouteLease, LpmError> {
    lpm_proxy::register(routes)
        .await
        .map_err(map_proxy_register_error)
}

fn map_proxy_register_error(err: lpm_proxy::ProxyError) -> LpmError {
    match err {
        lpm_proxy::ProxyError::IpcUnavailable(_) | lpm_proxy::ProxyError::IpcUnsupported => {
            LpmError::Script(format!(
                "local proxy is not running. Start it with `{}` before using `host` in lpm.json.",
                local_proxy_https_start_command()
            ))
        }
        other => LpmError::Script(format!("local proxy route registration failed: {other}")),
    }
}

fn local_proxy_https_start_command() -> String {
    install_ui::yellow("lpm proxy start --tls-port 9443").to_string()
}

async fn release_proxy_lease_after(
    result: Result<(), LpmError>,
    proxy_lease: &ProxyLeaseSlot,
) -> Result<(), LpmError> {
    let release_result = release_proxy_lease(proxy_lease).await;
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(release_err)) => {
            dev_ui::warn(&format!("local proxy route cleanup failed: {release_err}"));
            Err(primary)
        }
    }
}

async fn shutdown_spawned_tunnel(
    tunnel_handle: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
) {
    if let Some(shutdown_tx) = shutdown_tx {
        let _ = shutdown_tx.send(());
    }
    let Some(mut handle) = tunnel_handle else {
        return;
    };

    tokio::select! {
        _ = &mut handle => {}
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
            handle.abort();
            let _ = handle.await;
        }
    }
}

async fn shutdown_multi_service_tunnel_after(
    result: Result<(), LpmError>,
    tunnel_handle: Option<tokio::task::JoinHandle<()>>,
    capture_consumer_handle: Option<tokio::task::JoinHandle<()>>,
    inspector_state: Option<lpm_inspect::state::InspectorState>,
    inspector_handle: Option<lpm_inspect::InspectorHandle>,
) -> Result<(), LpmError> {
    if let Some(handle) = tunnel_handle {
        handle.abort();
        let _ = handle.await;
    }

    let capture_result = match capture_consumer_handle {
        Some(handle) => handle
            .await
            .map_err(|error| LpmError::Tunnel(format!("capture task failed: {error}"))),
        None => Ok(()),
    };
    let persistence_result = if let Some(state) = inspector_state {
        state.end_session().await;
        state.flush().await.map_err(|error| {
            LpmError::Tunnel(format!(
                "failed to commit captures to .lpm/inspector.db: {error}"
            ))
        })
    } else {
        Ok(())
    };
    if let Some(handle) = inspector_handle {
        handle.shutdown();
    }

    let cleanup_result = capture_result.and(persistence_result);
    match (result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(cleanup_error)) => {
            dev_ui::warn(&format!("tunnel capture cleanup failed: {cleanup_error}"));
            Err(primary)
        }
    }
}

fn release_multi_service_runtime(
    result: Result<(), LpmError>,
    frontend_slot: &Arc<Mutex<Option<DevFrontends>>>,
    dev_session_slot: &Arc<Mutex<Option<lpm_runner::dev_session::DevSessionLease>>>,
) -> Result<(), LpmError> {
    let release_result = (|| {
        let frontends = frontend_slot
            .lock()
            .map_err(|_| LpmError::Script("dev frontend state is poisoned".to_string()))?
            .take();
        let session = dev_session_slot
            .lock()
            .map_err(|_| LpmError::Script("dev session state is poisoned".to_string()))?
            .take();
        drop(frontends);
        drop(session);
        Ok(())
    })();
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(release_err)) => {
            dev_ui::warn(&format!("dev runtime cleanup failed: {release_err}"));
            Err(primary)
        }
    }
}

fn release_hosts_file_after(
    result: Result<(), LpmError>,
    hosts_file: Option<lpm_runner::local_domains::ManagedHostsFile>,
) -> Result<(), LpmError> {
    let release_result = release_hosts_file(hosts_file);
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(release_err)) => {
            dev_ui::warn(&format!("local hosts file cleanup failed: {release_err}"));
            Err(primary)
        }
    }
}

fn release_hosts_file(
    hosts_file: Option<lpm_runner::local_domains::ManagedHostsFile>,
) -> Result<(), LpmError> {
    if let Some(hosts_file) = hosts_file {
        crate::commands::hosts::release_hosts_file_with_permission(hosts_file)
            .map_err(|err| LpmError::Script(format!("local hosts file cleanup failed: {err}")))?;
    }
    Ok(())
}

async fn release_proxy_lease(proxy_lease: &ProxyLeaseSlot) -> Result<(), LpmError> {
    let mut runtime = {
        let mut guard = proxy_lease
            .lock()
            .map_err(|_| LpmError::Script("local proxy lease state is poisoned".into()))?;
        guard.take()
    };
    if let Some(ref mut runtime) = runtime {
        runtime
            .lease
            .release()
            .await
            .map_err(|err| LpmError::Script(format!("local proxy route release failed: {err}")))?;
    }
    Ok(())
}

fn print_registered_proxy_routes(routes: &[lpm_runner::local_domains::LocalDomainRoute]) {
    for route in routes {
        let upstream = if proxy_can_reach_target_directly(&route.upstream) {
            format!("localhost:{}", route.upstream.port)
        } else {
            route.upstream.url()
        };
        let target = format!("{} -> {upstream}", route.host);
        if let Some(ref service) = route.service {
            dev_ui::trusted_detail_with_hint("Proxy", &install_ui::yellow(&target), service);
        } else {
            dev_ui::trusted_detail("Proxy", &install_ui::yellow(&target));
        }
    }
    dev_ui::blank_line();
}

fn extend_unique_hostnames(hostnames: &mut Vec<String>, extra: impl IntoIterator<Item = String>) {
    for hostname in extra {
        push_unique_hostname(hostnames, hostname);
    }
}

fn push_unique_hostname(hostnames: &mut Vec<String>, hostname: String) {
    if !hostnames
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&hostname))
    {
        hostnames.push(hostname);
    }
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
    /// Live browser-inspector URL (e.g. `http://127.0.0.1:53412`) when
    /// `--tunnel` started one. Printed in the banner so the user can
    /// copy-paste it; the dashboard's `o` key opens the same URL.
    inspector_url: Option<String>,
    proxy_lines: Vec<StartupProxyLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StartupProxyLine {
    host: String,
    target: String,
    service: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct StartupBannerLine {
    label: &'static str,
    value: String,
    hint: Option<String>,
}

fn node_source_hint(project_dir: &Path) -> &'static str {
    if project_dir.join(".nvmrc").exists() {
        "from .nvmrc"
    } else if project_dir.join(".node-version").exists() {
        "from .node-version"
    } else {
        "system"
    }
}

fn normalize_env_banner_status(status: &str) -> (String, Option<String>) {
    match status {
        ".env loaded" => ("loaded".to_string(), Some("(.env)".to_string())),
        "created from .env.example" => ("created".to_string(), Some("(.env.example)".to_string())),
        _ => (status.to_string(), None),
    }
}

fn split_trailing_parenthetical(status: &str) -> (String, Option<String>) {
    let Some(open_index) = status.rfind(" (") else {
        return (status.to_string(), None);
    };
    if !status.ends_with(')') {
        return (status.to_string(), None);
    }
    (
        status[..open_index].to_string(),
        Some(status[open_index + 1..].to_string()),
    )
}

fn startup_banner_lines(info: &StartupInfo, project_dir: &Path) -> Vec<StartupBannerLine> {
    let mut lines = Vec::new();

    if let Some(ref version) = info.node_version {
        lines.push(StartupBannerLine {
            label: "Node",
            value: version.clone(),
            hint: Some(format!("({})", node_source_hint(project_dir))),
        });
    }

    if !info.deps_status.is_empty() {
        let (value, hint) = split_trailing_parenthetical(&info.deps_status);
        lines.push(StartupBannerLine {
            label: "Deps",
            value,
            hint,
        });
    }

    if let Some(ref status) = info.env_status {
        let (value, hint) = normalize_env_banner_status(status);
        lines.push(StartupBannerLine {
            label: "Env",
            value,
            hint,
        });
    }

    if info.https_active {
        lines.push(StartupBannerLine {
            label: "HTTPS",
            value: "enabled".to_string(),
            hint: Some("(trusted local certificate)".to_string()),
        });
    }

    for proxy in &info.proxy_lines {
        lines.push(StartupBannerLine {
            label: "Proxy",
            value: format!("https://{} -> {}", proxy.host, proxy.target),
            hint: proxy.service.as_ref().map(|service| format!("({service})")),
        });
    }

    if let Some(ref source) = info.tunnel_source {
        lines.push(StartupBannerLine {
            label: "Tunnel",
            value: info
                .tunnel_url
                .clone()
                .unwrap_or_else(|| "connecting...".to_string()),
            hint: Some(format!("({source})")),
        });
    }

    if let Some(ref url) = info.inspector_url {
        lines.push(StartupBannerLine {
            label: "Inspect",
            value: url.clone(),
            hint: None,
        });
    }

    if let Some(ref addr) = info.network_addr {
        lines.push(StartupBannerLine {
            label: "Network",
            value: addr.clone(),
            hint: None,
        });
    }

    lines
}

fn print_startup_banner(info: &StartupInfo, project_dir: &Path) {
    dev_ui::blank_line();

    for line in startup_banner_lines(info, project_dir) {
        if let Some(hint) = line.hint {
            dev_ui::readiness_with_hint(line.label, &line.value, &hint);
        } else {
            dev_ui::readiness(line.label, &line.value);
        }
    }

    dev_ui::blank_line();
}

// ── Zero-config helpers ──────────────────────────────────────────────

/// Check if dependencies are up to date by comparing install hash.
///
/// delegates to the shared `install_state::check_install_state()`
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
    compatibility_bin_names: &[String],
) -> Result<String, LpmError> {
    let pkg_json = project_dir.join("package.json");
    if !pkg_json.exists() {
        return Ok("no package.json".to_string());
    }

    let start = std::time::Instant::now();

    let (stale, _) = needs_install(project_dir);
    let compatibility_missing =
        dev_entrypoint_compatibility_missing(project_dir, compatibility_bin_names);
    if !stale && !compatibility_missing {
        let elapsed = start.elapsed();
        return Ok(format!("up to date ({})", format_duration(elapsed)));
    }

    if stale {
        dev_ui::phase("Dependencies out of date, installing...");
    } else {
        dev_ui::phase("Preparing dev tool compatibility...");
    }

    // Single-writer ownership: `run_with_options` is the only writer
    // of `.lpm/install-hash`. Pre-fix this branch wrote a stale,
    // pre-install single-line hash AFTER the install returned,
    // clobbering the v6 mtime / linker metadata the install pipeline
    // had just written and (worse) using the pre-install hash even
    // though save policy may have rewritten ranges during install.
    // The install pipeline now writes the correct v6 hash on every
    // successful exit path; this branch just propagates success.
    //
    // Step 6 fix: use the injected client. Pre-fix this
    // built a fresh `RegistryClient::new()` with no token, so any
    // `@lpm.dev` package required by the dev project would have been
    // unauthenticated.
    let nested_install_result = {
        let _stdout_suppressed = crate::output::suppress_stdout(true).map_err(LpmError::Script)?;
        let _stderr_suppressed = crate::output::suppress_stderr(true).map_err(LpmError::Script)?;

        crate::commands::install::run_with_options(
            client,
            project_dir,
            false, // json_output
            false, // offline
            crate::commands::install::FrozenLockfileMode::Never,
            false, // force
            false, // allow_new
            false, // strict_integrity
            false, // no_engine_strict
            None,  // strict_peer_dependencies_override
            None,  // linker_override
            crate::lpm_skills_config::LpmSkillsPreference::Config,
            false, // no_editor_setup
            true,  // no_security_summary
            false, // auto_build
            None,  // target_set: dev is single-project
            None,  // direct_versions_out: dev does not finalize placeholders
            None,  // requested_add_count: dev auto-install is not an add-path install
            None,  // script_policy_override: `lpm dev` does not expose policy flags
            None,  // advisor_override: `lpm dev` does not expose `--advisor`
            None,  // min_release_age_override: `lpm dev` uses the chain
            &[],
            crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm dev` enforces drift
            crate::provenance_fetch::VerifyPolicy::resolve_no_cli(), // verify-policy: `lpm dev` honors env + config posture chain
            crate::commands::install::InstallOmitPolicy::default(),
            // `lpm dev` does not surface its own
            // sandbox-mode flags. The env / config / default chain
            // inside `rebuild::run` still applies.
            false, // strict_sandbox
            false, // no_sandbox
            false, // verbose: internal pipeline, no user-facing Done footer
            false, // audit_after_install: internal pipeline never runs audit
            false, // timing: dev auto-install does not expose install's --timing flag
            compatibility_bin_names,
        )
        .await
    };

    match nested_install_result {
        Ok(()) => {
            let elapsed = start.elapsed();
            Ok(format!("installed in {}", format_duration(elapsed)))
        }
        Err(e) => Err(LpmError::Script(format!(
            "auto-install failed: {e}\n    Use --no-install to skip dependency installation."
        ))),
    }
}

fn dev_entrypoint_compatibility_bins(project_dir: &Path) -> Vec<String> {
    let Ok(script_cmd) = lpm_runner::script::script_command(project_dir, "dev") else {
        return Vec::new();
    };
    first_script_binary_name(&script_cmd)
        .map(|bin| vec![bin])
        .unwrap_or_default()
}

fn dev_entrypoint_compatibility_missing(project_dir: &Path, bin_names: &[String]) -> bool {
    !bin_names.is_empty()
        && lpm_store::StoreVersion::from_env().uses_virtual_store()
        && !lpm_linker::v2::project_compatibility_bins_ready(project_dir, bin_names)
}

fn first_script_binary_name(script_cmd: &str) -> Option<String> {
    let words = shlex::split(script_cmd)?;
    let mut index = 0usize;
    while index < words.len() {
        let word = words[index].as_str();
        if is_shell_assignment(word) {
            index += 1;
            continue;
        }
        match word {
            "env" | "command" => {
                index += 1;
                continue;
            }
            "cross-env" | "cross-env-shell" => {
                index += 1;
                while index < words.len() && is_shell_assignment(&words[index]) {
                    index += 1;
                }
                continue;
            }
            _ => return normalize_script_binary_name(word),
        }
    }
    None
}

fn is_shell_assignment(word: &str) -> bool {
    let Some((key, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn normalize_script_binary_name(word: &str) -> Option<String> {
    if word.is_empty()
        || word.starts_with('-')
        || word.contains('/')
        || word.contains('\\')
        || word.contains('\0')
        || matches!(
            word,
            "node"
                | "npm"
                | "npx"
                | "pnpm"
                | "yarn"
                | "bun"
                | "lpm"
                | "cd"
                | "echo"
                | "export"
                | "set"
                | "source"
                | "."
                | "&&"
                | "||"
                | ";"
                | "|"
        )
    {
        return None;
    }
    Some(word.to_string())
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
                        dev_ui::warn(&format!(
                            "Created .env but failed to copy from .env.example: {e}"
                        ));
                        dev_ui::hint_line("Fill in .env manually or delete it and retry.");
                        return Some("created (copy failed, fill manually)".to_string());
                    }
                }
                Err(e) => {
                    dev_ui::warn(&format!(
                        "Created .env but could not read .env.example: {e}"
                    ));
                    dev_ui::hint_line("Fill in .env manually.");
                    return Some("created (empty, could not read .env.example)".to_string());
                }
            }
            dev_ui::warn("No .env file found. Created from .env.example");
            dev_ui::hint_line("Review .env and fill in missing values");
            dev_ui::trusted_hint_line(install_ui::terminal_line!(
                "Or use {} to store secrets in the vault",
                install_ui::yellow("lpm env vars set"),
            ));
            Some("created from .env.example".to_string())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // .env already exists
            Some(".env loaded".to_string())
        }
        Err(e) => {
            dev_ui::warn(&format!("Could not create .env file: {e}"));
            dev_ui::hint_line("Create it manually or check directory permissions.");
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

fn format_dev_webhook_status(status: u16) -> install_ui::TerminalFragment {
    let status_label = status.to_string();
    if status >= 500 {
        install_ui::red(&status_label)
    } else if status >= 400 {
        install_ui::yellow(&status_label)
    } else {
        install_ui::status_ok(&status_label)
    }
}

fn format_dev_webhook_line(
    method: &str,
    path: &str,
    response_status: u16,
    duration_ms: u64,
    summary: &str,
) -> install_ui::TerminalLine {
    let method = method.to_uppercase();
    let warning = if response_status >= 400 {
        crate::install_ui::terminal_line!(" {}", install_ui::yellow("!"))
    } else {
        install_ui::TerminalLine::new("")
    };
    crate::install_ui::terminal_line!(
        "  {} {} {} -> {} {} — {}{}",
        install_ui::dim("tunnel"),
        install_ui::yellow(&method),
        install_ui::cyan(path),
        format_dev_webhook_status(response_status),
        install_ui::dim(&format!("({duration_ms}ms)")),
        summary,
        warning
    )
}

/// Check if a port number is in the privileged range (< 1024).
///
/// On Linux, binding to ports below 1024 requires root or `CAP_NET_BIND_SERVICE`.
/// macOS is more lenient but we still warn to avoid confusion.
fn is_privileged_port(port: u16) -> bool {
    port < 1024
}

fn resolve_dev_port(requested: Option<u16>, has_services: bool) -> u16 {
    if let Some(port) = requested {
        return port;
    }
    if has_services {
        return 3000;
    }
    lpm_runner::ports::find_available_port(3000).unwrap_or(3000)
}

fn find_internal_dev_port(public_port: u16) -> Result<u16, LpmError> {
    public_port
        .checked_add(1)
        .and_then(lpm_runner::ports::find_available_port)
        .or_else(|| lpm_runner::ports::find_available_port(3000))
        .ok_or_else(|| LpmError::Script("no available internal dev-server port found".to_string()))
}

async fn start_single_service_frontends(
    project_dir: &Path,
    child_target: LocalTarget,
    child_owner_pid: Option<u32>,
    https: bool,
    network: bool,
    requested_port: Option<u16>,
) -> Result<DevFrontends, LpmError> {
    if child_target.scheme == LocalScheme::Https {
        if https {
            let port_context = requested_port
                .filter(|port| *port != child_target.port)
                .map_or_else(String::new, |public_port| {
                    format!(" or remap it to requested public port {public_port}")
                });
            return Err(LpmError::Script(format!(
                "the child already serves HTTPS on port {}, so LPM CLI cannot terminate TLS{port_context}; configure the child to serve plain HTTP",
                child_target.port
            )));
        }
        if network {
            return Err(LpmError::Network(
                "the HTTPS child is loopback-only, so `--network` cannot publish it without a TLS-aware frontend; configure the child to serve plain HTTP and let LPM CLI terminate HTTPS"
                    .to_string(),
            ));
        }
        return Ok(DevFrontends {
            local_target: child_target.clone(),
            network_port: network.then_some(child_target.port),
            handles: Vec::new(),
        });
    }

    if https {
        let public_port = requested_port.unwrap_or(0);
        let bind_address = if network {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let listener = tokio::net::TcpListener::bind((bind_address, public_port))
            .await
            .map_err(|error| {
                LpmError::Script(format!(
                    "bind LPM HTTPS frontend on {bind_address}:{public_port}: {error}"
                ))
            })?;
        let cert_dir = project_dir.join(".lpm").join("certs");
        let handle = lpm_proxy::start_tls_frontend_on_listener(
            listener,
            &cert_dir.join("cert.pem"),
            &cert_dir.join("key.pem"),
            child_target.clone(),
        )
        .await
        .map_err(|error| LpmError::Script(format!("start LPM HTTPS frontend: {error}")))?;
        return Ok(DevFrontends {
            local_target: LocalTarget::loopback(LocalScheme::Https, handle.port())
                .with_base_path(child_target.base_path),
            network_port: network.then_some(handle.port()),
            handles: vec![handle],
        });
    }

    let mut handles = Vec::new();
    if network {
        let network_info = lpm_network::get_network_info(child_target.port, false)?;
        for address in network_info
            .addresses
            .iter()
            .filter(|address| !address.is_ipv6)
        {
            let Ok(ip) = address.ip.parse::<IpAddr>() else {
                continue;
            };
            match tokio::net::TcpListener::bind((ip, child_target.port)).await {
                Ok(listener) => {
                    let handle =
                        lpm_proxy::start_http_frontend_on_listener(listener, child_target.clone())
                            .map_err(|error| {
                                LpmError::Network(format!(
                                    "start LPM network frontend on {ip}:{}: {error}",
                                    child_target.port
                                ))
                            })?;
                    handles.push(handle);
                }
                Err(error) => {
                    let listeners = lpm_runner::ports::list_listening_ports();
                    let owned = lan_listener_is_owned_by_child(
                        &listeners,
                        ip,
                        child_target.port,
                        child_owner_pid,
                    );
                    let reachable = tokio::time::timeout(
                        std::time::Duration::from_millis(300),
                        tokio::net::TcpStream::connect((ip, child_target.port)),
                    )
                    .await
                    .is_ok_and(|result| result.is_ok());
                    if !owned || !reachable {
                        return Err(LpmError::Network(format!(
                            "bind LPM network frontend on {ip}:{}: {error}; the existing listener is not owned by the verified child endpoint",
                            child_target.port,
                        )));
                    }
                }
            }
        }
    }

    Ok(DevFrontends {
        network_port: network.then_some(child_target.port),
        local_target: child_target,
        handles,
    })
}

fn lan_listener_is_owned_by_child(
    listeners: &[lpm_runner::ports::ListeningPort],
    address: IpAddr,
    port: u16,
    child_owner_pid: Option<u32>,
) -> bool {
    let Some(child_owner_pid) = child_owner_pid else {
        return false;
    };
    listeners.iter().any(|listener| {
        listener.port == port
            && listener.pid == Some(child_owner_pid)
            && listener.address.as_deref().is_none_or(|listener_address| {
                listener_address
                    .parse::<IpAddr>()
                    .is_ok_and(|listener_address| listener_address == address)
            })
    })
}

async fn display_network_access(
    network_info: &lpm_network::NetworkInfo,
    port: u16,
    https: bool,
    base_path: &str,
    allow_ca_bootstrap: bool,
) -> Result<Option<String>, LpmError> {
    let scheme = if https { "https" } else { "http" };
    let mut network_addr = None;
    let primary = network_info
        .primary
        .as_ref()
        .filter(|address| !address.is_ipv6)
        .or_else(|| {
            network_info
                .addresses
                .iter()
                .find(|address| !address.is_ipv6)
        });
    if let Some(primary) = primary {
        network_addr = Some(format!("{}:{port}", primary.ip));
        let url = format_network_url(scheme, &primary.ip, primary.is_ipv6, port, base_path);
        dev_ui::blank_line();
        dev_ui::trusted_detail_with_hint(
            "Network",
            &install_ui::url(&url),
            &format!("({})", primary.interface_type),
        );
        for address in network_info
            .addresses
            .iter()
            .filter(|address| !address.is_preferred && !address.is_ipv6)
        {
            let url = format_network_url(scheme, &address.ip, address.is_ipv6, port, base_path);
            dev_ui::trusted_hint_line(install_ui::terminal_line!(
                "{} {}",
                install_ui::url(&url),
                install_ui::dim(&format!("({})", address.interface_type)),
            ));
        }

        if https
            && let Ok(ca_cert_path) = lpm_cert::paths::ca_cert_path()
            && ca_cert_path.exists()
        {
            if allow_ca_bootstrap {
                let ca_cert_data = lpm_common::read_file_capped(
                    &ca_cert_path,
                    lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES,
                )?;
                if !ca_cert_data.is_empty() {
                    let ca_port = start_ca_cert_server(ca_cert_data).await?;
                    dev_ui::blank_line();
                    dev_ui::trusted_detail_line(
                        "Mobile",
                        install_ui::terminal_line!(
                            "First time on mobile? Visit {} to install the CA certificate",
                            install_ui::url(&format!("http://{}:{ca_port}", primary.ip)),
                        ),
                    );
                }
            } else {
                dev_ui::blank_line();
                dev_ui::trusted_detail_line(
                    "Mobile",
                    install_ui::terminal_line!(
                        "enable with {} or copy {} to the device manually",
                        install_ui::cyan("--allow-ca-bootstrap"),
                        install_ui::cyan("rootCA.pem"),
                    ),
                );
            }
        }
    } else {
        dev_ui::warn("no IPv4 network interfaces found");
    }

    let qr_code = primary
        .map(|address| format_network_url(scheme, &address.ip, address.is_ipv6, port, base_path))
        .and_then(|url| lpm_network::qr::render_qr_code(&url).ok())
        .unwrap_or_default();
    if !qr_code.is_empty() {
        dev_ui::blank_line();
        dev_ui::untrusted_block(&qr_code);
    }
    for warning in &network_info.warnings {
        dev_ui::warn(warning);
    }
    dev_ui::blank_line();
    Ok(network_addr)
}

fn format_network_url(
    scheme: &str,
    address: &str,
    is_ipv6: bool,
    port: u16,
    base_path: &str,
) -> String {
    if is_ipv6 {
        format!("{scheme}://[{address}]:{port}{base_path}")
    } else {
        format!("{scheme}://{address}:{port}{base_path}")
    }
}

fn upsert_extra_env(extra_env: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some((_, existing)) = extra_env.iter_mut().find(|(env_key, _)| env_key == key) {
        *existing = value;
    } else {
        extra_env.push((key.to_string(), value));
    }
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
        lpm_runner::orchestrator::ServiceStatus::ReadinessFailed(error) => {
            lpm_dashboard::ServiceStatus::ReadinessFailed(error.clone())
        }
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

async fn start_ca_cert_server(ca_cert_data: Vec<u8>) -> Result<u16, LpmError> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| LpmError::Network(format!("bind mobile CA bootstrap server: {error}")))?;
    let port = listener
        .local_addr()
        .map_err(|error| LpmError::Network(format!("read CA bootstrap address: {error}")))?
        .port();
    tokio::spawn(serve_ca_cert(listener, ca_cert_data));
    Ok(port)
}

async fn serve_ca_cert(listener: tokio::net::TcpListener, ca_cert_data: Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    use std::collections::HashMap;
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
    fn network_urls_preserve_base_paths_and_bracket_ipv6_addresses() {
        assert_eq!(
            format_network_url("http", "192.0.2.10", false, 5173, "/app/"),
            "http://192.0.2.10:5173/app/"
        );
        assert_eq!(
            format_network_url("https", "2001:db8::1", true, 8443, "/app/"),
            "https://[2001:db8::1]:8443/app/"
        );
    }

    #[test]
    fn is_ci_detects_ci_env() {
        // Verify the function exists and returns bool — value depends on environment
        let _result: bool = is_ci();
    }

    #[test]
    fn first_script_binary_name_detects_plain_framework_entrypoint() {
        assert_eq!(
            first_script_binary_name("next dev --turbo").as_deref(),
            Some("next"),
        );
    }

    #[test]
    fn first_script_binary_name_skips_assignments_and_env_wrappers() {
        assert_eq!(
            first_script_binary_name("NODE_OPTIONS=--trace-warnings cross-env FOO=bar vite --host")
                .as_deref(),
            Some("vite"),
        );
    }

    #[test]
    fn first_script_binary_name_returns_none_for_runtime_commands() {
        assert_eq!(first_script_binary_name("node server.js"), None);
    }

    #[test]
    fn first_script_binary_name_returns_none_for_path_commands() {
        assert_eq!(
            first_script_binary_name("./node_modules/.bin/next dev"),
            None
        );
    }

    #[test]
    fn lan_listener_must_match_the_verified_child_owner() {
        let ip = "192.0.2.10".parse::<IpAddr>().unwrap();
        let rows = vec![lpm_runner::ports::ListeningPort {
            port: 5173,
            address: Some(ip.to_string()),
            pid: Some(200),
            process: Some("unrelated".to_string()),
            command: None,
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: None,
        }];

        assert!(!lan_listener_is_owned_by_child(&rows, ip, 5173, Some(100),));
        assert!(lan_listener_is_owned_by_child(&rows, ip, 5173, Some(200),));
        assert!(!lan_listener_is_owned_by_child(&rows, ip, 5173, None));
    }

    #[tokio::test]
    async fn an_https_child_rejects_a_different_requested_public_port() {
        let project = TempDir::new().unwrap();
        let child = LocalTarget::loopback(LocalScheme::Https, 5173);

        let result =
            start_single_service_frontends(project.path(), child, None, true, false, Some(4000))
                .await;
        let Err(error) = result else {
            panic!("an existing HTTPS child cannot be remapped without a TLS-aware frontend");
        };

        assert!(error.to_string().contains("already serves HTTPS"));
        assert!(error.to_string().contains("5173"));
        assert!(error.to_string().contains("4000"));
    }

    #[tokio::test]
    async fn an_https_child_rejects_lpm_tls_termination_mode() {
        let project = TempDir::new().unwrap();
        let child = LocalTarget::loopback(LocalScheme::Https, 5173);

        let result =
            start_single_service_frontends(project.path(), child, None, true, false, None).await;
        let Err(error) = result else {
            panic!("LPM TLS termination requires a plain HTTP child");
        };

        assert!(error.to_string().contains("already serves HTTPS"));
        assert!(error.to_string().contains("plain HTTP"));
    }

    #[tokio::test]
    async fn an_https_child_does_not_claim_unavailable_lan_forwarding() {
        let project = TempDir::new().unwrap();
        let child = LocalTarget::loopback(LocalScheme::Https, 5173);

        let result =
            start_single_service_frontends(project.path(), child, None, false, true, None).await;
        let Err(error) = result else {
            panic!("an HTTPS loopback child cannot be advertised on the LAN without forwarding");
        };

        assert!(error.to_string().contains("HTTPS child"));
        assert!(error.to_string().contains("--network"));
    }

    #[tokio::test]
    async fn a_local_domain_route_rejects_an_https_child() {
        let project = TempDir::new().unwrap();
        let routes = vec![lpm_runner::local_domains::LocalDomainRoute {
            host: "app.localhost".to_string(),
            upstream: LocalTarget::loopback(LocalScheme::Https, 5173),
            service: Some("web".to_string()),
        }];

        let Err(error) = prepare_proxy_routes(project.path(), &routes).await else {
            panic!("the local-domain proxy cannot safely forward to a framework HTTPS child");
        };

        assert!(error.to_string().contains("requires a plain HTTP child"));
        assert!(error.to_string().contains("https://127.0.0.1:5173/"));
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
    fn webhook_status_formatter_plain_content_is_stable() {
        assert_eq!(
            console::strip_ansi_codes(&format_dev_webhook_status(200)).into_owned(),
            "200"
        );
        assert_eq!(
            console::strip_ansi_codes(&format_dev_webhook_status(404)).into_owned(),
            "404"
        );
        assert_eq!(
            console::strip_ansi_codes(&format_dev_webhook_status(500)).into_owned(),
            "500"
        );
    }

    #[test]
    fn webhook_line_uses_slim_detail_shape_without_legacy_tag() {
        let line = format_dev_webhook_line("post", "/stripe", 502, 37, "Stripe: payment");
        let plain = console::strip_ansi_codes(&line);

        assert_eq!(
            plain,
            "  tunnel POST /stripe -> 502 (37ms) — Stripe: payment !"
        );
        assert!(
            !plain.contains("[tunnel]") && !plain.contains('›'),
            "webhook row must not use the old tag or a phase glyph: {plain:?}"
        );
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
    fn startup_banner_lines_use_slim_wording_for_created_env() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".nvmrc"), "22\n").unwrap();

        let info = StartupInfo {
            deps_status: "installed in 11ms".to_string(),
            env_status: Some("created from .env.example".to_string()),
            https_active: true,
            tunnel_url: None,
            tunnel_source: Some("lpm.json".to_string()),
            network_addr: Some("192.168.1.42:3000".to_string()),
            node_version: Some("v22.22.1".to_string()),
            inspector_url: Some("http://127.0.0.1:53412".to_string()),
            proxy_lines: vec![StartupProxyLine {
                host: "web.localhost".to_string(),
                target: "localhost:3000".to_string(),
                service: Some("web".to_string()),
            }],
        };

        assert_eq!(
            startup_banner_lines(&info, dir.path()),
            vec![
                StartupBannerLine {
                    label: "Node",
                    value: "v22.22.1".to_string(),
                    hint: Some("(from .nvmrc)".to_string()),
                },
                StartupBannerLine {
                    label: "Deps",
                    value: "installed in 11ms".to_string(),
                    hint: None,
                },
                StartupBannerLine {
                    label: "Env",
                    value: "created".to_string(),
                    hint: Some("(.env.example)".to_string()),
                },
                StartupBannerLine {
                    label: "HTTPS",
                    value: "enabled".to_string(),
                    hint: Some("(trusted local certificate)".to_string()),
                },
                StartupBannerLine {
                    label: "Proxy",
                    value: "https://web.localhost -> localhost:3000".to_string(),
                    hint: Some("(web)".to_string()),
                },
                StartupBannerLine {
                    label: "Tunnel",
                    value: "connecting...".to_string(),
                    hint: Some("(lpm.json)".to_string()),
                },
                StartupBannerLine {
                    label: "Inspect",
                    value: "http://127.0.0.1:53412".to_string(),
                    hint: None,
                },
                StartupBannerLine {
                    label: "Network",
                    value: "192.168.1.42:3000".to_string(),
                    hint: None,
                },
            ]
        );
    }

    #[test]
    fn startup_banner_lines_use_system_node_and_loaded_env_wording() {
        let dir = TempDir::new().unwrap();

        let info = StartupInfo {
            deps_status: "up to date (2ms)".to_string(),
            env_status: Some(".env loaded".to_string()),
            https_active: false,
            tunnel_url: Some("https://demo.lpm.dev".to_string()),
            tunnel_source: Some("--domain".to_string()),
            network_addr: None,
            node_version: Some("v20.11.0".to_string()),
            inspector_url: None,
            proxy_lines: Vec::new(),
        };

        assert_eq!(
            startup_banner_lines(&info, dir.path()),
            vec![
                StartupBannerLine {
                    label: "Node",
                    value: "v20.11.0".to_string(),
                    hint: Some("(system)".to_string()),
                },
                StartupBannerLine {
                    label: "Deps",
                    value: "up to date".to_string(),
                    hint: Some("(2ms)".to_string()),
                },
                StartupBannerLine {
                    label: "Env",
                    value: "loaded".to_string(),
                    hint: Some("(.env)".to_string()),
                },
                StartupBannerLine {
                    label: "Tunnel",
                    value: "https://demo.lpm.dev".to_string(),
                    hint: Some("(--domain)".to_string()),
                },
            ]
        );
    }

    #[test]
    fn startup_proxy_lines_do_not_publish_service_ports_before_assignment() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            services: HashMap::from([
                (
                    "api".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "node api.js".to_string(),
                        port: Some(4000),
                        host: Some("api.localhost".to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "web".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "next dev".to_string(),
                        host: Some("web.localhost".to_string()),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        assert_eq!(
            startup_proxy_lines_from_config(&config),
            vec![
                StartupProxyLine {
                    host: "api.localhost".to_string(),
                    target: "resolving endpoint".to_string(),
                    service: Some("api".to_string()),
                },
                StartupProxyLine {
                    host: "web.localhost".to_string(),
                    target: "resolving endpoint".to_string(),
                    service: Some("web".to_string()),
                },
            ]
        );
    }

    #[test]
    fn startup_proxy_lines_do_not_publish_the_single_script_port_before_discovery() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            startup_proxy_lines_from_config(&config),
            vec![StartupProxyLine {
                host: "app.localhost".to_string(),
                target: "resolving endpoint".to_string(),
                service: None,
            }]
        );
    }

    #[test]
    fn dashboard_service_hosts_include_service_and_primary_proxy_hosts() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            services: HashMap::from([
                (
                    "api".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "node api.js".to_string(),
                        port: Some(4000),
                        host: Some("api.localhost".to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "web".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "next dev".to_string(),
                        port: Some(3000),
                        host: Some("web.localhost".to_string()),
                        primary: true,
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        assert_eq!(
            dashboard_service_hosts(&config, "web"),
            vec!["web.localhost".to_string(), "app.localhost".to_string()]
        );
    }

    #[test]
    fn cert_prompt_field_keeps_label_and_value_on_one_aligned_line() {
        let line = format_cert_prompt_field("Fingerprint:", "sha256:abc");

        assert!(
            line.contains("Fingerprint:") && line.contains("sha256:abc"),
            "cert prompt field must include label and value: {line:?}"
        );
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
        // the unified predicate now requires lockfile existence
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

    // ── domain separator prevents ambiguous concatenation ──

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

    // ── needs_install returns hash ──

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

    /// Dev composed contract: `auto_install_if_stale` leaves the same
    /// metadata-rich `.lpm/install-hash` shape as the install pipeline.
    /// This calls `auto_install_if_stale` against an empty-deps project
    /// (no network needed; the install pipeline short-circuits at the
    /// empty-deps branch), then asserts the install-hash file is v8 shape.
    /// A future regression that reintroduces a parallel bare-hash overwrite
    /// in `auto_install_if_stale` or the dev flow fails here immediately.
    #[tokio::test]
    async fn auto_install_if_stale_writes_complete_install_state_for_empty_deps() {
        // Isolate every env var the install pipeline reads so a
        // developer's exported state can't pollute the test. `LPM_HOME`
        // redirects the store + cache + global config away from the
        // user's real `~/.lpm/`. `LPM_LINKER` is cleared so the install
        // resolves to the default Isolated. CI env vars are cleared so
        // OIDC paths don't fire.
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let p = project.path();
        let pkg = r#"{"name":"dev-auto-install-v6","version":"1.0.0","dependencies":{}}"#;
        fs::write(p.join("package.json"), pkg).unwrap();

        let _env = crate::test_env::ScopedEnv::update([
            (
                "LPM_HOME",
                Some(std::ffi::OsString::from(home.path().as_os_str())),
            ),
            (
                "HOME",
                Some(std::ffi::OsString::from(home.path().as_os_str())),
            ),
            ("LPM_LINKER", None),
            (lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None),
            ("LPM_TOKEN", None),
            ("NPM_TOKEN", None),
            ("GITHUB_ACTIONS", None),
            ("GITLAB_CI", None),
            ("LPM_FORCE_FILE_AUTH", Some(std::ffi::OsString::from("1"))),
            ("LPM_NO_UPDATE_CHECK", Some(std::ffi::OsString::from("1"))),
        ]);

        // RegistryClient::new() doesn't make network calls; the
        // empty-deps install short-circuits before any registry round-
        // trip would fire.
        let client = lpm_registry::RegistryClient::new();

        // Pre-condition: project is stale (no install-hash yet).
        let (stale_before, _) = needs_install(p);
        assert!(
            stale_before,
            "fresh project must look stale before auto_install_if_stale runs"
        );

        // Exercise the real dev/install handoff.
        let result = auto_install_if_stale(&client, p, &[]).await;
        assert!(
            result.is_ok(),
            "auto_install_if_stale must succeed on empty-deps project, got: {result:?}"
        );

        // Load-bearing pin: install-hash on disk has the complete metadata shape.
        // A regression that reintroduces `fs::write(install_hash, &bare_hash)`
        // anywhere in the dev path — inside auto_install_if_stale or a
        // helper it calls — fails the line-count assertion here.
        let on_disk = fs::read_to_string(p.join(".lpm").join("install-hash"))
            .expect("install-hash must exist after auto_install_if_stale");
        let lines: Vec<&str> = on_disk.lines().collect();
        assert_eq!(
            lines.len(),
            9,
            "install-hash MUST contain 9 lines (hash + m: + l: + i: + p: + a: + e: + n: + b:), got:\n{on_disk}\n\
             A bare-hash overwrite anywhere in the dev path would fail here."
        );
        assert_eq!(lines[0].len(), 64, "line 1 must be a SHA-256 hex hash");
        assert!(
            lines[1].starts_with("m:"),
            "line 2 must be mtime, got {:?}",
            lines[1]
        );
        // flipped `LinkerMode::default()` from
        // Isolated to Hoisted. The hash file's third line reflects
        // whatever default `auto_install_if_stale` resolves through
        // the linker chain — when no override is set, that's the
        // current default's `as_str()`. Asserting on the literal
        // `LinkerMode::default()` keeps the test stable across
        // future default flips.
        assert_eq!(
            lines[2],
            format!("l:{}", lpm_linker::LinkerMode::default().as_str()),
            "line 3 must be linker, got {:?}",
            lines[2]
        );
        assert_eq!(lines[3], "i:source", "line 4 must be integrity policy");
        assert!(
            lines[4].starts_with("p:"),
            "line 5 must be platform tuple, got {:?}",
            lines[4]
        );
        assert_eq!(
            lines[5], "a:enabled",
            "line 6 must record install-time source analysis"
        );
        assert_eq!(
            lines[6], "e:none",
            "line 7 must record unconstrained dependency engines"
        );
        assert_eq!(
            lines[7], "n:none",
            "line 8 must reserve Node runtime fingerprint metadata"
        );
        assert_eq!(
            lines[8], "b:not-required",
            "line 9 must record that importer state is TOML-only"
        );

        // Round-trip: needs_install reads the complete shape as up-to-date.
        let (stale_after, hash) = needs_install(p);
        assert!(
            !stale_after,
            "after auto_install_if_stale, needs_install must report up-to-date"
        );
        assert_eq!(
            hash.as_deref(),
            Some(lines[0]),
            "needs_install must return the same hash that's on disk"
        );
    }

    // ── should_open_browser logic ──

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
    fn convert_readiness_failure() {
        let result = convert_service_status(
            &lpm_runner::orchestrator::ServiceStatus::ReadinessFailed("timed out".to_string()),
        );
        assert_eq!(
            result,
            lpm_dashboard::ServiceStatus::ReadinessFailed("timed out".to_string())
        );
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
        let dash_tx_clone = dash_tx;
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
            timestamp: "T12:00:00Z".to_string(),
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
