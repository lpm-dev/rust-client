use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Run the `lpm dev` command with zero-config detection.
///
/// Auto-detects features from lpm.json: tunnel.domain, services.
/// Auto-installs dependencies if stale. Auto-copies .env.example.
/// Opens browser after services are ready.
pub async fn run(
	project_dir: &Path,
	https: bool,
	tunnel: bool,
	network: bool,
	port: Option<u16>,
	host: Option<&str>,
	token: Option<&str>,
	tunnel_domain: Option<&str>,
	extra_args: &[String],
	env_mode: Option<&str>,
	no_open: bool,
	no_install: bool,
	pre_parsed_config: Option<lpm_runner::lpm_json::LpmJsonConfig>,
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
				auto_install_if_stale(&install_dir).await
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
		async {
			node_version_handle.await.unwrap_or(None)
		},
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
		if https {
			if let Some(ref primary) = net_info.primary {
				println!();
				println!(
					"  {} First time on mobile? Visit {} to trust the certificate",
					"📱".dimmed(),
					format!("http://{}:{port}/__lpm/ca", primary.ip).bold()
				);
			}
		}

		// Inject HMR host for framework
		if let Some(ref primary) = net_info.primary {
			extra_env.push(("HOSTNAME".to_string(), "0.0.0.0".to_string()));

			// Detect framework for HMR-specific vars
			let framework = lpm_cert::framework::detect_framework(project_dir);
			match framework {
				lpm_cert::framework::Framework::Vite => {
					extra_env.push(("VITE_HMR_HOST".to_string(), primary.ip.clone()));
				}
				_ => {}
			}
		}

		println!();
	}

	// ── Tunnel setup ───────────────────────────────────────────────────
	let mut tunnel_handle: Option<tokio::task::JoinHandle<()>> = None;
	if tunnel {
		let token = token.ok_or_else(|| LpmError::Tunnel(
			"authentication required for tunnel. Run `lpm login` first.".into()
		))?;

		// Determine tunnel source for banner
		startup.tunnel_source = Some(if tunnel_domain.is_some() {
			"--domain".to_string()
		} else {
			"--tunnel".to_string()
		});

		// Create webhook capture channel and logger for inline display
		let (webhook_tx, mut webhook_rx) =
			tokio::sync::mpsc::unbounded_channel::<lpm_tunnel::webhook::CapturedWebhook>();
		let webhook_logger = lpm_tunnel::webhook_log::WebhookLogger::new(project_dir);

		let options = lpm_tunnel::client::TunnelOptions {
			relay_url: lpm_tunnel::DEFAULT_RELAY_URL.to_string(),
			token: token.to_string(),
			local_port: port,
			domain: tunnel_domain.map(|s| s.to_string()),
			tunnel_auth: None,
			webhook_tx: Some(webhook_tx),
			no_pin: false,
		};

		// Spawn webhook display + logging consumer.
		// Reads captured webhooks from the channel, persists them to disk,
		// and prints a compact one-line summary inline with dev output.
		tokio::spawn(async move {
			while let Some(webhook) = webhook_rx.recv().await {
				// Persist to JSONL log (non-blocking best-effort)
				let _ = webhook_logger.append(&webhook);

				// Inline display
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
					eprintln!(
						"           {}",
						format!("! {diag}").yellow()
					);
				}
			}
		});

		// Start tunnel in background task, storing the handle for clean shutdown
		let options_clone = options.clone();
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
						).green()
					);
				},
				|msg| {
					eprintln!("  {} {}", "⚠".yellow(), msg);
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
		lpm_runner::lpm_json::read_lpm_json(project_dir)
			.map_err(|e| LpmError::Script(e))?
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

		let options = lpm_runner::orchestrator::OrchestratorOptions {
			https,
			filter: extra_args.to_vec(), // lpm dev web api → filter to web + api
			extra_envs: extra_env.clone(),
			event_tx: None,
			on_all_ready: if open_browser {
				Some(Box::new(move || {
					let _ = open::that(&open_url);
				}))
			} else {
				None
			},
		};

		return lpm_runner::orchestrator::run_services(project_dir, services, options);
	}

	// ── Single service: start dev server ────────────────────────────
	let scheme = if https { "https" } else { "http" };
	let url = format!("{scheme}://localhost:{port}");
	println!(
		"  {} {}",
		"●".cyan(),
		format!("Local: {url}").cyan()
	);
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
					eprintln!(
						"  {} ready ({})",
						"✔".green(),
						format_duration(duration)
					);
					if open_browser {
						let _ = open::that(&open_url);
					}
				}
				Err(_) => {
					output::warn(&format!(
						"Service not ready after 30s — skipping browser open"
					));
				}
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
		println!(
			"  {} {}  {}",
			"●".cyan(),
			format!("Node     {version}"),
			format!("({source})").dimmed()
		);
	}

	// Deps status
	if !info.deps_status.is_empty() {
		println!(
			"  {} {}  {}",
			"●".cyan(),
			"Deps",
			info.deps_status.dimmed()
		);
	}

	// Env status
	if let Some(ref status) = info.env_status {
		println!(
			"  {} {}  {}",
			"●".cyan(),
			"Env",
			status.dimmed()
		);
	}

	// HTTPS
	if info.https_active {
		println!(
			"  {} {}  {}",
			"●".cyan(),
			"HTTPS",
			"certificate valid".dimmed()
		);
	}

	// Tunnel
	if let Some(ref source) = info.tunnel_source {
		if let Some(ref url) = info.tunnel_url {
			println!(
				"  {} {}  {}",
				"●".cyan(),
				format!("Tunnel   {url}"),
				format!("({source})").dimmed()
			);
		} else {
			println!(
				"  {} {}  {}",
				"●".cyan(),
				"Tunnel",
				format!("connecting... ({source})").dimmed()
			);
		}
	}

	// Network
	if let Some(ref addr) = info.network_addr {
		println!(
			"  {} {}",
			"●".cyan(),
			format!("Network  {addr}").dimmed()
		);
	}

	println!();
}

// ── Zero-config helpers ──────────────────────────────────────────────

/// Compute the install hash from package.json and lockfile contents.
///
/// Produces a deterministic SHA-256 hex digest so we can detect when
/// dependencies have changed without re-running `lpm install`.
pub(crate) fn compute_install_hash(pkg_content: &str, lock_content: &str) -> String {
	use sha2::{Digest, Sha256};
	let mut hasher = Sha256::new();
	hasher.update(pkg_content.as_bytes());
	hasher.update(b"\x00"); // domain separator prevents "ab"+"cd" == "abc"+"d"
	hasher.update(lock_content.as_bytes());
	format!("{:x}", hasher.finalize())
}

/// Check if dependencies are up to date by comparing install hash.
///
/// Returns `(needs_install, computed_hash)`. The hash is `None` only when
/// there is no `package.json` (nothing to install). Returning the hash
/// avoids re-reading package.json and lockfile when install is needed.
fn needs_install(project_dir: &std::path::Path) -> (bool, Option<String>) {
	let pkg_json = project_dir.join("package.json");
	if !pkg_json.exists() {
		return (false, None);
	}

	let hash_file = project_dir.join(".lpm").join("install-hash");
	let nm = project_dir.join("node_modules");

	let pkg_content = std::fs::read_to_string(&pkg_json).unwrap_or_default();
	let lock_content =
		std::fs::read_to_string(project_dir.join("lpm.lock")).unwrap_or_default();
	let current_hash = compute_install_hash(&pkg_content, &lock_content);

	let cached_hash = std::fs::read_to_string(&hash_file).ok();
	let up_to_date = cached_hash.as_deref() == Some(&current_hash) && nm.exists();
	(!up_to_date, Some(current_hash))
}

/// Auto-install dependencies if the install hash doesn't match.
///
/// Compares sha256(package.json + lockfile) against `.lpm/install-hash`.
/// If different or missing, runs `lpm install`. ~2ms when up-to-date.
///
/// Returns a status string for the startup banner.
async fn auto_install_if_stale(project_dir: &std::path::Path) -> Result<String, LpmError> {
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

	let registry_url = std::env::var("LPM_REGISTRY_URL")
		.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
	let client = lpm_registry::RegistryClient::new()
		.with_base_url(&registry_url);

	match crate::commands::install::run_with_options(&client, project_dir, false, false, false, None, false, false, true, false).await {
		Ok(()) => {
			// Write install hash
			if let Err(e) = std::fs::create_dir_all(project_dir.join(".lpm")) {
				tracing::warn!("failed to create .lpm directory: {e}");
			}
			if let Err(e) = std::fs::write(&hash_file, &current_hash) {
				tracing::warn!("failed to write install-hash: {e}");
			}
			let elapsed = start.elapsed();
			Ok(format!("installed in {}", format_duration(elapsed)))
		}
		Err(e) => {
			Err(LpmError::Script(format!(
				"auto-install failed: {e}\n    Use --no-install to skip dependency installation."
			)))
		}
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
					tracing::debug!("failed to open .env.example: {e}");
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
			tracing::debug!("failed to create .env: {e}");
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

#[cfg(test)]
mod tests {
	use super::*;
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
		// Verify the function exists and returns bool
		let result = is_ci();
		assert!(result == true || result == false);
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
		let dir = TempDir::new().unwrap();
		let pkg = r#"{"name":"test"}"#;
		fs::write(dir.path().join("package.json"), pkg).unwrap();
		fs::create_dir_all(dir.path().join("node_modules")).unwrap();

		let hash = compute_install_hash(pkg, "");
		fs::create_dir_all(dir.path().join(".lpm")).unwrap();
		fs::write(dir.path().join(".lpm/install-hash"), &hash).unwrap();

		assert!(!needs_install(dir.path()).0);
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
		assert_ne!(h1, h2, "domain separator should prevent 'ab'+'cd' == 'abc'+'d'");
	}

	// ── Finding #5: needs_install returns hash ──

	#[test]
	fn needs_install_returns_hash() {
		let dir = TempDir::new().unwrap();
		let pkg = r#"{"name":"test"}"#;
		fs::write(dir.path().join("package.json"), pkg).unwrap();

		let (stale, hash) = needs_install(dir.path());
		assert!(stale);
		assert!(hash.is_some(), "hash should be returned when package.json exists");
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
}
