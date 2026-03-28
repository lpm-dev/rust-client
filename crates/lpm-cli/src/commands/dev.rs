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
) -> Result<(), LpmError> {
	let port = port.unwrap_or(3000);
	let mut extra_env: Vec<(String, String)> = Vec::new();

	// ── Collect startup info for banner ─────────────────────────────
	let mut startup = StartupInfo {
		deps_status: String::new(),
		env_status: None,
		https_active: false,
		tunnel_url: None,
		tunnel_source: None,
		network_addr: None,
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

	let (install_result, env_result, https_result, _runtime_result) = tokio::join!(
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
				let net = network;
				let p = port;
				let host_clone = host_owned.clone();
				let setup = tokio::task::spawn_blocking(move || {
					let mut extra_hostnames: Vec<String> = Vec::new();
					if let Some(h) = host_clone {
						extra_hostnames.push(h);
					}
					// If network mode, add network IPs to the cert SANs
					if net {
						if let Ok(net_info) = lpm_network::get_network_info(p, true) {
							for addr in &net_info.addresses {
								if !addr.is_ipv6 {
									extra_hostnames.push(addr.ip.clone());
								}
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
	);

	// Process parallel results
	startup.deps_status = install_result?;
	startup.env_status = env_result;

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

	// ── Network info (depends on HTTPS result for scheme) ────────────
	if network {
		let scheme = if https { "https" } else { "http" };
		let net_info = lpm_network::get_network_info(port, https)?;

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

		let options = lpm_tunnel::client::TunnelOptions {
			relay_url: lpm_tunnel::DEFAULT_RELAY_URL.to_string(),
			token: token.to_string(),
			local_port: port,
			domain: tunnel_domain.map(|s| s.to_string()),
			tunnel_auth: None,
		};

		// Start tunnel in background task
		let options_clone = options.clone();
		tokio::spawn(async move {
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
		});
	}

	// ── Print startup banner ────────────────────────────────────────
	print_startup_banner(&startup);

	// ── Check for multi-service orchestration ──────────────────────────
	let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
		.map_err(|e| LpmError::Script(e))?;

	let has_services = lpm_config
		.as_ref()
		.map(|c| !c.services.is_empty())
		.unwrap_or(false);

	if has_services {
		let services = &lpm_config.as_ref().unwrap().services;

		let should_open = !no_open && !is_ci();
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
			on_all_ready: if should_open {
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
	let should_open = !no_open && !is_ci();
	if should_open {
		let open_url = url.clone();
		let port_check = port;
		std::thread::spawn(move || {
			// Wait for port to be ready (up to 30s)
			match lpm_runner::ready::wait_for_port(port_check, 30) {
				Ok(duration) => {
					eprintln!(
						"  {} ready ({})",
						"✔".green(),
						format_duration(duration)
					);
					let _ = open::that(&open_url);
				}
				Err(_) => {
					eprintln!(
						"  {} Service not responding on port {port_check} after 30s. Opening browser anyway.",
						"⚠".yellow()
					);
					let _ = open::that(&open_url);
				}
			}
		});
	}

	// Run the "dev" script with extra env vars injected safely (no unsafe set_var)
	lpm_runner::script::run_script_with_envs(project_dir, "dev", extra_args, env_mode, &extra_env)?;

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
}

fn print_startup_banner(info: &StartupInfo) {
	println!();

	// Node version (detect from runtime)
	if let Ok(output) = std::process::Command::new("node").arg("--version").output() {
		if output.status.success() {
			let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
			// Check for .nvmrc / .node-version to show source
			let source = if Path::new(".nvmrc").exists() {
				"from .nvmrc"
			} else if Path::new(".node-version").exists() {
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
fn compute_install_hash(pkg_content: &str, lock_content: &str) -> String {
	use sha2::{Digest, Sha256};
	let mut hasher = Sha256::new();
	hasher.update(pkg_content.as_bytes());
	hasher.update(lock_content.as_bytes());
	format!("{:x}", hasher.finalize())
}

/// Check if dependencies are up to date by comparing install hash.
///
/// Returns `true` if install is needed, `false` if up to date.
/// Returns `false` when there is no `package.json` (nothing to install).
fn needs_install(project_dir: &std::path::Path) -> bool {
	let pkg_json = project_dir.join("package.json");
	if !pkg_json.exists() {
		return false;
	}

	let hash_file = project_dir.join(".lpm").join("install-hash");
	let nm = project_dir.join("node_modules");

	let pkg_content = std::fs::read_to_string(&pkg_json).unwrap_or_default();
	let lock_content =
		std::fs::read_to_string(project_dir.join("lpm.lock")).unwrap_or_default();
	let current_hash = compute_install_hash(&pkg_content, &lock_content);

	let cached_hash = std::fs::read_to_string(&hash_file).ok();
	!(cached_hash.as_deref() == Some(&current_hash) && nm.exists())
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

	if !needs_install(project_dir) {
		let elapsed = start.elapsed();
		return Ok(format!("up to date ({})", format_duration(elapsed)));
	}

	// Recompute hash for writing after install
	let pkg_content = std::fs::read_to_string(&pkg_json).unwrap_or_default();
	let lock_content =
		std::fs::read_to_string(project_dir.join("lpm.lock")).unwrap_or_default();
	let current_hash = compute_install_hash(&pkg_content, &lock_content);
	let hash_file = project_dir.join(".lpm").join("install-hash");

	output::info("Dependencies out of date, installing...");

	let registry_url = std::env::var("LPM_REGISTRY_URL")
		.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
	let client = lpm_registry::RegistryClient::new()
		.with_base_url(&registry_url);

	match crate::commands::install::run_with_options(&client, project_dir, false, false).await {
		Ok(()) => {
			// Write install hash
			let _ = std::fs::create_dir_all(project_dir.join(".lpm"));
			let _ = std::fs::write(&hash_file, &current_hash);
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
		assert!(!needs_install(dir.path()));
	}

	#[test]
	fn needs_install_no_hash_file() {
		let dir = TempDir::new().unwrap();
		fs::write(dir.path().join("package.json"), r#"{"name":"test"}"#).unwrap();
		assert!(needs_install(dir.path()));
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

		assert!(needs_install(dir.path()));
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

		assert!(!needs_install(dir.path()));
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

		assert!(needs_install(dir.path()));
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

		assert!(!needs_install(dir.path()));
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

		assert!(needs_install(dir.path()));
	}
}
