//! Multi-service orchestrator for `lpm dev`.
//!
//! Starts multiple dev services with dependency ordering, readiness checks,
//! cross-service env injection, colored output, and graceful shutdown.

use crate::lpm_json::ServiceConfig;
use crate::{ports, ready, service_graph};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

/// Service runtime state.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
	Pending,
	Starting,
	WaitingForDep(String),
	Ready,
	Crashed(i32),
	Stopped,
}

/// Event sent from the orchestrator to the dashboard (or any observer).
pub enum OrchestratorEvent {
	/// A line of output from a service.
	ServiceLog { service_index: usize, line: String, is_stderr: bool },
	/// Service status changed.
	StatusChange { service_index: usize, status: ServiceStatus },
}

/// Structured record of a port reassignment.
#[derive(Debug, Clone)]
pub struct PortReassignment {
	/// The port originally requested (from config or persisted override).
	pub original: u16,
	/// The new port assigned after conflict resolution.
	pub new: u16,
	/// Human-readable reason, e.g. "node (PID 92341)".
	pub reason: String,
}

/// Options for the orchestrator.
pub struct OrchestratorOptions {
	/// Use HTTPS URLs in cross-service env injection.
	pub https: bool,
	/// Only start these services (+ their transitive deps). Empty = all.
	pub filter: Vec<String>,
	/// Extra environment variables to inject into all services (e.g., HTTPS cert paths).
	/// Passed via `Command::envs()` — no unsafe `set_var` needed.
	pub extra_envs: Vec<(String, String)>,
	/// Optional channel for sending events to a dashboard or observer.
	/// When set, events are sent in addition to (not instead of) terminal output.
	pub event_tx: Option<std::sync::mpsc::Sender<OrchestratorEvent>>,
	/// Called once after ALL initial services pass readiness checks.
	/// Used by dev.rs to open the browser at the right time.
	pub on_all_ready: Option<Box<dyn FnOnce() + Send>>,
}

impl Default for OrchestratorOptions {
	fn default() -> Self {
		Self {
			https: false,
			filter: vec![],
			extra_envs: vec![],
			event_tx: None,
			on_all_ready: None,
		}
	}
}

/// Colors for service output prefixes.
const COLORS: &[&str] = &[
	"\x1b[36m", // cyan
	"\x1b[33m", // yellow
	"\x1b[35m", // magenta
	"\x1b[32m", // green
	"\x1b[34m", // blue
	"\x1b[31m", // red
];
const RESET: &str = "\x1b[0m";

/// Run multiple services with dependency ordering.
///
/// This function blocks until all services exit or Ctrl+C is pressed.
///
/// Takes `options` by value so that `on_all_ready` (a `FnOnce`) can be consumed.
/// The `on_all_ready` callback fires once after ALL initial services pass readiness checks.
pub fn run_services(
	project_dir: &Path,
	services: &HashMap<String, ServiceConfig>,
	options: OrchestratorOptions,
) -> Result<(), LpmError> {
	if services.is_empty() {
		return Ok(());
	}

	// Filter services if specific ones were requested
	let active_services = if options.filter.is_empty() {
		services.clone()
	} else {
		let mut active = HashMap::new();
		for name in &options.filter {
			if !services.contains_key(name) {
				return Err(LpmError::Script(format!(
					"service '{name}' not found. Available: {}",
					services.keys().cloned().collect::<Vec<_>>().join(", ")
				)));
			}
			// Include transitive deps
			let deps = service_graph::transitive_deps(name, services);
			for dep_name in deps {
				if let Some(config) = services.get(&dep_name) {
					active.insert(dep_name, config.clone());
				}
			}
		}
		active
	};

	// Validate dependsOn references before sorting
	for (name, config) in &active_services {
		for dep in &config.depends_on {
			if !active_services.contains_key(dep) {
				return Err(LpmError::Script(format!(
					"service '{name}' depends on '{dep}', but '{dep}' is not defined in lpm.json services.\n    Available services: {}",
					active_services.keys().cloned().collect::<Vec<_>>().join(", ")
				)));
			}
		}
	}

	// Topological sort
	let groups = service_graph::topological_sort(&active_services)
		.map_err(|e| LpmError::Script(e))?;

	// Read persisted port overrides from previous sessions
	let port_overrides = ports::read_port_overrides(project_dir);

	// Check ports for conflicts (use persisted overrides if available)
	let mut port_map: HashMap<String, u16> = HashMap::new();
	let mut port_reassignments: HashMap<String, PortReassignment> = HashMap::new();

	for (name, config) in &active_services {
		// Use persisted override if available, otherwise use config port
		let base_port = port_overrides
			.get(name)
			.copied()
			.or(config.port);

		if let Some(port) = base_port {
			match ports::check_port(port) {
				ports::PortStatus::Free => {
					port_map.insert(name.clone(), port);
				}
				ports::PortStatus::InUse { pid, process_name } => {
					let reason = match (&pid, &process_name) {
						(Some(p), Some(n)) => format!("{n} (PID {p})"),
						(Some(p), None) => format!("PID {p}"),
						_ => "unknown process".to_string(),
					};

					if let Some(next) = ports::find_available_port(port + 1) {
						port_reassignments.insert(name.clone(), PortReassignment {
							original: port,
							new: next,
							reason: reason.clone(),
						});
						port_map.insert(name.clone(), next);
						// Persist the override for next session
						ports::write_port_override(project_dir, name, next);
					} else {
						return Err(LpmError::Script(format!(
							"no available port found near {port} for service '{name}'"
						)));
					}
				}
			}
		}
	}

	// Build cross-service env
	let cross_env = ports::build_cross_service_env(&port_map, options.https);

	// Build PATH
	let path = crate::bin_path::build_path_with_bins(project_dir);

	// Load .env files
	let dotenv = crate::dotenv::load_env_files(project_dir, None);

	// Assign colors
	let service_names: Vec<String> = groups.iter().flatten().cloned().collect();
	let color_map: HashMap<String, &str> = service_names
		.iter()
		.enumerate()
		.map(|(i, name)| (name.clone(), COLORS[i % COLORS.len()]))
		.collect();

	// Print startup banner with port reassignment info
	println!();
	for name in &service_names {
		let config = &active_services[name];
		let color = color_map[name];

		let port_info = if let Some(reassignment) = port_reassignments.get(name) {
			format!(
				" → :{} \x1b[33m(port {} in use by {})\x1b[0m",
				reassignment.new, reassignment.original, reassignment.reason
			)
		} else {
			port_map
				.get(name)
				.map(|p| format!(" → :{p}"))
				.unwrap_or_default()
		};

		let dep_info = if config.depends_on.is_empty() {
			String::new()
		} else {
			format!(" (after {})", config.depends_on.join(", "))
		};
		println!(
			"  {color}●{RESET} {color}{name}{RESET}  {}{port_info}{dep_info}",
			config.command
		);
	}
	println!();

	// Shutdown state: 0 = running, 1 = graceful shutdown (SIGTERM), 2+ = force kill (SIGKILL)
	let shutdown_state = Arc::new(AtomicU8::new(0));
	let children: Arc<Mutex<Vec<(String, Child)>>> = Arc::new(Mutex::new(Vec::new()));

	// RAII guard: ensures children are cleaned up even on panic
	let children_guard = ChildrenGuard(children.clone());

	// Set up Ctrl+C handler with double-press escalation
	let shutdown_state_clone = shutdown_state.clone();
	let children_clone = children.clone();
	ctrlc_handler(shutdown_state_clone, children_clone);

	// Start services in dependency order
	for group in &groups {
		if shutdown_state.load(Ordering::Relaxed) > 0 {
			break;
		}

		let mut handles = Vec::new();

		for name in group {
			if shutdown_state.load(Ordering::Relaxed) > 0 {
				break;
			}

			let config = &active_services[name];
			let color = color_map[name];

			// Build env for this service
			let mut env = dotenv.clone();
			env.extend(config.env.clone());
			if let Some(svc_cross_env) = cross_env.get(name) {
				env.extend(svc_cross_env.clone());
			}
			// Override PORT if we reassigned it
			if let Some(&port) = port_map.get(name) {
				env.insert("PORT".to_string(), port.to_string());
			}

			// Resolve working directory
			let cwd = if let Some(ref sub) = config.cwd {
				project_dir.join(sub)
			} else {
				project_dir.to_path_buf()
			};

			// Spawn the service process
			let (shell, flag) = if cfg!(windows) {
				("cmd", "/C")
			} else {
				("sh", "-c")
			};

			let mut cmd = Command::new(shell);
			cmd.arg(flag)
				.arg(&config.command)
				.current_dir(&cwd)
				.env("PATH", &path)
				.envs(&env)
				.stdout(Stdio::piped())
				.stderr(Stdio::piped());

			// Inject extra envs from HTTPS/tunnel/network setup (safe, no global mutation)
			for (key, value) in &options.extra_envs {
				cmd.env(key, value);
			}

			let child = cmd.spawn()
				.map_err(|e| {
					LpmError::Script(format!("failed to start service '{name}': {e}"))
				})?;

			let child_pid = child.id();
			children.lock().push((name.clone(), child));

			// Compute service index for event sending
			let service_index = service_names.iter().position(|n| n == name).unwrap_or(0);

			// Spawn output readers in background threads
			{
				let name = name.clone();
				let color = color.to_string();
				let children_ref = children.clone();
				let shutdown_ref = shutdown_state.clone();
				let event_tx = options.event_tx.clone();

				std::thread::spawn(move || {
					// Get the child from the shared list and take stdout/stderr
					let (stdout, stderr) = {
						let mut locked = children_ref.lock();
						let entry = locked.iter_mut().find(|(n, _)| *n == name);
						match entry {
							Some((_, child)) => {
								(child.stdout.take(), child.stderr.take())
							}
							None => return,
						}
					};

					// Read stdout
					if let Some(stdout) = stdout {
						let reader = BufReader::new(stdout);
						for line in reader.lines() {
							if shutdown_ref.load(Ordering::Relaxed) > 0 {
								break;
							}
							if let Ok(line) = line {
								println!("  {color}[{name}]{RESET} {line}");
								// Send to dashboard if connected
								if let Some(ref tx) = event_tx {
									let _ = tx.send(OrchestratorEvent::ServiceLog {
										service_index,
										line: line.clone(),
										is_stderr: false,
									});
								}
							}
						}
					}
				});
			}

			// stderr reader
			{
				let name = name.clone();
				let color = color.to_string();
				let children_ref = children.clone();
				let shutdown_ref = shutdown_state.clone();
				let event_tx = options.event_tx.clone();

				std::thread::spawn(move || {
					let stderr = {
						let mut locked = children_ref.lock();
						let entry = locked.iter_mut().find(|(n, _)| *n == name);
						match entry {
							Some((_, child)) => child.stderr.take(),
							None => return,
						}
					};

					if let Some(stderr) = stderr {
						let reader = BufReader::new(stderr);
						for line in reader.lines() {
							if shutdown_ref.load(Ordering::Relaxed) > 0 {
								break;
							}
							if let Ok(line) = line {
								eprintln!("  {color}[{name}]{RESET} {line}");
								if let Some(ref tx) = event_tx {
									let _ = tx.send(OrchestratorEvent::ServiceLog {
										service_index,
										line: line.clone(),
										is_stderr: true,
									});
								}
							}
						}
					}
				});
			}

			// Wait for readiness (in a background thread)
			let name_clone = name.clone();
			let ready_port = config.effective_ready_port();
			let ready_url = config.ready_url.clone();
			let timeout = config.ready_timeout;

			let handle = std::thread::spawn(move || -> Result<Option<Duration>, String> {
				if let Some(url) = ready_url {
					Ok(Some(ready::wait_for_url(&url, timeout)?))
				} else if let Some(port) = ready_port {
					Ok(Some(ready::wait_for_port(port, timeout)?))
				} else {
					Ok(None) // No readiness check = ready immediately
				}
			});

			handles.push((name.clone(), handle));
		}

		// Wait for all services in this group to be ready
		for (name, handle) in handles {
			match handle.join() {
				Ok(Ok(duration)) => {
					let color = color_map[&name];
					let timing = duration
						.map(|d| {
							let ms = d.as_millis();
							if ms < 1000 {
								format!(" ({ms}ms)")
							} else {
								format!(" ({:.1}s)", ms as f64 / 1000.0)
							}
						})
						.unwrap_or_default();
					eprintln!("  {color}[{name}]{RESET} \x1b[32m✔ ready{timing}\x1b[0m");
				}
				Ok(Err(e)) => {
					eprintln!(
						"  \x1b[31m[{name}]\x1b[0m \x1b[31m✖ {e}\x1b[0m"
					);
					if shutdown_state.load(Ordering::Relaxed) == 0 {
						shutdown_state.store(1, Ordering::Relaxed);
						shutdown_children(&children, false);
						return Err(LpmError::Script(format!(
							"service '{name}' failed readiness check: {e}"
						)));
					}
				}
				Err(_) => {
					eprintln!("  \x1b[31m[{name}]\x1b[0m readiness check panicked");
					if shutdown_state.load(Ordering::Relaxed) == 0 {
						shutdown_state.store(1, Ordering::Relaxed);
						shutdown_children(&children, false);
						return Err(LpmError::Script(format!(
							"service '{name}' readiness check panicked"
						)));
					}
				}
			}
		}
	}

	// All initial services are ready — fire callback (e.g., open browser)
	if let Some(callback) = options.on_all_ready {
		std::thread::spawn(callback);
	}

	// Track restart backoff per service: name → (attempt_count, last_crash_time)
	let mut restart_state: HashMap<String, (u32, std::time::Instant)> = HashMap::new();

	// Wait for all children to exit (or Ctrl+C)
	loop {
		if shutdown_state.load(Ordering::Relaxed) > 0 {
			break;
		}

		// Check if any child has exited
		let mut all_done = true;
		let mut to_restart: Vec<String> = Vec::new();
		{
			let mut locked = children.lock();
			for (name, child) in locked.iter_mut() {
				match child.try_wait() {
					Ok(Some(status)) => {
						let color = color_map.get(name.as_str()).unwrap_or(&RESET);
						if status.success() {
							eprintln!("  {color}[{name}]{RESET} exited");
						} else {
							let code = status.code().unwrap_or(-1);
							let config = active_services.get(name);
							let should_restart = config.map(|c| c.restart).unwrap_or(false);

							if should_restart && shutdown_state.load(Ordering::Relaxed) == 0 {
								to_restart.push(name.clone());
								eprintln!(
									"  \x1b[33m[{name}]\x1b[0m \x1b[33mcrashed (exit {code}), restarting...\x1b[0m"
								);
							} else {
								eprintln!(
									"  \x1b[31m[{name}]\x1b[0m \x1b[31mcrashed (exit {code})\x1b[0m"
								);
							}
						}
					}
					Ok(None) => {
						all_done = false; // Still running
					}
					Err(_) => {}
				}
			}
		}

		// Handle restarts with exponential backoff
		for name in to_restart {
			all_done = false; // Still need to run

			let (attempts, last_crash) = restart_state
				.entry(name.clone())
				.or_insert((0, std::time::Instant::now()));

			// Reset backoff if service was stable for 60+ seconds
			if last_crash.elapsed().as_secs() > 60 {
				*attempts = 0;
			}

			*attempts += 1;
			*last_crash = std::time::Instant::now();

			let delay_secs = std::cmp::min(1u64 << (*attempts - 1), 30);
			let color = color_map.get(name.as_str()).unwrap_or(&RESET);
			eprintln!(
				"  {color}[{name}]{RESET} restarting in {delay_secs}s (attempt {})...",
				attempts
			);

			std::thread::sleep(std::time::Duration::from_secs(delay_secs));

			if shutdown_state.load(Ordering::Relaxed) > 0 {
				break;
			}

			// Respawn the service
			if let Some(config) = active_services.get(&name) {
				let (shell, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };
				let cwd = if let Some(ref sub) = config.cwd {
					project_dir.join(sub)
				} else {
					project_dir.to_path_buf()
				};

				let mut env = dotenv.clone();
				env.extend(config.env.clone());
				if let Some(svc_cross_env) = cross_env.get(&name) {
					env.extend(svc_cross_env.clone());
				}
				if let Some(&port) = port_map.get(&name) {
					env.insert("PORT".to_string(), port.to_string());
				}

				let mut cmd = Command::new(shell);
				cmd.arg(flag)
					.arg(&config.command)
					.current_dir(&cwd)
					.env("PATH", &path)
					.envs(&env)
					.stdout(Stdio::piped())
					.stderr(Stdio::piped());

				for (key, value) in &options.extra_envs {
					cmd.env(key, value);
				}

				match cmd.spawn() {
					Ok(new_child) => {
						let mut locked = children.lock();
						// Remove old dead entry
						locked.retain(|(n, _)| n != &name);
						locked.push((name.clone(), new_child));
						eprintln!("  {color}[{name}]{RESET} \x1b[32m✔ restarted\x1b[0m");
					}
					Err(e) => {
						eprintln!(
							"  \x1b[31m[{name}]\x1b[0m \x1b[31mfailed to restart: {e}\x1b[0m"
						);
					}
				}
			}
		}

		if all_done {
			break;
		}

		std::thread::sleep(std::time::Duration::from_millis(500));
	}

	// Normal cleanup (guard will also cleanup on panic/early exit via Drop)
	let force = shutdown_state.load(Ordering::Relaxed) >= 2;
	shutdown_children(&children, force);
	std::mem::forget(children_guard); // Don't double-cleanup

	Ok(())
}

/// RAII guard that kills child processes on drop (panic safety).
struct ChildrenGuard(Arc<Mutex<Vec<(String, Child)>>>);

impl Drop for ChildrenGuard {
	fn drop(&mut self) {
		shutdown_children(&self.0, false);
	}
}

/// Set up signal handlers for graceful shutdown with double Ctrl+C escalation.
///
/// - First Ctrl+C: sets shutdown state to 1 (SIGTERM graceful shutdown)
/// - Second Ctrl+C within 3 seconds: sets state to 2 (SIGKILL force kill)
///
/// Uses `signal-hook` on Unix for safe, non-`unsafe` signal handling.
/// Falls back to a no-op on non-Unix (Windows child process cleanup
/// is handled by the `ChildrenGuard` RAII guard on drop).
fn ctrlc_handler(
	shutdown_state: Arc<AtomicU8>,
	children: Arc<Mutex<Vec<(String, Child)>>>,
) {
	#[cfg(unix)]
	{
		use signal_hook::consts::{SIGINT, SIGTERM};
		use signal_hook::iterator::Signals;

		let state = shutdown_state.clone();
		let kids = children.clone();
		if let Ok(mut signals) = Signals::new([SIGINT, SIGTERM]) {
			std::thread::spawn(move || {
				for _ in signals.forever() {
					let prev = state.fetch_add(1, Ordering::Relaxed);
					if prev == 0 {
						// First signal: graceful shutdown
						eprintln!("\n  Stopping services...");
					} else {
						// Second+ signal: force kill
						eprintln!("\n  Force-killing services...");
						force_kill_children(&kids);
						break;
					}
				}
			});
		}
	}
}

/// Immediately SIGKILL all children (used for double Ctrl+C escalation).
fn force_kill_children(children: &Arc<Mutex<Vec<(String, Child)>>>) {
	let mut locked = children.lock();
	for (name, child) in locked.iter_mut() {
		match child.try_wait() {
			Ok(Some(_)) => {} // Already exited
			_ => {
				let _ = child.kill();
				eprintln!("  [{name}] force-killed");
			}
		}
	}
	// Reap zombies
	for (_, child) in locked.iter_mut() {
		let _ = child.wait();
	}
}

/// Gracefully stop all child processes: SIGTERM first, wait, then SIGKILL.
///
/// This gives dev servers time to flush DB connections, finish in-flight
/// requests, and clean up temp files before being force-killed.
///
/// If `force` is true, skips SIGTERM and goes straight to SIGKILL (used when
/// the user double-pressed Ctrl+C).
fn shutdown_children(children: &Arc<Mutex<Vec<(String, Child)>>>, force: bool) {
	let mut locked = children.lock();
	let count = locked.len();

	if count == 0 {
		return;
	}

	if force {
		eprintln!("\n  Force-killing {count} services...");
		for (name, child) in locked.iter_mut() {
			let _ = child.kill();
			eprintln!("  [{name}] force-killed");
		}
		for (_, child) in locked.iter_mut() {
			let _ = child.wait();
		}
		return;
	}

	eprintln!("\n  Stopping {count} services...");

	// First pass: send SIGTERM for graceful shutdown
	for (name, child) in locked.iter_mut() {
		#[cfg(unix)]
		{
			// Send SIGTERM (can be caught and handled)
			let pid = child.id() as i32;
			unsafe { libc::kill(pid, libc::SIGTERM) };
			tracing::debug!("sent SIGTERM to service '{name}' (pid {pid})");
		}
		#[cfg(not(unix))]
		{
			// Windows: no SIGTERM equivalent, kill immediately
			let _ = child.kill();
			tracing::debug!("sent kill to service '{name}'");
		}
	}

	// Drop lock, wait up to 3 seconds for graceful exit
	drop(locked);
	std::thread::sleep(std::time::Duration::from_secs(3));

	// Second pass: report status and force-kill stragglers
	let mut locked = children.lock();
	for (name, child) in locked.iter_mut() {
		match child.try_wait() {
			Ok(Some(status)) => {
				eprintln!("  [{name}] stopped (exit {})", status.code().unwrap_or(-1));
			}
			_ => {
				tracing::debug!("force-killing service '{name}'");
				let _ = child.kill();
				eprintln!("  [{name}] force-killed");
			}
		}
	}

	// Final wait to reap zombie processes
	for (_, child) in locked.iter_mut() {
		let _ = child.wait();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::lpm_json::ServiceConfig;

	fn simple_service(command: &str) -> ServiceConfig {
		ServiceConfig {
			command: command.to_string(),
			..Default::default()
		}
	}

	fn service_with_dep(command: &str, dep: &str) -> ServiceConfig {
		ServiceConfig {
			command: command.to_string(),
			depends_on: vec![dep.to_string()],
			..Default::default()
		}
	}

	#[test]
	fn validates_depends_on_missing_service() {
		let mut services = HashMap::new();
		services.insert("api".to_string(), service_with_dep("echo api", "db"));
		// "db" not defined — should fail validation before spawning

		let options = OrchestratorOptions::default();
		let dir = tempfile::TempDir::new().unwrap();
		let result = run_services(dir.path(), &services, options);

		assert!(result.is_err());
		let err = result.unwrap_err().to_string();
		assert!(
			err.contains("depends on"),
			"error should mention dependency: {err}"
		);
		assert!(err.contains("db"), "error should name the missing service: {err}");
	}

	#[test]
	fn validates_depends_on_valid() {
		let mut services = HashMap::new();
		// Use `true` command — exits immediately with success on Unix
		services.insert("db".to_string(), simple_service("true"));
		services.insert("api".to_string(), service_with_dep("true", "db"));

		let options = OrchestratorOptions::default();
		let dir = tempfile::TempDir::new().unwrap();
		let result = run_services(dir.path(), &services, options);

		// It may fail for other reasons (e.g., readiness timeout)
		// but NOT because of dependsOn validation
		if let Err(e) = &result {
			let msg = e.to_string();
			assert!(
				!msg.contains("depends on"),
				"should not fail on dependsOn validation: {msg}"
			);
		}
	}

	#[test]
	fn empty_services_succeeds() {
		let services = HashMap::new();
		let options = OrchestratorOptions::default();
		let dir = tempfile::TempDir::new().unwrap();
		let result = run_services(dir.path(), &services, options);
		assert!(result.is_ok());
	}

	#[test]
	fn filter_unknown_service_fails() {
		let mut services = HashMap::new();
		services.insert("web".to_string(), simple_service("true"));

		let options = OrchestratorOptions {
			filter: vec!["nonexistent".to_string()],
			..Default::default()
		};
		let dir = tempfile::TempDir::new().unwrap();
		let result = run_services(dir.path(), &services, options);

		assert!(result.is_err());
		let err = result.unwrap_err().to_string();
		assert!(
			err.contains("nonexistent"),
			"error should name the unknown service: {err}"
		);
		assert!(err.contains("not found"), "error should say not found: {err}");
	}
}
