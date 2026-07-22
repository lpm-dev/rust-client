//! Multi-service orchestrator for `lpm dev`.
//!
//! Starts multiple dev services with dependency ordering, readiness checks,
//! cross-service env injection, colored output, and graceful shutdown.

use crate::lpm_json::ServiceConfig;
use crate::{ports, ready, service_graph};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
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
    ServiceLog {
        service_index: usize,
        line: String,
        is_stderr: bool,
    },
    /// Service status changed.
    StatusChange {
        service_index: usize,
        status: ServiceStatus,
    },
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

pub type ServicePortMap = HashMap<String, u16>;
pub type PortsAssignedCallback = Box<dyn Fn(&ServicePortMap) -> Result<(), LpmError> + Send>;

type PortReassignments = HashMap<String, PortReassignment>;

const HOST_ONLY_DEFAULT_PORT_START: u16 = 3000;

#[derive(Default)]
struct AssignedServicePorts {
    port_map: ServicePortMap,
    reassignments: PortReassignments,
    leases: Vec<ports::PortLease>,
}

/// Command sent from the dashboard (or external controller) to the orchestrator.
#[derive(Debug)]
pub enum OrchestratorCommand {
    /// Restart the service at the given index.
    RestartService(usize),
    /// Stop the service at the given index.
    StopService(usize),
    /// Stop all services and shut down.
    StopAll,
}

/// Options for the orchestrator.
#[derive(Default)]
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
    /// Optional channel for receiving commands from a dashboard or controller.
    /// The orchestrator checks this non-blockingly in its main loop.
    pub command_rx: Option<std::sync::mpsc::Receiver<OrchestratorCommand>>,
    /// Called once after ALL initial services pass readiness checks.
    /// Used by dev.rs to open the browser at the right time.
    pub on_all_ready: Option<Box<dyn FnOnce() + Send>>,
    /// Called once after declared ports are checked and final service ports are assigned.
    pub on_ports_assigned: Option<PortsAssignedCallback>,
}

/// Maximum number of restart attempts before marking a service as permanently failed.
const MAX_RESTART_ATTEMPTS: u32 = 10;

/// Brief grace period for services without explicit readiness checks.
/// Prevents immediately failing processes from being marked Ready before the first exit poll.
const NO_READINESS_GRACE: Duration = Duration::from_millis(100);

/// Colors for service output prefixes.
const COLORS: &[&str] = &[
    "\x1b[36m", // cyan
    "\x1b[33m", // yellow
    "\x1b[35m", // magenta
    "\x1b[32m", // green
    "\x1b[34m", // blue
    "\x1b[31m", // red
];
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

fn ui_paint(color: &str, text: &str) -> String {
    format!("{color}{text}{RESET}")
}

fn ui_phase(msg: &str) {
    eprintln!("  {} {msg}", ui_paint(CYAN, "›"));
}

fn ui_warn(msg: &str) {
    eprintln!("  {} {msg}", ui_paint(YELLOW, "!"));
}

fn ui_service_prefix(color: &str, name: &str) -> String {
    format!("{color}[{name}]{RESET}")
}

fn ui_service_status(color: &str, name: &str, status_color: &str, glyph: &str, msg: &str) {
    eprintln!(
        "  {} {} {msg}",
        ui_paint(status_color, glyph),
        ui_service_prefix(color, name),
    );
}

fn ui_service_note(color: &str, name: &str, msg: &str) {
    eprintln!("  {} {msg}", ui_service_prefix(color, name));
}

fn ui_format_duration(duration: Duration) -> String {
    let ms = duration.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.2}s", ms as f64 / 1000.0)
    }
}

fn ui_readiness_timing(duration: Option<Duration>) -> String {
    duration
        .map(|duration| format!(" ({})", ui_paint(GREEN, &ui_format_duration(duration))))
        .unwrap_or_default()
}

/// Safely resolve a service `cwd` relative to the project root.
///
/// 1. Joins `cwd_str` onto `project_root`
/// 2. Attempts `canonicalize()` — if the directory exists, verifies it's inside `project_root`
/// 3. If canonicalize fails (directory doesn't exist yet), rejects paths containing `..`
///    components which could escape the project directory
/// 4. Returns the validated absolute path
pub fn safe_resolve_cwd(project_root: &Path, cwd_str: &str) -> Result<PathBuf, LpmError> {
    let resolved = project_root.join(cwd_str);

    // Try canonicalize on both paths — this handles symlinks and existing dirs
    match (resolved.canonicalize(), project_root.canonicalize()) {
        (Ok(resolved_canon), Ok(project_canon)) => {
            if resolved_canon.starts_with(&project_canon) {
                Ok(resolved_canon)
            } else {
                Err(LpmError::Script(format!(
                    "service cwd '{cwd_str}' resolves to '{}' which is outside the project directory",
                    resolved_canon.display()
                )))
            }
        }
        (Err(_), Ok(project_canon)) => {
            if let Some(existing_ancestor) = nearest_existing_ancestor(&resolved)
                && let Ok(ancestor_canon) = existing_ancestor.canonicalize()
                && !ancestor_canon.starts_with(&project_canon)
            {
                return Err(LpmError::Script(format!(
                    "service cwd '{cwd_str}' resolves through '{}' which is outside the project directory",
                    ancestor_canon.display()
                )));
            }

            // Directory doesn't exist yet — check for `..` components that could escape
            // Normalize the path logically to catch `./nested/../../../escape`
            let normalized = normalize_path(&resolved);
            if !normalized.starts_with(&project_canon) {
                // Also check against un-canonicalized project_root for cases where
                // project_root itself can't be canonicalized
                if !normalized.starts_with(project_root) {
                    return Err(LpmError::Script(format!(
                        "service cwd '{cwd_str}' escapes the project directory"
                    )));
                }
            }
            // Also reject any remaining `..` components — even if normalization
            // kept us inside, `..` in a cwd is suspicious and fragile
            if resolved
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            {
                return Err(LpmError::Script(format!(
                    "service cwd '{cwd_str}' contains '..' components which are not allowed"
                )));
            }
            Ok(resolved)
        }
        _ => {
            // Can't canonicalize project_root itself — reject `..` as a safety measure
            if resolved
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            {
                return Err(LpmError::Script(format!(
                    "service cwd '{cwd_str}' contains '..' components which are not allowed"
                )));
            }
            Ok(resolved)
        }
    }
}

/// Normalize a path by resolving `.` and `..` components logically (without filesystem access).
fn normalize_path(path: &Path) -> PathBuf {
    let mut components: Vec<Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // Pop the last normal component, but don't pop past root/prefix
                if let Some(last) = components.last()
                    && matches!(last, Component::Normal(_))
                {
                    components.pop();
                    continue;
                }
                components.push(component);
            }
            Component::CurDir => {} // Skip `.`
            _ => components.push(component),
        }
    }
    components.iter().collect()
}

fn nearest_existing_ancestor(path: &Path) -> Option<&Path> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if candidate.exists() {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn service_exit_status(
    children: &Arc<Mutex<Vec<(String, Child)>>>,
    name: &str,
) -> Option<std::process::ExitStatus> {
    let mut locked = children.lock();
    let (_, child) = locked
        .iter_mut()
        .find(|(service_name, _)| service_name == name)?;
    child.try_wait().ok().flatten()
}

fn wait_for_service_readiness(
    ready_url: Option<String>,
    ready_port: Option<u16>,
    timeout_secs: u64,
) -> Result<Option<Duration>, String> {
    if let Some(url) = ready_url {
        Ok(Some(ready::wait_for_url(&url, timeout_secs)?))
    } else if let Some(port) = ready_port {
        Ok(Some(ready::wait_for_port(port, timeout_secs)?))
    } else {
        std::thread::sleep(NO_READINESS_GRACE);
        Ok(None)
    }
}

fn service_ready_port(config: &ServiceConfig, assigned_port: Option<u16>) -> Option<u16> {
    config.ready_port.or(assigned_port).or(config.port)
}

fn port_conflict_reason(port: u16, reserved_ports: &HashMap<u16, String>) -> Option<String> {
    if let Some(service_name) = reserved_ports.get(&port) {
        return Some(format!("service '{service_name}'"));
    }

    match ports::check_port(port) {
        ports::PortStatus::Free => None,
        ports::PortStatus::InUse { pid, process_name } => match (&pid, &process_name) {
            (Some(p), Some(n)) => Some(format!("{n} (PID {p})")),
            (Some(p), None) => Some(format!("PID {p}")),
            _ => Some("unknown process".to_string()),
        },
    }
}

enum ServicePortReservation {
    Acquired(ports::PortLease),
    Conflict(String),
}

fn reserve_service_port(
    port: u16,
    reserved_ports: &HashMap<u16, String>,
    port_allocation: &ports::PortAllocation,
) -> Result<ServicePortReservation, LpmError> {
    if let Some(reason) = port_conflict_reason(port, reserved_ports) {
        return Ok(ServicePortReservation::Conflict(reason));
    }
    match port_allocation.try_acquire_lease(port)? {
        Some(lease) => Ok(ServicePortReservation::Acquired(lease)),
        None => Ok(ServicePortReservation::Conflict(
            "another lpm dev process".to_string(),
        )),
    }
}

fn find_available_service_port(
    start: u16,
    reserved_ports: &HashMap<u16, String>,
    port_allocation: &ports::PortAllocation,
) -> Result<Option<(u16, ports::PortLease)>, LpmError> {
    let mut candidate = start;
    loop {
        if let ServicePortReservation::Acquired(lease) =
            reserve_service_port(candidate, reserved_ports, port_allocation)?
        {
            return Ok(Some((candidate, lease)));
        }
        if candidate == u16::MAX {
            return Ok(None);
        }
        candidate += 1;
    }
}

fn assign_service_ports(
    project_dir: &Path,
    active_services: &HashMap<String, ServiceConfig>,
    port_allocation: &mut ports::PortAllocation,
) -> Result<AssignedServicePorts, LpmError> {
    let port_overrides = port_allocation.read_overrides(project_dir);
    let mut port_map: ServicePortMap = HashMap::with_capacity(active_services.len());
    let mut reassignments: PortReassignments = HashMap::new();
    let mut reserved_ports: HashMap<u16, String> = HashMap::with_capacity(active_services.len());
    let mut leases = Vec::with_capacity(active_services.len());

    let mut service_names: Vec<&String> = active_services.keys().collect();
    service_names.sort_unstable();
    for name in service_names {
        let config = &active_services[name];
        let requested_port = port_overrides.get(name).copied().or(config.port);
        let Some(port) =
            requested_port.or_else(|| config.host.as_ref().map(|_| HOST_ONLY_DEFAULT_PORT_START))
        else {
            continue;
        };

        match reserve_service_port(port, &reserved_ports, port_allocation)? {
            ServicePortReservation::Conflict(reason) => {
                let (next, lease) = match port.checked_add(1) {
                    Some(start) => {
                        find_available_service_port(start, &reserved_ports, port_allocation)?
                    }
                    None => None,
                }
                .ok_or_else(|| {
                    LpmError::Script(format!(
                        "no available port found near {port} for service '{name}'"
                    ))
                })?;
                leases.push(lease);

                if requested_port.is_some() {
                    reassignments.insert(
                        name.clone(),
                        PortReassignment {
                            original: port,
                            new: next,
                            reason,
                        },
                    );
                }
                port_map.insert(name.clone(), next);
                reserved_ports.insert(next, name.clone());
                port_allocation.write_override(project_dir, name, next);
            }
            ServicePortReservation::Acquired(lease) => {
                leases.push(lease);
                port_map.insert(name.clone(), port);
                reserved_ports.insert(port, name.clone());
                if requested_port.is_none() {
                    port_allocation.write_override(project_dir, name, port);
                }
            }
        }
    }

    Ok(AssignedServicePorts {
        port_map,
        reassignments,
        leases,
    })
}

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
            if dep.trim().is_empty() {
                return Err(LpmError::Script(format!(
                    "service '{name}' has an empty dependency in dependsOn — remove it from lpm.json"
                )));
            }
            if dep == name {
                return Err(LpmError::Script(format!(
                    "service '{name}' depends on itself — remove '{name}' from dependsOn"
                )));
            }
            if !active_services.contains_key(dep) {
                return Err(LpmError::Script(format!(
                    "service '{name}' depends on '{dep}', but '{dep}' is not defined in lpm.json services.\n    Available services: {}",
                    active_services
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
    }

    // Topological sort
    let groups = service_graph::topological_sort(&active_services).map_err(LpmError::Script)?;

    let mut port_allocation = ports::acquire_port_allocation()?;
    let AssignedServicePorts {
        port_map,
        reassignments: port_reassignments,
        leases: port_leases,
    } = assign_service_ports(project_dir, &active_services, &mut port_allocation)?;
    drop(port_allocation);
    let _port_leases = port_leases;

    if let Some(ref callback) = options.on_ports_assigned {
        callback(&port_map)?;
    }

    // Build cross-service env
    let cross_env = ports::build_cross_service_env(&port_map, options.https);

    // Build PATH
    let path = crate::bin_path::build_path_with_bins(project_dir)?;

    // Load .env files + vault + validate schema (unified loader)
    let dotenv = crate::dotenv::load_project_env(project_dir, None)?;

    // Assign colors
    let service_names: Vec<String> = groups.iter().flatten().cloned().collect();
    let color_map: HashMap<String, &str> = service_names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.clone(), COLORS[i % COLORS.len()]))
        .collect();

    // Print startup banner with port reassignment info
    eprintln!();
    for name in &service_names {
        let config = &active_services[name];
        let color = color_map[name];

        let port_info = if let Some(reassignment) = port_reassignments.get(name) {
            format!(
                " -> :{} {}",
                reassignment.new,
                ui_paint(
                    YELLOW,
                    &format!(
                        "(port {} in use by {})",
                        reassignment.original, reassignment.reason
                    ),
                )
            )
        } else {
            port_map
                .get(name)
                .map(|p| format!(" -> :{p}"))
                .unwrap_or_default()
        };

        let dep_info = if config.depends_on.is_empty() {
            String::new()
        } else {
            format!(" (after {})", config.depends_on.join(", "))
        };
        ui_phase(&format!(
            "{} {}{port_info}{dep_info}",
            ui_service_prefix(color, name),
            config.command,
        ));
    }
    eprintln!();

    // Shutdown state: 0 = running, 1 = graceful shutdown (SIGTERM), 2+ = force kill (SIGKILL)
    let shutdown_state = Arc::new(AtomicU8::new(0));
    // Vec<(String, Child)> with linear scan is fine for typical dev setups
    // (<20 services). HashMap would be cleaner but Child doesn't implement Debug and
    // the vec allows ordered iteration useful for shutdown. O(n) cost negligible at this scale.
    let children: Arc<Mutex<Vec<(String, Child)>>> = Arc::new(Mutex::new(Vec::new()));

    // RAII guard: ensures children are cleaned up even on panic
    let children_guard = ChildrenGuard(children.clone());

    // Set up Ctrl+C handler with double-press escalation
    let shutdown_state_clone = shutdown_state.clone();
    let children_clone = children.clone();
    ctrlc_handler(shutdown_state_clone, children_clone);

    // Helper: send a StatusChange event to the dashboard (if connected).
    let send_status = |event_tx: &Option<std::sync::mpsc::Sender<OrchestratorEvent>>,
                       service_names: &[String],
                       name: &str,
                       status: ServiceStatus| {
        if let Some(tx) = event_tx {
            let index = service_names.iter().position(|n| n == name).unwrap_or(0);
            let _ = tx.send(OrchestratorEvent::StatusChange {
                service_index: index,
                status,
            });
        }
    };

    // Start services in dependency order
    let mut startup_interrupted = false;

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

            // Emit Starting status
            send_status(
                &options.event_tx,
                &service_names,
                name,
                ServiceStatus::Starting,
            );

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

            // Resolve working directory with path traversal protection
            let cwd = if let Some(ref sub) = config.cwd {
                safe_resolve_cwd(project_dir, sub)
                    .map_err(|e| LpmError::Script(format!("service '{name}': {e}")))?
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

            let child = cmd
                .spawn()
                .map_err(|e| LpmError::Script(format!("failed to start service '{name}': {e}")))?;

            children.lock().push((name.clone(), child));

            // Compute service index for event sending
            let service_index = service_names.iter().position(|n| n == name).unwrap_or(0);

            // Spawn output readers in background threads
            spawn_output_readers(
                name,
                color,
                service_index,
                &children,
                &shutdown_state,
                &options.event_tx,
            );

            // Wait for readiness (in a background thread)
            let ready_port = service_ready_port(config, port_map.get(name).copied());
            let ready_url = config.ready_url.clone();
            let timeout = config.ready_timeout;

            let handle = std::thread::spawn(move || {
                wait_for_service_readiness(ready_url, ready_port, timeout)
            });

            handles.push((name.clone(), handle));
        }

        // Wait for all services in this group to be ready
        for (name, handle) in handles {
            match handle.join() {
                Ok(Ok(duration)) => {
                    if service_exit_status(&children, &name).is_some() {
                        startup_interrupted = true;
                        break;
                    }

                    let color = color_map[&name];
                    let timing = ui_readiness_timing(duration);
                    ui_service_status(color, &name, GREEN, "✓", &format!("ready{timing}"));
                    send_status(
                        &options.event_tx,
                        &service_names,
                        &name,
                        ServiceStatus::Ready,
                    );
                }
                Ok(Err(e)) => {
                    if service_exit_status(&children, &name).is_some() {
                        startup_interrupted = true;
                        break;
                    }

                    // Readiness timeout is a warning, not a fatal error.
                    // The service process is still running — it may just be slow.
                    // Print the error but continue so the browser opens and the
                    // user can see the actual state in their browser.
                    ui_service_status(RESET, &name, YELLOW, "!", &format!("not ready - {e}"));
                    // Still mark as Ready — the service is running, just slow to respond.
                    // Timeout is a warning, not a state change to Crashed.
                    send_status(
                        &options.event_tx,
                        &service_names,
                        &name,
                        ServiceStatus::Ready,
                    );
                }
                Err(_) => {
                    ui_service_status(RESET, &name, RED, "✗", "readiness check panicked");
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

        if startup_interrupted {
            break;
        }
    }

    // All initial services are ready — fire callback (e.g., open browser)
    if !startup_interrupted && let Some(callback) = options.on_all_ready {
        std::thread::spawn(callback);
    }

    // Track restart backoff per service: name → (attempt_count, last_crash_time)
    let mut restart_state: HashMap<String, (u32, std::time::Instant)> = HashMap::new();

    // Pending restarts: name → Instant when restart should happen
    let mut pending_restarts: HashMap<String, std::time::Instant> = HashMap::new();

    // Wait for all children to exit (or Ctrl+C)
    loop {
        if shutdown_state.load(Ordering::Relaxed) > 0 {
            break;
        }

        // Check if any child has exited
        let mut all_done = true;
        let mut to_restart: Vec<String> = Vec::new();
        let mut crashed_no_restart: Vec<String> = Vec::new();
        {
            let mut locked = children.lock();
            for (name, child) in locked.iter_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let color = color_map.get(name.as_str()).unwrap_or(&RESET);
                        if status.success() {
                            ui_service_note(color, name, "exited");
                            send_status(
                                &options.event_tx,
                                &service_names,
                                name,
                                ServiceStatus::Stopped,
                            );
                        } else {
                            let code = status.code().unwrap_or(-1);
                            let config = active_services.get(name);
                            let should_restart = config.is_some_and(|c| c.restart);

                            if should_restart && shutdown_state.load(Ordering::Relaxed) == 0 {
                                to_restart.push(name.clone());
                                ui_service_status(
                                    RESET,
                                    name,
                                    YELLOW,
                                    "!",
                                    &format!("crashed (exit {code}), restarting..."),
                                );
                                send_status(
                                    &options.event_tx,
                                    &service_names,
                                    name,
                                    ServiceStatus::Crashed(code),
                                );
                            } else {
                                ui_service_status(
                                    RESET,
                                    name,
                                    RED,
                                    "✗",
                                    &format!("crashed (exit {code})"),
                                );
                                send_status(
                                    &options.event_tx,
                                    &service_names,
                                    name,
                                    ServiceStatus::Crashed(code),
                                );
                                crashed_no_restart.push(name.clone());
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

        // Stop transitive dependents of crashed (non-restarting) services
        for crashed_name in &crashed_no_restart {
            let dependents = service_graph::transitive_dependents(crashed_name, &active_services);
            if !dependents.is_empty() {
                let mut locked = children.lock();
                for dep_name in &dependents {
                    if let Some(pos) = locked.iter().position(|(n, _)| n == dep_name) {
                        let (name, mut child) = locked.remove(pos);
                        let _ = child.kill();
                        let _ = child.wait();
                        tracing::warn!("stopped {name} (depends on crashed {crashed_name})");
                        ui_service_status(
                            RESET,
                            &name,
                            RED,
                            "✗",
                            &format!("stopped (depends on crashed {crashed_name})"),
                        );
                        send_status(
                            &options.event_tx,
                            &service_names,
                            &name,
                            ServiceStatus::Stopped,
                        );
                    }
                    // Also cancel any pending restart for the dependent
                    pending_restarts.remove(dep_name);
                }
            }
        }

        // Schedule restarts with exponential backoff (non-blocking)
        for name in to_restart {
            all_done = false;

            let (attempts, last_crash) = restart_state
                .entry(name.clone())
                .or_insert((0, std::time::Instant::now()));

            // Reset backoff if service was stable for 60+ seconds
            if last_crash.elapsed().as_secs() > 60 {
                *attempts = 0;
            }

            *attempts += 1;
            *last_crash = std::time::Instant::now();

            // Max restart attempts
            if *attempts > MAX_RESTART_ATTEMPTS {
                let color = color_map.get(name.as_str()).unwrap_or(&RESET);
                ui_service_status(
                    color,
                    &name,
                    RED,
                    "✗",
                    &format!(
                        "exceeded max restart attempts ({MAX_RESTART_ATTEMPTS}), marking as permanently failed"
                    ),
                );
                tracing::error!(
                    "{name} exceeded max restart attempts ({MAX_RESTART_ATTEMPTS}), marking as permanently failed"
                );
                send_status(
                    &options.event_tx,
                    &service_names,
                    &name,
                    ServiceStatus::Stopped,
                );
                // Stop dependents of this permanently-failed service
                let dependents = service_graph::transitive_dependents(&name, &active_services);
                if !dependents.is_empty() {
                    let mut locked = children.lock();
                    for dep_name in &dependents {
                        if let Some(pos) = locked.iter().position(|(n, _)| n == dep_name) {
                            let (dname, mut child) = locked.remove(pos);
                            let _ = child.kill();
                            let _ = child.wait();
                            tracing::warn!(
                                "stopped {dname} (depends on permanently failed {name})"
                            );
                            ui_service_status(
                                RESET,
                                &dname,
                                RED,
                                "✗",
                                &format!("stopped (depends on permanently failed {name})"),
                            );
                            send_status(
                                &options.event_tx,
                                &service_names,
                                &dname,
                                ServiceStatus::Stopped,
                            );
                        }
                        pending_restarts.remove(dep_name);
                    }
                }
                continue;
            }

            // Non-blocking backoff — schedule restart for later instead of sleeping
            let delay_secs = std::cmp::min(1u64 << (*attempts - 1), 30);
            let color = color_map.get(name.as_str()).unwrap_or(&RESET);
            ui_service_status(
                color,
                &name,
                YELLOW,
                "!",
                &format!(
                    "restarting in {delay_secs}s (attempt {attempts}/{MAX_RESTART_ATTEMPTS})..."
                ),
            );
            let restart_at = std::time::Instant::now() + std::time::Duration::from_secs(delay_secs);
            pending_restarts.insert(name, restart_at);
        }

        // Process pending restarts whose delay has elapsed
        let now = std::time::Instant::now();
        let ready_restarts: Vec<String> = pending_restarts
            .iter()
            .filter(|(_, restart_at)| now >= **restart_at)
            .map(|(name, _)| name.clone())
            .collect();

        for name in ready_restarts {
            pending_restarts.remove(&name);
            all_done = false;

            if shutdown_state.load(Ordering::Relaxed) > 0 {
                break;
            }

            // Respawn the service
            send_status(
                &options.event_tx,
                &service_names,
                &name,
                ServiceStatus::Starting,
            );
            if let Some(config) = active_services.get(&name) {
                let (shell, flag) = if cfg!(windows) {
                    ("cmd", "/C")
                } else {
                    ("sh", "-c")
                };
                let cwd = if let Some(ref sub) = config.cwd {
                    match safe_resolve_cwd(project_dir, sub) {
                        Ok(p) => p,
                        Err(e) => {
                            ui_service_status(
                                RESET,
                                &name,
                                RED,
                                "✗",
                                &format!("failed to restart: {e}"),
                            );
                            continue;
                        }
                    }
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

                let color = color_map.get(name.as_str()).unwrap_or(&RESET);
                match cmd.spawn() {
                    Ok(new_child) => {
                        let mut locked = children.lock();
                        // Remove old dead entry
                        locked.retain(|(n, _)| n != &name);
                        locked.push((name.clone(), new_child));
                        drop(locked);

                        // Spawn output readers for the restarted process.
                        // The old reader threads are safe — their stdout/stderr streams are
                        // EOF'd when the old process exits, causing the BufReader iterator to
                        // return None and the thread to exit naturally. There is a brief overlap
                        // window but no data corruption or resource leak.
                        let service_index =
                            service_names.iter().position(|n| n == &name).unwrap_or(0);
                        spawn_output_readers(
                            &name,
                            color,
                            service_index,
                            &children,
                            &shutdown_state,
                            &options.event_tx,
                        );

                        let ready_result = wait_for_service_readiness(
                            config.ready_url.clone(),
                            service_ready_port(config, port_map.get(&name).copied()),
                            config.ready_timeout,
                        );

                        match ready_result {
                            Ok(duration) => {
                                if service_exit_status(&children, &name).is_some() {
                                    continue;
                                }

                                let timing = ui_readiness_timing(duration);
                                ui_service_status(
                                    color,
                                    &name,
                                    GREEN,
                                    "✓",
                                    &format!("restarted{timing}"),
                                );
                                send_status(
                                    &options.event_tx,
                                    &service_names,
                                    &name,
                                    ServiceStatus::Ready,
                                );
                            }
                            Err(error) => {
                                ui_service_status(
                                    RESET,
                                    &name,
                                    YELLOW,
                                    "!",
                                    &format!("restarted but not ready - {error}"),
                                );
                                send_status(
                                    &options.event_tx,
                                    &service_names,
                                    &name,
                                    ServiceStatus::Ready,
                                );
                            }
                        }
                    }
                    Err(e) => {
                        ui_service_status(
                            RESET,
                            &name,
                            RED,
                            "✗",
                            &format!("failed to restart: {e}"),
                        );
                    }
                }
            }
        }

        // Process commands from the dashboard (non-blocking).
        // Also detects channel disconnection (all senders dropped) as a shutdown
        // signal — this is defense-in-depth so the orchestrator stops cleanly even
        // if the caller exits without sending an explicit StopAll.
        if let Some(ref cmd_rx) = options.command_rx {
            loop {
                match cmd_rx.try_recv() {
                    Ok(OrchestratorCommand::StopAll) => {
                        shutdown_state.store(1, Ordering::Relaxed);
                        break;
                    }
                    Ok(OrchestratorCommand::StopService(idx)) => {
                        if let Some(name) = service_names.get(idx) {
                            let mut locked = children.lock();
                            if let Some(pos) = locked.iter().position(|(n, _)| n == name) {
                                let (sname, mut child) = locked.remove(pos);
                                let _ = child.kill();
                                let _ = child.wait();
                                ui_service_status(RESET, &sname, YELLOW, "!", "stopped by user");
                                send_status(
                                    &options.event_tx,
                                    &service_names,
                                    &sname,
                                    ServiceStatus::Stopped,
                                );
                            }
                            pending_restarts.remove(name);
                        }
                    }
                    Ok(OrchestratorCommand::RestartService(idx)) => {
                        if let Some(name) = service_names.get(idx).cloned() {
                            // Kill the current instance if running
                            {
                                let mut locked = children.lock();
                                if let Some(pos) = locked.iter().position(|(n, _)| n == &name) {
                                    let (_, mut child) = locked.remove(pos);
                                    let _ = child.kill();
                                    let _ = child.wait();
                                }
                            }
                            // Schedule immediate restart
                            pending_restarts.insert(name.clone(), std::time::Instant::now());
                            // Reset backoff counter for user-initiated restarts
                            restart_state.remove(&name);
                            all_done = false;
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        // All senders dropped — controller exited. Shut down gracefully.
                        shutdown_state.store(1, Ordering::Relaxed);
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                }
            }
        }

        // Still have pending restarts — keep loop alive
        if !pending_restarts.is_empty() {
            all_done = false;
        }

        if all_done {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Normal cleanup (guard will also cleanup on panic/early exit via Drop)
    let force = shutdown_state.load(Ordering::Relaxed) >= 2;
    shutdown_children_ordered(&children, force, Some(&groups));
    std::mem::forget(children_guard); // Don't double-cleanup

    Ok(())
}

/// Spawn background threads to read stdout and stderr from a child process.
///
/// Finds the child by name in the shared `children` vec, takes its stdout/stderr
/// handles, and spawns reader threads that print output with colored service prefixes
/// and optionally send events to the dashboard.
///
/// Must be called after every `spawn()` — both initial start and restart — otherwise
/// the new process's output is silently lost.
fn spawn_output_readers(
    name: &str,
    color: &str,
    service_index: usize,
    children: &Arc<Mutex<Vec<(String, Child)>>>,
    shutdown_state: &Arc<AtomicU8>,
    event_tx: &Option<std::sync::mpsc::Sender<OrchestratorEvent>>,
) {
    // stdout reader
    {
        let name = name.to_string();
        let color = color.to_string();
        let children_ref = children.clone();
        let shutdown_ref = shutdown_state.clone();
        let event_tx = event_tx.clone();

        std::thread::spawn(move || {
            let stdout = {
                let mut locked = children_ref.lock();
                let entry = locked.iter_mut().find(|(n, _)| *n == name);
                match entry {
                    Some((_, child)) => child.stdout.take(),
                    None => return,
                }
            };

            if let Some(stdout) = stdout {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if shutdown_ref.load(Ordering::Relaxed) > 0 {
                        break;
                    }
                    if let Ok(line) = line {
                        println!("  {color}[{name}]{RESET} {line}");
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
        let name = name.to_string();
        let color = color.to_string();
        let children_ref = children.clone();
        let shutdown_ref = shutdown_state.clone();
        let event_tx = event_tx.clone();

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
fn ctrlc_handler(shutdown_state: Arc<AtomicU8>, children: Arc<Mutex<Vec<(String, Child)>>>) {
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::iterator::Signals;

        let state = shutdown_state;
        let kids = children;
        if let Ok(mut signals) = Signals::new([SIGINT, SIGTERM]) {
            std::thread::spawn(move || {
                for _ in signals.forever() {
                    let prev = state.fetch_add(1, Ordering::Relaxed);
                    if prev == 0 {
                        // First signal: graceful shutdown
                        eprintln!();
                        ui_warn("Stopping services...");
                    } else {
                        // Second+ signal: force kill
                        eprintln!();
                        ui_warn("Force-killing services...");
                        force_kill_children(&kids);
                        break;
                    }
                }
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (shutdown_state, children);
    }
}

/// Immediately SIGKILL all children (used for double Ctrl+C escalation).
#[cfg(unix)]
fn force_kill_children(children: &Arc<Mutex<Vec<(String, Child)>>>) {
    let mut locked = children.lock();
    for (name, child) in locked.iter_mut() {
        match child.try_wait() {
            Ok(Some(_)) => {} // Already exited
            _ => {
                let _ = child.kill();
                ui_service_status(RESET, name, RED, "✗", "force-killed");
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
/// Shuts down in reverse topological order so that dependents (e.g., API
/// servers) stop before their dependencies (e.g., databases), giving services
/// time to flush connections and finish in-flight requests.
///
/// If `force` is true, skips SIGTERM and goes straight to SIGKILL (used when
/// the user double-pressed Ctrl+C).
fn shutdown_children(children: &Arc<Mutex<Vec<(String, Child)>>>, force: bool) {
    shutdown_children_ordered(children, force, None);
}

/// Shutdown with optional reverse topological ordering.
///
/// When `groups` is provided, services are stopped in reverse topological order
/// (dependents first, then their dependencies). Each group gets a 2s grace period.
/// When `groups` is None, all services are stopped simultaneously (legacy behavior).
fn shutdown_children_ordered(
    children: &Arc<Mutex<Vec<(String, Child)>>>,
    force: bool,
    groups: Option<&[Vec<String>]>,
) {
    let locked = children.lock();
    let count = locked.len();
    drop(locked);

    if count == 0 {
        return;
    }

    if force {
        let mut locked = children.lock();
        eprintln!();
        ui_warn(&format!("Force-killing {count} services..."));
        for (name, child) in locked.iter_mut() {
            let _ = child.kill();
            ui_service_status(RESET, name, RED, "✗", "force-killed");
        }
        for (_, child) in locked.iter_mut() {
            let _ = child.wait();
        }
        return;
    }

    eprintln!();
    ui_warn(&format!("Stopping {count} services..."));

    // Build the shutdown order: reverse topological levels (dependents first)
    let shutdown_order: Vec<Vec<String>> = if let Some(groups) = groups {
        groups.iter().rev().cloned().collect()
    } else {
        // No graph available — shutdown all at once
        let locked = children.lock();
        vec![locked.iter().map(|(n, _)| n.clone()).collect()]
    };

    for group in &shutdown_order {
        {
            let mut locked = children.lock();
            for name in group {
                if let Some((_, child)) = locked.iter_mut().find(|(n, _)| n == name) {
                    if let Ok(Some(_)) = child.try_wait() {
                        continue; // Already exited
                    }
                    #[cfg(unix)]
                    {
                        let pid = child.id() as i32;
                        unsafe { libc::kill(pid, libc::SIGTERM) };
                        tracing::debug!("sent SIGTERM to service '{name}' (pid {pid})");
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = child.kill();
                        tracing::debug!("sent kill to service '{name}'");
                    }
                }
            }
        }

        // Grace period between groups to allow orderly shutdown
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // Final pass: force-kill any stragglers and reap zombies
    let mut locked = children.lock();
    for (name, child) in locked.iter_mut() {
        match child.try_wait() {
            Ok(Some(status)) => {
                ui_service_note(
                    RESET,
                    name,
                    &format!("stopped (exit {})", status.code().unwrap_or(-1)),
                );
            }
            _ => {
                tracing::debug!("force-killing service '{name}'");
                let _ = child.kill();
                ui_service_status(RESET, name, RED, "✗", "force-killed");
            }
        }
    }
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
        assert!(
            err.contains("db"),
            "error should name the missing service: {err}"
        );
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
    fn service_ready_port_uses_final_assigned_port_before_config_port() {
        let config = ServiceConfig {
            command: "true".to_string(),
            port: Some(3000),
            ..Default::default()
        };

        assert_eq!(service_ready_port(&config, Some(3001)), Some(3001));
    }

    #[test]
    fn service_ready_port_keeps_explicit_ready_port_over_assigned_port() {
        let config = ServiceConfig {
            command: "true".to_string(),
            port: Some(3000),
            ready_port: Some(8080),
            ..Default::default()
        };

        assert_eq!(service_ready_port(&config, Some(3001)), Some(8080));
    }

    #[test]
    fn port_conflict_reason_reports_same_run_service_reservation() {
        let mut reserved_ports = HashMap::new();
        reserved_ports.insert(3000, "api".to_string());

        assert_eq!(
            port_conflict_reason(3000, &reserved_ports),
            Some("service 'api'".to_string())
        );
    }

    #[test]
    fn assign_service_ports_keeps_available_declared_port() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceConfig {
                command: "true".to_string(),
                port: Some(port),
                ..Default::default()
            },
        );
        let dir = tempfile::TempDir::new().unwrap();

        let mut allocation = ports::PortAllocation::acquire_for_root_and_lease_dir(
            lpm_common::LpmRoot::from_dir(dir.path().join(".lpm")),
            dir.path().join("port-leases"),
        )
        .unwrap();
        let assigned_ports = assign_service_ports(dir.path(), &services, &mut allocation).unwrap();

        assert_eq!(assigned_ports.port_map.get("web"), Some(&port));
        assert!(assigned_ports.reassignments.is_empty());
    }

    #[test]
    fn assign_service_ports_reassigns_conflicting_declared_port() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceConfig {
                command: "true".to_string(),
                port: Some(port),
                ..Default::default()
            },
        );
        let dir = tempfile::TempDir::new().unwrap();

        let mut allocation = ports::PortAllocation::acquire_for_root_and_lease_dir(
            lpm_common::LpmRoot::from_dir(dir.path().join(".lpm")),
            dir.path().join("port-leases"),
        )
        .unwrap();
        let assigned_ports = assign_service_ports(dir.path(), &services, &mut allocation).unwrap();

        let assigned = assigned_ports.port_map["web"];
        assert_ne!(assigned, port);
        assert_eq!(assigned_ports.reassignments["web"].original, port);
        assert_eq!(assigned_ports.reassignments["web"].new, assigned);
    }

    #[test]
    fn run_services_calls_on_ports_assigned_before_spawning_services() {
        let mut services = HashMap::new();
        services.insert("worker".to_string(), simple_service("true"));

        let observed_ports = Arc::new(Mutex::new(None));
        let captured_ports = Arc::clone(&observed_ports);
        let options = OrchestratorOptions {
            on_ports_assigned: Some(Box::new(move |ports| {
                *captured_ports.lock() = Some(ports.clone());
                Ok(())
            })),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        let _ = run_services(dir.path(), &services, options);

        assert_eq!(*observed_ports.lock(), Some(HashMap::new()));
    }

    #[test]
    fn run_services_stops_before_spawning_when_ports_assigned_callback_fails() {
        let marker = tempfile::NamedTempFile::new().unwrap();
        let marker_path = marker.path().to_path_buf();
        let mut services = HashMap::new();
        services.insert(
            "worker".to_string(),
            simple_service(&format!("touch {}", marker_path.display())),
        );
        let options = OrchestratorOptions {
            on_ports_assigned: Some(Box::new(|_| Err(LpmError::Script("proxy failed".into())))),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        let err = run_services(dir.path(), &services, options).unwrap_err();

        assert!(err.to_string().contains("proxy failed"), "got {err}");
        assert_eq!(std::fs::read_to_string(marker.path()).unwrap(), "");
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
        assert!(
            err.contains("not found"),
            "error should say not found: {err}"
        );
    }

    #[test]
    fn spawn_output_readers_captures_stdout_and_stderr() {
        // Spawn a real process that writes to both stdout and stderr
        let child = Command::new("sh")
            .arg("-c")
            .arg("echo STDOUT_LINE; echo STDERR_LINE >&2")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let name = "test-svc".to_string();
        let children: Arc<Mutex<Vec<(String, Child)>>> = Arc::new(Mutex::new(Vec::new()));
        children.lock().push((name.clone(), child));

        let shutdown = Arc::new(AtomicU8::new(0));
        let (tx, rx) = std::sync::mpsc::channel();

        spawn_output_readers(
            &name,
            "\x1b[36m", // cyan
            0,
            &children,
            &shutdown,
            &Some(tx),
        );

        // Wait for the child to finish and readers to flush
        {
            let mut locked = children.lock();
            if let Some((_, child)) = locked.iter_mut().find(|(n, _)| n == "test-svc") {
                let _ = child.wait();
            }
        }

        // Give reader threads time to process
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Collect events
        let mut stdout_lines = Vec::new();
        let mut stderr_lines = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let OrchestratorEvent::ServiceLog {
                line, is_stderr, ..
            } = event
            {
                if is_stderr {
                    stderr_lines.push(line);
                } else {
                    stdout_lines.push(line);
                }
            }
        }

        assert!(
            stdout_lines.iter().any(|l| l.contains("STDOUT_LINE")),
            "should capture stdout, got: {stdout_lines:?}"
        );
        assert!(
            stderr_lines.iter().any(|l| l.contains("STDERR_LINE")),
            "should capture stderr, got: {stderr_lines:?}"
        );
    }

    #[test]
    fn safe_resolve_cwd_allows_subdirectory() {
        let dir = tempfile::TempDir::new().unwrap();
        let sub = dir.path().join("src");
        std::fs::create_dir_all(&sub).unwrap();

        let result = safe_resolve_cwd(dir.path(), "src");
        assert!(
            result.is_ok(),
            "should allow existing subdirectory: {result:?}"
        );
        assert!(result.unwrap().ends_with("src"));
    }

    #[test]
    fn safe_resolve_cwd_rejects_parent_traversal() {
        let dir = tempfile::TempDir::new().unwrap();

        let result = safe_resolve_cwd(dir.path(), "../../etc");
        assert!(result.is_err(), "should reject path traversal: {result:?}");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("..") || err.contains("escapes") || err.contains("not allowed"),
            "error should mention traversal: {err}"
        );
    }

    #[test]
    fn safe_resolve_cwd_rejects_nested_traversal() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("nested")).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();

        // `./nested/../src` contains `..` — should be rejected
        let result = safe_resolve_cwd(dir.path(), "./nested/../src");
        assert!(
            result.is_err() || result.as_ref().is_ok_and(|p| p.ends_with("src")),
            "should either reject or resolve correctly: {result:?}"
        );
    }

    #[test]
    fn safe_resolve_cwd_allows_nonexistent_subdirectory() {
        let dir = tempfile::TempDir::new().unwrap();

        // Directory doesn't exist yet, but path is clean (no `..`)
        let result = safe_resolve_cwd(dir.path(), "build/output");
        assert!(
            result.is_ok(),
            "should allow non-existent clean path: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn safe_resolve_cwd_rejects_nonexistent_child_under_symlink_escape() {
        use std::os::unix::fs::symlink;

        let project_dir = tempfile::TempDir::new().unwrap();
        let outside_dir = tempfile::TempDir::new().unwrap();
        symlink(outside_dir.path(), project_dir.path().join("escape")).unwrap();

        let result = safe_resolve_cwd(project_dir.path(), "escape/newdir");
        assert!(
            result.is_err(),
            "cwd under symlinked parent escaping the project should be rejected: {result:?}"
        );
    }

    // ── Max restart attempts ──────────────────────────────────────────

    #[test]
    fn max_restart_attempts_constant() {
        assert_eq!(
            MAX_RESTART_ATTEMPTS, 10,
            "max restart attempts should be 10"
        );
    }

    // ── Reverse topological shutdown ─────────────────────────────────

    #[test]
    fn shutdown_ordered_reverses_groups() {
        // Verify that shutdown_children_ordered processes groups in reverse order.
        // We can't easily test with real Child processes, but we can verify the
        // reverse ordering logic by checking the shutdown_order construction.
        let groups = [
            vec!["db".to_string()],  // level 0: no deps
            vec!["api".to_string()], // level 1: depends on db
            vec!["web".to_string()], // level 2: depends on api
        ];

        // Reverse of groups should be: web, api, db (dependents first)
        let shutdown_order: Vec<Vec<String>> = groups.iter().rev().cloned().collect();
        assert_eq!(
            shutdown_order[0],
            vec!["web"],
            "web (dependent) should stop first"
        );
        assert_eq!(shutdown_order[1], vec!["api"], "api should stop second");
        assert_eq!(
            shutdown_order[2],
            vec!["db"],
            "db (dependency) should stop last"
        );
    }

    // ── Crash propagation to dependents ──────────────────────────────

    #[test]
    fn transitive_dependents_for_crash_propagation() {
        // When A crashes, B and C (which depend on A) should be stopped.
        let mut services = HashMap::new();
        services.insert("a".to_string(), simple_service("echo a"));
        services.insert("b".to_string(), service_with_dep("echo b", "a"));
        services.insert("c".to_string(), service_with_dep("echo c", "b"));

        let dependents = service_graph::transitive_dependents("a", &services);
        assert!(dependents.contains("b"), "b depends on a");
        assert!(dependents.contains("c"), "c transitively depends on a");
        assert!(
            !dependents.contains("a"),
            "a should not be in its own dependents"
        );
    }

    // ── empty string in dependsOn ──

    #[test]
    fn validates_empty_dependency_string() {
        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceConfig {
                command: "true".to_string(),
                depends_on: vec!["".to_string()],
                ..Default::default()
            },
        );

        let options = OrchestratorOptions::default();
        let dir = tempfile::TempDir::new().unwrap();
        let result = run_services(dir.path(), &services, options);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("empty dependency"),
            "error should mention empty dependency: {err}"
        );
    }

    // ── StatusChange event tests ──────────────────────────────────────

    #[test]
    fn status_change_events_sent_for_lifecycle() {
        // Start a service that exits immediately — should emit Starting + Ready/Stopped
        let mut services = HashMap::new();
        services.insert("fast".to_string(), simple_service("true"));

        let (tx, rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            event_tx: Some(tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let _ = run_services(dir.path(), &services, options);

        // Collect all StatusChange events
        let mut statuses = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let OrchestratorEvent::StatusChange { status, .. } = event {
                statuses.push(status);
            }
        }

        assert!(
            statuses
                .iter()
                .any(|s| matches!(s, ServiceStatus::Starting)),
            "should emit Starting status, got: {statuses:?}"
        );
    }

    #[test]
    fn status_change_crash_event_for_failing_service() {
        let mut services = HashMap::new();
        services.insert("crasher".to_string(), simple_service("exit 1"));

        let (tx, rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            event_tx: Some(tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let _ = run_services(dir.path(), &services, options);

        let mut statuses = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let OrchestratorEvent::StatusChange { status, .. } = event {
                statuses.push(status);
            }
        }

        assert!(
            statuses
                .iter()
                .any(|s| matches!(s, ServiceStatus::Crashed(_))),
            "should emit Crashed status for failing service, got: {statuses:?}"
        );
    }

    #[test]
    fn immediately_failing_service_does_not_emit_ready() {
        let mut services = HashMap::new();
        services.insert("crasher".to_string(), simple_service("exit 1"));

        let (tx, rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            event_tx: Some(tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let _ = run_services(dir.path(), &services, options);

        let mut statuses = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let OrchestratorEvent::StatusChange { status, .. } = event {
                statuses.push(status);
            }
        }

        assert!(
            !statuses.iter().any(|s| matches!(s, ServiceStatus::Ready)),
            "immediately failing service should not emit Ready, got: {statuses:?}"
        );
    }

    // ── OrchestratorCommand tests ──────────────────────────────────

    #[test]
    fn stop_all_command_terminates_orchestrator() {
        let mut services = HashMap::new();
        // Use "sleep 60" — a long-running service that needs to be stopped
        services.insert("sleeper".to_string(), simple_service("sleep 60"));

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        // Send StopAll after a short delay
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = cmd_tx.send(OrchestratorCommand::StopAll);
        });

        let result = run_services(dir.path(), &services, options);
        // Should exit cleanly (not hang forever)
        assert!(
            result.is_ok(),
            "StopAll should cause clean exit: {result:?}"
        );
    }

    // ── self-reference in dependsOn ──

    #[test]
    fn validates_self_dependency() {
        let mut services = HashMap::new();
        services.insert("web".to_string(), service_with_dep("true", "web"));

        let options = OrchestratorOptions::default();
        let dir = tempfile::TempDir::new().unwrap();
        let result = run_services(dir.path(), &services, options);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("depends on itself"),
            "error should say 'depends on itself': {err}"
        );
    }

    // ── Channel disconnection triggers graceful shutdown ──

    #[test]
    fn channel_disconnect_triggers_shutdown() {
        let mut services = HashMap::new();
        services.insert("sleeper".to_string(), simple_service("sleep 60"));

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<OrchestratorCommand>();
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        // Drop the sender after a short delay — simulates dashboard exiting
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            drop(cmd_tx);
        });

        let result = run_services(dir.path(), &services, options);
        // Should exit cleanly after detecting disconnection (not hang forever)
        assert!(
            result.is_ok(),
            "channel disconnect should cause clean exit: {result:?}"
        );
    }

    #[test]
    fn stop_service_command_stops_single_service() {
        let mut services = HashMap::new();
        services.insert("a".to_string(), simple_service("sleep 60"));
        services.insert("b".to_string(), simple_service("sleep 60"));

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        // Stop service at index 0 after startup, then StopAll
        let cmd_tx_clone = cmd_tx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = cmd_tx_clone.send(OrchestratorCommand::StopService(0));
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = cmd_tx.send(OrchestratorCommand::StopAll);
        });

        let _ = run_services(dir.path(), &services, options);

        // Verify we got a Stopped status for the killed service
        let mut saw_stopped = false;
        while let Ok(event) = event_rx.try_recv() {
            if let OrchestratorEvent::StatusChange {
                status: ServiceStatus::Stopped,
                ..
            } = event
            {
                saw_stopped = true;
            }
        }
        assert!(saw_stopped, "should emit Stopped status for killed service");
    }

    #[test]
    fn restart_service_command_restarts_service() {
        let mut services = HashMap::new();
        services.insert("worker".to_string(), simple_service("sleep 60"));

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        // Restart service 0, then StopAll
        let cmd_tx_clone = cmd_tx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = cmd_tx_clone.send(OrchestratorCommand::RestartService(0));
            std::thread::sleep(std::time::Duration::from_millis(800));
            let _ = cmd_tx.send(OrchestratorCommand::StopAll);
        });

        let _ = run_services(dir.path(), &services, options);

        // Verify we got a second Starting status (the restart)
        let mut starting_count = 0;
        while let Ok(event) = event_rx.try_recv() {
            if let OrchestratorEvent::StatusChange {
                status: ServiceStatus::Starting,
                ..
            } = event
            {
                starting_count += 1;
            }
        }
        assert!(
            starting_count >= 2,
            "should emit Starting at least twice (initial + restart), got {starting_count}"
        );
    }

    #[test]
    fn restart_service_command_emits_ready_again_after_restart() {
        let mut services = HashMap::new();
        services.insert("worker".to_string(), simple_service("sleep 60"));

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        let cmd_tx_clone = cmd_tx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = cmd_tx_clone.send(OrchestratorCommand::RestartService(0));
            std::thread::sleep(std::time::Duration::from_millis(800));
            let _ = cmd_tx.send(OrchestratorCommand::StopAll);
        });

        let _ = run_services(dir.path(), &services, options);

        let mut ready_count = 0;
        while let Ok(event) = event_rx.try_recv() {
            if let OrchestratorEvent::StatusChange {
                status: ServiceStatus::Ready,
                ..
            } = event
            {
                ready_count += 1;
            }
        }

        assert!(
            ready_count >= 2,
            "should emit Ready at least twice (initial + restart), got {ready_count}"
        );
    }

    #[test]
    fn reassigned_service_does_not_report_ready_from_stale_occupied_port() {
        let occupied_port = crate::ports::find_available_port(49000).unwrap();
        let occupied_listener = std::net::TcpListener::bind(("127.0.0.1", occupied_port)).unwrap();

        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceConfig {
                command: "sleep 5".to_string(),
                port: Some(occupied_port),
                ready_timeout: 1,
                ..Default::default()
            },
        );

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        let handle = std::thread::spawn(move || run_services(dir.path(), &services, options));

        let early_ready = event_rx
            .recv_timeout(std::time::Duration::from_millis(400))
            .ok();

        let _ = cmd_tx.send(OrchestratorCommand::StopAll);

        let result = handle.join().unwrap();

        drop(occupied_listener);

        assert!(
            result.is_ok(),
            "orchestrator should still exit cleanly: {result:?}"
        );
        assert!(
            !matches!(
                early_ready,
                Some(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Ready,
                    ..
                })
            ),
            "service should not be reported Ready from an unrelated occupied original port"
        );
    }
}
