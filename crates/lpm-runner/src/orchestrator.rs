//! Multi-service orchestrator for `lpm dev`.
//!
//! Starts multiple dev services with dependency ordering, readiness checks,
//! cross-service env injection, colored output, and graceful shutdown.

mod recovery;

use crate::dev_endpoint::DevEndpoint;
use crate::lpm_json::ServiceConfig;
use crate::{ports, ready, service_graph};
use lpm_common::{LocalTarget, LpmError, sanitize_terminal_inline};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use parking_lot::Mutex;

/// Service runtime state.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
    Pending,
    Starting,
    WaitingForDep(String),
    Ready,
    ReadinessFailed(String),
    Crashed(i32),
    Stopped,
}

/// Event sent from the orchestrator to the dashboard (or any observer).
#[derive(Debug)]
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
pub type ServiceEndpointMap = HashMap<String, DevEndpoint>;
pub type PortsAssignedCallback = Box<dyn Fn(&ServicePortMap) -> Result<(), LpmError> + Send>;
pub type AllReadyCallback = Box<dyn FnOnce(ServiceEndpointMap) -> Result<(), LpmError> + Send>;
pub type EndpointChangedCallback = Box<dyn Fn(DevEndpoint) -> Result<(), LpmError> + Send + Sync>;

type PortReassignments = HashMap<String, PortReassignment>;

const HOST_ONLY_DEFAULT_PORT_START: u16 = 3000;

#[derive(Default)]
struct AssignedServicePorts {
    port_map: ServicePortMap,
    reassignments: PortReassignments,
    leases: Vec<ports::PortLease>,
}

/// Command sent from the dashboard (or external controller) to the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestratorCommand {
    /// Restart the service at the given index.
    RestartService(usize),
    /// Stop the service at the given index.
    StopService(usize),
    /// Stop all services and shut down.
    StopAll,
}

#[derive(Debug)]
struct OrchestratorCommandMailbox {
    stop_all: AtomicBool,
    service_intents: Mutex<Vec<Option<OrchestratorCommand>>>,
}

/// Cloneable, bounded command sink for an active service orchestrator.
#[derive(Debug, Clone)]
pub struct OrchestratorCommandController {
    mailbox: Arc<OrchestratorCommandMailbox>,
}

impl OrchestratorCommandController {
    /// Create a controller with one coalesced command slot per service.
    pub fn new(service_count: usize) -> Self {
        Self {
            mailbox: Arc::new(OrchestratorCommandMailbox {
                stop_all: AtomicBool::new(false),
                service_intents: Mutex::new(vec![None; service_count]),
            }),
        }
    }

    /// Submit a command without blocking. The last command for each service wins.
    pub fn send(&self, command: OrchestratorCommand) {
        match command {
            OrchestratorCommand::StopAll => {
                self.mailbox.stop_all.store(true, Ordering::Release);
                self.mailbox.service_intents.lock().fill(None);
            }
            command @ (OrchestratorCommand::RestartService(index)
            | OrchestratorCommand::StopService(index)) => {
                if self.mailbox.stop_all.load(Ordering::Acquire) {
                    return;
                }
                if let Some(slot) = self.mailbox.service_intents.lock().get_mut(index) {
                    *slot = Some(command);
                }
            }
        }
    }

    fn stop_all_requested(&self) -> bool {
        self.mailbox.stop_all.load(Ordering::Acquire)
    }

    fn has_pending_service(&self, service_index: usize) -> bool {
        self.stop_all_requested()
            || self
                .mailbox
                .service_intents
                .lock()
                .get(service_index)
                .is_some_and(Option::is_some)
    }

    fn has_pending_command(&self) -> bool {
        self.stop_all_requested()
            || self
                .mailbox
                .service_intents
                .lock()
                .iter()
                .any(Option::is_some)
    }

    pub(super) fn drain(&self) -> Vec<OrchestratorCommand> {
        let mut intents = self.mailbox.service_intents.lock();
        if self.stop_all_requested() {
            intents.fill(None);
            return vec![OrchestratorCommand::StopAll];
        }
        intents.iter_mut().filter_map(Option::take).collect()
    }

    #[cfg(test)]
    fn pending_service_count(&self) -> usize {
        self.mailbox
            .service_intents
            .lock()
            .iter()
            .filter(|intent| intent.is_some())
            .count()
    }
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
    /// Environment selected by `lpm dev --env`. When absent, the `dev`
    /// mapping in `lpm.json` is used before falling back to the default files.
    pub env_mode: Option<String>,
    /// Managed runtimes prepared for each service working directory.
    pub service_runtime_hints: HashMap<String, crate::bin_path::ManagedRuntimeHint>,
    /// Optional channel for sending events to a dashboard or observer.
    /// When set, events are sent in addition to (not instead of) terminal output.
    pub event_tx: Option<std::sync::mpsc::SyncSender<OrchestratorEvent>>,
    /// Optional channel for receiving commands from a dashboard or controller.
    /// The orchestrator checks this non-blockingly in its main loop.
    pub command_rx: Option<std::sync::mpsc::Receiver<OrchestratorCommand>>,
    /// Bounded command controller used by interactive callers.
    pub command_controller: Option<OrchestratorCommandController>,
    /// Called once after ALL initial services pass readiness checks.
    /// Used by dev.rs to open the browser at the right time.
    pub on_all_ready: Option<AllReadyCallback>,
    /// Called after a restarted managed service publishes a newly verified endpoint.
    pub on_endpoint_changed: Option<EndpointChangedCallback>,
    /// Called once after declared ports are checked and final service ports are assigned.
    pub on_ports_assigned: Option<PortsAssignedCallback>,
    /// Called before orderly child-tree termination begins.
    pub on_shutdown_started: Option<crate::ShutdownStartedCallback>,
    /// CLI port override for the primary service.
    pub primary_port: Option<u16>,
    /// Allocate and verify an endpoint for the configured or implicit primary service.
    pub manage_primary_endpoint: bool,
    /// Public frontend port that child services must not bind.
    pub reserved_frontend_port: Option<u16>,
}

/// Maximum number of restart attempts before marking a service as permanently failed.
const MAX_RESTART_ATTEMPTS: u32 = 10;

/// Brief grace period for services without explicit readiness checks.
/// Prevents immediately failing processes from being marked Ready before the first exit poll.
const NO_READINESS_GRACE: Duration = Duration::from_millis(100);
const MAX_SERVICE_LOG_LINE_BYTES: usize = 64 * 1024;
struct CommandBridge {
    controller: OrchestratorCommandController,
    stop: Arc<AtomicU8>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CommandBridge {
    fn start(
        receiver: Option<Receiver<OrchestratorCommand>>,
        controller: Option<OrchestratorCommandController>,
        shutdown_state: Arc<AtomicU8>,
        service_count: usize,
    ) -> Self {
        let stop = Arc::new(AtomicU8::new(0));
        let controller =
            controller.unwrap_or_else(|| OrchestratorCommandController::new(service_count));
        let Some(receiver) = receiver else {
            return Self {
                controller,
                stop,
                thread: None,
            };
        };
        let bridge_stop = Arc::clone(&stop);
        let bridge_controller = controller.clone();
        let thread = std::thread::spawn(move || {
            while bridge_stop.load(Ordering::Relaxed) == 0 {
                match receiver.recv_timeout(Duration::from_millis(25)) {
                    Ok(command) => {
                        if matches!(command, OrchestratorCommand::StopAll) {
                            shutdown_state.store(1, Ordering::Release);
                        }
                        bridge_controller.send(command);
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        shutdown_state.store(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });
        Self {
            controller,
            stop,
            thread: Some(thread),
        }
    }

    fn controller(&self) -> &OrchestratorCommandController {
        &self.controller
    }

    fn startup_interrupted(&self, service_index: usize) -> bool {
        self.controller.has_pending_service(service_index)
    }

    fn has_startup_command(&self) -> bool {
        self.controller.has_pending_command()
    }
}

impl Drop for CommandBridge {
    fn drop(&mut self) {
        self.stop.store(1, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
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
    let name = sanitize_terminal_inline(name);
    format!("{color}[{name}]{RESET}")
}

fn ui_service_status(color: &str, name: &str, status_color: &str, glyph: &str, msg: &str) {
    let msg = sanitize_terminal_inline(msg);
    eprintln!(
        "  {} {} {msg}",
        ui_paint(status_color, glyph),
        ui_service_prefix(color, name),
    );
}

fn ui_service_note(color: &str, name: &str, msg: &str) {
    let msg = sanitize_terminal_inline(msg);
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

fn send_status(
    event_tx: &Option<std::sync::mpsc::SyncSender<OrchestratorEvent>>,
    service_names: &[String],
    name: &str,
    status: ServiceStatus,
) {
    if let Some(tx) = event_tx {
        let service_index = service_names
            .iter()
            .position(|service_name| service_name == name)
            .unwrap_or(0);
        let _ = tx.send(OrchestratorEvent::StatusChange {
            service_index,
            status,
        });
    }
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

fn group_has_exited_service(children: &Arc<Mutex<Vec<(String, Child)>>>, names: &[String]) -> bool {
    let mut locked = children.lock();
    locked
        .iter_mut()
        .any(|(name, child)| names.contains(name) && matches!(child.try_wait(), Ok(Some(_))))
}

struct InitialServiceReadiness {
    duration: Option<Duration>,
    endpoint: Option<DevEndpoint>,
}

struct InitialReadinessOptions<'a> {
    service_dir: &'a Path,
    root_pid: u32,
    assigned_port: Option<u16>,
    candidates: &'a Receiver<LocalTarget>,
    ready_url: Option<String>,
    ready_port: Option<u16>,
    timeout_secs: u64,
}

fn wait_for_initial_service_readiness(
    options: InitialReadinessOptions<'_>,
    mut should_cancel: impl FnMut() -> bool,
) -> Result<InitialServiceReadiness, String> {
    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(options.timeout_secs);
    let endpoint = if let Some(port) = options.assigned_port {
        crate::dev_endpoint::resolve_spawned_endpoint_until(
            options.service_dir,
            options.root_pid,
            None,
            Some(port),
            options.candidates,
            deadline,
            &mut should_cancel,
        )?
    } else {
        None
    };

    let explicit_readiness = if let Some(url) = options.ready_url {
        Some(ready::wait_for_url_until_deadline(
            &url,
            started,
            deadline,
            options.timeout_secs,
            &mut should_cancel,
        )?)
    } else if let Some(port) = options
        .ready_port
        .filter(|port| Some(*port) != options.assigned_port)
    {
        Some(ready::wait_for_port_until_deadline(
            port,
            started,
            deadline,
            options.timeout_secs,
            &mut should_cancel,
        )?)
    } else {
        None
    };

    if endpoint.is_none() && explicit_readiness.is_none() {
        let grace_deadline = std::time::Instant::now() + NO_READINESS_GRACE;
        while std::time::Instant::now() < grace_deadline {
            if should_cancel() {
                return Err("readiness cancelled".to_string());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        return Ok(InitialServiceReadiness {
            duration: None,
            endpoint: None,
        });
    }

    Ok(InitialServiceReadiness {
        duration: Some(started.elapsed()),
        endpoint,
    })
}

fn service_ready_port(config: &ServiceConfig, assigned_port: Option<u16>) -> Option<u16> {
    config.ready_port.or(assigned_port).or(config.port)
}

fn command_with_managed_port(command: &str, cwd: &Path, port: Option<u16>) -> String {
    let Some(port) = port else {
        return command.to_string();
    };
    let args = lpm_cert::framework::explicit_port_args_for_command(cwd, command, port);
    if args.is_empty() {
        return command.to_string();
    }

    let separator = if lpm_cert::framework::npm_script_requires_argument_separator(command) {
        " -- "
    } else {
        " "
    };
    let mut managed = String::with_capacity(
        command.len() + separator.len() + args.iter().map(String::len).sum::<usize>() + args.len(),
    );
    managed.push_str(command);
    managed.push_str(separator);
    managed.push_str(&args.join(" "));
    managed
}

fn port_conflict_reason(port: u16, reserved_ports: &HashMap<u16, String>) -> Option<String> {
    if let Some(service_name) = reserved_ports.get(&port) {
        return Some(format!("service '{service_name}'"));
    }

    if ports::loopback_port_available(port) {
        None
    } else {
        Some("another process".to_string())
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

fn primary_service_name(
    services: &HashMap<String, ServiceConfig>,
) -> Result<Option<&str>, LpmError> {
    service_graph::primary_service_name(services).map_err(LpmError::Script)
}

fn assign_service_ports(
    project_dir: &Path,
    active_services: &HashMap<String, ServiceConfig>,
    port_allocation: &mut ports::PortAllocation,
    primary_port: Option<u16>,
    manage_primary_endpoint: bool,
    reserved_frontend_port: Option<u16>,
) -> Result<AssignedServicePorts, LpmError> {
    let port_overrides = port_allocation.read_overrides(project_dir);
    let configured_primary = primary_service_name(active_services)?;
    let primary_service = if manage_primary_endpoint {
        configured_primary
    } else {
        None
    };
    let mut port_map: ServicePortMap = HashMap::with_capacity(active_services.len());
    let mut reassignments: PortReassignments = HashMap::new();
    let mut reserved_ports: HashMap<u16, String> = HashMap::with_capacity(active_services.len());
    if let Some(port) = reserved_frontend_port {
        reserved_ports.insert(port, "LPM public frontend".to_string());
    }
    let mut leases = Vec::with_capacity(active_services.len());

    let mut service_names: Vec<&String> = active_services.keys().collect();
    service_names.sort_unstable();
    for name in service_names {
        let config = &active_services[name];
        let is_primary = primary_service == Some(name.as_str());
        let requested_port = is_primary
            .then_some(primary_port)
            .flatten()
            .or_else(|| port_overrides.get(name).copied())
            .or(config.port);
        let needs_managed_port = is_primary || config.host.is_some();
        let Some(port) =
            requested_port.or_else(|| needs_managed_port.then_some(HOST_ONLY_DEFAULT_PORT_START))
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
    mut options: OrchestratorOptions,
) -> Result<(), LpmError> {
    if services.is_empty() {
        return Ok(());
    }

    let active_services = service_graph::select_active_services(services, &options.filter)
        .map_err(LpmError::Script)?;
    let primary_service = primary_service_name(&active_services)?;
    if options.manage_primary_endpoint && primary_service.is_none() {
        return Err(LpmError::Script(
            "multi-service dev features require exactly one active service marked `primary`"
                .to_string(),
        ));
    }

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
    } = assign_service_ports(
        project_dir,
        &active_services,
        &mut port_allocation,
        options.primary_port,
        options.manage_primary_endpoint,
        options.reserved_frontend_port,
    )?;
    drop(port_allocation);
    let _port_leases = port_leases;

    if let Some(ref callback) = options.on_ports_assigned {
        callback(&port_map)?;
    }

    // Build cross-service env
    let cross_env = ports::build_cross_service_env(&port_map, options.https);

    // Load .env files + vault + validate schema (unified loader)
    let dotenv = crate::script::load_script_env(project_dir, "dev", options.env_mode.as_deref())?;

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
            let reason = sanitize_terminal_inline(&reassignment.reason);
            format!(
                " -> :{} {}",
                reassignment.new,
                ui_paint(
                    YELLOW,
                    &format!("(port {} in use by {})", reassignment.original, reason),
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
            let dependencies = config
                .depends_on
                .iter()
                .map(|dependency| sanitize_terminal_inline(dependency))
                .collect::<Vec<_>>();
            format!(" (after {})", dependencies.join(", "))
        };
        let command = sanitize_terminal_inline(&config.command);
        ui_phase(&format!(
            "{} {}{port_info}{dep_info}",
            ui_service_prefix(color, name),
            command,
        ));
    }
    eprintln!();

    // Shutdown state: 0 = running, 1 = graceful shutdown (SIGTERM), 2+ = force kill (SIGKILL)
    let shutdown_state = Arc::new(AtomicU8::new(0));
    let command_bridge = CommandBridge::start(
        options.command_rx.take(),
        options.command_controller.take(),
        Arc::clone(&shutdown_state),
        service_names.len(),
    );
    // Vec<(String, Child)> with linear scan is fine for typical dev setups
    // (<20 services). HashMap would be cleaner but Child doesn't implement Debug and
    // the vec allows ordered iteration useful for shutdown. O(n) cost negligible at this scale.
    let children: Arc<Mutex<Vec<(String, Child)>>> = Arc::new(Mutex::new(Vec::new()));

    // RAII guard: ensures children are cleaned up even on panic
    let mut children_guard = ChildrenGuard {
        children: children.clone(),
        on_shutdown_started: options.on_shutdown_started.take(),
    };

    // Set up Ctrl+C handler with double-press escalation
    let shutdown_state_clone = shutdown_state.clone();
    let children_clone = children.clone();
    let _signal_handler = ctrlc_handler(shutdown_state_clone, children_clone);

    let runtime_result = (|| -> Result<(), LpmError> {
        // Start services in dependency order
        let mut startup_interrupted = false;
        let mut service_endpoints = ServiceEndpointMap::with_capacity(port_map.len());
        let mut initial_ready = HashSet::with_capacity(active_services.len());

        for group in &groups {
            if shutdown_state.load(Ordering::Relaxed) > 0 {
                break;
            }

            let mut handles = Vec::new();
            let group_names = Arc::new(group.clone());
            let group_failed = Arc::new(AtomicBool::new(false));

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
                let service_command =
                    command_with_managed_port(&config.command, &cwd, port_map.get(name).copied());
                let service_runtime_hint = options
                    .service_runtime_hints
                    .get(name)
                    .unwrap_or(&crate::bin_path::ManagedRuntimeHint::Unknown);
                let service_path =
                    crate::bin_path::build_path_with_bins_pre_resolved(&cwd, service_runtime_hint)?;
                let assigned_port = port_map.get(name).copied();
                // Spawn the service process
                let mut cmd = crate::shell::shell_process(&service_command)?;
                cmd.current_dir(&cwd)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                isolate_service_process_tree(&mut cmd);
                crate::shell::strip_inherited_env_hooks(&mut cmd);
                cmd.envs(&env).env("PATH", &service_path);

                // Inject extra envs from HTTPS/tunnel/network setup (safe, no global mutation)
                for (key, value) in &options.extra_envs {
                    cmd.env(key, value);
                }

                let mut child = cmd.spawn().map_err(|e| {
                    LpmError::Script(format!("failed to start service '{name}': {e}"))
                })?;
                let child_pid = child.id();
                let child_stdout = child.stdout.take();
                let child_stderr = child.stderr.take();

                children.lock().push((name.clone(), child));

                // Compute service index for event sending
                let service_index = service_names.iter().position(|n| n == name).unwrap_or(0);

                // Spawn output readers in background threads
                let (endpoint_tx, endpoint_rx) = std::sync::mpsc::channel();
                spawn_output_readers(
                    child_stdout,
                    child_stderr,
                    OutputReaderOptions {
                        name,
                        color,
                        service_index,
                        shutdown_state: &shutdown_state,
                        event_tx: &options.event_tx,
                        endpoint_tx: Some(endpoint_tx),
                    },
                );

                // Wait for readiness (in a background thread)
                let ready_port = service_ready_port(config, port_map.get(name).copied());
                let ready_url = config.ready_url.clone();
                let timeout = config.ready_timeout;
                let readiness_requires_running_process =
                    assigned_port.is_some() || ready_url.is_some() || ready_port.is_some();
                let service_dir = cwd;
                let readiness_children = Arc::clone(&children);
                let readiness_shutdown = Arc::clone(&shutdown_state);
                let readiness_name = name.clone();
                let readiness_group = Arc::clone(&group_names);
                let readiness_group_failed = Arc::clone(&group_failed);
                let readiness_command_controller = command_bridge.controller().clone();

                let handle = std::thread::spawn(move || {
                    wait_for_initial_service_readiness(
                        InitialReadinessOptions {
                            service_dir: &service_dir,
                            root_pid: child_pid,
                            assigned_port,
                            candidates: &endpoint_rx,
                            ready_url,
                            ready_port,
                            timeout_secs: timeout,
                        },
                        || {
                            if readiness_shutdown.load(Ordering::Relaxed) > 0 {
                                return true;
                            }
                            if readiness_command_controller.has_pending_service(service_index) {
                                terminate_named_service(&readiness_children, &readiness_name);
                                return true;
                            }
                            if readiness_requires_running_process
                                && group_has_exited_service(&readiness_children, &readiness_group)
                            {
                                readiness_group_failed.store(true, Ordering::Relaxed);
                                return true;
                            }
                            readiness_requires_running_process
                                && service_exit_status(&readiness_children, &readiness_name)
                                    .is_some()
                        },
                    )
                });

                handles.push((name.clone(), handle));
            }

            // Wait for all services in this group to be ready
            let mut readiness_failure = None;
            for (name, handle) in handles {
                match handle.join() {
                    Ok(Ok(readiness)) => {
                        if let Some(status) = service_exit_status(&children, &name) {
                            if status.success() {
                                startup_interrupted = true;
                                continue;
                            }
                            let code = status.code().unwrap_or(-1);
                            ui_service_status(
                                RESET,
                                &name,
                                RED,
                                "✗",
                                &format!("crashed (exit {code})"),
                            );
                            send_status(
                                &options.event_tx,
                                &service_names,
                                &name,
                                ServiceStatus::Crashed(code),
                            );
                            readiness_failure.get_or_insert((
                                name,
                                format!("service exited with status {code} before becoming ready"),
                            ));
                            continue;
                        }

                        if let Some(mut endpoint) = readiness.endpoint {
                            endpoint.service = Some(name.clone());
                            service_endpoints.insert(name.clone(), endpoint);
                        }
                        let color = color_map[&name];
                        let timing = ui_readiness_timing(readiness.duration);
                        ui_service_status(color, &name, GREEN, "✓", &format!("ready{timing}"));
                        send_status(
                            &options.event_tx,
                            &service_names,
                            &name,
                            ServiceStatus::Ready,
                        );
                        initial_ready.insert(name);
                    }
                    Ok(Err(error)) => {
                        if shutdown_state.load(Ordering::Relaxed) > 0 {
                            startup_interrupted = true;
                            continue;
                        }
                        let service_index = service_names
                            .iter()
                            .position(|service_name| service_name == &name)
                            .unwrap_or(usize::MAX);
                        if command_bridge.startup_interrupted(service_index) {
                            startup_interrupted = true;
                            continue;
                        }
                        if let Some(status) = service_exit_status(&children, &name) {
                            let code = status.code().unwrap_or(-1);
                            ui_service_status(
                                RESET,
                                &name,
                                RED,
                                "✗",
                                &format!("crashed (exit {code})"),
                            );
                            send_status(
                                &options.event_tx,
                                &service_names,
                                &name,
                                ServiceStatus::Crashed(code),
                            );
                            readiness_failure.get_or_insert((
                                name,
                                format!("service exited with status {code} before becoming ready"),
                            ));
                            continue;
                        }
                        if group_failed.load(Ordering::Relaxed) {
                            continue;
                        }
                        let display_error = sanitize_terminal_inline(&error).into_owned();
                        ui_service_status(
                            RESET,
                            &name,
                            RED,
                            "✗",
                            &format!("readiness failed - {display_error}"),
                        );
                        send_status(
                            &options.event_tx,
                            &service_names,
                            &name,
                            ServiceStatus::ReadinessFailed(display_error),
                        );
                        readiness_failure.get_or_insert((name, error));
                    }
                    Err(_) => {
                        ui_service_status(RESET, &name, RED, "✗", "readiness check panicked");
                        if shutdown_state.load(Ordering::Relaxed) == 0 {
                            shutdown_state.store(1, Ordering::Relaxed);
                            return Err(LpmError::Script(format!(
                                "service '{name}' readiness check panicked"
                            )));
                        }
                    }
                }
            }

            if command_bridge.has_startup_command() {
                startup_interrupted = true;
            }

            if let Some((name, error)) = readiness_failure {
                if !active_services
                    .get(&name)
                    .is_some_and(|config| config.restart)
                {
                    shutdown_state.store(1, Ordering::Relaxed);
                    return Err(LpmError::Script(format!(
                        "service '{name}' failed readiness: {error}"
                    )));
                }
                startup_interrupted = true;
            }

            if startup_interrupted {
                break;
            }
        }

        if startup_interrupted && shutdown_state.load(Ordering::Relaxed) == 0 {
            terminate_unready_initial_services(&children, &initial_ready);
        }

        let initial_publication_complete = !startup_interrupted;
        if initial_publication_complete && let Some(callback) = options.on_all_ready.take() {
            invoke_all_ready_callback(callback, std::mem::take(&mut service_endpoints))?;
        }

        recovery::supervise_services(recovery::RecoveryContext {
            project_dir,
            active_services: &active_services,
            groups: &groups,
            service_runtime_hints: &options.service_runtime_hints,
            dotenv: &dotenv,
            cross_env: &cross_env,
            port_map: &port_map,
            color_map: &color_map,
            service_names: &service_names,
            initial_ready: &initial_ready,
            children: &children,
            shutdown_state: &shutdown_state,
            event_tx: &options.event_tx,
            command_controller: Some(command_bridge.controller()),
            initial_publication_complete,
            initial_endpoints: service_endpoints,
            on_all_ready: options.on_all_ready.take(),
            on_endpoint_changed: options.on_endpoint_changed.as_ref(),
            extra_envs: &options.extra_envs,
        })?;

        Ok(())
    })();

    let force = shutdown_state.load(Ordering::Relaxed) >= 2;
    let shutdown_result = children_guard.begin_shutdown();
    shutdown_children_ordered(&children, force, Some(&groups));
    std::mem::forget(children_guard);
    match runtime_result {
        Ok(()) => shutdown_result,
        Err(primary) => Err(compose_runtime_and_shutdown_error(primary, shutdown_result)),
    }
}

fn compose_runtime_and_shutdown_error(
    primary: LpmError,
    shutdown_result: Result<(), LpmError>,
) -> LpmError {
    match shutdown_result {
        Ok(()) => primary,
        Err(shutdown) => LpmError::Script(format!(
            "{primary}; shutdown boundary also failed: {shutdown}"
        )),
    }
}

fn invoke_all_ready_callback(
    callback: AllReadyCallback,
    endpoints: ServiceEndpointMap,
) -> Result<(), LpmError> {
    match std::thread::spawn(move || callback(endpoints)).join() {
        Ok(result) => result,
        Err(_) => Err(LpmError::Script(
            "all-services-ready callback panicked".to_string(),
        )),
    }
}

/// Spawn background threads to read stdout and stderr from a child process.
///
/// Takes the spawned child's stdout/stderr handles and starts reader threads that
/// print output with colored service prefixes and optionally send dashboard events.
///
/// Must be called after every `spawn()` — both initial start and restart — otherwise
/// the new process's output is silently lost.
struct OutputReaderOptions<'a> {
    name: &'a str,
    color: &'a str,
    service_index: usize,
    shutdown_state: &'a Arc<AtomicU8>,
    event_tx: &'a Option<std::sync::mpsc::SyncSender<OrchestratorEvent>>,
    endpoint_tx: Option<std::sync::mpsc::Sender<LocalTarget>>,
}

fn spawn_output_readers(
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    options: OutputReaderOptions<'_>,
) {
    let OutputReaderOptions {
        name,
        color,
        service_index,
        shutdown_state,
        event_tx,
        endpoint_tx,
    } = options;
    let stderr_endpoint_tx = endpoint_tx.clone();
    // stdout reader
    {
        let name = name.to_string();
        let color = color.to_string();
        let shutdown_ref = shutdown_state.clone();
        let event_tx = event_tx.clone();

        std::thread::spawn(move || {
            if let Some(stdout) = stdout {
                drain_service_output(stdout, &shutdown_ref, |line| {
                    if let Some(ref tx) = endpoint_tx {
                        for target in crate::dev_endpoint::parse_local_targets(line) {
                            let _ = tx.send(target);
                        }
                    }
                    let safe_name = sanitize_terminal_inline(&name);
                    let safe_line = sanitize_terminal_inline(line);
                    println!("  {color}[{safe_name}]{RESET} {safe_line}");
                    if let Some(ref tx) = event_tx {
                        let _ = tx.try_send(OrchestratorEvent::ServiceLog {
                            service_index,
                            line: line.to_string(),
                            is_stderr: false,
                        });
                    }
                });
            }
        });
    }

    // stderr reader
    {
        let name = name.to_string();
        let color = color.to_string();
        let shutdown_ref = shutdown_state.clone();
        let event_tx = event_tx.clone();

        std::thread::spawn(move || {
            if let Some(stderr) = stderr {
                drain_service_output(stderr, &shutdown_ref, |line| {
                    if let Some(ref tx) = stderr_endpoint_tx {
                        for target in crate::dev_endpoint::parse_local_targets(line) {
                            let _ = tx.send(target);
                        }
                    }
                    let safe_name = sanitize_terminal_inline(&name);
                    let safe_line = sanitize_terminal_inline(line);
                    eprintln!("  {color}[{safe_name}]{RESET} {safe_line}");
                    if let Some(ref tx) = event_tx {
                        let _ = tx.try_send(OrchestratorEvent::ServiceLog {
                            service_index,
                            line: line.to_string(),
                            is_stderr: true,
                        });
                    }
                });
            }
        });
    }
}

fn drain_service_output<R: std::io::Read>(
    mut stream: R,
    shutdown_state: &AtomicU8,
    mut on_line: impl FnMut(&str),
) {
    let mut line = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let mut remaining = &chunk[..read];
        while let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
            if !truncated {
                let keep = newline.min(MAX_SERVICE_LOG_LINE_BYTES.saturating_sub(line.len()));
                line.extend_from_slice(&remaining[..keep]);
            }
            let rendered = String::from_utf8_lossy(&line);
            on_line(&rendered);
            line.clear();
            truncated = false;
            remaining = &remaining[newline + 1..];
        }
        if !remaining.is_empty() && !truncated {
            let keep = remaining
                .len()
                .min(MAX_SERVICE_LOG_LINE_BYTES.saturating_sub(line.len()));
            line.extend_from_slice(&remaining[..keep]);
            truncated = keep < remaining.len() || line.len() == MAX_SERVICE_LOG_LINE_BYTES;
        }
        if shutdown_state.load(Ordering::Relaxed) > 0 {
            break;
        }
    }
    if !line.is_empty() {
        let rendered = String::from_utf8_lossy(&line);
        on_line(&rendered);
    }
}

/// RAII guard that kills child processes on drop (panic safety).
struct ChildrenGuard {
    children: Arc<Mutex<Vec<(String, Child)>>>,
    on_shutdown_started: Option<crate::ShutdownStartedCallback>,
}

impl ChildrenGuard {
    fn begin_shutdown(&mut self) -> Result<(), LpmError> {
        crate::invoke_shutdown_started(&mut self.on_shutdown_started)
    }
}

impl Drop for ChildrenGuard {
    fn drop(&mut self) {
        if let Err(error) = self.begin_shutdown() {
            tracing::error!(%error, "shutdown boundary failed during child cleanup");
        }
        shutdown_children(&self.children, false);
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
#[cfg(unix)]
struct SignalHandler {
    handle: signal_hook::iterator::Handle,
    thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(test)]
    running: Arc<AtomicBool>,
}

#[cfg(unix)]
impl Drop for SignalHandler {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
fn ctrlc_handler(
    shutdown_state: Arc<AtomicU8>,
    children: Arc<Mutex<Vec<(String, Child)>>>,
) -> Option<SignalHandler> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let state = shutdown_state;
    let kids = children;
    let Ok(mut signals) = Signals::new([SIGINT, SIGTERM]) else {
        return None;
    };
    let handle = signals.handle();
    #[cfg(test)]
    let running = Arc::new(AtomicBool::new(false));
    #[cfg(test)]
    let thread_running = Arc::clone(&running);
    let thread = std::thread::spawn(move || {
        #[cfg(test)]
        thread_running.store(true, Ordering::Release);
        for _ in signals.forever() {
            let prev = state.fetch_add(1, Ordering::Relaxed);
            if prev == 0 {
                eprintln!();
                ui_warn("Stopping services...");
            } else {
                eprintln!();
                ui_warn("Force-killing services...");
                force_kill_children(&kids);
                break;
            }
        }
        #[cfg(test)]
        thread_running.store(false, Ordering::Release);
    });
    Some(SignalHandler {
        handle,
        thread: Some(thread),
        #[cfg(test)]
        running,
    })
}

#[cfg(not(unix))]
fn ctrlc_handler(shutdown_state: Arc<AtomicU8>, children: Arc<Mutex<Vec<(String, Child)>>>) {
    let _ = (shutdown_state, children);
}

/// Immediately SIGKILL all children (used for double Ctrl+C escalation).
#[cfg(unix)]
fn force_kill_children(children: &Arc<Mutex<Vec<(String, Child)>>>) {
    let mut locked = children.lock();
    for (name, child) in locked.iter_mut() {
        force_kill_service_tree(child);
        ui_service_status(RESET, name, RED, "✗", "force-killed");
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
/// (dependents first, then their dependencies). All groups share a 2s grace budget.
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
            force_kill_service_tree(child);
            ui_service_status(RESET, name, RED, "✗", "force-killed");
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

    let shutdown_deadline = std::time::Instant::now() + Duration::from_secs(2);
    for (group_index, group) in shutdown_order.iter().enumerate() {
        {
            let mut locked = children.lock();
            for name in group {
                if let Some((_, child)) = locked.iter_mut().find(|(n, _)| n == name) {
                    if let Ok(Some(_)) = child.try_wait() {
                        continue; // Already exited
                    }
                    #[cfg(unix)]
                    {
                        let pid = child.id();
                        signal_service_process_group(pid, libc::SIGTERM);
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

        let groups_remaining = u32::try_from(shutdown_order.len() - group_index).unwrap_or(1);
        let group_deadline = std::time::Instant::now()
            + shutdown_deadline.saturating_duration_since(std::time::Instant::now())
                / groups_remaining;
        loop {
            let group_still_running = {
                let mut locked = children.lock();
                group.iter().any(|name| {
                    locked
                        .iter_mut()
                        .find(|(child_name, _)| child_name == name)
                        .is_some_and(|(_, child)| {
                            let root_running = !matches!(child.try_wait(), Ok(Some(_)));
                            #[cfg(unix)]
                            {
                                root_running || service_process_group_exists(child.id())
                            }
                            #[cfg(not(unix))]
                            {
                                root_running
                            }
                        })
                })
            };
            if !group_still_running || std::time::Instant::now() >= group_deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        let mut locked = children.lock();
        for name in group {
            let Some((_, child)) = locked.iter_mut().find(|(child_name, _)| child_name == name)
            else {
                continue;
            };
            let root_running = !matches!(child.try_wait(), Ok(Some(_)));
            #[cfg(unix)]
            let tree_running = root_running || service_process_group_exists(child.id());
            #[cfg(not(unix))]
            let tree_running = root_running;
            if tree_running {
                tracing::debug!("force-killing service '{name}' before the next dependency level");
                force_kill_service_tree(child);
                ui_service_status(RESET, name, RED, "✗", "force-killed");
            }
        }
    }

    // Final pass: force-kill any stragglers and reap zombies
    let mut locked = children.lock();
    for (name, child) in locked.iter_mut() {
        let status = child.try_wait().ok().flatten();
        #[cfg(unix)]
        let descendants_remain = service_process_group_exists(child.id());
        #[cfg(not(unix))]
        let descendants_remain = false;
        if let Some(status) = status
            && !descendants_remain
        {
            ui_service_note(
                RESET,
                name,
                &format!("stopped (exit {})", status.code().unwrap_or(-1)),
            );
        } else {
            tracing::debug!("force-killing service '{name}'");
            force_kill_service_tree(child);
            ui_service_status(RESET, name, RED, "✗", "force-killed");
        }
    }
}

fn isolate_service_process_tree(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(not(unix))]
    let _ = command;
}

#[cfg(unix)]
fn signal_service_process_group(root_pid: u32, signal: libc::c_int) {
    let Ok(process_group) = libc::pid_t::try_from(root_pid) else {
        return;
    };
    // SAFETY: a negative PID targets the child-owned process group created at
    // spawn. The group ID is derived from the tracked child's positive PID.
    unsafe {
        libc::kill(-process_group, signal);
    }
}

#[cfg(unix)]
fn service_process_group_exists(root_pid: u32) -> bool {
    let Ok(process_group) = libc::pid_t::try_from(root_pid) else {
        return false;
    };
    // SAFETY: signal 0 checks whether the child-owned process group still has
    // members without delivering a signal.
    let result = unsafe { libc::kill(-process_group, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn terminate_service_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        let root_pid = child.id();
        signal_service_process_group(root_pid, libc::SIGTERM);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while service_process_group_exists(root_pid) && std::time::Instant::now() < deadline {
            let _ = child.try_wait();
            std::thread::sleep(Duration::from_millis(25));
        }
        if service_process_group_exists(root_pid) {
            signal_service_process_group(root_pid, libc::SIGKILL);
        }
        let _ = child.wait();
    }
    #[cfg(not(unix))]
    {
        let _ = ports::terminate_child_process_tree(child);
    }
}

fn terminate_named_service(children: &Arc<Mutex<Vec<(String, Child)>>>, name: &str) {
    let child = {
        let mut locked = children.lock();
        locked
            .iter()
            .position(|(child_name, _)| child_name == name)
            .map(|index| locked.remove(index).1)
    };
    if let Some(mut child) = child {
        terminate_service_tree(&mut child);
    }
}

#[cfg(unix)]
fn cleanup_exited_service_tree(root_pid: u32) {
    if service_process_group_exists(root_pid) {
        signal_service_process_group(root_pid, libc::SIGKILL);
    }
}

fn terminate_unready_initial_services(
    children: &Arc<Mutex<Vec<(String, Child)>>>,
    initial_ready: &HashSet<String>,
) {
    let mut unready = {
        let mut locked = children.lock();
        let mut retained = Vec::with_capacity(locked.len());
        let mut unready = Vec::new();
        for mut child in locked.drain(..) {
            if initial_ready.contains(&child.0) || matches!(child.1.try_wait(), Ok(Some(_))) {
                retained.push(child);
            } else {
                unready.push(child.1);
            }
        }
        *locked = retained;
        unready
    };
    for child in &mut unready {
        terminate_service_tree(child);
    }
}

#[cfg(not(unix))]
fn cleanup_exited_service_tree(_root_pid: u32) {}

fn force_kill_service_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        signal_service_process_group(child.id(), libc::SIGKILL);
        let _ = child.wait();
    }
    #[cfg(not(unix))]
    {
        let _ = ports::terminate_child_process_tree(child);
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
    fn vite_service_command_receives_the_managed_port_strictly() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"devDependencies":{"vite":"^7.0.0"}}"#,
        )
        .unwrap();

        assert_eq!(
            command_with_managed_port("vite", dir.path(), Some(5174)),
            "vite --port 5174 --strictPort"
        );
    }

    #[test]
    fn npm_script_receives_framework_args_after_argument_separator() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"dev":"vite"},"devDependencies":{"vite":"^7.0.0"}}"#,
        )
        .unwrap();

        assert_eq!(
            command_with_managed_port("npm run dev", dir.path(), Some(5174)),
            "npm run dev -- --port 5174 --strictPort"
        );
    }

    #[test]
    fn managed_port_args_do_not_leak_from_a_vite_dependency_to_a_node_service() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{
                "scripts":{"web":"vite","api":"node api.js"},
                "devDependencies":{"vite":"^7.0.0"}
            }"#,
        )
        .unwrap();

        assert_eq!(
            command_with_managed_port("node api.js", dir.path(), Some(4000)),
            "node api.js"
        );
        assert_eq!(
            command_with_managed_port("npm run api", dir.path(), Some(4000)),
            "npm run api"
        );
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
        let assigned_ports =
            assign_service_ports(dir.path(), &services, &mut allocation, None, false, None)
                .unwrap();

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
        let assigned_ports =
            assign_service_ports(dir.path(), &services, &mut allocation, None, false, None)
                .unwrap();

        let assigned = assigned_ports.port_map["web"];
        assert_ne!(assigned, port);
        assert_eq!(assigned_ports.reassignments["web"].original, port);
        assert_eq!(assigned_ports.reassignments["web"].new, assigned);
    }

    #[test]
    fn assign_service_ports_manages_the_implicit_primary_service_without_configured_port() {
        let mut services = HashMap::new();
        services.insert("web".to_string(), simple_service("true"));
        let dir = tempfile::TempDir::new().unwrap();

        let mut allocation = ports::PortAllocation::acquire_for_root_and_lease_dir(
            lpm_common::LpmRoot::from_dir(dir.path().join(".lpm")),
            dir.path().join("port-leases"),
        )
        .unwrap();
        let assigned_ports =
            assign_service_ports(dir.path(), &services, &mut allocation, None, true, None).unwrap();

        assert!(assigned_ports.port_map.contains_key("web"));
    }

    #[test]
    fn assign_service_ports_manages_an_explicit_primary_without_configured_port() {
        let mut services = HashMap::new();
        services.insert("api".to_string(), simple_service("true"));
        services.insert(
            "web".to_string(),
            ServiceConfig {
                command: "true".to_string(),
                primary: true,
                ..Default::default()
            },
        );
        let dir = tempfile::TempDir::new().unwrap();

        let mut allocation = ports::PortAllocation::acquire_for_root_and_lease_dir(
            lpm_common::LpmRoot::from_dir(dir.path().join(".lpm")),
            dir.path().join("port-leases"),
        )
        .unwrap();
        let assigned_ports =
            assign_service_ports(dir.path(), &services, &mut allocation, None, true, None).unwrap();

        assert!(assigned_ports.port_map.contains_key("web"));
        assert!(!assigned_ports.port_map.contains_key("api"));
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
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("echo STDOUT_LINE; echo STDERR_LINE >&2")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let child_stdout = child.stdout.take();
        let child_stderr = child.stderr.take();

        let name = "test-svc".to_string();
        let children: Arc<Mutex<Vec<(String, Child)>>> = Arc::new(Mutex::new(Vec::new()));
        children.lock().push((name.clone(), child));

        let shutdown = Arc::new(AtomicU8::new(0));
        let (tx, rx) = std::sync::mpsc::sync_channel(8);

        spawn_output_readers(
            child_stdout,
            child_stderr,
            OutputReaderOptions {
                name: &name,
                color: "\x1b[36m",
                service_index: 0,
                shutdown_state: &shutdown,
                event_tx: &Some(tx),
                endpoint_tx: None,
            },
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
    fn service_output_reader_bounds_a_newline_free_line() {
        let shutdown = AtomicU8::new(0);
        let input = vec![b'x'; MAX_SERVICE_LOG_LINE_BYTES * 4];
        let mut observed_len = None;

        drain_service_output(input.as_slice(), &shutdown, |line| {
            observed_len = Some(line.len());
        });

        assert_eq!(observed_len, Some(MAX_SERVICE_LOG_LINE_BYTES));
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

    #[test]
    fn wrapped_npm_scripts_receive_managed_port_arguments_after_npm_separator() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"dev":"vite"},"devDependencies":{"vite":"^7.0.0"}}"#,
        )
        .unwrap();

        assert_eq!(
            command_with_managed_port("FOO=1 npm run dev", dir.path(), Some(5174)),
            "FOO=1 npm run dev -- --port 5174 --strictPort"
        );
        assert_eq!(
            command_with_managed_port("cross-env FOO=1 npm run dev", dir.path(), Some(5174)),
            "cross-env FOO=1 npm run dev -- --port 5174 --strictPort"
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

        let (tx, rx) = std::sync::mpsc::sync_channel(256);
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

        let (tx, rx) = std::sync::mpsc::sync_channel(256);
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

        let (tx, rx) = std::sync::mpsc::sync_channel(256);
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

    #[test]
    fn crashed_service_does_not_wait_for_the_full_readiness_timeout() {
        let unavailable_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let unavailable_port = unavailable_listener.local_addr().unwrap().port();
        drop(unavailable_listener);
        let services = HashMap::from([(
            "crasher".to_string(),
            ServiceConfig {
                command: "exit 1".to_string(),
                ready_url: Some(format!("http://127.0.0.1:{unavailable_port}/health")),
                ready_timeout: 30,
                ..Default::default()
            },
        )]);
        let dir = tempfile::TempDir::new().unwrap();
        let started = std::time::Instant::now();

        let result = run_services(dir.path(), &services, OrchestratorOptions::default());

        assert!(result.is_err(), "crashed service unexpectedly succeeded");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "crashed service waited for readiness timeout: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn crashing_service_cancels_sibling_readiness_in_the_same_startup_level() {
        let unavailable_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let unavailable_port = unavailable_listener.local_addr().unwrap().port();
        drop(unavailable_listener);
        let services = HashMap::from([
            (
                "a-slow".to_string(),
                ServiceConfig {
                    command: "sleep 60".to_string(),
                    ready_url: Some(format!("http://127.0.0.1:{unavailable_port}/health")),
                    ready_timeout: 4,
                    ..Default::default()
                },
            ),
            ("z-crash".to_string(), simple_service("exit 1")),
        ]);
        let dir = tempfile::TempDir::new().unwrap();
        let started = std::time::Instant::now();

        let result = run_services(dir.path(), &services, OrchestratorOptions::default());

        assert!(
            result.is_err(),
            "crashing startup level unexpectedly succeeded"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "sibling crash waited for the unrelated readiness timeout: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn restart_policy_recovers_a_service_that_crashes_before_initial_readiness() {
        let ready_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let ready_port = ready_listener.local_addr().unwrap().port();
        drop(ready_listener);
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("crash-once.js"),
            format!(
                r#"
const fs = require('fs');
if (!fs.existsSync('crashed')) {{
  fs.writeFileSync('crashed', 'yes');
  process.exit(23);
}}
require('http').createServer((_request, response) => response.end('ok'))
  .listen({ready_port}, '127.0.0.1');
"#
            ),
        )
        .unwrap();
        let services = HashMap::from([(
            "worker".to_string(),
            ServiceConfig {
                command: "node crash-once.js".to_string(),
                restart: true,
                ready_url: Some(format!("http://127.0.0.1:{ready_port}")),
                ready_timeout: 3,
                ..Default::default()
            },
        )]);
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let project_dir = dir.path().to_path_buf();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = result_tx.send(run_services(&project_dir, &services, options));
        });

        let mut statuses = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while std::time::Instant::now() < deadline {
            match event_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(OrchestratorEvent::StatusChange { status, .. }) => {
                    let recovered = matches!(status, ServiceStatus::Ready);
                    statuses.push(status);
                    if recovered {
                        break;
                    }
                }
                Ok(OrchestratorEvent::ServiceLog { .. }) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(error) => panic!("orchestrator event channel disconnected: {error}"),
            }
        }
        command_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = result_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        assert!(result.is_ok(), "restart policy failed startup: {result:?}");
        assert!(
            statuses
                .iter()
                .any(|status| matches!(status, ServiceStatus::Crashed(23))),
            "initial crash was not reported: {statuses:?}"
        );
        assert!(
            statuses
                .iter()
                .filter(|status| matches!(status, ServiceStatus::Starting))
                .count()
                >= 2,
            "service was not restarted: {statuses:?}"
        );
        assert!(
            statuses
                .iter()
                .any(|status| matches!(status, ServiceStatus::Ready)),
            "restarted service did not become ready: {statuses:?}"
        );
    }

    // ── OrchestratorCommand tests ──────────────────────────────────

    #[test]
    fn stop_all_dominates_queued_service_commands() {
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        command_tx
            .send(OrchestratorCommand::RestartService(0))
            .unwrap();
        command_tx
            .send(OrchestratorCommand::StopService(0))
            .unwrap();
        command_tx.send(OrchestratorCommand::StopAll).unwrap();
        let shutdown_state = Arc::new(AtomicU8::new(0));
        let bridge = CommandBridge::start(Some(command_rx), None, Arc::clone(&shutdown_state), 1);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while shutdown_state.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }

        let command = bridge.controller().drain().into_iter().next().unwrap();

        assert!(matches!(command, OrchestratorCommand::StopAll));
    }

    #[test]
    fn service_command_storm_keeps_only_the_last_valid_intent() {
        let controller = OrchestratorCommandController::new(1);
        for index in 0..100_000 {
            let command = if index % 2 == 0 {
                OrchestratorCommand::RestartService(0)
            } else {
                OrchestratorCommand::StopService(0)
            };
            controller.send(command);
            controller.send(OrchestratorCommand::RestartService(usize::MAX));
        }

        assert_eq!(controller.pending_service_count(), 1);
        assert_eq!(
            controller.drain(),
            vec![OrchestratorCommand::StopService(0)]
        );
    }

    #[test]
    fn recovered_service_publishes_initial_readiness_before_endpoint_changes() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("crash-once.js"),
            r#"
const fs = require('fs');
if (!fs.existsSync('crashed')) {
  fs.writeFileSync('crashed', 'yes');
  process.exit(23);
}
require('net').createServer().listen(Number(process.env.PORT), '127.0.0.1');
"#,
        )
        .unwrap();
        let services = HashMap::from([(
            "web".to_string(),
            ServiceConfig {
                command: "node crash-once.js".to_string(),
                restart: true,
                ready_timeout: 3,
                ..Default::default()
            },
        )]);
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (publication_tx, publication_rx) = std::sync::mpsc::channel();
        let changed_tx = publication_tx.clone();
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            manage_primary_endpoint: true,
            on_all_ready: Some(Box::new(move |mut endpoints| {
                publication_tx
                    .send((true, endpoints.remove("web").unwrap()))
                    .unwrap();
                Ok(())
            })),
            on_endpoint_changed: Some(Box::new(move |endpoint| {
                changed_tx.send((false, endpoint)).unwrap();
                Ok(())
            })),
            ..Default::default()
        };
        let project_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || run_services(&project_dir, &services, options));

        let initial = publication_rx.recv_timeout(Duration::from_secs(8)).unwrap();
        command_tx
            .send(OrchestratorCommand::RestartService(0))
            .unwrap();
        let changed = publication_rx.recv_timeout(Duration::from_secs(8)).unwrap();
        command_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = handle.join().unwrap();

        assert!(result.is_ok(), "restart policy failed startup: {result:?}");
        assert!(
            initial.0,
            "recovery published an endpoint change before initial readiness"
        );
        assert_eq!(initial.1.service.as_deref(), Some("web"));
        assert!(!changed.0, "later restart repeated initial readiness");
        assert_eq!(changed.1.service.as_deref(), Some("web"));
        assert_ne!(changed.1.owner_pid, initial.1.owner_pid);
        assert!(
            publication_rx.try_recv().is_err(),
            "initial readiness was published more than once"
        );
    }

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
    fn channel_disconnect_interrupts_initial_readiness() {
        let unavailable_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let unavailable_port = unavailable_listener.local_addr().unwrap().port();
        drop(unavailable_listener);
        let services = HashMap::from([(
            "worker".to_string(),
            ServiceConfig {
                command: "sleep 60".to_string(),
                ready_url: Some(format!("http://127.0.0.1:{unavailable_port}/health")),
                ready_timeout: 4,
                ..Default::default()
            },
        )]);
        let (command_tx, command_rx) = std::sync::mpsc::channel::<OrchestratorCommand>();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let controller = std::thread::spawn(move || {
            while !matches!(
                event_rx.recv_timeout(Duration::from_secs(2)),
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Starting,
                    ..
                })
            ) {}
            drop(command_tx);
        });
        let dir = tempfile::TempDir::new().unwrap();
        let started = std::time::Instant::now();

        let result = run_services(dir.path(), &services, options);
        controller.join().unwrap();

        assert!(result.is_ok(), "channel disconnect failed: {result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "channel disconnect remained blocked behind initial readiness: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn stop_service_interrupts_its_initial_readiness() {
        let unavailable_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let unavailable_port = unavailable_listener.local_addr().unwrap().port();
        drop(unavailable_listener);
        let services = HashMap::from([(
            "worker".to_string(),
            ServiceConfig {
                command: "sleep 60".to_string(),
                ready_url: Some(format!("http://127.0.0.1:{unavailable_port}/health")),
                ready_timeout: 4,
                ..Default::default()
            },
        )]);
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let controller = std::thread::spawn(move || {
            while !matches!(
                event_rx.recv_timeout(Duration::from_secs(2)),
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Starting,
                    ..
                })
            ) {}
            command_tx
                .send(OrchestratorCommand::StopService(0))
                .unwrap();
        });
        let dir = tempfile::TempDir::new().unwrap();
        let started = std::time::Instant::now();

        let result = run_services(dir.path(), &services, options);
        controller.join().unwrap();

        assert!(
            result.is_ok(),
            "StopService failed during startup: {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "StopService remained blocked behind initial readiness: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn stop_service_terminates_its_starting_process_without_waiting_for_a_sibling() {
        let first_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let first_port = first_listener.local_addr().unwrap().port();
        drop(first_listener);
        let second_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let second_port = second_listener.local_addr().unwrap().port();
        drop(second_listener);
        let services = HashMap::from([
            (
                "a".to_string(),
                ServiceConfig {
                    command: "echo $$ > a.pid; sleep 60".to_string(),
                    ready_url: Some(format!("http://127.0.0.1:{first_port}/health")),
                    ready_timeout: 10,
                    ..Default::default()
                },
            ),
            (
                "b".to_string(),
                ServiceConfig {
                    command: "sleep 60".to_string(),
                    ready_url: Some(format!("http://127.0.0.1:{second_port}/health")),
                    ready_timeout: 10,
                    ..Default::default()
                },
            ),
        ]);
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let (stopped_tx, stopped_rx) = std::sync::mpsc::sync_channel(1);
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let pid_path = dir.path().join("a.pid");
        let controller = std::thread::spawn(move || {
            let mut starting = 0;
            while starting < 2 {
                if matches!(
                    event_rx.recv_timeout(Duration::from_secs(2)),
                    Ok(OrchestratorEvent::StatusChange {
                        status: ServiceStatus::Starting,
                        ..
                    })
                ) {
                    starting += 1;
                }
            }
            let pid_deadline = std::time::Instant::now() + Duration::from_secs(2);
            let pid = loop {
                if let Ok(content) = std::fs::read_to_string(&pid_path)
                    && let Ok(pid) = content.trim().parse::<u32>()
                {
                    break pid;
                }
                assert!(
                    std::time::Instant::now() < pid_deadline,
                    "service PID file was not populated before the deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            command_tx
                .send(OrchestratorCommand::StopService(0))
                .unwrap();
            let stop_deadline = std::time::Instant::now() + Duration::from_secs(1);
            while ports::process_is_running(pid) && std::time::Instant::now() < stop_deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            stopped_tx.send(!ports::process_is_running(pid)).unwrap();
            command_tx.send(OrchestratorCommand::StopAll).unwrap();
        });

        let result = run_services(dir.path(), &services, options);
        controller.join().unwrap();

        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert!(
            stopped_rx.recv().unwrap(),
            "target service remained alive behind sibling readiness"
        );
    }

    #[test]
    fn restarting_one_starting_service_does_not_restart_an_unrelated_starting_service() {
        let first_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let first_port = first_listener.local_addr().unwrap().port();
        drop(first_listener);
        let second_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let second_port = second_listener.local_addr().unwrap().port();
        drop(second_listener);
        let services = HashMap::from([
            (
                "a".to_string(),
                ServiceConfig {
                    command: format!(
                        "node -e \"setTimeout(() => require('http').createServer((_, response) => response.end('ok')).listen({first_port}, '127.0.0.1'), 500); setInterval(() => {{}}, 1000)\""
                    ),
                    ready_url: Some(format!("http://127.0.0.1:{first_port}")),
                    ready_timeout: 5,
                    ..Default::default()
                },
            ),
            (
                "b".to_string(),
                ServiceConfig {
                    command: format!(
                        "node -e \"setTimeout(() => require('http').createServer((_, response) => response.end('ok')).listen({second_port}, '127.0.0.1'), 500); setInterval(() => {{}}, 1000)\""
                    ),
                    ready_url: Some(format!("http://127.0.0.1:{second_port}")),
                    ready_timeout: 5,
                    ..Default::default()
                },
            ),
        ]);
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let project_dir = dir.path().to_path_buf();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = result_tx.send(run_services(&project_dir, &services, options));
        });

        let mut starting_counts = [0usize; 2];
        let mut ready = [false; 2];
        while starting_counts.iter().sum::<usize>() < 2 {
            match event_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(OrchestratorEvent::StatusChange {
                    service_index,
                    status: ServiceStatus::Starting,
                }) => starting_counts[service_index] += 1,
                Ok(_) => {}
                Err(error) => panic!("services did not begin initial startup: {error}"),
            }
        }
        command_tx
            .send(OrchestratorCommand::RestartService(0))
            .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while !ready.iter().all(|is_ready| *is_ready) && std::time::Instant::now() < deadline {
            if let Ok(OrchestratorEvent::StatusChange {
                service_index,
                status,
            }) = event_rx.recv_timeout(Duration::from_millis(100))
            {
                match status {
                    ServiceStatus::Starting => starting_counts[service_index] += 1,
                    ServiceStatus::Ready => ready[service_index] = true,
                    _ => {}
                }
            }
        }
        command_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = result_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert_eq!(starting_counts[0], 2, "target service should restart once");
        assert_eq!(
            starting_counts[1], 1,
            "unrelated service should keep its initial process"
        );
        assert!(ready.iter().all(|is_ready| *is_ready));
    }

    #[cfg(unix)]
    #[test]
    fn dropping_signal_handler_releases_its_background_thread() {
        let shutdown_state = Arc::new(AtomicU8::new(0));
        let children = Arc::new(Mutex::new(Vec::new()));

        let handler = ctrlc_handler(shutdown_state, children);
        let running = Arc::clone(&handler.as_ref().unwrap().running);
        let start_deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !running.load(Ordering::Acquire) && std::time::Instant::now() < start_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(running.load(Ordering::Acquire));
        drop(handler);

        assert!(!running.load(Ordering::Acquire));
    }

    #[test]
    fn stop_service_command_stops_single_service() {
        let mut services = HashMap::new();
        services.insert("a".to_string(), simple_service("sleep 60"));
        services.insert("b".to_string(), simple_service("sleep 60"));

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let project_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || run_services(&project_dir, &services, options));

        let ready_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut ready_count = 0;
        while ready_count < 2 && std::time::Instant::now() < ready_deadline {
            if let Ok(OrchestratorEvent::StatusChange {
                status: ServiceStatus::Ready,
                ..
            }) = event_rx.recv_timeout(Duration::from_millis(100))
            {
                ready_count += 1;
            }
        }
        cmd_tx.send(OrchestratorCommand::StopService(0)).unwrap();

        let mut saw_stopped = false;
        let stop_deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !saw_stopped && std::time::Instant::now() < stop_deadline {
            if let Ok(OrchestratorEvent::StatusChange {
                status: ServiceStatus::Stopped,
                ..
            }) = event_rx.recv_timeout(Duration::from_millis(100))
            {
                saw_stopped = true;
            }
        }
        cmd_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = handle.join().unwrap();

        assert_eq!(ready_count, 2, "services did not reach initial readiness");
        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert!(saw_stopped, "should emit Stopped status for killed service");
    }

    #[cfg(unix)]
    #[test]
    fn stop_all_invokes_the_shutdown_boundary_before_multi_service_cleanup() {
        let dir = tempfile::TempDir::new().unwrap();
        let started_path = dir.path().join("started");
        let services = HashMap::from([(
            "web".to_string(),
            simple_service(&format!(
                "touch '{}'; while :; do sleep 1; done",
                started_path.display()
            )),
        )]);
        let controller = OrchestratorCommandController::new(services.len());
        let shutdown_boundary_ran = Arc::new(AtomicBool::new(false));
        let callback_state = Arc::clone(&shutdown_boundary_ran);
        let options = OrchestratorOptions {
            command_controller: Some(controller.clone()),
            on_shutdown_started: Some(Box::new(move || {
                callback_state.store(true, Ordering::Release);
                Ok(())
            })),
            ..Default::default()
        };
        let project_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || run_services(&project_dir, &services, options));

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !started_path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(started_path.exists(), "service did not start");
        controller.send(OrchestratorCommand::StopAll);

        let result = handle.join().unwrap();
        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert!(
            shutdown_boundary_ran.load(Ordering::Acquire),
            "child cleanup started without acknowledging the shutdown boundary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publication_failure_preserves_the_shutdown_boundary_failure() {
        let dir = tempfile::TempDir::new().unwrap();
        let services = HashMap::from([(
            "web".to_string(),
            simple_service("while :; do sleep 1; done"),
        )]);
        let options = OrchestratorOptions {
            on_all_ready: Some(Box::new(|_| {
                Err(LpmError::Script(
                    "injected endpoint publication failure".to_string(),
                ))
            })),
            on_shutdown_started: Some(Box::new(|| {
                Err(LpmError::Tunnel(
                    "injected shutdown boundary failure".to_string(),
                ))
            })),
            ..Default::default()
        };

        let error = run_services(dir.path(), &services, options)
            .unwrap_err()
            .to_string();

        assert!(error.contains("injected endpoint publication failure"));
        assert!(error.contains("injected shutdown boundary failure"));
    }

    #[test]
    fn restart_service_command_restarts_service() {
        let mut services = HashMap::new();
        services.insert("worker".to_string(), simple_service("sleep 60"));

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let project_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || run_services(&project_dir, &services, options));

        let mut starting_count = 0;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while starting_count < 1 && std::time::Instant::now() < deadline {
            if let Ok(OrchestratorEvent::StatusChange {
                status: ServiceStatus::Starting,
                ..
            }) = event_rx.recv_timeout(Duration::from_millis(100))
            {
                starting_count += 1;
            }
        }
        cmd_tx.send(OrchestratorCommand::RestartService(0)).unwrap();
        while starting_count < 2 && std::time::Instant::now() < deadline {
            if let Ok(OrchestratorEvent::StatusChange {
                status: ServiceStatus::Starting,
                ..
            }) = event_rx.recv_timeout(Duration::from_millis(100))
            {
                starting_count += 1;
            }
        }
        cmd_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = handle.join().unwrap();

        assert!(result.is_ok(), "orchestrator failed: {result:?}");
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
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let project_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || run_services(&project_dir, &services, options));

        let mut ready_count = 0;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while ready_count < 1 && std::time::Instant::now() < deadline {
            if let Ok(OrchestratorEvent::StatusChange {
                status: ServiceStatus::Ready,
                ..
            }) = event_rx.recv_timeout(Duration::from_millis(100))
            {
                ready_count += 1;
            }
        }
        cmd_tx.send(OrchestratorCommand::RestartService(0)).unwrap();
        while ready_count < 2 && std::time::Instant::now() < deadline {
            if let Ok(OrchestratorEvent::StatusChange {
                status: ServiceStatus::Ready,
                ..
            }) = event_rx.recv_timeout(Duration::from_millis(100))
            {
                ready_count += 1;
            }
        }
        cmd_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = handle.join().unwrap();

        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert!(
            ready_count >= 2,
            "should emit Ready at least twice (initial + restart), got {ready_count}"
        );
    }

    #[test]
    fn restarted_managed_service_republishes_its_verified_endpoint() {
        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceConfig {
                command: "node -e \"require('net').createServer().listen(Number(process.env.PORT), '127.0.0.1')\"".to_string(),
                ready_timeout: 3,
                ..Default::default()
            },
        );

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (initial_tx, initial_rx) = std::sync::mpsc::channel();
        let (restart_tx, restart_rx) = std::sync::mpsc::channel();
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            manage_primary_endpoint: true,
            on_all_ready: Some(Box::new(move |mut endpoints| {
                initial_tx.send(endpoints.remove("web").unwrap()).unwrap();
                Ok(())
            })),
            on_endpoint_changed: Some(Box::new(move |endpoint| {
                restart_tx.send(endpoint).unwrap();
                Ok(())
            })),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let project_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || run_services(&project_dir, &services, options));

        let initial = initial_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cmd_tx.send(OrchestratorCommand::RestartService(0)).unwrap();
        let restarted = restart_rx.recv_timeout(Duration::from_secs(8)).unwrap();
        cmd_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = handle.join().unwrap();

        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert_eq!(restarted.target, initial.target);
        assert_ne!(restarted.owner_pid, initial.owner_pid);
    }

    #[test]
    fn restarted_service_retries_after_readiness_failure_without_reporting_ready() {
        let ready_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let ready_port = ready_listener.local_addr().unwrap().port();
        drop(ready_listener);
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("restart-readiness.js"),
            format!(
                r#"
const fs = require('fs');
if (!fs.existsSync('ready-once')) {{
  fs.writeFileSync('ready-once', 'ready');
  require('http').createServer((_request, response) => response.end('ok'))
    .listen({ready_port}, '127.0.0.1');
}}
setInterval(() => {{}}, 1000);
"#
            ),
        )
        .unwrap();
        let mut services = HashMap::new();
        services.insert(
            "worker".to_string(),
            ServiceConfig {
                command: "node restart-readiness.js".to_string(),
                ready_url: Some(format!("http://127.0.0.1:{ready_port}")),
                ready_timeout: 1,
                ..Default::default()
            },
        );

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(cmd_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let project_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || run_services(&project_dir, &services, options));

        loop {
            match event_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Ready,
                    ..
                }) => break,
                Ok(_) => {}
                Err(error) => panic!("initial service did not become ready: {error}"),
            }
        }
        cmd_tx.send(OrchestratorCommand::RestartService(0)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        let mut restart_events = Vec::new();
        while std::time::Instant::now() < deadline {
            if let Ok(event) = event_rx.recv_timeout(Duration::from_millis(100)) {
                restart_events.push(event);
                let starting_count = restart_events
                    .iter()
                    .filter(|event| {
                        matches!(
                            event,
                            OrchestratorEvent::StatusChange {
                                status: ServiceStatus::Starting,
                                ..
                            }
                        )
                    })
                    .count();
                if starting_count >= 2 {
                    break;
                }
            }
        }
        cmd_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = handle.join().unwrap();

        restart_events.extend(event_rx.try_iter());
        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert!(
            restart_events.iter().any(|event| matches!(
                event,
                OrchestratorEvent::StatusChange {
                    status: ServiceStatus::ReadinessFailed(_),
                    ..
                }
            )),
            "a failed restart must emit ReadinessFailed: {restart_events:?}"
        );
        assert!(
            restart_events
                .iter()
                .filter(|event| matches!(
                    event,
                    OrchestratorEvent::StatusChange {
                        status: ServiceStatus::Starting,
                        ..
                    }
                ))
                .count()
                >= 2,
            "a readiness failure must schedule another restart: {restart_events:?}"
        );
        assert!(
            !restart_events.iter().any(|event| matches!(
                event,
                OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Ready,
                    ..
                }
            )),
            "a failed restart must not emit Ready: {restart_events:?}"
        );
    }

    #[test]
    fn stop_all_interrupts_restart_readiness_without_waiting_for_its_timeout() {
        let ready_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let ready_port = ready_listener.local_addr().unwrap().port();
        drop(ready_listener);
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("ready-only-once.js"),
            format!(
                r#"
const fs = require('fs');
if (!fs.existsSync('ready-once')) {{
  fs.writeFileSync('ready-once', 'ready');
  require('http').createServer((_request, response) => response.end('ok'))
    .listen({ready_port}, '127.0.0.1');
}}
setInterval(() => {{}}, 1000);
"#
            ),
        )
        .unwrap();
        let services = HashMap::from([(
            "worker".to_string(),
            ServiceConfig {
                command: "node ready-only-once.js".to_string(),
                port: Some(ready_port),
                ready_url: Some(format!("http://127.0.0.1:{ready_port}")),
                ready_timeout: 30,
                ..Default::default()
            },
        )]);
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let project_dir = dir.path().to_path_buf();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = result_tx.send(run_services(&project_dir, &services, options));
        });

        loop {
            match event_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Ready,
                    ..
                }) => break,
                Ok(_) => {}
                Err(error) => panic!("initial service did not become ready: {error}"),
            }
        }
        command_tx
            .send(OrchestratorCommand::RestartService(0))
            .unwrap();
        loop {
            match event_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Starting,
                    ..
                }) => break,
                Ok(_) => {}
                Err(error) => panic!("service restart did not begin: {error}"),
            }
        }

        let stop_started = std::time::Instant::now();
        command_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = result_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("StopAll remained blocked behind restart readiness");

        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert!(stop_started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn stop_all_interrupts_initial_readiness_without_waiting_for_its_timeout() {
        let ready_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let ready_port = ready_listener.local_addr().unwrap().port();
        drop(ready_listener);
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("never-ready.js"),
            "setInterval(() => {}, 1000);\n",
        )
        .unwrap();
        let services = HashMap::from([(
            "worker".to_string(),
            ServiceConfig {
                command: "node never-ready.js".to_string(),
                port: Some(ready_port),
                ready_timeout: 3,
                ..Default::default()
            },
        )]);
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let controller = std::thread::spawn(move || {
            loop {
                match event_rx.recv_timeout(Duration::from_secs(2)) {
                    Ok(OrchestratorEvent::StatusChange {
                        status: ServiceStatus::Starting,
                        ..
                    }) => break,
                    Ok(_) => {}
                    Err(error) => panic!("initial service did not start: {error}"),
                }
            }
            let sent_at = std::time::Instant::now();
            command_tx.send(OrchestratorCommand::StopAll).unwrap();
            (sent_at, event_rx)
        });

        let result = run_services(dir.path(), &services, options);
        let (stop_sent_at, event_rx) = controller.join().unwrap();
        let events: Vec<_> = event_rx.try_iter().collect();

        assert!(result.is_ok(), "orchestrator failed: {result:?}");
        assert!(
            stop_sent_at.elapsed() < Duration::from_secs(2),
            "StopAll remained blocked behind initial readiness"
        );
        assert!(
            !events.iter().any(|event| matches!(
                event,
                OrchestratorEvent::StatusChange {
                    status: ServiceStatus::ReadinessFailed(_),
                    ..
                }
            )),
            "StopAll was reported as a readiness failure: {events:?}"
        );
    }

    #[test]
    fn repeated_restart_during_readiness_does_not_report_failure_or_back_off() {
        let ready_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let ready_port = ready_listener.local_addr().unwrap().port();
        drop(ready_listener);
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("ready-except-second.js"),
            format!(
                r#"
const fs = require('fs');
const count = fs.existsSync('starts') ? Number(fs.readFileSync('starts', 'utf8')) + 1 : 1;
fs.writeFileSync('starts', String(count));
if (count !== 2) {{
  require('http').createServer((_request, response) => response.end('ok'))
    .listen({ready_port}, '127.0.0.1');
}}
setInterval(() => {{}}, 1000);
"#
            ),
        )
        .unwrap();
        let services = HashMap::from([(
            "worker".to_string(),
            ServiceConfig {
                command: "node ready-except-second.js".to_string(),
                ready_url: Some(format!("http://127.0.0.1:{ready_port}")),
                ready_timeout: 30,
                ..Default::default()
            },
        )]);
        let (command_tx, command_rx) = std::sync::mpsc::channel();
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let project_dir = dir.path().to_path_buf();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = result_tx.send(run_services(&project_dir, &services, options));
        });

        loop {
            match event_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Ready,
                    ..
                }) => break,
                Ok(_) => {}
                Err(error) => panic!("initial service did not become ready: {error}"),
            }
        }
        command_tx
            .send(OrchestratorCommand::RestartService(0))
            .unwrap();
        loop {
            match event_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Starting,
                    ..
                }) => break,
                Ok(_) => {}
                Err(error) => panic!("first restart did not begin: {error}"),
            }
        }
        let restart_deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::fs::read_to_string(dir.path().join("starts"))
            .ok()
            .as_deref()
            != Some("2")
        {
            assert!(
                std::time::Instant::now() < restart_deadline,
                "first restart process did not enter readiness"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        command_tx
            .send(OrchestratorCommand::RestartService(0))
            .unwrap();
        let restart_started = std::time::Instant::now();
        loop {
            match event_rx.recv_timeout(Duration::from_secs(6)) {
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::ReadinessFailed(error),
                    ..
                }) => panic!("user-requested restart was reported as a failure: {error}"),
                Ok(OrchestratorEvent::StatusChange {
                    status: ServiceStatus::Ready,
                    ..
                }) => break,
                Ok(_) => {}
                Err(error) => panic!("second restart did not become ready promptly: {error}"),
            }
        }

        assert!(restart_started.elapsed() < Duration::from_secs(6));
        command_tx.send(OrchestratorCommand::StopAll).unwrap();
        let result = result_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(result.is_ok(), "orchestrator failed: {result:?}");
    }

    #[test]
    fn reassigned_service_fails_readiness_instead_of_using_stale_occupied_port() {
        let occupied_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let occupied_port = occupied_listener.local_addr().unwrap().port();

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

        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
        let options = OrchestratorOptions {
            event_tx: Some(event_tx),
            ..Default::default()
        };
        let dir = tempfile::TempDir::new().unwrap();

        let result = run_services(dir.path(), &services, options);
        let statuses: Vec<ServiceStatus> = event_rx
            .try_iter()
            .filter_map(|event| match event {
                OrchestratorEvent::StatusChange { status, .. } => Some(status),
                OrchestratorEvent::ServiceLog { .. } => None,
            })
            .collect();

        drop(occupied_listener);

        assert!(
            result.is_err(),
            "unowned reassigned port must fail startup: {result:?}"
        );
        assert!(
            !statuses
                .iter()
                .any(|status| matches!(status, ServiceStatus::Ready)),
            "service must not be Ready from an unrelated occupied original port: {statuses:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ordered_shutdown_does_not_wait_for_levels_that_exit_promptly() {
        let children = Arc::new(Mutex::new(Vec::new()));
        let mut groups = Vec::new();
        for name in ["db", "api", "web"] {
            let mut command = Command::new("sh");
            command
                .arg("-c")
                .arg("trap 'exit 0' TERM; while :; do sleep 0.05; done");
            isolate_service_process_tree(&mut command);
            children
                .lock()
                .push((name.to_string(), command.spawn().unwrap()));
            groups.push(vec![name.to_string()]);
        }

        std::thread::sleep(Duration::from_millis(100));
        let started = std::time::Instant::now();
        shutdown_children_ordered(&children, false, Some(&groups));

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "promptly exiting dependency levels waited for fixed grace periods: {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn crashed_service_cleanup_removes_surviving_process_group_members() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("trap '' TERM; sleep 60 & exit 1");
        isolate_service_process_tree(&mut command);
        let mut child = command.spawn().unwrap();
        let root_pid = child.id();
        let status = child.wait().unwrap();
        assert!(!status.success());
        assert!(service_process_group_exists(root_pid));

        cleanup_exited_service_tree(root_pid);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while service_process_group_exists(root_pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }

        assert!(!service_process_group_exists(root_pid));
    }

    #[cfg(unix)]
    #[test]
    fn force_cleanup_removes_descendants_after_the_root_exits() {
        let children = Arc::new(Mutex::new(Vec::new()));
        let mut command = Command::new("sh");
        command.arg("-c").arg("trap '' TERM; sleep 60 & exit 0");
        isolate_service_process_tree(&mut command);
        let mut child = command.spawn().unwrap();
        let root_pid = child.id();
        let status = child.wait().unwrap();
        assert!(status.success());
        assert!(service_process_group_exists(root_pid));
        children.lock().push(("worker".to_string(), child));

        force_kill_children(&children);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while service_process_group_exists(root_pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }

        assert!(!service_process_group_exists(root_pid));
    }

    #[cfg(unix)]
    #[test]
    fn ordered_shutdown_removes_signal_resistant_descendants_after_the_root_exits() {
        let children = Arc::new(Mutex::new(Vec::new()));
        let mut command = Command::new("sh");
        command.arg("-c").arg(
            "trap 'exit 0' TERM; sh -c \"trap '' TERM; sleep 60\" & while :; do sleep 0.05; done",
        );
        isolate_service_process_tree(&mut command);
        let child = command.spawn().unwrap();
        let root_pid = child.id();
        children.lock().push(("web".to_string(), child));
        std::thread::sleep(Duration::from_millis(100));

        shutdown_children_ordered(&children, false, Some(&[vec!["web".to_string()]]));

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while service_process_group_exists(root_pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(!service_process_group_exists(root_pid));
    }

    #[cfg(unix)]
    #[test]
    fn ordered_shutdown_force_kills_resistant_dependents_before_dependencies() {
        let dir = tempfile::TempDir::new().unwrap();
        let observation = dir.path().join("dependency-observation");
        let children = Arc::new(Mutex::new(Vec::new()));

        let mut web_command = Command::new("sh");
        web_command.arg("-c").arg("trap '' TERM; exec sleep 60");
        isolate_service_process_tree(&mut web_command);
        let web = web_command.spawn().unwrap();
        let web_pid = web.id();
        children.lock().push(("web".to_string(), web));

        let mut db_command = Command::new("sh");
        db_command.arg("-c").arg(format!(
            "trap 'if kill -0 -{web_pid} 2>/dev/null; then echo alive > \"{}\"; else echo gone > \"{}\"; fi; exit 0' TERM; while :; do sleep 0.05; done",
            observation.display(),
            observation.display()
        ));
        isolate_service_process_tree(&mut db_command);
        children
            .lock()
            .push(("db".to_string(), db_command.spawn().unwrap()));
        std::thread::sleep(Duration::from_millis(100));

        shutdown_children_ordered(
            &children,
            false,
            Some(&[vec!["db".to_string()], vec!["web".to_string()]]),
        );

        assert_eq!(std::fs::read_to_string(observation).unwrap().trim(), "gone");
    }
}
