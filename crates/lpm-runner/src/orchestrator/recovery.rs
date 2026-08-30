use super::{
    AllReadyCallback, EndpointChangedCallback, InitialReadinessOptions, InitialServiceReadiness,
    MAX_RESTART_ATTEMPTS, OrchestratorCommand, OrchestratorCommandController, OrchestratorEvent,
    OutputReaderOptions, RED, RESET, ServiceEndpointMap, ServicePortMap, ServiceStatus, YELLOW,
    command_with_managed_port, invoke_all_ready_callback, send_status, service_ready_port,
    spawn_output_readers, terminate_service_tree, ui_readiness_timing, ui_service_note,
    ui_service_status, wait_for_initial_service_readiness,
};
use crate::dev_endpoint::DevEndpoint;
use crate::lpm_json::ServiceConfig;
use crate::service_graph;
use lpm_common::{LpmError, sanitize_terminal_inline};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ServiceGoal {
    Running,
    StoppedByUser,
    Completed,
    Failed,
    BlockedByDependency,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ServicePhase {
    Ready,
    Starting,
    RestartScheduled(Instant),
    WaitingForDependencies(String),
    Stopped,
}

#[derive(Debug, Clone)]
struct ServiceRuntimeState {
    goal: ServiceGoal,
    phase: ServicePhase,
    restart_attempts: u32,
    last_failure: Option<Instant>,
    terminal_error: Option<String>,
}

struct EndpointPublication<'a> {
    initial_complete: bool,
    initial_endpoints: ServiceEndpointMap,
    on_all_ready: Option<AllReadyCallback>,
    on_endpoint_changed: Option<&'a EndpointChangedCallback>,
}

impl EndpointPublication<'_> {
    fn service_ready(
        &mut self,
        states: &HashMap<String, ServiceRuntimeState>,
        name: &str,
        endpoint: Option<DevEndpoint>,
    ) -> Result<(), LpmError> {
        if self.initial_complete {
            if let (Some(callback), Some(endpoint)) = (self.on_endpoint_changed, endpoint) {
                invoke_endpoint_changed_callback(callback, endpoint)?;
            }
            return Ok(());
        }

        if let Some(endpoint) = endpoint {
            self.initial_endpoints.insert(name.to_string(), endpoint);
        } else {
            self.initial_endpoints.remove(name);
        }

        if states
            .values()
            .all(|state| state.goal != ServiceGoal::Running || state.is_ready())
        {
            self.initial_endpoints.retain(|service, _| {
                states
                    .get(service)
                    .is_some_and(ServiceRuntimeState::is_ready)
            });
            self.initial_complete = true;
            if let Some(callback) = self.on_all_ready.take() {
                invoke_all_ready_callback(callback, std::mem::take(&mut self.initial_endpoints))?;
            } else {
                self.initial_endpoints.clear();
            }
        }

        Ok(())
    }
}

fn invoke_endpoint_changed_callback(
    callback: &EndpointChangedCallback,
    endpoint: DevEndpoint,
) -> Result<(), LpmError> {
    std::thread::scope(
        |scope| match scope.spawn(move || callback(endpoint)).join() {
            Ok(result) => result,
            Err(_) => Err(LpmError::Script(
                "endpoint-changed callback panicked".to_string(),
            )),
        },
    )
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RestartDecision {
    Scheduled { delay_secs: u64, attempt: u32 },
    Exhausted,
}

impl ServiceRuntimeState {
    fn initial(ready: bool, spawned: bool, now: Instant) -> Self {
        Self {
            goal: ServiceGoal::Running,
            phase: if ready {
                ServicePhase::Ready
            } else if spawned {
                ServicePhase::Starting
            } else {
                ServicePhase::RestartScheduled(now)
            },
            restart_attempts: 0,
            last_failure: None,
            terminal_error: None,
        }
    }

    fn is_ready(&self) -> bool {
        self.goal == ServiceGoal::Running && self.phase == ServicePhase::Ready
    }

    fn has_pending_work(&self) -> bool {
        self.goal == ServiceGoal::Running
            && matches!(
                self.phase,
                ServicePhase::Starting
                    | ServicePhase::RestartScheduled(_)
                    | ServicePhase::WaitingForDependencies(_)
            )
    }
}

pub(super) struct RecoveryContext<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) active_services: &'a HashMap<String, ServiceConfig>,
    pub(super) groups: &'a [Vec<String>],
    pub(super) service_runtime_hints: &'a HashMap<String, crate::bin_path::ManagedRuntimeHint>,
    pub(super) dotenv: &'a HashMap<String, String>,
    pub(super) cross_env: &'a HashMap<String, HashMap<String, String>>,
    pub(super) port_map: &'a ServicePortMap,
    pub(super) color_map: &'a HashMap<String, &'static str>,
    pub(super) service_names: &'a [String],
    pub(super) initial_ready: &'a HashSet<String>,
    pub(super) children: &'a Arc<Mutex<Vec<(String, Child)>>>,
    pub(super) shutdown_state: &'a Arc<AtomicU8>,
    pub(super) event_tx: &'a Option<std::sync::mpsc::SyncSender<OrchestratorEvent>>,
    pub(super) command_controller: Option<&'a OrchestratorCommandController>,
    pub(super) initial_publication_complete: bool,
    pub(super) initial_endpoints: ServiceEndpointMap,
    pub(super) on_all_ready: Option<AllReadyCallback>,
    pub(super) on_endpoint_changed: Option<&'a EndpointChangedCallback>,
    pub(super) extra_envs: &'a [(String, String)],
}

pub(super) fn supervise_services(mut context: RecoveryContext<'_>) -> Result<(), LpmError> {
    let mut publication = EndpointPublication {
        initial_complete: context.initial_publication_complete,
        initial_endpoints: std::mem::take(&mut context.initial_endpoints),
        on_all_ready: context.on_all_ready.take(),
        on_endpoint_changed: context.on_endpoint_changed,
    };
    let spawned: HashSet<String> = context
        .children
        .lock()
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    let now = Instant::now();
    let mut states: HashMap<String, ServiceRuntimeState> = context
        .service_names
        .iter()
        .map(|name| {
            (
                name.clone(),
                ServiceRuntimeState::initial(
                    context.initial_ready.contains(name),
                    spawned.contains(name),
                    now,
                ),
            )
        })
        .collect();

    loop {
        if context.shutdown_state.load(Ordering::Relaxed) > 0 {
            break;
        }

        for (name, status) in collect_exited_children(context.children) {
            handle_service_exit(&context, &mut states, &name, status);
        }

        process_commands(&context, &mut states);
        resume_waiting_services(&context, &mut states);
        process_due_restarts(&context, &mut states, &mut publication)?;
        resume_waiting_services(&context, &mut states);

        if states
            .values()
            .any(|state| state.goal == ServiceGoal::Failed)
        {
            break;
        }

        let has_children = !context.children.lock().is_empty();
        let has_pending_work = states.values().any(ServiceRuntimeState::has_pending_work);
        if !has_children && !has_pending_work {
            break;
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    let mut failures: Vec<_> = states
        .iter()
        .filter(|(_, state)| state.goal == ServiceGoal::Failed)
        .map(|(name, state)| {
            format!(
                "{name}: {}",
                state.terminal_error.as_deref().unwrap_or("service failed")
            )
        })
        .collect();
    failures.sort_unstable();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(LpmError::Script(format!(
            "lpm dev service failure: {}",
            failures.join("; ")
        )))
    }
}

fn collect_exited_children(
    children: &Arc<Mutex<Vec<(String, Child)>>>,
) -> Vec<(String, ExitStatus)> {
    let mut exited = Vec::new();
    let mut locked = children.lock();
    let mut index = 0;
    while index < locked.len() {
        match locked[index].1.try_wait() {
            Ok(Some(status)) => {
                let (name, child) = locked.remove(index);
                super::cleanup_exited_service_tree(child.id());
                exited.push((name, status));
            }
            Ok(None) | Err(_) => index += 1,
        }
    }
    exited
}

fn handle_service_exit(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    name: &str,
    status: ExitStatus,
) {
    let color = context.color_map.get(name).copied().unwrap_or(RESET);
    if status.success() {
        ui_service_note(color, name, "exited");
        send_status(
            context.event_tx,
            context.service_names,
            name,
            ServiceStatus::Stopped,
        );
        if let Some(state) = states.get_mut(name) {
            state.goal = ServiceGoal::Completed;
            state.phase = ServicePhase::Stopped;
        }
        stop_dependents(context, states, name, false, "stopped");
        return;
    }

    let code = status.code().unwrap_or(-1);
    let should_restart = context
        .active_services
        .get(name)
        .is_some_and(|config| config.restart);
    let message = if should_restart {
        format!("crashed (exit {code}), restarting...")
    } else {
        format!("crashed (exit {code})")
    };
    ui_service_status(
        RESET,
        name,
        if should_restart { YELLOW } else { RED },
        if should_restart { "!" } else { "✗" },
        &message,
    );
    send_status(
        context.event_tx,
        context.service_names,
        name,
        ServiceStatus::Crashed(code),
    );
    if let Some(state) = states.get_mut(name) {
        state.terminal_error = Some(format!("exited with code {code}"));
    }

    if should_restart {
        schedule_after_failure(context, states, name);
        if states
            .get(name)
            .is_some_and(|state| state.goal == ServiceGoal::Running)
        {
            stop_dependents(context, states, name, true, "restarting");
        }
    } else {
        if let Some(state) = states.get_mut(name) {
            state.goal = ServiceGoal::Failed;
            state.phase = ServicePhase::Stopped;
            state.terminal_error = Some(format!("exited with code {code}"));
        }
        stop_dependents(context, states, name, false, "crashed");
    }
}

fn schedule_after_failure(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    name: &str,
) {
    let now = Instant::now();
    let Some(decision) = states
        .get_mut(name)
        .map(|state| schedule_restart(state, now))
    else {
        return;
    };

    let RestartDecision::Scheduled {
        delay_secs,
        attempt,
    } = decision
    else {
        ui_service_status(
            context.color_map.get(name).copied().unwrap_or(RESET),
            name,
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
            context.event_tx,
            context.service_names,
            name,
            ServiceStatus::Stopped,
        );
        stop_dependents(context, states, name, false, "permanently failed");
        return;
    };

    ui_service_status(
        context.color_map.get(name).copied().unwrap_or(RESET),
        name,
        YELLOW,
        "!",
        &format!("restarting in {delay_secs}s (attempt {attempt}/{MAX_RESTART_ATTEMPTS})..."),
    );
}

fn schedule_restart(state: &mut ServiceRuntimeState, now: Instant) -> RestartDecision {
    if state
        .last_failure
        .is_some_and(|last_failure| now.duration_since(last_failure).as_secs() > 60)
    {
        state.restart_attempts = 0;
    }
    state.restart_attempts += 1;
    state.last_failure = Some(now);

    if state.restart_attempts > MAX_RESTART_ATTEMPTS {
        state.goal = ServiceGoal::Failed;
        state.phase = ServicePhase::Stopped;
        return RestartDecision::Exhausted;
    }

    let delay_secs = std::cmp::min(1u64 << (state.restart_attempts - 1), 30);
    let attempt = state.restart_attempts;
    state.phase = ServicePhase::RestartScheduled(now + Duration::from_secs(delay_secs));
    RestartDecision::Scheduled {
        delay_secs,
        attempt,
    }
}

fn stop_dependents(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    dependency: &str,
    recoverable: bool,
    reason: &str,
) {
    let dependents = service_graph::transitive_dependents(dependency, context.active_services);
    if dependents.is_empty() {
        return;
    }

    for group in context.groups.iter().rev() {
        for name in group {
            if !dependents.contains(name)
                || !states
                    .get(name)
                    .is_some_and(|state| state.goal == ServiceGoal::Running)
            {
                continue;
            }

            terminate_service(context.children, name);
            if let Some(state) = states.get_mut(name) {
                if recoverable {
                    state.phase = ServicePhase::WaitingForDependencies(dependency.to_string());
                } else {
                    state.goal = ServiceGoal::BlockedByDependency;
                    state.phase = ServicePhase::Stopped;
                }
            }

            if recoverable {
                ui_service_status(
                    RESET,
                    name,
                    YELLOW,
                    "!",
                    &format!("waiting for dependency {dependency}"),
                );
                send_status(
                    context.event_tx,
                    context.service_names,
                    name,
                    waiting_status(dependency),
                );
            } else {
                ui_service_status(
                    RESET,
                    name,
                    RED,
                    "✗",
                    &format!("stopped (dependency {dependency} {reason})"),
                );
                send_status(
                    context.event_tx,
                    context.service_names,
                    name,
                    ServiceStatus::Stopped,
                );
            }
        }
    }
}

fn terminate_service(children: &Arc<Mutex<Vec<(String, Child)>>>, name: &str) {
    let child = {
        let mut locked = children.lock();
        locked
            .iter()
            .position(|(service_name, _)| service_name == name)
            .map(|position| locked.remove(position).1)
    };
    if let Some(mut child) = child {
        terminate_service_tree(&mut child);
    }
}

fn resume_waiting_services(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
) {
    let now = Instant::now();
    for group in context.groups {
        for name in group {
            if !states.get(name).is_some_and(|state| {
                state.goal == ServiceGoal::Running
                    && matches!(state.phase, ServicePhase::WaitingForDependencies(_))
            }) {
                continue;
            }

            if let Some(dependency) = first_unready_dependency(context, states, name) {
                let changed = states.get(name).is_some_and(|state| {
                    state.phase != ServicePhase::WaitingForDependencies(dependency.clone())
                });
                if changed {
                    if let Some(state) = states.get_mut(name) {
                        state.phase = ServicePhase::WaitingForDependencies(dependency.clone());
                    }
                    send_status(
                        context.event_tx,
                        context.service_names,
                        name,
                        waiting_status(&dependency),
                    );
                }
                continue;
            }

            if let Some(state) = states.get_mut(name) {
                state.phase = ServicePhase::RestartScheduled(now);
            }
            ui_service_status(
                context.color_map.get(name).copied().unwrap_or(RESET),
                name,
                YELLOW,
                "!",
                "dependencies recovered, restarting...",
            );
        }
    }
}

fn first_unready_dependency(
    context: &RecoveryContext<'_>,
    states: &HashMap<String, ServiceRuntimeState>,
    name: &str,
) -> Option<String> {
    context
        .active_services
        .get(name)
        .and_then(|config| first_unready_dependency_for(config, states))
}

fn first_unready_dependency_for(
    config: &ServiceConfig,
    states: &HashMap<String, ServiceRuntimeState>,
) -> Option<String> {
    config
        .depends_on
        .iter()
        .find(|dependency| {
            !states
                .get(*dependency)
                .is_some_and(ServiceRuntimeState::is_ready)
        })
        .cloned()
}

fn process_due_restarts(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    publication: &mut EndpointPublication<'_>,
) -> Result<(), LpmError> {
    let now = Instant::now();
    let due: Vec<String> = context
        .groups
        .iter()
        .flatten()
        .filter(|name| {
            states.get(*name).is_some_and(|state| {
                state.goal == ServiceGoal::Running
                    && matches!(state.phase, ServicePhase::RestartScheduled(at) if now >= at)
            })
        })
        .cloned()
        .collect();

    process_restart_batch(
        due,
        states,
        restart_is_due,
        |states, name| {
            if context.shutdown_state.load(Ordering::Relaxed) > 0 {
                return Ok(None);
            }
            if let Some(dependency) = first_unready_dependency(context, states, name) {
                wait_for_dependency(context, states, name, dependency);
                return Ok(None);
            }
            Ok(start_restart_service(context, states, name))
        },
        |states, job| settle_restart_job(context, states, publication, job),
    )
}

fn restart_is_due(states: &HashMap<String, ServiceRuntimeState>, name: &str) -> bool {
    states.get(name).is_some_and(|state| {
        state.goal == ServiceGoal::Running
            && matches!(state.phase, ServicePhase::RestartScheduled(at) if Instant::now() >= at)
    })
}

fn process_restart_batch<State, Job, Error>(
    due: Vec<String>,
    state: &mut State,
    is_current: impl Fn(&State, &str) -> bool,
    mut start: impl FnMut(&mut State, &str) -> Result<Option<Job>, Error>,
    mut settle: impl FnMut(&mut State, Job) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut jobs = Vec::with_capacity(due.len());
    for name in due {
        if is_current(state, &name)
            && let Some(job) = start(state, &name)?
        {
            jobs.push(job);
        }
    }
    for job in jobs {
        settle(state, job)?;
    }
    Ok(())
}

fn wait_for_dependency(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    name: &str,
    dependency: String,
) {
    if let Some(state) = states.get_mut(name) {
        state.phase = ServicePhase::WaitingForDependencies(dependency.clone());
    }
    ui_service_status(
        context.color_map.get(name).copied().unwrap_or(RESET),
        name,
        YELLOW,
        "!",
        &format!("waiting for dependency {dependency}"),
    );
    send_status(
        context.event_tx,
        context.service_names,
        name,
        waiting_status(&dependency),
    );
}

fn waiting_status(dependency: &str) -> ServiceStatus {
    ServiceStatus::WaitingForDep(sanitize_terminal_inline(dependency).into_owned())
}

struct RestartJob {
    name: String,
    readiness: std::thread::JoinHandle<Result<InitialServiceReadiness, String>>,
}

fn start_restart_service(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    name: &str,
) -> Option<RestartJob> {
    if !restart_is_due(states, name) {
        return None;
    }
    let config = context.active_services.get(name)?;
    if let Some(state) = states.get_mut(name) {
        state.phase = ServicePhase::Starting;
    }
    send_status(
        context.event_tx,
        context.service_names,
        name,
        ServiceStatus::Starting,
    );

    let cwd = if let Some(subdirectory) = &config.cwd {
        match super::safe_resolve_cwd(context.project_dir, subdirectory) {
            Ok(path) => path,
            Err(error) => {
                report_restart_failure(context, states, name, &error.to_string(), false);
                return None;
            }
        }
    } else {
        context.project_dir.to_path_buf()
    };

    let mut env = context.dotenv.clone();
    env.extend(config.env.clone());
    if let Some(cross_env) = context.cross_env.get(name) {
        env.extend(cross_env.clone());
    }
    if let Some(port) = context.port_map.get(name) {
        env.insert("PORT".to_string(), port.to_string());
    }

    let service_command =
        command_with_managed_port(&config.command, &cwd, context.port_map.get(name).copied());
    let service_runtime_hint = context
        .service_runtime_hints
        .get(name)
        .unwrap_or(&crate::bin_path::ManagedRuntimeHint::Unknown);
    let service_path =
        match crate::bin_path::build_path_with_bins_pre_resolved(&cwd, service_runtime_hint) {
            Ok(path) => path,
            Err(error) => {
                report_restart_failure(context, states, name, &error.to_string(), false);
                return None;
            }
        };
    let assigned_port = context.port_map.get(name).copied();
    let mut command = match crate::shell::shell_process(&service_command) {
        Ok(command) => command,
        Err(error) => {
            report_restart_failure(context, states, name, &error.to_string(), false);
            return None;
        }
    };
    command
        .current_dir(&cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    super::isolate_service_process_tree(&mut command);
    crate::shell::strip_inherited_env_hooks(&mut command);
    command.envs(&env).env("PATH", service_path);
    for (key, value) in context.extra_envs {
        command.env(key, value);
    }

    let mut new_child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            report_restart_failure(context, states, name, &error.to_string(), false);
            return None;
        }
    };
    let child_pid = new_child.id();
    let child_stdout = new_child.stdout.take();
    let child_stderr = new_child.stderr.take();
    context.children.lock().push((name.to_string(), new_child));

    let service_index = context
        .service_names
        .iter()
        .position(|service_name| service_name == name)
        .unwrap_or(0);
    let (endpoint_tx, endpoint_rx) =
        std::sync::mpsc::sync_channel(super::MAX_PENDING_ENDPOINT_CANDIDATES);
    let endpoint_candidates = super::EndpointCandidateSink::new(endpoint_tx);
    spawn_output_readers(
        child_stdout,
        child_stderr,
        OutputReaderOptions {
            name,
            color: context.color_map.get(name).copied().unwrap_or(RESET),
            service_index,
            shutdown_state: context.shutdown_state,
            event_tx: context.event_tx,
            endpoint_candidates: Some(endpoint_candidates.clone()),
        },
    );

    let ready_url = super::service_ready_url(config, assigned_port);
    let ready_port = service_ready_port(config, assigned_port);
    let timeout_secs = config.ready_timeout;
    let readiness_requires_running_process =
        assigned_port.is_some() || ready_url.is_some() || ready_port.is_some();
    let readiness_children = Arc::clone(context.children);
    let readiness_shutdown = Arc::clone(context.shutdown_state);
    let readiness_controller = context.command_controller.cloned();
    let readiness_name = name.to_string();
    let job_name = readiness_name.clone();
    let readiness = std::thread::spawn(move || {
        let result = wait_for_initial_service_readiness(
            InitialReadinessOptions {
                service_dir: &cwd,
                root_pid: child_pid,
                assigned_port,
                candidates: &endpoint_rx,
                ready_url,
                ready_port,
                timeout_secs,
            },
            || {
                readiness_shutdown.load(Ordering::Relaxed) > 0
                    || readiness_controller
                        .as_ref()
                        .is_some_and(|controller| controller.has_pending_service(service_index))
                    || (readiness_requires_running_process
                        && super::service_exit_status(&readiness_children, &readiness_name)
                            .is_some())
            },
        );
        endpoint_candidates.deactivate();
        result
    });

    Some(RestartJob {
        name: job_name,
        readiness,
    })
}

fn settle_restart_job(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    publication: &mut EndpointPublication<'_>,
    job: RestartJob,
) -> Result<(), LpmError> {
    let name = job.name;
    let readiness = job.readiness.join().map_err(|_| {
        LpmError::Script(format!(
            "service `{name}` readiness worker panicked during restart"
        ))
    })?;
    process_commands(context, states);

    match readiness {
        Ok(mut readiness) => {
            if let Some(status) = take_exited_service(context.children, &name) {
                handle_service_exit(context, states, &name, status);
                return Ok(());
            }
            if !states.get(&name).is_some_and(|state| {
                state.goal == ServiceGoal::Running && state.phase == ServicePhase::Starting
            }) {
                return Ok(());
            }
            if let Some(endpoint) = &mut readiness.endpoint {
                endpoint.service = Some(name.clone());
            }
            if let Some(state) = states.get_mut(&name) {
                state.goal = ServiceGoal::Running;
                state.phase = ServicePhase::Ready;
                state.terminal_error = None;
            }
            let timing = ui_readiness_timing(readiness.duration);
            ui_service_status(
                context.color_map.get(&name).copied().unwrap_or(RESET),
                &name,
                super::GREEN,
                "✓",
                &format!("restarted{timing}"),
            );
            send_status(
                context.event_tx,
                context.service_names,
                &name,
                ServiceStatus::Ready,
            );
            publication.service_ready(states, &name, readiness.endpoint)?;
        }
        Err(error) => {
            if context.shutdown_state.load(Ordering::Relaxed) > 0
                || !states.get(&name).is_some_and(|state| {
                    state.goal == ServiceGoal::Running && state.phase == ServicePhase::Starting
                })
            {
                return Ok(());
            }
            terminate_service(context.children, &name);
            report_restart_failure(context, states, &name, &error, true);
        }
    }

    Ok(())
}

fn take_exited_service(
    children: &Arc<Mutex<Vec<(String, Child)>>>,
    name: &str,
) -> Option<ExitStatus> {
    let mut locked = children.lock();
    let position = locked
        .iter()
        .position(|(service_name, _)| service_name == name)?;
    let status = locked[position].1.try_wait().ok().flatten()?;
    let (_, child) = locked.remove(position);
    super::cleanup_exited_service_tree(child.id());
    Some(status)
}

fn report_restart_failure(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    name: &str,
    error: &str,
    readiness_failure: bool,
) {
    let display_error = sanitize_terminal_inline(error).into_owned();
    if let Some(state) = states.get_mut(name) {
        state.terminal_error = Some(display_error.clone());
    }
    ui_service_status(
        RESET,
        name,
        YELLOW,
        "!",
        &format!("restart failed - {display_error}"),
    );
    if readiness_failure {
        send_status(
            context.event_tx,
            context.service_names,
            name,
            ServiceStatus::ReadinessFailed(display_error),
        );
    }
    schedule_after_failure(context, states, name);
}

fn process_commands(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
) {
    let Some(command_controller) = context.command_controller else {
        return;
    };
    for command in command_controller.drain() {
        match command {
            OrchestratorCommand::StopAll => {
                context.shutdown_state.store(1, Ordering::Relaxed);
                break;
            }
            OrchestratorCommand::StopService(index) => {
                if let Some(name) = context.service_names.get(index) {
                    stop_dependents(context, states, name, true, "stopped by user");
                    terminate_service(context.children, name);
                    if let Some(state) = states.get_mut(name) {
                        state.goal = ServiceGoal::StoppedByUser;
                        state.phase = ServicePhase::Stopped;
                    }
                    ui_service_status(RESET, name, YELLOW, "!", "stopped by user");
                    send_status(
                        context.event_tx,
                        context.service_names,
                        name,
                        ServiceStatus::Stopped,
                    );
                }
            }
            OrchestratorCommand::RestartService(index) => {
                if let Some(name) = context.service_names.get(index) {
                    reactivate_blocked_dependents(context, states, name);
                    stop_dependents(context, states, name, true, "restarting");
                    terminate_service(context.children, name);
                    let dependency = first_unready_dependency(context, states, name);
                    if let Some(state) = states.get_mut(name) {
                        state.goal = ServiceGoal::Running;
                        state.restart_attempts = 0;
                        state.last_failure = None;
                        state.terminal_error = None;
                        state.phase = ServicePhase::Stopped;
                    }
                    if let Some(dependency) = dependency {
                        wait_for_dependency(context, states, name, dependency);
                    } else if let Some(state) = states.get_mut(name) {
                        state.phase = ServicePhase::RestartScheduled(Instant::now());
                    }
                }
            }
        }
    }
}

fn reactivate_blocked_dependents(
    context: &RecoveryContext<'_>,
    states: &mut HashMap<String, ServiceRuntimeState>,
    dependency: &str,
) {
    let dependents = service_graph::transitive_dependents(dependency, context.active_services);
    for name in dependents {
        let Some(state) = states.get_mut(&name) else {
            continue;
        };
        if state.goal == ServiceGoal::BlockedByDependency {
            state.goal = ServiceGoal::Running;
            state.phase = ServicePhase::WaitingForDependencies(dependency.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restarted_endpoint_callback_runs_outside_the_orchestrator_thread() {
        let orchestrator_thread = std::thread::current().id();
        let callback: EndpointChangedCallback = Box::new(move |_| {
            assert_ne!(std::thread::current().id(), orchestrator_thread);
            Ok(())
        });
        let mut publication = EndpointPublication {
            initial_complete: true,
            initial_endpoints: ServiceEndpointMap::new(),
            on_all_ready: None,
            on_endpoint_changed: Some(&callback),
        };
        let endpoint = DevEndpoint {
            target: lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 3000),
            owner_pid: None,
            owner_identity: None,
            service: Some("web".to_string()),
        };

        publication
            .service_ready(&HashMap::new(), "web", Some(endpoint))
            .unwrap();
    }

    #[test]
    fn restarted_endpoint_callback_panic_is_reported_as_an_error() {
        let callback: EndpointChangedCallback =
            Box::new(|_| panic!("injected endpoint callback panic"));
        let mut publication = EndpointPublication {
            initial_complete: true,
            initial_endpoints: ServiceEndpointMap::new(),
            on_all_ready: None,
            on_endpoint_changed: Some(&callback),
        };
        let endpoint = DevEndpoint {
            target: lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 3000),
            owner_pid: None,
            owner_identity: None,
            service: Some("web".to_string()),
        };

        let error = publication
            .service_ready(&HashMap::new(), "web", Some(endpoint))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("endpoint-changed callback panicked")
        );
    }

    #[test]
    fn stable_service_resets_restart_attempts_before_scheduling() {
        let now = Instant::now();
        let mut state = ServiceRuntimeState {
            goal: ServiceGoal::Running,
            phase: ServicePhase::Ready,
            restart_attempts: 7,
            last_failure: Some(now - Duration::from_secs(61)),
            terminal_error: None,
        };

        let decision = schedule_restart(&mut state, now);

        assert_eq!(
            decision,
            RestartDecision::Scheduled {
                delay_secs: 1,
                attempt: 1
            }
        );
    }

    #[test]
    fn restart_attempt_after_the_limit_marks_service_failed() {
        let now = Instant::now();
        let mut state = ServiceRuntimeState {
            goal: ServiceGoal::Running,
            phase: ServicePhase::Ready,
            restart_attempts: MAX_RESTART_ATTEMPTS,
            last_failure: Some(now),
            terminal_error: None,
        };

        let decision = schedule_restart(&mut state, now);

        assert_eq!(
            (decision, state.goal),
            (RestartDecision::Exhausted, ServiceGoal::Failed)
        );
    }

    #[test]
    fn manually_stopped_service_has_no_pending_work() {
        let state = ServiceRuntimeState {
            goal: ServiceGoal::StoppedByUser,
            phase: ServicePhase::Stopped,
            restart_attempts: 0,
            last_failure: None,
            terminal_error: None,
        };

        assert!(!state.has_pending_work());
    }

    #[test]
    fn stale_restart_batch_does_not_process_a_service_stopped_by_an_earlier_restart() {
        let mut running = HashMap::from([("a".to_string(), true), ("b".to_string(), true)]);
        let mut processed = Vec::new();

        process_restart_batch(
            vec!["a".to_string(), "b".to_string()],
            &mut running,
            |running, name| running.get(name).copied().unwrap_or(false),
            |running, name| {
                processed.push(name.to_string());
                if name == "a" {
                    running.insert("b".to_string(), false);
                }
                Ok::<Option<()>, ()>(Some(()))
            },
            |_, ()| Ok::<(), ()>(()),
        )
        .unwrap();

        assert_eq!(processed, vec!["a"]);
    }

    #[test]
    fn restart_batch_starts_every_current_job_before_settling_any_job() {
        let mut state = (
            HashMap::from([("a".to_string(), true), ("b".to_string(), true)]),
            0,
        );

        process_restart_batch(
            vec!["a".to_string(), "b".to_string()],
            &mut state,
            |state, name| state.0.get(name).copied().unwrap_or(false),
            |state, name| {
                state.1 += 1;
                Ok::<Option<String>, ()>(Some(name.to_string()))
            },
            |state, _job| {
                assert_eq!(state.1, 2, "every readiness job must already be active");
                Ok::<(), ()>(())
            },
        )
        .unwrap();
    }

    #[test]
    fn service_waits_until_every_direct_dependency_is_ready() {
        let config = ServiceConfig {
            depends_on: vec!["cache".to_string(), "db".to_string()],
            ..Default::default()
        };
        let now = Instant::now();
        let states = HashMap::from([
            (
                "cache".to_string(),
                ServiceRuntimeState::initial(true, true, now),
            ),
            (
                "db".to_string(),
                ServiceRuntimeState::initial(false, true, now),
            ),
        ]);

        let dependency = first_unready_dependency_for(&config, &states);

        assert_eq!(dependency.as_deref(), Some("db"));
    }

    #[cfg(unix)]
    #[test]
    fn taking_an_exited_service_cleans_its_surviving_process_group() {
        let children = Arc::new(Mutex::new(Vec::new()));
        let mut command = std::process::Command::new("sh");
        command.arg("-c").arg("trap '' TERM; sleep 60 & exit 1");
        super::super::isolate_service_process_tree(&mut command);
        let child = command.spawn().unwrap();
        let root_pid = child.id();
        children.lock().push(("worker".to_string(), child));

        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = take_exited_service(&children, "worker") {
                break status;
            }
            assert!(Instant::now() < deadline, "root process did not exit");
            std::thread::sleep(Duration::from_millis(10));
        };

        assert!(!status.success());
        let cleanup_deadline = Instant::now() + Duration::from_secs(2);
        while super::super::service_process_group_exists(root_pid)
            && Instant::now() < cleanup_deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!super::super::service_process_group_exists(root_pid));
    }

    #[test]
    fn waiting_status_removes_terminal_controls_from_dependency_name() {
        let status = waiting_status("db\n\x1b[31mspoofed");

        assert_eq!(
            status,
            ServiceStatus::WaitingForDep("db?spoofed".to_string())
        );
    }
}
