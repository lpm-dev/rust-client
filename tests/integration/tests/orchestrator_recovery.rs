use lpm_runner::lpm_json::ServiceConfig;
use lpm_runner::orchestrator::{
    OrchestratorCommand, OrchestratorEvent, OrchestratorOptions, ServiceStatus, run_services,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

struct OrchestratorGuard {
    command_tx: Sender<OrchestratorCommand>,
    handle: Option<JoinHandle<Result<(), lpm_common::LpmError>>>,
}

impl OrchestratorGuard {
    fn finish(mut self) {
        let _ = self.command_tx.send(OrchestratorCommand::StopAll);
        let result = self.handle.take().expect("orchestrator handle").join();
        assert!(
            matches!(&result, Ok(Ok(()))),
            "orchestrator must stop cleanly: {result:?}"
        );
    }
}

impl Drop for OrchestratorGuard {
    fn drop(&mut self) {
        let _ = self.command_tx.send(OrchestratorCommand::StopAll);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn long_running_service(dependencies: &[&str]) -> ServiceConfig {
    ServiceConfig {
        command: "node -e \"setInterval(() => {}, 1000)\"".to_string(),
        depends_on: dependencies
            .iter()
            .map(|dependency| dependency.to_string())
            .collect(),
        ..Default::default()
    }
}

fn start_orchestrator(
    project_dir: PathBuf,
    services: HashMap<String, ServiceConfig>,
) -> (OrchestratorGuard, Receiver<OrchestratorEvent>) {
    let (command_tx, command_rx) = std::sync::mpsc::channel();
    let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
    let options = OrchestratorOptions {
        command_rx: Some(command_rx),
        event_tx: Some(event_tx),
        ..Default::default()
    };
    let handle = std::thread::spawn(move || run_services(&project_dir, &services, options));
    (
        OrchestratorGuard {
            command_tx,
            handle: Some(handle),
        },
        event_rx,
    )
}

fn wait_for_ready_services(event_rx: &Receiver<OrchestratorEvent>, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = HashSet::with_capacity(count);
    while ready.len() < count && Instant::now() < deadline {
        if let Ok(OrchestratorEvent::StatusChange {
            service_index,
            status: ServiceStatus::Ready,
        }) = event_rx.recv_timeout(Duration::from_millis(100))
        {
            ready.insert(service_index);
        }
    }
    assert_eq!(ready.len(), count, "initial services did not become ready");
}

#[test]
fn manual_dependency_restart_recovers_services_in_graph_order() {
    let project = tempfile::TempDir::new().expect("create temporary project");
    let services = HashMap::from([
        ("db".to_string(), long_running_service(&[])),
        ("api".to_string(), long_running_service(&["db"])),
        ("web".to_string(), long_running_service(&["api"])),
    ]);
    let (guard, event_rx) = start_orchestrator(project.path().to_path_buf(), services);
    wait_for_ready_services(&event_rx, 3);

    guard
        .command_tx
        .send(OrchestratorCommand::RestartService(0))
        .expect("restart database");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut lifecycle = Vec::new();
    while Instant::now() < deadline {
        if let Ok(OrchestratorEvent::StatusChange {
            service_index,
            status,
        }) = event_rx.recv_timeout(Duration::from_millis(100))
        {
            lifecycle.push((service_index, status));
            if lifecycle
                .iter()
                .any(|event| matches!(event, (2, ServiceStatus::Ready)))
            {
                break;
            }
        }
    }

    let position = |service_index: usize, predicate: fn(&ServiceStatus) -> bool| {
        lifecycle
            .iter()
            .position(|(index, status)| *index == service_index && predicate(status))
            .unwrap_or_else(|| panic!("missing lifecycle event in {lifecycle:?}"))
    };
    let web_waiting = position(2, |status| {
        matches!(status, ServiceStatus::WaitingForDep(_))
    });
    let api_waiting = position(1, |status| {
        matches!(status, ServiceStatus::WaitingForDep(_))
    });
    let db_ready = position(0, |status| matches!(status, ServiceStatus::Ready));
    let api_ready = position(1, |status| matches!(status, ServiceStatus::Ready));
    let web_ready = position(2, |status| matches!(status, ServiceStatus::Ready));

    assert!(
        web_waiting < api_waiting
            && api_waiting < db_ready
            && db_ready < api_ready
            && api_ready < web_ready,
        "dependents must stop in reverse order and recover in dependency order: {lifecycle:?}"
    );
    guard.finish();
}

#[test]
fn manually_stopped_dependent_does_not_resume_after_dependency_restart() {
    let project = tempfile::TempDir::new().expect("create temporary project");
    let services = HashMap::from([
        ("db".to_string(), long_running_service(&[])),
        ("api".to_string(), long_running_service(&["db"])),
    ]);
    let (guard, event_rx) = start_orchestrator(project.path().to_path_buf(), services);
    wait_for_ready_services(&event_rx, 2);

    guard
        .command_tx
        .send(OrchestratorCommand::StopService(1))
        .expect("stop API");
    guard
        .command_tx
        .send(OrchestratorCommand::RestartService(0))
        .expect("restart database");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut api_ready_again = false;
    while Instant::now() < deadline {
        if let Ok(OrchestratorEvent::StatusChange {
            service_index: 1,
            status: ServiceStatus::Ready,
        }) = event_rx.recv_timeout(Duration::from_millis(100))
        {
            api_ready_again = true;
            break;
        }
    }

    assert!(
        !api_ready_again,
        "a manually stopped dependent must remain stopped"
    );
    guard.finish();
}

#[test]
fn dependency_exit_stops_running_dependents() {
    let project = tempfile::TempDir::new().expect("create temporary project");
    let services = HashMap::from([
        (
            "db".to_string(),
            ServiceConfig {
                command: "node -e \"setTimeout(() => {}, 500)\"".to_string(),
                ..Default::default()
            },
        ),
        ("api".to_string(), long_running_service(&["db"])),
    ]);
    let (event_tx, event_rx) = std::sync::mpsc::sync_channel(256);
    let result = run_services(
        project.path(),
        &services,
        OrchestratorOptions {
            event_tx: Some(event_tx),
            ..Default::default()
        },
    );

    let dependent_stopped = event_rx.try_iter().any(|event| {
        matches!(
            event,
            OrchestratorEvent::StatusChange {
                service_index: 1,
                status: ServiceStatus::Stopped
            }
        )
    });

    assert!(
        result.is_ok() && dependent_stopped,
        "a dependent must stop after its dependency exits: {result:?}"
    );
}
