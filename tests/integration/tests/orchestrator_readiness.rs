use lpm_runner::lpm_json::ServiceConfig;
use lpm_runner::orchestrator::{
    OrchestratorEvent, OrchestratorOptions, ServiceStatus, run_services,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn initial_readiness_failure_emits_failure_without_ready_or_all_ready_callback() {
    let project = tempfile::TempDir::new().expect("create temporary project");
    std::fs::write(
        project.path().join("slow-service.js"),
        "setTimeout(() => {}, 10000);\n",
    )
    .expect("write slow service");

    let services = HashMap::from([(
        "db".to_string(),
        ServiceConfig {
            command: "node slow-service.js".to_string(),
            ready_url: Some("http://127.0.0.1:0/health".to_string()),
            ready_timeout: 1,
            ..Default::default()
        },
    )]);
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let callback_called = Arc::new(AtomicBool::new(false));
    let callback_flag = Arc::clone(&callback_called);
    let options = OrchestratorOptions {
        event_tx: Some(event_tx),
        on_all_ready: Some(Box::new(move |_| {
            callback_flag.store(true, Ordering::Relaxed);
            Ok(())
        })),
        ..Default::default()
    };

    let result = run_services(project.path(), &services, options);
    let statuses: Vec<ServiceStatus> = event_rx
        .try_iter()
        .filter_map(|event| match event {
            OrchestratorEvent::StatusChange { status, .. } => Some(status),
            OrchestratorEvent::ServiceLog { .. } => None,
        })
        .collect();

    assert!(result.is_err(), "readiness failure must stop startup");
    let failure = statuses.iter().find_map(|status| match status {
        ServiceStatus::ReadinessFailed(error) => Some(error),
        _ => None,
    });
    assert!(
        failure.is_some(),
        "readiness failure status missing: {statuses:?}"
    );
    assert!(
        failure.is_some_and(|error| error.chars().all(|c| !matches!(c, '\n' | '\r' | '\x1b'))),
        "dashboard status must not contain terminal controls: {failure:?}"
    );
    assert!(
        !statuses
            .iter()
            .any(|status| matches!(status, ServiceStatus::Ready)),
        "failed service must not emit Ready: {statuses:?}"
    );
    assert!(
        !callback_called.load(Ordering::Relaxed),
        "all-ready callback must not run after readiness failure"
    );
}
