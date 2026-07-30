//! Diversion point for the install JSON envelope.
//!
//! Single-project installs print their envelope straight to stdout. A
//! recursive workspace install runs many install pipelines inside one
//! process and must emit exactly one stdout envelope, so the
//! orchestrator scopes each per-target pipeline with a capture sink;
//! every envelope emission site routes through [`emit_install_json`],
//! which stores the value in the active sink instead of printing when
//! one is set.

use std::future::Future;
use std::sync::{Arc, Mutex};

pub(crate) type CapturedInstallReport = Arc<Mutex<Option<serde_json::Value>>>;

tokio::task_local! {
    static INSTALL_REPORT_CAPTURE: CapturedInstallReport;
}

pub(crate) fn new_capture() -> CapturedInstallReport {
    Arc::new(Mutex::new(None))
}

pub(crate) async fn scope<F>(capture: CapturedInstallReport, future: F) -> F::Output
where
    F: Future,
{
    INSTALL_REPORT_CAPTURE.scope(capture, future).await
}

pub(crate) fn take(capture: &CapturedInstallReport) -> Option<serde_json::Value> {
    capture
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

/// Emit an install JSON envelope: into the active capture scope when
/// one is set, otherwise pretty-printed to stdout.
pub(crate) fn emit_install_json(json: &serde_json::Value) {
    let captured = INSTALL_REPORT_CAPTURE.try_with(|capture| {
        *capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(json.clone());
    });
    if captured.is_err() {
        println!("{}", serde_json::to_string_pretty(json).unwrap());
    }
}
