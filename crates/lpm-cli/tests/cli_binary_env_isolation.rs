//! Cli-binary tier — intentionally minimal binary-surface repro where
//! the workflow harness would obscure the failure.
//!
//! The cli-binary shared runner must carry the same host-state isolation
//! posture as the workflow runner. Security approval persistence is a
//! real `lpm-rs` subprocess concern, but invoking the old behavior would
//! touch the developer's macOS Keychain; this test pins the command
//! environment before the process is spawned.

mod common;

use std::ffi::OsStr;
use std::process::Command;
use tempfile::TempDir;

fn command_env_value<'a>(command: &'a Command, key: &str) -> Option<&'a OsStr> {
    command
        .get_envs()
        .find_map(|(name, value)| (name == OsStr::new(key)).then_some(value).flatten())
}

#[test]
fn cli_binary_common_runner_forces_file_backed_security_approval_store() {
    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp lpm home");

    let command = common::lpm_command(project.path(), lpm_home.path(), None, &["--version"]);

    assert_eq!(
        command_env_value(&command, "LPM_FORCE_FILE_VAULT"),
        Some(OsStr::new("1")),
        "cli-binary tests must not use the host keychain-backed security approval store",
    );
}
