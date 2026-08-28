use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use lpm_runtime::detect::RuntimeKind;

use super::tooling::wait_with_timeout;

const RUNTIME_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn get_system_node_version(project_dir: &Path) -> Option<String> {
    get_system_runtime_version(project_dir, RuntimeKind::Node).map(|version| {
        version
            .strip_prefix('v')
            .unwrap_or(&version)
            .trim()
            .to_owned()
    })
}

pub(super) fn get_system_bun_version(project_dir: &Path) -> Option<String> {
    get_system_runtime_version(project_dir, RuntimeKind::Bun)
}

pub(super) fn probe_system_version_if_unmanaged(
    managed_version: Option<&str>,
    probe: impl FnOnce() -> Option<String>,
) -> Option<String> {
    managed_version.is_none().then(probe).flatten()
}

fn get_system_runtime_version(project_dir: &Path, runtime: RuntimeKind) -> Option<String> {
    let trusted_path = trusted_runtime_path(project_dir)?;
    let executable = find_runtime_executable(&trusted_path, project_dir, runtime)?;
    let mut command = Command::new(executable);
    command
        .arg("--version")
        .current_dir(project_dir)
        .env_clear()
        .envs(crate::commands::rebuild::sandbox_env::build_sanitized_env())
        .env("PATH", &trusted_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = lpm_sandbox::spawn_tracked_command(&mut command).ok()?;
    let output = wait_with_timeout(child, RUNTIME_PROBE_TIMEOUT).ok()?;

    if output.status.success() {
        let version = std::str::from_utf8(&output.stdout).ok()?.trim();
        (!version.is_empty()).then(|| version.to_string())
    } else {
        None
    }
}

fn trusted_runtime_path(project_dir: &Path) -> Option<OsString> {
    let inherited = std::env::var_os("PATH")?;
    let project = canonical_or_absolute(project_dir)?;
    let workspace = lpm_workspace::find_workspace_root(project_dir)
        .ok()
        .flatten()
        .and_then(|root| canonical_or_absolute(&root));
    let mut trusted = Vec::new();

    for entry in std::env::split_paths(&inherited) {
        if !entry.is_absolute() || contains_node_modules_bin(&entry) {
            continue;
        }
        let resolved = entry.canonicalize().unwrap_or(entry);
        if resolved.starts_with(&project)
            || workspace
                .as_deref()
                .is_some_and(|root| resolved.starts_with(root))
        {
            continue;
        }
        if !trusted.contains(&resolved) {
            trusted.push(resolved);
        }
    }

    std::env::join_paths(trusted).ok()
}

fn find_runtime_executable(
    path: &OsStr,
    project_dir: &Path,
    runtime: RuntimeKind,
) -> Option<PathBuf> {
    let project = canonical_or_absolute(project_dir)?;
    let workspace = lpm_workspace::find_workspace_root(project_dir)
        .ok()
        .flatten()
        .and_then(|root| canonical_or_absolute(&root));

    for directory in std::env::split_paths(path) {
        for name in runtime_executable_names(runtime) {
            let candidate = directory.join(name);
            if !is_executable_file(&candidate) {
                continue;
            }
            let Ok(resolved) = candidate.canonicalize() else {
                continue;
            };
            if resolved.starts_with(&project)
                || workspace
                    .as_deref()
                    .is_some_and(|root| resolved.starts_with(root))
            {
                continue;
            }
            return Some(resolved);
        }
    }
    None
}

#[cfg(windows)]
fn runtime_executable_names(runtime: RuntimeKind) -> [&'static str; 2] {
    match runtime {
        RuntimeKind::Node => ["node.exe", "node.com"],
        RuntimeKind::Bun => ["bun.exe", "bun.com"],
    }
}

#[cfg(not(windows))]
fn runtime_executable_names(runtime: RuntimeKind) -> [&'static str; 1] {
    [runtime.binary_name()]
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn contains_node_modules_bin(path: &Path) -> bool {
    let mut previous_was_node_modules = false;
    for component in path.components() {
        let Component::Normal(name) = component else {
            previous_was_node_modules = false;
            continue;
        };
        if previous_was_node_modules && name == ".bin" {
            return true;
        }
        previous_was_node_modules = name == "node_modules";
    }
    false
}

fn canonical_or_absolute(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    std::env::current_dir().ok().map(|cwd| cwd.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_managed_runtime_skips_the_system_probe() {
        let version = probe_system_version_if_unmanaged(Some("22.1.0"), || {
            panic!("system probe must not run when the managed runtime already matches")
        });

        assert!(version.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn system_runtime_probe_does_not_inherit_ambient_secrets() {
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let node = bin.path().join("node");
        std::fs::write(
            &node,
            "#!/bin/sh\nprintf '%s' \"$LPM_DOCTOR_RUNTIME_UNIQUE_SECRET\"\n",
        )
        .unwrap();
        let mut permissions = node.metadata().unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&node, permissions).unwrap();
        let prior_path = std::env::var_os("PATH");
        let prior_secret = std::env::var_os("LPM_DOCTOR_RUNTIME_UNIQUE_SECRET");
        // SAFETY: both variables are restored before the test returns.
        unsafe {
            std::env::set_var("PATH", bin.path());
            std::env::set_var("LPM_DOCTOR_RUNTIME_UNIQUE_SECRET", "must-not-leak");
        }

        let version = get_system_node_version(project.path());

        match prior_path {
            Some(value) => unsafe { std::env::set_var("PATH", value) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        match prior_secret {
            Some(value) => unsafe { std::env::set_var("LPM_DOCTOR_RUNTIME_UNIQUE_SECRET", value) },
            None => unsafe { std::env::remove_var("LPM_DOCTOR_RUNTIME_UNIQUE_SECRET") },
        }
        assert!(
            version.is_none(),
            "runtime probe inherited a secret: {version:?}"
        );
    }
}
