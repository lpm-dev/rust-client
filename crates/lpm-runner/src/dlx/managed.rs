use lpm_common::LpmError;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn caller_controls(path: &Path, roots: &[PathBuf]) -> bool {
    let excluded = |path: &Path| {
        roots.iter().any(|root| path.starts_with(root))
            || path
                .components()
                .any(|part| part.as_os_str().eq_ignore_ascii_case("node_modules"))
    };
    !path.is_absolute()
        || excluded(path)
        || path
            .canonicalize()
            .is_ok_and(|canonical| excluded(&canonical))
}

fn caller_roots(project_dir: &Path) -> Vec<PathBuf> {
    let mut roots = vec![project_dir.to_path_buf()];
    if let Some(root) = lpm_workspace::find_project_root(project_dir) {
        roots.push(root);
    }
    if let Ok(Some(root)) = lpm_workspace::find_workspace_root(project_dir) {
        roots.push(root);
    }
    let canonical = roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect::<Vec<_>>();
    roots.extend(canonical);
    roots
}

fn trusted_node(roots: &[PathBuf]) -> Result<(PathBuf, std::ffi::OsString), LpmError> {
    let search = std::env::var_os("PATH").unwrap_or_default();
    let dirs = std::env::split_paths(&search)
        .filter(|path| !caller_controls(path, roots))
        .collect::<Vec<_>>();
    let path = std::env::join_paths(&dirs)
        .map_err(|error| LpmError::Script(format!("invalid managed runtime PATH: {error}")))?;
    let neutral = tempfile::tempdir()?;
    if caller_controls(neutral.path(), roots) {
        return Err(LpmError::Script(
            "MCP runtime requires a temporary directory outside the project".into(),
        ));
    }
    let executable = if cfg!(windows) { "node.exe" } else { "node" };
    for dir in dirs {
        let candidate = dir.join(executable);
        if !candidate.is_file() || caller_controls(&candidate, roots) {
            continue;
        }
        let mut probe = Command::new(&candidate);
        probe
            .env_clear()
            .env("PATH", &path)
            .current_dir(neutral.path());
        for name in [
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
        ] {
            if let Some(value) = std::env::var_os(name) {
                probe.env(name, value);
            }
        }
        probe.args(["-p", "JSON.stringify(process.execPath)"]);
        let Ok(output) = lpm_common::process_output::output_capped(
            &mut probe,
            std::time::Duration::from_secs(2),
            4096,
        ) else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let Ok(actual) = serde_json::from_slice::<String>(&output.stdout) else {
            continue;
        };
        let actual = PathBuf::from(actual);
        if actual.is_file() && !caller_controls(&actual, roots) {
            return Ok((actual.canonicalize()?, path));
        }
    }
    Err(LpmError::Script(
        "MCP runtime requires Node.js on PATH outside the project and node_modules".into(),
    ))
}

pub(super) fn entrypoint(cache_dir: &Path, package_spec: &str) -> Result<PathBuf, LpmError> {
    let (name, _) = super::parse_package_spec(package_spec);
    let package_dir = cache_dir.join("node_modules").join(&name).canonicalize()?;
    let package = lpm_workspace::read_package_json(&package_dir.join("package.json"))
        .map_err(|error| LpmError::Script(format!("invalid managed runtime manifest: {error}")))?;
    let bin_name = super::resolve_dlx_bin_name(cache_dir, package_spec)?;
    let entry = package
        .bin
        .as_ref()
        .and_then(|bin| {
            bin.entries(package.name.as_deref().unwrap_or(&name))
                .into_iter()
                .find(|(name, _)| name == &bin_name)
                .map(|(_, path)| path)
        })
        .ok_or_else(|| LpmError::Script("managed runtime has no entrypoint".into()))?;
    let entry = package_dir.join(entry).canonicalize()?;
    if !entry.starts_with(&package_dir) || !entry.is_file() {
        return Err(LpmError::Script(
            "managed runtime entrypoint leaves its installed package".into(),
        ));
    }
    Ok(entry)
}

pub(super) fn build_command(
    project_dir: &Path,
    cache_dir: &Path,
    package_spec: &str,
    extra_args: &[String],
) -> Result<Command, LpmError> {
    let entry = entrypoint(cache_dir, package_spec)?;
    let (node, path) = trusted_node(&caller_roots(project_dir))?;
    // This launcher restores credentials, so neither its interpreter nor inherited
    // child PATH can come from the caller's project. Ordinary dlx keeps local tools.
    let mut command = Command::new(node);
    crate::shell::strip_inherited_env_hooks(&mut command);
    command
        .env_remove("NODE_PATH")
        .env("PATH", path)
        .arg("--")
        .arg(entry)
        .args(extra_args)
        .current_dir(project_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    Ok(command)
}
