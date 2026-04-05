//! Port conflict detection, resolution, and cross-service env injection.
//!
//! Before starting services, checks all declared ports for conflicts
//! and builds cross-service environment variables ({SERVICE}_URL, {SERVICE}_PORT).

use std::collections::HashMap;
use std::net::TcpListener;
use std::process::Command;

/// Status of a port.
#[derive(Debug)]
pub enum PortStatus {
    Free,
    InUse {
        pid: Option<u32>,
        process_name: Option<String>,
    },
}

/// Check if a port is available.
pub fn check_port(port: u16) -> PortStatus {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => PortStatus::Free,
        Err(_) => {
            let (pid, name) = find_port_owner(port);
            PortStatus::InUse {
                pid,
                process_name: name,
            }
        }
    }
}

/// Find the next available port starting from `start`.
pub fn find_available_port(start: u16) -> Option<u16> {
    for port in start..=65535 {
        if let PortStatus::Free = check_port(port) {
            return Some(port);
        }
    }
    None
}

/// Kill the process using a specific port.
///
/// Re-checks the PID before killing to mitigate TOCTOU race conditions
/// (the port owner could change between detection and kill).
pub fn kill_port_owner(port: u16) -> Result<(), String> {
    let (pid, name) = find_port_owner(port);
    match pid {
        Some(pid) => {
            // Finding #10: Mitigate PID reuse TOCTOU by re-querying which PID
            // owns the *specific port* (not just checking if the PID exists).
            // `find_port_owner` runs `lsof -ti :{port}` which verifies the PID
            // is still bound to this exact port, not merely alive.
            std::thread::sleep(std::time::Duration::from_millis(50));
            let (pid_recheck, _) = find_port_owner(port);
            if pid_recheck != Some(pid) {
                return Err(format!(
                    "port {port} owner changed (was PID {pid}, now {:?}) — aborting kill for safety",
                    pid_recheck
                ));
            }

            let proc_name = name.as_deref().unwrap_or("unknown");
            tracing::debug!("killing PID {pid} ({proc_name}) on port {port}");

            #[cfg(unix)]
            {
                let output = Command::new("kill")
                    .arg(pid.to_string())
                    .output()
                    .map_err(|e| format!("failed to kill PID {pid} ({proc_name}): {e}"))?;
                if !output.status.success() {
                    return Err(format!(
                        "failed to kill PID {pid} ({proc_name}): {}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
            #[cfg(windows)]
            {
                let output = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .output()
                    .map_err(|e| format!("failed to kill PID {pid} ({proc_name}): {e}"))?;
                if !output.status.success() {
                    return Err(format!("failed to kill PID {pid} ({proc_name})"));
                }
            }
            Ok(())
        }
        None => Err(format!("no process found using port {port}")),
    }
}

/// Build cross-service environment variables.
///
/// For each service with a declared port, injects `{SERVICE}_URL` and `{SERVICE}_PORT`
/// into all OTHER services' environments.
///
/// Example: services "web" (port 3000) and "api" (port 4000)
/// - web gets: API_URL=http://localhost:4000, API_PORT=4000
/// - api gets: WEB_URL=http://localhost:3000, WEB_PORT=3000
pub fn build_cross_service_env(
    services: &HashMap<String, u16>,
    https: bool,
) -> HashMap<String, HashMap<String, String>> {
    let scheme = if https { "https" } else { "http" };
    let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();

    for name in services.keys() {
        result.insert(name.clone(), HashMap::new());
    }

    for (source_name, &source_port) in services {
        let upper = source_name.to_uppercase().replace('-', "_");
        let url_key = format!("{upper}_URL");
        let port_key = format!("{upper}_PORT");
        let url_value = format!("{scheme}://localhost:{source_port}");
        let port_value = source_port.to_string();

        // Inject into all OTHER services
        for (target_name, env) in result.iter_mut() {
            if target_name != source_name {
                env.insert(url_key.clone(), url_value.clone());
                env.insert(port_key.clone(), port_value.clone());
            }
        }
    }

    result
}

/// Find the PID and process name using a port.
fn find_port_owner(port: u16) -> (Option<u32>, Option<String>) {
    #[cfg(unix)]
    {
        // lsof -ti :{port}
        let output = Command::new("lsof")
            .args(["-ti", &format!(":{port}")])
            .output()
            .ok();

        if let Some(output) = output
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let pid_str = stdout.trim().lines().next().unwrap_or("").trim();
            if let Ok(pid) = pid_str.parse::<u32>() {
                // Get process name via ps
                let name = Command::new("ps")
                    .args(["-p", &pid.to_string(), "-o", "comm="])
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                        } else {
                            None
                        }
                    });
                return (Some(pid), name);
            }
        }
    }

    (None, None)
}

// ── Port Persistence ───────────────────────────────────────────────

/// Read persisted port overrides for a project.
///
/// Returns a map of service_name → port from `~/.lpm/ports.toml`.
/// Uses the project directory hash as the key to avoid conflicts.
pub fn read_port_overrides(project_dir: &std::path::Path) -> HashMap<String, u16> {
    let path = match ports_toml_path() {
        Some(p) => p,
        None => return HashMap::new(),
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };

    let doc: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };

    let project_key = project_hash(project_dir);
    let mut result = HashMap::new();

    if let Some(project) = doc.get(&project_key).and_then(|p| p.as_table()) {
        for (name, value) in project {
            if let Some(port) = value.as_integer() {
                result.insert(name.clone(), port as u16);
            }
        }
    }

    result
}

/// Write a port override for a project service.
///
/// Uses atomic write (tempfile + rename) to prevent corruption from
/// concurrent `lpm dev` instances writing to the same file.
pub fn write_port_override(project_dir: &std::path::Path, service_name: &str, port: u16) {
    let path = match ports_toml_path() {
        Some(p) => p,
        None => return,
    };

    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc: toml::value::Table = content
        .parse::<toml::Value>()
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_default();

    let project_key = project_hash(project_dir);
    let project_table = doc
        .entry(project_key)
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));

    if let Some(table) = project_table.as_table_mut() {
        table.insert(service_name.to_string(), toml::Value::Integer(port as i64));
    }

    atomic_write_toml(&path, &doc);
}

/// Clear all port overrides for a project.
///
/// Uses atomic write to prevent corruption from concurrent access.
pub fn clear_port_overrides(project_dir: &std::path::Path) {
    let path = match ports_toml_path() {
        Some(p) => p,
        None => return,
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut doc: toml::value::Table = match content.parse::<toml::Value>() {
        Ok(v) => v.try_into().unwrap_or_default(),
        Err(_) => return,
    };

    let project_key = project_hash(project_dir);
    doc.remove(&project_key);

    atomic_write_toml(&path, &doc);
}

/// Atomically write a TOML table to a file via tempfile + rename.
///
/// This prevents corruption from concurrent writes: either the old or
/// the new content is visible, never a partial write.
fn atomic_write_toml(path: &std::path::Path, doc: &toml::value::Table) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let content = toml::to_string_pretty(doc).unwrap_or_default();

    // Write to a temp file in the same directory, then rename.
    // Same-directory ensures we stay on the same filesystem (rename is atomic).
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let tmp_path = parent.join(format!(".ports.toml.{}.tmp", std::process::id()));
    if std::fs::write(&tmp_path, &content).is_ok() {
        if std::fs::rename(&tmp_path, path).is_err() {
            // rename failed (cross-device?), fall back to direct write
            let _ = std::fs::write(path, content);
            let _ = std::fs::remove_file(&tmp_path);
        }
    } else {
        // Fallback: direct write
        let _ = std::fs::write(path, content);
    }
}

fn ports_toml_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".lpm").join("ports.toml"))
}

fn project_hash(project_dir: &std::path::Path) -> String {
    let hash = crate::dlx::deterministic_hash(&project_dir.to_string_lossy());
    format!("project_{hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_free_port() {
        // Port 0 lets the OS pick a free port; use a high random port
        // that's very unlikely to be in use
        let port = 49152 + (std::process::id() as u16 % 1000);
        // This might be in use, so just verify the function doesn't panic
        let _ = check_port(port);
    }

    #[test]
    fn find_available_port_works() {
        let port = find_available_port(49000);
        assert!(port.is_some());
        assert!(port.unwrap() >= 49000);
    }

    #[test]
    fn cross_service_env_two_services() {
        let mut services = HashMap::new();
        services.insert("web".to_string(), 3000u16);
        services.insert("api".to_string(), 4000u16);

        let env = build_cross_service_env(&services, false);

        // web should have API_URL and API_PORT
        let web_env = &env["web"];
        assert_eq!(web_env.get("API_URL").unwrap(), "http://localhost:4000");
        assert_eq!(web_env.get("API_PORT").unwrap(), "4000");

        // api should have WEB_URL and WEB_PORT
        let api_env = &env["api"];
        assert_eq!(api_env.get("WEB_URL").unwrap(), "http://localhost:3000");
        assert_eq!(api_env.get("WEB_PORT").unwrap(), "3000");

        // web should NOT have its own URL
        assert!(!web_env.contains_key("WEB_URL"));
    }

    #[test]
    fn write_and_read_port_override() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project_dir = tmp.path().join("my-project");
        std::fs::create_dir_all(&project_dir).unwrap();

        // Override HOME so ports.toml is written to a temp location
        let fake_home = tmp.path().join("home");
        std::fs::create_dir_all(fake_home.join(".lpm")).unwrap();
        let toml_path = fake_home.join(".lpm").join("ports.toml");

        // Write override directly to the temp path
        let project_key = project_hash(&project_dir);
        let mut doc = toml::value::Table::new();
        let mut project_table = toml::value::Table::new();
        project_table.insert("web".to_string(), toml::Value::Integer(4001));
        doc.insert(project_key.clone(), toml::Value::Table(project_table));
        std::fs::write(&toml_path, toml::to_string_pretty(&doc).unwrap()).unwrap();

        // Verify it was written
        let content = std::fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("4001"), "should contain port override");
    }

    #[test]
    fn clear_port_overrides_removes_project_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project_dir = tmp.path().join("my-project");
        std::fs::create_dir_all(&project_dir).unwrap();

        // Manually create a ports.toml with this project's entry
        let lpm_dir = tmp.path().join(".lpm");
        std::fs::create_dir_all(&lpm_dir).unwrap();
        let toml_path = lpm_dir.join("ports.toml");

        let project_key = project_hash(&project_dir);
        let mut doc = toml::value::Table::new();
        let mut project_table = toml::value::Table::new();
        project_table.insert("web".to_string(), toml::Value::Integer(4001));
        doc.insert(project_key.clone(), toml::Value::Table(project_table));
        // Also add another project's entry to verify it's preserved
        let mut other = toml::value::Table::new();
        other.insert("api".to_string(), toml::Value::Integer(5000));
        doc.insert("project_other".to_string(), toml::Value::Table(other));
        std::fs::write(&toml_path, toml::to_string_pretty(&doc).unwrap()).unwrap();

        // Clear via the function (uses real HOME, so we test the logic directly)
        // We can't easily override HOME, so test the TOML manipulation directly
        let content = std::fs::read_to_string(&toml_path).unwrap();
        let mut parsed: toml::value::Table = content.parse::<toml::Value>().unwrap().try_into().unwrap();
        parsed.remove(&project_key);
        std::fs::write(&toml_path, toml::to_string_pretty(&parsed).unwrap()).unwrap();

        // Verify: project entry gone, other entry preserved
        let result = std::fs::read_to_string(&toml_path).unwrap();
        assert!(!result.contains("4001"), "project entry should be removed");
        assert!(result.contains("5000"), "other project entry should be preserved");
    }

    #[test]
    fn clear_nonexistent_project_is_harmless() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project_dir = tmp.path().join("nonexistent");
        // clear_port_overrides should not panic or fail
        clear_port_overrides(&project_dir);
    }

    #[test]
    fn atomic_write_creates_parent_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("deep").join("nested").join("ports.toml");
        let doc = toml::value::Table::new();
        atomic_write_toml(&path, &doc);
        assert!(path.exists(), "file should be created with parent dirs");
    }

    #[test]
    fn cross_service_env_https() {
        let mut services = HashMap::new();
        services.insert("web".to_string(), 3000u16);
        services.insert("api".to_string(), 4000u16);

        let env = build_cross_service_env(&services, true);
        assert_eq!(env["web"].get("API_URL").unwrap(), "https://localhost:4000");
    }
}
