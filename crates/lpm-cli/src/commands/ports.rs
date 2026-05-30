use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_runner::lpm_json;
use lpm_runner::ports;
use std::path::Path;

/// Run the `lpm ports` command.
pub async fn run(
    action: &str,
    port_arg: Option<u16>,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        "list" | "" => run_list(project_dir, json_output),
        "kill" => {
            let port = port_arg.ok_or_else(|| {
                LpmError::Script("missing port number. Usage: lpm ports kill <port>".into())
            })?;
            run_kill(port, json_output)
        }
        "reset" => {
            run_reset(project_dir, json_output);
            Ok(())
        }
        _ => Err(LpmError::Script(format!(
            "unknown action '{action}'. Available: list, kill, reset"
        ))),
    }
}

fn run_list(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;

    let services = config
        .as_ref()
        .map(|c| &c.services)
        .filter(|s| !s.is_empty());

    let services = match services {
        Some(s) => s,
        None => {
            if json_output {
                println!("{{\"ports\":[]}}");
            } else {
                install_ui::warn("No services defined in lpm.json");
            }
            return Ok(());
        }
    };

    if json_output {
        let ports: Vec<serde_json::Value> = services
            .iter()
            .filter_map(|(name, config)| {
                config.port.map(|port| {
                    let status = match ports::check_port(port) {
                        ports::PortStatus::Free => "free",
                        ports::PortStatus::InUse { .. } => "in_use",
                    };
                    serde_json::json!({
                        "service": name,
                        "port": port,
                        "status": status,
                    })
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "success": true, "ports": ports }));
        return Ok(());
    }

    let rows: Vec<_> = services
        .iter()
        .filter_map(|(name, config)| {
            config.port.map(|port| {
                let status = match ports::check_port(port) {
                    ports::PortStatus::Free => "free".green(),
                    ports::PortStatus::InUse { pid, process_name } => {
                        let owner = match (&pid, &process_name) {
                            (Some(p), Some(n)) => format!("{n} (PID {p})"),
                            (Some(p), None) => format!("PID {p}"),
                            _ => "unknown".to_string(),
                        };
                        format!("{} ({})", "in use".red(), owner.dimmed())
                    }
                };
                (name.as_str(), port, status)
            })
        })
        .collect();

    if rows.is_empty() {
        install_ui::warn("No declared service ports");
        return Ok(());
    }

    let service_width = rows
        .iter()
        .map(|(name, _, _)| name.len())
        .chain(std::iter::once("Service".len()))
        .max()
        .unwrap_or("Service".len());

    println!("{:<service_width$}  Port   Status", "Service");
    for (name, port, status) in &rows {
        println!("{name:<service_width$}  {port:<5}  {status}");
    }
    println!();
    install_ui::done(&format!(
        "{} declared service {}",
        rows.len(),
        if rows.len() == 1 { "port" } else { "ports" }
    ));
    Ok(())
}

fn run_kill(port: u16, json_output: bool) -> Result<(), LpmError> {
    match ports::check_port(port) {
        ports::PortStatus::Free => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({ "success": true, "port": port, "status": "already_free" })
                );
            } else {
                install_ui::done(&format!("Port {port} is not in use"));
            }
        }
        ports::PortStatus::InUse { pid, process_name } => {
            let owner = match (&pid, &process_name) {
                (Some(p), Some(n)) => format!("{n} (PID {p})"),
                (Some(p), None) => format!("PID {p}"),
                _ => "unknown".to_string(),
            };

            ports::kill_port_owner(port).map_err(LpmError::Script)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({ "success": true, "port": port, "killed": owner })
                );
            } else {
                install_ui::done(&format!("Killed {owner} on port {port}"));
            }
        }
    }
    Ok(())
}

fn run_reset(project_dir: &Path, json_output: bool) {
    ports::clear_port_overrides(project_dir);

    if json_output {
        println!("{}", serde_json::json!({ "success": true, "reset": true }));
    } else {
        install_ui::done("Port overrides cleared for this project");
    }
}
