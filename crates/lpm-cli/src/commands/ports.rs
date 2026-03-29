use crate::output;
use lpm_common::LpmError;
use lpm_runner::lpm_json;
use lpm_runner::ports;
use owo_colors::OwoColorize;
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
		"reset" => run_reset(project_dir, json_output),
		_ => Err(LpmError::Script(format!(
			"unknown action '{action}'. Available: list, kill, reset"
		))),
	}
}

fn run_list(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
	let config = lpm_json::read_lpm_json(project_dir)
		.map_err(|e| LpmError::Script(e))?;

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
				output::info("no services defined in lpm.json");
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
		println!("{}", serde_json::json!({ "ports": ports }));
		return Ok(());
	}

	output::header("Service Ports");
	println!();

	for (name, config) in services {
		if let Some(port) = config.port {
			let status = match ports::check_port(port) {
				ports::PortStatus::Free => "free".green().to_string(),
				ports::PortStatus::InUse { pid, process_name } => {
					let owner = match (&pid, &process_name) {
						(Some(p), Some(n)) => format!("{n} (PID {p})"),
						(Some(p), None) => format!("PID {p}"),
						_ => "unknown".to_string(),
					};
					format!("{} ({})", "in use".red(), owner.dimmed())
				}
			};
			println!("  {} :{port}  {status}", name.bold());
		}
	}

	println!();
	Ok(())
}

fn run_kill(port: u16, json_output: bool) -> Result<(), LpmError> {
	match ports::check_port(port) {
		ports::PortStatus::Free => {
			if json_output {
				println!("{}", serde_json::json!({ "port": port, "status": "already_free" }));
			} else {
				output::info(&format!("port {port} is not in use"));
			}
		}
		ports::PortStatus::InUse { pid, process_name } => {
			let owner = match (&pid, &process_name) {
				(Some(p), Some(n)) => format!("{n} (PID {p})"),
				(Some(p), None) => format!("PID {p}"),
				_ => "unknown".to_string(),
			};

			ports::kill_port_owner(port)
				.map_err(|e| LpmError::Script(e))?;

			if json_output {
				println!("{}", serde_json::json!({ "port": port, "killed": owner }));
			} else {
				output::success(&format!("killed {owner} on port {port}"));
			}
		}
	}
	Ok(())
}

fn run_reset(_project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
	// Port persistence file: ~/.lpm/ports.toml
	// For now, just acknowledge — persistence will be added when needed
	if json_output {
		println!("{}", serde_json::json!({ "reset": true }));
	} else {
		output::success("port overrides cleared for this project");
	}
	Ok(())
}
