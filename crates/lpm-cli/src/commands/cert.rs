use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Run the `lpm cert` subcommand.
pub async fn run(
	action: &str,
	project_dir: &Path,
	extra_hosts: &[String],
	json_output: bool,
) -> Result<(), LpmError> {
	match action {
		"status" => run_status(project_dir, json_output),
		"trust" => run_trust(json_output),
		"uninstall" => run_uninstall(json_output),
		"generate" => run_generate(project_dir, extra_hosts, json_output),
		_ => Err(LpmError::Cert(format!(
			"unknown action '{action}'. Available: status, trust, uninstall, generate"
		))),
	}
}

fn run_status(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
	let status = lpm_cert::status(project_dir)?;

	if json_output {
		println!(
			"{}",
			serde_json::json!({
				"success": true,
				"ca": {
					"exists": status.ca_exists,
					"trusted": status.ca_trusted,
					"expires": status.ca_expires,
					"subject": status.ca_subject,
				},
				"project": {
					"exists": status.project_cert_exists,
					"expires": status.project_cert_expires,
					"hostnames": status.project_cert_hostnames,
					"needs_renewal": status.project_cert_needs_renewal,
				}
			})
		);
		return Ok(());
	}

	output::header("Root CA");
	if status.ca_exists {
		let trusted_str = if status.ca_trusted {
			"trusted".green().to_string()
		} else {
			"not trusted".red().to_string()
		};
		output::field("status", &format!("installed ({})", trusted_str));

		if let Some(subject) = &status.ca_subject {
			output::field("subject", subject);
		}
		if let Some(expires) = &status.ca_expires {
			output::field("expires", expires);
		}
	} else {
		output::field("status", &"not installed".red().to_string());
		println!("  {}", "Run `lpm cert trust` to generate and install the CA".dimmed());
	}

	output::header("Project Certificate");
	if status.project_cert_exists {
		if status.project_cert_needs_renewal {
			output::field("status", &"needs renewal".yellow().to_string());
		} else {
			output::field("status", &"valid".green().to_string());
		}
		if let Some(expires) = &status.project_cert_expires {
			output::field("expires", expires);
		}
		if !status.project_cert_hostnames.is_empty() {
			output::field("hostnames", &status.project_cert_hostnames.join(", "));
		}
	} else {
		output::field("status", &"not generated".dimmed().to_string());
		println!("  {}", "Run `lpm dev --https` or `lpm cert generate` to create".dimmed());
	}

	Ok(())
}

fn run_trust(json_output: bool) -> Result<(), LpmError> {
	let ca_cert_path = lpm_cert::paths::ca_cert_path()?;

	if !ca_cert_path.exists() {
		// Generate CA first
		let ca_dir = lpm_cert::paths::ca_dir()?;
		std::fs::create_dir_all(&ca_dir)
			.map_err(|e| LpmError::Cert(format!("failed to create cert dir: {e}")))?;

		let (ca_cert_pem, ca_key_pem) = lpm_cert::ca::generate_ca()
			.map_err(|e| LpmError::Cert(format!("failed to generate CA: {e}")))?;

		std::fs::write(&ca_cert_path, &ca_cert_pem)
			.map_err(|e| LpmError::Cert(format!("failed to write CA cert: {e}")))?;

		let key_path = lpm_cert::paths::ca_key_path()?;
		// Atomic write with restricted permissions to avoid TOCTOU race
		// where the file is briefly world-readable between write and chmod.
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			use std::io::Write;
			let mut f = std::fs::OpenOptions::new()
				.write(true)
				.create(true)
				.truncate(true)
				.mode(0o600)
				.open(&key_path)
				.map_err(|e| LpmError::Cert(format!("failed to write CA key: {e}")))?;
			f.write_all(ca_key_pem.as_bytes())
				.map_err(|e| LpmError::Cert(format!("failed to write CA key: {e}")))?;
		}
		#[cfg(not(unix))]
		{
			std::fs::write(&key_path, &ca_key_pem)
				.map_err(|e| LpmError::Cert(format!("failed to write CA key: {e}")))?;
		}

		if !json_output {
			output::success("root CA generated");
		}
	}

	// Install to trust store
	lpm_cert::trust::install_ca(&ca_cert_path)?;

	if json_output {
		println!("{}", serde_json::json!({ "success": true, "ca_installed": true }));
	} else {
		output::success("CA installed to system trust store");
		let info = lpm_cert::cert::read_cert_info(&ca_cert_path)?;
		output::field("subject", &info.subject);
		output::field("expires", &info.not_after);
		output::field("path", &ca_cert_path.to_string_lossy());
	}

	Ok(())
}

fn run_uninstall(json_output: bool) -> Result<(), LpmError> {
	lpm_cert::trust::uninstall_ca()?;

	if json_output {
		println!("{}", serde_json::json!({ "success": true, "ca_uninstalled": true }));
	} else {
		output::success("CA removed from system trust store");
	}

	Ok(())
}

fn run_generate(
	project_dir: &Path,
	extra_hosts: &[String],
	json_output: bool,
) -> Result<(), LpmError> {
	let setup = lpm_cert::ensure_https(project_dir, extra_hosts)?;

	if json_output {
		println!(
			"{}",
			serde_json::json!({
				"success": true,
				"cert_path": setup.cert_path,
				"key_path": setup.key_path,
				"ca_freshly_installed": setup.ca_freshly_installed,
				"cert_freshly_generated": setup.cert_freshly_generated,
			})
		);
	} else {
		if setup.ca_freshly_installed {
			output::success("root CA generated and installed to trust store");
		}
		if setup.cert_freshly_generated {
			output::success("project certificate generated");
		} else {
			output::info("project certificate already exists and is valid");
		}
		output::field("cert", &setup.cert_path);
		output::field("key", &setup.key_path);
	}

	Ok(())
}
