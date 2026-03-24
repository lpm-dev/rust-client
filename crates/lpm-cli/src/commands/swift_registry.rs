use crate::{auth, output};
use lpm_common::LpmError;
use owo_colors::OwoColorize;

/// Configure Swift Package Manager to use LPM as a package registry.
///
/// Steps:
/// 1. swift package-registry set --scope lpmdev <registry_url>/api/swift-registry
/// 2. swift package-registry login --token <lpm_token> (HTTPS only)
/// 3. Download signing certificate to ~/.swiftpm/security/trusted-root-certs/lpm.der
pub async fn run(registry_url: &str, json_output: bool) -> Result<(), LpmError> {
	let swift_registry_url = format!("{registry_url}/api/swift-registry");
	let is_https = registry_url.starts_with("https://");

	if !json_output {
		output::info(&format!(
			"Configuring SPM to use LPM registry at {}",
			swift_registry_url.bold()
		));
	}

	// Step 1: Set the registry for the lpmdev scope
	let mut args = vec![
		"package-registry".to_string(),
		"set".to_string(),
		"--scope".to_string(),
		"lpmdev".to_string(),
	];

	if !is_https {
		args.push("--allow-insecure-http".to_string());
	}

	args.push(swift_registry_url.clone());

	let status = std::process::Command::new("swift")
		.args(&args)
		.stdout(std::process::Stdio::inherit())
		.stderr(std::process::Stdio::inherit())
		.status()
		.map_err(|e| {
			LpmError::Registry(format!(
				"failed to run swift command: {e}. Is Swift installed?"
			))
		})?;

	if !status.success() {
		return Err(LpmError::Registry(
			"swift package-registry set failed".into(),
		));
	}

	// Step 2: Login with LPM token (HTTPS only — SPM refuses auth over HTTP)
	if is_https {
		if let Some(token) = auth::get_token(registry_url) {
			if !json_output {
				output::info("Configuring authentication...");
			}

			let login_status = std::process::Command::new("swift")
				.args([
					"package-registry",
					"login",
					&swift_registry_url,
					"--token",
					&token,
					"--no-confirm",
				])
				.stdout(std::process::Stdio::inherit())
				.stderr(std::process::Stdio::inherit())
				.status()
				.map_err(|e| LpmError::Registry(format!("swift login failed: {e}")))?;

			if !login_status.success() {
				output::warn(
					"Token login failed — you may need to run: swift package-registry login manually",
				);
			}
		} else if !json_output {
			output::warn("No LPM token found — run `lpm-rs login` first for authenticated access");
		}
	} else if !json_output {
		output::warn("HTTP registry — SPM won't send auth. Use HTTPS in production.");
	}

	// Step 3: Install signing certificate to SPM trust store
	let cert_installed = install_signing_certificate(&swift_registry_url, json_output).await;

	if json_output {
		let json = serde_json::json!({
			"registry_url": swift_registry_url,
			"scope": "lpmdev",
			"https": is_https,
			"signing_certificate_installed": cert_installed,
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		println!();
		output::success("SPM configured to use LPM registry");
		if cert_installed {
			println!(
				"  {} Package signatures will be verified automatically.",
				"✔".green()
			);
		}
		println!();
		println!("  Use in Package.swift:");
		println!(
			"    {}",
			".package(id: \"lpmdev.<owner>-<package>\", from: \"1.0.0\")"
				.dimmed()
		);
		println!();
		println!(
			"  Identity mapping: {} → {}",
			"@lpm.dev/owner.pkg".dimmed(),
			"lpmdev.owner-pkg".bold()
		);
		println!();
	}

	Ok(())
}

/// Download the LPM signing certificate and install to SPM's trust store.
/// Returns true if certificate was installed successfully.
async fn install_signing_certificate(swift_registry_url: &str, json_output: bool) -> bool {
	let cert_url = format!("{swift_registry_url}/certificate");
	let trust_dir = dirs::home_dir()
		.map(|h| h.join(".swiftpm/security/trusted-root-certs"));

	let Some(trust_dir) = trust_dir else {
		if !json_output {
			output::warn("Could not determine home directory for certificate installation");
		}
		return false;
	};

	let cert_path = trust_dir.join("lpm.der");

	// Skip if already installed
	if cert_path.exists() {
		if !json_output {
			output::info("Signing certificate already installed");
		}
		return true;
	}

	if !json_output {
		output::info("Installing package signing certificate...");
	}

	// Download certificate
	let client = reqwest::Client::new();
	let response = match client.get(&cert_url).send().await {
		Ok(r) => r,
		Err(e) => {
			if !json_output {
				output::warn(&format!("Could not download signing certificate: {e}"));
			}
			return false;
		}
	};

	if !response.status().is_success() {
		if !json_output {
			output::warn(&format!(
				"Signing certificate not available (HTTP {})",
				response.status()
			));
		}
		return false;
	}

	let cert_bytes = match response.bytes().await {
		Ok(b) => b,
		Err(e) => {
			if !json_output {
				output::warn(&format!("Failed to read certificate: {e}"));
			}
			return false;
		}
	};

	// Create trust directory if needed
	if let Err(e) = std::fs::create_dir_all(&trust_dir) {
		if !json_output {
			output::warn(&format!("Failed to create trust directory: {e}"));
		}
		return false;
	}

	// Write certificate
	if let Err(e) = std::fs::write(&cert_path, &cert_bytes) {
		if !json_output {
			output::warn(&format!("Failed to write certificate: {e}"));
		}
		return false;
	}

	if !json_output {
		output::info(&format!(
			"Signing certificate installed to {}",
			cert_path.display().to_string().dimmed()
		));
	}

	true
}
