//! LPM certificate management for local HTTPS development.
//!
//! Provides zero-config HTTPS for local development by:
//! 1. Generating a root CA (one-time, stored in `~/.lpm/certs/`)
//! 2. Installing it in the system trust store
//! 3. Generating per-project certificates signed by that CA
//! 4. Detecting the dev framework and injecting the right env vars

pub mod ca;
pub mod cert;
pub mod framework;
pub mod paths;
pub mod trust;

use lpm_common::LpmError;
use std::path::Path;

/// Result of setting up HTTPS for a project.
#[derive(Debug)]
pub struct HttpsSetup {
	/// Path to the project certificate PEM file.
	pub cert_path: String,
	/// Path to the project private key PEM file.
	pub key_path: String,
	/// Environment variables to inject into the dev server process.
	pub env_vars: Vec<(String, String)>,
	/// Whether the CA was freshly installed (first time).
	pub ca_freshly_installed: bool,
	/// Whether the project cert was freshly generated.
	pub cert_freshly_generated: bool,
}

/// Certificate status information.
#[derive(Debug)]
pub struct CertStatus {
	/// Whether the root CA exists on disk.
	pub ca_exists: bool,
	/// Whether the root CA is installed in the system trust store.
	pub ca_trusted: bool,
	/// CA certificate expiry date (if exists).
	pub ca_expires: Option<String>,
	/// CA certificate subject CN.
	pub ca_subject: Option<String>,
	/// Whether a project certificate exists.
	pub project_cert_exists: bool,
	/// Project certificate expiry date (if exists).
	pub project_cert_expires: Option<String>,
	/// Hostnames in the project certificate SAN.
	pub project_cert_hostnames: Vec<String>,
	/// Whether the project cert needs renewal (within 30 days of expiry).
	pub project_cert_needs_renewal: bool,
}

/// One-call setup: ensures CA exists and is trusted, generates project cert if needed,
/// returns paths and env vars ready for the dev server.
pub fn ensure_https(
	project_dir: &Path,
	extra_hostnames: &[String],
) -> Result<HttpsSetup, LpmError> {
	let ca_dir = paths::ca_dir()?;
	let project_cert_dir = paths::project_cert_dir(project_dir)?;

	// Step 1: Ensure root CA exists
	let ca_freshly_installed = if !paths::ca_cert_path()?.exists() {
		tracing::info!("generating root CA...");
		let (ca_cert_pem, ca_key_pem) = ca::generate_ca()
			.map_err(|e| LpmError::Cert(format!("failed to generate CA: {e}")))?;

		std::fs::create_dir_all(&ca_dir)
			.map_err(|e| LpmError::Cert(format!("failed to create cert dir: {e}")))?;

		let cert_path = paths::ca_cert_path()?;
		let key_path = paths::ca_key_path()?;

		std::fs::write(&cert_path, &ca_cert_pem)
			.map_err(|e| LpmError::Cert(format!("failed to write CA cert: {e}")))?;
		std::fs::write(&key_path, &ca_key_pem)
			.map_err(|e| LpmError::Cert(format!("failed to write CA key: {e}")))?;

		// Set key file permissions to 0o600 on Unix
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
				.map_err(|e| LpmError::Cert(format!("failed to set key permissions: {e}")))?;
		}

		// Install CA into trust store
		tracing::info!("installing CA into system trust store...");
		trust::install_ca(&cert_path)
			.map_err(|e| LpmError::Cert(format!("failed to install CA: {e}")))?;

		true
	} else {
		// Check if CA is trusted
		let cert_path = paths::ca_cert_path()?;
		if !trust::is_ca_installed(&cert_path)? {
			tracing::info!("CA exists but not trusted, installing...");
			trust::install_ca(&cert_path)
				.map_err(|e| LpmError::Cert(format!("failed to install CA: {e}")))?;
		}
		false
	};

	// Step 2: Ensure project certificate exists and is valid
	let proj_cert_path = project_cert_dir.join("cert.pem");
	let proj_key_path = project_cert_dir.join("key.pem");

	let cert_freshly_generated = if !proj_cert_path.exists() || cert::needs_renewal(&proj_cert_path)? {
		tracing::info!("generating project certificate...");
		std::fs::create_dir_all(&project_cert_dir)
			.map_err(|e| LpmError::Cert(format!("failed to create project cert dir: {e}")))?;

		let ca_cert_pem = std::fs::read_to_string(paths::ca_cert_path()?)
			.map_err(|e| LpmError::Cert(format!("failed to read CA cert: {e}")))?;
		let ca_key_pem = std::fs::read_to_string(paths::ca_key_path()?)
			.map_err(|e| LpmError::Cert(format!("failed to read CA key: {e}")))?;

		let (cert_pem, key_pem) = cert::generate_project_cert(&ca_cert_pem, &ca_key_pem, extra_hostnames)
			.map_err(|e| LpmError::Cert(format!("failed to generate project cert: {e}")))?;

		std::fs::write(&proj_cert_path, &cert_pem)
			.map_err(|e| LpmError::Cert(format!("failed to write project cert: {e}")))?;
		std::fs::write(&proj_key_path, &key_pem)
			.map_err(|e| LpmError::Cert(format!("failed to write project key: {e}")))?;

		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&proj_key_path, std::fs::Permissions::from_mode(0o600))
				.map_err(|e| LpmError::Cert(format!("failed to set key permissions: {e}")))?;
		}

		true
	} else {
		false
	};

	// Step 3: Build env vars for the dev server
	let ca_cert_path_str = paths::ca_cert_path()?.to_string_lossy().to_string();
	let proj_cert_str = proj_cert_path.to_string_lossy().to_string();
	let proj_key_str = proj_key_path.to_string_lossy().to_string();

	let mut env_vars = vec![
		("NODE_EXTRA_CA_CERTS".to_string(), ca_cert_path_str),
		("SSL_CERT_FILE".to_string(), proj_cert_str.clone()),
		("SSL_KEY_FILE".to_string(), proj_key_str.clone()),
	];

	// Add framework-specific env vars
	let framework_env = framework::detect_and_get_env(project_dir, &proj_cert_str, &proj_key_str);
	env_vars.extend(framework_env);

	Ok(HttpsSetup {
		cert_path: proj_cert_str,
		key_path: proj_key_str,
		env_vars,
		ca_freshly_installed,
		cert_freshly_generated,
	})
}

/// Get the current certificate status for display.
pub fn status(project_dir: &Path) -> Result<CertStatus, LpmError> {
	let ca_cert_path = paths::ca_cert_path()?;
	let ca_exists = ca_cert_path.exists();

	let (ca_trusted, ca_expires, ca_subject) = if ca_exists {
		let trusted = trust::is_ca_installed(&ca_cert_path).unwrap_or(false);
		let info = cert::read_cert_info(&ca_cert_path).ok();
		(
			trusted,
			info.as_ref().map(|i| i.not_after.clone()),
			info.as_ref().map(|i| i.subject.clone()),
		)
	} else {
		(false, None, None)
	};

	let project_cert_dir = paths::project_cert_dir(project_dir)?;
	let proj_cert_path = project_cert_dir.join("cert.pem");
	let project_cert_exists = proj_cert_path.exists();

	let (project_cert_expires, project_cert_hostnames, project_cert_needs_renewal) = if project_cert_exists {
		let info = cert::read_cert_info(&proj_cert_path).ok();
		let needs_renewal = cert::needs_renewal(&proj_cert_path).unwrap_or(true);
		(
			info.as_ref().map(|i| i.not_after.clone()),
			info.as_ref().map(|i| i.san_entries.clone()).unwrap_or_default(),
			needs_renewal,
		)
	} else {
		(None, vec![], false)
	};

	Ok(CertStatus {
		ca_exists,
		ca_trusted,
		ca_expires,
		ca_subject,
		project_cert_exists,
		project_cert_expires,
		project_cert_hostnames,
		project_cert_needs_renewal,
	})
}
