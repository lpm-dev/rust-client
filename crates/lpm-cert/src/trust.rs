//! System trust store management.
//!
//! Installs/removes the LPM root CA from the OS trust store so browsers
//! and Node.js trust certificates signed by it.

use lpm_common::LpmError;
use std::path::Path;
use std::process::Command;

const CA_COMMON_NAME: &str = "LPM Local Development CA";

/// Install the CA certificate into the system trust store.
///
/// Platform behavior:
/// - macOS: adds to user login keychain (no sudo needed)
/// - Linux: copies to ca-certificates dir + runs update-ca-certificates (needs sudo)
/// - Windows: uses certutil to add to Root store (UAC prompt)
pub fn install_ca(ca_cert_path: &Path) -> Result<(), LpmError> {
	let path_str = ca_cert_path.to_string_lossy();

	#[cfg(target_os = "macos")]
	{
		install_ca_macos(&path_str)
	}

	#[cfg(target_os = "linux")]
	{
		install_ca_linux(&path_str)
	}

	#[cfg(target_os = "windows")]
	{
		install_ca_windows(&path_str)
	}

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	{
		Err(LpmError::Cert(format!(
			"automatic trust store installation is not supported on this platform. \
			 Manually add {} to your system's trusted certificates.",
			path_str
		)))
	}
}

/// Check if the LPM CA is currently installed in the system trust store.
pub fn is_ca_installed(_ca_cert_path: &Path) -> Result<bool, LpmError> {
	#[cfg(target_os = "macos")]
	{
		is_ca_installed_macos()
	}

	#[cfg(target_os = "linux")]
	{
		is_ca_installed_linux()
	}

	#[cfg(target_os = "windows")]
	{
		is_ca_installed_windows()
	}

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	{
		// Can't check on unsupported platforms
		Ok(false)
	}
}

/// Remove the LPM CA from the system trust store.
pub fn uninstall_ca() -> Result<(), LpmError> {
	#[cfg(target_os = "macos")]
	{
		uninstall_ca_macos()
	}

	#[cfg(target_os = "linux")]
	{
		uninstall_ca_linux()
	}

	#[cfg(target_os = "windows")]
	{
		uninstall_ca_windows()
	}

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	{
		Err(LpmError::Cert(
			"automatic trust store removal is not supported on this platform".into(),
		))
	}
}

// ── macOS ──────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn install_ca_macos(cert_path: &str) -> Result<(), LpmError> {
	tracing::debug!("installing CA to macOS login keychain: {cert_path}");

	let mut cmd = Command::new("security");
	cmd.args([
		"add-trusted-cert",
		"-r", "trustRoot",
		"-k",
	])
	.arg(login_keychain_path()?)
	.arg(cert_path);

	let output = cmd.output()
		.map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		// "already exists" is not an error
		if stderr.contains("already exists") || stderr.contains("duplicate") {
			tracing::debug!("CA already in keychain");
			return Ok(());
		}
		return Err(LpmError::Cert(format!(
			"failed to install CA to keychain: {stderr}"
		)));
	}

	tracing::info!("CA installed to macOS login keychain");
	Ok(())
}

#[cfg(target_os = "macos")]
fn is_ca_installed_macos() -> Result<bool, LpmError> {
	let output = Command::new("security")
		.args(["find-certificate", "-c", CA_COMMON_NAME])
		.arg(login_keychain_path()?)
		.output()
		.map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

	Ok(output.status.success())
}

#[cfg(target_os = "macos")]
fn uninstall_ca_macos() -> Result<(), LpmError> {
	let output = Command::new("security")
		.args(["delete-certificate", "-c", CA_COMMON_NAME])
		.arg(login_keychain_path()?)
		.output()
		.map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		if stderr.contains("could not be found") {
			return Ok(()); // Already removed
		}
		return Err(LpmError::Cert(format!(
			"failed to remove CA from keychain: {stderr}"
		)));
	}

	tracing::info!("CA removed from macOS login keychain");
	Ok(())
}

#[cfg(target_os = "macos")]
fn login_keychain_path() -> Result<String, LpmError> {
	let home = dirs::home_dir()
		.ok_or_else(|| LpmError::Cert("could not determine home directory".into()))?;
	let keychain = home.join("Library/Keychains/login.keychain-db");

	// Fall back to login.keychain if -db variant doesn't exist
	if keychain.exists() {
		Ok(keychain.to_string_lossy().to_string())
	} else {
		let alt = home.join("Library/Keychains/login.keychain");
		Ok(alt.to_string_lossy().to_string())
	}
}

// ── Linux ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn install_ca_linux(cert_path: &str) -> Result<(), LpmError> {
	let dest = Path::new("/usr/local/share/ca-certificates/lpm-local-ca.crt");

	tracing::debug!("installing CA to {}", dest.display());

	// Copy cert (needs sudo)
	let output = Command::new("sudo")
		.args(["cp", cert_path, &dest.to_string_lossy()])
		.output()
		.map_err(|e| LpmError::Cert(format!(
			"failed to copy CA cert (sudo required): {e}"
		)))?;

	if !output.status.success() {
		return Err(LpmError::Cert(format!(
			"failed to copy CA cert: {}",
			String::from_utf8_lossy(&output.stderr)
		)));
	}

	// Update ca-certificates
	let output = Command::new("sudo")
		.args(["update-ca-certificates"])
		.output()
		.map_err(|e| LpmError::Cert(format!(
			"failed to run update-ca-certificates: {e}. Install with: sudo apt install ca-certificates"
		)))?;

	if !output.status.success() {
		return Err(LpmError::Cert(format!(
			"update-ca-certificates failed: {}",
			String::from_utf8_lossy(&output.stderr)
		)));
	}

	tracing::info!("CA installed to Linux trust store");
	Ok(())
}

#[cfg(target_os = "linux")]
fn is_ca_installed_linux() -> Result<bool, LpmError> {
	let dest = Path::new("/usr/local/share/ca-certificates/lpm-local-ca.crt");
	Ok(dest.exists())
}

#[cfg(target_os = "linux")]
fn uninstall_ca_linux() -> Result<(), LpmError> {
	let dest = "/usr/local/share/ca-certificates/lpm-local-ca.crt";

	let output = Command::new("sudo")
		.args(["rm", "-f", dest])
		.output()
		.map_err(|e| LpmError::Cert(format!("failed to remove CA cert: {e}")))?;

	if !output.status.success() {
		return Err(LpmError::Cert(format!(
			"failed to remove CA cert: {}",
			String::from_utf8_lossy(&output.stderr)
		)));
	}

	let _ = Command::new("sudo")
		.args(["update-ca-certificates", "--fresh"])
		.output();

	tracing::info!("CA removed from Linux trust store");
	Ok(())
}

// ── Windows ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn install_ca_windows(cert_path: &str) -> Result<(), LpmError> {
	tracing::debug!("installing CA to Windows Root store: {cert_path}");

	let output = Command::new("certutil")
		.args(["-addstore", "Root", cert_path])
		.output()
		.map_err(|e| LpmError::Cert(format!("failed to run certutil: {e}")))?;

	if !output.status.success() {
		return Err(LpmError::Cert(format!(
			"certutil failed: {}",
			String::from_utf8_lossy(&output.stderr)
		)));
	}

	tracing::info!("CA installed to Windows Root store");
	Ok(())
}

#[cfg(target_os = "windows")]
fn is_ca_installed_windows() -> Result<bool, LpmError> {
	let output = Command::new("certutil")
		.args(["-store", "Root", CA_COMMON_NAME])
		.output()
		.map_err(|e| LpmError::Cert(format!("failed to run certutil: {e}")))?;

	Ok(output.status.success())
}

#[cfg(target_os = "windows")]
fn uninstall_ca_windows() -> Result<(), LpmError> {
	let output = Command::new("certutil")
		.args(["-delstore", "Root", CA_COMMON_NAME])
		.output()
		.map_err(|e| LpmError::Cert(format!("failed to run certutil: {e}")))?;

	if !output.status.success() {
		return Err(LpmError::Cert(format!(
			"certutil failed: {}",
			String::from_utf8_lossy(&output.stderr)
		)));
	}

	tracing::info!("CA removed from Windows Root store");
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	#[cfg(target_os = "macos")]
	fn login_keychain_path_resolves() {
		let path = login_keychain_path().unwrap();
		assert!(path.contains("Keychains/login.keychain"));
	}
}
