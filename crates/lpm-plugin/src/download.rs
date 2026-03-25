//! Download plugin binaries from GitHub Releases.

use crate::registry::{self, PluginDef};
use crate::store;
use lpm_common::LpmError;
use lpm_runtime::platform::Platform;

/// Download and install a plugin binary.
pub async fn download_plugin(
	def: &PluginDef,
	version: &str,
	platform: &Platform,
) -> Result<(), LpmError> {
	let platform_str = platform.to_string();
	let asset_name = registry::resolve_platform_asset(def, &platform_str)
		.ok_or_else(|| {
			LpmError::Script(format!(
				"plugin '{}' has no binary for platform {}",
				def.name, platform_str
			))
		})?;

	let url = def
		.url_template
		.replace("{version}", version)
		.replace("{platform}", asset_name);

	tracing::debug!("downloading plugin {}@{} from {}", def.name, version, url);

	let client = reqwest::Client::builder()
		.timeout(std::time::Duration::from_secs(120))
		.build()
		.map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

	let resp = client
		.get(&url)
		.header("User-Agent", "lpm-cli")
		.send()
		.await
		.map_err(|e| LpmError::Network(format!("failed to download {}: {e}", def.name)))?;

	if !resp.status().is_success() {
		return Err(LpmError::Http {
			status: resp.status().as_u16(),
			message: format!("failed to download {} from {}", def.name, url),
		});
	}

	let bytes = resp
		.bytes()
		.await
		.map_err(|e| LpmError::Network(format!("failed to read {}: {e}", def.name)))?;

	// Save to plugin directory
	let version_dir = store::plugin_version_dir(def.name, version)?;
	std::fs::create_dir_all(&version_dir)?;

	let bin_path = version_dir.join(def.binary_name);

	if def.is_archive {
		// Extract from .tar.gz — binary is at the root of the archive
		extract_binary_from_archive(&bytes, &bin_path, def.binary_name)?;
	} else {
		// Direct binary download
		std::fs::write(&bin_path, &bytes)?;
	}

	// Make executable on Unix
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755))?;
	}

	tracing::debug!(
		"installed plugin {}@{} to {} ({} bytes)",
		def.name,
		version,
		bin_path.display(),
		bytes.len()
	);

	Ok(())
}

/// Extract a specific binary from a .tar.gz archive.
fn extract_binary_from_archive(
	data: &[u8],
	dest_path: &std::path::Path,
	binary_name: &str,
) -> Result<(), LpmError> {
	let decoder = flate2::read::GzDecoder::new(data)
		.map_err(|e| LpmError::Script(format!("failed to decompress plugin archive: {e}")))?;
	let mut archive = tar::Archive::new(decoder);

	for entry in archive.entries().map_err(|e| {
		LpmError::Script(format!("failed to read plugin archive: {e}"))
	})? {
		let mut entry = entry.map_err(|e| {
			LpmError::Script(format!("failed to read archive entry: {e}"))
		})?;

		let path = entry.path().map_err(|e| {
			LpmError::Script(format!("failed to read entry path: {e}"))
		})?;

		// The binary may have a platform suffix (e.g., "oxlint-aarch64-apple-darwin")
		// Match if the filename starts with the binary name
		let file_name = path
			.file_name()
			.map(|n| n.to_string_lossy().to_string())
			.unwrap_or_default();

		if file_name == binary_name || file_name.starts_with(&format!("{binary_name}-")) {
			let mut output = std::fs::File::create(dest_path)?;
			std::io::copy(&mut entry, &mut output).map_err(|e| {
				LpmError::Script(format!("failed to extract {binary_name}: {e}"))
			})?;
			return Ok(());
		}
	}

	Err(LpmError::Script(format!(
		"binary '{binary_name}' not found in archive"
	)))
}
