//! Runtime version management for LPM.
//!
//! Downloads, installs, and manages Node.js versions. Integrates with
//! the runner to auto-switch per project based on `lpm.json`, `package.json`
//! engines, `.nvmrc`, or `.node-version`.
//!
//! Storage layout:
//! ```text
//! ~/.lpm/runtimes/
//!   node/
//!     22.5.0/
//!       bin/node
//!       bin/npm
//!       bin/npx
//!     20.18.0/
//!       ...
//!   index-cache.json   ← cached Node.js release index (1h TTL)
//! ```

pub mod detect;
pub mod download;
pub mod node;
pub mod platform;

/// Result of ensuring a runtime is available before script execution.
#[derive(Debug, Clone)]
pub enum RuntimeStatus {
	/// A managed runtime version is installed and ready to use.
	Ready {
		version: String,
		source: String,
	},
	/// The required version was not installed and has been auto-installed.
	Installed {
		version: String,
		source: String,
	},
	/// The required version is not installed and auto-install is disabled.
	NotInstalled {
		spec: String,
		source: String,
	},
	/// No version requirement was detected (use system Node).
	NoRequirement,
}

/// Detect the required Node.js version and auto-install if needed.
///
/// This should be called from the CLI layer (which is async) before running scripts.
/// After this returns `Ready` or `Installed`, `bin_path::build_path_with_bins()` will
/// find the installed version and prepend it to PATH.
///
/// Auto-install is enabled by default. Set `LPM_NO_AUTO_INSTALL=true` to disable.
pub async fn ensure_runtime(
	project_dir: &std::path::Path,
) -> RuntimeStatus {
	let detected = match detect::detect_node_version(project_dir) {
		Some(d) => d,
		None => return RuntimeStatus::NoRequirement,
	};

	let source = detected.source.to_string();
	let spec = &detected.spec;

	// Strip range operators for lookup
	let clean_spec = spec
		.trim_start_matches(">=")
		.trim_start_matches("^")
		.trim_start_matches("~")
		.trim_start_matches('>');

	// Check if already installed
	if let Ok(installed) = node::list_installed() {
		if let Some(version) = node::find_matching_installed(clean_spec, &installed) {
			if let Ok(bin_dir) = node::node_bin_dir(&version) {
				if bin_dir.exists() {
					return RuntimeStatus::Ready {
						version,
						source,
					};
				}
			}
		}
	}

	// Not installed — check if auto-install is disabled
	let no_auto_install = std::env::var("LPM_NO_AUTO_INSTALL")
		.map(|v| v == "true" || v == "1")
		.unwrap_or(false);

	if no_auto_install {
		return RuntimeStatus::NotInstalled {
			spec: clean_spec.to_string(),
			source,
		};
	}

	// Auto-install
	let http_client = match reqwest::Client::builder()
		.timeout(std::time::Duration::from_secs(60))
		.build()
	{
		Ok(c) => c,
		Err(_) => {
			return RuntimeStatus::NotInstalled {
				spec: clean_spec.to_string(),
				source,
			};
		}
	};

	let platform = platform::Platform::current();

	let releases = match node::fetch_index(&http_client).await {
		Ok(r) => r,
		Err(_) => {
			return RuntimeStatus::NotInstalled {
				spec: clean_spec.to_string(),
				source,
			};
		}
	};

	let release = match node::resolve_version(&releases, clean_spec, &platform) {
		Some(r) => r,
		None => {
			return RuntimeStatus::NotInstalled {
				spec: clean_spec.to_string(),
				source,
			};
		}
	};

	match download::install_node(&http_client, &release, &platform).await {
		Ok(version) => RuntimeStatus::Installed { version, source },
		Err(_) => RuntimeStatus::NotInstalled {
			spec: clean_spec.to_string(),
			source,
		},
	}
}
