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
//!   index-cache.json   <- cached Node.js release index (1h TTL)
//! ```

pub mod detect;
pub mod download;
pub mod node;
pub mod platform;

/// Result of ensuring a runtime is available before script execution.
///
/// `Ready` and `Installed` carry the resolved managed-runtime `bin_dir` so the
/// PATH builder doesn't have to re-run `detect_node_version` + `list_installed`
/// on every `lpm run` invocation. See `lpm_runner::bin_path::ManagedRuntimeHint`.
#[derive(Debug, Clone)]
pub enum RuntimeStatus {
    /// A managed runtime version is installed and ready to use.
    Ready {
        version: String,
        source: String,
        bin_dir: std::path::PathBuf,
    },
    /// The required version was not installed and has been auto-installed.
    Installed {
        version: String,
        source: String,
        bin_dir: std::path::PathBuf,
    },
    /// The required version is not installed and auto-install is disabled.
    NotInstalled { spec: String, source: String },
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
pub async fn ensure_runtime(project_dir: &std::path::Path) -> RuntimeStatus {
    let detected = match detect::detect_node_version(project_dir) {
        Some(d) => d,
        None => return RuntimeStatus::NoRequirement,
    };

    let source = detected.source.to_string();
    let spec = &detected.spec;

    // Validate the version spec before processing (Finding #5)
    if let Err(e) = node::validate_version_spec(spec) {
        tracing::warn!("invalid version spec from {source}: {e}");
        return RuntimeStatus::NotInstalled {
            spec: spec.to_string(),
            source,
        };
    }

    // Strip range operators for lookup
    let clean_spec = spec
        .trim_start_matches(">=")
        .trim_start_matches("^")
        .trim_start_matches("~")
        .trim_start_matches('>');

    // Check if already installed
    if let Ok(installed) = node::list_installed()
        && let Some(version) = node::find_matching_installed(spec, &installed)
        && let Ok(bin_dir) = node::node_bin_dir(&version)
        && bin_dir.exists()
    {
        return RuntimeStatus::Ready {
            version,
            source,
            bin_dir,
        };
    }

    // Not installed -- check if auto-install is disabled
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
        Err(e) => {
            // Finding #13: Log error details instead of swallowing
            tracing::warn!("failed to create HTTP client for runtime install: {e}");
            return RuntimeStatus::NotInstalled {
                spec: clean_spec.to_string(),
                source,
            };
        }
    };

    let platform = match platform::Platform::current() {
        Ok(p) => p,
        Err(e) => {
            // Finding #13: Log error details instead of swallowing
            tracing::warn!("unsupported platform for runtime install: {e}");
            return RuntimeStatus::NotInstalled {
                spec: clean_spec.to_string(),
                source,
            };
        }
    };

    let releases = match node::fetch_index(&http_client).await {
        Ok(r) => r,
        Err(e) => {
            // Finding #13: Log error details instead of swallowing
            tracing::warn!("failed to fetch node.js release index: {e}");
            return RuntimeStatus::NotInstalled {
                spec: clean_spec.to_string(),
                source,
            };
        }
    };

    let release = match node::resolve_version(&releases, clean_spec) {
        Some(r) => r,
        None => {
            tracing::warn!("no node.js release found matching spec '{clean_spec}'");
            return RuntimeStatus::NotInstalled {
                spec: clean_spec.to_string(),
                source,
            };
        }
    };

    match download::install_node(&http_client, &release, &platform).await {
        Ok(version) => match node::node_bin_dir(&version) {
            Ok(bin_dir) if bin_dir.exists() => RuntimeStatus::Installed {
                version,
                source,
                bin_dir,
            },
            // Should not happen — we just installed it — but degrade gracefully
            // rather than panic if the bin dir vanished mid-call.
            _ => RuntimeStatus::NotInstalled {
                spec: clean_spec.to_string(),
                source,
            },
        },
        Err(e) => {
            // Finding #13: Log error details instead of swallowing
            tracing::warn!(
                "failed to auto-install node {}: {e}",
                release.version_bare()
            );
            RuntimeStatus::NotInstalled {
                spec: clean_spec.to_string(),
                source,
            }
        }
    }
}
