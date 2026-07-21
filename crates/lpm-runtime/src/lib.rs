//! Runtime version management for LPM.
//!
//! Downloads, installs, and manages Node.js and Bun versions. Integrates with
//! the runner to auto-switch per project based on managed runtime pins.
//!
//! Storage layout:
//! ```text
//! ~/.lpm/runtimes/
//!   node/
//!     22.5.0/
//!       bin/node
//!       bin/npm
//!       bin/npx
//!   bun/
//!     1.3.14/
//!       bin/bun
//!   index-cache.json       <- cached Node.js release index (1h TTL)
//!   bun-index-cache.json   <- cached Bun release index (1h TTL)
//! ```

pub mod bun;
pub mod detect;
pub mod download;
pub mod effective;
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
        runtime: detect::RuntimeKind,
        version: String,
        source: String,
        bin_dir: std::path::PathBuf,
    },
    /// The required version was not installed and has been auto-installed.
    Installed {
        runtime: detect::RuntimeKind,
        version: String,
        source: String,
        bin_dir: std::path::PathBuf,
    },
    /// The required version is not installed and auto-install is disabled.
    NotInstalled {
        runtime: detect::RuntimeKind,
        spec: String,
        source: String,
    },
}

/// Detect required managed runtime versions and auto-install if needed.
///
/// This should be called from the CLI layer (which is async) before running scripts.
/// Each `Ready` or `Installed` result carries a bin dir for PATH injection.
///
/// Auto-install is enabled by default. Set `LPM_NO_AUTO_INSTALL=true` to disable.
pub async fn ensure_runtime(project_dir: &std::path::Path) -> Vec<RuntimeStatus> {
    let detected = detect::detect_runtime_versions(project_dir);
    if detected.is_empty() {
        return Vec::new();
    }

    let mut install_context = RuntimeInstallContext::default();
    let mut statuses = Vec::with_capacity(detected.len());
    for runtime in detected {
        statuses.push(ensure_one_runtime(runtime, &mut install_context).await);
    }
    statuses
}

#[derive(Default)]
struct RuntimeInstallContext {
    http_client: Option<reqwest::Client>,
    http_client_failed: bool,
    platform: Option<platform::Platform>,
    platform_failed: bool,
}

impl RuntimeInstallContext {
    fn http_client(&mut self) -> Option<&reqwest::Client> {
        if self.http_client_failed {
            return None;
        }
        if self.http_client.is_none() {
            match lpm_http::client_builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
            {
                Ok(client) => self.http_client = Some(client),
                Err(e) => {
                    tracing::warn!("failed to create HTTP client for runtime install: {e}");
                    self.http_client_failed = true;
                    return None;
                }
            }
        }
        self.http_client.as_ref()
    }

    fn platform(&mut self) -> Option<&platform::Platform> {
        if self.platform_failed {
            return None;
        }
        if self.platform.is_none() {
            match platform::Platform::current() {
                Ok(platform) => self.platform = Some(platform),
                Err(e) => {
                    tracing::warn!("unsupported platform for runtime install: {e}");
                    self.platform_failed = true;
                    return None;
                }
            }
        }
        self.platform.as_ref()
    }
}

async fn ensure_one_runtime(
    detected: detect::DetectedRuntimeVersion,
    install_context: &mut RuntimeInstallContext,
) -> RuntimeStatus {
    let runtime = detected.runtime;
    let source = detected.source.to_string();
    let spec = &detected.spec;

    if let Err(e) = validate_version_spec(runtime, spec) {
        tracing::warn!("invalid version spec from {source}: {e}");
        return RuntimeStatus::NotInstalled {
            runtime,
            spec: spec.to_string(),
            source,
        };
    }

    let clean_spec = clean_lookup_spec(runtime, spec);

    if let Ok(installed) = list_installed(runtime)
        && let Some(version) = find_matching_installed(runtime, spec, &installed)
        && let Ok(bin_dir) = bin_dir(runtime, &version)
        && bin_dir.exists()
    {
        return RuntimeStatus::Ready {
            runtime,
            version,
            source,
            bin_dir,
        };
    }

    // Not installed -- check if auto-install is disabled
    let no_auto_install =
        std::env::var("LPM_NO_AUTO_INSTALL").is_ok_and(|v| v == "true" || v == "1");

    if no_auto_install {
        return RuntimeStatus::NotInstalled {
            runtime,
            spec: clean_spec,
            source,
        };
    }

    let Some(http_client) = install_context.http_client().cloned() else {
        return RuntimeStatus::NotInstalled {
            runtime,
            spec: clean_spec,
            source,
        };
    };
    let Some(platform) = install_context.platform().cloned() else {
        return RuntimeStatus::NotInstalled {
            runtime,
            spec: clean_spec,
            source,
        };
    };

    match runtime {
        detect::RuntimeKind::Node => {
            ensure_node_installed(&http_client, &platform, clean_spec, source).await
        }
        detect::RuntimeKind::Bun => {
            ensure_bun_installed(&http_client, &platform, clean_spec, source).await
        }
    }
}

async fn ensure_node_installed(
    http_client: &reqwest::Client,
    platform: &platform::Platform,
    clean_spec: String,
    source: String,
) -> RuntimeStatus {
    let runtime = detect::RuntimeKind::Node;
    let releases = match node::fetch_index(http_client).await {
        Ok(releases) => releases,
        Err(e) => {
            tracing::warn!("failed to fetch node.js release index: {e}");
            return RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            };
        }
    };

    let release = match node::resolve_version(&releases, &clean_spec) {
        Some(release) => release,
        None => {
            tracing::warn!("no node.js release found matching spec '{clean_spec}'");
            return RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            };
        }
    };

    match download::install_node(http_client, &release, platform).await {
        Ok(version) => match node::node_bin_dir(&version) {
            Ok(bin_dir) if bin_dir.exists() => RuntimeStatus::Installed {
                runtime,
                version,
                source,
                bin_dir,
            },
            _ => RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            },
        },
        Err(e) => {
            tracing::warn!(
                "failed to auto-install node {}: {e}",
                release.version_bare()
            );
            RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            }
        }
    }
}

async fn ensure_bun_installed(
    http_client: &reqwest::Client,
    platform: &platform::Platform,
    clean_spec: String,
    source: String,
) -> RuntimeStatus {
    let runtime = detect::RuntimeKind::Bun;
    let releases = match bun::fetch_releases(http_client).await {
        Ok(releases) => releases,
        Err(e) => {
            tracing::warn!("failed to fetch bun release index: {e}");
            return RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            };
        }
    };

    let release = match bun::resolve_version(&releases, &clean_spec) {
        Ok(Some(release)) => release,
        Ok(None) => {
            tracing::warn!("no Bun release found matching spec '{clean_spec}'");
            return RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            };
        }
        Err(e) => {
            tracing::warn!("invalid Bun runtime spec '{clean_spec}': {e}");
            return RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            };
        }
    };

    let asset = match release.asset_for_platform(platform) {
        Some(asset) => asset,
        None => {
            tracing::warn!(
                "no Bun asset found for platform {} in {}",
                platform,
                release.tag_name
            );
            return RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            };
        }
    };

    match download::install_bun(http_client, &release, &asset).await {
        Ok(version) => match bun::bun_bin_dir(&version) {
            Ok(bin_dir) if bin_dir.exists() => RuntimeStatus::Installed {
                runtime,
                version,
                source,
                bin_dir,
            },
            _ => RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            },
        },
        Err(e) => {
            tracing::warn!("failed to auto-install bun {}: {e}", release.version_bare());
            RuntimeStatus::NotInstalled {
                runtime,
                spec: clean_spec,
                source,
            }
        }
    }
}

fn validate_version_spec(
    runtime: detect::RuntimeKind,
    spec: &str,
) -> Result<(), lpm_common::LpmError> {
    match runtime {
        detect::RuntimeKind::Node => node::validate_version_spec(spec),
        detect::RuntimeKind::Bun => bun::validate_version_spec(spec),
    }
}

fn list_installed(runtime: detect::RuntimeKind) -> Result<Vec<String>, lpm_common::LpmError> {
    match runtime {
        detect::RuntimeKind::Node => node::list_installed(),
        detect::RuntimeKind::Bun => bun::list_installed(),
    }
}

fn find_matching_installed(
    runtime: detect::RuntimeKind,
    spec: &str,
    installed: &[String],
) -> Option<String> {
    match runtime {
        detect::RuntimeKind::Node => node::find_matching_installed(spec, installed),
        detect::RuntimeKind::Bun => bun::find_matching_installed(spec, installed),
    }
}

fn bin_dir(
    runtime: detect::RuntimeKind,
    version: &str,
) -> Result<std::path::PathBuf, lpm_common::LpmError> {
    match runtime {
        detect::RuntimeKind::Node => node::node_bin_dir(version),
        detect::RuntimeKind::Bun => bun::bun_bin_dir(version),
    }
}

fn clean_lookup_spec(runtime: detect::RuntimeKind, spec: &str) -> String {
    match runtime {
        detect::RuntimeKind::Node => spec
            .trim_start_matches(">=")
            .trim_start_matches("^")
            .trim_start_matches("~")
            .trim_start_matches('>')
            .to_string(),
        detect::RuntimeKind::Bun => bun::normalize_spec(spec),
    }
}
