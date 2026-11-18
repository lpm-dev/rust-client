mod configuration;
mod signing;

use crate::{auth_storage_notice, install_ui};
use lpm_common::LpmError;
use signing::{RootsOutcome, SignerTrust};
use std::path::Path;

fn swift_registry_endpoint(registry_url: &str) -> Result<reqwest::Url, LpmError> {
    if !lpm_common::lpm_registry_url_is_accepted(registry_url) {
        return Err(LpmError::Registry(
            "Swift registry setup requires an HTTPS base URL or an HTTP loopback base URL without embedded credentials".into(),
        ));
    }
    let mut base = reqwest::Url::parse(registry_url)
        .map_err(|error| LpmError::Registry(format!("invalid Swift registry base URL: {error}")))?;
    if base.query().is_some() || base.fragment().is_some() {
        return Err(LpmError::Registry(
            "Swift registry base URL must not contain a query or fragment".into(),
        ));
    }
    let endpoint_path = format!("{}/api/swift-registry", base.path().trim_end_matches('/'));
    base.set_path(&endpoint_path);
    Ok(base)
}

fn swift_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("swift");
    crate::swift_manifest::sanitize_swift_environment(command.as_std_mut());
    command
}

async fn resolve_lpm_bearer_optional(
    session: &lpm_auth::SessionManager,
) -> Result<Option<String>, LpmError> {
    match session
        .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
        .await
    {
        Ok(token) => Ok(Some(token)),
        Err(LpmError::AuthRequired) => Ok(None),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy)]
enum SwiftLoginOutput {
    Inherit,
    Suppress,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SwiftAuthenticationOutcome {
    Configured,
    NoCredential,
}

async fn run_swift_login(
    swift_registry_url: &str,
    token: &str,
    package_dir: Option<&Path>,
    output: SwiftLoginOutput,
) -> Result<std::process::ExitStatus, LpmError> {
    use std::io::Write;

    let mut token_file = tempfile::Builder::new()
        .prefix("lpm-swift-token-")
        .tempfile()
        .map_err(|error| {
            LpmError::CredentialStorage(format!(
                "failed to create the temporary SwiftPM token file: {error}"
            ))
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        token_file
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                LpmError::CredentialStorage(format!(
                    "failed to restrict the temporary SwiftPM token file: {error}"
                ))
            })?;
    }
    token_file.write_all(token.as_bytes()).map_err(|error| {
        LpmError::CredentialStorage(format!(
            "failed to write the temporary SwiftPM token file: {error}"
        ))
    })?;
    token_file.flush().map_err(|error| {
        LpmError::CredentialStorage(format!(
            "failed to flush the temporary SwiftPM token file: {error}"
        ))
    })?;

    let mut command = swift_command();
    command
        .args([
            "package-registry",
            "login",
            swift_registry_url,
            "--token-file",
        ])
        .arg(token_file.path())
        .arg("--no-confirm");
    if let Some(package_dir) = package_dir {
        command.current_dir(package_dir);
    }
    match output {
        SwiftLoginOutput::Inherit => {
            command
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit());
        }
        SwiftLoginOutput::Suppress => {
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
        }
    }
    command
        .arg("--security-path")
        .arg(crate::swift_manifest::paths::security_dir()?);
    let endpoint = reqwest::Url::parse(swift_registry_url)
        .map_err(|error| LpmError::Registry(error.to_string()))?;
    tokio::task::spawn_blocking(move || {
        let mut command = command.into_std();
        let mut status = None;
        let host = swiftpm_registry_host(&endpoint);
        let authority = match endpoint.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let result = configuration::update(&configuration::global_path()?, host, |config| {
            let staged = tempfile::tempdir()?;
            let mut native_config = config.clone();
            let root = ensure_json_object(&mut native_config)?;
            root.entry("version")
                .or_insert_with(|| serde_json::json!(1));
            root.entry("registries")
                .or_insert_with(|| serde_json::json!({}));
            std::fs::write(
                staged.path().join("registries.json"),
                serde_json::to_vec(&native_config)?,
            )?;
            let login_status = command
                .arg("--config-path")
                .arg(staged.path())
                .status()
                .map_err(|error| LpmError::Registry(format!("swift login failed: {error}")))?;
            status = Some(login_status);
            if login_status.success() {
                let native_config =
                    configuration::load(&staged.path().join("registries.json"), host)?;
                let entry = native_config
                    .get("authentication")
                    .and_then(|value| value.get(&authority))
                    .and_then(serde_json::Value::as_object)
                    .ok_or_else(|| {
                        LpmError::Registry(
                            "Swift login did not write its authentication configuration".into(),
                        )
                    })?;
                let root = ensure_json_object(config)?;
                root.entry("version")
                    .or_insert_with(|| serde_json::json!(1));
                root.entry("registries")
                    .or_insert_with(|| serde_json::json!({}));
                let authentication = root
                    .entry("authentication")
                    .or_insert_with(|| serde_json::json!({}));
                let target = ensure_json_object(authentication)?
                    .entry(&authority)
                    .or_insert_with(|| serde_json::json!({}));
                let target = ensure_json_object(target)?;
                for key in ["type", "loginAPIPath"] {
                    if let Some(value) = entry.get(key) {
                        target.insert(key.into(), value.clone());
                    } else {
                        target.remove(key);
                    }
                }
            }
            Ok(())
        });
        let cleanup = token_file.close();
        match (result, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(LpmError::CredentialStorage(format!(
                "failed to remove the temporary SwiftPM token file: {error}"
            ))),
            (Ok(_), Ok(())) => {
                status.ok_or_else(|| LpmError::Registry("Swift login did not run".into()))
            }
        }
    })
    .await
    .map_err(|error| LpmError::Registry(format!("Swift login task failed: {error}")))?
}

async fn configure_swift_authentication(
    session: &lpm_auth::SessionManager,
    swift_registry_url: &str,
    package_dir: Option<&Path>,
    output: SwiftLoginOutput,
    show_progress: bool,
) -> Result<SwiftAuthenticationOutcome, LpmError> {
    let Some(token) = resolve_lpm_bearer_optional(session).await? else {
        return Ok(SwiftAuthenticationOutcome::NoCredential);
    };

    if show_progress {
        install_ui::phase("Configuring authentication");
    }
    let can_refresh = session
        .current_source()?
        .is_some_and(|source| source.refresh_policy() == lpm_auth::RefreshPolicy::IfRefreshable);
    let first_output = if can_refresh {
        SwiftLoginOutput::Suppress
    } else {
        output
    };
    let first_status =
        run_swift_login(swift_registry_url, &token, package_dir, first_output).await?;
    if first_status.success() {
        return Ok(SwiftAuthenticationOutcome::Configured);
    }

    if can_refresh {
        session.refresh_now().await?;
        let refreshed = session
            .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
            .await?;
        let retry_status =
            run_swift_login(swift_registry_url, &refreshed, package_dir, output).await?;
        if retry_status.success() {
            return Ok(SwiftAuthenticationOutcome::Configured);
        }
        return Err(LpmError::Registry(format!(
            "swift package-registry login failed with status {retry_status} after refreshing the LPM session"
        )));
    }

    Err(LpmError::Registry(format!(
        "swift package-registry login failed with status {first_status}"
    )))
}

/// Whether `configure_signing_trust` changed the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustOutcome {
    Configured,
    AlreadyConfigured,
}

/// What `configure_signing_trust` did, and the policy it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustConfiguration {
    outcome: TrustOutcome,
    /// SwiftPM accepts the registry's releases from any signer.
    accepts_any_signer: bool,
    /// An earlier LPM CLI release had set the pinned registry back to
    /// accepting any signer.
    restored_after_earlier_release: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SwiftRegistrySetupOutcome {
    scope_repaired: bool,
    certificate_repaired: bool,
    trust_repaired: bool,
}

impl SwiftRegistrySetupOutcome {
    pub(crate) fn include_scope_repair(&mut self, repaired: bool) {
        self.scope_repaired |= repaired;
    }

    pub(crate) fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "scope": setup_action(self.scope_repaired),
            "signing_certificate": setup_action(self.certificate_repaired),
            "signing_trust": setup_action(self.trust_repaired),
        })
    }
}

fn setup_action(repaired: bool) -> &'static str {
    if repaired { "repaired" } else { "retained" }
}

/// Configure Swift Package Manager to use LPM as a package registry.
///
/// Steps:
/// 1. swift package-registry set --scope lpmdev <registry_url>/api/swift-registry
/// 2. swift package-registry login --token-file <temporary_file> (HTTPS only)
/// 3. Install the registry's pinned signing roots, when it has any
/// 4. Configure which signers SwiftPM accepts for the registry
pub async fn run(
    session: &lpm_auth::SessionManager,
    registry_url: &str,
    json_output: bool,
    force: bool,
) -> Result<(), LpmError> {
    run_in_directory(
        session,
        registry_url,
        json_output,
        force,
        &std::env::current_dir()?,
    )
    .await
}

async fn run_in_directory(
    session: &lpm_auth::SessionManager,
    registry_url: &str,
    json_output: bool,
    force: bool,
    cwd: &Path,
) -> Result<(), LpmError> {
    let endpoint = swift_registry_endpoint(registry_url)?;
    let is_https = endpoint.scheme() == "https";
    let swift_registry_url = endpoint.to_string();
    let manifest = crate::swift_manifest::find_package_swift(cwd);
    let xcode_project = if manifest.is_none() {
        crate::xcode_project::find_xcodeproj(cwd)?
    } else {
        None
    };
    let package_dir = manifest
        .as_deref()
        .or(xcode_project.as_deref())
        .and_then(Path::parent)
        .unwrap_or(cwd);
    match &xcode_project {
        Some(project) => preflight_xcode_configuration(
            registry_url,
            package_dir,
            &crate::xcode_project::native::containers(cwd, project)?,
        )?,
        None => preflight_configuration(registry_url, package_dir)?,
    }

    if !json_output {
        install_ui::phase_line(swift_package_manager_phase());
    }

    configure_project_scope(package_dir, &endpoint).await?;
    if xcode_project.is_some() {
        ensure_xcode_registry_scope(registry_url)?;
    }
    if !json_output {
        install_ui::done_line(scope_set_message(&swift_registry_url));
    }

    let authentication_outcome = if is_https {
        let output = if json_output {
            SwiftLoginOutput::Suppress
        } else {
            SwiftLoginOutput::Inherit
        };
        match configure_swift_authentication(
            session,
            &swift_registry_url,
            None,
            output,
            !json_output,
        )
        .await?
        {
            SwiftAuthenticationOutcome::Configured => {
                if !json_output {
                    install_ui::done("Authentication configured");
                }
                "configured"
            }
            SwiftAuthenticationOutcome::NoCredential => {
                if !json_output {
                    install_ui::warn(
                        "No LPM.dev Registry token found — run `lpm login`, then rerun `lpm swift-registry` for authenticated access",
                    );
                }
                "skipped_no_credential"
            }
        }
    } else {
        if !json_output {
            install_ui::warn("HTTP registry — SPM won't send auth. Use HTTPS in production.");
        }
        "skipped_http"
    };

    let host = swiftpm_registry_host(&endpoint);
    let trust = SignerTrust::for_host(host)?;
    let roots_outcome = install_signing_roots(&trust, json_output, force)?;
    let configured = configure_signing_trust(host, &trust, json_output)?;
    if configured.accepts_any_signer && !json_output {
        install_ui::warn_line(unpinned_signer_warning(host));
    }

    let roots_outcome_label = match roots_outcome {
        RootsOutcome::Installed => "installed",
        RootsOutcome::Repaired => "repaired",
        RootsOutcome::AlreadyInstalled => "already_installed",
        RootsOutcome::NotPinned => "not_pinned",
    };
    let trust_outcome_label = match configured.outcome {
        TrustOutcome::Configured => "configured",
        TrustOutcome::AlreadyConfigured => "already_configured",
    };
    let trust_anchor = if !configured.accepts_any_signer {
        "pinned_root"
    } else if is_https {
        "https"
    } else {
        "insecure_http"
    };

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "registry_url": swift_registry_url,
            "scope": "lpmdev",
            "https": is_https,
            "signing_certificate_installed": trust.is_pinned(),
            "signing_trust_configured": true,
            "signing_certificate_outcome": roots_outcome_label,
            "signing_trust_outcome": trust_outcome_label,
            "trust_anchor": trust_anchor,
            "authentication_outcome": authentication_outcome,
            "signer_trust_policy": if configured.accepts_any_signer { "silentAllow" } else { "error" },
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        install_ui::done("Done · Swift registry integration is ready");
    }

    Ok(())
}

/// Disposition of an existing `lpmdev` scope in `registries.json`.
/// Carries enough information for the caller to either short-circuit
/// (URL already matches), re-resolve and surface the mismatch (URL
/// points elsewhere), or run a fresh setup (no entry at all).
#[derive(Debug, PartialEq)]
enum ExistingScope {
    /// `registries.lpmdev.url` parses cleanly and equals the expected
    /// LPM swift-registry endpoint.
    Matches,
    /// A `lpmdev` entry exists but its URL differs from the expected
    /// endpoint (or is missing/malformed). A malicious repo could
    /// commit this to substitute the SwiftPM registry on every
    /// teammate that runs `lpm install`; we surface a warning and
    /// re-run setup so the scope URL is overwritten.
    Mismatch { existing: String },
    /// No `lpmdev` entry — first-time setup.
    Absent,
}

// SwiftPM uses Foundation URL.host, which omits IPv6 brackets.
fn swiftpm_registry_host(endpoint: &reqwest::Url) -> &str {
    let host = endpoint.host_str().unwrap_or_default();
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}

fn evaluate_existing_lpmdev_scope(
    config_path: &std::path::Path,
    expected_url: &str,
) -> Result<ExistingScope, LpmError> {
    let endpoint =
        reqwest::Url::parse(expected_url).map_err(|error| LpmError::Registry(error.to_string()))?;
    let json = configuration::load(config_path, swiftpm_registry_host(&endpoint))?;
    let Some(scope) = json.get("registries").and_then(|r| r.get("lpmdev")) else {
        return Ok(ExistingScope::Absent);
    };
    let existing_url = scope.get("url").and_then(|u| u.as_str()).unwrap_or("");
    if existing_url == expected_url {
        Ok(ExistingScope::Matches)
    } else {
        Ok(ExistingScope::Mismatch {
            existing: existing_url.to_string(),
        })
    }
}

/// Called automatically during `lpm install` so the user never has to run `lpm swift-registry`
/// as a separate step.
pub async fn ensure_configured(
    session: Option<&lpm_auth::SessionManager>,
    registry_url: &str,
    package_dir: &std::path::Path,
    json_output: bool,
) -> Result<SwiftRegistrySetupOutcome, LpmError> {
    ensure_configured_for_install(session, registry_url, package_dir, json_output, false).await
}

pub(crate) async fn ensure_configured_for_install(
    session: Option<&lpm_auth::SessionManager>,
    registry_url: &str,
    package_dir: &std::path::Path,
    json_output: bool,
    anonymous: bool,
) -> Result<SwiftRegistrySetupOutcome, LpmError> {
    let endpoint = swift_registry_endpoint(registry_url)?;
    let is_https = endpoint.scheme() == "https";
    let swift_registry_url = endpoint.to_string();

    preflight_configuration(registry_url, package_dir)?;
    let config_path = package_dir.join(".swiftpm/configuration/registries.json");
    let scope_matches = match evaluate_existing_lpmdev_scope(&config_path, &swift_registry_url)? {
        ExistingScope::Matches => true,
        ExistingScope::Mismatch { existing } => {
            tracing::warn!(
                existing = %existing,
                expected = %swift_registry_url,
                "SwiftPM `lpmdev` scope is mapped to a non-LPM URL — re-resolving",
            );
            if !json_output {
                install_ui::warn_untrusted(&format!(
                    "SwiftPM `lpmdev` scope mapped to {existing}, expected {swift_registry_url} — re-resolving"
                ));
            }
            false
        }
        ExistingScope::Absent => false,
    };

    if !scope_matches && !json_output {
        install_ui::phase_line(swift_package_manager_phase());
    }

    if !scope_matches {
        configure_project_scope(package_dir, &endpoint).await?;
        if !json_output {
            install_ui::done_line(scope_set_message(&swift_registry_url));
        }
    }

    if is_https && !anonymous {
        let discovered_session;
        let session = match session {
            Some(session) => session,
            None => {
                discovered_session = auth_storage_notice::attach(
                    lpm_auth::SessionManager::new(registry_url, None),
                    json_output,
                );
                &discovered_session
            }
        };
        configure_swift_authentication(
            session,
            &swift_registry_url,
            Some(package_dir),
            SwiftLoginOutput::Suppress,
            false,
        )
        .await?;
    }

    let host = swiftpm_registry_host(&endpoint);
    let trust = SignerTrust::for_host(host)?;
    let roots = install_signing_roots(&trust, json_output, false)?;
    let configured = configure_signing_trust(host, &trust, json_output)?;
    if configured.outcome == TrustOutcome::Configured
        && configured.accepts_any_signer
        && !json_output
    {
        install_ui::warn_line(unpinned_signer_warning(host));
    }

    Ok(SwiftRegistrySetupOutcome {
        scope_repaired: !scope_matches,
        certificate_repaired: matches!(roots, RootsOutcome::Installed | RootsOutcome::Repaired),
        trust_repaired: configured.outcome == TrustOutcome::Configured,
    })
}

async fn configure_project_scope(
    package_dir: &Path,
    endpoint: &reqwest::Url,
) -> Result<(), LpmError> {
    let status = swift_command()
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(|error| {
            LpmError::Registry(format!("failed to run swift: {error}. Is Swift installed?"))
        })?;
    if !status.success() {
        return Err(LpmError::Registry("Swift toolchain check failed".into()));
    }
    let path = package_dir.join(".swiftpm/configuration/registries.json");
    configuration::update(&path, swiftpm_registry_host(endpoint), |config| {
        apply_registry_scope(config, endpoint)
    })?;
    Ok(())
}

fn apply_registry_scope(
    config: &mut serde_json::Value,
    endpoint: &reqwest::Url,
) -> Result<(), LpmError> {
    let root = ensure_json_object(config)?;
    root.entry("version")
        .or_insert_with(|| serde_json::json!(1));
    let registries = root
        .entry("registries")
        .or_insert_with(|| serde_json::json!({}));
    let entry = ensure_json_object(registries)?
        .entry("lpmdev")
        .or_insert_with(|| serde_json::json!({}));
    let entry = ensure_json_object(entry)?;
    entry.insert(
        "url".into(),
        serde_json::Value::String(endpoint.to_string()),
    );
    entry.insert(
        "supportsAvailability".into(),
        serde_json::Value::Bool(false),
    );
    Ok(())
}

pub(crate) fn ensure_xcode_registry_scope(registry_url: &str) -> Result<bool, LpmError> {
    let endpoint = swift_registry_endpoint(registry_url)?;
    let host = swiftpm_registry_host(&endpoint);
    configuration::update(&configuration::global_path()?, host, |config| {
        apply_registry_scope(config, &endpoint)
    })
}

/// Checks the user's and the package's SwiftPM configuration before setup
/// changes anything, and refuses a package whose own signing settings would
/// keep the registry's pinned roots from applying to it.
pub(crate) fn preflight_configuration(
    registry_url: &str,
    package_dir: &Path,
) -> Result<(), LpmError> {
    preflight_project_configurations(registry_url, [project_configuration(package_dir)])
}

/// [`preflight_configuration`] for an Xcode project, whose containers'
/// SwiftPM configuration Xcode reads as well.
pub(crate) fn preflight_xcode_configuration(
    registry_url: &str,
    package_dir: &Path,
    containers: &[crate::xcode_project::native::Container],
) -> Result<(), LpmError> {
    preflight_project_configurations(
        registry_url,
        std::iter::once(project_configuration(package_dir)).chain(
            containers
                .iter()
                .map(crate::xcode_project::native::Container::registries_configuration),
        ),
    )
}

fn project_configuration(package_dir: &Path) -> std::path::PathBuf {
    package_dir.join(".swiftpm/configuration/registries.json")
}

fn preflight_project_configurations(
    registry_url: &str,
    project_configurations: impl IntoIterator<Item = std::path::PathBuf>,
) -> Result<(), LpmError> {
    let endpoint = swift_registry_endpoint(registry_url)?;
    let host = swiftpm_registry_host(&endpoint);
    configuration::load(&configuration::global_path()?, host)?;
    let trust = SignerTrust::for_host(host)?;
    for path in project_configurations {
        if signing::project_sets_aside(&configuration::load(&path, host)?, host, &trust) {
            return Err(LpmError::Registry(project_sets_aside_pin_message(
                &path, host,
            )));
        }
    }
    Ok(())
}

fn install_signing_roots(
    trust: &SignerTrust,
    json_output: bool,
    force: bool,
) -> Result<RootsOutcome, LpmError> {
    let outcome = signing::install_roots(trust, force)?;
    if let (SignerTrust::Pinned { directory, .. }, false) = (trust, json_output) {
        install_ui::done_line(match outcome {
            RootsOutcome::Installed => signing_root_installed_message(directory),
            RootsOutcome::Repaired => signing_roots_repaired_message(directory),
            RootsOutcome::AlreadyInstalled | RootsOutcome::NotPinned => {
                signing_root_already_installed_message(directory)
            }
        });
    }
    Ok(outcome)
}

/// Sets which signers SwiftPM accepts for `host`, the registry's host as
/// SwiftPM keys it, and keeps strict defaults for every other registry.
/// SwiftPM takes signing actions only from registry overrides, not scope
/// overrides.
fn configure_signing_trust(
    host: &str,
    trust: &SignerTrust,
    json_output: bool,
) -> Result<TrustConfiguration, LpmError> {
    let config_path = configuration::global_path()?;
    let mut restored_after_earlier_release = false;
    let mut accepts_any_signer = true;
    let changed = configuration::update(&config_path, host, |config| {
        if !signing::is_applied(config, host, trust) {
            restored_after_earlier_release =
                signing::set_aside_by_earlier_release(config, host, trust);
            signing::apply(config, host, trust)?;
        }
        accepts_any_signer = signing::accepts_any_signer(config, host);
        Ok(())
    })?;
    if !json_output {
        let message = if changed {
            signing_trust_updated_message(&config_path)
        } else {
            signing_trust_already_configured_message(&config_path)
        };
        install_ui::done_line(message);
        if restored_after_earlier_release {
            install_ui::warn_line(earlier_release_warning(host));
        }
    }
    Ok(TrustConfiguration {
        outcome: if changed {
            TrustOutcome::Configured
        } else {
            TrustOutcome::AlreadyConfigured
        },
        accepts_any_signer,
        restored_after_earlier_release,
    })
}

fn ensure_json_object(
    value: &mut serde_json::Value,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, LpmError> {
    value.as_object_mut().ok_or_else(|| {
        LpmError::Registry("Swift signing trust configuration must contain objects".into())
    })
}

fn earlier_release_warning(host: &str) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "An earlier LPM CLI release on this machine had set {} back to accepting any signer; this release restored its signing root. Update every LPM CLI you run here",
        host
    )
}

fn unpinned_signer_warning(host: &str) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "LPM CLI pins no signing root for {}, so Swift Package Manager accepts its releases from any signer",
        host
    )
}

fn project_sets_aside_pin_message(path: &Path, host: &str) -> String {
    format!(
        "{} has its own signing settings, which Swift Package Manager uses in place of yours, so it wouldn't check {host}'s releases against LPM's signing root here. Remove the `security` section from it, moving any settings you need to your user-wide SwiftPM configuration, then try again.",
        path.display()
    )
}

fn swift_package_manager_phase() -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "Configuring Swift Package Manager for {}",
        install_ui::yellow("lpmdev")
    )
}

fn scope_set_message(swift_registry_url: &str) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "Scope set: {} → {}",
        install_ui::yellow("lpmdev"),
        swift_registry_url
    )
}

fn signing_root_installed_message(roots: &Path) -> install_ui::TerminalLine {
    let home = dirs::home_dir();
    signing_root_installed_message_with_home(roots, home.as_deref())
}

fn signing_root_installed_message_with_home(
    roots: &Path,
    home: Option<&Path>,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "Installed signing root {}",
        display_home_relative_with(roots, home)
    )
}

fn signing_roots_repaired_message(roots: &Path) -> install_ui::TerminalLine {
    let home = dirs::home_dir();
    crate::install_ui::terminal_line!(
        "Removed files that aren't signing roots from {}",
        display_home_relative_with(roots, home.as_deref())
    )
}

fn signing_root_already_installed_message(roots: &Path) -> install_ui::TerminalLine {
    let home = dirs::home_dir();
    signing_root_already_installed_message_with_home(roots, home.as_deref())
}

fn signing_root_already_installed_message_with_home(
    roots: &Path,
    home: Option<&Path>,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "Signing root already installed {}",
        display_home_relative_with(roots, home)
    )
}

fn signing_trust_updated_message(config_path: &Path) -> install_ui::TerminalLine {
    let home = dirs::home_dir();
    signing_trust_updated_message_with_home(config_path, home.as_deref())
}

fn signing_trust_updated_message_with_home(
    config_path: &Path,
    home: Option<&Path>,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!("Updated {}", display_home_relative_with(config_path, home))
}

fn signing_trust_already_configured_message(config_path: &Path) -> install_ui::TerminalLine {
    let home = dirs::home_dir();
    signing_trust_already_configured_message_with_home(config_path, home.as_deref())
}

fn signing_trust_already_configured_message_with_home(
    config_path: &Path,
    home: Option<&Path>,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "Signing trust already configured {}",
        display_home_relative_with(config_path, home)
    )
}

fn display_home_relative_with(path: &Path, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return path.display().to_string();
    };
    let Ok(relative) = path.strip_prefix(home) else {
        return path.display().to_string();
    };
    if relative.as_os_str().is_empty() {
        "~".to_string()
    } else {
        format!("~/{}", relative.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn valid_der_certificate() -> Vec<u8> {
        rcgen::generate_simple_self_signed(vec!["lpm.dev".to_string()])
            .unwrap()
            .cert
            .der()
            .to_vec()
    }

    fn lpm_dev_trust() -> SignerTrust {
        SignerTrust::for_host("lpm.dev").unwrap()
    }

    fn pinned_roots_directory(home: &Path) -> PathBuf {
        lpm_common::symlink::windows_plain_path(
            &test_swiftpm_root(&fs::canonicalize(home).unwrap())
                .join("security")
                .join("lpm-trusted-roots")
                .join("lpm.dev"),
        )
    }

    fn built_in_root() -> Vec<u8> {
        let SignerTrust::Pinned { roots, .. } = lpm_dev_trust() else {
            panic!("lpm.dev must be pinned");
        };
        assert_eq!(roots.len(), 1);
        roots.into_iter().next().unwrap()
    }

    fn built_in_root_path(home: &Path) -> PathBuf {
        pinned_roots_directory(home)
            .join("c96df3ac7c141082cae02d6cbfa41b3753d64972e3199c64ba41a05359966cde.der")
    }

    fn legacy_certificate_path(home: &Path) -> PathBuf {
        test_swiftpm_root(home).join("security/trusted-root-certs/lpm.der")
    }

    fn pinned_signing_trust(home: &Path) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "registries": {},
            "security": {
                "default": {
                    "signing": {
                        "onUnsigned": "error",
                        "onUntrustedCertificate": "error"
                    }
                },
                "registryOverrides": {
                    "lpm.dev": {
                        "signing": {
                            "onUnsigned": "error",
                            "onUntrustedCertificate": "error",
                            "trustedRootCertificatesPath": pinned_roots_directory(home),
                            "includeDefaultTrustedRootCertificates": false
                        }
                    }
                }
            }
        })
    }

    fn write_matching_package_scope(package_dir: &Path, registry_url: &str) {
        let config_path = package_dir.join(".swiftpm/configuration/registries.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(
            config_path,
            serde_json::to_vec(&serde_json::json!({
                "registries": {
                    "lpmdev": {
                        "url": format!("{registry_url}/api/swift-registry")
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn complete_signing_trust() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "registries": {},
            "security": {
                "default": {
                    "signing": {
                        "onUnsigned": "error",
                        "onUntrustedCertificate": "error"
                    }
                },
                "registryOverrides": {
                    "127.0.0.1": {
                        "signing": {
                            "onUntrustedCertificate": "silentAllow"
                        }
                    }
                }
            }
        })
    }

    fn test_swiftpm_root(home: &Path) -> PathBuf {
        if cfg!(target_os = "macos") {
            home.join("Library").join("org.swift.swiftpm")
        } else if cfg!(windows) {
            home.join("swiftpm-test-config").join("swiftpm")
        } else {
            home.join(".swiftpm")
        }
    }

    fn write_global_signing_trust(home: &Path, config: &serde_json::Value) -> PathBuf {
        let config_path = test_swiftpm_root(home)
            .join("configuration")
            .join("registries.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, serde_json::to_vec(config).unwrap()).unwrap();
        config_path
    }

    #[tokio::test]
    async fn native_platform_configuration_is_validated_instead_of_an_unused_legacy_file() {
        let home = TempDir::new().unwrap();
        let xdg = home.path().join("xdg");
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("XDG_CONFIG_HOME", Some(xdg.as_os_str().to_owned())),
        ]);
        let native = if cfg!(target_os = "macos") {
            home.path().join("Library/org.swift.swiftpm")
        } else {
            xdg.join("swiftpm")
        };
        let config = native.join("configuration/registries.json");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(&config, "invalid native configuration").unwrap();
        assert!(configure_signing_trust("lpm.dev", &lpm_dev_trust(), true).is_err());
        assert_eq!(
            fs::read_to_string(config).unwrap(),
            "invalid native configuration"
        );
        assert!(!home.path().join(".swiftpm").exists());
    }

    #[tokio::test]
    async fn signing_configuration_rejects_invalid_shapes_without_replacing_bytes() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let path = write_global_signing_trust(home.path(), &serde_json::json!({}));
        let cases = [
            "broken json",
            "null",
            "[]",
            "42",
            r#"{"version":2}"#,
            r#"{"version":"1"}"#,
            r#"{"registries":[]}"#,
            r#"{"registries":{"lpmdev":{"url":42}}}"#,
            r#"{"registries":{"lpmdev":{"url":"https://lpm.dev/api/swift-registry","supportsAvailability":"bad"}}}"#,
            r#"{"security":null}"#,
            r#"{"security":{"default":[]}}"#,
            r#"{"security":{"default":{"signing":false}}}"#,
            r#"{"security":{"default":{"signing":{"onUnsigned":42}}}}"#,
            r#"{"security":{"scopeOverrides":[]}}"#,
            r#"{"security":{"scopeOverrides":{"lpmdev":{"signing":[]}}}}"#,
            r#"{"security":{"registryOverrides":{"lpm.dev":null}}}"#,
            r#"{"security":{"registryOverrides":{"lpm.dev":{"signing":{"onUntrustedCertificate":false}}}}}"#,
            r#"{"security":{"registryOverrides":{"lpm.dev":{"signing":{"trustedRootCertificatesPath":42}}}}}"#,
            r#"{"security":{"registryOverrides":{"lpm.dev":{"signing":{"includeDefaultTrustedRootCertificates":"no"}}}}}"#,
            r#"{"security":{"scopeOverrides":{"lpmdev":{"signing":{"includeDefaultTrustedRootCertificates":1}}}}}"#,
            r#"{"security":{"scopeOverrides":{"LPMDEV":{"signing":[]}}}}"#,
            r#"{"security":{"scopeOverrides":{"LpmDev":[]}}}"#,
            r#"{"security":{"packageOverrides":{"lpmdev.logger":[]}}}"#,
            r#"{"security":{"packageOverrides":{"LPMDEV.logger":{"signing":{"trustedRootCertificatesPath":false}}}}}"#,
        ];
        // The error names the file canonically, which spells out a Windows
        // 8.3 short name such as `RUNNER~1` in the temp path.
        let canonical_path = fs::canonicalize(&path).unwrap();
        let mut accepted = Vec::new();
        for original in cases {
            fs::write(&path, original).unwrap();
            let result = configure_signing_trust("lpm.dev", &lpm_dev_trust(), true);
            if result.is_ok() || fs::read_to_string(&path).unwrap() != original {
                accepted.push(original);
            } else {
                let error = result.err().unwrap().to_string();
                assert!(
                    error.contains(path.to_str().unwrap())
                        || error.contains(canonical_path.to_str().unwrap()),
                    "{error} must name {}",
                    path.display()
                );
            }
        }
        assert!(
            accepted.is_empty(),
            "invalid configurations accepted or replaced: {accepted:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signing_configuration_preserves_swiftpm_global_directory_alias() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let native = home.path().join("Library/org.swift.swiftpm/configuration");
        fs::create_dir_all(&native).unwrap();
        fs::write(
            native.join("registries.json"),
            r#"{"version":1,"registries":{"other":{"url":"https://other.example"}}}"#,
        )
        .unwrap();
        let swiftpm = home.path().join(".swiftpm");
        fs::create_dir(&swiftpm).unwrap();
        let alias = swiftpm.join("configuration");
        std::os::unix::fs::symlink(&native, &alias).unwrap();
        configure_signing_trust("lpm.dev", &lpm_dev_trust(), true).unwrap();
        assert!(
            fs::symlink_metadata(alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(native.join("registries.json")).unwrap()).unwrap();
        assert_eq!(
            config["registries"]["other"]["url"],
            "https://other.example"
        );
        assert_eq!(
            config["security"]["registryOverrides"]["lpm.dev"]["signing"]["onUntrustedCertificate"],
            "error"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signing_configuration_rejects_symlinks_without_replacing_them() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let path = write_global_signing_trust(home.path(), &serde_json::json!({}));
        let target = home.path().join("shared.json");
        fs::rename(&path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(configure_signing_trust("lpm.dev", &lpm_dev_trust(), true).is_err());
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "{}");
    }

    #[tokio::test]
    async fn signing_configuration_concurrent_hosts_keep_each_override() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let path = write_global_signing_trust(
            home.path(),
            &serde_json::json!({"unrelated": "x".repeat(500_000)}),
        );
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for index in 0..8 {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    configure_signing_trust(
                        &format!("registry{index}.example"),
                        &SignerTrust::Unpinned,
                        true,
                    )
                    .unwrap();
                });
            }
        });
        let config: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        for index in 0..8 {
            assert_eq!(
                config["security"]["registryOverrides"][format!("registry{index}.example")]["signing"]
                    ["onUntrustedCertificate"],
                "silentAllow"
            );
        }
    }

    #[tokio::test]
    async fn automatic_setup_rejects_invalid_configuration_before_installing_roots() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        write_matching_package_scope(package.path(), "https://lpm.dev");
        let path = write_global_signing_trust(home.path(), &serde_json::json!({}));
        fs::write(&path, "broken json").unwrap();
        let legacy = legacy_certificate_path(home.path());
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, "existing certificate").unwrap();

        let result =
            ensure_configured_for_install(None, "https://lpm.dev", package.path(), true, true)
                .await;

        assert!(result.is_err(), "invalid configuration must stop setup");
        assert_eq!(fs::read_to_string(path).unwrap(), "broken json");
        assert_eq!(fs::read_to_string(legacy).unwrap(), "existing certificate");
        assert!(!pinned_roots_directory(home.path()).exists());
    }

    #[cfg(unix)]
    fn fake_swift_path(home: &Path) -> std::ffi::OsString {
        use std::os::unix::fs::PermissionsExt;

        let bin_dir = home.join("fake-swift-bin");
        fs::create_dir_all(&bin_dir).expect("create fake Swift bin directory");
        let swift_path = bin_dir.join("swift");
        fs::write(
            &swift_path,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then exit 0; fi
if [ "$1" = "package-registry" ] && [ "$2" = "set" ]; then
  exit 0
fi
if [ "$1" = "package-registry" ] && [ "$2" = "login" ]; then
  registry_url="$3"
  authority="${registry_url#*://}"
  authority="${authority%%/*}"
  login_path="${registry_url#*://$authority}"
  shift 2
  config_path=""
  if [ -e "$HOME/swift-login-output-modes" ]; then
    if [ /dev/fd/1 -ef /dev/null ]; then stdout_mode="null"; else stdout_mode="live"; fi
    if [ /dev/fd/2 -ef /dev/null ]; then stderr_mode="null"; else stderr_mode="live"; fi
    printf '%s/%s\n' "$stdout_mode" "$stderr_mode" >> "$HOME/swift-login-output-modes"
  fi
  token=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--token" ]; then
      shift
      token="$1"
    fi
    if [ "$1" = "--token-file" ]; then
      shift
      token="$(cat "$1")"
    fi
    if [ "$1" = "--config-path" ]; then shift; config_path="$1"; fi
    shift
  done
  printf '%s\n' "$token" >> "$HOME/swift-login-tokens"
  if [ "$token" = "rejected-access" ]; then
    exit 1
  fi
  if [ -n "$config_path" ]; then
    printf '{"version":1,"registries":{},"authentication":{"%s":{"type":"token","loginAPIPath":"%s"}}}' "$authority" "$login_path" > "$config_path/registries.json"
  fi
  exit 0
fi
exit 64
"#,
        )
        .expect("write fake Swift executable");
        let mut permissions = fs::metadata(&swift_path)
            .expect("read fake Swift metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&swift_path, permissions).expect("mark fake Swift executable");

        let existing_path = std::env::var_os("PATH").unwrap_or_default();
        std::env::join_paths(std::iter::once(bin_dir).chain(std::env::split_paths(&existing_path)))
            .expect("construct PATH with fake Swift")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn staged_login_and_signing_trust_use_native_ipv6_host_keys() {
        let home = TempDir::new().unwrap();
        let path = fake_swift_path(home.path());
        fs::write(home.path().join("fake-swift-bin/swift"), r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--config-path" ]; then shift; config="$1"; fi
  shift
done
printf '%s' '{"version":1,"registries":{},"authentication":{"::1:8443":{"type":"token","loginAPIPath":"/api/swift-registry"}}}' > "$config/registries.json"
"#).unwrap();
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
        ]);
        assert!(
            run_swift_login(
                "https://[::1]:8443/api/swift-registry",
                "fixture-token",
                None,
                SwiftLoginOutput::Suppress
            )
            .await
            .unwrap()
            .success()
        );
        configure_signing_trust("::1", &SignerTrust::Unpinned, true).unwrap();
        let config = configuration::load(&configuration::global_path().unwrap(), "::1").unwrap();
        assert_eq!(config["authentication"]["::1:8443"]["type"], "token");
        assert_eq!(
            config["security"]["registryOverrides"]["::1"]["signing"]["onUntrustedCertificate"],
            "silentAllow"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejected_fresh_login_leaves_the_global_configuration_absent() {
        let home = TempDir::new().unwrap();
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
        ]);
        assert!(
            !run_swift_login(
                "https://lpm.dev/api/swift-registry",
                "rejected-access",
                None,
                SwiftLoginOutput::Suppress
            )
            .await
            .unwrap()
            .success()
        );
        assert!(!configuration::global_path().unwrap().exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_fresh_login_writes_required_native_fields_before_later_setup_steps() {
        let home = TempDir::new().unwrap();
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
        ]);
        assert!(
            run_swift_login(
                "https://lpm.dev/api/swift-registry",
                "fixture-token",
                None,
                SwiftLoginOutput::Suppress
            )
            .await
            .unwrap()
            .success()
        );
        let config =
            configuration::load(&configuration::global_path().unwrap(), "lpm.dev").unwrap();
        assert!(config["registries"].is_object());
        assert_eq!(config["version"], 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_login_preserves_existing_global_configuration_extensions() {
        let home = TempDir::new().unwrap();
        let path = fake_swift_path(home.path());
        fs::write(home.path().join("fake-swift-bin/swift"), r#"#!/bin/sh
if [ "$(uname)" = "Darwin" ]; then config="$HOME/Library/org.swift.swiftpm/configuration"; else config="$HOME/.swiftpm/configuration"; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--config-path" ]; then shift; config="$1"; fi
  shift
done
mkdir -p "$config"
printf '%s' '{"version":1,"registries":{},"authentication":{"lpm.dev":{"type":"token","loginAPIPath":"/api/swift-registry"}}}' > "$config/registries.json"
"#).unwrap();
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
        ]);
        let config_path = write_global_signing_trust(
            home.path(),
            &serde_json::json!({
                "version":1,"registries":{},"unrelated":{"keep":true},
                "authentication":{"lpm.dev":{"type":"token","extension":"preserve"}}
            }),
        );
        assert!(
            run_swift_login(
                "https://lpm.dev/api/swift-registry",
                "fixture-token",
                None,
                SwiftLoginOutput::Suppress
            )
            .await
            .unwrap()
            .success()
        );
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert_eq!(config["unrelated"]["keep"], true);
        assert_eq!(config["authentication"]["lpm.dev"]["extension"], "preserve");
        assert_eq!(
            config["authentication"]["lpm.dev"]["loginAPIPath"],
            "/api/swift-registry"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn swift_registry_retries_rejected_stored_session_after_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "rotated-access",
                "refreshToken": "rotated-refresh",
                "expiresAt": "2099-01-01T00:00:00Z",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let home = TempDir::new().expect("create isolated home");
        let login_tokens = home.path().join("swift-login-tokens");
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
            ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ("LPM_TEST_FAST_SCRYPT", Some("1".into())),
            (
                "LPM_TEST_SWIFT_LOGIN_TOKENS",
                Some(login_tokens.as_os_str().to_owned()),
            ),
            (
                "LPM_TEST_SWIFT_REJECT_TOKEN",
                Some("rejected-access".into()),
            ),
            ("LPM_TOKEN", None),
        ]);
        lpm_auth::store_refresh_backed_session(
            &server.uri(),
            "rejected-access",
            "valid-refresh",
            "2099-01-01T00:00:00Z",
        )
        .await
        .expect("store refresh-backed session");
        let session = lpm_auth::SessionManager::new(server.uri(), None);
        let swift_registry_origin = server.uri().replacen("http://", "https://", 1);

        let package = TempDir::new().unwrap();
        let _ = run_in_directory(
            &session,
            &swift_registry_origin,
            true,
            false,
            package.path(),
        )
        .await;

        let attempted_tokens = fs::read_to_string(login_tokens).expect("read Swift login attempts");
        assert_eq!(attempted_tokens, "rejected-access\nrotated-access\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refresh_retry_suppresses_the_speculative_swiftpm_failure_output() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "rotated-access",
                "refreshToken": "rotated-refresh",
                "expiresAt": "2099-01-01T00:00:00Z",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let home = TempDir::new().expect("create isolated home");
        let login_tokens = home.path().join("swift-login-tokens");
        let output_modes = home.path().join("swift-login-output-modes");
        fs::write(&output_modes, []).expect("create Swift login output mode log");
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
            ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ("LPM_TEST_FAST_SCRYPT", Some("1".into())),
            (
                "LPM_TEST_SWIFT_LOGIN_TOKENS",
                Some(login_tokens.as_os_str().to_owned()),
            ),
            (
                "LPM_TEST_SWIFT_LOGIN_OUTPUT_MODES",
                Some(output_modes.as_os_str().to_owned()),
            ),
            (
                "LPM_TEST_SWIFT_REJECT_TOKEN",
                Some("rejected-access".into()),
            ),
            ("LPM_TOKEN", None),
        ]);
        lpm_auth::store_refresh_backed_session(
            &server.uri(),
            "rejected-access",
            "valid-refresh",
            "2099-01-01T00:00:00Z",
        )
        .await
        .expect("store refresh-backed session");
        let session = lpm_auth::SessionManager::new(server.uri(), None);

        let outcome = configure_swift_authentication(
            &session,
            "https://registry.example/api/swift-registry",
            None,
            SwiftLoginOutput::Inherit,
            false,
        )
        .await
        .expect("SwiftPM login must recover after refreshing the LPM session");

        assert!(outcome == SwiftAuthenticationOutcome::Configured);
        assert_eq!(
            fs::read_to_string(output_modes).expect("read Swift login output modes"),
            "null/null\nlive/live\n"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn anonymous_lpm_dev_setup_pins_the_built_in_root_without_logging_in() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
            ("LPM_TOKEN", None),
        ]);
        write_matching_package_scope(package.path(), "https://lpm.dev");
        let session =
            lpm_auth::SessionManager::new("https://lpm.dev", Some("rejected-access".into()));

        let outcome = ensure_configured_for_install(
            Some(&session),
            "https://lpm.dev",
            package.path(),
            true,
            true,
        )
        .await
        .unwrap();

        assert!(!home.path().join("swift-login-tokens").exists());
        assert_eq!(
            fs::read(built_in_root_path(home.path())).unwrap(),
            built_in_root()
        );
        assert_eq!(
            outcome.to_json(),
            serde_json::json!({
                "scope": "retained",
                "signing_certificate": "repaired",
                "signing_trust": "repaired"
            })
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn automatic_setup_reports_swiftpm_login_failure() {
        let server = MockServer::start().await;
        let home = TempDir::new().expect("create isolated home");
        let package = TempDir::new().expect("create Swift package directory");
        let login_tokens = home.path().join("swift-login-tokens");
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
            (
                "LPM_TEST_SWIFT_LOGIN_TOKENS",
                Some(login_tokens.as_os_str().to_owned()),
            ),
            (
                "LPM_TEST_SWIFT_REJECT_TOKEN",
                Some("rejected-access".into()),
            ),
            ("LPM_TOKEN", None),
        ]);
        let registry_url = server.uri().replacen("http://", "https://", 1);
        let session =
            lpm_auth::SessionManager::new(&registry_url, Some("rejected-access".to_string()));

        let error = ensure_configured(Some(&session), &registry_url, package.path(), true)
            .await
            .expect_err("SwiftPM login rejection must fail automatic setup");

        assert!(
            error
                .to_string()
                .contains("swift package-registry login failed"),
            "unexpected automatic setup error: {error}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn automatic_setup_authenticates_when_the_registry_scope_already_matches() {
        let server = MockServer::start().await;
        let registry_url = server.uri().replacen("http://", "https://", 1);
        let home = TempDir::new().expect("create isolated home");
        let package = TempDir::new().expect("create Swift package directory");
        write_matching_package_scope(package.path(), &registry_url);
        let login_tokens = home.path().join("swift-login-tokens");
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_HOME", Some(home.path().join(".lpm").into_os_string())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
            (
                "LPM_TEST_SWIFT_LOGIN_TOKENS",
                Some(login_tokens.as_os_str().to_owned()),
            ),
            ("LPM_TEST_SWIFT_REJECT_TOKEN", Some(String::new().into())),
            ("LPM_TOKEN", None),
        ]);
        let session =
            lpm_auth::SessionManager::new(&registry_url, Some("matching-scope-access".to_string()));

        let _ = ensure_configured(Some(&session), &registry_url, package.path(), true).await;

        assert_eq!(
            fs::read_to_string(login_tokens)
                .expect("matching scope must not suppress SwiftPM authentication"),
            "matching-scope-access\n"
        );
    }

    #[tokio::test]
    async fn automatic_setup_prefers_the_dispatch_explicit_bearer_over_the_environment() {
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_TOKEN",
            std::ffi::OsString::from("environment-token"),
        )]);
        let registry_url = "https://registry.example";
        let dispatch_session =
            lpm_auth::SessionManager::new(registry_url, Some("explicit-token".to_string()));

        let resolved = resolve_lpm_bearer_optional(&dispatch_session)
            .await
            .expect("resolve dispatch session");

        assert_eq!(resolved.as_deref(), Some("explicit-token"));
    }

    #[test]
    fn existing_scope_check_rejects_oversized_swift_registry_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registries.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();

        let error = evaluate_existing_lpmdev_scope(&path, "https://swift.lpm.dev").unwrap_err();

        let message = error.to_string();
        assert!(
            message.contains(&path.display().to_string())
                && message.contains("16777216-byte limit"),
            "error must identify Swift registry config and limit: {message}"
        );
    }

    /// Serialize tests that mutate the process-wide `HOME` env var, so they
    /// don't trample each other under `cargo test` parallelism. Async-aware
    /// so the guard can be held across `.await` points (wiremock setup).
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' && chars.peek() == Some(&'[') {
                chars.next();
                for cc in chars.by_ref() {
                    let cb = cc as u32;
                    if (0x40..=0x7e).contains(&cb) {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// `HOME` set to `home` until the guard drops, with `XDG_CONFIG_HOME`
    /// inside it on Windows and unset elsewhere.
    fn home_override(home: &std::path::Path) -> crate::test_env::ScopedEnv {
        let xdg = cfg!(windows).then(|| home.join("swiftpm-test-config").into_os_string());
        crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.as_os_str().to_owned())),
            ("XDG_CONFIG_HOME", xdg),
        ])
    }

    #[test]
    fn swift_registry_slim_messages_match_design_copy() {
        let home = std::path::PathBuf::from("/Users/example");
        let roots = home.join(".swiftpm/security/lpm-trusted-roots/lpm.dev");
        let config_path = home.join(".swiftpm/configuration/registries.json");
        let scope_message = scope_set_message("https://lpm.dev/api/swift-registry");
        let phase_message = swift_package_manager_phase();

        assert_eq!(
            strip_ansi(&phase_message),
            "Configuring Swift Package Manager for lpmdev"
        );
        assert_eq!(
            strip_ansi(&scope_message),
            "Scope set: lpmdev → https://lpm.dev/api/swift-registry"
        );
        if lpm_common::color::enabled() {
            assert!(
                phase_message.contains("\u{1b}[33mlpmdev\u{1b}[39m")
                    && scope_message.contains("\u{1b}[33mlpmdev\u{1b}[39m"),
                "swift-registry must color the lpmdev scope target, got phase={phase_message:?}, scope={scope_message:?}"
            );
        }
        assert_eq!(
            display_home_relative_with(&roots, Some(&home)),
            "~/.swiftpm/security/lpm-trusted-roots/lpm.dev"
        );
        assert_eq!(
            signing_root_installed_message_with_home(&roots, Some(&home)).to_string(),
            "Installed signing root ~/.swiftpm/security/lpm-trusted-roots/lpm.dev"
        );
        assert_eq!(
            signing_root_already_installed_message_with_home(&roots, Some(&home)).to_string(),
            "Signing root already installed ~/.swiftpm/security/lpm-trusted-roots/lpm.dev"
        );
        assert_eq!(
            strip_ansi(&unpinned_signer_warning("registry.example")),
            "LPM CLI pins no signing root for registry.example, so Swift Package Manager accepts its releases from any signer"
        );
        assert_eq!(
            signing_trust_updated_message_with_home(&config_path, Some(&home)).to_string(),
            "Updated ~/.swiftpm/configuration/registries.json"
        );
    }

    #[test]
    fn signing_trust_preserves_existing_authentication_configuration() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let config = serde_json::json!({
            "version": 1,
            "authentication": {
                "lpm.dev": { "loginAPIPath": "/api/swift-registry", "type": "token" }
            },
            "registries": {}
        });
        let path = write_global_signing_trust(home.path(), &config);
        configure_signing_trust("lpm.dev", &lpm_dev_trust(), true).unwrap();
        let updated: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(updated["authentication"], config["authentication"]);
    }

    #[test]
    fn the_built_in_root_is_lpm_dev_s_offline_swift_signing_root() {
        use sha2::Digest as _;
        use x509_parser::prelude::{FromDer as _, X509Certificate};

        let root = built_in_root();
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&root)),
            "c96df3ac7c141082cae02d6cbfa41b3753d64972e3199c64ba41a05359966cde"
        );
        let (rest, certificate) = X509Certificate::from_der(&root).unwrap();
        assert!(rest.is_empty());
        let constraints = certificate.basic_constraints().unwrap().unwrap();
        assert!(constraints.critical && constraints.value.ca);
        assert_eq!(constraints.value.path_len_constraint, Some(0));
        let usage = certificate.key_usage().unwrap().unwrap();
        assert!(usage.critical && usage.value.key_cert_sign());
        assert_eq!(certificate.subject(), certificate.issuer());
    }

    #[test]
    fn only_lpm_dev_is_pinned() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        for host in ["lpm.dev", "LPM.dev"] {
            assert_eq!(
                SignerTrust::for_host(host).unwrap(),
                SignerTrust::Pinned {
                    roots: vec![built_in_root()],
                    directory: pinned_roots_directory(home.path()),
                },
                "{host}"
            );
        }
        for host in [
            "127.0.0.1",
            "registry.example",
            "www.lpm.dev",
            "lpm.dev.example",
        ] {
            assert_eq!(
                SignerTrust::for_host(host).unwrap(),
                SignerTrust::Unpinned,
                "{host}"
            );
        }
    }

    #[test]
    fn pinned_roots_leave_the_directory_holding_exactly_the_built_in_root() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let directory = pinned_roots_directory(home.path());
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("other-root.der"), valid_der_certificate()).unwrap();
        fs::write(directory.join(".DS_Store"), "finder state").unwrap();
        let legacy = legacy_certificate_path(home.path());
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, valid_der_certificate()).unwrap();

        assert_eq!(
            signing::install_roots(&lpm_dev_trust(), false).unwrap(),
            RootsOutcome::Installed
        );

        let entries: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries, [built_in_root_path(home.path())]);
        assert_eq!(
            fs::read(built_in_root_path(home.path())).unwrap(),
            built_in_root()
        );
        assert!(
            !legacy.exists(),
            "the certificate earlier releases wrote stays"
        );
        assert_eq!(
            signing::install_roots(&lpm_dev_trust(), false).unwrap(),
            RootsOutcome::AlreadyInstalled
        );
        assert_eq!(
            signing::install_roots(&lpm_dev_trust(), true).unwrap(),
            RootsOutcome::Installed
        );
    }

    #[test]
    fn a_damaged_pinned_root_is_rewritten() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let root = built_in_root_path(home.path());
        fs::create_dir_all(root.parent().unwrap()).unwrap();
        fs::write(&root, &built_in_root()[..100]).unwrap();

        assert_eq!(
            signing::install_roots(&lpm_dev_trust(), false).unwrap(),
            RootsOutcome::Installed
        );
        assert_eq!(fs::read(root).unwrap(), built_in_root());
    }

    #[test]
    fn pinned_roots_refuse_a_directory_inside_the_roots_directory() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let nested = pinned_roots_directory(home.path()).join("nested");
        fs::create_dir_all(&nested).unwrap();

        let error = signing::install_roots(&lpm_dev_trust(), false).unwrap_err();

        assert!(error.to_string().contains("remove it"), "{error}");
        assert!(nested.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_roots_refuse_a_linked_roots_directory() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let directory = pinned_roots_directory(home.path());
        let elsewhere = home.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &directory).unwrap();

        let error = signing::install_roots(&lpm_dev_trust(), false).unwrap_err();

        assert!(error.to_string().contains("not a link"), "{error}");
        assert_eq!(fs::read_dir(elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn an_unpinned_registry_installs_no_roots_and_keeps_the_earlier_certificate() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let legacy = legacy_certificate_path(home.path());
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, valid_der_certificate()).unwrap();

        assert_eq!(
            signing::install_roots(&SignerTrust::Unpinned, true).unwrap(),
            RootsOutcome::NotPinned
        );
        assert!(legacy.exists());
        assert!(
            !test_swiftpm_root(home.path())
                .join("security/lpm-trusted-roots")
                .exists()
        );
    }

    #[tokio::test]
    async fn a_project_whose_own_signing_settings_set_the_pin_aside_is_refused_before_changes() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let project_config = package
            .path()
            .join(".swiftpm/configuration/registries.json");
        fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        fs::write(
            &project_config,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "registries": {"lpmdev": {"url": "https://lpm.dev/api/swift-registry"}},
                "security": {}
            }))
            .unwrap(),
        )
        .unwrap();

        let error =
            ensure_configured_for_install(None, "https://lpm.dev", package.path(), true, true)
                .await
                .unwrap_err()
                .to_string();

        assert!(error.contains("its own signing settings"), "{error}");
        assert!(error.contains("registries.json"), "{error}");
        assert!(error.contains("Remove the `security` section"), "{error}");
        assert!(
            !test_swiftpm_root(home.path())
                .join("configuration/registries.json")
                .exists()
        );
        assert!(!pinned_roots_directory(home.path()).exists());
    }

    #[test]
    fn null_optional_signing_fields_read_as_absent() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let unset = serde_json::json!({
            "onUnsigned": null,
            "onUntrustedCertificate": null,
            "trustedRootCertificatesPath": null,
            "includeDefaultTrustedRootCertificates": null
        });
        let mut config = pinned_signing_trust(home.path());
        config["security"]["scopeOverrides"] = serde_json::json!({"lpmdev": {"signing": unset}});
        config["security"]["packageOverrides"] =
            serde_json::json!({"lpmdev.logger": {"signing": unset}});
        assert!(signing::is_applied(&config, "lpm.dev", &lpm_dev_trust()));
        let path = write_global_signing_trust(home.path(), &config);

        assert_eq!(
            configure_signing_trust("lpm.dev", &lpm_dev_trust(), true)
                .unwrap()
                .outcome,
            TrustOutcome::AlreadyConfigured
        );

        let mut earlier = complete_signing_trust();
        earlier["security"]["registryOverrides"] =
            serde_json::json!({"lpm.dev": {"signing": unset}});
        fs::write(&path, serde_json::to_vec(&earlier).unwrap()).unwrap();
        assert_eq!(
            configure_signing_trust("lpm.dev", &lpm_dev_trust(), true)
                .unwrap()
                .outcome,
            TrustOutcome::Configured
        );
        let repaired: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert!(signing::is_applied(&repaired, "lpm.dev", &lpm_dev_trust()));
    }

    #[test]
    fn an_unpinned_registry_leaves_lpmdev_scope_and_package_roots_alone() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let roots = serde_json::json!({
            "signing": {
                "trustedRootCertificatesPath": "/elsewhere",
                "includeDefaultTrustedRootCertificates": true
            }
        });
        let mut config = complete_signing_trust();
        config["security"]["scopeOverrides"] = serde_json::json!({"lpmdev": roots});
        config["security"]["packageOverrides"] = serde_json::json!({"lpmdev.logger": roots});
        let path = write_global_signing_trust(home.path(), &config);

        assert_eq!(
            configure_signing_trust("127.0.0.1", &SignerTrust::Unpinned, true)
                .unwrap()
                .outcome,
            TrustOutcome::AlreadyConfigured
        );
        let retained: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(retained["security"]["scopeOverrides"]["lpmdev"], roots);
        assert_eq!(
            retained["security"]["packageOverrides"]["lpmdev.logger"],
            roots
        );
    }

    #[test]
    fn the_roots_path_swiftpm_reads_is_plain() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let SignerTrust::Pinned { directory, .. } = lpm_dev_trust() else {
            panic!("lpm.dev must be pinned");
        };
        let path = directory.to_str().unwrap();
        assert!(!path.starts_with(r"\\?\"), "{path}");
        assert!(directory.is_absolute(), "{path}");
    }

    #[cfg(unix)]
    #[test]
    fn pinned_roots_refuse_a_linked_lock_file() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let directory = pinned_roots_directory(home.path());
        fs::create_dir_all(&directory).unwrap();
        let elsewhere = home.path().join("elsewhere.lock");
        fs::write(&elsewhere, "unrelated").unwrap();
        std::os::unix::fs::symlink(
            &elsewhere,
            directory.parent().unwrap().join(".lpm-trusted-roots.lock"),
        )
        .unwrap();

        assert!(signing::install_roots(&lpm_dev_trust(), false).is_err());
        assert_eq!(fs::read_to_string(elsewhere).unwrap(), "unrelated");
        assert!(!built_in_root_path(home.path()).exists());
    }

    #[test]
    fn a_directory_at_a_root_s_name_is_refused_with_a_remedy() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        fs::create_dir_all(built_in_root_path(home.path())).unwrap();

        let error = signing::install_roots(&lpm_dev_trust(), false).unwrap_err();

        assert!(error.to_string().contains("remove it"), "{error}");
    }

    #[test]
    fn an_unpinned_registry_keeps_the_user_s_own_signing_root() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let mut config = complete_signing_trust();
        config["security"]["registryOverrides"] = serde_json::json!({
            "registry.example": {"signing": {
                "onUntrustedCertificate": "error",
                "trustedRootCertificatesPath": "/Users/example/registry-roots"
            }}
        });
        let path = write_global_signing_trust(home.path(), &config);

        let configured =
            configure_signing_trust("registry.example", &SignerTrust::Unpinned, true).unwrap();

        assert_eq!(configured.outcome, TrustOutcome::AlreadyConfigured);
        assert!(!configured.accepts_any_signer);
        let kept: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(kept, config);
        let fresh = configure_signing_trust("other.example", &SignerTrust::Unpinned, true).unwrap();
        assert!(fresh.accepts_any_signer);
    }

    #[test]
    fn an_earlier_release_s_any_signer_policy_beside_the_pinned_roots_is_reported() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let mut config = pinned_signing_trust(home.path());
        config["security"]["registryOverrides"]["lpm.dev"]["signing"]["onUntrustedCertificate"] =
            serde_json::json!("silentAllow");
        write_global_signing_trust(home.path(), &config);

        let configured = configure_signing_trust("lpm.dev", &lpm_dev_trust(), true).unwrap();

        assert_eq!(configured.outcome, TrustOutcome::Configured);
        assert!(configured.restored_after_earlier_release);
        assert!(!configured.accepts_any_signer);
        let again = configure_signing_trust("lpm.dev", &lpm_dev_trust(), true).unwrap();
        assert!(!again.restored_after_earlier_release);
    }

    #[test]
    fn a_roots_directory_only_cleaned_up_is_reported_as_repaired() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        signing::install_roots(&lpm_dev_trust(), false).unwrap();
        fs::write(pinned_roots_directory(home.path()).join("desktop.ini"), "").unwrap();

        assert_eq!(
            signing::install_roots(&lpm_dev_trust(), false).unwrap(),
            RootsOutcome::Repaired
        );
    }

    #[cfg(windows)]
    #[test]
    fn pinned_roots_refuse_a_junction_in_place_of_the_roots_directory() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let directory = pinned_roots_directory(home.path());
        let elsewhere = home.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        lpm_common::create_dir_symlink_or_junction(&elsewhere, &directory).unwrap();

        let error = signing::install_roots(&lpm_dev_trust(), false).unwrap_err();

        assert!(error.to_string().contains("not a link"), "{error}");
        assert_eq!(fs::read_dir(elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn lpm_dev_signatures_must_chain_to_the_pinned_root() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());

        let outcome = configure_signing_trust("lpm.dev", &lpm_dev_trust(), true)
            .unwrap()
            .outcome;

        assert_eq!(outcome, TrustOutcome::Configured);
        let config_path = test_swiftpm_root(home.path()).join("configuration/registries.json");
        let json: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        assert_eq!(json, pinned_signing_trust(home.path()));
        assert_eq!(
            configure_signing_trust("lpm.dev", &lpm_dev_trust(), true)
                .unwrap()
                .outcome,
            TrustOutcome::AlreadyConfigured
        );
    }

    #[test]
    fn signing_trust_replaces_a_silent_allow_lpm_dev_override_with_the_pin() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let mut earlier = complete_signing_trust();
        earlier["security"]["registryOverrides"] = serde_json::json!({
            "lpm.dev": {"signing": {"onUntrustedCertificate": "silentAllow"}}
        });
        assert!(!signing::is_applied(&earlier, "lpm.dev", &lpm_dev_trust()));
        let path = write_global_signing_trust(home.path(), &earlier);

        assert_eq!(
            configure_signing_trust("lpm.dev", &lpm_dev_trust(), true)
                .unwrap()
                .outcome,
            TrustOutcome::Configured
        );

        let repaired: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(repaired, pinned_signing_trust(home.path()));
    }

    #[test]
    fn signing_trust_drops_lpmdev_scope_and_package_roots_that_would_replace_the_pin() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let mut config = pinned_signing_trust(home.path());
        let other_roots = serde_json::json!({
            "signing": {
                "trustedRootCertificatesPath": "/elsewhere",
                "includeDefaultTrustedRootCertificates": true
            }
        });
        config["security"]["scopeOverrides"] =
            serde_json::json!({"LPMDEV": other_roots, "other": other_roots});
        config["security"]["packageOverrides"] =
            serde_json::json!({"lpmdev.logger": other_roots, "other.logger": other_roots});
        assert!(!signing::is_applied(&config, "lpm.dev", &lpm_dev_trust()));
        let path = write_global_signing_trust(home.path(), &config);

        configure_signing_trust("lpm.dev", &lpm_dev_trust(), true).unwrap();

        let repaired: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert!(signing::is_applied(&repaired, "lpm.dev", &lpm_dev_trust()));
        assert_eq!(
            repaired["security"]["scopeOverrides"]["LPMDEV"]["signing"],
            serde_json::json!({})
        );
        assert_eq!(
            repaired["security"]["packageOverrides"]["lpmdev.logger"]["signing"],
            serde_json::json!({})
        );
        assert_eq!(repaired["security"]["scopeOverrides"]["other"], other_roots);
        assert_eq!(
            repaired["security"]["packageOverrides"]["other.logger"],
            other_roots
        );
    }

    #[test]
    fn a_project_with_its_own_signing_settings_sets_the_pin_aside() {
        let home = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let trust = lpm_dev_trust();
        let scope_only = serde_json::json!({"version": 1, "registries": {}});
        let own_settings = serde_json::json!({
            "version": 1,
            "registries": {},
            "security": {"default": {"signing": {"onUnsigned": "warn"}}}
        });

        assert!(!signing::project_sets_aside(&scope_only, "lpm.dev", &trust));
        assert!(signing::project_sets_aside(
            &own_settings,
            "lpm.dev",
            &trust
        ));
        assert!(!signing::project_sets_aside(
            &pinned_signing_trust(home.path()),
            "lpm.dev",
            &trust
        ));
        assert!(!signing::project_sets_aside(
            &own_settings,
            "127.0.0.1",
            &SignerTrust::Unpinned
        ));
        let mut restated_with_own_defaults = pinned_signing_trust(home.path());
        restated_with_own_defaults["security"]["default"]["signing"]["onUnsigned"] =
            serde_json::json!("warn");
        assert!(!signing::project_sets_aside(
            &restated_with_own_defaults,
            "lpm.dev",
            &trust
        ));
        let mut scope_roots = pinned_signing_trust(home.path());
        scope_roots["security"]["scopeOverrides"] = serde_json::json!({
            "lpmdev": {"signing": {"trustedRootCertificatesPath": "/elsewhere"}}
        });
        assert!(signing::project_sets_aside(&scope_roots, "lpm.dev", &trust));
    }

    // ── M53: scope URL verification ──────────────────────────────

    /// No registries.json yet — first-time setup.
    #[test]
    fn scope_eval_returns_absent_when_no_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registries.json");
        let outcome =
            evaluate_existing_lpmdev_scope(&path, "https://lpm.dev/api/swift-registry").unwrap();
        assert_eq!(outcome, ExistingScope::Absent);
    }

    /// `registries.json` exists but has no `lpmdev` scope — absent.
    #[test]
    fn scope_eval_returns_absent_when_no_lpmdev_entry() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registries.json");
        std::fs::write(
            &path,
            r#"{"registries": {"other": {"url": "https://other.example/"}}}"#,
        )
        .unwrap();
        let outcome =
            evaluate_existing_lpmdev_scope(&path, "https://lpm.dev/api/swift-registry").unwrap();
        assert_eq!(outcome, ExistingScope::Absent);
    }

    /// The scope URL matches the resolved registry endpoint — short-circuit OK.
    #[test]
    fn scope_eval_returns_matches_on_url_equality() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registries.json");
        std::fs::write(
            &path,
            r#"{"registries": {"lpmdev": {"url": "https://lpm.dev/api/swift-registry"}}}"#,
        )
        .unwrap();
        let outcome =
            evaluate_existing_lpmdev_scope(&path, "https://lpm.dev/api/swift-registry").unwrap();
        assert_eq!(outcome, ExistingScope::Matches);
    }

    /// M53: a hostile repo can commit `registries.json` with `lpmdev`
    /// mapped to an attacker URL. The check must NOT short-circuit on
    /// the bare presence of the entry — it must compare URLs.
    #[test]
    fn scope_eval_returns_mismatch_when_lpmdev_url_points_elsewhere() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registries.json");
        std::fs::write(
            &path,
            r#"{"registries": {"lpmdev": {"url": "https://attacker.example/registry"}}}"#,
        )
        .unwrap();
        let outcome =
            evaluate_existing_lpmdev_scope(&path, "https://lpm.dev/api/swift-registry").unwrap();
        assert_eq!(
            outcome,
            ExistingScope::Mismatch {
                existing: "https://attacker.example/registry".to_string(),
            }
        );
    }

    #[test]
    fn scope_eval_rejects_malformed_json_and_repairs_missing_url() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registries.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(
            evaluate_existing_lpmdev_scope(&path, "https://lpm.dev/api/swift-registry").is_err()
        );

        std::fs::write(&path, r#"{"registries": {"lpmdev": {}}}"#).unwrap();
        assert_eq!(
            evaluate_existing_lpmdev_scope(&path, "https://lpm.dev/api/swift-registry").unwrap(),
            ExistingScope::Mismatch {
                existing: String::new(),
            }
        );
    }

    #[tokio::test]
    async fn automatic_setup_installs_missing_pinned_roots_when_scope_and_trust_match() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        write_matching_package_scope(package.path(), "https://lpm.dev");
        write_global_signing_trust(home.path(), &pinned_signing_trust(home.path()));

        let outcome =
            ensure_configured_for_install(None, "https://lpm.dev", package.path(), true, true)
                .await
                .unwrap();

        assert_eq!(
            fs::read(built_in_root_path(home.path())).unwrap(),
            built_in_root()
        );
        assert_eq!(
            outcome.to_json(),
            serde_json::json!({
                "scope": "retained",
                "signing_certificate": "repaired",
                "signing_trust": "retained"
            })
        );
    }

    #[tokio::test]
    async fn automatic_setup_against_an_unpinned_registry_requests_no_certificate() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let server = MockServer::start().await;
        write_matching_package_scope(package.path(), &server.uri());

        let outcome = ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(!test_swiftpm_root(home.path()).join("security").exists());
        assert_eq!(
            outcome.to_json(),
            serde_json::json!({
                "scope": "retained",
                "signing_certificate": "retained",
                "signing_trust": "repaired"
            })
        );
    }

    #[tokio::test]
    async fn automatic_setup_adds_a_missing_signing_trust_policy() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let server = MockServer::start().await;
        write_matching_package_scope(package.path(), &server.uri());
        let config_path =
            write_global_signing_trust(home.path(), &serde_json::json!({"version": 1}));

        ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert!(signing::is_applied(
            &repaired,
            "127.0.0.1",
            &SignerTrust::Unpinned
        ));
    }

    #[tokio::test]
    async fn automatic_setup_repairs_incorrect_default_signing_policy() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        write_matching_package_scope(package.path(), "https://lpm.dev");
        let mut trust = pinned_signing_trust(home.path());
        trust["security"]["default"]["signing"]["onUnsigned"] = serde_json::json!("silentAllow");
        let config_path = write_global_signing_trust(home.path(), &trust);

        ensure_configured_for_install(None, "https://lpm.dev", package.path(), true, true)
            .await
            .unwrap();

        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert_eq!(repaired, pinned_signing_trust(home.path()));
    }

    #[tokio::test]
    async fn automatic_setup_retains_complete_unpinned_trust() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        let server = MockServer::start().await;
        write_matching_package_scope(package.path(), &server.uri());
        let config_path = write_global_signing_trust(home.path(), &complete_signing_trust());

        let outcome = ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        let retained: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert_eq!(retained, complete_signing_trust());
        assert_eq!(
            outcome.to_json(),
            serde_json::json!({
                "scope": "retained",
                "signing_certificate": "retained",
                "signing_trust": "retained"
            })
        );
    }

    #[tokio::test]
    async fn automatic_setup_surfaces_a_roots_directory_it_cant_create() {
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        write_matching_package_scope(package.path(), "https://lpm.dev");
        write_global_signing_trust(home.path(), &pinned_signing_trust(home.path()));
        let blocked = test_swiftpm_root(home.path()).join("security/lpm-trusted-roots");
        fs::create_dir_all(blocked.parent().unwrap()).unwrap();
        fs::write(&blocked, "not a directory").unwrap();

        let error =
            ensure_configured_for_install(None, "https://lpm.dev", package.path(), true, true)
                .await
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Can't set up the Swift signing roots"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn automatic_setup_retains_matching_roots_and_complete_trust_without_rewrites() {
        use std::os::unix::fs::MetadataExt;

        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = home_override(home.path());
        write_matching_package_scope(package.path(), "https://lpm.dev");
        let config_path =
            write_global_signing_trust(home.path(), &pinned_signing_trust(home.path()));
        signing::install_roots(&lpm_dev_trust(), false).unwrap();
        let root_inode = fs::metadata(built_in_root_path(home.path())).unwrap().ino();
        let config_inode = fs::metadata(&config_path).unwrap().ino();

        let outcome =
            ensure_configured_for_install(None, "https://lpm.dev", package.path(), true, true)
                .await
                .unwrap();

        assert_eq!(
            fs::metadata(built_in_root_path(home.path())).unwrap().ino(),
            root_inode
        );
        assert_eq!(fs::metadata(config_path).unwrap().ino(), config_inode);
        assert_eq!(
            outcome.to_json(),
            serde_json::json!({
                "scope": "retained",
                "signing_certificate": "retained",
                "signing_trust": "retained"
            })
        );
    }
}
