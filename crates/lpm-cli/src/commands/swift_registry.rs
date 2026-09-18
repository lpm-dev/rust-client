mod configuration;

use crate::{auth_storage_notice, install_ui};
use futures::StreamExt;
use lpm_common::LpmError;
use std::path::Path;
use x509_parser::prelude::{FromDer, X509Certificate};

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

/// Minimum size in bytes for a valid DER certificate.
/// A DER-encoded X.509 certificate is at minimum ~100 bytes (header + key material).
const MIN_CERT_SIZE: u64 = 100;
const MAX_CERT_SIZE: usize = 64 * 1024;

/// Result of `install_signing_certificate`. Distinguishes "I downloaded
/// and wrote the cert this run" from "I found a valid one already on
/// disk and skipped"; the call site uses this to decide whether
/// success messaging is meaningful or noisy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertOutcome {
    Installed,
    AlreadyInstalled,
}

/// Result of `configure_signing_trust`. Mirrors `CertOutcome` in shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustOutcome {
    Configured,
    AlreadyConfigured,
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
/// 3. Download signing certificate to ~/.swiftpm/security/trusted-root-certs/lpm.der
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
    let package_dir = manifest.as_deref().and_then(Path::parent).unwrap_or(cwd);
    preflight_configuration(registry_url, package_dir)?;

    if !json_output {
        install_ui::phase_line(swift_package_manager_phase());
    }

    configure_project_scope(package_dir, &endpoint).await?;
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

    // Step 3: Install signing certificate to SPM trust store. Fatal on
    // failure — proceeding without a cert leaves SPM without the bytes
    // it needs to verify the CMS signatures attached to LPM packages.
    let cert_outcome = install_signing_certificate(&swift_registry_url, json_output, force).await?;

    let trust_outcome = configure_signing_trust(registry_url, json_output)?;

    let cert_outcome_label = match cert_outcome {
        CertOutcome::Installed => "installed",
        CertOutcome::AlreadyInstalled => "already_installed",
    };
    let trust_outcome_label = match trust_outcome {
        TrustOutcome::Configured => "configured",
        TrustOutcome::AlreadyConfigured => "already_configured",
    };

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "registry_url": swift_registry_url,
            "scope": "lpmdev",
            "https": is_https,
            "signing_certificate_installed": true,
            "signing_trust_configured": true,
            "signing_certificate_outcome": cert_outcome_label,
            "signing_trust_outcome": trust_outcome_label,
            "trust_anchor": if is_https { "https" } else { "insecure_http" },
            "authentication_outcome": authentication_outcome,
            "signer_trust_policy": "silentAllow",
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        install_ui::done("Done · Swift registry integration is ready");
    }

    Ok(())
}

/// Auto-configure SE-0292 registry scope for a Swift package directory if not already set up.
///
/// Checks `{package_dir}/.swiftpm/configuration/registries.json` for the `lpmdev` scope.
/// If missing, runs `swift package-registry set --scope lpmdev`, installs signing cert,
/// and configures signing trust policy — all silently.
///
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

    let certificate = install_signing_certificate(&swift_registry_url, json_output, false).await?;
    let trust = configure_signing_trust(registry_url, json_output)?;

    Ok(SwiftRegistrySetupOutcome {
        scope_repaired: !scope_matches,
        certificate_repaired: certificate == CertOutcome::Installed,
        trust_repaired: trust == TrustOutcome::Configured,
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

pub(crate) fn preflight_configuration(
    registry_url: &str,
    package_dir: &Path,
) -> Result<(), LpmError> {
    let endpoint = swift_registry_endpoint(registry_url)?;
    let host = swiftpm_registry_host(&endpoint);
    configuration::load(&configuration::global_path()?, host)?;
    configuration::load(
        &package_dir.join(".swiftpm/configuration/registries.json"),
        host,
    )?;
    Ok(())
}

/// Check whether a certificate file exists and is valid (non-empty, non-corrupted).
/// Returns `true` if the file should be considered already installed.
#[cfg(test)]
fn is_cert_valid(cert_path: &std::path::Path) -> bool {
    read_valid_der_certificate(cert_path).is_some()
}

fn read_valid_der_certificate(cert_path: &Path) -> Option<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(cert_path).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_CERT_SIZE as u64
    {
        return None;
    }
    let bytes = lpm_common::read_file_capped(cert_path, MAX_CERT_SIZE as u64).ok()?;
    validate_der_certificate(&bytes).ok()?;
    Some(bytes)
}

fn validate_der_certificate(bytes: &[u8]) -> Result<(), LpmError> {
    if bytes.len() < MIN_CERT_SIZE as usize {
        return Err(LpmError::Registry(format!(
            "certificate is too small ({} bytes)",
            bytes.len()
        )));
    }
    if bytes.len() > MAX_CERT_SIZE {
        return Err(LpmError::Registry(format!(
            "certificate exceeds the {MAX_CERT_SIZE}-byte limit"
        )));
    }
    let (remaining, _) = X509Certificate::from_der(bytes).map_err(|error| {
        LpmError::Registry(format!("certificate is not valid DER X.509: {error}"))
    })?;
    if !remaining.is_empty() {
        return Err(LpmError::Registry(
            "certificate contains trailing data after the DER X.509 object".into(),
        ));
    }
    Ok(())
}

async fn fetch_signing_certificate(cert_url: &str) -> Result<Vec<u8>, LpmError> {
    let client = lpm_http::client_builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| {
            LpmError::Registry(format!(
                "could not build signing certificate client: {error}"
            ))
        })?;
    let response = client.get(cert_url).send().await.map_err(|error| {
        if error.is_timeout() {
            return LpmError::Registry(
                "signing certificate request timed out (10-second connection limit; 30-second overall limit)".into(),
            );
        }
        LpmError::Registry(format!(
            "could not download signing certificate: {}",
            lpm_http::display_error(&error)
        ))
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(LpmError::Registry(format!(
            "signing certificate not available (HTTP {status} from {cert_url})"
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_CERT_SIZE as u64)
    {
        return Err(LpmError::Registry(format!(
            "signing certificate from {cert_url} exceeds the {MAX_CERT_SIZE}-byte limit"
        )));
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(MIN_CERT_SIZE)
            .min(MAX_CERT_SIZE as u64) as usize,
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            if error.is_timeout() {
                return LpmError::Registry(
                    "signing certificate request timed out (10-second connection limit; 30-second overall limit)".into(),
                );
            }
            LpmError::Registry(format!(
                "failed to read signing certificate from {cert_url}: {error}"
            ))
        })?;
        if bytes.len().saturating_add(chunk.len()) > MAX_CERT_SIZE {
            return Err(LpmError::Registry(format!(
                "signing certificate from {cert_url} exceeds the {MAX_CERT_SIZE}-byte limit"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    validate_der_certificate(&bytes).map_err(|error| {
        LpmError::Registry(format!(
            "downloaded signing certificate from {cert_url} is invalid: {error}"
        ))
    })?;
    Ok(bytes)
}

/// Fetch and validate the current certificate before comparing local bytes.
/// Matching bytes avoid a rewrite unless `force` is set. Download or validation
/// failures preserve the existing certificate and stop setup.
async fn install_signing_certificate(
    swift_registry_url: &str,
    json_output: bool,
    force: bool,
) -> Result<CertOutcome, LpmError> {
    let cert_url = format!("{swift_registry_url}/certificate");
    let trust_dir = crate::swift_manifest::paths::security_dir()?.join("trusted-root-certs");

    let cert_path = trust_dir.join("lpm.der");

    let cert_bytes = fetch_signing_certificate(&cert_url).await?;
    let installed_matches = !force
        && read_valid_der_certificate(&cert_path).is_some_and(|installed| installed == cert_bytes);
    if installed_matches {
        if !json_output {
            install_ui::done_line(signing_certificate_already_installed_message(&cert_path));
        }
        return Ok(CertOutcome::AlreadyInstalled);
    }

    if !json_output {
        if force && cert_path.exists() {
            install_ui::phase("Re-downloading package signing certificate");
        } else {
            install_ui::phase("Installing package signing certificate");
        }
    }

    std::fs::create_dir_all(&trust_dir).map_err(|e| {
        LpmError::Registry(format!(
            "failed to create trust directory {}: {e}",
            trust_dir.display()
        ))
    })?;

    lpm_common::write_file_atomic(&cert_path, &cert_bytes).map_err(|e| {
        LpmError::Registry(format!(
            "failed to write certificate to {}: {e}",
            cert_path.display()
        ))
    })?;

    if !json_output {
        install_ui::done_line(signing_certificate_installed_message(&cert_path));
    }

    Ok(CertOutcome::Installed)
}

/// Configure the registry host's HTTPS-anchored signer policy while retaining
/// strict defaults for other registries. SwiftPM only supports signing actions
/// in registry overrides, not scope overrides.
fn configure_signing_trust(
    registry_url: &str,
    json_output: bool,
) -> Result<TrustOutcome, LpmError> {
    let endpoint = swift_registry_endpoint(registry_url)?;
    let host = swiftpm_registry_host(&endpoint);
    let config_path = configuration::global_path()?;
    let changed = configuration::update(&config_path, host, |config| {
        if signing_trust_is_valid(config, host) {
            return Ok(());
        }
        apply_signing_trust(config, host)
    })?;
    if !json_output {
        let message = if changed {
            signing_trust_updated_message(&config_path)
        } else {
            signing_trust_already_configured_message(&config_path)
        };
        install_ui::done_line(message);
    }
    Ok(if changed {
        TrustOutcome::Configured
    } else {
        TrustOutcome::AlreadyConfigured
    })
}

fn apply_signing_trust(
    config: &mut serde_json::Value,
    registry_host: &str,
) -> Result<(), LpmError> {
    let root = ensure_json_object(config)?;
    root.insert("version".to_string(), serde_json::json!(1));
    ensure_json_object(
        root.entry("registries")
            .or_insert_with(|| serde_json::json!({})),
    )?;

    // Merge security config — preserve any existing keys
    let security = ensure_json_object(config)?
        .entry("security")
        .or_insert_with(|| serde_json::json!({}));

    let default = ensure_json_object(security)?
        .entry("default")
        .or_insert_with(|| serde_json::json!({}));

    let signing = ensure_json_object(default)?
        .entry("signing")
        .or_insert_with(|| serde_json::json!({}));
    let signing_obj = ensure_json_object(signing)?;
    repair_default_signing_policy(signing_obj, "onUnsigned");
    repair_default_signing_policy(signing_obj, "onUntrustedCertificate");

    if let Some(scope_signing) = security
        .get_mut("scopeOverrides")
        .and_then(|value| value.get_mut("lpmdev"))
        .and_then(|value| value.get_mut("signing"))
        .and_then(serde_json::Value::as_object_mut)
    {
        scope_signing.remove("onUntrustedCertificate");
    }
    let registry_overrides = ensure_json_object(security)?
        .entry("registryOverrides")
        .or_insert_with(|| serde_json::json!({}));
    let registry = ensure_json_object(registry_overrides)?
        .entry(registry_host)
        .or_insert_with(|| serde_json::json!({}));
    let registry_signing = ensure_json_object(registry)?
        .entry("signing")
        .or_insert_with(|| serde_json::json!({}));
    ensure_json_object(registry_signing)?.insert(
        "onUntrustedCertificate".to_string(),
        serde_json::Value::String("silentAllow".to_string()),
    );

    Ok(())
}

fn ensure_json_object(
    value: &mut serde_json::Value,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, LpmError> {
    value.as_object_mut().ok_or_else(|| {
        LpmError::Registry("Swift signing trust configuration must contain objects".into())
    })
}

fn default_signing_policy_is_secure(value: Option<&serde_json::Value>) -> bool {
    value.and_then(serde_json::Value::as_str) == Some("error")
}

fn repair_default_signing_policy(
    signing: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    if !default_signing_policy_is_secure(signing.get(key)) {
        signing.insert(
            key.to_string(),
            serde_json::Value::String("error".to_string()),
        );
    }
}

fn signing_trust_is_valid(config: &serde_json::Value, registry_host: &str) -> bool {
    if config.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || !config
            .get("registries")
            .is_some_and(serde_json::Value::is_object)
        || config
            .pointer("/security/scopeOverrides/lpmdev/signing/onUntrustedCertificate")
            .is_some()
    {
        return false;
    }
    let signing = config
        .get("security")
        .and_then(|security| security.get("default"))
        .and_then(|default| default.get("signing"));
    let defaults_match =
        default_signing_policy_is_secure(signing.and_then(|value| value.get("onUnsigned")))
            && default_signing_policy_is_secure(
                signing.and_then(|value| value.get("onUntrustedCertificate")),
            );
    let override_matches = config
        .get("security")
        .and_then(|s| s.get("registryOverrides"))
        .and_then(|o| o.get(registry_host))
        .and_then(|l| l.get("signing"))
        .and_then(|s| s.get("onUntrustedCertificate"))
        .and_then(|v| v.as_str())
        .is_some_and(|v| v == "silentAllow");
    defaults_match && override_matches
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

fn signing_certificate_installed_message(cert_path: &Path) -> install_ui::TerminalLine {
    let home = dirs::home_dir();
    signing_certificate_installed_message_with_home(cert_path, home.as_deref())
}

fn signing_certificate_installed_message_with_home(
    cert_path: &Path,
    home: Option<&Path>,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "Installed signing certificate {}",
        display_home_relative_with(cert_path, home)
    )
}

fn signing_certificate_already_installed_message(cert_path: &Path) -> install_ui::TerminalLine {
    let home = dirs::home_dir();
    signing_certificate_already_installed_message_with_home(cert_path, home.as_deref())
}

fn signing_certificate_already_installed_message_with_home(
    cert_path: &Path,
    home: Option<&Path>,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "Signing certificate already installed {}",
        display_home_relative_with(cert_path, home)
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
    use std::sync::OnceLock;
    use tempfile::TempDir;
    use tokio::sync::Mutex as AsyncMutex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn valid_der_certificate() -> Vec<u8> {
        rcgen::generate_simple_self_signed(vec!["lpm.dev".to_string()])
            .unwrap()
            .cert
            .der()
            .to_vec()
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
            home.join("Library/org.swift.swiftpm")
        } else if cfg!(windows) {
            home.join("swiftpm-test-config/swiftpm")
        } else {
            home.join(".swiftpm")
        }
    }

    fn write_global_signing_trust(home: &Path, config: &serde_json::Value) -> PathBuf {
        let config_path = test_swiftpm_root(home).join("configuration/registries.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, serde_json::to_vec(config).unwrap()).unwrap();
        config_path
    }

    #[tokio::test]
    async fn native_platform_configuration_is_validated_instead_of_an_unused_legacy_file() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let xdg = home.path().join("xdg");
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
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
        assert!(configure_signing_trust("https://lpm.dev", true).is_err());
        assert_eq!(
            fs::read_to_string(config).unwrap(),
            "invalid native configuration"
        );
        assert!(!home.path().join(".swiftpm").exists());
    }

    #[tokio::test]
    async fn signing_configuration_rejects_invalid_shapes_without_replacing_bytes() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
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
        ];
        let mut accepted = Vec::new();
        for original in cases {
            fs::write(&path, original).unwrap();
            let result = configure_signing_trust("https://lpm.dev", true);
            if result.is_ok() || fs::read_to_string(&path).unwrap() != original {
                accepted.push(original);
            } else {
                assert!(
                    result
                        .err()
                        .unwrap()
                        .to_string()
                        .contains(path.to_str().unwrap())
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
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
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
        configure_signing_trust("https://lpm.dev", true).unwrap();
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
            "silentAllow"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signing_configuration_rejects_symlinks_without_replacing_them() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let path = write_global_signing_trust(home.path(), &serde_json::json!({}));
        let target = home.path().join("shared.json");
        fs::rename(&path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(configure_signing_trust("https://lpm.dev", true).is_err());
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
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
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
                    configure_signing_trust(&format!("https://registry{index}.example"), true)
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
    async fn automatic_setup_rejects_invalid_configuration_before_certificate_changes() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        write_matching_package_scope(package.path(), &server.uri());
        let path = write_global_signing_trust(home.path(), &serde_json::json!({}));
        fs::write(&path, "broken json").unwrap();
        let certificate = signing_certificate_path(home.path());
        fs::create_dir_all(certificate.parent().unwrap()).unwrap();
        fs::write(&certificate, "existing certificate").unwrap();
        Mock::given(method("GET"))
            .and(wiremock::matchers::path("/api/swift-registry/certificate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(valid_der_certificate()))
            .mount(&server)
            .await;
        let result =
            ensure_configured_for_install(None, &server.uri(), package.path(), true, true).await;
        assert!(result.is_err(), "invalid configuration must stop setup");
        assert_eq!(fs::read_to_string(path).unwrap(), "broken json");
        assert_eq!(
            fs::read_to_string(certificate).unwrap(),
            "existing certificate"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    fn signing_certificate_path(home: &Path) -> PathBuf {
        test_swiftpm_root(home).join("security/trusted-root-certs/lpm.der")
    }

    async fn mount_signing_certificate(server: &MockServer, certificate: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path("/api/swift-registry/certificate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(certificate))
            .expect(1)
            .mount(server)
            .await;
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
        let _guard = home_env_lock().lock().await;
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
        configure_signing_trust("https://[::1]:8443", true).unwrap();
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
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
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
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
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
        let _guard = home_env_lock().lock().await;
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
        let _lock = home_env_lock().lock().await;
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
        let _lock = home_env_lock().lock().await;
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
    async fn anonymous_https_setup_skips_rejected_credentials_but_requires_certificate_verification()
     {
        let _lock = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
            ("PATH", Some(path)),
            ("XDG_CONFIG_HOME", None),
            ("LPM_TOKEN", None),
        ]);
        let registry_url = "https://127.0.0.1:1";
        write_matching_package_scope(package.path(), registry_url);
        let session = lpm_auth::SessionManager::new(registry_url, Some("rejected-access".into()));
        let error =
            ensure_configured_for_install(Some(&session), registry_url, package.path(), true, true)
                .await
                .expect_err("unreachable certificate endpoint must prevent setup");
        assert!(!home.path().join("swift-login-tokens").exists());
        assert!(error.to_string().contains("certificate"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn automatic_setup_reports_swiftpm_login_failure() {
        let _lock = home_env_lock().lock().await;
        let server = MockServer::start().await;
        let home = TempDir::new().expect("create isolated home");
        let package = TempDir::new().expect("create Swift package directory");
        let login_tokens = home.path().join("swift-login-tokens");
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
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
        let _lock = home_env_lock().lock().await;
        let server = MockServer::start().await;
        let registry_url = server.uri().replacen("http://", "https://", 1);
        let home = TempDir::new().expect("create isolated home");
        let package = TempDir::new().expect("create Swift package directory");
        write_matching_package_scope(package.path(), &registry_url);
        let login_tokens = home.path().join("swift-login-tokens");
        let path = fake_swift_path(home.path());
        let _environment = crate::test_env::ScopedEnv::update([
            ("HOME", Some(home.path().as_os_str().to_owned())),
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
    fn home_env_lock() -> &'static AsyncMutex<()> {
        static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| AsyncMutex::new(()))
    }

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

    /// RAII override of `HOME`. Drop restores the prior value (or removes
    /// the var if there was none). Must be held alongside `home_env_lock()`.
    struct HomeOverride {
        prior: Option<std::ffi::OsString>,
        prior_xdg: Option<std::ffi::OsString>,
    }

    impl HomeOverride {
        fn new(home: &std::path::Path) -> Self {
            let prior = std::env::var_os("HOME");
            let prior_xdg = std::env::var_os("XDG_CONFIG_HOME");
            // SAFETY: caller holds home_env_lock(), serializing env mutation
            // across the test module.
            unsafe {
                std::env::set_var("HOME", home);
                if cfg!(windows) {
                    std::env::set_var("XDG_CONFIG_HOME", home.join("swiftpm-test-config"));
                } else {
                    std::env::remove_var("XDG_CONFIG_HOME");
                }
            };
            HomeOverride { prior, prior_xdg }
        }
    }

    impl Drop for HomeOverride {
        fn drop(&mut self) {
            // SAFETY: still inside the home_env_lock()-protected section.
            unsafe {
                match &self.prior_xdg {
                    Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                    None => std::env::remove_var("XDG_CONFIG_HOME"),
                }
                match &self.prior {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    // Cert idempotency should check file size, not just existence.
    // An empty or very small file should NOT be considered a valid certificate.

    #[test]
    fn is_cert_valid_returns_false_for_nonexistent_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.der");
        assert!(!is_cert_valid(&path));
    }

    #[test]
    fn is_cert_valid_returns_false_for_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.der");
        fs::write(&path, b"").unwrap();
        assert!(!is_cert_valid(&path));
    }

    #[test]
    fn is_cert_valid_returns_false_for_truncated_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("small.der");
        // 50 bytes is well below the MIN_CERT_SIZE threshold
        fs::write(&path, vec![0u8; 50]).unwrap();
        assert!(!is_cert_valid(&path));
    }

    #[test]
    fn is_cert_valid_rejects_plausibly_sized_malformed_der() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("malformed.der");
        fs::write(&path, vec![0x30u8; MIN_CERT_SIZE as usize]).unwrap();
        assert!(!is_cert_valid(&path));
    }

    #[test]
    fn is_cert_valid_accepts_a_complete_x509_der_certificate() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("valid.der");
        fs::write(&path, valid_der_certificate()).unwrap();
        assert!(is_cert_valid(&path));
    }

    #[test]
    fn is_cert_valid_rejects_an_oversized_certificate_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oversized.der");
        fs::write(&path, vec![0x30; MAX_CERT_SIZE + 1]).unwrap();
        assert!(!is_cert_valid(&path));
    }

    #[cfg(unix)]
    #[test]
    fn is_cert_valid_rejects_a_certificate_symlink() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.der");
        let path = dir.path().join("linked.der");
        fs::write(&target, valid_der_certificate()).unwrap();
        symlink(target, &path).unwrap();
        assert!(!is_cert_valid(&path));
    }

    #[test]
    fn swift_registry_slim_messages_match_design_copy() {
        let home = std::path::PathBuf::from("/Users/example");
        let cert_path = home.join(".swiftpm/security/trusted-root-certs/lpm.der");
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
            display_home_relative_with(&cert_path, Some(&home)),
            "~/.swiftpm/security/trusted-root-certs/lpm.der"
        );
        assert_eq!(
            signing_certificate_installed_message_with_home(&cert_path, Some(&home)).to_string(),
            "Installed signing certificate ~/.swiftpm/security/trusted-root-certs/lpm.der"
        );
        assert_eq!(
            signing_trust_updated_message_with_home(&config_path, Some(&home)).to_string(),
            "Updated ~/.swiftpm/configuration/registries.json"
        );
    }

    #[test]
    fn signing_trust_preserves_existing_authentication_configuration() {
        let _guard = home_env_lock().blocking_lock();
        let home = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let config = serde_json::json!({
            "version": 1,
            "authentication": {
                "lpm.dev": { "loginAPIPath": "/api/swift-registry", "type": "token" }
            },
            "registries": {}
        });
        let path = write_global_signing_trust(home.path(), &config);
        configure_signing_trust("https://lpm.dev", true).unwrap();
        let updated: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(updated["authentication"], config["authentication"]);
    }

    /// First-run cert install must fail-closed when the registry returns
    /// a non-2xx for the cert endpoint. Pre-fix this returned `false` and
    /// the wider `lpm swift-registry` flow continued, printing
    /// `"success": true` with `signing_certificate_installed: false` —
    /// users with an off-line origin would think setup was done.
    #[tokio::test]
    async fn install_signing_certificate_errors_on_http_404() {
        let _guard = home_env_lock().lock().await;
        let temp_home = TempDir::new().unwrap();
        let _home = HomeOverride::new(temp_home.path());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/swift-registry/certificate"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let result = install_signing_certificate(
            &format!("{}/api/swift-registry", server.uri()),
            true, // json_output — silence stdout for tests
            false,
        )
        .await;

        let err = result.expect_err("404 from cert endpoint must be fatal");
        let msg = err.to_string();
        assert!(
            msg.contains("HTTP 404") || msg.contains("not available"),
            "error should name the HTTP failure mode, got: {msg:?}"
        );
    }

    /// First-run cert install must fail-closed when the body is below
    /// the minimum cert size (truncated, empty, or HTML error page).
    /// Same justification as the 404 case.
    #[tokio::test]
    async fn install_signing_certificate_errors_on_truncated_body() {
        let _guard = home_env_lock().lock().await;
        let temp_home = TempDir::new().unwrap();
        let _home = HomeOverride::new(temp_home.path());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/swift-registry/certificate"))
            // 32 bytes — well below MIN_CERT_SIZE.
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 32]))
            .expect(1)
            .mount(&server)
            .await;

        let result = install_signing_certificate(
            &format!("{}/api/swift-registry", server.uri()),
            true,
            false,
        )
        .await;

        let err = result.expect_err("truncated cert body must be fatal");
        assert!(
            err.to_string().contains("too small"),
            "error should call out the size guard, got: {err}"
        );
    }

    /// Happy path: a server returning a plausibly-sized DER blob lands at
    /// `~/.swiftpm/security/trusted-root-certs/lpm.der` and reports
    /// `CertOutcome::Installed`.
    #[tokio::test]
    async fn install_signing_certificate_writes_cert_to_swiftpm_trust_store() {
        let _guard = home_env_lock().lock().await;
        let temp_home = TempDir::new().unwrap();
        let _home = HomeOverride::new(temp_home.path());

        let server = MockServer::start().await;
        let cert_bytes = valid_der_certificate();
        Mock::given(method("GET"))
            .and(path("/api/swift-registry/certificate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cert_bytes.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = install_signing_certificate(
            &format!("{}/api/swift-registry", server.uri()),
            true,
            false,
        )
        .await
        .expect("first install should succeed against a healthy origin");

        assert_eq!(outcome, CertOutcome::Installed);
        let cert_path =
            test_swiftpm_root(temp_home.path()).join("security/trusted-root-certs/lpm.der");
        let written = fs::read(&cert_path).expect("cert should land at the SPM trust path");
        assert_eq!(written, cert_bytes);
    }

    /// Idempotent re-run verifies the Registry's current certificate and
    /// retains matching local bytes without rewriting them.
    #[tokio::test]
    async fn install_signing_certificate_skips_when_valid_cert_already_installed() {
        let _guard = home_env_lock().lock().await;
        let temp_home = TempDir::new().unwrap();
        let _home = HomeOverride::new(temp_home.path());

        let cert_path =
            test_swiftpm_root(temp_home.path()).join("security/trusted-root-certs/lpm.der");
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        let cert_bytes = valid_der_certificate();
        fs::write(&cert_path, &cert_bytes).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/swift-registry/certificate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(cert_bytes))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = install_signing_certificate(
            &format!("{}/api/swift-registry", server.uri()),
            true,
            false,
        )
        .await
        .expect("idempotent re-run should not fail");

        assert_eq!(outcome, CertOutcome::AlreadyInstalled);
    }

    /// `--force` must re-fetch the cert even when a valid one is on disk
    /// (so a user can rotate the cert deliberately) AND must propagate
    /// download failure as `Err` even though a stale cert exists.
    /// Silently keeping the stale cert and reporting "success" would
    /// defeat the explicit re-fetch the user asked for.
    #[tokio::test]
    async fn install_signing_certificate_force_propagates_download_failure() {
        let _guard = home_env_lock().lock().await;
        let temp_home = TempDir::new().unwrap();
        let _home = HomeOverride::new(temp_home.path());

        // Seed a valid cert on disk that --force should override.
        let cert_path =
            test_swiftpm_root(temp_home.path()).join("security/trusted-root-certs/lpm.der");
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(&cert_path, valid_der_certificate()).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/swift-registry/certificate"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let result = install_signing_certificate(
            &format!("{}/api/swift-registry", server.uri()),
            true,
            true, // force
        )
        .await;

        let err = result.expect_err(
            "--force download failure must be fatal even when a stale cert exists on disk",
        );
        assert!(err.to_string().contains("503") || err.to_string().contains("not available"));
    }

    /// `configure_signing_trust` writes the registry silentAllow
    /// override into a fresh `~/.swiftpm/configuration/registries.json`.
    /// Pin the produced shape so the trust-anchor docs and the file
    /// contents stay aligned.
    #[test]
    fn configure_signing_trust_writes_registry_override_for_lpm_host() {
        let _guard = home_env_lock().blocking_lock();
        let temp_home = TempDir::new().unwrap();
        let _home = HomeOverride::new(temp_home.path());

        let outcome =
            configure_signing_trust("https://lpm.dev", true).expect("trust config should succeed");
        assert_eq!(outcome, TrustOutcome::Configured);

        let config_path = test_swiftpm_root(temp_home.path()).join("configuration/registries.json");
        let content = fs::read_to_string(&config_path).expect("registries.json should be written");
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            json["security"]["registryOverrides"]["lpm.dev"]["signing"]["onUntrustedCertificate"]
                .as_str(),
            Some("silentAllow"),
            "registry host must pin onUntrustedCertificate=silentAllow"
        );

        // Idempotent re-run on the same registries.json reports
        // AlreadyConfigured, no rewrite.
        let outcome2 = configure_signing_trust("https://lpm.dev", true)
            .expect("idempotent re-run should succeed");
        assert_eq!(outcome2, TrustOutcome::AlreadyConfigured);
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
    async fn automatic_setup_repairs_a_missing_certificate_when_scope_and_trust_match() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        let certificate = valid_der_certificate();
        mount_signing_certificate(&server, certificate.clone()).await;
        write_matching_package_scope(package.path(), &server.uri());
        write_global_signing_trust(home.path(), &complete_signing_trust());

        ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        assert_eq!(
            fs::read(signing_certificate_path(home.path())).unwrap(),
            certificate
        );
    }

    #[tokio::test]
    async fn automatic_setup_replaces_a_malformed_local_certificate() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        let certificate = valid_der_certificate();
        mount_signing_certificate(&server, certificate.clone()).await;
        write_matching_package_scope(package.path(), &server.uri());
        write_global_signing_trust(home.path(), &complete_signing_trust());
        let cert_path = signing_certificate_path(home.path());
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(&cert_path, vec![0x30; MIN_CERT_SIZE as usize]).unwrap();

        ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        assert_eq!(fs::read(cert_path).unwrap(), certificate);
    }

    #[tokio::test]
    async fn automatic_setup_replaces_a_stale_but_valid_local_certificate() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        let expected = valid_der_certificate();
        let stale = valid_der_certificate();
        assert_ne!(stale, expected);
        mount_signing_certificate(&server, expected.clone()).await;
        write_matching_package_scope(package.path(), &server.uri());
        write_global_signing_trust(home.path(), &complete_signing_trust());
        let cert_path = signing_certificate_path(home.path());
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(&cert_path, stale).unwrap();

        ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        assert_eq!(fs::read(cert_path).unwrap(), expected);
    }

    #[tokio::test]
    async fn automatic_setup_adds_a_missing_signing_trust_policy() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        let certificate = valid_der_certificate();
        mount_signing_certificate(&server, certificate.clone()).await;
        write_matching_package_scope(package.path(), &server.uri());
        let config_path =
            write_global_signing_trust(home.path(), &serde_json::json!({"version": 1}));
        let cert_path = signing_certificate_path(home.path());
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(cert_path, certificate).unwrap();

        ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert!(signing_trust_is_valid(&repaired, "127.0.0.1"));
    }

    #[tokio::test]
    async fn automatic_setup_repairs_incorrect_default_signing_policy() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        let certificate = valid_der_certificate();
        mount_signing_certificate(&server, certificate.clone()).await;
        write_matching_package_scope(package.path(), &server.uri());
        let mut trust = complete_signing_trust();
        trust["security"]["default"]["signing"]["onUnsigned"] = serde_json::json!("silentAllow");
        let config_path = write_global_signing_trust(home.path(), &trust);
        let cert_path = signing_certificate_path(home.path());
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(cert_path, certificate).unwrap();

        ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert!(signing_trust_is_valid(&repaired, "127.0.0.1"));
        assert_eq!(
            repaired["security"]["default"]["signing"]["onUnsigned"],
            "error"
        );
    }

    #[tokio::test]
    async fn automatic_setup_retains_stricter_default_signing_policies() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        let certificate = valid_der_certificate();
        mount_signing_certificate(&server, certificate.clone()).await;
        write_matching_package_scope(package.path(), &server.uri());
        let mut trust = complete_signing_trust();
        trust["security"]["default"]["signing"]["onUnsigned"] = serde_json::json!("error");
        trust["security"]["default"]["signing"]["onUntrustedCertificate"] =
            serde_json::json!("error");
        let config_path = write_global_signing_trust(home.path(), &trust);
        let cert_path = signing_certificate_path(home.path());
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(cert_path, certificate).unwrap();

        let outcome = ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        let retained: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert_eq!(
            retained["security"]["default"]["signing"]["onUnsigned"],
            "error"
        );
        assert_eq!(
            retained["security"]["default"]["signing"]["onUntrustedCertificate"],
            "error"
        );
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
    async fn automatic_setup_surfaces_certificate_repair_failure() {
        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        mount_signing_certificate(&server, valid_der_certificate()).await;
        write_matching_package_scope(package.path(), &server.uri());
        write_global_signing_trust(home.path(), &complete_signing_trust());
        let blocked_directory = test_swiftpm_root(home.path()).join("security/trusted-root-certs");
        fs::create_dir_all(blocked_directory.parent().unwrap()).unwrap();
        fs::write(&blocked_directory, "not a directory").unwrap();

        let error = ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("failed to create trust directory"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn automatic_setup_retains_matching_certificate_and_complete_trust_without_rewrites() {
        use std::os::unix::fs::MetadataExt;

        let _guard = home_env_lock().lock().await;
        let home = TempDir::new().unwrap();
        let package = TempDir::new().unwrap();
        let _home = HomeOverride::new(home.path());
        let server = MockServer::start().await;
        let certificate = valid_der_certificate();
        mount_signing_certificate(&server, certificate.clone()).await;
        write_matching_package_scope(package.path(), &server.uri());
        let config_path = write_global_signing_trust(home.path(), &complete_signing_trust());
        let cert_path = signing_certificate_path(home.path());
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(&cert_path, certificate).unwrap();
        let cert_inode = fs::metadata(&cert_path).unwrap().ino();
        let config_inode = fs::metadata(&config_path).unwrap().ino();

        let outcome = ensure_configured(None, &server.uri(), package.path(), true)
            .await
            .unwrap();

        assert_eq!(fs::metadata(cert_path).unwrap().ino(), cert_inode);
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
