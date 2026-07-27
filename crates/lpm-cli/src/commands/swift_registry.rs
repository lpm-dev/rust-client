use crate::{auth_storage_notice, install_ui};
use futures::StreamExt;
use lpm_common::LpmError;
use std::path::Path;
use x509_parser::prelude::{FromDer, X509Certificate};

/// resolve a usable LPM bearer for Swift Package Manager
/// integration. SPM's login flow takes the token as a CLI arg, so a
/// SecretString round-trip would just leak immediately — this helper
/// returns `Option<String>` to preserve the existing "skip auth on
/// missing token" semantics without spreading `ExposeSecret` here.
async fn resolve_lpm_bearer_optional(registry_url: &str, json_output: bool) -> Option<String> {
    let session = auth_storage_notice::attach(
        lpm_auth::SessionManager::new(registry_url, None),
        json_output,
    );
    session
        .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
        .await
        .ok()
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
/// 2. swift package-registry login --token <lpm_token> (HTTPS only)
/// 3. Download signing certificate to ~/.swiftpm/security/trusted-root-certs/lpm.der
pub async fn run(registry_url: &str, json_output: bool, force: bool) -> Result<(), LpmError> {
    // H20: refuse to globally install SwiftPM signing trust for a
    // registry URL that fails the same gating contract used for
    // LPM_REGISTRY_URL itself (H16). HTTPS is accepted for any host
    // (legitimate private mirror / on-prem appliance); HTTP only for
    // loopback (workflow tests against wiremock). Plain HTTP non-
    // loopback was previously passed straight to SwiftPM with
    // `--allow-insecure-http`, which then installed `lpm.der` into
    // `~/.swiftpm/security/trusted-root-certs/` and silently allowed
    // every `lpmdev` Swift package to be signed against whatever
    // cert that registry served. That's a persistent SwiftPM trust
    // downgrade that survives across LPM sessions. Refuse upfront.
    if !lpm_common::lpm_registry_url_is_accepted(registry_url) {
        return Err(LpmError::Registry(format!(
            "swift-registry setup refuses to install global SwiftPM signing trust against {registry_url}: only https:// (any host) or http:// loopback URLs are accepted (H20). Pass an https:// registry URL or unset LPM_REGISTRY_URL."
        )));
    }

    let swift_registry_url = format!("{registry_url}/api/swift-registry");
    let is_https = registry_url.starts_with("https://");

    if !json_output {
        install_ui::phase_line(swift_package_manager_phase());
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

    // Use tokio::process::Command instead of std::process::Command
    // to avoid blocking the async runtime thread.
    // When json_output is true, suppress subprocess stdout/stderr
    // to avoid interleaving with our JSON output.
    let step1_result = if json_output {
        tokio::process::Command::new("swift")
            .args(&args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .status()
            .await
    } else {
        tokio::process::Command::new("swift")
            .args(&args)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .await
    };

    let status = step1_result.map_err(|e| {
        LpmError::Registry(format!(
            "failed to run swift command: {e}. Is Swift installed?"
        ))
    })?;

    if !status.success() {
        return Err(LpmError::Registry(
            "swift package-registry set failed".into(),
        ));
    }
    if !json_output {
        install_ui::done_line(scope_set_message(&swift_registry_url));
    }

    // Step 2: Login with LPM token (HTTPS only — SPM refuses auth over HTTP)
    if is_https {
        if let Some(token) = resolve_lpm_bearer_optional(registry_url, json_output).await {
            if !json_output {
                install_ui::phase("Configuring authentication");
            }

            // SPM's `swift package-registry login` does not support reading
            // the token from stdin — it requires `--token <value>` as a CLI argument.
            // This means the token is briefly visible in the process list (`ps aux`).
            // This is a known limitation of SPM's CLI design. We accept this trade-off
            // because there is no alternative mechanism (no env var support, no stdin pipe,
            // no config file option for token injection). The risk is mitigated by the
            // token being short-lived in the process list (command completes quickly).
            //
            // H19: surface the argv-leak window via tracing::warn so a same-host
            // observer scanning logs after a swift-registry setup sees the explicit
            // trust posture (instead of having to read source). The warn lands on
            // stderr regardless of --json so CI / agent runs also see it.
            tracing::warn!(
                target: "lpm_cli::swift_registry",
                "swift package-registry login passes the LPM bearer via `--token <value>` in process argv — token is briefly observable to same-host processes via `ps`. SPM has no stdin/env/config alternative; accepted trade-off documented in code."
            );
            let login_result = if json_output {
                tokio::process::Command::new("swift")
                    .args([
                        "package-registry",
                        "login",
                        &swift_registry_url,
                        "--token",
                        &token,
                        "--no-confirm",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .status()
                    .await
            } else {
                tokio::process::Command::new("swift")
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
                    .await
            };

            let login_status =
                login_result.map_err(|e| LpmError::Registry(format!("swift login failed: {e}")))?;

            if !login_status.success() {
                install_ui::warn(
                    "Token login failed — you may need to run: swift package-registry login manually",
                );
            } else if !json_output {
                install_ui::done("Authentication configured");
            }
        } else if !json_output {
            // User-facing binary name is `lpm`, not `lpm-rs`
            install_ui::warn(
                "No LPM.dev Registry token found — run `lpm login` first for authenticated access",
            );
        }
    } else if !json_output {
        install_ui::warn("HTTP registry — SPM won't send auth. Use HTTPS in production.");
    }

    // Step 3: Install signing certificate to SPM trust store. Fatal on
    // failure — proceeding without a cert leaves SPM without the bytes
    // it needs to verify the CMS signatures attached to LPM packages.
    let cert_outcome = install_signing_certificate(&swift_registry_url, json_output, force).await?;

    // Step 4: Configure signing trust policy in registries.json. Fatal
    // on failure — without the lpmdev scope override, SPM rejects every
    // signed LPM package as "untrusted signer" because the cert is
    // self-signed and not a CA root.
    let trust_outcome = configure_signing_trust(json_output)?;

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
            // Trust-model honesty: signer authentication is bypassed for
            // the lpmdev scope (silentAllow); the trust anchor is the
            // HTTPS connection to the LPM registry, not a cert chain.
            // See docs/packages/swift-package-registry.mdx.
            "trust_anchor": "https",
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

/// Inspect `registries.json` and classify the state of the `lpmdev`
/// scope. Pure, no IO failure leaks: any read/parse error is treated
/// as `Absent` (the caller does a fresh setup, which produces a
/// correct registry config).
fn evaluate_existing_lpmdev_scope(
    config_path: &std::path::Path,
    expected_url: &str,
) -> Result<ExistingScope, LpmError> {
    let content = match lpm_common::read_text_file_capped(
        config_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Ok(ExistingScope::Absent);
        }
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Ok(ExistingScope::Absent);
    };
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
    registry_url: &str,
    package_dir: &std::path::Path,
    json_output: bool,
) -> Result<SwiftRegistrySetupOutcome, LpmError> {
    if !lpm_common::lpm_registry_url_is_accepted(registry_url) {
        return Err(LpmError::Registry(format!(
            "automatic Swift registry setup refuses {registry_url}: only https:// URLs or http:// loopback URLs are accepted"
        )));
    }
    let swift_registry_url = format!("{registry_url}/api/swift-registry");
    let is_https = registry_url.starts_with("https://");

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

        let status = tokio::process::Command::new("swift")
            .args(&args)
            .current_dir(package_dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .status()
            .await
            .map_err(|e| LpmError::Registry(format!("failed to run swift: {e}")))?;

        if !status.success() {
            return Err(LpmError::Registry(
                "Failed to configure SPM registry scope. Run `lpm swift-registry` manually.".into(),
            ));
        }
        if !json_output {
            install_ui::done_line(scope_set_message(&swift_registry_url));
        }

        if is_https
            && let Some(token) = resolve_lpm_bearer_optional(registry_url, json_output).await
        {
            let _ = tokio::process::Command::new("swift")
                .args([
                    "package-registry",
                    "login",
                    &swift_registry_url,
                    "--token",
                    &token,
                    "--no-confirm",
                ])
                .current_dir(package_dir)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
        }
    }

    let certificate = install_signing_certificate(&swift_registry_url, json_output, false).await?;
    let trust = configure_signing_trust(json_output)?;

    Ok(SwiftRegistrySetupOutcome {
        scope_repaired: !scope_matches,
        certificate_repaired: certificate == CertOutcome::Installed,
        trust_repaired: trust == TrustOutcome::Configured,
    })
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
    let client = lpm_http::client_builder().build().map_err(|error| {
        LpmError::Registry(format!(
            "could not build signing certificate client: {error}"
        ))
    })?;
    let response = client.get(cert_url).send().await.map_err(|error| {
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

/// Download the LPM signing certificate and install to SPM's trust store.
///
/// Idempotent: a valid cert already on disk short-circuits with
/// `CertOutcome::AlreadyInstalled`. Failures (network, HTTP, mkdir,
/// disk write, or a downloaded cert that fails the minimum-size guard)
/// surface as `Err(LpmError::Registry(...))` so the caller — `run` for
/// the user-facing setup, `ensure_configured` for the auto-setup path
/// from `lpm install` — can fail-closed instead of completing with
/// silently-broken signing.
///
/// `--force` bypasses idempotency: even with a valid cert on disk,
/// the cert is re-downloaded so a server-side rotation can be picked
/// up. A failed re-download with `--force` is fatal even if the old
/// cert is still on disk — staying on the stale cert without telling
/// the user would defeat the purpose of `--force`.
async fn install_signing_certificate(
    swift_registry_url: &str,
    json_output: bool,
    force: bool,
) -> Result<CertOutcome, LpmError> {
    let cert_url = format!("{swift_registry_url}/certificate");
    let trust_dir = dirs::home_dir()
        .map(|h| h.join(".swiftpm/security/trusted-root-certs"))
        .ok_or_else(|| {
            LpmError::Registry(
                "Could not determine home directory for certificate installation".into(),
            )
        })?;

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

/// Configure SPM's signing trust policy in ~/.swiftpm/configuration/registries.json.
///
/// Two distinct concerns this function addresses:
///
/// 1. The registries.json `security.default.signing` defaults so SPM has a
///    base policy (warn on unsigned, warn on untrusted-cert) rather than the
///    SPM default of strict.
/// 2. A scope override pinning `lpmdev` to `onUntrustedCertificate = "silentAllow"`.
///    LPM's signing cert is a self-signed, non-CA, code-signing-only cert; SPM
///    rejects it as a trust root because trust roots must have
///    basicConstraints CA=true. The override tells SPM "trust packages from
///    the lpmdev scope without the cert being in a system trust store" —
///    the CMS detached signature is still cryptographically verified, but
///    signer authentication is anchored in HTTPS to lpm.dev rather than a
///    cert chain. See docs/infra/secrets-vault.mdx and
///    docs/packages/swift-package-registry.mdx for the trust-model rationale.
///
/// Idempotent — already-configured registries.json files short-circuit with
/// `TrustOutcome::AlreadyConfigured`. Mkdir / write failures surface as
/// `Err(LpmError::Registry(...))`; without the registries.json side, SPM
/// would reject every signed package the cert covers, so silent failure is
/// not an acceptable mode here.
fn configure_signing_trust(json_output: bool) -> Result<TrustOutcome, LpmError> {
    let home = dirs::home_dir().ok_or_else(|| {
        LpmError::Registry(
            "could not determine home directory for SPM signing trust configuration".into(),
        )
    })?;

    let config_path = home.join(".swiftpm/configuration/registries.json");

    // Read existing config or start fresh
    let mut config: serde_json::Value = match lpm_common::read_text_file_capped(
        &config_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => {
            serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({ "version": 1 }))
        }
        Err(lpm_common::BoundedReadError::NotFound { .. }) => serde_json::json!({ "version": 1 }),
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };

    // Check if scope override for lpmdev is already configured
    let already_configured = signing_trust_is_valid(&config);

    if already_configured {
        if !json_output {
            install_ui::done_line(signing_trust_already_configured_message(&config_path));
        }
        return Ok(TrustOutcome::AlreadyConfigured);
    }

    if !config.is_object() {
        config = serde_json::json!({ "version": 1 });
    }

    // Merge security config — preserve any existing keys
    let security = ensure_json_object(&mut config)?
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

    let scope_overrides = ensure_json_object(security)?
        .entry("scopeOverrides")
        .or_insert_with(|| serde_json::json!({}));
    let lpmdev_scope = ensure_json_object(scope_overrides)?
        .entry("lpmdev")
        .or_insert_with(|| serde_json::json!({}));
    let scope_signing = ensure_json_object(lpmdev_scope)?
        .entry("signing")
        .or_insert_with(|| serde_json::json!({}));
    ensure_json_object(scope_signing)?.insert(
        "onUntrustedCertificate".to_string(),
        serde_json::Value::String("silentAllow".to_string()),
    );

    // Ensure the parent dir exists — first install on a fresh machine
    // typically has no `~/.swiftpm/configuration/`.
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            LpmError::Registry(format!(
                "failed to create SPM configuration directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    let json_str = serde_json::to_string_pretty(&config).map_err(|e| {
        LpmError::Registry(format!("failed to serialize signing trust config: {e}"))
    })?;
    lpm_common::write_file_atomic(&config_path, json_str).map_err(|e| {
        LpmError::Registry(format!(
            "failed to write signing trust config to {}: {e}",
            config_path.display()
        ))
    })?;

    if !json_output {
        install_ui::done_line(signing_trust_updated_message(&config_path));
    }

    Ok(TrustOutcome::Configured)
}

fn ensure_json_object(
    value: &mut serde_json::Value,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, LpmError> {
    if !value.is_object() {
        *value = serde_json::Value::Object(serde_json::Map::new());
    }
    value.as_object_mut().ok_or_else(|| {
        LpmError::Registry("failed to normalize Swift signing trust configuration".into())
    })
}

fn default_signing_policy_is_secure(value: Option<&serde_json::Value>) -> bool {
    matches!(
        value.and_then(serde_json::Value::as_str),
        Some("warn" | "error")
    )
}

fn repair_default_signing_policy(
    signing: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    if !default_signing_policy_is_secure(signing.get(key)) {
        signing.insert(
            key.to_string(),
            serde_json::Value::String("warn".to_string()),
        );
    }
}

fn signing_trust_is_valid(config: &serde_json::Value) -> bool {
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
        .and_then(|s| s.get("scopeOverrides"))
        .and_then(|o| o.get("lpmdev"))
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
            "security": {
                "default": {
                    "signing": {
                        "onUnsigned": "warn",
                        "onUntrustedCertificate": "warn"
                    }
                },
                "scopeOverrides": {
                    "lpmdev": {
                        "signing": {
                            "onUntrustedCertificate": "silentAllow"
                        }
                    }
                }
            }
        })
    }

    fn write_global_signing_trust(home: &Path, config: &serde_json::Value) -> PathBuf {
        let config_path = home.join(".swiftpm/configuration/registries.json");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, serde_json::to_vec(config).unwrap()).unwrap();
        config_path
    }

    fn signing_certificate_path(home: &Path) -> PathBuf {
        home.join(".swiftpm/security/trusted-root-certs/lpm.der")
    }

    async fn mount_signing_certificate(server: &MockServer, certificate: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path("/api/swift-registry/certificate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(certificate))
            .expect(1)
            .mount(server)
            .await;
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
    }

    impl HomeOverride {
        fn new(home: &std::path::Path) -> Self {
            let prior = std::env::var_os("HOME");
            // SAFETY: caller holds home_env_lock(), serializing env mutation
            // across the test module.
            unsafe { std::env::set_var("HOME", home) };
            HomeOverride { prior }
        }
    }

    impl Drop for HomeOverride {
        fn drop(&mut self) {
            // SAFETY: still inside the home_env_lock()-protected section.
            unsafe {
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

    // configure_signing_trust tests use the real home dir, so we test the
    // serialization/merge logic on mock JSON structures instead.
    #[test]
    fn signing_trust_config_merges_into_existing_json() {
        let mut config = serde_json::json!({
            "version": 1,
            "authentication": {
                "lpm.dev": { "loginAPIPath": "/api/swift-registry", "type": "token" }
            },
            "registries": {}
        });

        // Simulate the merge logic from configure_signing_trust
        let security = config
            .as_object_mut()
            .unwrap()
            .entry("security")
            .or_insert_with(|| serde_json::json!({}));
        let default = security
            .as_object_mut()
            .unwrap()
            .entry("default")
            .or_insert_with(|| serde_json::json!({}));
        let signing = default
            .as_object_mut()
            .unwrap()
            .entry("signing")
            .or_insert_with(|| serde_json::json!({}));
        signing
            .as_object_mut()
            .unwrap()
            .entry("onUnsigned")
            .or_insert_with(|| serde_json::Value::String("warn".into()));

        let scope_overrides = security
            .as_object_mut()
            .unwrap()
            .entry("scopeOverrides")
            .or_insert_with(|| serde_json::json!({}));
        let lpmdev = scope_overrides
            .as_object_mut()
            .unwrap()
            .entry("lpmdev")
            .or_insert_with(|| serde_json::json!({}));
        let scope_signing = lpmdev
            .as_object_mut()
            .unwrap()
            .entry("signing")
            .or_insert_with(|| serde_json::json!({}));
        scope_signing.as_object_mut().unwrap().insert(
            "onUntrustedCertificate".into(),
            serde_json::Value::String("silentAllow".into()),
        );

        // Existing keys preserved
        assert_eq!(config["version"], 1);
        assert_eq!(
            config["authentication"]["lpm.dev"]["type"].as_str(),
            Some("token")
        );

        // Default signing policy added
        assert_eq!(
            config["security"]["default"]["signing"]["onUnsigned"].as_str(),
            Some("warn")
        );

        // Scope override for lpmdev added
        assert_eq!(
            config["security"]["scopeOverrides"]["lpmdev"]["signing"]["onUntrustedCertificate"]
                .as_str(),
            Some("silentAllow")
        );
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
        let cert_path = temp_home
            .path()
            .join(".swiftpm/security/trusted-root-certs/lpm.der");
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

        let cert_path = temp_home
            .path()
            .join(".swiftpm/security/trusted-root-certs/lpm.der");
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
        let cert_path = temp_home
            .path()
            .join(".swiftpm/security/trusted-root-certs/lpm.der");
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

    /// `configure_signing_trust` writes the lpmdev silentAllow scope
    /// override into a fresh `~/.swiftpm/configuration/registries.json`.
    /// Pin the produced shape so the trust-anchor docs and the file
    /// contents stay aligned.
    #[test]
    fn configure_signing_trust_writes_scope_override_for_lpmdev() {
        let _guard = home_env_lock().blocking_lock();
        let temp_home = TempDir::new().unwrap();
        let _home = HomeOverride::new(temp_home.path());

        let outcome = configure_signing_trust(true).expect("trust config should succeed");
        assert_eq!(outcome, TrustOutcome::Configured);

        let config_path = temp_home
            .path()
            .join(".swiftpm/configuration/registries.json");
        let content = fs::read_to_string(&config_path).expect("registries.json should be written");
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            json["security"]["scopeOverrides"]["lpmdev"]["signing"]["onUntrustedCertificate"]
                .as_str(),
            Some("silentAllow"),
            "lpmdev scope must pin onUntrustedCertificate=silentAllow"
        );

        // Idempotent re-run on the same registries.json reports
        // AlreadyConfigured, no rewrite.
        let outcome2 = configure_signing_trust(true).expect("idempotent re-run should succeed");
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

    /// Malformed JSON / missing `url` field — fall through to fresh
    /// setup. Treating a corrupted file as "matching" would honour
    /// whatever happened to be on disk; treating it as Absent forces
    /// the setup to write the correct URL.
    #[test]
    fn scope_eval_handles_malformed_or_partial_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registries.json");

        std::fs::write(&path, "not json").unwrap();
        assert_eq!(
            evaluate_existing_lpmdev_scope(&path, "https://lpm.dev/api/swift-registry").unwrap(),
            ExistingScope::Absent
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

        ensure_configured(&server.uri(), package.path(), true)
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

        ensure_configured(&server.uri(), package.path(), true)
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

        ensure_configured(&server.uri(), package.path(), true)
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

        ensure_configured(&server.uri(), package.path(), true)
            .await
            .unwrap();

        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert!(signing_trust_is_valid(&repaired));
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

        ensure_configured(&server.uri(), package.path(), true)
            .await
            .unwrap();

        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
        assert!(signing_trust_is_valid(&repaired));
        assert_eq!(
            repaired["security"]["default"]["signing"]["onUnsigned"],
            "warn"
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

        let outcome = ensure_configured(&server.uri(), package.path(), true)
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
        let blocked_directory = home.path().join(".swiftpm/security/trusted-root-certs");
        fs::create_dir_all(blocked_directory.parent().unwrap()).unwrap();
        fs::write(&blocked_directory, "not a directory").unwrap();

        let error = ensure_configured(&server.uri(), package.path(), true)
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

        let outcome = ensure_configured(&server.uri(), package.path(), true)
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
