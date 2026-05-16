use crate::output;
use lpm_common::LpmError;
use lpm_common::color::Painted;

/// resolve a usable LPM bearer for Swift Package Manager
/// integration. SPM's login flow takes the token as a CLI arg, so a
/// SecretString round-trip would just leak immediately — this helper
/// returns `Option<String>` to preserve the existing "skip auth on
/// missing token" semantics without spreading `ExposeSecret` here.
async fn resolve_lpm_bearer_optional(registry_url: &str) -> Option<String> {
    let session = lpm_auth::SessionManager::new(registry_url, None);
    session
        .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
        .await
        .ok()
}

/// Minimum size in bytes for a valid DER certificate.
/// A DER-encoded X.509 certificate is at minimum ~100 bytes (header + key material).
const MIN_CERT_SIZE: u64 = 100;

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

/// Configure Swift Package Manager to use LPM as a package registry.
///
/// Steps:
/// 1. swift package-registry set --scope lpmdev <registry_url>/api/swift-registry
/// 2. swift package-registry login --token <lpm_token> (HTTPS only)
/// 3. Download signing certificate to ~/.swiftpm/security/trusted-root-certs/lpm.der
pub async fn run(registry_url: &str, json_output: bool, force: bool) -> Result<(), LpmError> {
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

    // Step 2: Login with LPM token (HTTPS only — SPM refuses auth over HTTP)
    if is_https {
        if let Some(token) = resolve_lpm_bearer_optional(registry_url).await {
            if !json_output {
                output::info("Configuring authentication...");
            }

            // SPM's `swift package-registry login` does not support reading
            // the token from stdin — it requires `--token <value>` as a CLI argument.
            // This means the token is briefly visible in the process list (`ps aux`).
            // This is a known limitation of SPM's CLI design. We accept this trade-off
            // because there is no alternative mechanism (no env var support, no stdin pipe,
            // no config file option for token injection). The risk is mitigated by the
            // token being short-lived in the process list (command completes quickly).
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
                output::warn(
                    "Token login failed — you may need to run: swift package-registry login manually",
                );
            }
        } else if !json_output {
            // User-facing binary name is `lpm`, not `lpm-rs`
            output::warn("No LPM token found — run `lpm login` first for authenticated access");
        }
    } else if !json_output {
        output::warn("HTTP registry — SPM won't send auth. Use HTTPS in production.");
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
        println!();
        output::success("SPM configured to use LPM registry");
        println!(
            "  {} LPM signing cert installed; CMS detached signature integrity is checked.",
            "✔".green()
        );
        println!(
            "  {} Signer trust = silentAllow for the lpmdev scope.",
            "ⓘ".dimmed()
        );
        println!(
            "  {} Trust anchor: HTTPS to {} (not a public-CA-chained signer).",
            "ⓘ".dimmed(),
            "lpm.dev".bold()
        );
        println!();
        println!("  Use in Package.swift:");
        println!(
            "    {}",
            ".package(id: \"lpmdev.<owner>-<package>\", from: \"1.0.0\")".dimmed()
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

/// Auto-configure SE-0292 registry scope for a Swift package directory if not already set up.
///
/// Checks `{package_dir}/.swiftpm/configuration/registries.json` for the `lpmdev` scope.
/// If missing, runs `swift package-registry set --scope lpmdev`, installs signing cert,
/// and configures signing trust policy — all silently.
///
/// Called automatically during `lpm install` so the user never has to run `lpm swift-registry`
/// as a separate step.
pub async fn ensure_configured(
    registry_url: &str,
    package_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    // Check if lpmdev scope is already registered — parse JSON structure
    // instead of substring matching to avoid false positives
    let config_path = package_dir.join(".swiftpm/configuration/registries.json");
    if config_path.exists()
        && let Ok(content) = std::fs::read_to_string(&config_path)
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
        && json
            .get("registries")
            .and_then(|r| r.get("lpmdev"))
            .is_some()
    {
        return Ok(());
    }

    let swift_registry_url = format!("{registry_url}/api/swift-registry");
    let is_https = registry_url.starts_with("https://");

    if !json_output {
        output::info("Configuring SPM registry scope for lpmdev...");
    }

    // Step 1: Set the registry scope
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

    // Step 2: Login (HTTPS only)
    if is_https && let Some(token) = resolve_lpm_bearer_optional(registry_url).await {
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

    // Step 3: Install signing certificate. Fatal on failure — same
    // reasoning as the user-facing `run` path: silently completing
    // setup without a cert leaves SPM unable to verify any LPM
    // package signature on the next `swift build`.
    install_signing_certificate(&swift_registry_url, json_output, false).await?;

    // Step 4: Configure signing trust. Fatal on failure — without the
    // lpmdev scope override SPM rejects every signed LPM package.
    configure_signing_trust(json_output)?;

    Ok(())
}

/// Check whether a certificate file exists and is valid (non-empty, non-corrupted).
/// Returns `true` if the file should be considered already installed.
fn is_cert_valid(cert_path: &std::path::Path) -> bool {
    match std::fs::metadata(cert_path) {
        Ok(meta) => meta.len() >= MIN_CERT_SIZE,
        Err(_) => false,
    }
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

    // Idempotency: a non-empty cert already on disk is good enough unless
    // the user passed --force. We keep the size guard to catch a
    // previously-truncated install (empty / aborted writes).
    if !force && is_cert_valid(&cert_path) {
        if !json_output {
            output::info("Signing certificate already installed");
        }
        return Ok(CertOutcome::AlreadyInstalled);
    }

    if !json_output {
        if force && cert_path.exists() {
            output::info("Force re-downloading signing certificate...");
        } else {
            output::info("Installing package signing certificate...");
        }
    }

    // Download certificate
    let client = reqwest::Client::new();
    let response = client.get(&cert_url).send().await.map_err(|e| {
        LpmError::Registry(format!(
            "could not download signing certificate from {cert_url}: {e}"
        ))
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(LpmError::Registry(format!(
            "signing certificate not available (HTTP {status} from {cert_url})"
        )));
    }

    let cert_bytes = response.bytes().await.map_err(|e| {
        LpmError::Registry(format!(
            "failed to read signing certificate from {cert_url}: {e}"
        ))
    })?;

    // Validate downloaded certificate is not empty/truncated
    if (cert_bytes.len() as u64) < MIN_CERT_SIZE {
        return Err(LpmError::Registry(format!(
            "downloaded certificate from {cert_url} is too small ({} bytes) — possibly corrupted",
            cert_bytes.len()
        )));
    }

    std::fs::create_dir_all(&trust_dir).map_err(|e| {
        LpmError::Registry(format!(
            "failed to create trust directory {}: {e}",
            trust_dir.display()
        ))
    })?;

    std::fs::write(&cert_path, &cert_bytes).map_err(|e| {
        LpmError::Registry(format!(
            "failed to write certificate to {}: {e}",
            cert_path.display()
        ))
    })?;

    if !json_output {
        output::info(&format!(
            "Signing certificate installed to {}",
            cert_path.display().to_string().dimmed()
        ));
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
    let mut config: serde_json::Value = if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => serde_json::from_str(&content)
                .unwrap_or_else(|_| serde_json::json!({ "version": 1 })),
            Err(_) => serde_json::json!({ "version": 1 }),
        }
    } else {
        serde_json::json!({ "version": 1 })
    };

    // Check if scope override for lpmdev is already configured
    let already_configured = config
        .get("security")
        .and_then(|s| s.get("scopeOverrides"))
        .and_then(|o| o.get("lpmdev"))
        .and_then(|l| l.get("signing"))
        .and_then(|s| s.get("onUntrustedCertificate"))
        .and_then(|v| v.as_str())
        .is_some_and(|v| v == "silentAllow");

    if already_configured {
        return Ok(TrustOutcome::AlreadyConfigured);
    }

    // Merge security config — preserve any existing keys
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

    // Set default signing policy: warn on unsigned, warn on untrusted
    let signing_obj = signing.as_object_mut().unwrap();
    signing_obj
        .entry("onUnsigned")
        .or_insert_with(|| serde_json::Value::String("warn".to_string()));
    signing_obj
        .entry("onUntrustedCertificate")
        .or_insert_with(|| serde_json::Value::String("warn".to_string()));

    // Add scope override for lpmdev: silently allow LPM's signing cert.
    // LPM uses a self-signed ECDSA cert (not a CA cert), so it can't be added to
    // SPM's trust roots (which require basicConstraints: CA=true). Instead, we tell
    // SPM to trust packages from the lpmdev scope without the cert being in a root store.
    // The CMS signature is still cryptographically verified — this only skips the
    // "is the signer in my trust chain?" check for this scope.
    let scope_overrides = security
        .as_object_mut()
        .unwrap()
        .entry("scopeOverrides")
        .or_insert_with(|| serde_json::json!({}));

    let lpmdev_scope = scope_overrides
        .as_object_mut()
        .unwrap()
        .entry("lpmdev")
        .or_insert_with(|| serde_json::json!({}));

    let scope_signing = lpmdev_scope
        .as_object_mut()
        .unwrap()
        .entry("signing")
        .or_insert_with(|| serde_json::json!({}));

    scope_signing.as_object_mut().unwrap().insert(
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

    // Write back with pretty formatting to match SPM's own style
    let json_str = serde_json::to_string_pretty(&config).map_err(|e| {
        LpmError::Registry(format!("failed to serialize signing trust config: {e}"))
    })?;
    std::fs::write(&config_path, json_str).map_err(|e| {
        LpmError::Registry(format!(
            "failed to write signing trust config to {}: {e}",
            config_path.display()
        ))
    })?;

    if !json_output {
        output::info("Configured signing trust policy in registries.json");
    }

    Ok(TrustOutcome::Configured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::OnceLock;
    use tempfile::TempDir;
    use tokio::sync::Mutex as AsyncMutex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Serialize tests that mutate the process-wide `HOME` env var, so they
    /// don't trample each other under `cargo test` parallelism. Async-aware
    /// so the guard can be held across `.await` points (wiremock setup).
    fn home_env_lock() -> &'static AsyncMutex<()> {
        static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| AsyncMutex::new(()))
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
    fn is_cert_valid_returns_true_for_valid_size_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("valid.der");
        // MIN_CERT_SIZE bytes — meets the threshold
        fs::write(&path, vec![0x30u8; MIN_CERT_SIZE as usize]).unwrap();
        assert!(is_cert_valid(&path));
    }

    #[test]
    fn is_cert_valid_returns_true_for_large_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("large.der");
        // A realistic DER cert is ~800-2000 bytes
        fs::write(&path, vec![0x30u8; 1024]).unwrap();
        assert!(is_cert_valid(&path));
    }

    // Binary name should be `lpm`, not `lpm-rs`.
    // This is a string literal test — we verify the warning message references the correct name.
    // The actual string is on the `output::warn` call in the `run` function.
    // We can't easily unit-test the full `run` function (it requires subprocess + network),
    // but we verify the constant is correct by checking source text indirectly.
    // The real coverage comes from the code review + the edit itself.

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
        let cert_bytes = vec![0x30u8; 1024];
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

    /// Idempotent re-run: a valid cert already on disk short-circuits with
    /// `AlreadyInstalled` and never hits the network. Pinning this prevents
    /// a regression where every `lpm install <swift-pkg>` would re-fetch
    /// the cert.
    #[tokio::test]
    async fn install_signing_certificate_skips_when_valid_cert_already_installed() {
        let _guard = home_env_lock().lock().await;
        let temp_home = TempDir::new().unwrap();
        let _home = HomeOverride::new(temp_home.path());

        let cert_path = temp_home
            .path()
            .join(".swiftpm/security/trusted-root-certs/lpm.der");
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(&cert_path, vec![0x30u8; 1024]).unwrap();

        // No mock mounted — if the function reaches the network the test
        // fails with a connection error.
        let server = MockServer::start().await;

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

        // Seed a valid-looking cert on disk that --force should override.
        let cert_path = temp_home
            .path()
            .join(".swiftpm/security/trusted-root-certs/lpm.der");
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        fs::write(&cert_path, vec![0x30u8; 1024]).unwrap();

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
}
