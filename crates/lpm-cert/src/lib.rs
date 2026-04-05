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

/// Write sensitive key material to a file with restricted permissions (0o600) from creation.
///
/// On Unix, the file is created with mode 0o600 atomically via `OpenOptionsExt::mode()`,
/// eliminating the TOCTOU window where the file would be world-readable.
/// On non-Unix, falls back to `std::fs::write` (no permission control available).
#[cfg(unix)]
fn write_key_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Remove existing file first so create_new succeeds on regeneration
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

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
        let (ca_cert_pem, ca_key_pem) =
            ca::generate_ca().map_err(|e| LpmError::Cert(format!("failed to generate CA: {e}")))?;

        std::fs::create_dir_all(&ca_dir)
            .map_err(|e| LpmError::Cert(format!("failed to create cert dir: {e}")))?;

        let cert_path = paths::ca_cert_path()?;
        let key_path = paths::ca_key_path()?;

        std::fs::write(&cert_path, &ca_cert_pem)
            .map_err(|e| LpmError::Cert(format!("failed to write CA cert: {e}")))?;
        write_key_file(&key_path, ca_key_pem.as_bytes())
            .map_err(|e| LpmError::Cert(format!("failed to write CA key: {e}")))?;

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

    let cert_freshly_generated =
        if !proj_cert_path.exists() || cert::needs_renewal(&proj_cert_path)? {
            tracing::info!("generating project certificate...");
            std::fs::create_dir_all(&project_cert_dir)
                .map_err(|e| LpmError::Cert(format!("failed to create project cert dir: {e}")))?;

            let ca_cert_pem = std::fs::read_to_string(paths::ca_cert_path()?)
                .map_err(|e| LpmError::Cert(format!("failed to read CA cert: {e}")))?;
            let ca_key_pem = std::fs::read_to_string(paths::ca_key_path()?)
                .map_err(|e| LpmError::Cert(format!("failed to read CA key: {e}")))?;

            let (cert_pem, key_pem) =
                cert::generate_project_cert(&ca_cert_pem, &ca_key_pem, extra_hostnames)
                    .map_err(|e| LpmError::Cert(format!("failed to generate project cert: {e}")))?;

            std::fs::write(&proj_cert_path, &cert_pem)
                .map_err(|e| LpmError::Cert(format!("failed to write project cert: {e}")))?;
            write_key_file(&proj_key_path, key_pem.as_bytes())
                .map_err(|e| LpmError::Cert(format!("failed to write project key: {e}")))?;

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

    let (project_cert_expires, project_cert_hostnames, project_cert_needs_renewal) =
        if project_cert_exists {
            let info = cert::read_cert_info(&proj_cert_path).ok();
            let needs_renewal = cert::needs_renewal(&proj_cert_path).unwrap_or(true);
            (
                info.as_ref().map(|i| i.not_after.clone()),
                info.as_ref()
                    .map(|i| i.san_entries.clone())
                    .unwrap_or_default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_key_file_creates_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        write_key_file(&key_path, b"secret-key-material").unwrap();

        // Verify the file was created with the correct permissions immediately
        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "key file should be created with 0o600 permissions, got 0o{mode:o}"
        );

        // Verify contents were written correctly
        let contents = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(contents, "secret-key-material");
    }

    #[cfg(unix)]
    #[test]
    fn write_key_file_not_world_or_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test2.key");

        write_key_file(&key_path, b"another-secret").unwrap();

        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;

        // No group read/write/execute
        assert_eq!(mode & 0o070, 0, "key file should not be group-accessible");
        // No other read/write/execute
        assert_eq!(mode & 0o007, 0, "key file should not be world-accessible");
    }

    #[cfg(unix)]
    #[test]
    fn write_key_file_overwrites_existing() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("overwrite.key");

        // Write initial file
        write_key_file(&key_path, b"first-key").unwrap();

        // Overwrite with new content (simulates key regeneration)
        write_key_file(&key_path, b"second-key").unwrap();

        let contents = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(contents, "second-key");

        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn status_with_no_certs_reports_nothing_exists() {
        let project_dir = tempfile::tempdir().unwrap();
        // status() reads from ~/.lpm/certs (global) and {project}/.lpm/certs (local).
        // The project dir has no certs, so project_cert_exists should be false.
        let result = status(project_dir.path()).unwrap();
        assert!(!result.project_cert_exists);
        assert!(result.project_cert_hostnames.is_empty());
        assert!(!result.project_cert_needs_renewal);
    }

    #[test]
    fn status_with_project_cert_reports_exists() {
        let project_dir = tempfile::tempdir().unwrap();
        let cert_dir = project_dir.path().join(".lpm").join("certs");
        std::fs::create_dir_all(&cert_dir).unwrap();

        // Generate a CA and project cert to seed the project directory
        let (ca_cert, ca_key) = ca::generate_ca().unwrap();
        let (proj_cert, proj_key) = cert::generate_project_cert(&ca_cert, &ca_key, &[]).unwrap();

        std::fs::write(cert_dir.join("cert.pem"), &proj_cert).unwrap();
        write_key_file(&cert_dir.join("key.pem"), proj_key.as_bytes()).unwrap();

        let result = status(project_dir.path()).unwrap();
        assert!(result.project_cert_exists);
        assert!(!result.project_cert_needs_renewal);
        // Default SANs: localhost, 127.0.0.1, ::1 (shown in x509-parser format)
        assert!(
            !result.project_cert_hostnames.is_empty(),
            "expected SANs, got empty list"
        );
        assert!(
            result
                .project_cert_hostnames
                .iter()
                .any(|s| s.contains("localhost")),
            "expected localhost in SANs, got {:?}",
            result.project_cert_hostnames
        );
    }

    #[test]
    fn full_cert_generation_integration() {
        // Generate CA → generate project cert signed by CA → verify chain
        let (ca_cert_pem, ca_key_pem) = ca::generate_ca().unwrap();

        // Generate project cert with extra hostnames
        let extra = vec!["myapp.local".to_string(), "192.168.1.42".to_string()];
        let (cert_pem, _key_pem) =
            cert::generate_project_cert(&ca_cert_pem, &ca_key_pem, &extra).unwrap();

        // Write to temp and read back
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();

        let info = cert::read_cert_info(&cert_path).unwrap();
        // SAN entries from x509-parser use format like "DNS:localhost", "IP:..." or hex
        assert!(
            info.san_entries.iter().any(|s| s.contains("localhost")),
            "missing localhost in SANs: {:?}",
            info.san_entries
        );
        assert!(
            info.san_entries.iter().any(|s| s.contains("myapp.local")),
            "missing myapp.local in SANs: {:?}",
            info.san_entries
        );
        assert!(
            info.san_entries.len() >= 5,
            "expected at least 5 SANs (3 default + 2 extra), got {:?}",
            info.san_entries
        );
        assert!(!cert::needs_renewal(&cert_path).unwrap());
    }

    #[test]
    fn framework_env_integration_with_cert_paths() {
        // Test the full flow: detect_and_get_env with real paths
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            project_dir.path().join("package.json"),
            r#"{"devDependencies":{"@sveltejs/kit":"^2.0.0"}}"#,
        )
        .unwrap();

        let env = framework::detect_and_get_env(
            project_dir.path(),
            "/path/to/cert.pem",
            "/path/to/key.pem",
        );

        // SvelteKit should get Vite cert env vars (our fix)
        assert!(
            env.iter().any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_CERT"),
            "SvelteKit should include VITE_DEV_SERVER_HTTPS_CERT, got: {env:?}"
        );
        assert!(
            env.iter().any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_KEY"),
            "SvelteKit should include VITE_DEV_SERVER_HTTPS_KEY, got: {env:?}"
        );
    }
}
