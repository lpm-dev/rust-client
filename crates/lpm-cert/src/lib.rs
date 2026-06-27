//! LPM certificate management for local HTTPS development.
//!
//! Provides zero-config HTTPS for local development by:
//! 1. Generating a root CA (one-time, stored in `~/.lpm/certs/`)
//! 2. Installing it in the system trust store
//! 3. Generating per-project certificates signed by that CA
//! 4. Detecting the dev framework and injecting the right env vars

pub mod audit;
pub mod ca;
pub mod cert;
pub mod framework;
pub mod name_constraints;
pub mod paths;
pub mod projects;
pub mod reconcile;
pub mod rotate;
pub mod trust;

use lpm_common::LpmError;
use std::path::Path;

pub(crate) fn test_env_overrides_enabled() -> bool {
    cfg!(debug_assertions)
}

/// Write sensitive key material to a file with restricted permissions (0o600) from creation.
///
/// On Unix, the existing file (if any) is removed before `create_new` opens it with
/// mode 0o600. This is the contract callers depend on: a stale 0o644 file from an
/// earlier broken install gets replaced, not truncated-in-place with its old mode kept.
/// `OpenOptionsExt::mode()` only applies on create — `truncate(true)` over an existing
/// file would silently preserve the old permission bits.
/// On non-Unix, falls back to `std::fs::write` (no permission control available).
#[cfg(unix)]
pub fn write_key_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

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
pub fn write_key_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// Static label for the platform's trust store, used as the `store` field in audit
/// events. Lowercase + kebab to match the strings logged by other LPM subsystems.
pub fn trust_store_label() -> &'static str {
    if test_env_overrides_enabled() && std::env::var_os("LPM_CERT_TEST_TRUST_STORE_DIR").is_some() {
        return "test";
    }
    #[cfg(target_os = "macos")]
    {
        "macos-login"
    }
    #[cfg(target_os = "linux")]
    {
        "linux-ca-certificates"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-root"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "unknown"
    }
}

/// Days remaining until the CA at `path` expires. `Some(0)` for already-expired,
/// `None` only if the cert can't be read or parsed.
pub fn ca_days_until_expiry(path: &Path) -> Option<i64> {
    let pem_str = std::fs::read_to_string(path).ok()?;
    let pem = pem::parse(&pem_str).ok()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(pem.contents()).ok()?;
    let not_after = parsed.validity().not_after.to_datetime();
    let now = time::OffsetDateTime::now_utc();
    let days = (not_after - now).whole_days();
    Some(days.max(0))
}

/// Describes a permission-mode drift on a sensitive cert artifact.
#[derive(Debug, Clone)]
pub struct PermissionDrift {
    /// Path of the drifted artifact (CA key, CA dir, etc.).
    pub path: std::path::PathBuf,
    /// Mode bits actually observed on disk (`& 0o777`).
    pub actual_mode: u32,
    /// What we require for this artifact.
    pub expected_mode: u32,
    /// Human-readable label of the artifact role.
    pub role: &'static str,
}

impl PermissionDrift {
    /// One-line summary of the drift suitable for warnings and `lpm cert status`.
    pub fn summary(&self) -> String {
        format!(
            "{role} at {path} has mode 0o{actual:o}, expected 0o{expected:o}",
            role = self.role,
            path = self.path.display(),
            actual = self.actual_mode,
            expected = self.expected_mode,
        )
    }
    /// chmod command line the user can copy-paste to fix the drift.
    pub fn chmod_hint(&self) -> String {
        format!(
            "chmod {expected:o} {path}",
            expected = self.expected_mode,
            path = self.path.display(),
        )
    }
}

/// Audit the on-disk CA key, the CA dir, and the audit log dir for permission
/// drift on Unix. Returns one entry per drifted artifact; empty `Vec` if clean.
/// On non-Unix, always returns `Ok(vec![])` (modes don't apply).
pub fn audit_cert_permissions() -> Result<Vec<PermissionDrift>, LpmError> {
    #[cfg(not(unix))]
    let out: Vec<PermissionDrift> = Vec::new();
    #[cfg(unix)]
    let mut out: Vec<PermissionDrift> = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fn drift_if<P: AsRef<std::path::Path>>(
            path: P,
            expected: u32,
            role: &'static str,
            out: &mut Vec<PermissionDrift>,
        ) -> Result<(), LpmError> {
            let p = path.as_ref();
            if !p.exists() {
                return Ok(());
            }
            let mode = std::fs::metadata(p)
                .map_err(|e| LpmError::Cert(format!("stat {} failed: {e}", p.display())))?
                .permissions()
                .mode()
                & 0o777;
            if mode != expected {
                out.push(PermissionDrift {
                    path: p.to_path_buf(),
                    actual_mode: mode,
                    expected_mode: expected,
                    role,
                });
            }
            Ok(())
        }

        drift_if(paths::ca_dir()?, 0o700, "cert dir", &mut out)?;
        drift_if(paths::ca_key_path()?, 0o600, "CA private key", &mut out)?;
        let audit_dir = audit::audit_log_path()?.parent().map(|p| p.to_path_buf());
        if let Some(dir) = audit_dir {
            drift_if(dir, 0o700, "audit dir", &mut out)?;
        }
        drift_if(audit::audit_log_path()?, 0o600, "audit log", &mut out)?;
    }
    Ok(out)
}

/// Returns the first key-file drift if `ca_key_path()` is group- or world-readable.
/// Used by `ensure_https` to refuse signing with a leaky key.
pub fn ca_key_drift() -> Result<Option<PermissionDrift>, LpmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = paths::ca_key_path()?;
        if !key.exists() {
            return Ok(None);
        }
        let mode = std::fs::metadata(&key)
            .map_err(|e| LpmError::Cert(format!("stat {} failed: {e}", key.display())))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Ok(Some(PermissionDrift {
                path: key,
                actual_mode: mode,
                expected_mode: 0o600,
                role: "CA private key",
            }));
        }
    }
    Ok(None)
}

/// Log a yellow `warn` at <60d and a red `error` at <30d remaining. Never
/// auto-rotates — the user is the consent boundary for trust-store mutations.
pub fn warn_if_ca_expiring_soon(path: &Path) {
    let Some(days) = ca_days_until_expiry(path) else {
        return;
    };
    if days < 30 {
        tracing::error!(
            target: "lpm_cert",
            "root CA at {} expires in {days} day(s). Run `lpm cert rotate` to roll it.",
            path.display()
        );
    } else if days < 60 {
        tracing::warn!(
            target: "lpm_cert",
            "root CA at {} expires in {days} day(s). Plan a rotation with `lpm cert rotate`.",
            path.display()
        );
    }
}

/// Create `path` (parents included) and tighten its mode to `0o700` on Unix.
///
/// The mode is reapplied every call, not only at creation, because a pre-H11 install may
/// have left the dir at `0o755`. On non-Unix the mode call is a no-op and the
/// user-profile ACL governs access.
pub fn create_dir_secure(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Caller-supplied callback that renders the consent UI and returns the user's
/// decision. Lives in `lpm-cli` so the CA crate doesn't depend on cliclack.
pub type ConsentCallback<'a> = Box<dyn FnOnce(&ConsentRequest) -> Result<bool, LpmError> + 'a>;

/// Whether `ensure_https_with_consent` may install the CA into the OS trust store.
pub enum TrustStoreConsent<'a> {
    /// Install without prompting. Caller has already gathered consent
    /// (e.g. `lpm cert trust`, or `lpm dev --https --yes`).
    PreApproved,
    /// Never install. Generate the CA files on disk if missing, but stop short
    /// of pushing into the trust store. Used by `lpm cert generate`.
    Decline,
    /// Prompt the user via the supplied callback. The callback returns `Ok(true)`
    /// to install or `Ok(false)` to decline.
    Prompt(ConsentCallback<'a>),
}

impl<'a> std::fmt::Debug for TrustStoreConsent<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustStoreConsent::PreApproved => write!(f, "PreApproved"),
            TrustStoreConsent::Decline => write!(f, "Decline"),
            TrustStoreConsent::Prompt(_) => write!(f, "Prompt(<callback>)"),
        }
    }
}

fn resolve_consent(consent: TrustStoreConsent<'_>, ca_path: &Path) -> Result<bool, LpmError> {
    match consent {
        TrustStoreConsent::PreApproved => Ok(true),
        TrustStoreConsent::Decline => Ok(false),
        TrustStoreConsent::Prompt(callback) => {
            let info = cert::read_cert_info(ca_path)?;
            let mut permitted = vec![
                "localhost".to_string(),
                "*.local".to_string(),
                "*.test".to_string(),
                "127.0.0.0/8".to_string(),
                "RFC1918 private IPs".to_string(),
                "::1".to_string(),
            ];
            if !ca::wants_name_constraints() {
                permitted = vec![
                    "any (no name constraints — set LPM_CERT_NAME_CONSTRAINTS=1 to scope)".into(),
                ];
            }
            let req = ConsentRequest {
                fingerprint: cert::fingerprint_hex(&cert::fingerprint_sha256(ca_path)?),
                expires: info.not_after,
                permitted_names: permitted,
                name_constraints_enabled: ca::wants_name_constraints(),
            };
            callback(&req)
        }
    }
}

/// Information shown to the user when asking for trust-store consent.
#[derive(Debug, Clone)]
pub struct ConsentRequest {
    pub fingerprint: String,
    pub expires: String,
    pub permitted_names: Vec<String>,
    pub name_constraints_enabled: bool,
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
    ensure_https_with_consent(project_dir, extra_hostnames, TrustStoreConsent::PreApproved)
}

/// Full-control variant of `ensure_https` exposing the trust-store consent decision.
pub fn ensure_https_with_consent(
    project_dir: &Path,
    extra_hostnames: &[String],
    consent: TrustStoreConsent<'_>,
) -> Result<HttpsSetup, LpmError> {
    ensure_https_with_consent_and_permitted_dns(project_dir, extra_hostnames, &[], consent)
}

/// Full-control variant of `ensure_https` that also permits validated
/// project DNS subtrees on the constrained intermediate.
pub fn ensure_https_with_consent_and_permitted_dns(
    project_dir: &Path,
    extra_hostnames: &[String],
    extra_permitted_dns_subtrees: &[String],
    consent: TrustStoreConsent<'_>,
) -> Result<HttpsSetup, LpmError> {
    let ca_dir = paths::ca_dir()?;
    let project_cert_dir = paths::project_cert_dir(project_dir)?;

    if ca_dir.exists() || !paths::ca_cert_path()?.exists() {
        create_dir_secure(&ca_dir)
            .map_err(|e| LpmError::Cert(format!("failed to secure cert dir: {e}")))?;
    }

    let ca_freshly_installed = if !paths::ca_cert_path()?.exists() {
        tracing::info!("generating root CA...");
        let (ca_cert_pem, ca_key_pem) =
            ca::generate_ca().map_err(|e| LpmError::Cert(format!("failed to generate CA: {e}")))?;

        let cert_path = paths::ca_cert_path()?;
        let key_path = paths::ca_key_path()?;

        std::fs::write(&cert_path, &ca_cert_pem)
            .map_err(|e| LpmError::Cert(format!("failed to write CA cert: {e}")))?;
        write_key_file(&key_path, ca_key_pem.as_bytes())
            .map_err(|e| LpmError::Cert(format!("failed to write CA key: {e}")))?;

        let fp = cert::fingerprint_sha256(&cert_path)?;
        let fp_hex = cert::fingerprint_hex(&fp);
        audit::append_best_effort(audit::AuditAction::CaGenerate {
            fingerprint: fp_hex.clone(),
            validity_days: ca::CA_VALIDITY_DAYS,
            name_constraints: ca::wants_name_constraints(),
        });

        let approved = resolve_consent(consent, &cert_path)?;
        if approved {
            tracing::info!("installing CA into system trust store...");
            match trust::install_ca(&cert_path) {
                Ok(()) => {
                    audit::append_best_effort(audit::AuditAction::CaTrustInstall {
                        fingerprint: fp_hex,
                        store: trust_store_label(),
                        status: audit::AuditStatus::Ok,
                        error: None,
                    });
                }
                Err(e) => {
                    audit::append_best_effort(audit::AuditAction::CaTrustInstall {
                        fingerprint: fp_hex,
                        store: trust_store_label(),
                        status: audit::AuditStatus::Error,
                        error: Some(e.to_string()),
                    });
                    return Err(LpmError::Cert(format!("failed to install CA: {e}")));
                }
            }
        } else {
            tracing::warn!(
                "trust-store install declined; CA files are on disk at {} but browsers will not trust them until you run `lpm cert trust`",
                cert_path.display()
            );
        }

        approved
    } else {
        let cert_path = paths::ca_cert_path()?;
        if let Some(drift) = ca_key_drift()? {
            return Err(LpmError::Cert(format!(
                "{}. Refusing to sign with a group-/world-readable private key. Fix with: {}",
                drift.summary(),
                drift.chmod_hint()
            )));
        }
        if ca::wants_name_constraints() && !ca::cert_has_name_constraints(&cert_path)? {
            tracing::warn!(
                target: "lpm_cert",
                "LPM_CERT_NAME_CONSTRAINTS is set but the installed CA at {} predates this build and has no name constraints. Run `lpm cert rotate` to replace it with a constrained CA.",
                cert_path.display()
            );
        }
        warn_if_ca_expiring_soon(&cert_path);
        if !trust::is_ca_installed(&cert_path)? {
            let approved = resolve_consent(consent, &cert_path)?;
            if approved {
                tracing::info!("CA exists but not trusted, installing...");
                let fp_hex = cert::fingerprint_hex(&cert::fingerprint_sha256(&cert_path)?);
                match trust::install_ca(&cert_path) {
                    Ok(()) => {
                        audit::append_best_effort(audit::AuditAction::CaTrustInstall {
                            fingerprint: fp_hex,
                            store: trust_store_label(),
                            status: audit::AuditStatus::Ok,
                            error: None,
                        });
                    }
                    Err(e) => {
                        audit::append_best_effort(audit::AuditAction::CaTrustInstall {
                            fingerprint: fp_hex,
                            store: trust_store_label(),
                            status: audit::AuditStatus::Error,
                            error: Some(e.to_string()),
                        });
                        return Err(LpmError::Cert(format!("failed to install CA: {e}")));
                    }
                }
            } else {
                tracing::warn!(
                    "trust-store install declined; browsers will not trust certificates signed by {}",
                    cert_path.display()
                );
            }
        }
        false
    };

    let active_ca_cert = paths::ca_cert_path()?;
    let proj_cert_path = project_cert_dir.join("cert.pem");
    let proj_key_path = project_cert_dir.join("key.pem");
    let needs_project_intermediate =
        !extra_hostnames.is_empty() || !extra_permitted_dns_subtrees.is_empty();

    let needs_reissue_chain_mismatch = proj_cert_path.exists()
        && !cert::project_cert_chains_to_root(&proj_cert_path, &active_ca_cert).unwrap_or(false);
    let needs_reissue_for_project_intermediate = needs_project_intermediate
        && proj_cert_path.exists()
        && !cert::project_cert_has_intermediate(&proj_cert_path).unwrap_or(false);
    let needs_reissue_for_project_constraints = needs_project_intermediate
        && proj_cert_path.exists()
        && !cert::project_cert_constraints_cover_dns(
            &proj_cert_path,
            extra_hostnames,
            extra_permitted_dns_subtrees,
        )
        .unwrap_or(false);

    let cert_freshly_generated = if !proj_cert_path.exists()
        || needs_reissue_chain_mismatch
        || needs_reissue_for_project_intermediate
        || needs_reissue_for_project_constraints
        || cert::needs_renewal(&proj_cert_path)?
        || !cert::covers_requested_hostnames(&proj_cert_path, extra_hostnames)?
    {
        if needs_reissue_chain_mismatch {
            tracing::info!(
                "project leaf at {} no longer chains to the active CA; re-issuing",
                proj_cert_path.display()
            );
        } else if needs_reissue_for_project_intermediate {
            tracing::info!(
                "project leaf at {} needs a constrained project intermediate for custom hostnames; re-issuing",
                proj_cert_path.display()
            );
        } else if needs_reissue_for_project_constraints {
            tracing::info!(
                "project leaf at {} needs updated project DNS constraints; re-issuing",
                proj_cert_path.display()
            );
        } else {
            tracing::info!("generating project certificate...");
        }
        std::fs::create_dir_all(&project_cert_dir)
            .map_err(|e| LpmError::Cert(format!("failed to create project cert dir: {e}")))?;

        let ca_cert_pem = std::fs::read_to_string(&active_ca_cert)
            .map_err(|e| LpmError::Cert(format!("failed to read CA cert: {e}")))?;
        let ca_key_pem = std::fs::read_to_string(paths::ca_key_path()?)
            .map_err(|e| LpmError::Cert(format!("failed to read CA key: {e}")))?;

        let (cert_pem, key_pem) = if needs_project_intermediate {
            if !ca::cert_allows_project_intermediates(&active_ca_cert)? {
                return Err(LpmError::Cert(
                    "active LPM root CA cannot sign project-scoped constrained intermediates \
                     because its pathLenConstraint is 0. Run `lpm cert rotate`, then retry."
                        .into(),
                ));
            }
            cert::generate_project_cert_with_constrained_intermediate(
                &ca_cert_pem,
                &ca_key_pem,
                extra_hostnames,
                extra_permitted_dns_subtrees,
            )
        } else {
            cert::generate_project_cert(&ca_cert_pem, &ca_key_pem, extra_hostnames)
        }
        .map_err(|e| LpmError::Cert(format!("failed to generate project cert: {e}")))?;

        std::fs::write(&proj_cert_path, &cert_pem)
            .map_err(|e| LpmError::Cert(format!("failed to write project cert: {e}")))?;
        write_key_file(&proj_key_path, key_pem.as_bytes())
            .map_err(|e| LpmError::Cert(format!("failed to write project key: {e}")))?;

        true
    } else {
        false
    };

    if let Err(e) = projects::record(project_dir) {
        tracing::debug!("failed to record project in cert-projects index: {e}");
    }

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
    fn create_dir_secure_sets_0700_on_fresh_dir() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("certs");

        create_dir_secure(&target).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "newly-created cert dir should be 0o700, got 0o{mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_secure_tightens_pre_existing_dir() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("certs");

        // Simulate a pre-H11 install: dir already exists at 0o755.
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();

        create_dir_secure(&target).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "existing cert dir should be re-tightened to 0o700, got 0o{mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_key_file_tightens_stale_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("stale.key");

        std::fs::write(&key_path, b"stale-contents").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        write_key_file(&key_path, b"fresh-contents").unwrap();

        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "overwriting a pre-existing key file must reset mode to 0o600, got 0o{mode:o}"
        );
        let contents = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(contents, "fresh-contents");
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
