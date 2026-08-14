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

pub use paths::RuntimeCertificateLease;

use lpm_common::LpmError;
use std::path::Path;

pub(crate) fn test_env_overrides_enabled() -> bool {
    cfg!(debug_assertions)
}

#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Atomically replace sensitive key material with owner-only permissions on Unix.
pub fn write_key_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    paths::write_sensitive_file(path, contents)
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

/// Result of generating and installing the machine-local root CA.
#[derive(Debug)]
pub struct TrustCaResult {
    /// Root certificate path.
    pub cert_path: std::path::PathBuf,
    /// Whether this operation generated a new root pair.
    pub generated: bool,
}

/// Generate the root pair when absent and install the certificate into the OS
/// trust store as one serialized machine-wide operation.
pub fn trust_ca() -> Result<TrustCaResult, LpmError> {
    let operation = paths::CertificateOperation::begin()?;
    trust_ca_locked(&operation.ca)
}

/// Result of removing the active LPM root from the OS trust store.
#[derive(Debug)]
pub struct UninstallCaResult {
    /// Root certificate path used to identify the trust-store entry.
    pub cert_path: std::path::PathBuf,
    /// SHA-256 fingerprint of the removed certificate.
    pub fingerprint: String,
}

/// Remove the active LPM root from the OS trust store and record the exact
/// fingerprint while holding the machine-wide certificate operation lock.
pub fn uninstall_active_ca() -> Result<UninstallCaResult, LpmError> {
    let operation = paths::CertificateOperation::begin()?;
    let ca_cert_path = operation.ca.path("rootCA.pem");
    if !operation.ca.exists("rootCA.pem")? {
        return Err(LpmError::Cert(format!(
            "no on-disk CA at {}; nothing to uninstall (the fingerprint of the cert to remove is read from this file)",
            ca_cert_path.display()
        )));
    }
    let cert_pem = operation.ca.read("rootCA.pem")?;
    let _generation_guard = operation.acquire_destructive_generation(&cert_pem)?;
    let fingerprint = cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(&cert_pem)?);
    match trust::uninstall_ca_bytes(&cert_pem, &ca_cert_path) {
        Ok(()) => audit::append_best_effort(audit::AuditAction::CaTrustUninstall {
            fingerprint: fingerprint.clone(),
            store: trust_store_label(),
            status: audit::AuditStatus::Ok,
            error: None,
        }),
        Err(error) => {
            audit::append_best_effort(audit::AuditAction::CaTrustUninstall {
                fingerprint,
                store: trust_store_label(),
                status: audit::AuditStatus::Error,
                error: Some(error.to_string()),
            });
            return Err(error);
        }
    }
    Ok(UninstallCaResult {
        cert_path: ca_cert_path,
        fingerprint,
    })
}

fn trust_ca_locked(ca_dir: &paths::GlobalCaDirectory) -> Result<TrustCaResult, LpmError> {
    let root = ensure_root_ca_pair_locked(ca_dir)?;
    let fingerprint = cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(&root.cert_pem)?);
    match trust::install_ca_bytes(&root.cert_pem, &root.cert_path) {
        Ok(()) => audit::append_best_effort(audit::AuditAction::CaTrustInstall {
            fingerprint,
            store: trust_store_label(),
            status: audit::AuditStatus::Ok,
            error: None,
        }),
        Err(error) => {
            audit::append_best_effort(audit::AuditAction::CaTrustInstall {
                fingerprint,
                store: trust_store_label(),
                status: audit::AuditStatus::Error,
                error: Some(error.to_string()),
            });
            return Err(error);
        }
    }

    Ok(TrustCaResult {
        cert_path: root.cert_path,
        generated: root.generated,
    })
}

struct RootCaPair {
    cert_path: std::path::PathBuf,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    generated: bool,
}

fn ensure_root_ca_pair_locked(ca_dir: &paths::GlobalCaDirectory) -> Result<RootCaPair, LpmError> {
    let cert_path = ca_dir.path("rootCA.pem");
    let key_path = ca_dir.path("rootCA-key.pem");
    let generated = match (
        ca_dir.exists("rootCA.pem")?,
        ca_dir.exists("rootCA-key.pem")?,
    ) {
        (false, false) => {
            let (cert_pem, key_pem) = ca::generate_ca()
                .map_err(|error| LpmError::Cert(format!("failed to generate CA: {error}")))?;
            ca_dir.write_ca_pair(
                "rootCA.pem",
                "rootCA-key.pem",
                cert_pem.as_bytes(),
                key_pem.as_bytes(),
            )?;
            let fingerprint =
                cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(cert_pem.as_bytes())?);
            audit::append_best_effort(audit::AuditAction::CaGenerate {
                fingerprint,
                validity_days: ca::CA_VALIDITY_DAYS,
                name_constraints: ca::wants_name_constraints(),
            });
            true
        }
        (true, true) => false,
        (true, false) => {
            return Err(LpmError::Cert(format!(
                "root CA certificate exists at {} but its private key is missing at {}; restore the matching key or remove the certificate and run `lpm cert trust` again",
                cert_path.display(),
                key_path.display()
            )));
        }
        (false, true) => {
            return Err(LpmError::Cert(format!(
                "root CA private key exists at {} but its certificate is missing at {}; restore the matching certificate or remove the key and run `lpm cert trust` again",
                key_path.display(),
                cert_path.display()
            )));
        }
    };

    if let Some(drift) = ca_key_drift_in(ca_dir)? {
        return Err(LpmError::Cert(format!(
            "{}. Refusing to use a CA with a group-/world-readable private key. Fix with: {}",
            drift.summary(),
            drift.chmod_hint()
        )));
    }
    let ca_cert_pem = ca_dir.read("rootCA.pem")?;
    let ca_key_pem = ca_dir.read("rootCA-key.pem")?;
    let ca_cert_text = std::str::from_utf8(&ca_cert_pem)
        .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in CA certificate: {error}")))?;
    let ca_key_text = std::str::from_utf8(&ca_key_pem)
        .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in CA key: {error}")))?;
    cert::validate_ca_key_pair(ca_cert_text, ca_key_text)
        .map_err(|error| LpmError::Cert(format!("invalid root CA pair: {error}")))?;

    Ok(RootCaPair {
        cert_path,
        cert_pem: ca_cert_pem,
        key_pem: ca_key_pem,
        generated,
    })
}

/// Days remaining until the CA at `path` expires. `Some(0)` for already-expired,
/// `None` only if the cert can't be read or parsed.
pub fn ca_days_until_expiry(path: &Path) -> Option<i64> {
    let pem_str =
        lpm_common::read_text_file_capped(path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
            .ok()?;
    ca_days_until_expiry_bytes(pem_str.as_bytes())
}

fn ca_days_until_expiry_bytes(cert_pem: &[u8]) -> Option<i64> {
    let pem = pem::parse(cert_pem).ok()?;
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
    let Some(ca_dir) = paths::open_global_ca_directory(false).ok() else {
        return Ok(None);
    };
    ca_key_drift_in(&ca_dir)
}

#[cfg(unix)]
fn ca_key_drift_in(ca_dir: &paths::GlobalCaDirectory) -> Result<Option<PermissionDrift>, LpmError> {
    if !ca_dir.exists("rootCA-key.pem")? {
        return Ok(None);
    }
    let key = ca_dir.path("rootCA-key.pem");
    let mode = ca_dir.mode("rootCA-key.pem")?;
    if mode & 0o077 != 0 {
        return Ok(Some(PermissionDrift {
            path: key,
            actual_mode: mode,
            expected_mode: 0o600,
            role: "CA private key",
        }));
    }
    Ok(None)
}

#[cfg(not(unix))]
fn ca_key_drift_in(
    _ca_dir: &paths::GlobalCaDirectory,
) -> Result<Option<PermissionDrift>, LpmError> {
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

fn warn_if_ca_bytes_expiring_soon(cert_pem: &[u8], display_path: &Path) {
    let Some(days) = ca_days_until_expiry_bytes(cert_pem) else {
        return;
    };
    if days < 30 {
        tracing::error!(
            target: "lpm_cert",
            "root CA at {} expires in {days} day(s). Run `lpm cert rotate` to roll it.",
            display_path.display()
        );
    } else if days < 60 {
        tracing::warn!(
            target: "lpm_cert",
            "root CA at {} expires in {days} day(s). Plan a rotation with `lpm cert rotate`.",
            display_path.display()
        );
    }
}

/// Create `path` (parents included) and restrict it to the owner and system account.
///
/// The mode is reapplied every call, not only at creation, because a pre-H11 install may
/// have left the dir at `0o755`. Windows replaces inherited access with a protected
/// owner-and-system DACL.
pub fn create_dir_secure(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    paths::windows_security::protect_directory_path(path)?;
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

fn resolve_consent(consent: TrustStoreConsent<'_>, cert_pem: &[u8]) -> Result<bool, LpmError> {
    match consent {
        TrustStoreConsent::PreApproved => Ok(true),
        TrustStoreConsent::Decline => Ok(false),
        TrustStoreConsent::Prompt(callback) => {
            let info = cert::read_cert_info_bytes(cert_pem)?;
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
                fingerprint: cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(cert_pem)?),
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
pub struct HttpsSetup {
    /// Path to the project certificate PEM file.
    pub cert_path: String,
    /// Path to the project private key PEM file.
    pub key_path: String,
    /// Certificate PEM bytes loaded through the retained project directory capability.
    pub cert_pem: Vec<u8>,
    /// Private-key PEM bytes loaded through the retained project directory capability.
    pub key_pem: Vec<u8>,
    /// Lease that keeps the issuing root trusted while these in-memory credentials are served.
    pub runtime_lease: RuntimeCertificateLease,
    /// Environment variables to inject into the dev server process.
    pub env_vars: Vec<(String, String)>,
    /// Whether the CA was freshly installed (first time).
    pub ca_freshly_installed: bool,
    /// Whether the project cert was freshly generated.
    pub cert_freshly_generated: bool,
}

pub struct LoadedHttpsMaterial {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub runtime_lease: RuntimeCertificateLease,
}

impl std::fmt::Debug for LoadedHttpsMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedHttpsMaterial")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .field("runtime_lease", &self.runtime_lease)
            .finish()
    }
}

impl std::fmt::Debug for HttpsSetup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpsSetup")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .field("runtime_lease", &self.runtime_lease)
            .field("env_vars", &self.env_vars)
            .field("ca_freshly_installed", &self.ca_freshly_installed)
            .field("cert_freshly_generated", &self.cert_freshly_generated)
            .finish()
    }
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
    let operation = paths::CertificateOperation::begin()?;
    ensure_https_locked(
        &operation,
        project_dir,
        extra_hostnames,
        extra_permitted_dns_subtrees,
        consent,
    )
}

pub fn load_project_https_material(
    project_dir: &Path,
    hostnames: &[String],
) -> Result<LoadedHttpsMaterial, LpmError> {
    let operation = paths::CertificateOperation::begin()?;
    let root = ensure_root_ca_pair_locked(&operation.ca)?;
    let project_cert_dir =
        paths::open_project_cert_directory(project_dir, false)?.ok_or_else(|| {
            LpmError::Cert(format!(
                "project certificate directory is missing for {}",
                project_dir.display()
            ))
        })?;
    let (cert_pem, key_pem) = project_cert_dir.read_pair()?;
    cert::validate_project_key_pair_bytes(&cert_pem, &key_pem)?;
    cert::validate_project_server_chain_bytes(&cert_pem, &root.cert_pem, hostnames).map_err(
        |error| {
            LpmError::Cert(format!(
                "project certificate for {} is not safe to publish: {error}",
                project_dir.display()
            ))
        },
    )?;
    let runtime_lease = operation.acquire_runtime_lease(&root.cert_pem)?;
    Ok(LoadedHttpsMaterial {
        cert_pem,
        key_pem,
        runtime_lease,
    })
}

fn ensure_https_locked(
    operation: &paths::CertificateOperation,
    project_dir: &Path,
    extra_hostnames: &[String],
    extra_permitted_dns_subtrees: &[String],
    consent: TrustStoreConsent<'_>,
) -> Result<HttpsSetup, LpmError> {
    let project_cert_dir = paths::open_project_cert_directory(project_dir, true)?
        .ok_or_else(|| LpmError::Cert("failed to create project certificate directory".into()))?;
    let root = ensure_root_ca_pair_locked(&operation.ca)?;

    let ca_freshly_installed = if root.generated {
        let fp_hex = cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(&root.cert_pem)?);
        let approved = resolve_consent(consent, &root.cert_pem)?;
        if approved {
            tracing::info!("installing CA into system trust store...");
            match trust::install_ca_bytes(&root.cert_pem, &root.cert_path) {
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
                root.cert_path.display()
            );
        }

        approved
    } else {
        if ca::wants_name_constraints() && !ca::cert_has_name_constraints_bytes(&root.cert_pem)? {
            tracing::warn!(
                target: "lpm_cert",
                "LPM_CERT_NAME_CONSTRAINTS is set but the installed CA at {} predates this build and has no name constraints. Run `lpm cert rotate` to replace it with a constrained CA.",
                root.cert_path.display()
            );
        }
        warn_if_ca_bytes_expiring_soon(&root.cert_pem, &root.cert_path);
        if !trust::is_ca_installed_bytes(&root.cert_pem, &root.cert_path)? {
            let approved = resolve_consent(consent, &root.cert_pem)?;
            if approved {
                tracing::info!("CA exists but not trusted, installing...");
                let fp_hex =
                    cert::fingerprint_hex(&cert::fingerprint_sha256_bytes(&root.cert_pem)?);
                match trust::install_ca_bytes(&root.cert_pem, &root.cert_path) {
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
                    root.cert_path.display()
                );
            }
        }
        false
    };

    let proj_cert_path = project_cert_dir.path().join("cert.pem");
    let proj_key_path = project_cert_dir.path().join("key.pem");
    paths::reject_linked_project_cert_file(&proj_cert_path)?;
    paths::reject_linked_project_cert_file(&proj_key_path)?;
    let needs_project_intermediate =
        !extra_hostnames.is_empty() || !extra_permitted_dns_subtrees.is_empty();

    let existing_project_pair = project_cert_dir.read_optional_pair()?;
    let needs_reissue_chain_mismatch = existing_project_pair.as_ref().is_some_and(|material| {
        !cert::project_cert_chains_to_root_bytes(&material.cert, &root.cert_pem).unwrap_or(false)
    });
    let needs_reissue_key_mismatch = existing_project_pair.as_ref().is_some_and(|material| {
        material
            .key
            .as_deref()
            .is_none_or(|key| cert::validate_project_key_pair_bytes(&material.cert, key).is_err())
    });
    let needs_reissue_for_project_intermediate = needs_project_intermediate
        && existing_project_pair.as_ref().is_some_and(|material| {
            !cert::project_cert_has_intermediate_bytes(&material.cert).unwrap_or(false)
        });
    let needs_reissue_for_project_constraints = needs_project_intermediate
        && existing_project_pair.as_ref().is_some_and(|material| {
            !cert::project_cert_constraints_cover_dns_bytes(
                &material.cert,
                extra_hostnames,
                extra_permitted_dns_subtrees,
            )
            .unwrap_or(false)
        });

    let cert_freshly_generated = if existing_project_pair.is_none()
        || needs_reissue_chain_mismatch
        || needs_reissue_key_mismatch
        || needs_reissue_for_project_intermediate
        || needs_reissue_for_project_constraints
        || existing_project_pair
            .as_ref()
            .is_some_and(|material| cert::needs_renewal_bytes(&material.cert).unwrap_or(true))
        || existing_project_pair.as_ref().is_some_and(|material| {
            !cert::covers_requested_hostnames_bytes(&material.cert, extra_hostnames)
                .unwrap_or(false)
        }) {
        if needs_reissue_chain_mismatch {
            tracing::info!(
                "project leaf at {} no longer chains to the active CA; re-issuing",
                proj_cert_path.display()
            );
        } else if needs_reissue_key_mismatch {
            tracing::info!(
                "project leaf and private key at {} do not match; re-issuing",
                project_cert_dir.path().display()
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
        paths::reject_linked_project_cert_file(&proj_cert_path)?;
        paths::reject_linked_project_cert_file(&proj_key_path)?;

        let ca_cert_pem = std::str::from_utf8(&root.cert_pem)
            .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in CA certificate: {error}")))?;
        let ca_key_pem = std::str::from_utf8(&root.key_pem)
            .map_err(|error| LpmError::Cert(format!("invalid UTF-8 in CA key: {error}")))?;

        let (cert_pem, key_pem) = if needs_project_intermediate {
            if !ca::cert_allows_project_intermediates_bytes(&root.cert_pem)? {
                return Err(LpmError::Cert(
                    "active LPM root CA cannot sign project-scoped constrained intermediates \
                     because its pathLenConstraint is 0. Run `lpm cert rotate`, then retry."
                        .into(),
                ));
            }
            cert::generate_project_cert_with_constrained_intermediate(
                ca_cert_pem,
                ca_key_pem,
                extra_hostnames,
                extra_permitted_dns_subtrees,
            )
        } else {
            cert::generate_project_cert(ca_cert_pem, ca_key_pem, extra_hostnames)
        }
        .map_err(|e| LpmError::Cert(format!("failed to generate project cert: {e}")))?;

        project_cert_dir.write_pair(cert_pem.as_bytes(), key_pem.as_bytes())?;

        true
    } else {
        false
    };

    if let Err(e) = projects::record(project_dir) {
        tracing::debug!("failed to record project in cert-projects index: {e}");
    }

    // Step 3: Build env vars for the dev server
    let ca_cert_path_str = root.cert_path.to_string_lossy().to_string();
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

    let (cert_pem, key_pem) = project_cert_dir.read_pair()?;
    cert::validate_project_key_pair_bytes(&cert_pem, &key_pem)?;
    let runtime_lease = operation.acquire_runtime_lease(&root.cert_pem)?;

    Ok(HttpsSetup {
        cert_path: proj_cert_str,
        key_path: proj_key_str,
        cert_pem,
        key_pem,
        runtime_lease,
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

    let project_cert_dir = paths::secure_project_cert_dir(project_dir, false)?;
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

    #[test]
    fn https_setup_debug_output_redacts_private_key_material() {
        let setup = HttpsSetup {
            cert_path: "/project/cert.pem".to_string(),
            key_path: "/project/key.pem".to_string(),
            cert_pem: b"certificate".to_vec(),
            key_pem: b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----".to_vec(),
            runtime_lease: RuntimeCertificateLease::for_test(),
            env_vars: Vec::new(),
            ca_freshly_installed: false,
            cert_freshly_generated: false,
        };

        let debug = format!("{setup:?}");

        assert!(!debug.contains("secret"), "{debug}");
        assert!(!debug.contains("BEGIN PRIVATE KEY"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

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
