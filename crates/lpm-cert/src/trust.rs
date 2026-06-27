//! System trust store management.
//!
//! Installs/removes the LPM root CA from the OS trust store so browsers
//! and Node.js trust certificates signed by it. Detection and removal are
//! fingerprint-keyed, not CN-keyed: a different cert that happens to share the LPM CN
//! is never mistaken for the legitimate root.

use crate::cert;
use lpm_common::LpmError;
use std::path::Path;
use std::process::Command;

#[cfg(any(target_os = "macos", target_os = "windows"))]
const CA_COMMON_NAME: &str = "LPM Local Development CA";
const TEST_TRUST_STORE_DIR_ENV: &str = "LPM_CERT_TEST_TRUST_STORE_DIR";

#[cfg(target_os = "linux")]
const LINUX_TRUST_STORE_PATH: &str = "/usr/local/share/ca-certificates/lpm-local-ca.crt";

fn test_trust_store_dir() -> Option<std::path::PathBuf> {
    if !crate::test_env_overrides_enabled() {
        return None;
    }
    std::env::var_os(TEST_TRUST_STORE_DIR_ENV).map(std::path::PathBuf::from)
}

fn test_trust_store_path() -> Option<std::path::PathBuf> {
    test_trust_store_dir().map(|dir| dir.join("lpm-local-ca.pem"))
}

fn test_trust_store_sidecar() -> Option<std::path::PathBuf> {
    test_trust_store_dir().map(|dir| dir.join("lpm-local-ca.sha256"))
}

fn install_ca_test(ca_cert_path: &Path, trust_store_path: &Path) -> Result<(), LpmError> {
    if let Some(parent) = trust_store_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| LpmError::Cert(format!("failed to create test trust store: {e}")))?;
    }

    std::fs::copy(ca_cert_path, trust_store_path)
        .map_err(|e| LpmError::Cert(format!("failed to install CA to test trust store: {e}")))?;

    let fp = cert::fingerprint_sha256(ca_cert_path)?;
    if let Some(sidecar) = test_trust_store_sidecar() {
        std::fs::write(&sidecar, cert::fingerprint_hex(&fp)).map_err(|e| {
            LpmError::Cert(format!("failed to write test sidecar fingerprint: {e}"))
        })?;
    }
    Ok(())
}

fn is_ca_installed_test(
    expected_fingerprint_hex: &str,
    trust_store_path: &Path,
) -> Result<bool, LpmError> {
    if !trust_store_path.exists() {
        return Ok(false);
    }
    let recorded = match test_trust_store_sidecar() {
        Some(p) if p.exists() => std::fs::read_to_string(&p)
            .map_err(|e| LpmError::Cert(format!("failed to read sidecar: {e}")))?,
        _ => {
            let fp = cert::fingerprint_sha256(trust_store_path)?;
            cert::fingerprint_hex(&fp)
        }
    };
    Ok(recorded.trim() == expected_fingerprint_hex)
}

fn uninstall_ca_test(
    expected_fingerprint_hex: &str,
    trust_store_path: &Path,
) -> Result<(), LpmError> {
    let installed = is_ca_installed_test(expected_fingerprint_hex, trust_store_path)?;
    if !installed {
        if trust_store_path.exists() {
            tracing::warn!(
                "test trust store contains a cert at {} whose fingerprint does not match the expected LPM CA — leaving it in place",
                trust_store_path.display()
            );
        }
        return Ok(());
    }
    if trust_store_path.exists() {
        std::fs::remove_file(trust_store_path).map_err(|e| {
            LpmError::Cert(format!("failed to remove CA from test trust store: {e}"))
        })?;
    }
    if let Some(sidecar) = test_trust_store_sidecar()
        && sidecar.exists()
    {
        std::fs::remove_file(&sidecar).map_err(|e| {
            LpmError::Cert(format!("failed to remove test sidecar fingerprint: {e}"))
        })?;
    }
    Ok(())
}

/// Install the CA certificate into the system trust store.
///
/// Platform behavior:
/// - macOS: adds to user login keychain (no sudo needed)
/// - Linux: copies to ca-certificates dir + runs update-ca-certificates (needs sudo)
/// - Windows: uses certutil to add to Root store (UAC prompt)
pub fn install_ca(ca_cert_path: &Path) -> Result<(), LpmError> {
    if let Some(trust_store_path) = test_trust_store_path() {
        return install_ca_test(ca_cert_path, &trust_store_path);
    }

    let path_str = ca_cert_path.to_string_lossy();

    #[cfg(target_os = "macos")]
    {
        install_ca_macos(&path_str)
    }

    #[cfg(target_os = "linux")]
    {
        install_ca_linux(&path_str)
    }

    #[cfg(target_os = "windows")]
    {
        install_ca_windows(&path_str)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(LpmError::Cert(format!(
            "automatic trust store installation is not supported on this platform. \
				 Manually add {} to your system's trusted certificates.",
            path_str
        )))
    }
}

/// True iff a cert with the same SHA-256 fingerprint as `ca_cert_path` is currently
/// in the user trust store. Identity check, not CN substring match — a planted cert
/// with the same CN but a different fingerprint reads as "not installed."
pub fn is_ca_installed(ca_cert_path: &Path) -> Result<bool, LpmError> {
    let expected = cert::fingerprint_sha256(ca_cert_path)?;
    let expected_hex = cert::fingerprint_hex(&expected);

    if let Some(trust_store_path) = test_trust_store_path() {
        return is_ca_installed_test(&expected_hex, &trust_store_path);
    }

    #[cfg(target_os = "macos")]
    {
        is_ca_installed_macos(&expected_hex)
    }

    #[cfg(target_os = "linux")]
    {
        is_ca_installed_linux(ca_cert_path)
    }

    #[cfg(target_os = "windows")]
    {
        let sha1 = cert::fingerprint_sha1(ca_cert_path)?;
        is_ca_installed_windows(&cert::fingerprint_hex(&sha1))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = ca_cert_path;
        Ok(false)
    }
}

/// Remove the LPM CA from the system trust store. Only fingerprints matching
/// `ca_cert_path` are removed; lookalikes with the same CN are preserved with a
/// warning so the user can inspect them.
pub fn uninstall_ca(ca_cert_path: &Path) -> Result<(), LpmError> {
    let expected = cert::fingerprint_sha256(ca_cert_path)?;
    let expected_hex = cert::fingerprint_hex(&expected);

    if let Some(trust_store_path) = test_trust_store_path() {
        return uninstall_ca_test(&expected_hex, &trust_store_path);
    }

    #[cfg(target_os = "macos")]
    {
        uninstall_ca_macos(&expected_hex)
    }

    #[cfg(target_os = "linux")]
    {
        uninstall_ca_linux(ca_cert_path)
    }

    #[cfg(target_os = "windows")]
    {
        let sha1 = cert::fingerprint_sha1(ca_cert_path)?;
        uninstall_ca_windows(&cert::fingerprint_hex(&sha1))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = ca_cert_path;
        Err(LpmError::Cert(
            "automatic trust store removal is not supported on this platform".into(),
        ))
    }
}

// ── macOS ──────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn install_ca_macos(cert_path: &str) -> Result<(), LpmError> {
    tracing::debug!("installing CA to macOS login keychain: {cert_path}");

    let mut cmd = Command::new("security");
    cmd.args(["add-trusted-cert", "-r", "trustRoot", "-k"])
        .arg(login_keychain_path()?)
        .arg(cert_path);

    let output = cmd
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("already exists") || stderr.contains("duplicate") {
            tracing::debug!("CA already in keychain");
            return Ok(());
        }
        return Err(LpmError::Cert(format!(
            "failed to install CA to keychain: {stderr}"
        )));
    }

    tracing::info!("CA installed to macOS login keychain");
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_ca_installed_macos(expected_fingerprint_hex: &str) -> Result<bool, LpmError> {
    let output = Command::new("security")
        .args(["find-certificate", "-Z", "-a", "-c", CA_COMMON_NAME])
        .arg(login_keychain_path()?)
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("could not be found") || output.stdout.is_empty() {
            return Ok(false);
        }
        return Err(LpmError::Cert(format!(
            "`security find-certificate` failed: {stderr}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_macos_sha256_lines(&stdout)
        .any(|fp| fp.eq_ignore_ascii_case(expected_fingerprint_hex)))
}

#[cfg(target_os = "macos")]
fn uninstall_ca_macos(expected_fingerprint_hex: &str) -> Result<(), LpmError> {
    let output = Command::new("security")
        .args(["find-certificate", "-Z", "-a", "-c", CA_COMMON_NAME])
        .arg(login_keychain_path()?)
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run `security`: {e}")))?;

    if !output.status.success() || output.stdout.is_empty() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut matched = false;
    let mut lookalikes: Vec<String> = Vec::new();
    for fp in parse_macos_sha256_lines(&stdout) {
        if fp.eq_ignore_ascii_case(expected_fingerprint_hex) {
            matched = true;
            let del = Command::new("security")
                .args(["delete-certificate", "-Z", &fp])
                .arg(login_keychain_path()?)
                .output()
                .map_err(|e| {
                    LpmError::Cert(format!("failed to run `security delete-certificate`: {e}"))
                })?;
            if !del.status.success() {
                let stderr = String::from_utf8_lossy(&del.stderr);
                if !stderr.contains("could not be found") {
                    return Err(LpmError::Cert(format!(
                        "failed to remove CA from keychain: {stderr}"
                    )));
                }
            }
        } else {
            lookalikes.push(fp);
        }
    }

    for fp in &lookalikes {
        tracing::warn!(
            "found a different cert with CN={CA_COMMON_NAME:?} at SHA-256 {fp}; not removing"
        );
    }

    if !matched {
        tracing::info!("no LPM CA matching the on-disk fingerprint was found in the keychain");
    } else {
        tracing::info!("CA removed from macOS login keychain");
    }
    Ok(())
}

/// Parse the `SHA-256 hash: …` lines emitted by `security find-certificate -Z`.
/// Output is one block per match separated by blank lines; we yield each SHA-256
/// in original casing (uppercase hex with no separators on macOS).
#[cfg(target_os = "macos")]
fn parse_macos_sha256_lines(stdout: &str) -> impl Iterator<Item = String> + '_ {
    stdout.lines().filter_map(|line| {
        let trimmed = line.trim_start();
        let prefix = "SHA-256 hash:";
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let hex = rest.trim();
            if hex.is_empty() {
                None
            } else {
                Some(insert_colons_in_hex(hex))
            }
        } else {
            None
        }
    })
}

#[cfg(target_os = "macos")]
fn insert_colons_in_hex(hex: &str) -> String {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut out = String::with_capacity(clean.len() + clean.len() / 2);
    for (i, c) in clean.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(':');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

#[cfg(target_os = "macos")]
fn login_keychain_path() -> Result<String, LpmError> {
    let home = dirs::home_dir()
        .ok_or_else(|| LpmError::Cert("could not determine home directory".into()))?;
    let keychain = home.join("Library/Keychains/login.keychain-db");

    if keychain.exists() {
        Ok(keychain.to_string_lossy().to_string())
    } else {
        let alt = home.join("Library/Keychains/login.keychain");
        Ok(alt.to_string_lossy().to_string())
    }
}

// ── Linux ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn install_ca_linux(cert_path: &str) -> Result<(), LpmError> {
    let dest = Path::new(LINUX_TRUST_STORE_PATH);

    tracing::debug!("installing CA to {}", dest.display());

    let output = Command::new("sudo")
        .args(["cp", cert_path, &dest.to_string_lossy()])
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to copy CA cert (sudo required): {e}")))?;

    if !output.status.success() {
        return Err(LpmError::Cert(format!(
            "failed to copy CA cert: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let output = Command::new("sudo")
		.args(["update-ca-certificates"])
		.output()
		.map_err(|e| LpmError::Cert(format!(
			"failed to run update-ca-certificates: {e}. Install with: sudo apt install ca-certificates"
		)))?;

    if !output.status.success() {
        return Err(LpmError::Cert(format!(
            "update-ca-certificates failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    tracing::info!("CA installed to Linux trust store");
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_ca_installed_linux(expected_ca_path: &Path) -> Result<bool, LpmError> {
    let dest = Path::new(LINUX_TRUST_STORE_PATH);
    if !dest.exists() {
        return Ok(false);
    }
    let installed_fp = match cert::fingerprint_sha256(dest) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::warn!(
                "found {} but failed to read its fingerprint: {e}",
                dest.display()
            );
            return Ok(false);
        }
    };
    let expected_fp = cert::fingerprint_sha256(expected_ca_path)?;
    if installed_fp != expected_fp {
        tracing::warn!(
            "a different `lpm-local-ca.crt` is present at {} (SHA-256 {}); re-install will overwrite it",
            dest.display(),
            cert::fingerprint_hex(&installed_fp)
        );
        return Ok(false);
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn uninstall_ca_linux(expected_ca_path: &Path) -> Result<(), LpmError> {
    let dest = LINUX_TRUST_STORE_PATH;
    let dest_path = Path::new(dest);
    if !dest_path.exists() {
        return Ok(());
    }
    if !is_ca_installed_linux(expected_ca_path)? {
        tracing::warn!(
            "trust-store file {} does not match on-disk LPM CA; leaving in place",
            dest
        );
        return Ok(());
    }

    let output = Command::new("sudo")
        .args(["rm", "-f", dest])
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to remove CA cert: {e}")))?;

    if !output.status.success() {
        return Err(LpmError::Cert(format!(
            "failed to remove CA cert: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let _ = Command::new("sudo")
        .args(["update-ca-certificates", "--fresh"])
        .output();

    tracing::info!("CA removed from Linux trust store");
    Ok(())
}

// ── Windows ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn install_ca_windows(cert_path: &str) -> Result<(), LpmError> {
    tracing::debug!("installing CA to Windows Root store: {cert_path}");

    let output = Command::new("certutil")
        .args(["-addstore", "Root", cert_path])
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run certutil: {e}")))?;

    if !output.status.success() {
        return Err(LpmError::Cert(format!(
            "certutil failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    tracing::info!("CA installed to Windows Root store");
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_ca_installed_windows(expected_sha1_hex: &str) -> Result<bool, LpmError> {
    let output = Command::new("certutil")
        .args(["-store", "Root", CA_COMMON_NAME])
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run certutil: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.is_empty() {
            return Ok(false);
        }
        return Err(LpmError::Cert(format!("certutil failed: {stderr}")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_certutil_sha1_thumbprints(&stdout)
        .iter()
        .any(|tp| tp.eq_ignore_ascii_case(expected_sha1_hex)))
}

#[cfg(target_os = "windows")]
fn uninstall_ca_windows(expected_sha1_hex: &str) -> Result<(), LpmError> {
    let plain = expected_sha1_hex.replace(':', "");
    let output = Command::new("certutil")
        .args(["-delstore", "Root", &plain])
        .output()
        .map_err(|e| LpmError::Cert(format!("failed to run certutil: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Cannot find") || stderr.is_empty() {
            return Ok(());
        }
        return Err(LpmError::Cert(format!("certutil failed: {stderr}")));
    }

    tracing::info!("CA removed from Windows Root store");
    Ok(())
}

/// Extract every SHA-1 thumbprint emitted by `certutil -store`, robustly across
/// localized installs. The literal `sha1` token is preserved on every locale we've
/// sampled (English, German, Japanese, Chinese); only the surrounding label varies.
/// We match case-insensitively on `sha1` and capture the hex group that follows.
pub fn parse_certutil_sha1_thumbprints(stdout: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        regex::Regex::new(r"(?im)^\s*[^\n:]*\bsha1\b[^\n:]*:\s*([0-9a-f][0-9a-f\s]+)\s*$")
            .expect("compiled certutil thumbprint regex")
    });
    pattern
        .captures_iter(stdout)
        .filter_map(|cap| {
            let raw = cap.get(1)?.as_str();
            let clean: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if clean.len() == 40 {
                Some(insert_colons_uppercase(&clean))
            } else {
                None
            }
        })
        .collect()
}

fn insert_colons_uppercase(hex: &str) -> String {
    let mut out = String::with_capacity(hex.len() + hex.len() / 2);
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(':');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn login_keychain_path_resolves() {
        let path = super::login_keychain_path().unwrap();
        assert!(path.contains("Keychains/login.keychain"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn parse_macos_sha256_lines_extracts_all_blocks() {
        let stdout = "\
keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
version: 256
class: 0x80001000
SHA-256 hash: AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899

keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
version: 256
class: 0x80001000
SHA-256 hash: 1122334455667788990011223344556677889900112233445566778899001122

";
        let collected: Vec<_> = parse_macos_sha256_lines(stdout).collect();
        assert_eq!(collected.len(), 2);
        assert!(collected[0].starts_with("AA:BB:CC:"));
        assert!(collected[1].starts_with("11:22:33:"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn parse_macos_sha256_lines_returns_empty_on_no_match() {
        let stdout = "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"\nversion: 256\nclass: 0x80001000\n";
        assert_eq!(parse_macos_sha256_lines(stdout).count(), 0);
    }

    #[test]
    fn parse_certutil_sha1_english_locale() {
        let stdout = "================ Certificate 0 ================\nIssuer: CN=LPM Local Development CA\nSubject: CN=LPM Local Development CA\nCert Hash(sha1): a1 b2 c3 d4 e5 f6 78 90 12 34 56 78 90 ab cd ef 12 34 56 78\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 1);
        assert_eq!(
            tps[0],
            "A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:AB:CD:EF:12:34:56:78"
        );
    }

    #[test]
    fn parse_certutil_sha1_german_locale() {
        let stdout = "================ Zertifikat 0 ================\nAussteller: CN=LPM Local Development CA\nAntragsteller: CN=LPM Local Development CA\nZertifikathash(sha1): a1b2c3d4e5f6789012345678 90 ab cd ef 12 34 56 78\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 1);
        assert_eq!(
            tps[0],
            "A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:AB:CD:EF:12:34:56:78"
        );
    }

    #[test]
    fn parse_certutil_sha1_japanese_locale() {
        let stdout = "================ 証明書 0 ================\n発行者: CN=LPM Local Development CA\nサブジェクト: CN=LPM Local Development CA\n証明書ハッシュ(sha1): a1b2c3d4e5f6789012345678 90 ab cd ef 12 34 56 78\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 1);
        assert_eq!(
            tps[0],
            "A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:AB:CD:EF:12:34:56:78"
        );
    }

    #[test]
    fn parse_certutil_sha1_returns_none_on_no_match() {
        let stdout = "================ Certificate 0 ================\nIssuer: CN=Other CA\nNotBefore: 2026-01-01\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 0);
    }

    #[test]
    fn parse_certutil_sha1_returns_multiple_when_multiple_blocks() {
        let stdout = "Cert Hash(sha1): a1b2c3d4e5f67890123456789012345678 90 ab cd\nCert Hash(sha1): 0011223344556677889900112233445566778899\n";
        let tps = parse_certutil_sha1_thumbprints(stdout);
        assert_eq!(tps.len(), 2);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn is_ca_installed_uses_fingerprint_via_test_backend() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(TEST_TRUST_STORE_DIR_ENV, dir.path());

        let (ca_pem, _) = crate::ca::generate_ca().unwrap();
        let ca_path = dir.path().join("source-rootCA.pem");
        std::fs::write(&ca_path, &ca_pem).unwrap();

        assert!(!is_ca_installed(&ca_path).unwrap());

        install_ca(&ca_path).unwrap();
        assert!(is_ca_installed(&ca_path).unwrap());

        let (other_pem, _) = crate::ca::generate_ca().unwrap();
        let other_path = dir.path().join("other.pem");
        std::fs::write(&other_path, &other_pem).unwrap();
        assert!(
            !is_ca_installed(&other_path).unwrap(),
            "a different cert (same CN, different fingerprint) must read as not installed"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn uninstall_preserves_lookalike_with_different_fingerprint() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(TEST_TRUST_STORE_DIR_ENV, dir.path());

        let (real_pem, _) = crate::ca::generate_ca().unwrap();
        let real_path = dir.path().join("real.pem");
        std::fs::write(&real_path, &real_pem).unwrap();
        install_ca(&real_path).unwrap();

        let (planted_pem, _) = crate::ca::generate_ca().unwrap();
        let planted_path = dir.path().join("planted.pem");
        std::fs::write(&planted_path, &planted_pem).unwrap();

        uninstall_ca(&planted_path).unwrap();

        assert!(
            is_ca_installed(&real_path).unwrap(),
            "uninstall keyed by a non-matching fingerprint must leave the real CA alone"
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn test_trust_store_env_is_ignored_in_release_builds() {
        let _serial = serial_lock();
        let dir = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(TEST_TRUST_STORE_DIR_ENV, dir.path());

        assert_eq!(test_trust_store_path(), None);
        assert_ne!(crate::trust_store_label(), "test");
    }

    /// Tests that mutate `LPM_CERT_TEST_TRUST_STORE_DIR` lock this mutex so they
    /// serialize within a single cargo-test binary process. nextest uses one
    /// process per test and doesn't need this, but plain `cargo test` does.
    fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set<P: AsRef<std::ffi::OsStr>>(key: &'static str, value: P) -> Self {
            let prev = std::env::var_os(key);
            // SAFETY: tests in this crate are not parallelized across this env key
            // via a separate mutex, but cargo nextest gives each test its own process,
            // and within `cargo test --lib` the two callers below run sequentially in a
            // single thread because they share `TEST_TRUST_STORE_DIR_ENV` mutation.
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }
}
