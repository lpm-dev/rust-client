//! macOS Keychain integration for vault secrets.
//!
//! Uses the `security` CLI tool for compatibility with the SwiftUI Vault app.
//! Both CLI and app share the same Keychain items via an index-based design:
//!
//! - **Index item**: service=`dev.lpm.vault`, account=`__index__`
//!   JSON array of `[{"id":"vault-id","name":"project-name","path":"/project/path"}]`
//! - **Data items**: service=`dev.lpm.vault`, account=`{vault-id}`
//!   JSON dict of `{"KEY": "VALUE", ...}`
//!
//! This avoids `SecItemCopyMatching` with `kSecMatchLimitAll` which is unreliable.

use std::collections::HashMap;

type SecretMap = HashMap<String, String>;
type EnvironmentMap = HashMap<String, SecretMap>;

/// Keychain service name — shared with the SwiftUI Vault app.
const SERVICE: &str = "dev.lpm.vault";

/// Account name for the project index.
const INDEX_ACCOUNT: &str = "__index__";

/// Maximum recommended vault size (90KB warning threshold).
const MAX_VAULT_SIZE_WARNING: usize = 90 * 1024;

/// A project entry in the index.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct IndexEntry {
    pub id: String,
    pub name: String,
    pub path: String,
}

/// Wrapper for the environments Keychain format.
#[derive(serde::Serialize, serde::Deserialize)]
struct EnvironmentsWrapper {
    environments: EnvironmentMap,
}

/// Read all secrets for a vault ID from the Keychain.
/// Handles both new format (`{"environments": {...}}`) and old flat format (`{"KEY": "VALUE"}`).
/// The `env` parameter selects which environment to return (default: "default").
pub fn read_vault(vault_id: &str) -> Option<SecretMap> {
    try_read_vault(vault_id).ok().flatten()
}

pub fn try_read_vault(vault_id: &str) -> Result<Option<SecretMap>, String> {
    try_read_vault_env(vault_id, "default")
}

/// Read secrets for a specific environment from the Keychain.
pub fn read_vault_env(vault_id: &str, env: &str) -> Option<SecretMap> {
    try_read_vault_env(vault_id, env).ok().flatten()
}

pub fn try_read_vault_env(vault_id: &str, env: &str) -> Result<Option<SecretMap>, String> {
    let Some(json) = try_read_keychain_password(SERVICE, vault_id)? else {
        return Ok(None);
    };

    // Try new format first
    if let Ok(wrapper) = serde_json::from_str::<EnvironmentsWrapper>(&json) {
        return Ok(wrapper.environments.get(env).cloned());
    }

    // Fall back to old flat format (treat as "default" environment)
    match serde_json::from_str::<SecretMap>(&json) {
        Ok(flat) if env == "default" => Ok(Some(flat)),
        Ok(_) => Ok(None),
        Err(e) => Err(format!("vault keychain data is not valid JSON: {e}")),
    }
}

/// Read all environments for a vault ID.
pub fn read_all_environments(vault_id: &str) -> Option<EnvironmentMap> {
    try_read_all_environments(vault_id).ok().flatten()
}

pub fn try_read_all_environments(vault_id: &str) -> Result<Option<EnvironmentMap>, String> {
    let Some(json) = try_read_keychain_password(SERVICE, vault_id)? else {
        return Ok(None);
    };

    // Try new format
    if let Ok(wrapper) = serde_json::from_str::<EnvironmentsWrapper>(&json) {
        return Ok(Some(wrapper.environments));
    }

    // Fall back to old flat format
    if let Ok(flat) = serde_json::from_str::<SecretMap>(&json) {
        let mut envs = HashMap::new();
        envs.insert("default".to_string(), flat);
        return Ok(Some(envs));
    }

    Err("vault keychain data is not a valid vault payload".to_string())
}

/// Write secrets to the Keychain using the environments format.
pub fn write_vault(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    secrets: &SecretMap,
) -> Result<(), String> {
    write_vault_env(vault_id, project_name, project_path, "default", secrets)
}

pub fn write_all_environments(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &EnvironmentMap,
) -> Result<(), String> {
    let wrapper = EnvironmentsWrapper {
        environments: environments.clone(),
    };
    let json = serde_json::to_string(&wrapper)
        .map_err(|e| format!("failed to serialize environments: {e}"))?;

    if json.len() > MAX_VAULT_SIZE_WARNING {
        tracing::warn!(
            "vault data is {} bytes (approaching ~100KB Keychain limit)",
            json.len()
        );
    }

    write_keychain_password(SERVICE, vault_id, &json)?;

    let mut index = read_index();
    if let Some(entry) = index.iter_mut().find(|e| e.id == vault_id) {
        entry.name = project_name.to_string();
        entry.path = project_path.to_string();
    } else {
        index.push(IndexEntry {
            id: vault_id.to_string(),
            name: project_name.to_string(),
            path: project_path.to_string(),
        });
    }
    write_index(&index)?;

    Ok(())
}

/// Write secrets for a specific environment to the Keychain.
pub fn write_vault_env(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    env: &str,
    secrets: &SecretMap,
) -> Result<(), String> {
    // Read existing environments, update the target env, write back
    let mut all_envs = try_read_all_environments(vault_id)?.unwrap_or_default();
    all_envs.insert(env.to_string(), secrets.clone());

    let wrapper = EnvironmentsWrapper {
        environments: all_envs,
    };
    let json = serde_json::to_string(&wrapper)
        .map_err(|e| format!("failed to serialize environments: {e}"))?;

    if json.len() > MAX_VAULT_SIZE_WARNING {
        tracing::warn!(
            "vault data is {} bytes (approaching ~100KB Keychain limit)",
            json.len()
        );
    }

    // Write secrets data
    write_keychain_password(SERVICE, vault_id, &json)?;

    // Update project index
    let mut index = read_index();
    if let Some(entry) = index.iter_mut().find(|e| e.id == vault_id) {
        entry.name = project_name.to_string();
        entry.path = project_path.to_string();
    } else {
        index.push(IndexEntry {
            id: vault_id.to_string(),
            name: project_name.to_string(),
            path: project_path.to_string(),
        });
    }
    write_index(&index)?;

    Ok(())
}

/// Delete a vault from the Keychain and remove from index.
///
/// If the Keychain delete fails (e.g. locked keychain, permission
/// denied, system framework error) we keep the index entry intact and
/// surface the error to the caller — half-deleting (keychain entry
/// alive but index claims gone) would leave a usable secret that
/// `list_vaults` no longer surfaces and the user can no longer wipe
/// through the normal path. `NotFound` is treated as success so
/// `lpm logout` / second-time `delete_vault` is idempotent.
pub fn delete_vault(vault_id: &str) -> Result<(), String> {
    delete_keychain_password(SERVICE, vault_id)?;

    let mut index = read_index();
    index.retain(|e| e.id != vault_id);
    write_index(&index)?;

    Ok(())
}

/// List all vault projects from the index.
pub fn list_vaults() -> Vec<IndexEntry> {
    read_index()
}

// ─── X25519 Private Key Storage ───────────────────────────────────

const X25519_ACCOUNT: &str = "__x25519_private_key__";

/// Read the stored X25519 private key from Keychain.
pub fn read_x25519_private_key() -> Option<[u8; 32]> {
    let b64 = read_keychain_password(SERVICE, X25519_ACCOUNT)?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

/// Store an X25519 private key in Keychain.
pub fn write_x25519_private_key(private_key: &[u8; 32]) -> Result<(), String> {
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, private_key);
    write_keychain_password(SERVICE, X25519_ACCOUNT, &b64)
}

/// Get or create the X25519 keypair. Returns (private_key, public_key).
/// Generates and stores a new keypair if none exists.
pub fn get_or_create_x25519_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    if let Some(private) = read_x25519_private_key() {
        let public = crate::crypto::x25519_public_from_private(&private);
        return Ok((private, public));
    }

    let (private, public) = crate::crypto::generate_x25519_keypair();
    write_x25519_private_key(&private)?;
    Ok((private, public))
}

/// Delete the stored X25519 private key from the Keychain. Used by the
/// rotation promote path so subsequent `load_local_public_key_state`
/// calls fall through to the file-backed slot the rotation just wrote.
///
/// Best-effort: a `not found` result is the steady state for users who
/// were already on the file fallback. Returns `Ok(())` either way so
/// callers don't need to special-case the absence path.
pub fn delete_x25519_keypair() -> Result<(), String> {
    // Reuse the existing keychain delete primitive; the underlying API
    // returns `not found` errors which are not actionable here.
    let _ = delete_keychain_password(SERVICE, X25519_ACCOUNT);
    Ok(())
}

// ─── Index Management ──────────────────────────────────────────────

fn read_index() -> Vec<IndexEntry> {
    read_keychain_password(SERVICE, INDEX_ACCOUNT)
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn write_index(entries: &[IndexEntry]) -> Result<(), String> {
    let json =
        serde_json::to_string(entries).map_err(|e| format!("failed to serialize index: {e}"))?;
    write_keychain_password(SERVICE, INDEX_ACCOUNT, &json)
}

// ─── macOS Keychain via `security` CLI ─────────────────────────────

fn read_keychain_password(service: &str, account: &str) -> Option<String> {
    try_read_keychain_password(service, account).ok().flatten()
}

fn try_read_keychain_password(service: &str, account: &str) -> Result<Option<String>, String> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .output()
        .map_err(|e| format!("keychain read spawn error: {e}"))?;

    if output.status.success() {
        let value = String::from_utf8(output.stdout)
            .map_err(|e| format!("keychain read utf8 error: {e}"))?;
        let value = value.trim().to_string();
        return Ok((!value.is_empty()).then_some(value));
    }

    if output.status.code() == Some(44) {
        return Ok(None);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "security find-generic-password failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    ))
}

fn write_keychain_password(service: &str, account: &str, password: &str) -> Result<(), String> {
    // Vault secrets (dev.lpm.vault) are shared between the Rust CLI and the
    // SwiftUI LPMVault macOS app. Both need to read/write the same Keychain
    // entries. The Swift app uses Security.framework with
    // kSecAttrAccessibleWhenUnlocked which doesn't set per-app ACLs.
    //
    // Default posture: use `-A` (any-app access). The `security` CLI
    // without -A or -T creates an ACL that only trusts `security` itself —
    // blocking the Swift app. With -A, any app when keychain is unlocked
    // can access (matching the Swift app's behavior). This is acceptable
    // because:
    // 1. macOS Keychain encrypts at rest (locked keychain = no access)
    // 2. Physical access + unlocked session already implies full compromise
    // 3. Lifecycle scripts are blocked by lpm-security (no postinstall)
    //
    // H5 opt-out: operators who do NOT use the Swift desktop app can set
    // `LPM_VAULT_KEYCHAIN_RESTRICT=1` to drop `-A` and let the macOS
    // keychain default to the more restrictive policy where only
    // `/usr/bin/security` (the CLI we shell out to) is in the ACL.
    // Trade-off: the Swift desktop app then cannot read the entries
    // without the user re-approving them via the keychain prompt on
    // first access. The default stays `-A` because the Swift app is a
    // first-class consumer; the opt-out exists for users who want
    // tighter posture.
    //
    // Pattern: delete + add with retry. The delete+add is not atomic, so
    // concurrent writes (e.g., parallel tests writing the __index__ entry)
    // can race: process A deletes, process B deletes (no-op), process A adds,
    // process B add fails (errSecDuplicateItem). The retry handles this by
    // deleting the stale entry and re-adding.
    //
    // We cannot use -U (update-if-exists) with -A because macOS Keychain's
    // SecKeychainItemModifyContent fails when the existing item's ACL differs
    // from what -U/-A would set — producing errSecDuplicateItem instead of
    // updating.
    //
    // For CLI-only services (lpm-cli auth tokens): same delete+add pattern
    // but without -A for stricter ACL.

    let is_shared = service == SERVICE;
    let is_test_service = cfg!(debug_assertions) && service.starts_with("dev.lpm.vault.test.");
    let use_any_app_acl = if is_shared {
        !restrict_acl_via_env()
    } else if is_test_service {
        // Debug-build-only carve-out for the keychain integration
        // tests. Tests write to a pid-suffixed service like
        // `dev.lpm.vault.test.<pid>` so they never collide with real
        // vault data; the trade-off is that the strict ACL (which
        // restricts the entry to whoever wrote it) would force a
        // macOS keychain prompt on the read-after-write path of a
        // fresh runner — the dedicated-lane invocation
        // (LPM_RUN_KEYCHAIN_TESTS=1, --include-ignored,
        // --test-threads=1) cannot answer that prompt. `-A` widens
        // the ACL to "any app while keychain unlocked" for the test
        // entry only; cleanup deletes the entry immediately after
        // the assertions. Release builds (`!cfg!(debug_assertions)`)
        // never take this branch, so a release binary cannot be
        // tricked into using the test ACL via a crafted service
        // string.
        true
    } else {
        false
    };

    // Attempt delete+add, retry once on errSecDuplicateItem (exit 45)
    for attempt in 0..2 {
        // Delete existing entry (ignore errors if missing)
        let _ = std::process::Command::new("security")
            .args(["delete-generic-password", "-s", service, "-a", account])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        let extra: &[&str] = if use_any_app_acl { &["-A"] } else { &[] };
        // Debug-build-only carve-out: for test services the password is
        // a fixture string ("hello-vault", "value-1", etc.), not a real
        // credential, so the argv-leak that the stdin-piped helper
        // exists to prevent does not apply. The stdin path additionally
        // relies on `readpassphrase()` reading from stdin instead of
        // `/dev/tty`, which is platform-version-dependent on macOS —
        // when the security CLI falls back to /dev/tty for the
        // re-confirm prompt the write succeeds with an empty password
        // and the read-after-write assertion fails. Argv form
        // sidesteps both concerns for the test lane. Release builds
        // (`!cfg!(debug_assertions)`) always go through the stdin
        // helper so no real credential ever lands in argv.
        #[cfg(debug_assertions)]
        let result = if is_test_service {
            macos_security_add_generic_password_argv(service, account, password, extra)
        } else {
            macos_security_add_generic_password(service, account, password, extra)
        };

        #[cfg(not(debug_assertions))]
        let result = macos_security_add_generic_password(service, account, password, extra);

        match result {
            Ok(()) => return Ok(()),
            Err(msg) => {
                // Exit 45 = errSecDuplicateItem — another process added the
                // entry between our delete and add. Retry once.
                if attempt == 0 && msg.contains("exit 45") {
                    continue;
                }
                return Err(msg);
            }
        }
    }

    unreachable!("loop always returns")
}

/// Test-only sibling of [`macos_security_add_generic_password`] that
/// passes the password via argv (`-w <password>`) instead of stdin.
/// Used by the keychain integration tests because `security`'s
/// `readpassphrase()` call falls back to `/dev/tty` for the re-confirm
/// prompt on some macOS versions; the dedicated-lane runner can't
/// answer that prompt and the write succeeds with an empty value
/// (silent failure surfacing only on the read-after-write check).
///
/// `cfg(debug_assertions)`-gated at the only call site so a release
/// binary can never reach this argv-leak path for real services.
#[cfg(debug_assertions)]
fn macos_security_add_generic_password_argv(
    service: &str,
    account: &str,
    password: &str,
    extra_args: &[&str],
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    let mut args: Vec<&str> = vec!["add-generic-password"];
    args.extend_from_slice(extra_args);
    args.extend(["-s", service, "-a", account, "-w", password]);
    let output = Command::new("security")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("keychain spawn error: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "security add-generic-password failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    ))
}

/// H5: returns `true` when the operator has opted in to the
/// more-restrictive keychain ACL by setting
/// `LPM_VAULT_KEYCHAIN_RESTRICT=1`. Default `false` preserves the
/// Swift desktop app's interop (current behavior).
///
/// Accepts `1`, `true`, `yes`, `on` (case-insensitive). Anything
/// else (including unset) → false.
fn restrict_acl_via_env() -> bool {
    matches!(
        std::env::var("LPM_VAULT_KEYCHAIN_RESTRICT")
            .ok()
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Spawn `security add-generic-password` with the password piped via
/// stdin rather than passed as `-w <value>` argv. See the matching
/// helper in `lpm-auth` for the threat-model rationale (`ps` leak).
/// `extra_args` carries the optional `-A` flag for shared-service
/// items.
fn macos_security_add_generic_password(
    service: &str,
    account: &str,
    password: &str,
    extra_args: &[&str],
) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut args: Vec<&str> = vec!["add-generic-password"];
    args.extend_from_slice(extra_args);
    args.extend(["-s", service, "-a", account, "-w"]);

    let mut child = Command::new("security")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("keychain spawn error: {e}"))?;

    {
        // `security` calls readpassphrase() twice (initial entry +
        // retype verification). Feed the password on both lines and
        // close stdin so the CLI proceeds to write the item.
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "keychain stdin not piped".to_string())?;
        stdin
            .write_all(password.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.write_all(password.as_bytes()))
            .and_then(|_| stdin.write_all(b"\n"))
            .map_err(|e| format!("keychain stdin write error: {e}"))?;
    }
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
        .map_err(|e| format!("keychain wait error: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "security add-generic-password failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    ))
}

/// Outcome of a keychain delete. Distinguishes "the item didn't
/// exist" (a normal idempotent outcome for `lpm logout` etc.) from
/// "the delete actually failed" (which should surface to the user so
/// they don't believe their token was wiped when it wasn't).
///
/// macOS `security delete-generic-password` returns exit 44 for
/// `errSecItemNotFound`; any other non-zero exit is a real failure.
#[derive(Debug)]
pub(crate) enum KeychainDeleteOutcome {
    /// Item was present and is now gone.
    Deleted,
    /// Item was already absent — no-op. Treated as success by every
    /// caller that just wants the slot empty afterwards.
    NotFound,
}

fn delete_keychain_password(service: &str, account: &str) -> Result<KeychainDeleteOutcome, String> {
    let output = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", service, "-a", account])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("keychain delete spawn error: {e}"))?;

    if output.status.success() {
        return Ok(KeychainDeleteOutcome::Deleted);
    }
    // Exit 44 = errSecItemNotFound. Already-absent is success for our
    // idempotent delete semantics — don't surface to the caller as an
    // error.
    if output.status.code() == Some(44) {
        return Ok(KeychainDeleteOutcome::NotFound);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "security delete-generic-password failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests hit the real macOS Keychain with a unique
    // pid-suffixed service name and clean up after themselves.
    //
    // Opt-in execution. Tests that CALL `security add-generic-password`
    // are `#[ignore]`d and gated behind the
    // `LPM_RUN_KEYCHAIN_TESTS=1` env var. They are NOT in the
    // default `cargo test` / `cargo nextest run` path because
    // parallel `security` invocations stack macOS keychain
    // authorization dialogs that either hang waiting for user input
    // or auto-cancel with `exit 154: authorization was canceled by
    // the user` — the stdin-piped password feed in
    // `macos_security_add_generic_password` cannot answer the
    // prompt programmatically.
    //
    // To run the gated tests:
    //     LPM_RUN_KEYCHAIN_TESTS=1 cargo test -p lpm-vault \
    //         --lib keychain:: -- --include-ignored --test-threads=1
    //
    // `--test-threads=1` is load-bearing: each `security` call must
    // complete (and any prompt dismissed by the runner) before the
    // next one fires. The env-var gate is a safety net so a stray
    // `--include-ignored` doesn't accidentally trigger keychain
    // prompts from elsewhere.
    //
    // The non-writing tests (`keychain_read_missing`,
    // `delete_keychain_password_returns_not_found_when_item_absent`,
    // `restrict_acl_env_*`) stay in the default run because they
    // exercise pure read or pure env-var logic that never reaches
    // the `security add-generic-password` path.

    /// Hard gate: panic with a clear remediation message if the
    /// opt-in env var is unset. Called as the FIRST line of each
    /// ignored-by-default keychain test so an accidental
    /// `--include-ignored` (without the env var) produces a clear
    /// error instead of a real keychain mutation attempt.
    fn require_keychain_opt_in() {
        if std::env::var("LPM_RUN_KEYCHAIN_TESTS").is_err() {
            panic!(
                "keychain integration test requires `LPM_RUN_KEYCHAIN_TESTS=1`. \
                 Run via: `LPM_RUN_KEYCHAIN_TESTS=1 cargo test -p lpm-vault --lib keychain:: -- --include-ignored --test-threads=1`"
            );
        }
    }

    fn test_service() -> String {
        format!("dev.lpm.vault.test.{}", std::process::id())
    }

    fn cleanup_item(service: &str, account: &str) {
        let _ = std::process::Command::new("security")
            .args(["delete-generic-password", "-s", service, "-a", account])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    #[test]
    #[ignore = "macOS keychain integration; see require_keychain_opt_in for the dedicated-lane run instructions"]
    fn keychain_round_trip() {
        require_keychain_opt_in();
        let svc = test_service();
        let account = "test-round-trip";
        defer_cleanup(&svc, account);

        write_keychain_password(&svc, account, "hello-vault").unwrap();
        let result = read_keychain_password(&svc, account);
        assert_eq!(result.as_deref(), Some("hello-vault"));

        cleanup_item(&svc, account);
    }

    #[test]
    fn keychain_read_missing() {
        // Read-only path — the `security find-generic-password`
        // invocation does not require the keychain ACL prompt that
        // `add-generic-password` triggers under parallel execution.
        // Safe to leave on the default run.
        let svc = test_service();
        let result = read_keychain_password(&svc, "nonexistent");
        assert!(result.is_none());
    }

    #[test]
    #[ignore = "macOS keychain integration; see require_keychain_opt_in for the dedicated-lane run instructions"]
    fn keychain_overwrite() {
        require_keychain_opt_in();
        let svc = test_service();
        let account = "test-overwrite";
        defer_cleanup(&svc, account);

        write_keychain_password(&svc, account, "value-1").unwrap();
        write_keychain_password(&svc, account, "value-2").unwrap();
        let result = read_keychain_password(&svc, account);
        assert_eq!(result.as_deref(), Some("value-2"));

        cleanup_item(&svc, account);
    }

    #[test]
    #[ignore = "macOS keychain integration; see require_keychain_opt_in for the dedicated-lane run instructions"]
    fn keychain_json_secrets() {
        require_keychain_opt_in();
        let svc = test_service();
        let account = "test-json";
        defer_cleanup(&svc, account);

        let mut secrets = HashMap::new();
        secrets.insert("DB_HOST".to_string(), "localhost".to_string());
        secrets.insert("API_KEY".to_string(), "sk-123".to_string());

        let json = serde_json::to_string(&secrets).unwrap();
        write_keychain_password(&svc, account, &json).unwrap();

        let stored = read_keychain_password(&svc, account).unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(&stored).unwrap();
        assert_eq!(parsed["DB_HOST"], "localhost");
        assert_eq!(parsed["API_KEY"], "sk-123");

        cleanup_item(&svc, account);
    }

    fn defer_cleanup(_svc: &str, _account: &str) {
        // Marker function — cleanup_item is called explicitly.
        // Using defer pattern would require a Drop impl, but explicit cleanup is fine for tests.
    }

    /// `delete_keychain_password` distinguishes "already absent"
    /// (idempotent success) from "real failure" (locked keychain,
    /// permission denied, framework error). Pre-fix the function
    /// returned `()` and swallowed every outcome, so `lpm logout`
    /// could claim success while leaving the entry in place.
    ///
    /// Stays on the default run because the absent-item path returns
    /// exit 44 immediately without prompting for keychain ACL approval.
    #[test]
    fn delete_keychain_password_returns_not_found_when_item_absent() {
        let svc = test_service();
        // Cleanup just in case a prior failed test left an entry behind.
        cleanup_item(&svc, "never-written");

        match delete_keychain_password(&svc, "never-written") {
            Ok(KeychainDeleteOutcome::NotFound) => {}
            other => panic!("expected NotFound for absent item, got {other:?}"),
        }
    }

    /// And the post-write call returns `Deleted` — exercising the
    /// success path that `delete_vault` now propagates instead of
    /// silently ignoring.
    #[test]
    #[ignore = "macOS keychain integration; see require_keychain_opt_in for the dedicated-lane run instructions"]
    fn delete_keychain_password_returns_deleted_when_item_present() {
        require_keychain_opt_in();
        let svc = test_service();
        let account = "test-deleted";
        write_keychain_password(&svc, account, "to-be-deleted").unwrap();

        match delete_keychain_password(&svc, account) {
            Ok(KeychainDeleteOutcome::Deleted) => {}
            other => panic!("expected Deleted, got {other:?}"),
        }

        // Sanity: second delete is NotFound (idempotent).
        match delete_keychain_password(&svc, account) {
            Ok(KeychainDeleteOutcome::NotFound) => {}
            other => panic!("second delete should report NotFound, got {other:?}"),
        }
    }

    /// Global mutex serialising the three H5 env-mutation tests so
    /// they don't race against each other (or other tests in this
    /// process that touch the same env var).
    static H5_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// H5: the `LPM_VAULT_KEYCHAIN_RESTRICT` env var is the operator's
    /// opt-out from the `-A` (any-app while unlocked) ACL. Default
    /// off (preserves Swift-app interop); accepts `1`/`true`/`yes`/`on`.
    #[test]
    fn restrict_acl_env_default_off() {
        let _g = H5_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prior = std::env::var("LPM_VAULT_KEYCHAIN_RESTRICT").ok();
        unsafe {
            std::env::remove_var("LPM_VAULT_KEYCHAIN_RESTRICT");
        }
        assert!(
            !restrict_acl_via_env(),
            "default must be permissive (-A) for Swift app interop"
        );
        unsafe {
            if let Some(v) = prior {
                std::env::set_var("LPM_VAULT_KEYCHAIN_RESTRICT", v);
            }
        }
    }

    #[test]
    fn restrict_acl_env_accepts_truthy_values() {
        let _g = H5_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prior = std::env::var("LPM_VAULT_KEYCHAIN_RESTRICT").ok();
        for value in ["1", "true", "yes", "on", "TRUE", "Yes", "ON"] {
            unsafe {
                std::env::set_var("LPM_VAULT_KEYCHAIN_RESTRICT", value);
            }
            assert!(
                restrict_acl_via_env(),
                "value '{value}' must enable the restrictive ACL"
            );
        }
        unsafe {
            match prior {
                Some(v) => std::env::set_var("LPM_VAULT_KEYCHAIN_RESTRICT", v),
                None => std::env::remove_var("LPM_VAULT_KEYCHAIN_RESTRICT"),
            }
        }
    }

    #[test]
    fn restrict_acl_env_ignores_other_values() {
        let _g = H5_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prior = std::env::var("LPM_VAULT_KEYCHAIN_RESTRICT").ok();
        for value in ["0", "false", "no", "off", "asdf", ""] {
            unsafe {
                std::env::set_var("LPM_VAULT_KEYCHAIN_RESTRICT", value);
            }
            assert!(
                !restrict_acl_via_env(),
                "value '{value}' must NOT enable the restrictive ACL"
            );
        }
        unsafe {
            match prior {
                Some(v) => std::env::set_var("LPM_VAULT_KEYCHAIN_RESTRICT", v),
                None => std::env::remove_var("LPM_VAULT_KEYCHAIN_RESTRICT"),
            }
        }
    }
}
