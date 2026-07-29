use super::prelude::*;

#[cfg(any(debug_assertions, test))]
fn managed_policy_path_override() -> Option<PathBuf> {
    std::env::var(SECURITY_POLICY_PATH_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
}

#[cfg(not(any(debug_assertions, test)))]
fn managed_policy_path_override() -> Option<PathBuf> {
    None
}

fn managed_policy_path() -> PathBuf {
    if let Some(path) = managed_policy_path_override() {
        return path;
    }
    PathBuf::from(DEFAULT_SECURITY_POLICY_PATH)
}

pub(super) fn managed_policy_error(path: &Path, message: impl Into<String>) -> LpmError {
    LpmError::Registry(format!(
        "managed security policy {} {}",
        path.display(),
        message.into()
    ))
}

fn managed_protection_status(
    path: &Path,
    policy: Option<ManagedPolicy>,
) -> ManagedProtectionStatus {
    let firewall_mode = policy
        .as_ref()
        .and_then(|policy| policy.firewall_mode)
        .map(|mode| mode.as_str().to_string());
    ManagedProtectionStatus {
        path: path.display().to_string(),
        active: firewall_mode.is_some(),
        firewall_mode,
        managed_policy: policy.map(|policy| policy.status),
    }
}

pub(crate) fn load_managed_protection_status() -> Result<ManagedProtectionStatus, LpmError> {
    let path = managed_policy_path();
    let policy = load_managed_policy()?;
    Ok(managed_protection_status(&path, policy))
}

#[cfg(all(unix, any(test, not(debug_assertions))))]
fn canonical_policy_path(path: &Path, default_path: &Path) -> Result<PathBuf, LpmError> {
    let canonical = std::fs::canonicalize(path)?;
    let canonical_default = std::fs::canonicalize(default_path)?;
    if canonical != canonical_default {
        return Err(managed_policy_error(
            path,
            format!("must resolve to {}", default_path.display()),
        ));
    }
    Ok(canonical)
}

#[cfg(all(unix, any(test, not(debug_assertions))))]
fn canonical_policy_parent(path: &Path, default_path: &Path) -> Result<PathBuf, LpmError> {
    let Some(parent) = path.parent() else {
        return Err(managed_policy_error(
            path,
            "must have a managed parent directory",
        ));
    };
    let Some(default_parent) = default_path.parent() else {
        return Err(managed_policy_error(
            default_path,
            "must have a managed parent directory",
        ));
    };
    let Some(file_name) = path.file_name() else {
        return Err(managed_policy_error(path, "must have a managed file name"));
    };
    let Some(default_file_name) = default_path.file_name() else {
        return Err(managed_policy_error(
            default_path,
            "must have a managed file name",
        ));
    };

    let canonical_parent = std::fs::canonicalize(parent)?;
    let canonical_default_parent = std::fs::canonicalize(default_parent)?;
    let canonical_path = canonical_parent.join(file_name);
    let canonical_default_path = canonical_default_parent.join(default_file_name);
    if canonical_path != canonical_default_path {
        return Err(managed_policy_error(
            path,
            format!("must resolve to {}", default_path.display()),
        ));
    }
    Ok(canonical_parent)
}

#[cfg(all(unix, not(any(debug_assertions, test))))]
fn validate_managed_policy_parent_authority(path: &Path) -> Result<(), LpmError> {
    let default_path = Path::new(DEFAULT_SECURITY_POLICY_PATH);
    let parent = canonical_policy_parent(path, default_path)?;
    let mut current = Some(parent.as_path());
    while let Some(dir) = current {
        validate_root_owned_path(dir, true)?;
        current = dir.parent();
    }
    Ok(())
}

#[cfg(all(windows, not(any(debug_assertions, test))))]
fn validate_managed_policy_parent_authority(path: &Path) -> Result<(), LpmError> {
    let default_path = PathBuf::from(DEFAULT_SECURITY_POLICY_PATH);
    if path != default_path {
        return Err(managed_policy_error(
            path,
            format!("must resolve to {}", DEFAULT_SECURITY_POLICY_PATH),
        ));
    }
    let Some(parent) = path.parent() else {
        return Err(managed_policy_error(
            path,
            "must have a managed parent directory",
        ));
    };
    validate_windows_admin_owned_path(parent, true)
}

#[cfg(any(debug_assertions, test))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "debug/test stub must preserve the fallible production signature"
)]
fn validate_managed_policy_parent_authority(_path: &Path) -> Result<(), LpmError> {
    Ok(())
}

fn privileged_policy_io_error(path: &Path, action: &str, err: std::io::Error) -> LpmError {
    LpmError::Registry(format!(
        "could not {action} managed security policy {}: {err}. Re-run with administrator privileges.",
        path.display()
    ))
}

fn ensure_policy_parent_for_write(path: &Path) -> Result<(), LpmError> {
    let Some(parent) = path.parent() else {
        return Err(managed_policy_error(
            path,
            "must have a managed parent directory",
        ));
    };
    #[cfg(unix)]
    let parent_existed = parent.exists();
    std::fs::create_dir_all(parent)
        .map_err(|err| privileged_policy_io_error(path, "prepare", err))?;
    #[cfg(unix)]
    if !parent_existed {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
            .map_err(|err| privileged_policy_io_error(path, "secure parent for", err))?;
    }
    validate_managed_policy_parent_authority(path)
}

fn read_managed_policy_value(path: &Path) -> Result<toml::Value, LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(toml::Value::Table(toml::map::Map::new()));
        }
        Err(error) => return Err(privileged_policy_io_error(path, "inspect", error)),
    }
    validate_managed_policy_authority(path)?;
    let content = lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .map_err(|error| managed_policy_error(path, error.to_string()))?;
    toml::from_str(&content).map_err(|e| managed_policy_error(path, format!("parse error: {e}")))
}

fn table_mut<'a>(
    value: &'a mut toml::Value,
    path: &Path,
    label: &str,
) -> Result<&'a mut toml::map::Map<String, toml::Value>, LpmError> {
    value
        .as_table_mut()
        .ok_or_else(|| managed_policy_error(path, format!("must set `{label}` to a TOML table")))
}

fn child_table_mut<'a>(
    table: &'a mut toml::map::Map<String, toml::Value>,
    key: &str,
    path: &Path,
) -> Result<&'a mut toml::map::Map<String, toml::Value>, LpmError> {
    table
        .entry(key.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| managed_policy_error(path, format!("must set `[{key}]` to a TOML table")))
}

fn ensure_protect_policy_metadata(
    table: &mut toml::map::Map<String, toml::Value>,
    path: &Path,
) -> Result<bool, LpmError> {
    let policy = child_table_mut(table, "policy", path)?;
    let mut changed = false;
    if !policy.contains_key("name") {
        policy.insert(
            "name".to_string(),
            toml::Value::String("lpm local protection".to_string()),
        );
        changed = true;
    }
    if !policy.contains_key("source") {
        policy.insert(
            "source".to_string(),
            toml::Value::String("lpm security protect".to_string()),
        );
        changed = true;
    }
    Ok(changed)
}

fn policy_value_has_enforced_controls(value: &toml::Value) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    table.contains_key("script-policy")
        || table.contains_key("minimum-release-age-secs")
        || table.contains_key(crate::release_age_config::GLOBAL_POLICY_KEY)
        || table.contains_key(crate::commands::config::TYPOSQUAT_GUARD_KEY)
        || table
            .get("sandbox")
            .and_then(toml::Value::as_table)
            .is_some_and(|sandbox| {
                sandbox.contains_key("mode") || sandbox.contains_key("allow-degraded")
            })
        || table
            .get("sigstore")
            .and_then(toml::Value::as_table)
            .is_some_and(|sigstore| sigstore.contains_key("verify"))
        || table
            .get(crate::npm_firewall_config::FIREWALL_CONFIG_SECTION)
            .and_then(toml::Value::as_table)
            .is_some_and(|firewall| {
                firewall.contains_key(crate::npm_firewall_config::FIREWALL_CONFIG_MODE_KEY)
            })
}

fn remove_empty_table(table: &mut toml::map::Map<String, toml::Value>, key: &str) {
    if table
        .get(key)
        .and_then(toml::Value::as_table)
        .is_some_and(toml::map::Map::is_empty)
    {
        table.remove(key);
    }
}

fn write_managed_policy_value(path: &Path, value: &toml::Value) -> Result<(), LpmError> {
    if path.exists() {
        validate_managed_policy_authority(path)?;
    } else {
        ensure_policy_parent_for_write(path)?;
    }
    let content = toml::to_string_pretty(value)
        .map_err(|e| managed_policy_error(path, format!("serialize error: {e}")))?;
    lpm_common::write_file_atomic_with_options(
        path,
        content,
        lpm_common::AtomicWriteOptions::new()
            .unix_mode(0o644)
            .sync_file(),
    )
    .map_err(|err| privileged_policy_io_error(path, "write", err))?;
    validate_managed_policy_authority(path)
}

pub(crate) fn install_managed_firewall_protection(
    mode: crate::npm_firewall_config::NpmFirewallMode,
) -> Result<ManagedProtectionReport, LpmError> {
    if matches!(mode, crate::npm_firewall_config::NpmFirewallMode::Off) {
        return Err(LpmError::Registry(
            "`lpm security protect enable` requires `--firewall monitor` or `--firewall enforce`; `off` would not protect against LPM_HOME bypass".into(),
        ));
    }

    let path = managed_policy_path();
    let mut value = read_managed_policy_value(&path)?;
    let top = table_mut(&mut value, &path, "policy")?;
    let metadata_changed = ensure_protect_policy_metadata(top, &path)?;
    let firewall = child_table_mut(
        top,
        crate::npm_firewall_config::FIREWALL_CONFIG_SECTION,
        &path,
    )?;
    let previous_mode = firewall
        .get(crate::npm_firewall_config::FIREWALL_CONFIG_MODE_KEY)
        .and_then(toml::Value::as_str)
        .and_then(crate::npm_firewall_config::NpmFirewallMode::parse);
    firewall.insert(
        crate::npm_firewall_config::FIREWALL_CONFIG_MODE_KEY.to_string(),
        toml::Value::String(mode.as_str().to_string()),
    );
    let changed = metadata_changed || previous_mode != Some(mode);
    if changed {
        write_managed_policy_value(&path, &value)?;
    }
    Ok(ManagedProtectionReport {
        change: if changed {
            ManagedProtectionChange::Enabled
        } else {
            ManagedProtectionChange::Unchanged
        },
        status: load_managed_protection_status()?,
    })
}

pub(crate) fn remove_managed_firewall_protection() -> Result<ManagedProtectionReport, LpmError> {
    let path = managed_policy_path();
    if !path.exists() {
        return Ok(ManagedProtectionReport {
            change: ManagedProtectionChange::Unchanged,
            status: managed_protection_status(&path, None),
        });
    }
    let mut value = read_managed_policy_value(&path)?;
    let Some(top) = value.as_table_mut() else {
        return Err(managed_policy_error(
            &path,
            "must be a TOML table at the top level",
        ));
    };
    let removed = top
        .get_mut(crate::npm_firewall_config::FIREWALL_CONFIG_SECTION)
        .and_then(toml::Value::as_table_mut)
        .and_then(|firewall| firewall.remove(crate::npm_firewall_config::FIREWALL_CONFIG_MODE_KEY))
        .is_some();
    if !removed {
        return Ok(ManagedProtectionReport {
            change: ManagedProtectionChange::Unchanged,
            status: load_managed_protection_status()?,
        });
    }
    remove_empty_table(top, crate::npm_firewall_config::FIREWALL_CONFIG_SECTION);
    if policy_value_has_enforced_controls(&value) {
        write_managed_policy_value(&path, &value)?;
    } else {
        validate_managed_policy_authority(&path)?;
        std::fs::remove_file(&path)
            .map_err(|err| privileged_policy_io_error(&path, "remove", err))?;
    }
    Ok(ManagedProtectionReport {
        change: ManagedProtectionChange::Disabled,
        status: load_managed_protection_status()?,
    })
}

#[cfg(all(unix, not(any(debug_assertions, test))))]
fn validate_root_owned_path(path: &Path, expect_dir: bool) -> Result<(), LpmError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(managed_policy_error(
            path,
            "must not be a symlink-backed path",
        ));
    }
    if expect_dir && !metadata.is_dir() {
        return Err(managed_policy_error(path, "must be a directory"));
    }
    if !expect_dir && !metadata.is_file() {
        return Err(managed_policy_error(path, "must be a regular file"));
    }
    if metadata.uid() != 0 {
        return Err(managed_policy_error(path, "must be owned by root"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(managed_policy_error(
            path,
            "must not be group- or world-writable",
        ));
    }
    if metadata.file_type().is_socket()
        || metadata.file_type().is_fifo()
        || metadata.file_type().is_block_device()
        || metadata.file_type().is_char_device()
    {
        return Err(managed_policy_error(
            path,
            "must not be a special device path",
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(any(debug_assertions, test))))]
fn validate_managed_policy_authority(path: &Path) -> Result<(), LpmError> {
    let default_path = Path::new(DEFAULT_SECURITY_POLICY_PATH);
    let canonical = canonical_policy_path(path, default_path)?;

    validate_root_owned_path(path, false)?;
    let mut current = canonical.parent();
    while let Some(dir) = current {
        validate_root_owned_path(dir, true)?;
        current = dir.parent();
    }
    Ok(())
}

#[cfg(all(windows, not(any(debug_assertions, test))))]
fn validate_windows_admin_owned_path(path: &Path, expect_dir: bool) -> Result<(), LpmError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const WRITE_MASK: u32 = 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000 // GENERIC_WRITE
        | 0x0001_0000 // DELETE
        | 0x0004_0000 // WRITE_DAC
        | 0x0008_0000 // WRITE_OWNER
        | 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x0000_0010 // FILE_WRITE_EA
        | 0x0000_0100; // FILE_WRITE_ATTRIBUTES

    struct LocalAlloc(*mut c_void);
    impl Drop for LocalAlloc {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    fn wide_null(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn sid_from_sddl(sddl: &[u16]) -> Result<LocalAlloc, LpmError> {
        let mut sid: PSID = std::ptr::null_mut();
        let ok = unsafe { ConvertStringSidToSidW(sddl.as_ptr(), &mut sid) };
        if ok == 0 || sid.is_null() {
            return Err(LpmError::Registry(
                "failed to initialize Windows managed-policy authority SID".into(),
            ));
        }
        Ok(LocalAlloc(sid.cast()))
    }

    fn sid_matches(sid: PSID, trusted: &[LocalAlloc]) -> bool {
        trusted
            .iter()
            .any(|trusted_sid| unsafe { EqualSid(sid, trusted_sid.0.cast()) != 0 })
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(managed_policy_error(
            path,
            "must not be a reparse-point-backed path",
        ));
    }
    if expect_dir && !metadata.is_dir() {
        return Err(managed_policy_error(path, "must be a directory"));
    }
    if !expect_dir && !metadata.is_file() {
        return Err(managed_policy_error(path, "must be a regular file"));
    }

    let system_sid = sid_from_sddl(&[
        b'S' as u16,
        b'-' as u16,
        b'1' as u16,
        b'-' as u16,
        b'5' as u16,
        b'-' as u16,
        b'1' as u16,
        b'8' as u16,
        0,
    ])?;
    let admins_sid = sid_from_sddl(&[
        b'S' as u16,
        b'-' as u16,
        b'1' as u16,
        b'-' as u16,
        b'5' as u16,
        b'-' as u16,
        b'3' as u16,
        b'2' as u16,
        b'-' as u16,
        b'5' as u16,
        b'4' as u16,
        b'4' as u16,
        0,
    ])?;
    let trusted_sids = [system_sid, admins_sid];

    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let path_wide = wide_null(path);
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(managed_policy_error(
            path,
            format!("could not read Windows security descriptor: error {status}"),
        ));
    }
    let _descriptor_guard = LocalAlloc(descriptor.cast());

    if owner.is_null() || !sid_matches(owner, &trusted_sids) {
        return Err(managed_policy_error(
            path,
            "must be owned by SYSTEM or Administrators",
        ));
    }

    let mut owner_from_descriptor: PSID = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner_from_descriptor, &mut owner_defaulted)
    } == 0
        || owner_from_descriptor.is_null()
        || !sid_matches(owner_from_descriptor, &trusted_sids)
    {
        return Err(managed_policy_error(
            path,
            "must have a valid SYSTEM or Administrators owner",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(managed_policy_error(path, "must have a readable DACL"));
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err(managed_policy_error(path, "must not have a null DACL"));
    }

    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..ace_count {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, u32::from(index), &mut ace) } == 0 || ace.is_null() {
            return Err(managed_policy_error(path, "has an unreadable DACL entry"));
        }
        let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
        if allowed.Mask & WRITE_MASK == 0 {
            continue;
        }
        let sid = std::ptr::addr_of!(allowed.SidStart).cast::<c_void>() as PSID;
        if !sid_matches(sid, &trusted_sids) {
            return Err(managed_policy_error(
                path,
                "must not grant write access to non-administrator principals",
            ));
        }
    }

    Ok(())
}

#[cfg(all(windows, not(any(debug_assertions, test))))]
fn validate_managed_policy_authority(path: &Path) -> Result<(), LpmError> {
    let canonical = std::fs::canonicalize(path)?;
    let default_path = PathBuf::from(DEFAULT_SECURITY_POLICY_PATH);
    let canonical_default = std::fs::canonicalize(&default_path)?;
    if !canonical
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(canonical_default.as_os_str().to_string_lossy().as_ref())
    {
        return Err(managed_policy_error(
            path,
            format!("must resolve to {}", DEFAULT_SECURITY_POLICY_PATH),
        ));
    }

    validate_windows_admin_owned_path(path, false)?;
    let Some(parent) = path.parent() else {
        return Err(managed_policy_error(
            path,
            "must have a managed parent directory",
        ));
    };
    validate_windows_admin_owned_path(parent, true)?;
    Ok(())
}

#[cfg(any(debug_assertions, test))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "debug/test stub must preserve the fallible production signature"
)]
fn validate_managed_policy_authority(_path: &Path) -> Result<(), LpmError> {
    Ok(())
}

fn parse_policy_u64(path: &Path, key: &str, value: &toml::Value) -> Result<Option<u64>, LpmError> {
    match value {
        toml::Value::Integer(raw) => u64::try_from(*raw)
            .map(Some)
            .map_err(|_| managed_policy_error(path, format!("has invalid `{key}` value `{raw}`"))),
        toml::Value::String(raw) => crate::release_age_config::parse_strict_u64_string(raw)
            .map(Some)
            .ok_or_else(|| {
                managed_policy_error(path, format!("has invalid `{key}` value `{raw}`"))
            }),
        _ => Err(managed_policy_error(
            path,
            format!("must set `{key}` to a non-negative integer second count"),
        )),
    }
}

fn parse_policy_sigstore(path: &Path, raw: &str) -> Result<EnforceMode, LpmError> {
    match raw {
        "deny" => Ok(EnforceMode::Deny),
        "warn" => Ok(EnforceMode::Warn),
        "off" => Ok(EnforceMode::Off),
        _ => Err(managed_policy_error(
            path,
            format!("has invalid `[sigstore].verify` value `{raw}`"),
        )),
    }
}

fn parse_policy_firewall(
    path: &Path,
    raw: &str,
) -> Result<crate::npm_firewall_config::NpmFirewallMode, LpmError> {
    crate::npm_firewall_config::NpmFirewallMode::parse(raw).ok_or_else(|| {
        managed_policy_error(path, format!("has invalid `[firewall].mode` value `{raw}`"))
    })
}

pub(super) fn load_managed_policy() -> Result<Option<ManagedPolicy>, LpmError> {
    let path = managed_policy_path();
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(privileged_policy_io_error(&path, "inspect", error)),
    }
    validate_managed_policy_authority(&path)?;

    let content = lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .map_err(|error| managed_policy_error(&path, error.to_string()))?;
    let parsed: toml::Value = toml::from_str(&content)
        .map_err(|e| managed_policy_error(&path, format!("parse error: {e}")))?;
    let table = parsed
        .as_table()
        .ok_or_else(|| managed_policy_error(&path, "must be a TOML table at the top level"))?;

    let policy_meta = table.get("policy").and_then(|value| value.as_table());
    let name = policy_meta
        .and_then(|meta| meta.get("name"))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let source = policy_meta
        .and_then(|meta| meta.get("source"))
        .and_then(|value| value.as_str())
        .map(str::to_string);

    let script_policy = table
        .get("script-policy")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| managed_policy_error(&path, "must set `script-policy` to a string"))
        })
        .transpose()?
        .map(|raw| ScriptPolicy::parse(raw).map_err(|e| managed_policy_error(&path, e.to_string())))
        .transpose()?;

    let minimum_release_age_secs = table
        .get("minimum-release-age-secs")
        .map(|value| parse_policy_u64(&path, "minimum-release-age-secs", value))
        .transpose()?
        .flatten();

    let release_age_policy = table
        .get(crate::release_age_config::GLOBAL_POLICY_KEY)
        .map(|value| {
            value.as_str().ok_or_else(|| {
                managed_policy_error(&path, "must set `release-age-policy` to a string")
            })
        })
        .transpose()?
        .map(|raw| {
            ReleaseAgePolicy::parse("release-age-policy", raw)
                .map_err(|e| managed_policy_error(&path, e.to_string()))
        })
        .transpose()?;

    let sandbox = table.get("sandbox").and_then(|value| value.as_table());
    let sandbox_mode = sandbox
        .and_then(|tbl| tbl.get("mode"))
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| managed_policy_error(&path, "must set `[sandbox].mode` to a string"))
        })
        .transpose()?
        .map(|raw| {
            ResolvedSandboxMode::parse_for_security_floor(raw).ok_or_else(|| {
                managed_policy_error(&path, format!("has invalid `[sandbox].mode` value `{raw}`"))
            })
        })
        .transpose()?;
    let sandbox_allow_degraded = sandbox
        .and_then(|tbl| tbl.get("allow-degraded"))
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                managed_policy_error(&path, "must set `[sandbox].allow-degraded` to a boolean")
            })
        })
        .transpose()?;

    let sigstore = table.get("sigstore").and_then(|value| value.as_table());
    let sigstore_verify = sigstore
        .and_then(|tbl| tbl.get("verify"))
        .map(|value| {
            value.as_str().ok_or_else(|| {
                managed_policy_error(&path, "must set `[sigstore].verify` to a string")
            })
        })
        .transpose()?
        .map(|raw| parse_policy_sigstore(&path, raw))
        .transpose()?;

    let typosquat_guard = table
        .get(crate::commands::config::TYPOSQUAT_GUARD_KEY)
        .map(|value| {
            value.as_str().ok_or_else(|| {
                managed_policy_error(&path, "must set `typosquat-guard` to a string")
            })
        })
        .transpose()?
        .map(|raw| {
            crate::commands::config::TyposquatGuardSelection::parse(raw).ok_or_else(|| {
                managed_policy_error(
                    &path,
                    format!("has invalid `typosquat-guard` value `{raw}`"),
                )
            })
        })
        .transpose()?;

    let firewall = table
        .get(crate::npm_firewall_config::FIREWALL_CONFIG_SECTION)
        .map(|value| {
            value
                .as_table()
                .ok_or_else(|| managed_policy_error(&path, "must set `[firewall]` to a TOML table"))
        })
        .transpose()?;
    let firewall_mode = firewall
        .and_then(|tbl| tbl.get(crate::npm_firewall_config::FIREWALL_CONFIG_MODE_KEY))
        .map(|value| {
            value.as_str().ok_or_else(|| {
                managed_policy_error(&path, "must set `[firewall].mode` to a string")
            })
        })
        .transpose()?
        .map(|raw| parse_policy_firewall(&path, raw))
        .transpose()?;
    let install_time_source_analysis = table
        .get(crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY)
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                managed_policy_error(
                    &path,
                    format!(
                        "must set `{}` to a boolean",
                        crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY
                    ),
                )
            })
        })
        .transpose()?;

    let mut enforced_controls = Vec::new();
    if script_policy.is_some() {
        enforced_controls.push("script-policy".to_string());
    }
    if minimum_release_age_secs.is_some() {
        enforced_controls.push("minimum-release-age-secs".to_string());
    }
    if release_age_policy.is_some() {
        enforced_controls.push(crate::release_age_config::GLOBAL_POLICY_KEY.to_string());
    }
    if sandbox_mode.is_some() {
        enforced_controls.push("sandbox.mode".to_string());
    }
    if sandbox_allow_degraded.is_some() {
        enforced_controls.push("sandbox.allow-degraded".to_string());
    }
    if sigstore_verify.is_some() {
        enforced_controls.push("sigstore.verify".to_string());
    }
    if typosquat_guard.is_some() {
        enforced_controls.push(crate::commands::config::TYPOSQUAT_GUARD_KEY.to_string());
    }
    if firewall_mode.is_some() {
        enforced_controls.push("firewall.mode".to_string());
    }
    if install_time_source_analysis.is_some() {
        enforced_controls
            .push(crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY.to_string());
    }

    Ok(Some(ManagedPolicy {
        status: ManagedPolicyStatus {
            path: path.display().to_string(),
            name,
            source,
            enforced_controls,
        },
        script_policy,
        minimum_release_age_secs,
        release_age_policy,
        sandbox_mode,
        sandbox_allow_degraded,
        sigstore_verify,
        typosquat_guard,
        firewall_mode,
        install_time_source_analysis,
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn canonical_policy_path_accepts_default_path_through_symlinked_parent() {
        let temp = tempfile::tempdir().unwrap();
        let real_etc = temp.path().join("private/etc");
        let link_etc = temp.path().join("etc");
        let real_lpm = real_etc.join("lpm");
        std::fs::create_dir_all(&real_lpm).unwrap();
        std::os::unix::fs::symlink(&real_etc, &link_etc).unwrap();

        let default_path = link_etc.join("lpm/security-policy.toml");
        let real_path = real_lpm.join("security-policy.toml");
        std::fs::write(&real_path, "[firewall]\nmode = \"enforce\"\n").unwrap();
        let canonical_real_path = std::fs::canonicalize(&real_path).unwrap();
        let canonical_real_lpm = std::fs::canonicalize(&real_lpm).unwrap();

        assert_eq!(
            canonical_policy_path(&default_path, &default_path).unwrap(),
            canonical_real_path
        );
        assert_eq!(
            canonical_policy_parent(&default_path, &default_path).unwrap(),
            canonical_real_lpm
        );
    }
}
