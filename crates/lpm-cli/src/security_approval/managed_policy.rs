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

#[cfg_attr(test, allow(dead_code))]
#[cfg(unix)]
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

#[cfg(all(unix, not(test)))]
fn validate_managed_policy_authority(path: &Path) -> Result<(), LpmError> {
    let canonical = std::fs::canonicalize(path)?;
    if canonical != Path::new(DEFAULT_SECURITY_POLICY_PATH) {
        return Err(managed_policy_error(
            path,
            format!("must resolve to {}", DEFAULT_SECURITY_POLICY_PATH),
        ));
    }

    validate_root_owned_path(path, false)?;
    let mut current = path.parent();
    while let Some(dir) = current {
        validate_root_owned_path(dir, true)?;
        if dir == Path::new("/etc") {
            break;
        }
        current = dir.parent();
    }
    Ok(())
}

#[cfg(all(windows, not(test)))]
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

#[cfg(all(windows, not(test)))]
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

#[cfg(test)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "test stub must preserve the fallible production signature"
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
    if !path.exists() {
        return Ok(None);
    }
    validate_managed_policy_authority(&path)?;

    let content = std::fs::read_to_string(&path)?;
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
    }))
}
