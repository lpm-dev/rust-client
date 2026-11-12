use std::ffi::OsStr;

use lpm_common::LpmError;

use crate::cli::Commands;

#[cfg(all(unix, debug_assertions))]
const TEST_ASSUME_ROOT_ENV: &str = "LPM_TEST_ASSUME_EUID_ROOT";

pub(crate) fn ensure_user_invocation_allowed() -> Result<(), LpmError> {
    if is_sudo_transition() {
        Err(LpmError::SudoNotSupported)
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_command_allowed(command: &Commands) -> Result<(), LpmError> {
    if is_sudo_transition() && !is_privileged_helper(command) {
        Err(LpmError::SudoNotSupported)
    } else {
        Ok(())
    }
}

#[cfg_attr(
    not(any(unix, windows)),
    expect(
        clippy::unnecessary_wraps,
        reason = "Unix requires effective root and Windows an elevated token"
    )
)]
pub(crate) fn require_effective_root(helper: &str) -> Result<(), LpmError> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = helper;
        Ok(())
    }

    #[cfg(unix)]
    if is_effective_root() {
        Ok(())
    } else {
        Err(LpmError::Forbidden(format!(
            "the internal {helper} helper requires effective UID 0"
        )))
    }

    #[cfg(windows)]
    if is_elevated() {
        Ok(())
    } else {
        Err(LpmError::Forbidden(format!(
            "the internal {helper} helper must run elevated, as an administrator"
        )))
    }
}

#[cfg(unix)]
pub(crate) fn is_effective_root() -> bool {
    effective_uid() == 0
}

/// Whether the process runs with an elevated token, as an administrator's
/// does after a UAC prompt or with UAC off.
#[cfg(windows)]
pub(crate) fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle is valid; `token` receives a handle closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut length = 0;
    // SAFETY: `elevation` is writable for the size passed.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            std::ptr::from_mut(&mut elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    };
    // SAFETY: `token` is open and closed once here.
    unsafe { CloseHandle(token) };
    read != 0 && elevation.TokenIsElevated != 0
}

fn is_sudo_transition() -> bool {
    let effective_uid = effective_uid();
    if effective_uid != 0 {
        return false;
    }
    let sudo_user = std::env::var_os("SUDO_USER");
    classifies_as_sudo_transition(effective_uid, sudo_user.as_deref())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    #[cfg(debug_assertions)]
    if std::env::var_os(TEST_ASSUME_ROOT_ENV).as_deref() == Some(OsStr::new("1")) {
        return 0;
    }

    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    u32::MAX
}

fn classifies_as_sudo_transition(effective_uid: u32, sudo_user: Option<&OsStr>) -> bool {
    if effective_uid != 0 {
        return false;
    }

    match sudo_user {
        None => false,
        Some(user) => match user.to_str() {
            Some(user) => {
                let user = user.trim();
                !user.is_empty() && user != "root"
            }
            None => true,
        },
    }
}

fn is_privileged_helper(command: &Commands) -> bool {
    matches!(
        command,
        Commands::InternalHostsFile(_)
            | Commands::InternalSecurityPolicy(_)
            | Commands::InternalCertStore(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    #[test]
    fn non_root_is_not_a_sudo_transition_even_with_sudo_user() {
        assert!(!classifies_as_sudo_transition(
            501,
            Some(OsStr::new("alice"))
        ));
    }

    #[test]
    fn root_without_sudo_user_is_not_a_sudo_transition() {
        assert!(!classifies_as_sudo_transition(0, None));
    }

    #[test]
    fn root_with_empty_sudo_user_is_not_a_sudo_transition() {
        assert!(!classifies_as_sudo_transition(0, Some(OsStr::new(""))));
    }

    #[test]
    fn root_with_root_sudo_user_is_not_a_sudo_transition() {
        assert!(!classifies_as_sudo_transition(0, Some(OsStr::new("root"))));
    }

    #[test]
    fn root_with_non_root_sudo_user_is_a_sudo_transition() {
        assert!(classifies_as_sudo_transition(0, Some(OsStr::new("alice"))));
    }

    #[test]
    fn internal_hosts_file_is_a_privileged_helper() {
        let command = Cli::try_parse_from(["lpm", "internal-hosts-file", "clean"])
            .unwrap()
            .command
            .unwrap();

        assert!(is_privileged_helper(&command));
    }

    /// Any user could run the internal helpers directly, and a standard
    /// user's could make `C:\ProgramData\lpm` theirs.
    #[cfg(windows)]
    #[test]
    fn the_internal_helpers_need_an_elevated_token_on_windows() {
        let required = require_effective_root("security-policy");
        if is_elevated() {
            assert!(required.is_ok());
        } else {
            assert!(
                required
                    .unwrap_err()
                    .to_string()
                    .contains("must run elevated, as an administrator")
            );
        }
    }

    #[test]
    fn internal_cert_store_is_a_privileged_helper() {
        for argv in [
            &[
                "lpm",
                "internal-cert-store",
                "add",
                "--certificate",
                "MAMCAQA=",
                "--sha256",
                "AB",
            ][..],
            &["lpm", "internal-cert-store", "remove", "--sha1", "AB"][..],
        ] {
            let command = Cli::try_parse_from(argv).unwrap().command.unwrap();
            assert!(is_privileged_helper(&command), "{argv:?}");
        }
        assert!(
            Cli::try_parse_from(["lpm", "internal-cert-store", "add", "--sha256", "AB"]).is_err()
        );
        assert!(Cli::try_parse_from(["lpm", "internal-cert-store", "remove"]).is_err());
    }

    #[test]
    fn internal_security_policy_is_a_privileged_helper() {
        let command = Cli::try_parse_from(["lpm", "internal-security-policy", "enable-enforce"])
            .unwrap()
            .command
            .unwrap();

        assert!(is_privileged_helper(&command));
    }
}
