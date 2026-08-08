use std::ffi::OsStr;

use lpm_common::LpmError;

use crate::cli::Commands;

#[cfg(debug_assertions)]
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

pub(crate) fn require_effective_root(helper: &str) -> Result<(), LpmError> {
    #[cfg(not(unix))]
    {
        let _ = helper;
        return Ok(());
    }

    #[cfg(unix)]
    if is_effective_root() {
        Ok(())
    } else {
        Err(LpmError::Forbidden(format!(
            "the internal {helper} helper requires effective UID 0"
        )))
    }
}

#[cfg(unix)]
pub(crate) fn is_effective_root() -> bool {
    effective_uid() == 0
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
        Commands::InternalHostsFile(_) | Commands::InternalSecurityPolicy(_)
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

    #[test]
    fn internal_security_policy_is_a_privileged_helper() {
        let command = Cli::try_parse_from(["lpm", "internal-security-policy", "enable-enforce"])
            .unwrap()
            .command
            .unwrap();

        assert!(is_privileged_helper(&command));
    }
}
