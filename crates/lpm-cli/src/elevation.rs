use std::path::Path;

use lpm_common::LpmError;

#[cfg(any(test, unix))]
const TRUSTED_SUDO_PATHS: &[&str] = &[
    "/usr/bin/sudo",
    "/bin/sudo",
    "/run/wrappers/bin/sudo",
    "/run/current-system/sw/bin/sudo",
];

#[cfg(any(test, unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElevationPlatform {
    #[cfg(any(test, unix))]
    Unix,
    #[cfg(any(test, windows))]
    Windows,
}

#[cfg(any(test, unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElevationBackend {
    #[cfg(any(test, unix))]
    Sudo(&'static str),
    #[cfg(any(test, windows))]
    WindowsRunAs,
}

#[cfg(any(test, unix, windows))]
fn select_elevation_backend(
    platform: ElevationPlatform,
    candidate_exists: impl Fn(&Path) -> bool,
) -> Option<ElevationBackend> {
    match platform {
        #[cfg(any(test, unix))]
        ElevationPlatform::Unix => TRUSTED_SUDO_PATHS
            .iter()
            .copied()
            .find(|candidate| candidate_exists(Path::new(candidate)))
            .map(ElevationBackend::Sudo),
        #[cfg(any(test, windows))]
        ElevationPlatform::Windows => Some(ElevationBackend::WindowsRunAs),
    }
}

pub(crate) fn run_current_exe_helper(
    args: &[String],
    prompt: &str,
    helper: &str,
) -> Result<(), LpmError> {
    let exe = std::env::current_exe().map_err(|error| {
        LpmError::Registry(format!(
            "could not resolve the current executable for the privileged {helper} helper: {error}"
        ))
    })?;
    run_platform_helper(&exe, args, prompt, helper)
}

#[cfg(unix)]
fn run_platform_helper(
    exe: &Path,
    args: &[String],
    prompt: &str,
    helper: &str,
) -> Result<(), LpmError> {
    let Some(ElevationBackend::Sudo(sudo)) =
        select_elevation_backend(ElevationPlatform::Unix, trusted_sudo_candidate)
    else {
        return Err(LpmError::Registry(format!(
            "could not find a trusted sudo executable for the privileged {helper} helper; checked {}",
            TRUSTED_SUDO_PATHS.join(", ")
        )));
    };

    let status = std::process::Command::new(sudo)
        .arg("-p")
        .arg(prompt)
        .arg("--")
        .arg(exe)
        .args(args)
        .status()
        .map_err(|error| {
            LpmError::Registry(format!(
                "could not run the privileged {helper} helper with {sudo}: {error}"
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "privileged {helper} helper exited with {status}"
        )))
    }
}

#[cfg(unix)]
fn trusted_sudo_candidate(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
    })
}

#[cfg(windows)]
fn run_platform_helper(
    exe: &Path,
    args: &[String],
    _prompt: &str,
    helper: &str,
) -> Result<(), LpmError> {
    let Some(ElevationBackend::WindowsRunAs) =
        select_elevation_backend(ElevationPlatform::Windows, |_| false)
    else {
        return Err(LpmError::Registry(format!(
            "Windows runas elevation is unavailable for the privileged {helper} helper"
        )));
    };
    run_windows_elevated_helper(exe, args, helper)
}

#[cfg(not(any(unix, windows)))]
fn run_platform_helper(
    _exe: &Path,
    _args: &[String],
    _prompt: &str,
    helper: &str,
) -> Result<(), LpmError> {
    Err(LpmError::Registry(format!(
        "privileged {helper} helpers are not available on this platform"
    )))
}

#[cfg(windows)]
fn run_windows_elevated_helper(exe: &Path, args: &[String], helper: &str) -> Result<(), LpmError> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, INFINITE, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    struct ProcessHandle(HANDLE);

    impl ProcessHandle {
        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    // SAFETY: This handle came from ShellExecuteExW with
                    // SEE_MASK_NOCLOSEPROCESS and is owned by this guard.
                    CloseHandle(self.0);
                }
            }
        }
    }

    let verb = wide_str("runas");
    let file: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let parameters = wide_str(&quote_windows_args(args));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };

    let launched = unsafe {
        // SAFETY: `info` points to a fully initialized SHELLEXECUTEINFOW. The
        // UTF-16 buffers are null-terminated and live until this call returns.
        ShellExecuteExW(&mut info)
    };
    if launched == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            return Err(LpmError::Registry(format!(
                "Windows elevation was cancelled for the privileged {helper} helper"
            )));
        }
        return Err(LpmError::Registry(format!(
            "could not run the privileged {helper} helper with Windows UAC: {error}"
        )));
    }
    if info.hProcess.is_null() {
        return Err(LpmError::Registry(format!(
            "the privileged {helper} helper did not return a Windows process handle"
        )));
    }

    let process = ProcessHandle(info.hProcess);
    let wait = unsafe {
        // SAFETY: `process.raw()` is the live process handle returned by
        // ShellExecuteExW and remains owned by `process` during this wait.
        WaitForSingleObject(process.raw(), INFINITE)
    };
    if wait == WAIT_FAILED {
        return Err(LpmError::Registry(format!(
            "could not wait for the privileged {helper} helper: {}",
            std::io::Error::last_os_error()
        )));
    }
    if wait != WAIT_OBJECT_0 {
        return Err(LpmError::Registry(format!(
            "waiting for the privileged {helper} helper returned 0x{wait:08X}"
        )));
    }

    let mut exit_code = 1u32;
    let got_exit = unsafe {
        // SAFETY: `process.raw()` remains valid after the successful wait, and
        // `exit_code` is a valid out pointer for GetExitCodeProcess.
        GetExitCodeProcess(process.raw(), &mut exit_code)
    };
    if got_exit == 0 {
        return Err(LpmError::Registry(format!(
            "could not read the privileged {helper} helper exit code: {}",
            std::io::Error::last_os_error()
        )));
    }
    if exit_code == 0 {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "privileged {helper} helper exited with code {exit_code}"
        )))
    }
}

#[cfg(windows)]
fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn quote_windows_args(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(test, windows))]
fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\"' | b'\\'))
    {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                quoted.push('\\');
            }
            quoted.push('"');
            backslashes = 0;
            continue;
        }
        for _ in 0..backslashes {
            quoted.push('\\');
        }
        backslashes = 0;
        quoted.push(ch);
    }
    for _ in 0..(backslashes * 2) {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_elevation_uses_nixos_sudo_wrapper_when_fhs_paths_are_absent() {
        let backend = select_elevation_backend(ElevationPlatform::Unix, |path| {
            path == Path::new("/run/wrappers/bin/sudo")
        });

        assert_eq!(
            backend,
            Some(ElevationBackend::Sudo("/run/wrappers/bin/sudo"))
        );
    }

    #[test]
    fn unix_elevation_does_not_search_untrusted_paths() {
        let backend = select_elevation_backend(ElevationPlatform::Unix, |path| {
            path == Path::new("/tmp/sudo")
        });

        assert_eq!(backend, None);
    }

    #[test]
    fn windows_elevation_uses_runas_backend() {
        let backend = select_elevation_backend(ElevationPlatform::Windows, |_| false);

        assert_eq!(backend, Some(ElevationBackend::WindowsRunAs));
    }

    #[test]
    fn windows_arg_quoting_escapes_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(
            quote_windows_arg(r#"C:\Program Files\LPM\lpm-rs.exe"#),
            r#""C:\Program Files\LPM\lpm-rs.exe""#
        );
        assert_eq!(
            quote_windows_arg(r#"host"alias.test"#),
            r#""host\"alias.test""#
        );
        assert_eq!(quote_windows_arg(r#"C:\Temp\"#), r#""C:\Temp\\""#);
    }
}
