use super::*;
use crate::control::{ControlStreamContext, handle_control_request};

#[cfg(windows)]
pub(crate) async fn connect_named_pipe_client(
    pipe_name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, ProxyError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT,
    };
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    let mut attempts = 0u8;
    let pipe_name_wide = wide_null(pipe_name);
    loop {
        let ready = unsafe {
            // SAFETY: `pipe_name_wide` is a nul-terminated UTF-16 string that
            // remains alive for the duration of the call.
            WaitNamedPipeW(pipe_name_wide.as_ptr(), 250)
        };
        if ready == 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error().map(|code| code as u32) {
                Some(ERROR_FILE_NOT_FOUND | ERROR_SEM_TIMEOUT | ERROR_PIPE_BUSY)
                    if attempts < 40 =>
                {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    continue;
                }
                _ => return Err(ipc_pipe_connect_error(err, pipe_name)),
            }
        }
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempts < 40 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => return Err(ipc_pipe_connect_error(err, pipe_name)),
        }
    }
}

#[cfg(windows)]
pub(crate) fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
pub(crate) fn create_named_pipe_server(
    pipe_name: &str,
    first_instance: bool,
    allowed_user_sid: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, ProxyError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let security = WindowsPipeSecurity::for_user_sid(allowed_user_sid)?;
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    // SAFETY: `security` owns a SECURITY_ATTRIBUTES value and descriptor that
    // remain alive for the duration of the create call; Tokio copies the
    // resulting OS handle into the returned `NamedPipeServer`.
    unsafe {
        options
            .create_with_security_attributes_raw(pipe_name, security.as_ptr())
            .map_err(|err| ProxyError::Ipc(format!("create named pipe {pipe_name}: {err}")))
    }
}

#[cfg(windows)]
pub(crate) async fn handle_windows_control_stream(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    context: ControlStreamContext,
    expected_client_sid: String,
) -> Result<bool, ProxyError> {
    validate_windows_pipe_client(&stream, &expected_client_sid)?;
    let request = match read_proxy_request_with_timeout(&mut stream).await {
        Ok(request) => request,
        Err(ProxyError::IpcProtocol(message)) if message == EMPTY_CONTROL_FRAME_MESSAGE => {
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    handle_control_request(&mut stream, request, context).await
}

#[cfg(windows)]
pub(crate) fn ipc_pipe_connect_error(err: std::io::Error, pipe_name: &str) -> ProxyError {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    match err.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            ProxyError::IpcUnavailable(format!("{pipe_name} ({err})"))
        }
        _ if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
            ProxyError::IpcUnavailable(format!("{pipe_name} ({err})"))
        }
        _ => ProxyError::Ipc(format!("connect {pipe_name}: {err}")),
    }
}

#[cfg(windows)]
struct WindowsPipeSecurity {
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl WindowsPipeSecurity {
    fn for_user_sid(user_sid: &str) -> Result<Self, ProxyError> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{user_sid})\0")
            .encode_utf16()
            .collect();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `sddl` is a nul-terminated UTF-16 buffer that lives for the
        // duration of the call, and `descriptor` is a valid out pointer.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(ProxyError::Ipc(
                "build current-user named-pipe ACL failed".to_string(),
            ));
        }

        Ok(Self {
            descriptor,
            attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: descriptor.cast(),
                bInheritHandle: 0,
            },
        })
    }

    fn as_ptr(&self) -> *mut std::ffi::c_void {
        std::ptr::from_ref(&self.attributes).cast_mut().cast()
    }
}

#[cfg(windows)]
struct WindowsTokenHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsTokenHandle {
    fn drop(&mut self) {
        // SAFETY: `WindowsTokenHandle` is only constructed after a Windows API
        // returns a non-null owned HANDLE; closing it once in Drop is required.
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
pub(crate) fn current_user_sid_sddl() -> Result<String, ProxyError> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns the process pseudo-handle and
    // `token` is a valid out pointer for `OpenProcessToken`.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return Err(ProxyError::Ipc(format!(
            "open process token: {}",
            std::io::Error::last_os_error()
        )));
    }
    let token = WindowsTokenHandle(token);

    token_user_sid_sddl(token.0, "process")
}

#[cfg(windows)]
pub(crate) fn current_thread_user_sid_sddl() -> Result<String, ProxyError> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: after successful named-pipe impersonation, the current thread
    // may expose an impersonation token; `token` is a valid out pointer.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    if opened == 0 || token.is_null() {
        return Err(ProxyError::Ipc(format!(
            "open impersonated thread token: {}",
            std::io::Error::last_os_error()
        )));
    }
    let token = WindowsTokenHandle(token);

    token_user_sid_sddl(token.0, "thread")
}

#[cfg(windows)]
pub(crate) fn token_user_sid_sddl(
    token: windows_sys::Win32::Foundation::HANDLE,
    token_kind: &str,
) -> Result<String, ProxyError> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};

    let mut needed = 0u32;
    // SAFETY: the first call intentionally passes a null buffer to ask Windows
    // for the required TokenUser byte length via `needed`.
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(ProxyError::Ipc(format!(
            "query {token_kind} token size: {}",
            std::io::Error::last_os_error()
        )));
    }

    let word_len = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; word_len];
    // SAFETY: `buffer` is sized from the byte count returned by Windows above
    // and is aligned to at least pointer width for the TOKEN_USER layout.
    let got_token = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if got_token == 0 {
        return Err(ProxyError::Ipc(format!(
            "query {token_kind} token user: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: a successful `GetTokenInformation(TokenUser, ...)` writes a
    // TOKEN_USER record at the beginning of the provided buffer.
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: `token_user.User.Sid` is supplied by Windows from the token and
    // `sid_string` is a valid out pointer for the allocated UTF-16 string.
    let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) };
    if converted == 0 || sid_string.is_null() {
        return Err(ProxyError::Ipc(format!(
            "convert {token_kind} token user SID: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut len = 0usize;
    // SAFETY: `sid_string` is nul-terminated by ConvertSidToStringSidW.
    unsafe {
        while *sid_string.add(len) != 0 {
            len += 1;
        }
    }
    // SAFETY: the slice covers the initialized UTF-16 code units before the
    // terminating nul and stays valid until LocalFree below.
    let sid = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, len)) };
    // SAFETY: `sid_string` was allocated by ConvertSidToStringSidW.
    unsafe {
        let _ = windows_sys::Win32::Foundation::LocalFree(sid_string.cast());
    }
    Ok(sid)
}

#[cfg(windows)]
pub(crate) fn validate_windows_pipe_client(
    stream: &tokio::net::windows::named_pipe::NamedPipeServer,
    expected_sid: &str,
) -> Result<(), ProxyError> {
    let client_sid = impersonated_pipe_client_sid_sddl(stream)?;
    if client_sid != expected_sid {
        return Err(ProxyError::Ipc(
            "reject control pipe connection from another Windows user".to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn impersonated_pipe_client_sid_sddl(
    stream: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<String, ProxyError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::RevertToSelf;
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;

    struct RevertGuard;
    impl Drop for RevertGuard {
        fn drop(&mut self) {
            // SAFETY: this Drop guard is created only after a successful
            // impersonation call and restores the thread token on scope exit.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }

    // SAFETY: `stream` is a connected named-pipe server handle; Windows owns
    // the impersonation semantics and reports failure through the return code.
    let impersonated = unsafe { ImpersonateNamedPipeClient(stream.as_raw_handle()) };
    if impersonated == 0 {
        return Err(ProxyError::Ipc(format!(
            "impersonate control pipe client: {}",
            std::io::Error::last_os_error()
        )));
    }
    let _guard = RevertGuard;

    current_thread_user_sid_sddl()
}

#[cfg(windows)]
impl Drop for WindowsPipeSecurity {
    fn drop(&mut self) {
        // SAFETY: `descriptor` is allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW and freed once.
        unsafe {
            let _ = windows_sys::Win32::Foundation::LocalFree(self.descriptor.cast());
        }
    }
}
