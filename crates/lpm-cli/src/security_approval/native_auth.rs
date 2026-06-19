use lpm_common::LpmError;

pub(super) fn request_native_approval(prompt: &str) -> Result<bool, LpmError> {
    if let Some(result) = super::test_native_auth_override() {
        return match result.as_str() {
            "approve" => Ok(true),
            "deny" => Ok(false),
            "error" => Err(LpmError::Registry(
                "test native security approval backend forced an error".into(),
            )),
            other => Err(LpmError::Registry(format!(
                "test native security approval override must be one of: approve | deny | error (got `{other}`)"
            ))),
        };
    }

    request_platform_approval(prompt)
}

#[cfg(target_os = "macos")]
fn request_platform_approval(prompt: &str) -> Result<bool, LpmError> {
    request_macos_local_authentication(prompt)
}

#[cfg(target_os = "linux")]
fn request_platform_approval(_prompt: &str) -> Result<bool, LpmError> {
    run_native_auth_command({
        let mut command = std::process::Command::new("pkexec");
        command.arg("/bin/true");
        command
    })
}

#[cfg(target_os = "windows")]
fn request_platform_approval(prompt: &str) -> Result<bool, LpmError> {
    match request_windows_hello_approval(prompt)? {
        WindowsHelloVerificationAction::Approved => Ok(true),
        WindowsHelloVerificationAction::Denied => Ok(false),
        WindowsHelloVerificationAction::TerminalFallback(reason) => {
            request_windows_terminal_fallback(prompt, reason)
        }
        WindowsHelloVerificationAction::FailClosed(reason) => {
            Err(windows_hello_unavailable_error(reason))
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn request_platform_approval(prompt: &str) -> Result<bool, LpmError> {
    Err(LpmError::Registry(format!(
        "native security approval is not implemented for this platform; prompt was: {prompt}"
    )))
}

#[cfg(target_os = "linux")]
fn run_native_auth_command(mut command: std::process::Command) -> Result<bool, LpmError> {
    match command.status() {
        Ok(status) => Ok(status.success()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(LpmError::Registry(
            "native security approval is unavailable on this machine; use managed policy or install a supported desktop auth backend".into(),
        )),
        Err(err) => Err(LpmError::Registry(format!(
            "native security approval failed to launch: {err}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn request_windows_hello_approval(
    prompt: &str,
) -> Result<WindowsHelloVerificationAction, LpmError> {
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
    use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
    use windows::Win32::System::Console::GetConsoleWindow;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::core::{HSTRING, factory};
    use windows_future::IAsyncOperation;

    let _apartment = WindowsRuntimeApartment::initialize(RPC_E_CHANGED_MODE)?;
    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|operation| operation.join())
        .map_err(|err| {
            LpmError::Registry(format!(
                "native Windows security approval could not check Windows Hello availability: {err}"
            ))
        })?;
    match windows_hello_availability_action(availability.0) {
        WindowsHelloAvailabilityAction::UseWindowsHello => {}
        WindowsHelloAvailabilityAction::TerminalFallback(reason) => {
            return Ok(WindowsHelloVerificationAction::TerminalFallback(reason));
        }
        WindowsHelloAvailabilityAction::FailClosed(reason) => {
            return Ok(WindowsHelloVerificationAction::FailClosed(reason));
        }
    }

    let message = HSTRING::from(prompt);
    let hwnd = unsafe {
        // SAFETY: `GetConsoleWindow` only returns the HWND associated with this process's
        // console, or a null HWND when there is no console window.
        GetConsoleWindow()
    };
    let operation: IAsyncOperation<UserConsentVerificationResult> = if hwnd.0.is_null() {
        UserConsentVerifier::RequestVerificationAsync(&message)
    } else {
        let interop =
            factory::<UserConsentVerifier, IUserConsentVerifierInterop>().map_err(|err| {
                LpmError::Registry(format!(
                    "native Windows security approval could not load Windows Hello interop: {err}"
                ))
            })?;
        unsafe {
            // SAFETY: `interop` is the activation factory for UserConsentVerifier, `hwnd`
            // belongs to this process's console window, and `message` is a live HSTRING.
            interop.RequestVerificationForWindowAsync(hwnd, &message)
        }
    }
    .map_err(|err| {
        LpmError::Registry(format!(
            "native Windows security approval could not open Windows Hello: {err}"
        ))
    })?;

    let result = operation.join().map_err(|err| {
        LpmError::Registry(format!(
            "native Windows security approval did not return a result: {err}"
        ))
    })?;
    Ok(windows_hello_verification_action(result.0))
}

#[cfg(target_os = "windows")]
struct WindowsRuntimeApartment {
    should_uninitialize: bool,
}

#[cfg(target_os = "windows")]
impl WindowsRuntimeApartment {
    fn initialize(changed_mode: windows::core::HRESULT) -> Result<Self, LpmError> {
        match unsafe {
            // SAFETY: Initializes WinRT for the current thread before using WinRT APIs.
            windows::Win32::System::WinRT::RoInitialize(
                windows::Win32::System::WinRT::RO_INIT_MULTITHREADED,
            )
        } {
            Ok(()) => Ok(Self {
                should_uninitialize: true,
            }),
            Err(err) if err.code() == changed_mode => Ok(Self {
                should_uninitialize: false,
            }),
            Err(err) => Err(LpmError::Registry(format!(
                "native Windows security approval could not initialize Windows Runtime: {err}"
            ))),
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsRuntimeApartment {
    fn drop(&mut self) {
        if self.should_uninitialize {
            unsafe {
                // SAFETY: Paired with a successful `RoInitialize` on this thread.
                windows::Win32::System::WinRT::RoUninitialize();
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn request_windows_terminal_fallback(prompt: &str, reason: &str) -> Result<bool, LpmError> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(LpmError::Registry(format!(
            "native Windows security approval is unavailable: {reason}; run this command in an interactive terminal or configure Windows Hello or PIN"
        )));
    }

    crate::output::warn(&format!(
        "Windows Hello security approval is unavailable: {reason}. Falling back to terminal confirmation."
    ));
    cliclack::confirm(prompt)
        .interact()
        .map_err(crate::prompt::prompt_err)
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowsHelloAvailabilityAction {
    UseWindowsHello,
    TerminalFallback(&'static str),
    FailClosed(&'static str),
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_hello_availability_action(code: i32) -> WindowsHelloAvailabilityAction {
    match code {
        0 => WindowsHelloAvailabilityAction::UseWindowsHello,
        1 => WindowsHelloAvailabilityAction::TerminalFallback(
            "Windows Hello or PIN is not available on this device",
        ),
        2 => WindowsHelloAvailabilityAction::TerminalFallback(
            "Windows Hello or PIN is not configured for this user",
        ),
        3 => WindowsHelloAvailabilityAction::FailClosed(
            "Windows Hello or PIN verification is disabled by policy",
        ),
        4 => WindowsHelloAvailabilityAction::FailClosed(
            "Windows Hello or PIN verification device is busy; try again",
        ),
        _ => WindowsHelloAvailabilityAction::FailClosed(
            "Windows Hello or PIN availability returned an unknown status",
        ),
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowsHelloVerificationAction {
    Approved,
    Denied,
    TerminalFallback(&'static str),
    FailClosed(&'static str),
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_hello_verification_action(code: i32) -> WindowsHelloVerificationAction {
    match code {
        0 => WindowsHelloVerificationAction::Approved,
        1 => WindowsHelloVerificationAction::TerminalFallback(
            "Windows Hello or PIN is not available on this device",
        ),
        2 => WindowsHelloVerificationAction::TerminalFallback(
            "Windows Hello or PIN is not configured for this user",
        ),
        3 => WindowsHelloVerificationAction::FailClosed(
            "Windows Hello or PIN verification is disabled by policy",
        ),
        4 => WindowsHelloVerificationAction::FailClosed(
            "Windows Hello or PIN verification device is busy; try again",
        ),
        5 => WindowsHelloVerificationAction::Denied,
        6 => WindowsHelloVerificationAction::Denied,
        _ => WindowsHelloVerificationAction::FailClosed(
            "Windows Hello or PIN verification returned an unknown status",
        ),
    }
}

#[cfg(target_os = "windows")]
fn windows_hello_unavailable_error(reason: &str) -> LpmError {
    LpmError::Registry(format!(
        "native Windows security approval is unavailable: {reason}"
    ))
}

#[cfg(target_os = "macos")]
fn request_macos_local_authentication(prompt: &str) -> Result<bool, LpmError> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::LAContext;
    use std::sync::mpsc;

    // SAFETY: `new` returns a retained `LAContext` instance managed by objc2.
    let context = unsafe { LAContext::new() };
    let policy = macos_local_auth_policy();
    // SAFETY: The context is valid and `policy` is a public LA policy.
    if let Err(error) = unsafe { context.canEvaluatePolicy_error(policy) } {
        return Err(LpmError::Registry(format!(
            "native macOS authentication is unavailable: {}",
            format_macos_auth_error(&error)
        )));
    }

    let fallback_title = macos_local_auth_fallback_title().map(NSString::from_str);
    // SAFETY: Both setters operate on a valid `LAContext`; the fallback title
    // is copied by LocalAuthentication when present and the reuse duration is
    // a scalar.
    unsafe {
        context.setLocalizedFallbackTitle(fallback_title.as_deref());
        context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
    }
    let reason = NSString::from_str(&macos_local_auth_reason(prompt));
    let (tx, rx) = mpsc::channel();
    let reply: RcBlock<dyn Fn(Bool, *mut NSError)> =
        RcBlock::new(move |success: Bool, _error: *mut NSError| {
            let _ = tx.send(success.as_bool());
        });

    // SAFETY: `reason` is non-empty, `reply` is heap-backed and sendable, and
    // both the block and context remain alive until the callback is received.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply);
    }

    rx.recv().map_err(|err| {
        LpmError::Registry(format!(
            "native macOS authentication did not return a result: {err}"
        ))
    })
}

#[cfg(target_os = "macos")]
pub(super) fn macos_local_auth_policy() -> objc2_local_authentication::LAPolicy {
    objc2_local_authentication::LAPolicy::DeviceOwnerAuthentication
}

#[cfg(target_os = "macos")]
pub(super) fn macos_local_auth_fallback_title() -> Option<&'static str> {
    None
}

#[cfg(target_os = "macos")]
fn format_macos_auth_error(error: &objc2_foundation::NSError) -> String {
    format!("{} (code {})", error.localizedDescription(), error.code())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_local_auth_reason(prompt: &str) -> String {
    let trimmed = prompt.trim().trim_end_matches(['?', '.', '!']).trim();
    let trimmed = trimmed.strip_suffix(" now").unwrap_or(trimmed).trim();
    if trimmed.is_empty() {
        return "approve this LPM security action".to_string();
    }

    let mut chars = trimmed.chars();
    let first = chars.next().unwrap_or_default();
    let mut reason = String::with_capacity(trimmed.len());
    reason.extend(first.to_lowercase());
    reason.push_str(chars.as_str());
    reason
}
