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
    run_native_auth_command(linux_native_auth_command()?)
}

#[cfg(any(target_os = "linux", test))]
fn linux_native_auth_command() -> Result<std::process::Command, LpmError> {
    const BACKENDS: &[&str] = &[
        "/usr/bin/pkexec",
        "/bin/pkexec",
        "/run/wrappers/bin/pkexec",
        "/run/current-system/sw/bin/pkexec",
    ];
    let program = BACKENDS.iter().find(|path| trusted_native_auth_program(std::path::Path::new(path)))
        .ok_or_else(|| LpmError::Registry("native security approval requires an administrator-owned polkit pkexec executable in a system directory".into()))?;
    let mut command = std::process::Command::new(program);
    command.arg("/bin/true");
    Ok(command)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn trusted_native_auth_program(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(metadata) = std::fs::metadata(&canonical) else {
        return false;
    };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return false;
    }
    [path.parent(), canonical.parent()]
        .into_iter()
        .flatten()
        .all(|parent| {
            parent.ancestors().all(|dir| {
                std::fs::metadata(dir).is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
                })
            })
        })
}

#[cfg(all(test, not(unix)))]
fn trusted_native_auth_program(_path: &std::path::Path) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn request_platform_approval(prompt: &str) -> Result<bool, LpmError> {
    match request_windows_hello_approval(prompt)? {
        WindowsHelloVerificationAction::Approved => Ok(true),
        WindowsHelloVerificationAction::Denied => Ok(false),
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
    use super::windows_hello_bindings::{
        GetConsoleWindow, IUserConsentVerifierInterop, RPC_E_CHANGED_MODE,
        UserConsentVerificationResult, UserConsentVerifier,
    };
    use windows_core::{HSTRING, factory};
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
    let operation = if hwnd.0.is_null() {
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
            interop.RequestVerificationForWindowAsync::<IAsyncOperation<UserConsentVerificationResult>>(
                hwnd, &message,
            )
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
    fn initialize(changed_mode: windows_core::HRESULT) -> Result<Self, LpmError> {
        use super::windows_hello_bindings::{RO_INIT_MULTITHREADED, RoInitialize};

        // Every success code, including S_FALSE for a thread already in the
        // multithreaded apartment, takes a reference that needs `RoUninitialize`.
        match unsafe {
            // SAFETY: Initializes WinRT for the current thread before using WinRT APIs.
            RoInitialize(RO_INIT_MULTITHREADED)
        }
        .ok()
        {
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
                super::windows_hello_bindings::RoUninitialize();
            }
        }
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowsHelloAvailabilityAction {
    UseWindowsHello,
    FailClosed(&'static str),
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_hello_availability_action(code: i32) -> WindowsHelloAvailabilityAction {
    match code {
        0 => WindowsHelloAvailabilityAction::UseWindowsHello,
        1 => WindowsHelloAvailabilityAction::FailClosed(
            "Windows Hello or PIN is not available on this device",
        ),
        2 => WindowsHelloAvailabilityAction::FailClosed(
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
    FailClosed(&'static str),
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_hello_verification_action(code: i32) -> WindowsHelloVerificationAction {
    match code {
        0 => WindowsHelloVerificationAction::Approved,
        1 => WindowsHelloVerificationAction::FailClosed(
            "Windows Hello or PIN is not available on this device",
        ),
        2 => WindowsHelloVerificationAction::FailClosed(
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

#[cfg(test)]
mod backend_tests {
    #[test]
    fn linux_native_approval_never_resolves_an_executable_from_caller_path() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("pkexec"),
            "fake authentication backend",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::update([(
            "PATH",
            Some(directory.path().as_os_str().to_owned()),
        )]);
        if let Ok(command) = super::linux_native_auth_command() {
            assert!(
                std::path::Path::new(command.get_program()).is_absolute(),
                "native approval must not search the caller's PATH"
            );
            assert_ne!(
                std::path::Path::new(command.get_program()).parent(),
                Some(directory.path())
            );
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_runtime_apartment_tests {
    use super::WindowsRuntimeApartment;
    use crate::security_approval::windows_hello_bindings::{
        RO_INIT_MULTITHREADED, RO_INIT_SINGLETHREADED, RO_INIT_TYPE, RPC_E_CHANGED_MODE,
        RoInitialize, RoUninitialize, S_FALSE, S_OK,
    };
    use lpm_common::LpmError;
    use windows_core::HRESULT;

    /// Runs `test` on a new thread, which starts outside any apartment, and
    /// never alongside another of these tests. When the last apartment in the
    /// process closes, COM tears down process-wide state, and a thread entering
    /// a single-threaded apartment at that moment fails with
    /// ERROR_CANNOT_FIND_WND_CLASS (0x8007057F).
    fn alone_on_fresh_thread(test: impl FnOnce() + Send + 'static) {
        static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _turn = TURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(panic) = std::thread::spawn(test).join() {
            std::panic::resume_unwind(panic);
        }
    }

    fn ro_initialize(mode: RO_INIT_TYPE) -> HRESULT {
        // SAFETY: Each successful call is paired with `ro_uninitialize` on the same thread.
        unsafe { RoInitialize(mode) }
    }

    fn ro_uninitialize() {
        // SAFETY: Paired with a successful `ro_initialize` on this thread.
        unsafe { RoUninitialize() }
    }

    fn enter_apartment() -> WindowsRuntimeApartment {
        WindowsRuntimeApartment::initialize(RPC_E_CHANGED_MODE)
            .unwrap_or_else(|err| panic!("Windows Runtime apartment failed to initialize: {err}"))
    }

    #[test]
    fn first_initialization_on_a_thread_leaves_the_apartment_on_drop() {
        alone_on_fresh_thread(|| {
            let apartment = enter_apartment();
            assert!(apartment.should_uninitialize);
            drop(apartment);

            // A thread still in the multithreaded apartment would get RPC_E_CHANGED_MODE.
            assert_eq!(ro_initialize(RO_INIT_SINGLETHREADED), S_OK);
            ro_uninitialize();
        });
    }

    #[test]
    fn initializing_inside_a_multithreaded_apartment_releases_only_its_own_reference() {
        alone_on_fresh_thread(|| {
            assert_eq!(ro_initialize(RO_INIT_MULTITHREADED), S_OK);

            let apartment = enter_apartment();
            assert!(apartment.should_uninitialize);
            drop(apartment);

            assert_eq!(
                ro_initialize(RO_INIT_SINGLETHREADED),
                RPC_E_CHANGED_MODE,
                "the caller's reference must keep the thread in the multithreaded apartment"
            );
            ro_uninitialize();
            assert_eq!(
                ro_initialize(RO_INIT_SINGLETHREADED),
                S_OK,
                "the approval's S_FALSE reference must have been released"
            );
            ro_uninitialize();
        });
    }

    #[test]
    fn initializing_inside_a_single_threaded_apartment_reuses_it_without_uninitializing() {
        alone_on_fresh_thread(|| {
            assert_eq!(ro_initialize(RO_INIT_SINGLETHREADED), S_OK);

            let apartment = enter_apartment();
            assert!(!apartment.should_uninitialize);
            drop(apartment);

            assert_eq!(
                ro_initialize(RO_INIT_SINGLETHREADED),
                S_FALSE,
                "the caller's single-threaded apartment must survive the approval"
            );
            ro_uninitialize();
            ro_uninitialize();
        });
    }

    #[test]
    fn an_unexpected_initialization_failure_fails_closed_without_leaving_the_callers_apartment() {
        alone_on_fresh_thread(|| {
            assert_eq!(ro_initialize(RO_INIT_SINGLETHREADED), S_OK);

            // With S_OK as the reusable code, the RPC_E_CHANGED_MODE that the
            // single-threaded apartment produces is an unexpected failure.
            let Err(LpmError::Registry(message)) = WindowsRuntimeApartment::initialize(S_OK) else {
                panic!("an unexpected RoInitialize failure must fail closed");
            };
            assert!(
                message.starts_with(
                    "native Windows security approval could not initialize Windows Runtime: "
                ),
                "{message}"
            );
            // The system message before the code is localized.
            assert!(message.ends_with("(0x80010106)"), "{message}");

            assert_eq!(
                ro_initialize(RO_INIT_SINGLETHREADED),
                S_FALSE,
                "the caller's single-threaded apartment must survive the failure"
            );
            ro_uninitialize();
            ro_uninitialize();
        });
    }
}
