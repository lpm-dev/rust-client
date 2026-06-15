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
fn request_platform_approval(_prompt: &str) -> Result<bool, LpmError> {
    run_native_auth_command({
        let mut command = std::process::Command::new("powershell");
        command.args([
            "-NoProfile",
            "-Command",
            "Start-Process -FilePath powershell -ArgumentList '-NoProfile -Command exit 0' -Verb RunAs -Wait",
        ]);
        command
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn request_platform_approval(prompt: &str) -> Result<bool, LpmError> {
    Err(LpmError::Registry(format!(
        "native security approval is not implemented for this platform; prompt was: {prompt}"
    )))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
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

#[cfg(target_os = "macos")]
fn request_macos_local_authentication(prompt: &str) -> Result<bool, LpmError> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::mpsc;

    // SAFETY: `new` returns a retained `LAContext` instance managed by objc2.
    let context = unsafe { LAContext::new() };
    let policy = LAPolicy::DeviceOwnerAuthentication;
    // SAFETY: The context is valid and `DeviceOwnerAuthentication` is a public LA policy.
    if let Err(error) = unsafe { context.canEvaluatePolicy_error(policy) } {
        return Err(LpmError::Registry(format!(
            "native macOS authentication is unavailable: {}",
            format_macos_auth_error(&error)
        )));
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
