use crate::doctor_catalog;

use super::check::Check;

/// Probe the sandbox backend for `SandboxMode::Enforce` on this
/// platform. Runs in-memory (macOS) or via a single benign
/// landlock ruleset-create syscall (Linux); no persistent I/O.
///
/// the probe loads the user's `[sandbox] allow-degraded`
/// config (project lpm.toml + global ~/.lpm/config.toml — same
/// chain the install pipeline uses) so the doctor surface reports
/// the SAME posture the next `lpm install` will actually
/// construct. Without that, a user who opted into degraded posture
/// on a kernel < 6.7 would see "strict / fail" in doctor while
/// their installs silently run under V1 (or vice-versa).
pub(super) fn probe_sandbox_backend() -> Check {
    use lpm_sandbox::{
        SandboxError, SandboxMode, SandboxPosture, SandboxSpec, new_for_platform_with_options,
    };

    let tmpdir = std::env::temp_dir();
    let home = dirs::home_dir().unwrap_or_else(|| tmpdir.clone());
    let spec = SandboxSpec {
        // `validate_spec` requires absolute paths + non-empty
        // identity. Nothing reads from these; the probe only
        // checks whether the backend can be constructed for
        // this platform + mode.
        package_dir: tmpdir.join("lpm-doctor-sandbox-probe"),
        project_dir: tmpdir.join("lpm-doctor-sandbox-probe"),
        package_name: "lpm-doctor-probe".into(),
        package_version: "0.0.0".into(),
        store_root: home.join(".lpm").join("store"),
        home_dir: home.clone(),
        tmpdir: tmpdir.clone(),
        secret_read_allow: Vec::new(),
        extra_write_dirs: Vec::new(),
    };

    // load the `[sandbox] allow-degraded` knob from
    // `<cwd>/lpm.toml` + `~/.lpm/config.toml`. The project-side read
    // uses the current working directory — that's what `lpm doctor`
    // is reporting on, and matches the install pipeline's
    // resolution against the same directory.
    //
    // A failed config load surfaces as `sandbox_probe_failed`
    // EXPLICITLY rather than getting silently defaulted to strict.
    // A broken `lpm.toml` / `~/.lpm/config.toml` makes the real
    // install fail at config-load time; doctor's job is to surface
    // that on the same machine, NOT to hide it behind a default-
    // strict posture the install will never actually reach. Only
    // `current_dir()` failing (no cwd resolvable, e.g. running
    // from a deleted directory) falls back to the strict default —
    // there's no config to parse in that case.
    let (sandbox_options, resolved_mode) = match std::env::current_dir() {
        // route through the precedence chain so
        // `LPM_STRICT_SANDBOX=1` and `[sandbox] mode` flow through
        // the doctor probe identically to the install pipeline.
        Ok(cwd) => {
            match crate::sandbox_config::resolve_sandbox_mode_from_chain(&cwd, false, false, true) {
                Ok(pair) => pair,
                Err(e) => {
                    if e.error_code() == "security_approval_required" {
                        return Check::fail(
                            &doctor_catalog::SANDBOX_CONFIG_APPROVAL_REQUIRED,
                            &format!("sandbox config requires security approval: {e}"),
                        );
                    }
                    return Check::fail(
                        &doctor_catalog::SANDBOX_PROBE_FAILED,
                        &format!(
                            "could not load sandbox config: {e}. Doctor refuses to default \
                         this to strict — the same broken config will fail your next \
                         `lpm install`. Fix `lpm.toml` / `~/.lpm/config.toml` and re-run."
                        ),
                    );
                }
            }
        }
        Err(_) => (
            lpm_sandbox::SandboxOptions::default(),
            crate::sandbox_config::ResolvedSandboxMode::Default,
        ),
    };

    // When the resolved mode is `None` (`[sandbox] mode = "none"` in
    // `~/.lpm/config.toml` / `./lpm.toml`, persisted by
    // `lpm config sandbox --set none`), the install pipeline runs
    // [`SandboxMode::Disabled`] — so doctor must report that posture
    // directly instead of probing `Enforce` and reporting whatever
    // the host's backend happens to support. Otherwise doctor can
    // claim default-mode containment even when config requested none,
    // contradicting install behavior.
    if matches!(
        resolved_mode,
        crate::sandbox_config::ResolvedSandboxMode::None
    ) {
        let os = std::env::consts::OS;
        return Check::warn(
            &doctor_catalog::SANDBOX_DISABLED_BY_USER,
            &format!(
                "sandbox DISABLED on {os} via `[sandbox] mode = \"none\"` (set by \
                 `lpm config sandbox --set none` or directly in `~/.lpm/config.toml` / \
                 `./lpm.toml`). Lifecycle scripts will run WITHOUT filesystem / env / \
                 network containment. Re-enable the default posture via \
                 `lpm config sandbox --set default`."
            ),
        );
    }

    match new_for_platform_with_options(spec, SandboxMode::Enforce, sandbox_options) {
        Ok(sb) => {
            let backend = sb.backend_name();
            let os = std::env::consts::OS;
            // On Windows, `windows-appcontainer` is the strict backend
            // and needs `lpm-sandbox-helper.exe` next to `lpm.exe`.
            // Falling back to Low IL means filesystem containment is
            // available but outbound-network denial is not.
            if os == "windows" && backend == "windows-il" {
                return Check::warn(
                    &doctor_catalog::SANDBOX_HELPER_MISSING,
                    "windows-il available on windows — falling back from AppContainer \
                     because `lpm-sandbox-helper.exe` is not located next to \
                     `lpm.exe`. The Low IL backend contains filesystem \
                     writes but does NOT deny outbound network. Reinstall lpm \
                     (`@lpm-registry/cli`) to restore the helper, or override the \
                     helper location via `LPM_SANDBOX_HELPER=<path>`. With the helper \
                     present, `lpm doctor` reports `windows-appcontainer` and \
                     strict mode is available.",
                );
            }
            match sb.posture() {
                SandboxPosture::Default => Check::pass(
                    &doctor_catalog::SANDBOX_AVAILABLE,
                    &format!(
                        "{backend} available on {os} — default mode: filesystem-write \
                         containment + env scrubbing, outbound network ALLOWED. Enable \
                         strict mode (also denies outbound network) via \
                         `lpm config sandbox --set strict`, `--strict-sandbox` per-command, \
                         or `LPM_STRICT_SANDBOX=1` in env."
                    ),
                ),
                SandboxPosture::Strict => {
                    // Network-denial coverage is platform-asymmetric:
                    // - macOS Seatbelt's `(deny default)` covers every
                    //   socket family unconditionally.
                    // - Windows AppContainer denies
                    //   every socket family via the WFP layer once the
                    //   capability list is empty — same coverage shape
                    //   as macOS Seatbelt.
                    // - Linux landlock V4 + seccomp-bpf
                    //   layered together: landlock denies BindTcp +
                    //   ConnectTcp, seccomp denies direct
                    //   socket(AF_INET|AF_INET6, SOCK_DGRAM|SOCK_RAW)
                    //   + AF_PACKET + AF_NETLINK. AF_UNIX intentionally
                    //   allowed (legitimate IPC); resolver-mediated DNS
                    //   stays host-dependent.
                    let net_coverage = if os == "macos" {
                        "full outbound network denial (all socket families)"
                    } else if backend == "windows-appcontainer" {
                        "full outbound network denial via AppContainer + WFP \
                         (all socket families)"
                    } else {
                        "outbound TCP denial (landlock V4: BindTcp + ConnectTcp) + \
                         direct UDP / raw / AF_PACKET / AF_NETLINK denial \
                         (seccomp-bpf, 1); AF_UNIX allowed for IPC"
                    };
                    Check::pass(
                        &doctor_catalog::SANDBOX_AVAILABLE,
                        &format!(
                            "{backend} available on {os} — strict mode: enforces \
                             filesystem-write containment + {net_coverage}"
                        ),
                    )
                }
                SandboxPosture::Degraded {
                    kernel,
                    abi,
                    missing,
                } => {
                    // both Linux
                    // (kernel < 6.7 + allow-degraded) and Windows
                    // (`windows-il` Low IL FALLBACK when the
                    // `lpm-sandbox-helper.exe` AppContainer launcher
                    // is missing + allow-degraded) reach this arm.
                    // The `abi` field carries the discriminator
                    // (`v1` = Linux landlock V1 fallback; `low-il`
                    // = Windows Mandatory Integrity Control
                    // fallback). Pick a platform-honest message —
                    // a single Linux-shaped string would lie about
                    // the remediation on Windows.
                    //
                    // On Windows the strict-mode cause is now
                    // "the helper binary that delivers AppContainer
                    // strict isn't sitting next to lpm.exe." That's
                    // an npm-install corruption symptom — reinstall
                    // is the fix.
                    let cause_and_fix = if abi == "low-il" {
                        "user requested strict but `lpm-sandbox-helper.exe` is not located \
                         next to `lpm.exe`; the AppContainer backend (filesystem + \
                         outbound-network containment) needs the helper to \
                         deliver strict mode. Falling back to Low IL backend, \
                         which contains filesystem writes but does NOT deny outbound \
                         network. Reinstall lpm (`@lpm-registry/cli`) to restore the helper, \
                         or override the helper location via `LPM_SANDBOX_HELPER=<path>`. \
                         Switch to `lpm config sandbox --set default` to drop the strict \
                         request and silence this warning."
                    } else {
                        "user requested strict but kernel can't deliver V4; enforces \
                         filesystem only. Upgrade the kernel to 6.7+ to restore strict \
                         containment, or switch to `lpm config sandbox --set default` to \
                         drop the strict request and silence this warning."
                    };
                    Check::warn(
                        &doctor_catalog::SANDBOX_DEGRADED,
                        &format!(
                            "{backend} available on {os} — DEGRADED posture (kernel \
                             {kernel}, abi {abi}); {cause_and_fix} missing={missing}."
                        ),
                    )
                }
                SandboxPosture::Disabled => Check::warn(
                    &doctor_catalog::SANDBOX_AVAILABLE,
                    &format!(
                        "{backend} returned Disabled posture on {os} — unexpected for \
                         SandboxMode::Enforce. File an issue with `lpm doctor --json` output."
                    ),
                ),
            }
        }
        Err(SandboxError::UnsupportedPlatform {
            platform,
            remediation,
        }) => Check::warn(
            &doctor_catalog::SANDBOX_UNSUPPORTED_PLATFORM,
            &format!(
                "unavailable on {platform} — {remediation}. Lifecycle scripts under \
                 `script-policy = \"triage\"` or `\"allow\"`, and any `lpm rebuild` \
                 invocation, run without filesystem containment on this platform — \
                 sandbox enforcement isn't supported here yet."
            ),
        ),
        Err(SandboxError::KernelTooOld {
            detected,
            required,
            remediation,
        }) => Check::warn(
            &doctor_catalog::SANDBOX_KERNEL_TOO_OLD,
            &format!(
                "Linux kernel {detected} is below the landlock requirement \
                 ({required}+). {remediation}"
            ),
        ),
        Err(e) => Check::fail(
            &doctor_catalog::SANDBOX_PROBE_FAILED,
            &format!(
                "probe failed: {e}. This is unexpected — the synthetic spec is \
                 well-formed; file an issue with `lpm doctor --json` output."
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor::test_support::isolated_security_env_vars;
    use crate::doctor_catalog::Severity;

    #[test]
    fn sandbox_probe_emits_known_code() {
        let security = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set(isolated_security_env_vars(security.path()));
        // Pin the codes the sandbox probe is allowed to emit so the
        // automation contract for this check stays stable across
        // platforms and backend availability.
        let c = probe_sandbox_backend();
        let allowed = [
            "sandbox_available",
            "sandbox_helper_missing",
            "sandbox_degraded",
            "sandbox_disabled_by_user",
            "sandbox_config_approval_required",
            "sandbox_unsupported_platform",
            "sandbox_kernel_too_old",
            "sandbox_probe_failed",
        ];
        assert!(
            allowed.contains(&c.code()),
            "unexpected sandbox probe code: {} (allowed: {:?})",
            c.code(),
            allowed
        );
    }

    /// Universal smoke test: the sandbox probe must always return a
    /// `Check` on every platform the CI matrix + local dev runs on
    /// (macOS, Linux, Windows). Pins the contract that the probe
    /// never panics regardless of backend availability — a fail
    /// result on a misbehaving platform is still a Check, not a
    /// crash. The per-platform severity assertions below narrow
    /// this further; this test is the "always produces output"
    /// floor.
    #[test]
    fn sandbox_probe_always_returns_a_check() {
        let security = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set(isolated_security_env_vars(security.path()));
        let c = probe_sandbox_backend();
        assert_eq!(c.name(), "Sandbox");
        // Severity ∈ {Pass, Warn, Fail}. All three are acceptable
        // depending on platform + kernel; what matters is that the
        // probe didn't panic and produced a named Check.
        assert!(
            !c.detail.is_empty(),
            "probe must emit a non-empty detail line"
        );
    }

    /// On macOS, the probe must return Pass with detail naming
    /// `seatbelt`. CI's macOS runners have Seatbelt available by
    /// construction; developer machines do too.
    #[cfg(target_os = "macos")]
    #[test]
    fn sandbox_probe_on_macos_passes_with_seatbelt_backend() {
        let security = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set(isolated_security_env_vars(security.path()));
        let c = probe_sandbox_backend();
        assert!(
            matches!(c.severity, Severity::Pass),
            "macOS sandbox probe should pass — expected Seatbelt available. detail={}",
            c.detail
        );
        assert!(
            c.detail.contains("seatbelt"),
            "detail must name the backend so users can debug. detail={}",
            c.detail
        );
    }

    /// On Linux, the probe returns Pass (kernel >= 5.13 with
    /// landlock) OR Warn (older kernel). Either outcome is a
    /// meaningful Check — but never a Fail, because an unsupported
    /// kernel on a supported platform is a warning, not a failure
    /// per the `KernelTooOld` arm.
    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_probe_on_linux_passes_or_warns_never_fails() {
        let security = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set(isolated_security_env_vars(security.path()));
        let c = probe_sandbox_backend();
        assert!(
            !matches!(c.severity, Severity::Fail),
            "Linux sandbox probe must not Fail — Pass (landlock) or \
             Warn (kernel too old) are the only acceptable outcomes. detail={}",
            c.detail
        );
    }

    /// On Windows, the active backend is determined by helper-binary
    /// presence:
    ///
    /// - **`windows-appcontainer`** when
    ///   `lpm-sandbox-helper.exe` is reachable. Pass under default,
    ///   Pass naming "AppContainer + WFP" under strict.
    /// - **`windows-il` (fallback)** when the helper
    ///   binary is missing. Warn surfaces the fallback explicitly
    ///   with the reinstall remediation, even under default — the
    ///   user has lost outbound-network containment in strict mode
    ///   and should know that.
    /// - **Warn `sandbox_disabled_by_user`** when the user has
    ///   `[sandbox] mode = "none"` persisted.
    ///
    /// A Fail here is a regression — Mandatory Integrity Control
    /// has been in every Windows release since Vista, and the AppContainer backend's
    /// AppContainer backend has no preconditions beyond
    /// "Win32_Security_Isolation surface is reachable" (Windows
    /// 8+).
    ///
    /// The legacy `--unsafe-full-env` partner flag must stay out of
    /// remediation text; `--no-sandbox` is the supported opt-out.
    #[cfg(target_os = "windows")]
    #[test]
    fn sandbox_probe_on_windows_passes_or_warns_with_known_backend_name() {
        let security = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set(isolated_security_env_vars(security.path()));
        let c = probe_sandbox_backend();
        assert!(
            !matches!(c.severity, Severity::Fail),
            "Windows sandbox probe must not Fail (AppContainer + Low IL fallback \
             are both reachable on every supported Windows host). detail={}",
            c.detail
        );
        // Whichever path fired, the detail names the active backend
        // so users can route the right remediation.
        assert!(
            c.detail.contains("windows-il") || c.detail.contains("windows-appcontainer"),
            "doctor detail must name the active backend; got: {}",
            c.detail
        );
        // legacy partner flag must never appear.
        assert!(
            !c.detail.contains("--unsafe-full-env"),
            "legacy partner flag must be gone from doctor output: {}",
            c.detail
        );
    }

    /// Raw `[sandbox] mode = "none"` in `~/.lpm/config.toml` is a guarded
    /// posture downgrade. Doctor should not treat a hand edit as an approved
    /// disabled posture; it should surface the same approval boundary the
    /// install pipeline will enforce.
    ///
    /// Test isolates the global config by overriding `HOME` to a
    /// tempdir and writing the wizard's on-disk shape directly. The
    /// project tier is silent (no `lpm.toml` in cwd typically), so
    /// the global tier wins.
    ///
    /// `cfg(unix)` because `dirs::home_dir()` only consults `HOME`
    /// on Unix-not-redox; on Windows it uses the Win32
    /// GetUserProfileDirectory call, so the `HOME=tempdir` override
    /// here doesn't redirect `~/.lpm/config.toml` to the tempdir.
    /// The persistent-mode-none behavior on Windows is covered
    /// indirectly by the integration tests in
    /// `tests/workflows/tests/sandbox_*` which exercise the
    /// resolver against the real per-platform config home.
    #[cfg(unix)]
    #[test]
    fn sandbox_probe_requires_approval_for_raw_persistent_mode_none_from_global_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        std::fs::write(
            home.join(".lpm").join("config.toml"),
            "[sandbox]\nmode = \"none\"\n",
        )
        .unwrap();
        // Override HOME for the duration of the probe call. The
        // resolver's `dirs::home_dir()` consults HOME on Unix; the
        // ScopedEnv mutex serialises with other tests that touch
        // process-wide env vars.
        let mut env = isolated_security_env_vars(tmp.path());
        env.push(("HOME", home.as_os_str().to_owned()));
        let _env = crate::test_env::ScopedEnv::set(env);

        let c = probe_sandbox_backend();

        assert_eq!(
            c.code(),
            "sandbox_config_approval_required",
            "doctor must report the security approval boundary for an unapproved \
             persistent sandbox downgrade. got: code={} detail={}",
            c.code(),
            c.detail,
        );
        assert!(
            matches!(c.severity, Severity::Fail),
            "unapproved `mode = \"none\"` should fail doctor because install will \
             also refuse it. got severity={:?}, detail={}",
            c.severity,
            c.detail,
        );
        assert!(
            c.detail.contains("security approval"),
            "detail must name the approval boundary. got: {}",
            c.detail,
        );
        assert!(
            !c.detail.contains("default mode:"),
            "regression detail leaked under raw `mode = \"none\"` — doctor must NOT \
             claim default-mode containment when config asked for none. got: {}",
            c.detail,
        );
    }

    /// Once the disabled sandbox posture has been approved, doctor reports it
    /// as the active user-chosen state instead of probing `SandboxMode::Enforce`.
    #[cfg(unix)]
    #[test]
    fn sandbox_probe_honors_approved_persistent_mode_none_from_global_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        std::fs::write(
            home.join(".lpm").join("config.toml"),
            "[sandbox]\nmode = \"none\"\n",
        )
        .unwrap();
        let mut env = isolated_security_env_vars(tmp.path());
        env.push(("HOME", home.as_os_str().to_owned()));
        let _env = crate::test_env::ScopedEnv::set(env);
        let posture = crate::security_approval::AuthorizedPosture {
            sandbox_mode: "none".to_string(),
            ..crate::security_approval::AuthorizedPosture::default()
        };
        crate::security_approval::persist_authorized_posture(&posture).unwrap();

        let c = probe_sandbox_backend();

        assert_eq!(
            c.code(),
            "sandbox_disabled_by_user",
            "doctor must emit the dedicated `sandbox_disabled_by_user` code for an \
             approved persistent-off posture. got: code={} detail={}",
            c.code(),
            c.detail,
        );
        assert!(
            matches!(c.severity, Severity::Warn),
            "approved persistent `mode = \"none\"` is a chosen-state warning, not a pass. \
             got severity={:?}, detail={}",
            c.severity,
            c.detail,
        );
        assert!(
            c.detail.contains("DISABLED") || c.detail.contains("disabled"),
            "detail must announce the disabled posture so the user sees their \
             config decision is taking effect. got: {}",
            c.detail,
        );
        // If this string resurfaces under `mode = "none"`, doctor is
        // back to reporting containment that config explicitly disabled.
        assert!(
            !c.detail.contains("default mode:"),
            "regression detail leaked under `mode = \"none\"` — doctor must NOT \
             claim default-mode containment when config asked for none. got: {}",
            c.detail,
        );
    }
}
