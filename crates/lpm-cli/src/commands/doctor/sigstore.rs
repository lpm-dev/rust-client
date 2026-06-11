use crate::doctor_catalog;

use super::check::Check;

/// Emit the doctor row for the resolved Sigstore verification posture.
pub(super) fn check_sigstore_verify_posture() -> Check {
    use crate::provenance_fetch::{EnforceMode, EnforceModeSource};
    let cfg = crate::commands::config::GlobalConfig::load();
    let (mode, source) = EnforceMode::resolve_from_chain(
        std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
        || cfg.get_sigstore_verify(),
    );
    let source_label = match source {
        EnforceModeSource::Env => "LPM_PROVENANCE_ENFORCE env",
        EnforceModeSource::Config => "[sigstore].verify in ~/.lpm/config.toml",
        EnforceModeSource::Default => "default",
    };
    match mode {
        EnforceMode::Deny => Check::pass(
            &doctor_catalog::SIGSTORE_VERIFY_ENFORCED,
            &format!("deny (source: {source_label})"),
        ),
        EnforceMode::Warn => Check::warn(
            &doctor_catalog::SIGSTORE_VERIFY_WARN_MODE,
            &format!(
                "warn (source: {source_label}) — verifier rejections only log; \
                 install still proceeds. {}",
                source.re_enable_hint(),
            ),
        ),
        EnforceMode::Off => Check::warn(
            &doctor_catalog::SIGSTORE_VERIFY_DISABLED,
            &format!(
                "off (source: {source_label}) — every Sigstore attestation will be \
                 IGNORED. {}",
                source.re_enable_hint(),
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;

    /// Doctor must emit the dedicated `sigstore_verify_enforced`
    /// pass row when no operator override is in scope (env unset,
    /// config absent). Default `Deny` is the recommended posture.
    /// The HOME isolation matches the sandbox-probe test pattern
    /// so the dev's `~/.lpm/config.toml` doesn't leak in.
    #[cfg(unix)]
    #[test]
    fn sigstore_posture_check_reports_enforced_under_default() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.as_os_str().to_owned()),
            ("LPM_PROVENANCE_ENFORCE", std::ffi::OsString::new()),
        ]);

        let c = check_sigstore_verify_posture();
        assert_eq!(c.code(), "sigstore_verify_enforced");
        assert!(matches!(c.severity, Severity::Pass));
        assert!(
            c.detail.contains("deny"),
            "detail must name the resolved mode; got: {}",
            c.detail
        );
        assert!(
            c.detail.contains("default"),
            "detail must name the source (default) so operators can trace the posture; got: {}",
            c.detail,
        );
    }

    /// `[sigstore].verify = "warn"` in the user's config → warn row
    /// with the re-enable hint. Doctor must surface the degraded
    /// posture even when no install is in flight — that's the
    /// "operator forgot they flipped the knob" mitigation the plan
    /// pins.
    #[cfg(unix)]
    #[test]
    fn sigstore_posture_check_reports_warn_mode_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        std::fs::write(
            home.join(".lpm").join("config.toml"),
            "[sigstore]\nverify = \"warn\"\n",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.as_os_str().to_owned()),
            ("LPM_PROVENANCE_ENFORCE", std::ffi::OsString::new()),
        ]);

        let c = check_sigstore_verify_posture();
        assert_eq!(
            c.code(),
            "sigstore_verify_warn_mode",
            "doctor must emit the dedicated `sigstore_verify_warn_mode` code so JSON \
             consumers can tell warn-mode apart from the disabled state",
        );
        assert!(matches!(c.severity, Severity::Warn));
        assert!(
            c.detail.contains("lpm config sigstore --set deny"),
            "warn detail must point at the wizard re-enable command so operators know \
             how to tighten back; got: {}",
            c.detail,
        );
    }

    /// `LPM_PROVENANCE_ENFORCE=off` → disabled-posture warn row.
    /// Env wins over config per the precedence chain.
    #[cfg(unix)]
    #[test]
    fn sigstore_posture_check_reports_disabled_from_env_over_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        // Config says deny — env says off — env wins.
        std::fs::write(
            home.join(".lpm").join("config.toml"),
            "[sigstore]\nverify = \"deny\"\n",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.as_os_str().to_owned()),
            ("LPM_PROVENANCE_ENFORCE", std::ffi::OsString::from("off")),
        ]);

        let c = check_sigstore_verify_posture();
        assert_eq!(c.code(), "sigstore_verify_disabled");
        assert!(matches!(c.severity, Severity::Warn));
        assert!(
            c.detail.contains("IGNORED"),
            "detail must announce the fleet-wide opt-out posture; got: {}",
            c.detail,
        );
        assert!(
            c.detail.contains("LPM_PROVENANCE_ENFORCE"),
            "detail must point at the env re-enable knob (env was the source); got: {}",
            c.detail,
        );
    }
}
