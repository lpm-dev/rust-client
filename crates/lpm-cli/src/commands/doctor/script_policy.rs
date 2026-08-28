use crate::doctor_catalog;

use super::check::Check;
use super::sandbox::probe_sandbox_backend_with_global;

pub(super) fn check_script_policy_surface_with_global(
    global: &crate::commands::config::GlobalConfig,
    package: Option<&lpm_workspace::PackageJson>,
) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(probe_sandbox_backend_with_global(global));

    // Only surface the force-security-floor kill-switch when the flag
    // is set; unset is the default and should not clutter clean output.
    if let Some(check) = check_force_security_floor(global, package) {
        out.push(check);
    }

    out
}

/// Report the force-security-floor kill-switch state.
///
/// Returns `None` when the flag is unset (the default), so
/// clean output stays clean. Returns `Some(Check::warn(...))` when
/// set, naming the count of suspended approvals if a project
/// `package.json` is present — empty project or no approvals produces
/// a no-count variant of the same message.
fn check_force_security_floor(
    global: &crate::commands::config::GlobalConfig,
    package: Option<&lpm_workspace::PackageJson>,
) -> Option<Check> {
    if !global.get_bool("force-security-floor").unwrap_or(false) {
        return None;
    }

    let suspended_count = package.map(|package| {
        package
            .lpm
            .as_ref()
            .map_or(0, |config| config.trusted_dependencies.len())
    });

    let detail = match suspended_count {
        None => "enabled — no `package.json` in current directory, so suspended-approval \
             count is not available. Run `lpm config unset force-security-floor` to reactivate \
             approvals (any loosening CLI flags are also currently suppressed)."
            .to_string(),
        Some(0) => "enabled — the current project has no approvals in \
             `package.json > lpm > trustedDependencies` to suspend. Run \
             `lpm config unset force-security-floor` to remove the kill-switch."
            .to_string(),
        Some(n) => format!(
            "enabled — {n} approval(s) in `package.json > lpm > trustedDependencies` \
             are currently suspended (scripts for these packages will NOT run until \
             the kill-switch is unset). Run `lpm config unset force-security-floor` \
             to reactivate all {n} approval(s) without re-review."
        ),
    };
    Some(Check::warn(
        &doctor_catalog::POLICY_FORCE_SECURITY_FLOOR,
        &detail,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor::test_support::isolated_security_env_vars;

    fn check_script_policy_surface() -> Vec<Check> {
        let global = crate::commands::config::GlobalConfig::load();
        let project_dir = std::env::current_dir().unwrap();
        let package = lpm_workspace::read_package_json(&project_dir.join("package.json")).ok();
        check_script_policy_surface_with_global(&global, package.as_ref())
    }

    /// `policy_scope_project_only` must stay retired even when globals
    /// are present, because global installs now honor the same policy
    /// gates as project installs.
    #[test]
    fn doctor_does_not_emit_policy_scope_boundary_for_globals() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let global_root = root.global_root();
        std::fs::create_dir_all(&global_root).unwrap();
        std::fs::write(
            global_root.join("manifest.toml"),
            r#"schema_version = 1

    [packages.some-pkg]
    saved_spec = "^1"
    resolved = "1.0.0"
    integrity = "sha512-fixture"
    source = "upstream-npm"
    installed_at = "T00:00:00Z"
    root = "installs/some-pkg@1.0.0"
    commands = []
    "#,
        )
        .unwrap();
        let mut env = isolated_security_env_vars(tmp.path());
        env.push(("LPM_HOME", tmp.path().as_os_str().to_owned()));
        let _env = crate::test_env::ScopedEnv::set(env);
        let out = check_script_policy_surface();
        for c in &out {
            assert_ne!(
                c.code(),
                "policy_scope_project_only",
                "scope-boundary check must no longer fire",
            );
        }
    }

    /// `check_script_policy_surface` always emits the sandbox probe
    /// (never conditional). This test pins the aggregator's contract
    /// against regression — a future refactor that accidentally
    /// gated the sandbox probe behind some condition would be caught here.
    #[test]
    fn check_script_policy_surface_always_includes_sandbox_probe() {
        let security = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set(isolated_security_env_vars(security.path()));
        let out = check_script_policy_surface();
        assert!(!out.is_empty(), "must emit at least the sandbox probe");
        assert_eq!(
            out[0].name(),
            "Sandbox",
            "sandbox probe must be the first entry so it renders \
             next to the other infrastructure checks"
        );
    }
}
