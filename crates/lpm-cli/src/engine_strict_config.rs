//! `engine-strict` config loader.
//!
//! Reads the workspace-root `package.json > lpm > engineStrict` value
//! and folds it into a precedence chain with the CLI override and the
//! per-user `~/.lpm/config.toml > engine-strict` setting.
//!
//! ## Precedence (highest wins)
//!
//! 1. `--no-engine-strict` CLI flag (when set, disables enforcement).
//! 2. `package.json > lpm > engineStrict` (per-project, team-shared).
//!    The **workspace root** manifest is the authoritative source —
//!    [`crate::engine_check::enforce`] discovers the root before
//!    calling this resolver, so a member-dir invocation honors the
//!    root's value.
//! 3. `~/.lpm/config.toml` key `engine-strict` (per-user, this machine).
//! 4. Default: `true` — engines are enforced.
//!
//! `engine-strict` is a stricter-by-default knob: matches LPM's
//! "stricter rails than npm" stance. Other PMs default to false; LPM
//! defaults to true and provides an explicit opt-out for projects /
//! environments that need it.

use crate::commands::config::GlobalConfig;
use lpm_workspace::PackageJson;

/// Resolved value of the `engine-strict` knob.
///
/// `true` means engine constraints are enforced — mismatched versions
/// abort install / rebuild / add. `false` means constraints are read
/// but not enforced (npm's default behavior).
pub type EngineStrict = bool;

/// Default value when no source sets `engine-strict`.
pub const DEFAULT_ENGINE_STRICT: EngineStrict = true;

/// Resolve `engine-strict` against the **workspace root** manifest.
///
/// Callers are expected to discover the root via
/// `lpm_workspace::discover_workspace` first and pass the root's
/// already-parsed `PackageJson`. This avoids both a duplicate disk
/// read AND the bug where reading the member's manifest would shadow
/// the root's opt-out.
///
/// `cli_no_engine_strict` is `true` when the user passed
/// `--no-engine-strict` on this invocation. The flag is opt-out only —
/// there is no `--engine-strict` to force-on at the CLI layer (the
/// default already enforces).
pub fn resolve_for_root(cli_no_engine_strict: bool, root_pkg: &PackageJson) -> EngineStrict {
    if cli_no_engine_strict {
        return false;
    }
    if let Some(lpm) = root_pkg.lpm.as_ref()
        && let Some(value) = lpm.engine_strict
    {
        return value;
    }
    let global = GlobalConfig::load();
    global
        .get_bool("engine-strict")
        .unwrap_or(DEFAULT_ENGINE_STRICT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_workspace::{LpmConfig, PackageJson, TrustedDependencies};
    use std::path::Path;
    use tempfile::tempdir;

    fn pkg_with_lpm(engine_strict: Option<bool>) -> PackageJson {
        PackageJson {
            lpm: Some(LpmConfig {
                strict_deps: None,
                linker: None,
                trusted_dependencies: TrustedDependencies::default(),
                minimum_release_age: None,
                engine_strict,
                overrides: Default::default(),
                patched_dependencies: Default::default(),
                peer_dependency_rules: Default::default(),
                auto_install_peers: None,
            }),
            ..Default::default()
        }
    }

    fn pkg_without_lpm() -> PackageJson {
        PackageJson::default()
    }

    fn isolate_home<F: FnOnce()>(f: F) {
        let dir = tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(dir.path().to_str().unwrap()),
        )]);
        f();
    }

    #[test]
    fn default_is_true() {
        const { assert!(DEFAULT_ENGINE_STRICT) };
    }

    #[test]
    fn cli_no_engine_strict_wins_over_project_true() {
        let pkg = pkg_with_lpm(Some(true));
        isolate_home(|| {
            assert!(!resolve_for_root(true, &pkg));
        });
    }

    #[test]
    fn project_true_wins_over_global() {
        let pkg = pkg_with_lpm(Some(true));
        isolate_home(|| {
            assert!(resolve_for_root(false, &pkg));
        });
    }

    #[test]
    fn project_false_wins_over_global_default_true() {
        let pkg = pkg_with_lpm(Some(false));
        isolate_home(|| {
            assert!(!resolve_for_root(false, &pkg));
        });
    }

    #[test]
    fn default_when_nothing_set() {
        let pkg = pkg_without_lpm();
        isolate_home(|| {
            assert_eq!(resolve_for_root(false, &pkg), DEFAULT_ENGINE_STRICT);
        });
    }

    #[test]
    fn lpm_block_without_engine_strict_falls_through() {
        // Project has an `lpm` block but no `engineStrict` key →
        // resolution falls through to global / default.
        let pkg = pkg_with_lpm(None);
        isolate_home(|| {
            assert_eq!(resolve_for_root(false, &pkg), DEFAULT_ENGINE_STRICT);
        });
    }

    /// Smoke test: deserialization wires up correctly so the
    /// loader sees `engineStrict` from a real `package.json` blob.
    /// This guards against a `#[serde(rename = "engineStrict")]`
    /// regression in lpm-workspace.
    #[test]
    fn deserializes_engine_strict_from_package_json_lpm_block() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"engineStrict":false}}"#,
        )
        .unwrap();
        let pkg = lpm_workspace::read_package_json(&dir.path().join("package.json")).unwrap();
        let strict = pkg.lpm.as_ref().and_then(|l| l.engine_strict);
        assert_eq!(
            strict,
            Some(false),
            "engineStrict must deserialize via serde"
        );
        let _path: &Path = dir.path();
    }
}
