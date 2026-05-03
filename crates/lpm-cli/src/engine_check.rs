//! `engines.lpm` and `engines.node` enforcement.
//!
//! Reads `engines` from the workspace root `package.json`, compares
//! constraints against the running CLI version (`engines.lpm`) and the
//! effective Node version (`engines.node`), and aborts the install /
//! rebuild / add pipeline when a constraint isn't satisfied.
//!
//! ## Defaults
//!
//! - `engine-strict = true` by default. Mismatches abort.
//! - Workspace **root** package's `engines` block is the gate. Member
//!   packages don't gate the workspace install. The same root manifest
//!   owns the `lpm.engineStrict` opt-out — running `lpm install` from
//!   `packages/foo/` honors the root's `engineStrict = false`.
//! - Unknown `engines.<other-pm>` keys (`npm`, `pnpm`, `yarn`, `bun`)
//!   produce a one-line stderr warning so migrators see that LPM
//!   ignores those fields.
//! - When **no `package.json` exists** (workspace root or otherwise),
//!   the gate skips silently. This preserves `lpm add`'s plain-source-
//!   copy flow into directories without a manifest.
//!
//! Opt-out:
//! - `--no-engine-strict` CLI flag
//! - `package.json > lpm > engineStrict: false`
//! - `~/.lpm/config.toml > engine-strict = false`
//!
//! Precedence is owned by [`crate::engine_strict_config`].

use crate::engine_strict_config;
use crate::output;
use lpm_common::LpmError;
use lpm_runtime::effective::resolve_effective_node_version_with_engines;
use lpm_workspace::{PackageJson, discover_workspace, read_package_json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Other package-manager engines keys we recognize as "ignored on
/// purpose, please migrate." Editor-specific or unknown keys are left
/// alone — those aren't necessarily mistakes.
const KNOWN_PM_ENGINE_KEYS: &[&str] = &["npm", "pnpm", "yarn", "bun"];

/// Run the engine gate for `start_dir`.
///
/// Walks up to the workspace root (or uses `start_dir` for a single-
/// package project) for both:
/// 1. The `engines` block to enforce.
/// 2. The `lpm.engineStrict` opt-out source (so a member dir
///    invocation honors the root's setting).
///
/// Returns:
/// - `Ok(())` when every constraint is satisfied, when `engineStrict`
///   resolves to `false`, or when no `package.json` exists at or above
///   `start_dir`.
/// - `Err(LpmError::EngineMismatch)` when a constraint is violated and
///   `engineStrict` is `true`. The structured error carries the
///   `engine_mismatch` code so `--json` consumers can branch on it.
///
/// `cli_no_engine_strict` is the value of the `--no-engine-strict`
/// flag for this invocation. `json_output` suppresses stderr warnings
/// (machine-readable mode); hard failures still propagate via the
/// error envelope.
pub fn enforce(
    start_dir: &Path,
    cli_no_engine_strict: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let Some((root_dir, root_pkg)) = resolve_root_package(start_dir)? else {
        // No `package.json` anywhere above `start_dir`. Plain source
        // copy (`lpm add`) lives here; `lpm install` / `lpm rebuild`
        // would already error downstream with their own NotFound. The
        // gate has nothing to validate against.
        return Ok(());
    };
    let engine_strict = engine_strict_config::resolve_for_root(cli_no_engine_strict, &root_pkg);
    enforce_with_root(&root_dir, &root_pkg, engine_strict, json_output)
}

/// Variant that takes the already-resolved root + manifest. Use this
/// at call sites that have parsed the workspace themselves to avoid a
/// second discovery pass.
pub fn enforce_with_root(
    root_dir: &Path,
    root_pkg: &PackageJson,
    engine_strict: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if root_pkg.engines.is_empty() {
        return Ok(());
    }

    warn_unknown_pm_keys(&root_pkg.engines, json_output);

    let lpm_result = check_lpm_engine(&root_pkg.engines);
    let node_result = check_node_engine(&root_pkg.engines, root_dir);

    if !engine_strict {
        // Soft mode: surface mismatches as warnings, never abort.
        if let Err(msg) = &lpm_result
            && !json_output
        {
            output::warn(&format!("{msg} (engine-strict disabled, ignoring)"));
        }
        if let Err(msg) = &node_result
            && !json_output
        {
            output::warn(&format!("{msg} (engine-strict disabled, ignoring)"));
        }
        return Ok(());
    }

    // Hard mode: first failure wins. lpm before node so the user sees
    // the version-pinning issue before the runtime one.
    lpm_result.map_err(|m| m.into_error("lpm"))?;
    node_result.map_err(|m| m.into_error("node"))?;
    Ok(())
}

/// Walk up from `start_dir` to the workspace root (or use `start_dir`
/// directly for a single-package project), returning the directory +
/// parsed `PackageJson`.
///
/// Returns `Ok(None)` when there is no `package.json` at `start_dir`
/// AND no workspace root above. This is the supported state for
/// `lpm add`'s plain source copy into a manifest-less directory; the
/// gate skips silently rather than blocking the flow.
fn resolve_root_package(start_dir: &Path) -> Result<Option<(PathBuf, PackageJson)>, LpmError> {
    if let Some(ws) = discover_workspace(start_dir)
        .map_err(|e| LpmError::Workspace(format!("could not discover workspace: {e}")))?
    {
        return Ok(Some((ws.root, ws.root_package)));
    }
    let pkg_json = start_dir.join("package.json");
    if !pkg_json.exists() {
        return Ok(None);
    }
    let pkg = read_package_json(&pkg_json)
        .map_err(|e| LpmError::Workspace(format!("could not read package.json: {e}")))?;
    Ok(Some((start_dir.to_path_buf(), pkg)))
}

/// Internal mismatch description. Converted to `LpmError::EngineMismatch`
/// at the boundary, with the engine name plugged in.
struct Mismatch {
    required: String,
    actual: String,
    source: String,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "engine '{}' (required) does not satisfy actual {} (from {})",
            self.required, self.actual, self.source
        )
    }
}

impl Mismatch {
    fn into_error(self, engine: &str) -> LpmError {
        LpmError::EngineMismatch {
            engine: engine.to_string(),
            required: self.required,
            actual: self.actual,
            from: self.source,
        }
    }
}

/// Compare `engines.lpm` against the running CLI version.
fn check_lpm_engine(engines: &HashMap<String, String>) -> Result<(), Mismatch> {
    let Some(required) = engines.get("lpm") else {
        return Ok(());
    };
    let actual = env!("CARGO_PKG_VERSION");
    match version_satisfies(required, actual) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Mismatch {
            required: required.clone(),
            actual: actual.to_string(),
            source: "package.json > engines.lpm".to_string(),
        }),
        // Unparseable constraint — treat as mismatch so the user fixes
        // their manifest. Otherwise a typo like "engines.lpm = '>=1,0'"
        // would silently pass.
        Err(parse_err) => Err(Mismatch {
            required: format!("{required} (parse error: {parse_err})"),
            actual: actual.to_string(),
            source: "package.json > engines.lpm".to_string(),
        }),
    }
}

/// Compare `engines.node` against the effective Node version LPM will
/// use for this project (managed runtime if installed, else system
/// Node, else skip).
fn check_node_engine(
    engines: &HashMap<String, String>,
    project_dir: &Path,
) -> Result<(), Mismatch> {
    let Some(required) = engines.get("node") else {
        return Ok(());
    };
    let effective = resolve_effective_node_version_with_engines(project_dir, engines);
    let Some(actual) = effective.version() else {
        // No Node available at all (no managed runtime, no system
        // Node). Don't fail — there's nothing to validate against. If
        // the user actually runs scripts later, the runtime layer will
        // surface the missing-Node error.
        return Ok(());
    };
    let source_label = effective.source_label();
    let source = format!("package.json > engines.node (compared against {source_label})");
    match version_satisfies(required, actual) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Mismatch {
            required: required.clone(),
            actual: actual.to_string(),
            source,
        }),
        Err(parse_err) => Err(Mismatch {
            required: format!("{required} (parse error: {parse_err})"),
            actual: actual.to_string(),
            source,
        }),
    }
}

/// Parse `required` as a semver range and `actual` as a version, then
/// check satisfaction. Returns the inner `Result` from semver parsing
/// so the caller can surface unparseable constraints distinctly from
/// failed matches.
fn version_satisfies(required: &str, actual: &str) -> Result<bool, String> {
    let req = lpm_semver::VersionReq::parse(required)
        .map_err(|e| format!("could not parse range '{required}': {e}"))?;
    let version = lpm_semver::Version::parse(actual)
        .map_err(|e| format!("could not parse version '{actual}': {e}"))?;
    Ok(req.matches(&version))
}

/// Emit a one-line stderr warning for any `engines.<pm>` key other
/// than `node` and `lpm` from the known-PM list. Migrators expect
/// LPM to honor those; the warning makes the silent-ignore explicit.
fn warn_unknown_pm_keys(engines: &HashMap<String, String>, json_output: bool) {
    if json_output {
        return;
    }
    for key in KNOWN_PM_ENGINE_KEYS {
        if engines.contains_key(*key) {
            output::warn(&format!(
                "engines.{key} is set in package.json but LPM does not enforce it. \
                 Use engines.lpm to constrain the LPM CLI version."
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn engines(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn empty_engines_passes() {
        let dir = tempdir().unwrap();
        let pkg = PackageJson::default();
        assert!(enforce_with_root(dir.path(), &pkg, true, false).is_ok());
    }

    #[test]
    fn lpm_engine_satisfied_passes() {
        let cur = env!("CARGO_PKG_VERSION");
        let pkg = PackageJson {
            engines: engines(&[("lpm", &format!(">={cur}"))]),
            ..Default::default()
        };
        let dir = tempdir().unwrap();
        assert!(enforce_with_root(dir.path(), &pkg, true, true).is_ok());
    }

    #[test]
    fn lpm_engine_mismatch_aborts() {
        let pkg = PackageJson {
            engines: engines(&[("lpm", ">=999.0.0")]),
            ..Default::default()
        };
        let dir = tempdir().unwrap();
        let err = enforce_with_root(dir.path(), &pkg, true, true).unwrap_err();
        match err {
            LpmError::EngineMismatch {
                engine,
                required,
                from,
                ..
            } => {
                assert_eq!(engine, "lpm");
                assert_eq!(required, ">=999.0.0");
                assert!(from.contains("engines.lpm"));
            }
            other => panic!("expected EngineMismatch, got {other:?}"),
        }
    }

    #[test]
    fn lpm_engine_mismatch_warns_under_soft_mode() {
        let pkg = PackageJson {
            engines: engines(&[("lpm", ">=999.0.0")]),
            ..Default::default()
        };
        let dir = tempdir().unwrap();
        // engine_strict = false → no error.
        assert!(enforce_with_root(dir.path(), &pkg, false, true).is_ok());
    }

    #[test]
    fn unparseable_lpm_engine_aborts_in_strict_mode() {
        let pkg = PackageJson {
            engines: engines(&[("lpm", "not-a-range")]),
            ..Default::default()
        };
        let dir = tempdir().unwrap();
        let err = enforce_with_root(dir.path(), &pkg, true, true).unwrap_err();
        assert!(matches!(err, LpmError::EngineMismatch { .. }));
    }

    #[test]
    fn node_engine_with_no_node_at_all_skips() {
        // engines.node = ">=22" but no managed runtime AND no
        // system Node would mean Effective::Unknown → skip.
        // We can't reliably make `node` absent on a dev machine, so
        // this test only confirms that "absent engines.node" is OK.
        let pkg = PackageJson {
            engines: engines(&[("lpm", ">=0.1.0")]),
            ..Default::default()
        };
        let dir = tempdir().unwrap();
        assert!(enforce_with_root(dir.path(), &pkg, true, true).is_ok());
    }

    #[test]
    fn enforce_walks_up_to_workspace_root() {
        // Workspace root with engines.lpm = ">=999"; member dir
        // without engines. Running enforce(member) must read the
        // root and fail.
        let root = tempdir().unwrap();
        let member = root.path().join("packages").join("foo");
        fs::create_dir_all(&member).unwrap();
        fs::write(
            root.path().join("package.json"),
            r#"{
                "name": "root",
                "workspaces": ["packages/*"],
                "engines": {"lpm": ">=999.0.0"}
            }"#,
        )
        .unwrap();
        fs::write(
            member.join("package.json"),
            r#"{"name": "foo", "version": "0.0.0"}"#,
        )
        .unwrap();

        let result = enforce(&member, false, true);
        assert!(matches!(result, Err(LpmError::EngineMismatch { .. })));
    }

    /// Regression: workspace-root `lpm.engineStrict = false` must
    /// suppress the gate for invocations from any member directory.
    /// Pre-fix, `engine_strict_config::from_package_json` read the
    /// member's manifest directly, ignoring the root's opt-out.
    #[test]
    fn workspace_root_engine_strict_false_honored_from_member() {
        let root = tempdir().unwrap();
        let member = root.path().join("packages").join("foo");
        fs::create_dir_all(&member).unwrap();
        // Root: engines mismatch + engineStrict = false (opt-out).
        fs::write(
            root.path().join("package.json"),
            r#"{
                "name": "root",
                "workspaces": ["packages/*"],
                "engines": {"lpm": ">=999.0.0"},
                "lpm": {"engineStrict": false}
            }"#,
        )
        .unwrap();
        fs::write(
            member.join("package.json"),
            r#"{"name": "foo", "version": "0.0.0"}"#,
        )
        .unwrap();

        // Run from the member dir (cwd-style). Must NOT abort.
        let result = enforce(&member, false, true);
        assert!(
            result.is_ok(),
            "root engineStrict=false must suppress the gate from member dir; got {result:?}"
        );
    }

    /// Regression: workspace-root `engineStrict = true` (explicit)
    /// from member dir behaves the same as default — gate enforces.
    #[test]
    fn workspace_root_engine_strict_true_explicit_enforces_from_member() {
        let root = tempdir().unwrap();
        let member = root.path().join("packages").join("foo");
        fs::create_dir_all(&member).unwrap();
        fs::write(
            root.path().join("package.json"),
            r#"{
                "name": "root",
                "workspaces": ["packages/*"],
                "engines": {"lpm": ">=999.0.0"},
                "lpm": {"engineStrict": true}
            }"#,
        )
        .unwrap();
        fs::write(
            member.join("package.json"),
            r#"{"name": "foo", "version": "0.0.0"}"#,
        )
        .unwrap();
        let result = enforce(&member, false, true);
        assert!(matches!(result, Err(LpmError::EngineMismatch { .. })));
    }

    /// Regression: `lpm add` into a directory without a `package.json`
    /// is a supported flow (plain source copy). The gate must skip
    /// silently rather than block with a NotFound.
    #[test]
    fn no_package_json_anywhere_skips_gate() {
        let dir = tempdir().unwrap();
        // No package.json exists anywhere in the tree.
        let result = enforce(dir.path(), false, true);
        assert!(
            result.is_ok(),
            "no package.json must not block the gate; got {result:?}"
        );
    }

    #[test]
    fn version_satisfies_caret() {
        assert!(version_satisfies("^1.2.3", "1.5.0").unwrap());
        assert!(!version_satisfies("^1.2.3", "2.0.0").unwrap());
    }

    #[test]
    fn version_satisfies_gte() {
        assert!(version_satisfies(">=22.0.0", "22.5.0").unwrap());
        assert!(!version_satisfies(">=22.0.0", "20.18.0").unwrap());
    }

    #[test]
    fn version_satisfies_unparseable_range_errors() {
        assert!(version_satisfies("not a range", "1.0.0").is_err());
    }

    #[test]
    fn version_satisfies_unparseable_version_errors() {
        assert!(version_satisfies(">=1.0.0", "not a version").is_err());
    }
}
