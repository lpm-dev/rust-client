//! `engines.lpm` and `engines.node` enforcement, plus the manifest-side
//! compatibility warning loop.
//!
//! Reads `engines` from the workspace root and installed dependency
//! metadata, compares constraints against the running stable compatibility
//! version (`engines.lpm`) and the effective Node version (`engines.node`),
//! and aborts the install / rebuild / add pipeline when a required constraint
//! isn't satisfied. While we have the parsed root manifest in hand, this is
//! also the right place to emit the structured manifest-compat warnings driven
//! by [`lpm_workspace::PackageJson::manifest_compat_issues`] — a single
//! emission shared across install / rebuild / add.
//!
//! ## Defaults
//!
//! - `engine-strict = true` by default. Mismatches abort.
//! - The workspace root owns `engines.lpm`, its own `engines.node`, and the
//!   `lpm.engineStrict` policy. Installed dependency `engines.node`
//!   constraints are then checked under that same policy.
//! - Unknown `engines.<other-pm>` keys (`npm`, `pnpm`, `yarn`, `bun`),
//!   `pnpm.overrides` / `pnpm.patchedDependencies` drift, and other
//!   manifest-side silent drops produce one-line stderr warnings via
//!   the shared detector.
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
use lpm_runtime::effective::{
    PathNodeResolution, probe_node_fingerprint_on_path, resolve_node_on_path_with_fingerprint,
};
use lpm_workspace::{PackageJson, read_package_json};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const LOCKFILE_NODE_ENGINE_NEEDLE: &str = "node-engine = ";
const DEFAULT_NODE_SELECTOR_HINT: &str = "22";
const NEUTRAL_NODE_SELECTOR_HINT: &str = "<matching-version>";

pub(crate) struct RootNodeEngineRequirement {
    pub(crate) required: String,
    pub(crate) engine_strict: bool,
}

pub(crate) struct NodeEngineRequirement {
    pub(crate) required: String,
    pub(crate) engine_strict: bool,
    pub(crate) source: String,
}

pub(crate) struct DependencyEnginePolicy {
    engine_strict: bool,
    json_output: bool,
    script_cwd: PathBuf,
    script_path: OsString,
    effective_node: OnceLock<PathNodeResolution>,
}

impl DependencyEnginePolicy {
    fn new(
        script_cwd: PathBuf,
        script_path: OsString,
        engine_strict: bool,
        json_output: bool,
    ) -> Self {
        Self {
            engine_strict,
            json_output,
            script_cwd,
            script_path,
            effective_node: OnceLock::new(),
        }
    }

    fn with_resolved_node(
        effective_node: PathNodeResolution,
        engine_strict: bool,
        json_output: bool,
    ) -> Self {
        Self {
            engine_strict,
            json_output,
            script_cwd: PathBuf::new(),
            script_path: OsString::new(),
            effective_node: OnceLock::from(effective_node),
        }
    }

    fn effective_node_version(&self) -> Option<&str> {
        self.effective_node_resolution().version()
    }

    fn effective_node_resolution(&self) -> &PathNodeResolution {
        self.effective_node.get_or_init(|| {
            resolve_node_on_path_with_fingerprint(&self.script_cwd, &self.script_path)
        })
    }

    fn check_node_requirement(&self, required: &str, source: String) -> Result<(), Mismatch> {
        let Some(actual) = self.effective_node_version() else {
            let selector = compatible_node_selector_hint(required);
            return Err(Mismatch {
                required: required.to_string(),
                actual: format!(
                    "not found on PATH; select one explicitly (for example, `lpm use node@{selector}`)"
                ),
                source: format!("{source} (compatibility constraint)"),
            });
        };
        let source = format!("{source} (compared against script PATH)");
        match version_satisfies(required, actual) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Mismatch {
                required: required.to_string(),
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

    pub(crate) fn enforce_dependency(
        &self,
        package_name: &str,
        package_version: &str,
        required: &str,
        optional: bool,
    ) -> Result<bool, LpmError> {
        let source = format!("{package_name}@{package_version} > engines.node");
        let Err(mismatch) = self.check_node_requirement(required, source) else {
            return Ok(true);
        };

        if !self.engine_strict {
            if !self.json_output {
                output::warn(&format!(
                    "{package_name}@{package_version}: {mismatch} (engine-strict disabled, ignoring)"
                ));
            }
            return Ok(true);
        }
        if optional {
            if !self.json_output {
                output::warn(&format!(
                    "skipping optional {package_name}@{package_version}: {mismatch}"
                ));
            }
            return Ok(false);
        }
        Err(mismatch.into_error("node"))
    }

    pub(crate) fn allows_dependency_materialization(&self, required: Option<&str>) -> bool {
        if !self.engine_strict {
            return true;
        }
        let Some(required) = required else {
            return true;
        };
        self.check_node_requirement(required, "dependency prefetch > engines.node".to_string())
            .is_ok()
    }

    pub(crate) fn freshness_key(&self, lockfile_content: &str) -> String {
        if lockfile_version(lockfile_content)
            .is_some_and(|version| version < lpm_lockfile::LOCKFILE_VERSION_WITH_DEPENDENCY_ENGINES)
        {
            return "legacy".to_string();
        }
        if !lockfile_has_dependency_node_engines(lockfile_content) {
            return "none".to_string();
        }
        self.constrained_freshness_key()
    }

    pub(crate) fn constrained_freshness_key(&self) -> String {
        let version = self.effective_node_version().unwrap_or("unknown");
        format!("{}:{version}", u8::from(self.engine_strict))
    }

    pub(crate) fn probe_node_runtime_fingerprint(&self) -> Option<String> {
        probe_node_fingerprint_on_path(&self.script_cwd, &self.script_path)
    }

    pub(crate) fn resolved_node_runtime_fingerprint(&self) -> Option<&str> {
        self.effective_node_resolution().runtime_fingerprint()
    }

    pub(crate) fn can_reuse_constrained_freshness_key(&self, key: &str) -> bool {
        let prefix = if self.engine_strict { "1:" } else { "0:" };
        let Some(version) = key.strip_prefix(prefix) else {
            return false;
        };
        lpm_semver::Version::parse(version).is_ok()
    }
}

pub(crate) fn lockfile_has_dependency_node_engines(content: &str) -> bool {
    content.contains(LOCKFILE_NODE_ENGINE_NEEDLE)
}

fn lockfile_version(content: &str) -> Option<u32> {
    content.lines().find_map(|line| {
        line.trim()
            .strip_prefix("lockfile-version = ")?
            .parse()
            .ok()
    })
}

pub(crate) fn prepare_dependency_policy(
    start_dir: &Path,
    cli_no_engine_strict: bool,
    json_output: bool,
) -> Result<DependencyEnginePolicy, LpmError> {
    let Some((root_dir, root_pkg)) = resolve_root_package(start_dir)? else {
        return Ok(DependencyEnginePolicy::new(
            start_dir.to_path_buf(),
            OsString::new(),
            false,
            json_output,
        ));
    };
    let engine_strict = engine_strict_config::resolve_for_root(cli_no_engine_strict, &root_pkg);
    let script_path = lpm_runner::bin_path::build_path_with_bins(&root_dir)?;
    let policy =
        DependencyEnginePolicy::new(root_dir, script_path.into(), engine_strict, json_output);
    enforce_root_with_policy(&root_pkg, &policy)?;
    Ok(policy)
}

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
    prepare_dependency_policy(start_dir, cli_no_engine_strict, json_output).map(|_| ())
}

/// Validate a resolved script Node against an engine requirement.
pub(crate) fn enforce_resolved_node_for_run(
    requirement: RootNodeEngineRequirement,
    effective_node: PathNodeResolution,
    json_output: bool,
) -> Result<(), LpmError> {
    enforce_resolved_node_requirement_for_run(
        requirement.required,
        requirement.engine_strict,
        "package.json > engines.node".to_string(),
        effective_node,
        json_output,
    )
}

pub(crate) fn enforce_resolved_node_requirement_for_run(
    required: String,
    engine_strict: bool,
    source: String,
    effective_node: PathNodeResolution,
    json_output: bool,
) -> Result<(), LpmError> {
    let policy =
        DependencyEnginePolicy::with_resolved_node(effective_node, engine_strict, json_output);
    let result = policy.check_node_requirement(&required, source);

    if !engine_strict {
        if let Err(mismatch) = result
            && !json_output
        {
            output::warn(&format!("{mismatch} (engine-strict disabled, ignoring)"));
        }
        return Ok(());
    }

    result.map_err(|mismatch| mismatch.into_run_error("node"))
}

pub(crate) fn resolve_root_node_engine_requirement(
    start_dir: &Path,
) -> Result<Option<RootNodeEngineRequirement>, LpmError> {
    let Some((_, root_pkg)) = resolve_root_package(start_dir)? else {
        return Ok(None);
    };
    let Some(required) = root_pkg.engines.get("node") else {
        return Ok(None);
    };
    Ok(Some(RootNodeEngineRequirement {
        required: required.clone(),
        engine_strict: engine_strict_config::resolve_for_root(false, &root_pkg),
    }))
}

pub(crate) fn resolve_execution_node_engine_requirements(
    start_dir: &Path,
) -> Result<Vec<NodeEngineRequirement>, LpmError> {
    let workspace = crate::workspace_discovery_cache::discover_workspace(start_dir)
        .map_err(|error| LpmError::Workspace(format!("could not discover workspace: {error}")))?;
    let (root_dir, root_pkg) = match workspace.as_ref() {
        Some(workspace) => (workspace.root.as_path(), &workspace.root_package),
        None => {
            let package_path = start_dir.join("package.json");
            if !package_path.exists() {
                return Ok(Vec::new());
            }
            let package = read_package_json(&package_path).map_err(|error| {
                LpmError::Workspace(format!("could not read package.json: {error}"))
            })?;
            let engine_strict = engine_strict_config::resolve_for_root(false, &package);
            return Ok(package
                .engines
                .get("node")
                .map(|required| {
                    vec![NodeEngineRequirement {
                        required: required.clone(),
                        engine_strict,
                        source: "package.json > engines.node".to_string(),
                    }]
                })
                .unwrap_or_default());
        }
    };
    let member_package = if start_dir != root_dir {
        let package_path = start_dir.join("package.json");
        if package_path.exists() {
            Some(read_package_json(&package_path).map_err(|error| {
                LpmError::Workspace(format!("could not read package.json: {error}"))
            })?)
        } else {
            None
        }
    } else {
        None
    };
    let engine_strict = engine_strict_config::resolve_for_root(false, root_pkg);
    Ok(workspace_node_engine_requirements(
        root_pkg,
        member_package.as_ref(),
        engine_strict,
    ))
}

pub(crate) fn workspace_node_engine_requirements(
    root_package: &PackageJson,
    member_package: Option<&PackageJson>,
    engine_strict: bool,
) -> Vec<NodeEngineRequirement> {
    let mut requirements = Vec::with_capacity(2);
    if let Some(required) = root_package.engines.get("node") {
        requirements.push(NodeEngineRequirement {
            required: required.clone(),
            engine_strict,
            source: "workspace root package.json > engines.node".to_string(),
        });
    }
    if let Some(required) = member_package.and_then(|package| package.engines.get("node"))
        && !requirements
            .iter()
            .any(|requirement| requirement.required == *required)
    {
        requirements.push(NodeEngineRequirement {
            required: required.clone(),
            engine_strict,
            source: "service package.json > engines.node".to_string(),
        });
    }
    requirements
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
    let script_path = lpm_runner::bin_path::build_path_with_bins(root_dir)?;
    let policy = DependencyEnginePolicy::new(
        root_dir.to_path_buf(),
        script_path.into(),
        engine_strict,
        json_output,
    );
    enforce_root_with_policy(root_pkg, &policy)
}

fn enforce_root_with_policy(
    root_pkg: &PackageJson,
    policy: &DependencyEnginePolicy,
) -> Result<(), LpmError> {
    // Manifest-compat warnings always run — regardless of whether
    // `engines` is set, because the detector also surfaces
    // `pnpm.overrides` / `pnpm.patchedDependencies` drift that has
    // nothing to do with the engines block. Silenced under `--json`
    // so the stdout JSON contract stays clean; automation pulls the
    // same signals from `lpm doctor --json`.
    emit_manifest_compat_warnings(root_pkg, policy.json_output);

    if root_pkg.engines.is_empty() {
        return Ok(());
    }

    let lpm_result = check_lpm_engine(&root_pkg.engines);
    let node_result = root_pkg.engines.get("node").map_or(Ok(()), |required| {
        policy.check_node_requirement(required, "package.json > engines.node".to_string())
    });

    if !policy.engine_strict {
        // Soft mode: surface mismatches as warnings, never abort.
        if let Err(msg) = &lpm_result
            && !policy.json_output
        {
            output::warn(&format!("{msg} (engine-strict disabled, ignoring)"));
        }
        if let Err(msg) = &node_result
            && !policy.json_output
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
    if let Some(ws) = crate::workspace_discovery_cache::discover_workspace(start_dir)
        .map_err(|e| LpmError::Workspace(format!("could not discover workspace: {e}")))?
    {
        return Ok(Some((ws.root.clone(), ws.root_package.clone())));
    }
    let pkg_json = start_dir.join("package.json");
    if !pkg_json.exists() {
        return Ok(None);
    }
    let pkg = read_package_json(&pkg_json)
        .map_err(|e| LpmError::Workspace(format!("could not read package.json: {e}")))?;
    Ok(Some((start_dir.to_path_buf(), pkg)))
}

/// Internal mismatch description. Converted to the command-appropriate
/// structured engine mismatch at the boundary.
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

    fn into_run_error(self, engine: &str) -> LpmError {
        LpmError::RunEngineMismatch {
            engine: engine.to_string(),
            required: self.required,
            actual: self.actual,
            from: self.source,
        }
    }
}

/// Compare `engines.lpm` against the running CLI's compatibility version.
fn check_lpm_engine(engines: &HashMap<String, String>) -> Result<(), Mismatch> {
    let Some(required) = engines.get("lpm") else {
        return Ok(());
    };
    let actual = crate::build_version::engine_compatibility_version();
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

/// Parse `required` as a semver range and `actual` as a version, then
/// check satisfaction. Returns the inner `Result` from semver parsing
/// so the caller can surface unparseable constraints distinctly from
/// failed matches.
pub(crate) fn version_satisfies(required: &str, actual: &str) -> Result<bool, String> {
    let req = lpm_semver::VersionReq::parse(required)
        .map_err(|e| format!("could not parse range '{required}': {e}"))?;
    let version = lpm_semver::Version::parse(actual)
        .map_err(|e| format!("could not parse version '{actual}': {e}"))?;
    Ok(req.matches(&version))
}

fn compatible_node_selector_hint(required: &str) -> String {
    let Ok(requirement) = lpm_semver::VersionReq::parse(required) else {
        return NEUTRAL_NODE_SELECTOR_HINT.to_string();
    };

    for major in [DEFAULT_NODE_SELECTOR_HINT, "24", "20", "18", "16"] {
        let Ok(candidate) = lpm_semver::Version::parse(&format!("{major}.999.999")) else {
            continue;
        };
        if requirement.matches(&candidate) {
            return major.to_string();
        }
    }

    for token in required.split(|character: char| character.is_whitespace() || character == '|') {
        let candidate = token.trim_matches(|character| {
            matches!(character, '<' | '>' | '=' | '^' | '~' | ',' | '(' | ')')
        });
        let candidate = candidate.strip_prefix('v').unwrap_or(candidate);
        let Ok(version) = lpm_semver::Version::parse(candidate) else {
            continue;
        };
        if requirement.matches(&version) {
            return candidate.to_string();
        }
    }

    NEUTRAL_NODE_SELECTOR_HINT.to_string()
}

/// Emit one stderr warning per [`lpm_workspace::ManifestCompatIssue`]
/// returned by `pkg.manifest_compat_issues()`. Silenced under JSON
/// output so the stdout JSON contract stays clean — automation
/// pipelines should consume the same signals from `lpm doctor --json`,
/// where each issue lands as a `Check::warn` with its stable code.
///
/// Renders each issue as a slim warning plus a dimmed `fix:` detail row.
fn emit_manifest_compat_warnings(pkg: &PackageJson, json_output: bool) {
    if json_output {
        return;
    }
    // Recursive workspace installs run this preflight once per target
    // against the same workspace-root manifest; dedupe so each issue
    // is reported once per process instead of once per target.
    static EMITTED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    for issue in pkg.manifest_compat_issues() {
        let first_emission = EMITTED
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(issue.detail.clone());
        if first_emission {
            output::warn(&issue.detail);
            output::field("fix", &issue.remediation);
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
    fn compatible_node_selector_prefers_default_for_open_lower_bound() {
        assert_eq!(compatible_node_selector_hint(">=18"), "22");
    }

    #[test]
    fn compatible_node_selector_uses_caret_major() {
        assert_eq!(compatible_node_selector_hint("^20"), "20");
    }

    #[test]
    fn compatible_node_selector_uses_wildcard_major() {
        assert_eq!(compatible_node_selector_hint("20.x"), "20");
    }

    #[test]
    fn compatible_node_selector_stays_below_upper_bound() {
        assert_eq!(compatible_node_selector_hint("<22"), "20");
    }

    #[test]
    fn compatible_node_selector_uses_neutral_hint_for_invalid_range() {
        assert_eq!(
            compatible_node_selector_hint("not-a-range"),
            "<matching-version>"
        );
    }

    #[test]
    fn empty_engines_passes() {
        let dir = tempdir().unwrap();
        let pkg = PackageJson::default();
        assert!(enforce_with_root(dir.path(), &pkg, true, false).is_ok());
    }

    #[test]
    fn workspace_engine_requirements_reuse_parsed_root_and_member_manifests() {
        let root = PackageJson {
            engines: engines(&[("node", ">=20")]),
            ..Default::default()
        };
        let member = PackageJson {
            engines: engines(&[("node", "^22")]),
            ..Default::default()
        };

        let requirements = workspace_node_engine_requirements(&root, Some(&member), true);

        assert_eq!(requirements.len(), 2);
        assert_eq!(requirements[0].required, ">=20");
        assert_eq!(requirements[1].required, "^22");
        assert_eq!(
            requirements[0].source,
            "workspace root package.json > engines.node"
        );
        assert_eq!(
            requirements[1].source,
            "service package.json > engines.node"
        );
    }

    #[test]
    fn workspace_engine_requirements_deduplicate_equal_constraints() {
        let root = PackageJson {
            engines: engines(&[("node", "^22")]),
            ..Default::default()
        };
        let member = root.clone();

        let requirements = workspace_node_engine_requirements(&root, Some(&member), true);

        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].required, "^22");
    }

    #[test]
    fn lpm_engine_satisfied_passes() {
        let cur = crate::build_version::engine_compatibility_version();
        let pkg = PackageJson {
            engines: engines(&[("lpm", &format!(">={cur}"))]),
            ..Default::default()
        };
        let dir = tempdir().unwrap();
        assert!(enforce_with_root(dir.path(), &pkg, true, true).is_ok());
    }

    #[test]
    fn nightly_build_satisfies_workspace_stable_lpm_engine_floor() {
        let pkg = PackageJson {
            engines: engines(&[("lpm", concat!(">=", env!("CARGO_PKG_VERSION")))]),
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

    #[test]
    fn legacy_lockfile_uses_migration_freshness_without_resolving_node() {
        let policy = DependencyEnginePolicy::new(PathBuf::new(), OsString::new(), true, true);

        assert_eq!(policy.freshness_key("lockfile-version = 5\n"), "legacy");
        assert!(policy.effective_node.get().is_none());
    }

    #[test]
    fn current_unconstrained_lockfile_preserves_existing_freshness() {
        let policy = DependencyEnginePolicy::new(PathBuf::new(), OsString::new(), true, true);
        let lockfile = format!("lockfile-version = {}\n", lpm_lockfile::LOCKFILE_VERSION);

        assert_eq!(policy.freshness_key(&lockfile), "none");
        assert!(policy.effective_node.get().is_none());
    }

    #[test]
    fn unknown_node_version_is_never_reused_from_fingerprint_cache() {
        let policy = DependencyEnginePolicy::new(PathBuf::new(), OsString::new(), true, true);

        assert!(!policy.can_reuse_constrained_freshness_key("1:unknown"));
    }
}
