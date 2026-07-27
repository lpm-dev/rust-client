//! Linker mode resolution for the install pipeline.
//!
//! Surfaces — in precedence order — that can override the default:
//!
//! 1. `--linker <isolated|hoisted>` CLI flag (clamped at clap parse time
//!    via `LinkerCli` and supplied by the caller as
//!    `Option<LinkerMode>`). Only the top-level `lpm install` dispatch has
//!    its own flag; internal callers that reuse the install pipeline
//!    (`lpm add`, `lpm upgrade`, `lpm dev`, `lpm migrate`, `lpm deploy`,
//!    `lpm dlx`, `lpm install -g`, `lpm global update`, `lpm doctor --fix`)
//!    pass `None` so the rest of the chain still applies.
//! 2. `~/.lpm/config.toml > linker` — global config-file value.
//! 3. `LPM_LINKER` env var — process-scoped override, useful for hermetic
//!    CI runs.
//! 4. `package.json > lpm > linker` — project-scoped value (read inside
//!    the install pipeline because it lives next to the manifest read).
//! 5. **Workspace-aware default**: if
//!    [`lpm_workspace::discover_workspace`] resolves to a workspace root
//!    (npm/yarn `workspaces` field OR `pnpm-workspace.yaml`) at the
//!    project dir or any ancestor, return `Isolated` — strict per-package
//!    dep boundaries pay off in monorepos where phantom-dep regressions
//!    are most expensive. Otherwise fall through.
//! 6. Default [`LinkerMode::default`] = `Hoisted` —
//!    single-package projects keep the npm-compat fast path.
//!
//! Unknown values from any non-CLI surface return an error pointing at the
//! offending surface so the install pipeline can surface them as
//! `LpmError::Script` BEFORE any work begins. The CLI flag never reaches
//! this module as a free string — clap rejects bad values at parse time.
//!
//! Living here (not on `main.rs`) keeps the module callable from inside
//! `commands::install` and re-usable from any future install entry point.

use std::path::Path;

use crate::commands::config::GlobalConfig;
use lpm_linker::LinkerMode;
use lpm_workspace::PackageJson;

/// Where the resolved [`LinkerMode`] came from.
///
/// Surfaced by [`resolve_effective_linker_with_source`] for diagnostics
/// (`lpm doctor`) so users can answer "why is my linker mode X?" without
/// re-deriving the precedence chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkerModeSource {
    /// Set by `--linker` on the CLI.
    CliFlag,
    /// Set by `~/.lpm/config.toml > linker`.
    GlobalConfig,
    /// Set by the `LPM_LINKER` env var.
    EnvVar,
    /// Set by `package.json > lpm > linker`.
    PackageJson,
    /// No explicit override; auto-resolved to `Isolated` because
    /// [`lpm_workspace::discover_workspace`] found a workspace root
    /// (npm/yarn `workspaces` field or `pnpm-workspace.yaml`) at the
    /// project dir or any ancestor.
    WorkspaceAutoDetected,
    /// No explicit override and not a workspace project — fell through
    /// to [`LinkerMode::default`] (Hoisted, 4f).
    Default,
}

impl LinkerModeSource {
    /// Short human-readable label for diagnostics output. Intentionally
    /// terse so it fits inside a `lpm doctor` `detail:` field; keep
    /// stable so users can grep for it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::CliFlag => "--linker flag",
            Self::GlobalConfig => "~/.lpm/config.toml",
            Self::EnvVar => "LPM_LINKER env",
            Self::PackageJson => "package.json > lpm > linker",
            Self::WorkspaceAutoDetected => "workspace auto-detected",
            Self::Default => "default",
        }
    }
}

/// Resolve the FULL linker chain to a single concrete `LinkerMode`.
/// Precedence: `cli_override` > `~/.lpm/config.toml > linker` >
/// `LPM_LINKER` > `package.json > lpm > linker` > workspace detection
/// > default hoisted.
///
/// This is the single source of truth used by both the install pipeline's
/// validation seam (where errors must surface loudly) AND the freshness
/// path (where the resolved mode is folded into the install-hash so a
/// post-install env or config change invalidates the "up to date" cache).
///
/// `project_dir` powers the workspace-detection step: a project sitting under a workspace root
/// auto-resolves to `Isolated` even without an explicit
/// `package.json > lpm > linker` setting. Single-package projects keep
/// the default `Hoisted`. Adding/removing a workspace globs file flips
/// the resolved mode, which feeds into the install-hash and triggers a
/// re-link on the next install — no manual cache bust required.
///
/// Errors carry the offending surface in their message so callers can
/// produce useful diagnostics without re-deriving the source.
pub(crate) fn resolve_effective_linker(
    cli_override: Option<LinkerMode>,
    pkg: &PackageJson,
    cfg: &GlobalConfig,
    project_dir: &Path,
) -> Result<LinkerMode, String> {
    resolve_effective_linker_with_source(cli_override, pkg, cfg, project_dir).map(|(mode, _)| mode)
}

/// Same as [`resolve_effective_linker`] but also returns the
/// [`LinkerModeSource`] that won the precedence chain.
///
/// Used by `lpm doctor` to surface "why is my linker mode X?" without
/// re-deriving the chain. The install pipeline calls
/// [`resolve_effective_linker`] and discards the source — keeps the
/// hot path's signature lean.
pub(crate) fn resolve_effective_linker_with_source(
    cli_override: Option<LinkerMode>,
    pkg: &PackageJson,
    cfg: &GlobalConfig,
    project_dir: &Path,
) -> Result<(LinkerMode, LinkerModeSource), String> {
    if let Some(mode) = cli_override {
        return Ok((mode, LinkerModeSource::CliFlag));
    }
    // The two env-driven surfaces share a helper but resolve from
    // different inputs — disambiguate the source here so `lpm doctor`
    // can name which one fired.
    if let Some(s) = cfg.get_str("linker") {
        let mode = LinkerMode::parse_str(s)
            .map_err(|e| format!("invalid `linker` in ~/.lpm/config.toml: {e}"))?;
        return Ok((mode, LinkerModeSource::GlobalConfig));
    }
    if let Ok(s) = std::env::var("LPM_LINKER")
        && !s.is_empty()
    {
        let mode =
            LinkerMode::parse_str(&s).map_err(|e| format!("invalid LPM_LINKER value: {e}"))?;
        return Ok((mode, LinkerModeSource::EnvVar));
    }
    if let Some(s) = pkg.lpm.as_ref().and_then(|l| l.linker.as_deref()) {
        let mode = LinkerMode::parse_str(s)
            .map_err(|e| format!("invalid `lpm.linker` in package.json: {e}"))?;
        return Ok((mode, LinkerModeSource::PackageJson));
    }
    // Workspace-aware default. `discover_workspace`
    // walks up from `project_dir` looking for a root manifest with a
    // `workspaces` glob OR a `pnpm-workspace.yaml`; either signal flips
    // us to `Isolated`. On I/O failure (permission denied, broken parent
    // chain) we fall through silently to the default rather than fail
    // the install — the install pipeline still works under Hoisted, so
    // the cost of a recoverable I/O blip should not be a hard error.
    if matches!(
        crate::workspace_discovery_cache::discover_workspace(project_dir),
        Ok(Some(_))
    ) {
        return Ok((
            LinkerMode::Isolated,
            LinkerModeSource::WorkspaceAutoDetected,
        ));
    }
    Ok((LinkerMode::default(), LinkerModeSource::Default))
}

/// Same as [`resolve_effective_linker`] but driven from raw `pkg_content`
/// bytes instead of a parsed [`PackageJson`]. Used by the freshness
/// surface ([`crate::install_state::check_install_state`]) which already
/// has the manifest as bytes and needs to avoid a second typed parse on
/// the hot path.
///
/// **Two-stage parse invariant.** The silent `Isolated` fallback below
/// is safe because of an upstream contract: `lpm install` only ever
/// writes the install-hash via `write_post_install_hash` AFTER
/// `read_package_json` has already succeeded with the typed
/// `PackageJson` parse (install fails fast otherwise). So whenever the
/// mtime fast path finds a matching install hash on disk, the manifest at
/// that mtime DID typed-parse at install time. The fast path can
/// trust mtime as a content proxy without re-running the typed parse.
/// The slow path's own typed-parse guard at
/// `check_install_state_with_linker` is the safety net for the
/// remaining cases (no hash file yet, or mtime-mismatch fall-through).
/// Pinned by `syntactically_invalid_json_returns_not_up_to_date` and
/// `semantically_invalid_manifest_returns_not_up_to_date` in
/// `install_state::tests` — both write a v1-shape hash file (which
/// the mtime fast path can't read), and assert the slow-path guard
/// catches the parse failure.
pub(crate) fn resolve_effective_linker_from_bytes(
    cli_override: Option<LinkerMode>,
    pkg_content: &str,
    cfg: &GlobalConfig,
    project_dir: &Path,
) -> Result<LinkerMode, String> {
    let pkg: PackageJson = match serde_json::from_str(pkg_content) {
        Ok(p) => p,
        Err(_) => return Ok(LinkerMode::default()),
    };
    resolve_effective_linker(cli_override, &pkg, cfg, project_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ScopedEnv;

    fn empty_cfg() -> GlobalConfig {
        GlobalConfig::empty()
    }

    /// Helper for env-var precedence tests: build an empty single-package
    /// project so the env-var surface is the one being exercised, not
    /// workspace detection or `package.json > lpm > linker`.
    fn empty_single_package() -> (tempfile::TempDir, std::path::PathBuf, PackageJson) {
        let pkg_content = r#"{"name":"x","version":"1.0.0"}"#;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), pkg_content).unwrap();
        let path = dir.path().to_path_buf();
        let pkg = parse_pkg(pkg_content);
        (dir, path, pkg)
    }

    #[test]
    fn env_var_unset_falls_through_to_default() {
        let _env = ScopedEnv::update([("LPM_LINKER", None)]);
        let (_dir, project, pkg) = empty_single_package();
        let (mode, source) =
            resolve_effective_linker_with_source(None, &pkg, &empty_cfg(), &project).unwrap();
        assert_eq!(mode, LinkerMode::Hoisted);
        assert_eq!(source, LinkerModeSource::Default);
    }

    #[test]
    fn env_var_set_wins_with_envvar_source() {
        let _env = ScopedEnv::set([("LPM_LINKER", "hoisted".into())]);
        let (_dir, project, pkg) = empty_single_package();
        let (mode, source) =
            resolve_effective_linker_with_source(None, &pkg, &empty_cfg(), &project).unwrap();
        assert_eq!(mode, LinkerMode::Hoisted);
        assert_eq!(source, LinkerModeSource::EnvVar);
    }

    #[test]
    fn env_var_invalid_value_errors_loudly_and_names_var() {
        let _env = ScopedEnv::set([("LPM_LINKER", "symlink".into())]);
        let (_dir, project, pkg) = empty_single_package();
        let err =
            resolve_effective_linker_with_source(None, &pkg, &empty_cfg(), &project).unwrap_err();
        assert!(err.contains("LPM_LINKER"), "error must name the var: {err}");
        assert!(err.contains("unknown linker mode"));
        assert!(err.contains("\"isolated\"") && err.contains("\"hoisted\""));
    }

    #[test]
    fn empty_env_var_falls_through_past_envvar_surface() {
        let _env = ScopedEnv::set([("LPM_LINKER", "".into())]);
        let (_dir, project, pkg) = empty_single_package();
        let (mode, source) =
            resolve_effective_linker_with_source(None, &pkg, &empty_cfg(), &project).unwrap();
        assert_eq!(mode, LinkerMode::Hoisted);
        assert_eq!(
            source,
            LinkerModeSource::Default,
            "empty `LPM_LINKER=` must NOT count as the EnvVar surface",
        );
    }

    /// Helper for the workspace-detection tests below: build a temp
    /// project dir and write the given `package.json` content into it.
    /// Returns the dir handle (to keep the temp alive) plus its path.
    fn temp_project(pkg_json: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), pkg_json).unwrap();
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    fn parse_pkg(content: &str) -> PackageJson {
        serde_json::from_str(content).expect("test fixture must be valid JSON")
    }

    #[test]
    fn single_package_project_defaults_to_hoisted() {
        let _env = ScopedEnv::update([("LPM_LINKER", None)]);
        let pkg_content = r#"{"name":"single","version":"1.0.0"}"#;
        let (_dir, project) = temp_project(pkg_content);
        let pkg = parse_pkg(pkg_content);
        assert_eq!(
            resolve_effective_linker(None, &pkg, &empty_cfg(), &project).unwrap(),
            LinkerMode::Hoisted,
            "no workspaces glob anywhere → fall back to default Hoisted",
        );
    }

    #[test]
    fn npm_yarn_workspaces_field_flips_default_to_isolated() {
        let _env = ScopedEnv::update([("LPM_LINKER", None)]);
        let pkg_content = r#"{
            "name":"monorepo-root",
            "version":"1.0.0",
            "workspaces":["packages/*"]
        }"#;
        let (_dir, project) = temp_project(pkg_content);
        // Materialize a member dir so `discover_workspace` finds at
        // least one resolved workspace member (some implementations
        // require a non-empty member set).
        let member = project.join("packages").join("a");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            member.join("package.json"),
            r#"{"name":"@scope/a","version":"0.1.0"}"#,
        )
        .unwrap();
        let pkg = parse_pkg(pkg_content);
        assert_eq!(
            resolve_effective_linker(None, &pkg, &empty_cfg(), &project).unwrap(),
            LinkerMode::Isolated,
            "npm/yarn `workspaces` field at the project root → Isolated",
        );
    }

    #[test]
    fn pnpm_workspace_yaml_flips_default_to_isolated() {
        let _env = ScopedEnv::update([("LPM_LINKER", None)]);
        let pkg_content = r#"{"name":"pnpm-monorepo","version":"1.0.0"}"#;
        let (_dir, project) = temp_project(pkg_content);
        // pnpm-workspace.yaml as the alternate workspace signal.
        std::fs::write(
            project.join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n",
        )
        .unwrap();
        let member = project.join("packages").join("a");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            member.join("package.json"),
            r#"{"name":"@scope/a","version":"0.1.0"}"#,
        )
        .unwrap();
        let pkg = parse_pkg(pkg_content);
        assert_eq!(
            resolve_effective_linker(None, &pkg, &empty_cfg(), &project).unwrap(),
            LinkerMode::Isolated,
            "pnpm-workspace.yaml at the project root → Isolated",
        );
    }

    #[test]
    fn workspace_member_dir_resolves_via_walk_up() {
        let _env = ScopedEnv::update([("LPM_LINKER", None)]);
        let root_pkg = r#"{
            "name":"monorepo-root",
            "version":"1.0.0",
            "workspaces":["packages/*"]
        }"#;
        let (_dir, project) = temp_project(root_pkg);
        let member = project.join("packages").join("a");
        std::fs::create_dir_all(&member).unwrap();
        let member_pkg = r#"{"name":"@scope/a","version":"0.1.0"}"#;
        std::fs::write(member.join("package.json"), member_pkg).unwrap();
        // Resolve from the MEMBER's perspective — `discover_workspace`
        // walks up to find the root manifest.
        let pkg = parse_pkg(member_pkg);
        assert_eq!(
            resolve_effective_linker(None, &pkg, &empty_cfg(), &member).unwrap(),
            LinkerMode::Isolated,
            "running `lpm install` inside a workspace member must resolve to Isolated",
        );
    }

    #[test]
    fn cli_override_beats_workspace_detection() {
        let _env = ScopedEnv::update([("LPM_LINKER", None)]);
        let pkg_content = r#"{
            "name":"monorepo-root",
            "version":"1.0.0",
            "workspaces":["packages/*"]
        }"#;
        let (_dir, project) = temp_project(pkg_content);
        let pkg = parse_pkg(pkg_content);
        assert_eq!(
            resolve_effective_linker(Some(LinkerMode::Hoisted), &pkg, &empty_cfg(), &project)
                .unwrap(),
            LinkerMode::Hoisted,
            "explicit `--linker hoisted` wins over workspace auto-detection",
        );
    }

    #[test]
    fn env_var_beats_workspace_detection() {
        let _env = ScopedEnv::set([("LPM_LINKER", "hoisted".into())]);
        let pkg_content = r#"{
            "name":"monorepo-root",
            "version":"1.0.0",
            "workspaces":["packages/*"]
        }"#;
        let (_dir, project) = temp_project(pkg_content);
        let pkg = parse_pkg(pkg_content);
        assert_eq!(
            resolve_effective_linker(None, &pkg, &empty_cfg(), &project).unwrap(),
            LinkerMode::Hoisted,
            "`LPM_LINKER=hoisted` wins over workspace auto-detection",
        );
    }

    #[test]
    fn package_json_lpm_linker_beats_workspace_detection() {
        let _env = ScopedEnv::update([("LPM_LINKER", None)]);
        let pkg_content = r#"{
            "name":"monorepo-root",
            "version":"1.0.0",
            "workspaces":["packages/*"],
            "lpm":{"linker":"hoisted"}
        }"#;
        let (_dir, project) = temp_project(pkg_content);
        let pkg = parse_pkg(pkg_content);
        assert_eq!(
            resolve_effective_linker(None, &pkg, &empty_cfg(), &project).unwrap(),
            LinkerMode::Hoisted,
            "`package.json > lpm > linker` wins over workspace auto-detection",
        );
    }
}
