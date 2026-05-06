//! Linker mode resolution for the install pipeline.
//!
//! Surfaces — in precedence order — that can override the default isolated
//! layout:
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
//! 5. Default `LinkerMode::Isolated` (pnpm-style).
//!
//! Unknown values from any non-CLI surface return an error pointing at the
//! offending surface so the install pipeline can surface them as
//! `LpmError::Script` BEFORE any work begins. The CLI flag never reaches
//! this module as a free string — clap rejects bad values at parse time.
//!
//! Living here (not on `main.rs`) keeps the module callable from inside
//! `commands::install` and re-usable from any future install entry point.

use crate::commands::config::GlobalConfig;
use lpm_linker::LinkerMode;
use lpm_workspace::PackageJson;

/// Resolve the environment-driven linker override (config.toml + env var).
/// Returns `Ok(None)` when neither surface is set; install then falls
/// through to `package.json > lpm > linker` and finally the default.
///
/// Empty `LPM_LINKER=""` falls through (consistent with the tunnel-relay
/// resolver's empty-value handling — `unset` and `set-to-empty` both mean
/// "no override").
pub(crate) fn resolve_environment_linker_override(
    cfg: &GlobalConfig,
) -> Result<Option<LinkerMode>, String> {
    if let Some(s) = cfg.get_str("linker") {
        let mode = LinkerMode::parse_str(s)
            .map_err(|e| format!("invalid `linker` in ~/.lpm/config.toml: {e}"))?;
        return Ok(Some(mode));
    }
    match std::env::var("LPM_LINKER") {
        Ok(s) if !s.is_empty() => {
            let mode =
                LinkerMode::parse_str(&s).map_err(|e| format!("invalid LPM_LINKER value: {e}"))?;
            Ok(Some(mode))
        }
        _ => Ok(None),
    }
}

/// Resolve the FULL linker chain to a single concrete `LinkerMode`.
/// Precedence: `cli_override` > `~/.lpm/config.toml > linker` >
/// `LPM_LINKER` > `package.json > lpm > linker` > default isolated.
///
/// This is the single source of truth used by both the install pipeline's
/// validation seam (where errors must surface loudly) AND the freshness
/// path (where the resolved mode is folded into the install-hash so a
/// post-install env or config change invalidates the "up to date" cache).
///
/// Errors carry the offending surface in their message so callers can
/// produce useful diagnostics without re-deriving the source.
pub(crate) fn resolve_effective_linker(
    cli_override: Option<LinkerMode>,
    pkg: &PackageJson,
    cfg: &GlobalConfig,
) -> Result<LinkerMode, String> {
    if let Some(mode) = cli_override {
        return Ok(mode);
    }
    if let Some(mode) = resolve_environment_linker_override(cfg)? {
        return Ok(mode);
    }
    if let Some(s) = pkg.lpm.as_ref().and_then(|l| l.linker.as_deref()) {
        return LinkerMode::parse_str(s)
            .map_err(|e| format!("invalid `lpm.linker` in package.json: {e}"));
    }
    Ok(LinkerMode::Isolated)
}

/// Same as [`resolve_effective_linker`] but driven from raw `pkg_content`
/// bytes instead of a parsed [`PackageJson`]. Used by the freshness
/// surface ([`crate::install_state::check_install_state`]) which already
/// has the manifest as bytes and needs to avoid a second typed parse on
/// the hot path.
///
/// **Two-stage parse invariant.** The silent `Isolated` fallback below
/// is safe because of an upstream contract: `lpm install` only ever
/// writes a v6 install-hash via `write_post_install_v6_hash` AFTER
/// `read_package_json` has already succeeded with the typed
/// `PackageJson` parse (install fails fast otherwise). So whenever the
/// mtime fast path finds a matching v6 hash on disk, the manifest at
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
) -> Result<LinkerMode, String> {
    let pkg: PackageJson = match serde_json::from_str(pkg_content) {
        Ok(p) => p,
        Err(_) => return Ok(LinkerMode::Isolated),
    };
    resolve_effective_linker(cli_override, &pkg, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ScopedEnv;

    fn empty_cfg() -> GlobalConfig {
        GlobalConfig::empty()
    }

    #[test]
    fn unset_returns_none() {
        let _env = ScopedEnv::update([("LPM_LINKER", None)]);
        assert_eq!(
            resolve_environment_linker_override(&empty_cfg()).unwrap(),
            None
        );
    }

    #[test]
    fn env_var_set_returns_parsed_mode() {
        let _env = ScopedEnv::set([("LPM_LINKER", "hoisted".into())]);
        assert_eq!(
            resolve_environment_linker_override(&empty_cfg()).unwrap(),
            Some(LinkerMode::Hoisted),
        );
    }

    #[test]
    fn env_var_invalid_value_errors_loudly_and_names_var() {
        let _env = ScopedEnv::set([("LPM_LINKER", "symlink".into())]);
        let err = resolve_environment_linker_override(&empty_cfg()).unwrap_err();
        assert!(err.contains("LPM_LINKER"), "error must name the var: {err}");
        assert!(err.contains("unknown linker mode"));
        assert!(err.contains("\"isolated\"") && err.contains("\"hoisted\""));
    }

    #[test]
    fn empty_env_var_falls_through_to_none() {
        let _env = ScopedEnv::set([("LPM_LINKER", "".into())]);
        assert_eq!(
            resolve_environment_linker_override(&empty_cfg()).unwrap(),
            None
        );
    }
}
