//! Resolve the "effective" Node.js version for a project — the version
//! that LPM will actually invoke when scripts run.
//!
//! Used by the engine-strict gate (`crates/lpm-cli/src/engine_check.rs`)
//! to validate `engines.node` against the version that will be picked
//! up at script-execution time, rather than blindly trusting whatever
//! happens to be on `PATH`.
//!
//! Resolution order:
//!
//! 1. If the project pins a Node version (`lpm.json > runtime.node`,
//!    `package.json > engines.node`, `.nvmrc`, `.node-version`) AND a
//!    managed runtime under `~/.lpm/runtimes/node/` satisfies that pin,
//!    use the managed version.
//! 2. Else, fall back to the system `node --version` from `PATH`.
//! 3. Else, return [`Effective::Unknown`] — the engine check should
//!    skip rather than fail when no Node is available at all.
//!
//! The pin-but-not-yet-installed case intentionally falls through to
//! the system Node: that mirrors npm's behavior (compare engines.node
//! against the running Node), and it gives the user a clear escape
//! hatch — `lpm use node@<v>` first, then re-run install.

use crate::detect;
use crate::node;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// What Node version LPM resolved as "effective" for this project.
#[derive(Debug, Clone)]
pub enum Effective {
    /// A managed runtime at `~/.lpm/runtimes/node/<version>/` matched
    /// the project's pin. This version will be on `PATH` when scripts
    /// run.
    Managed { version: String, source: String },
    /// No managed runtime matched (or no pin exists). `node --version`
    /// from `PATH` will be invoked.
    System { version: String },
    /// No managed runtime matched and `node` is not on `PATH`. The
    /// engine check should skip — there's nothing to validate against.
    Unknown,
}

impl Effective {
    /// The resolved version string, if any.
    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Managed { version, .. } | Self::System { version } => Some(version),
            Self::Unknown => None,
        }
    }

    /// Where the version came from, for user-facing error messages.
    pub fn source_label(&self) -> &str {
        match self {
            Self::Managed { source, .. } => source,
            Self::System { .. } => "system PATH",
            Self::Unknown => "unknown",
        }
    }
}

/// Resolve the effective Node version LPM would invoke for `project_dir`.
///
/// Pure helper: no network, no filesystem mutation. Reads the project's
/// pin sources and `~/.lpm/runtimes/node/`, and shells out to `node
/// --version` once at the system-fallback step.
pub fn resolve_effective_node_version(project_dir: &Path) -> Effective {
    resolve_inner(detect::detect_node_version(project_dir))
}

/// Variant for callers that have already parsed `package.json`'s
/// `engines` block. Skips the duplicate disk read in [`detect`].
pub fn resolve_effective_node_version_with_engines(
    project_dir: &Path,
    engines: &HashMap<String, String>,
) -> Effective {
    resolve_inner(detect::detect_node_version_with_engines(
        project_dir,
        engines,
    ))
}

fn resolve_inner(detected: Option<detect::DetectedNodeVersion>) -> Effective {
    if let Some(detected) = detected {
        let installed = node::list_installed().unwrap_or_default();
        if let Some(version) = node::find_matching_installed(&detected.spec, &installed) {
            return Effective::Managed {
                version,
                source: detected.source.to_string(),
            };
        }
    }

    if let Some(version) = system_node_version() {
        return Effective::System { version };
    }

    Effective::Unknown
}

/// Run `node --version` and return the bare version string (no `v`
/// prefix). Returns `None` when `node` is not on `PATH` or the output
/// is unparseable.
fn system_node_version() -> Option<String> {
    let output = Command::new("node").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    let bare = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn no_pin_no_node_returns_managed_or_system_or_unknown() {
        // We can't reliably control PATH in a unit test, so the only
        // assertion that holds across CI environments is "doesn't panic
        // and returns one of the three variants."
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_effective_node_version(dir.path());
        match result {
            Effective::Managed { .. } | Effective::System { .. } | Effective::Unknown => {}
        }
    }

    #[test]
    fn unknown_has_no_version() {
        let e = Effective::Unknown;
        assert!(e.version().is_none());
        assert_eq!(e.source_label(), "unknown");
    }

    #[test]
    fn managed_exposes_source_label() {
        let e = Effective::Managed {
            version: "22.5.0".into(),
            source: "lpm.json".into(),
        };
        assert_eq!(e.version(), Some("22.5.0"));
        assert_eq!(e.source_label(), "lpm.json");
    }

    #[test]
    fn system_exposes_path_source_label() {
        let e = Effective::System {
            version: "20.18.0".into(),
        };
        assert_eq!(e.version(), Some("20.18.0"));
        assert_eq!(e.source_label(), "system PATH");
    }

    #[test]
    fn pin_without_managed_runtime_falls_through_to_system() {
        // Project pins node@99.0.0 — no managed runtime exists for
        // that. The helper must not crash; it should fall through to
        // the system Node (or Unknown if none is on PATH).
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines": {"node": "99.0.0"}}"#,
        )
        .unwrap();
        let result = resolve_effective_node_version(dir.path());
        assert!(!matches!(
            result,
            Effective::Managed { ref version, .. } if version == "99.0.0"
        ));
    }
}
