//! Phase 37 M5 — `~/.lpm/global/trusted-dependencies.json` storage.
//!
//! Parallels the project-level `package.json :: lpm.trustedDependencies`
//! for globally-installed packages. Where a project's trust list lives
//! in its `package.json` (per-project scope), a globally-installed
//! package's synthesized `package.json` is ephemeral — the trust list
//! must live in a durable, machine-global file instead.
//!
//! ## Schema
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "trusted": {
//!     "esbuild@0.25.1": {
//!       "integrity": "sha512-...",
//!       "scriptHash": "sha256-..."
//!     }
//!   }
//! }
//! ```
//!
//! One flat map keyed by `name@version`. Same binding format as the
//! project-level `TrustedDependencyBinding` (we reuse that struct
//! verbatim via lpm-workspace). `script_hash` and `integrity` are both
//! optional because an older `lpm approve-builds` run may have approved
//! a package before either field was reliably available — strict-gate
//! lookup in [`GlobalTrustedDependencies::matches_strict`] degrades
//! accordingly.
//!
//! ## Atomic-write contract
//!
//! Same pattern as `manifest.toml`: serialize to JSON, write via
//! tempfile + rename. POSIX rename is atomic on the same filesystem;
//! on Windows the `MoveFileEx`-backed `std::fs::rename` is functionally
//! equivalent for a file this size. Callers are responsible for
//! serializing writes through the global `.tx.lock` when updating
//! trust state as part of a larger transaction.
//!
//! ## Why keyed by `name@version` not `name`
//!
//! Phase 4's strict binding: trust is bound to a specific integrity +
//! script-hash of a specific version. Approving `esbuild@0.20.2`
//! doesn't automatically trust `esbuild@0.25.1` — the install pipeline
//! blocks the new version on the expected "re-review" path. Matches
//! the project-level model exactly.

use lpm_common::{LpmError, LpmRoot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Binding metadata for one entry in the global trusted-deps map.
///
/// Wire-identical to `lpm_workspace::TrustedDependencyBinding` —
/// same field names, same serde rename for `scriptHash`, same
/// `skip_serializing_if = Option::is_none`. Duplicated here rather
/// than imported so `lpm-global` stays lower-layer and can't
/// accidentally pull in the broader workspace / manifest dependency
/// graph. If the two ever drift, `approve-builds --global` is the
/// integration layer responsible for reconciling; for v1 they match.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustedDependencyBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    #[serde(
        default,
        rename = "scriptHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub script_hash: Option<String>,
}

pub const SCHEMA_VERSION: u32 = 1;
pub const FILENAME: &str = "trusted-dependencies.json";

/// Top-level shape of `~/.lpm/global/trusted-dependencies.json`.
///
/// `BTreeMap` (rather than `HashMap`) so on-disk JSON ordering is
/// deterministic. Important for diffability and for tests that assert
/// the full file contents round-trip unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalTrustedDependencies {
    pub schema_version: u32,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub trusted: BTreeMap<String, TrustedDependencyBinding>,
}

impl Default for GlobalTrustedDependencies {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            trusted: BTreeMap::new(),
        }
    }
}

/// Key format used internally + by consumers: `"name@version"`. Single
/// source of truth so every caller produces the same string.
pub fn rich_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

/// Query result. Mirrors the project-level `TrustMatch` shape so the
/// install pipeline can branch uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustMatch {
    /// Rich entry exists with integrity + scriptHash matching the query.
    /// Script execution allowed.
    Strict,
    /// Rich entry exists for this `name@version` but at least one of
    /// integrity / scriptHash differs from the query. Script execution
    /// BLOCKED; caller surfaces binding drift to the user.
    BindingDrift { stored: TrustedDependencyBinding },
    /// No matching entry. Script execution blocked; user must run
    /// `lpm approve-builds --global` to opt in.
    NotTrusted,
}

impl GlobalTrustedDependencies {
    /// Strict query for a `(name, version, integrity, script_hash)`
    /// tuple. Mirrors `TrustedDependencies::matches_strict` from
    /// lpm-workspace's project-level counterpart, scoped to the global
    /// trust file.
    pub fn matches_strict(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> TrustMatch {
        let key = rich_key(name, version);
        let Some(binding) = self.trusted.get(&key) else {
            return TrustMatch::NotTrusted;
        };
        // Strict equality on both fields. If a stored field is `None`,
        // the caller's field being `Some(_)` counts as drift — the
        // query's signal is stricter than the stored trust.
        let integ_match = match (binding.integrity.as_deref(), integrity) {
            (Some(stored), Some(queried)) => stored == queried,
            (None, None) => true,
            _ => false,
        };
        let script_match = match (binding.script_hash.as_deref(), script_hash) {
            (Some(stored), Some(queried)) => stored == queried,
            (None, None) => true,
            _ => false,
        };
        if integ_match && script_match {
            TrustMatch::Strict
        } else {
            TrustMatch::BindingDrift {
                stored: binding.clone(),
            }
        }
    }

    /// Insert-or-overwrite a strict trust binding for the given
    /// `(name, version)`. Used by `lpm approve-builds --global`'s
    /// write path when the user approves a previously-blocked package.
    ///
    /// Both `integrity` and `script_hash` are optional because the
    /// blocked-set capture may have missed one (e.g. a registry
    /// response that lacked the SRI). Approving anyway is a deliberate
    /// user choice — the strict query degrades to drift-detection for
    /// any missing field pair.
    pub fn insert_strict(
        &mut self,
        name: &str,
        version: &str,
        integrity: Option<String>,
        script_hash: Option<String>,
    ) {
        self.trusted.insert(
            rich_key(name, version),
            TrustedDependencyBinding {
                integrity,
                script_hash,
            },
        );
    }

    /// Remove a trust binding. Used on `uninstall -g <pkg>` to sweep
    /// trust rows for the uninstalled install's transitive deps.
    ///
    /// Safe to call for bindings that don't exist — returns `false`
    /// silently. The caller (uninstall) iterates candidates without
    /// knowing which are actually trusted.
    pub fn remove(&mut self, name: &str, version: &str) -> bool {
        self.trusted.remove(&rich_key(name, version)).is_some()
    }
}

/// Read the global trusted-deps file. Missing file is NOT an error —
/// returns the default (empty) struct. This matches the project-level
/// behaviour where a `package.json` without `lpm.trustedDependencies`
/// is semantically equivalent to an empty list.
///
/// Schema version mismatches currently return `default()` with a debug
/// log. A future release that introduces a non-backward-compatible
/// schema change would rewrite this to migrate or hard-error; for v1
/// forward-compat via serde's `default` + `skip_serializing_if` is
/// sufficient.
pub fn read_for(root: &LpmRoot) -> Result<GlobalTrustedDependencies, LpmError> {
    read_at(&root.global_trusted_deps())
}

/// Lower-level read against a specific path. Useful for tests and
/// recovery paths that read from a non-default location (e.g. a
/// backup file during a migration).
pub fn read_at(path: &Path) -> Result<GlobalTrustedDependencies, LpmError> {
    match fs::read(path) {
        Ok(bytes) => {
            let value: GlobalTrustedDependencies = serde_json::from_slice(&bytes).map_err(|e| {
                LpmError::Script(format!(
                    "{} is malformed: {e}. Delete it to reset the global trust list, \
                         or fix the JSON manually.",
                    path.display()
                ))
            })?;
            if value.schema_version > SCHEMA_VERSION {
                return Err(LpmError::Script(format!(
                    "{} was written by a newer lpm (schema {}); this binary only understands \
                     schema up to {}. Upgrade lpm or use a compatible binary.",
                    path.display(),
                    value.schema_version,
                    SCHEMA_VERSION,
                )));
            }
            Ok(value)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(GlobalTrustedDependencies::default())
        }
        Err(e) => Err(LpmError::Io(e)),
    }
}

/// Write atomically. Serialized body is pretty-printed with a
/// trailing newline for diffability — an operator doing `git log -p`
/// on a checked-in `.lpm/global/` will see clean JSON diffs.
pub fn write_for(root: &LpmRoot, value: &GlobalTrustedDependencies) -> Result<(), LpmError> {
    write_at(&root.global_trusted_deps(), value)
}

pub fn write_at(path: &Path, value: &GlobalTrustedDependencies) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut body = serde_json::to_string_pretty(value)
        .map_err(|e| LpmError::Script(format!("serialize trusted-deps: {e}")))?;
    body.push('\n');
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, body.as_bytes())?;
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(LpmError::Io(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn binding(integ: Option<&str>, script: Option<&str>) -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            integrity: integ.map(String::from),
            script_hash: script.map(String::from),
        }
    }

    #[test]
    fn default_is_empty_at_current_schema_version() {
        let d = GlobalTrustedDependencies::default();
        assert_eq!(d.schema_version, SCHEMA_VERSION);
        assert!(d.trusted.is_empty());
    }

    #[test]
    fn rich_key_format_is_stable() {
        assert_eq!(rich_key("eslint", "9.24.0"), "eslint@9.24.0");
        // Scoped names round-trip without special handling.
        assert_eq!(
            rich_key("@lpm.dev/owner.tool", "1.0.0"),
            "@lpm.dev/owner.tool@1.0.0"
        );
    }

    #[test]
    fn read_missing_file_returns_default() {
        let tmp = TempDir::new().unwrap();
        let out = read_at(&tmp.path().join("absent.json")).unwrap();
        assert_eq!(out, GlobalTrustedDependencies::default());
    }

    #[test]
    fn round_trip_preserves_all_entries() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-esb".into()),
            Some("sha256-scr".into()),
        );
        gtd.insert_strict("sharp", "0.33.0", None, None);
        write_at(&path, &gtd).unwrap();
        let read = read_at(&path).unwrap();
        assert_eq!(read, gtd);
    }

    #[test]
    fn serialized_body_is_pretty_printed_json_with_trailing_newline() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("x", "1.0.0", Some("sha512-a".into()), None);
        write_at(&path, &gtd).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let body = String::from_utf8(bytes).unwrap();
        assert!(body.ends_with('\n'), "file must end with a newline");
        assert!(body.contains("  "), "body must be pretty-printed");
    }

    #[test]
    fn matches_strict_returns_strict_for_exact_binding() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-e".into()),
            Some("sha256-s".into()),
        );
        let m = gtd.matches_strict("esbuild", "0.25.1", Some("sha512-e"), Some("sha256-s"));
        assert_eq!(m, TrustMatch::Strict);
    }

    #[test]
    fn matches_strict_returns_not_trusted_for_missing_entry() {
        let gtd = GlobalTrustedDependencies::default();
        let m = gtd.matches_strict("ghost", "1.0.0", Some("a"), Some("b"));
        assert_eq!(m, TrustMatch::NotTrusted);
    }

    #[test]
    fn matches_strict_returns_binding_drift_on_integrity_mismatch() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-STORED".into()),
            Some("sha256-same".into()),
        );
        let m = gtd.matches_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-QUERIED"),
            Some("sha256-same"),
        );
        match m {
            TrustMatch::BindingDrift { stored } => {
                assert_eq!(stored.integrity.as_deref(), Some("sha512-STORED"));
            }
            other => panic!("expected BindingDrift, got {other:?}"),
        }
    }

    #[test]
    fn matches_strict_returns_binding_drift_on_script_hash_mismatch() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-same".into()),
            Some("sha256-STORED".into()),
        );
        let m = gtd.matches_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-same"),
            Some("sha256-QUERIED"),
        );
        assert!(matches!(m, TrustMatch::BindingDrift { .. }));
    }

    /// Version-specific trust: approving 0.25.1 does NOT implicitly
    /// trust 0.25.2. Pins the Phase 4 version-bound trust model for
    /// the global analogue.
    #[test]
    fn matches_strict_version_bound_does_not_leak_across_versions() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("esbuild", "0.25.1", Some("a".into()), Some("b".into()));
        let m = gtd.matches_strict("esbuild", "0.25.2", Some("a"), Some("b"));
        assert_eq!(m, TrustMatch::NotTrusted);
    }

    /// Missing stored integrity counts as drift against a queried
    /// present value. The pre-Phase-4-schema-aware approval case: we
    /// had no SRI at approve time, but the install pipeline now has
    /// one. Surfaced as drift so the user can re-approve with the
    /// richer binding.
    #[test]
    fn matches_strict_missing_stored_field_against_present_query_is_drift() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("esbuild", "0.25.1", None, Some("sha256-s".into()));
        let m = gtd.matches_strict("esbuild", "0.25.1", Some("sha512-e"), Some("sha256-s"));
        assert!(matches!(m, TrustMatch::BindingDrift { .. }));
    }

    #[test]
    fn insert_strict_overwrites_existing_binding() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("x", "1.0.0", Some("old".into()), None);
        gtd.insert_strict("x", "1.0.0", Some("new".into()), Some("s".into()));
        let b = gtd.trusted.get("x@1.0.0").unwrap();
        assert_eq!(b.integrity.as_deref(), Some("new"));
        assert_eq!(b.script_hash.as_deref(), Some("s"));
        assert_eq!(gtd.trusted.len(), 1);
    }

    #[test]
    fn remove_returns_true_when_entry_existed() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("x", "1.0.0", None, None);
        assert!(gtd.remove("x", "1.0.0"));
        assert!(gtd.trusted.is_empty());
    }

    #[test]
    fn remove_returns_false_for_missing_entry() {
        let mut gtd = GlobalTrustedDependencies::default();
        assert!(!gtd.remove("ghost", "1.0.0"));
    }

    #[test]
    fn read_malformed_json_returns_script_error_naming_path() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        std::fs::write(&path, b"not json {{{").unwrap();
        let err = read_at(&path).unwrap_err();
        assert!(
            err.to_string().contains("is malformed"),
            "error must name the malformed-json case: {err}"
        );
    }

    #[test]
    fn read_newer_schema_version_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        let future = serde_json::json!({
            "schema_version": SCHEMA_VERSION + 1,
            "trusted": {}
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&future).unwrap()).unwrap();
        let err = read_at(&path).unwrap_err();
        assert!(err.to_string().contains("newer lpm"));
    }

    /// Pre-existing file with no `trusted` field deserializes as empty
    /// via `serde(default)`. Protects against a future refactor that
    /// drops the attribute.
    #[test]
    fn read_file_without_trusted_field_deserializes_as_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        std::fs::write(&path, br#"{"schema_version": 1}"#).unwrap();
        let read = read_at(&path).unwrap();
        assert!(read.trusted.is_empty());
    }

    #[test]
    fn read_for_uses_global_trusted_deps_path() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        // Defaults to empty when the file doesn't exist.
        assert!(read_for(&root).unwrap().trusted.is_empty());

        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("x", "1.0.0", None, None);
        write_for(&root, &gtd).unwrap();

        let round_tripped = read_for(&root).unwrap();
        assert_eq!(round_tripped.trusted.len(), 1);
    }

    /// Silent use of unused field helper to suppress borrow-checker
    /// warning. `binding` is only used by the drift tests above —
    /// suppressing the "unused" warning for consistency.
    #[test]
    fn binding_helper_is_equivalent_to_manual_construction() {
        let a = binding(Some("i"), Some("s"));
        let b = TrustedDependencyBinding {
            integrity: Some("i".into()),
            script_hash: Some("s".into()),
        };
        assert_eq!(a, b);
    }
}
