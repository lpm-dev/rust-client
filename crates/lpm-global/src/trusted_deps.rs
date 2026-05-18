//! `~/.lpm/global/trusted-dependencies.json` storage.
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
//! One flat map keyed by `name@version`. The binding payload is
//! wire-identical to the project-level shape, but it is duplicated in
//! this crate so `lpm-global` does not depend on `lpm-workspace`.
//! `script_hash` and `integrity` are both optional because an older
//! `lpm approve-scripts` run may have approved a package before either
//! field was reliably available — strict-gate lookup in
//! [`GlobalTrustedDependencies::matches_strict`] degrades accordingly.
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
//! Trust is bound to a specific integrity +
//! script-hash of a specific version. Approving `esbuild@0.20.2`
//! doesn't automatically trust `esbuild@0.25.1` — the install pipeline
//! blocks the new version on the expected "re-review" path. Matches
//! the project-level model exactly.

use lpm_common::{LpmError, LpmRoot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Binding metadata for one entry in the global trusted-deps map.
///
/// Mirrors the subset of `lpm_workspace::TrustedDependencyBinding`
/// enforced on the global install path: `integrity`, `script_hash`,
/// and `provenance_at_approval` (which drives the install-time drift
/// gate via the synthetic `package.json > lpm > trustedDependencies`
/// projection in `install_global::synthesize_pkg_json`). The
/// project-only fields — `behavioral_tags_hash`, `behavioral_tags`,
/// `capability_hash` — are NOT yet captured here; revisit when the
/// matching gates extend to globals.
///
/// Duplicated rather than imported so `lpm-global` stays lower-layer
/// and can't accidentally pull in the broader workspace / manifest
/// dependency graph. The serde shape (field names + renames +
/// `skip_serializing_if`) is intentionally byte-compatible with the
/// project-level binding so a snapshot stored here deserializes into
/// the project-shape binding cleanly when the inner install pipeline
/// reads the synthetic package.json.
///
/// `ProvenanceSnapshot` lives in `lpm-common` (re-exported from
/// `lpm-workspace`) specifically so both bindings can share that
/// type without `lpm-global` needing to depend on `lpm-workspace`.
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
    /// Snapshot of the publisher identity tuple captured at the moment
    /// this binding was approved. The
    /// install-time drift gate compares this against the candidate
    /// version's freshly-fetched provenance to detect publisher drift
    /// across the approval boundary. `None` means the binding pre-dates
    /// provenance capture (legacy upgrade path) OR the approved version
    /// had no attestation; both cases degrade to "cannot detect drift"
    /// and the other strict-gate dimensions still fire on their own.
    ///
    /// Non-breaking via `#[serde(default, skip_serializing_if)]`:
    /// Older entries on disk that pre-date this field round-trip unchanged.
    #[serde(
        default,
        rename = "provenanceAtApproval",
        skip_serializing_if = "Option::is_none"
    )]
    pub provenance_at_approval: Option<lpm_common::ProvenanceSnapshot>,
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
    /// `lpm approve-scripts --global` to opt in.
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
    /// `(name, version)`. Used by `lpm approve-scripts --global`'s
    /// write path when the user approves a previously-blocked package.
    ///
    /// Both `integrity` and `script_hash` are optional because the
    /// blocked-set capture may have missed one (e.g. a registry
    /// response that lacked the SRI). Approving anyway is a deliberate
    /// user choice — the strict query degrades to drift-detection for
    /// any missing field pair.
    ///
    /// Legacy two-field shortcut for tests
    /// and any caller that genuinely doesn't want to capture provenance.
    /// Production `--global` write paths should use [`Self::insert_binding`]
    /// to persist a richer binding (including `provenance_at_approval`).
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
                provenance_at_approval: None,
            },
        );
    }

    /// Insert-or-overwrite a fully-populated trust binding. Used by
    /// `lpm approve-scripts --global` to persist `provenance_at_approval`
    /// alongside `integrity` and `script_hash` so the install-time
    /// drift gate has a reference snapshot to compare future versions
    /// against.
    pub fn insert_binding(&mut self, name: &str, version: &str, binding: TrustedDependencyBinding) {
        self.trusted.insert(rich_key(name, version), binding);
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

    /// Bulk-remove trust bindings. Returns the count of entries that
    /// were actually present and removed (entries that weren't in the
    /// map are silently skipped — idempotent).
    ///
    /// Used by the uninstall path's M76 trust-prune step + recovery's
    /// `roll_forward_uninstall` replay. Both consume an
    /// `uninstall_trust_prune: Vec<TrustPruneEntry>` set computed
    /// against the uninstalling install's reachable tree, and apply
    /// it via this helper for atomic transaction shape (one
    /// read-modify-write under `.tx.lock`).
    pub fn remove_many(&mut self, entries: &[(&str, &str)]) -> usize {
        let mut removed = 0usize;
        for (name, version) in entries {
            if self.remove(name, version) {
                removed += 1;
            }
        }
        removed
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
    // Windows long-path support — no-op on POSIX.
    let path = lpm_common::as_extended_path(path);
    let path = path.as_path();
    // Cap the read before any bytes are buffered. A bloated trust
    // file collapses to the same "missing state" shape callers
    // already handle (default empty list, recoverable from the
    // next `lpm approve-scripts --global` write).
    let bytes =
        match lpm_common::read_capped_state_file(path, lpm_common::STATE_FILE_SIZE_CAP_BYTES) {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(GlobalTrustedDependencies::default()),
            Err(e) => return Err(LpmError::Io(e)),
        };
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

/// Write atomically. Serialized body is pretty-printed with a
/// trailing newline for diffability — an operator doing `git log -p`
/// on a checked-in `.lpm/global/` will see clean JSON diffs.
pub fn write_for(root: &LpmRoot, value: &GlobalTrustedDependencies) -> Result<(), LpmError> {
    write_at(&root.global_trusted_deps(), value)
}

pub fn write_at(path: &Path, value: &GlobalTrustedDependencies) -> Result<(), LpmError> {
    // Windows long-path support — no-op on POSIX.
    let path = lpm_common::as_extended_path(path);
    let path = path.as_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut body = serde_json::to_string_pretty(value)
        .map_err(|e| LpmError::Script(format!("serialize trusted-deps: {e}")))?;
    body.push('\n');
    // Per-pid tmp suffix avoids racing concurrent lpm invocations on
    // the same trust file; the parent .tx.lock serializes the
    // logical write, but a crashed prior run could leave a stale
    // `*.json.tmp` and the next start should not be tripped by it.
    let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let tmp_path = lpm_common::as_extended_path(&tmp_path);
    let mut open_opts = fs::OpenOptions::new();
    open_opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The file lists private package names/versions plus
        // approval hashes/provenance and drives lifecycle-script
        // authorization. Owner-only matches the broader credential-
        // metadata posture; it must not land world-readable on
        // permissive umasks.
        open_opts.mode(0o600);
    }
    {
        let mut f = open_opts.open(&tmp_path).map_err(LpmError::Io)?;
        f.write_all(body.as_bytes()).map_err(LpmError::Io)?;
        f.sync_all().map_err(LpmError::Io)?;
    }
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
            provenance_at_approval: None,
        }
    }

    fn provenance_snap(publisher: &str, workflow_path: &str) -> lpm_common::ProvenanceSnapshot {
        lpm_common::ProvenanceSnapshot {
            present: true,
            publisher: Some(publisher.into()),
            workflow_path: Some(workflow_path.into()),
            workflow_ref: Some("refs/tags/v1.0.0".into()),
            attestation_cert_sha256: Some("sha256-cert".into()),
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
    /// trust 0.25.2. Pins the version-bound trust model for
    /// the global analogue.
    #[test]
    fn matches_strict_version_bound_does_not_leak_across_versions() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("esbuild", "0.25.1", Some("a".into()), Some("b".into()));
        let m = gtd.matches_strict("esbuild", "0.25.2", Some("a"), Some("b"));
        assert_eq!(m, TrustMatch::NotTrusted);
    }

    /// Missing stored integrity counts as drift against a queried
    /// present value. The pre-schema-aware approval case: we
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

    /// M76: bulk-prune helper drops only the listed entries and
    /// returns the count actually removed. Pin both the selectivity
    /// (other entries survive) and the count contract so the
    /// uninstall envelope's `trust_entries_pruned` field stays
    /// honest.
    #[test]
    fn remove_many_drops_only_listed_entries_returns_count() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("a", "1.0.0", None, None);
        gtd.insert_strict("b", "2.0.0", None, None);
        gtd.insert_strict("c", "3.0.0", None, None);
        let removed = gtd.remove_many(&[("a", "1.0.0"), ("c", "3.0.0")]);
        assert_eq!(removed, 2);
        assert!(!gtd.trusted.contains_key("a@1.0.0"));
        assert!(gtd.trusted.contains_key("b@2.0.0"));
        assert!(!gtd.trusted.contains_key("c@3.0.0"));
    }

    /// M76: recovery may replay the prune after a successful
    /// in-tx prune; the second invocation must be a no-op (count = 0)
    /// rather than an error. Same shape as the existing
    /// [`Self::remove`] idempotency contract.
    #[test]
    fn remove_many_is_idempotent_for_absent_entries() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("a", "1.0.0", None, None);
        // First call drops the present entry.
        assert_eq!(gtd.remove_many(&[("a", "1.0.0"), ("ghost", "9.9.9")]), 1);
        // Second call finds nothing — returns 0, doesn't error.
        assert_eq!(gtd.remove_many(&[("a", "1.0.0"), ("ghost", "9.9.9")]), 0);
        assert!(gtd.trusted.is_empty());
    }

    /// M76: empty input must be safe (no-op, count = 0). Recovery's
    /// replay path passes whatever the Intent stored, which is empty
    /// for installs and upgrades — the common case must not panic.
    #[test]
    fn remove_many_empty_input_returns_zero() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("a", "1.0.0", None, None);
        assert_eq!(gtd.remove_many(&[]), 0);
        assert_eq!(gtd.trusted.len(), 1);
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
            provenance_at_approval: None,
        };
        assert_eq!(a, b);
    }

    // ── provenance_at_approval round-trip + insert_binding ──

    /// A binding with a full provenance snapshot must round-trip
    /// through the on-disk JSON unchanged. Drives the drift gate via
    /// `synthesize_pkg_json`'s `serde_json::to_value(binding)`.
    #[test]
    fn round_trip_preserves_provenance_at_approval() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_binding(
            "esbuild",
            "0.25.1",
            TrustedDependencyBinding {
                integrity: Some("sha512-e".into()),
                script_hash: Some("sha256-s".into()),
                provenance_at_approval: Some(provenance_snap(
                    "github:evanw/esbuild",
                    ".github/workflows/release.yml",
                )),
            },
        );
        write_at(&path, &gtd).unwrap();
        let read = read_at(&path).unwrap();
        assert_eq!(read, gtd);
        let snap = read.trusted["esbuild@0.25.1"]
            .provenance_at_approval
            .as_ref()
            .expect("provenance must round-trip");
        assert_eq!(snap.publisher.as_deref(), Some("github:evanw/esbuild"));
    }

    /// Pre-Phase-68 entries on disk (no `provenanceAtApproval` field)
    /// must deserialize cleanly with `provenance_at_approval = None`.
    /// Additive `serde(default)` is the load-bearing guarantee here.
    #[test]
    fn read_old_schema_without_provenance_defaults_to_none() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        let body = r#"{
            "schema_version": 1,
            "trusted": {
                "esbuild@0.25.1": {
                    "integrity": "sha512-e",
                    "scriptHash": "sha256-s"
                }
            }
        }"#;
        std::fs::write(&path, body).unwrap();
        let read = read_at(&path).unwrap();
        let bind = &read.trusted["esbuild@0.25.1"];
        assert_eq!(bind.integrity.as_deref(), Some("sha512-e"));
        assert_eq!(bind.script_hash.as_deref(), Some("sha256-s"));
        assert!(bind.provenance_at_approval.is_none());
    }

    /// `insert_binding` is the new write API for paths that capture
    /// provenance. Asserts overwrite semantics + that the rich
    /// binding survives.
    #[test]
    fn insert_binding_stores_rich_binding_and_overwrites() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_binding(
            "esbuild",
            "0.25.1",
            TrustedDependencyBinding {
                integrity: Some("sha512-old".into()),
                script_hash: None,
                provenance_at_approval: None,
            },
        );
        let new = TrustedDependencyBinding {
            integrity: Some("sha512-new".into()),
            script_hash: Some("sha256-s".into()),
            provenance_at_approval: Some(provenance_snap(
                "github:evanw/esbuild",
                ".github/workflows/release.yml",
            )),
        };
        gtd.insert_binding("esbuild", "0.25.1", new.clone());
        assert_eq!(gtd.trusted.len(), 1);
        assert_eq!(gtd.trusted["esbuild@0.25.1"], new);
    }

    /// `matches_strict` is the aggregate-filter query and the post-
    /// install-banner query. Neither consumes `provenance_at_approval`
    /// — drift comparison happens against the project-shape binding
    /// inside the inner install pipeline. Pin that contract: two
    /// otherwise-identical bindings that differ only in
    /// `provenance_at_approval` must both report `Strict`.
    #[test]
    fn matches_strict_ignores_provenance_at_approval() {
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_binding(
            "esbuild",
            "0.25.1",
            TrustedDependencyBinding {
                integrity: Some("sha512-e".into()),
                script_hash: Some("sha256-s".into()),
                provenance_at_approval: Some(provenance_snap(
                    "github:evanw/esbuild",
                    ".github/workflows/release.yml",
                )),
            },
        );
        let m = gtd.matches_strict("esbuild", "0.25.1", Some("sha512-e"), Some("sha256-s"));
        assert_eq!(m, TrustMatch::Strict);
    }

    /// A bloated `trusted-dependencies.json` must collapse to the
    /// default-empty trust list without buffering or parsing the
    /// payload. Matches the "missing state" fall-through that other
    /// callers of `read_capped_state_file` rely on.
    #[test]
    fn read_over_cap_file_returns_default_empty_trust_list() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        // Cap is 16 MB; write 17 MB of zeros so the cap fires.
        let body = vec![
            b'x';
            (lpm_common::STATE_FILE_SIZE_CAP_BYTES as usize).saturating_add(1024 * 1024)
        ];
        std::fs::write(&path, &body).unwrap();
        let read = read_at(&path).expect("over-cap must not be an error");
        assert_eq!(read, GlobalTrustedDependencies::default());
    }

    /// The trust file lists private package names + approval hashes
    /// and drives lifecycle-script authorization. Owner-only perms
    /// keep it from leaking what global packages a user has trusted
    /// on a shared host.
    #[cfg(unix)]
    #[test]
    fn write_creates_file_with_0o600_perms() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict(
            "x",
            "1.0.0",
            Some("sha512-e".into()),
            Some("sha256-s".into()),
        );
        write_at(&path, &gtd).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
    }

    /// Successful writes must not leave a `*.json.tmp.<pid>` straggler
    /// behind. Pins the rename-then-clean-up contract and guards
    /// against a future refactor that breaks the same-FS rename arm.
    #[test]
    fn write_leaves_no_tempfile_on_success() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FILENAME);
        let mut gtd = GlobalTrustedDependencies::default();
        gtd.insert_strict("x", "1.0.0", None, None);
        write_at(&path, &gtd).unwrap();
        let prefix = format!("{FILENAME}.tmp.");
        let leaks: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .collect();
        assert!(leaks.is_empty(), "tempfile leaked: {leaks:?}");
    }
}
