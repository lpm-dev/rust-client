//! Translate `package.json > pnpm.patchedDependencies`
//! into LPM's native `patches/` directory + `lpm.patchedDependencies`
//! manifest entries at migrate time.
//!
//! Mirrors the override migration design (see [`super::migrate_overrides`])
//! with two extra concerns specific to patches:
//!
//! 1. **Integrity binding** — LPM's `lpm.patchedDependencies[k]` carries
//!    `originalIntegrity` (the SRI of the store tarball the patch was
//!    authored against). pnpm's manifest doesn't store this. We resolve
//!    it from the just-migrated lockfile and **fail-hard** on any miss
//!    (package not in lockfile, or lockfile entry has no integrity).
//!    No partial conversion of security-sensitive metadata.
//!
//! 2. **Patch source path containment** — the value of each
//!    `pnpm.patchedDependencies[k]` is a user-authored path string. We
//!    reuse `resolve_manifest_path` (4-rule check: absolute / `..` /
//!    nearest-ancestor canonicalize / starts_with project root)
//!    and add patch-source-specific rejections on top: empty /
//!    whitespace-only values, paths whose target is a directory, paths
//!    whose source file is missing on disk.
//!
//! ## Plan classification
//!
//! Every entry in `pnpm.patchedDependencies` lands in exactly one bucket:
//!
//! - `to_apply` — clean: resolved source, integrity from lockfile, no
//!   conflict with existing `lpm.patchedDependencies`.
//! - `conflicts` — same key in `lpm.patchedDependencies` with a different
//!   effective `path`. Same key + same path is idempotent (skipped).
//! - `parse_errors` — key isn't `name@version`-shaped after cleaning any
//!   pnpm v9 peer-suffix.
//! - `unsupported_shapes` — value isn't a string (object / array / null /
//!   number).
//! - `path_violations` — empty / whitespace / `..` / absolute / symlink
//!   escape / directory target / source missing.
//! - `integrity_misses` — lockfile lookup failure or `integrity = None`.
//!
//! Any non-`to_apply` bucket being non-empty makes
//! [`PnpmPatchesPlan::has_blocking_errors`] true, and the migrate
//! handler MUST abort before any backup or filesystem mutation.
//!
//! ## Source-equals-destination
//!
//! If the user already used LPM's canonical naming
//! (`patches/<safe_key>.patch`) as their pnpm value, the source and
//! destination resolve to the same canonical path. The translation is
//! a validated no-op: no copy is performed, the manifest entry is
//! still written.

use lpm_common::LpmError;
use lpm_lockfile::Lockfile;
use lpm_migrate::backup::resolve_manifest_path;
use lpm_migrate::pnpm::clean_pnpm_key;
use lpm_workspace::PackageJson;
use std::path::{Path, PathBuf};

/// Outcome of analyzing `package.json > pnpm.patchedDependencies`
/// against the project's existing LPM-side patches and the just-migrated
/// lockfile. The migrate handler reads this BEFORE the first file
/// mutation.
#[derive(Debug, Default)]
pub struct PnpmPatchesPlan {
    pub to_apply: Vec<PatchTranslation>,
    pub conflicts: Vec<PatchConflict>,
    pub parse_errors: Vec<KeyParseError>,
    pub unsupported_shapes: Vec<UnsupportedShape>,
    pub path_violations: Vec<PathViolation>,
    pub integrity_misses: Vec<IntegrityMiss>,
}

/// One ready-to-apply patch translation. The migrate handler copies
/// `src_absolute` to `dest_absolute` (or skips when `is_self_copy`),
/// then writes the `lpm.patchedDependencies[<lpm_key>]` entry.
#[derive(Debug, Clone)]
pub struct PatchTranslation {
    /// LPM-side key (cleaned of pnpm v9 peer-suffix). What gets written
    /// to `lpm.patchedDependencies`.
    pub lpm_key: String,
    /// The original key as it appeared in `pnpm.patchedDependencies`
    /// (preserves any pnpm v9 peer-suffix the user authored). The
    /// migrate handler uses this to look up the corresponding entry in
    /// the live `pnpm.patchedDependencies` map for the post-translate
    /// path rewrite — see `apply_patches` in `commands::migrate`.
    pub pnpm_key: String,
    /// Verbatim path string from `pnpm.patchedDependencies[k]`. Read
    /// today only by tests; future renderers can use it to show the
    /// user "we translated `<src_relative>` → `<dest_relative>`."
    #[allow(dead_code)]
    pub src_relative: String,
    /// Absolute, canonicalized source path.
    pub src_absolute: PathBuf,
    /// LPM's canonical destination relative to the project root —
    /// `patches/<safe_key>.patch` where `safe_key = lpm_key.replace('/', "__")`.
    pub dest_relative: String,
    /// Absolute destination (may not exist yet).
    pub dest_absolute: PathBuf,
    /// SRI integrity hash from the migrated lockfile — written to the
    /// `originalIntegrity` field on the LPM manifest entry.
    pub integrity: String,
    /// True iff source and destination resolve to the same canonical
    /// path. The migrate handler skips the copy in this case (and the
    /// destination is NOT added to the backup chain — there's no write
    /// to undo).
    pub is_self_copy: bool,
    /// True iff the destination patch file already exists pre-migration.
    /// The migrate handler adds this path to the backup chain so a
    /// rollback restores its original content. Always false when
    /// `is_self_copy` is true.
    pub dest_pre_exists: bool,
}

/// `pnpm.patchedDependencies[key] = pnpm_dest_path` collides with
/// `lpm.patchedDependencies[key].path = lpm_path` where the two paths
/// disagree on effective destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchConflict {
    pub key: String,
    pub pnpm_dest: String,
    pub lpm_path: String,
}

/// `pnpm.patchedDependencies` key isn't `name@version`-shaped (after
/// cleaning any pnpm v9 peer-suffix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyParseError {
    pub key: String,
    pub reason: &'static str,
}

/// Value at `pnpm.patchedDependencies[k]` isn't a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedShape {
    pub key: String,
    pub got: &'static str,
}

/// Patch source path failed safety / shape validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathViolation {
    pub key: String,
    pub raw_value: String,
    pub kind: PathViolationKind,
    /// Detail line from the underlying validator (containment helper
    /// or this module's empty / directory checks).
    pub detail: String,
}

/// Why a patch source path was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathViolationKind {
    /// Empty or whitespace-only value.
    Empty,
    /// Absolute path (`/foo` on Unix, `C:\foo` on Windows).
    Absolute,
    /// Path contains a `..` component.
    ParentDir,
    /// Path resolves outside the project root via a symlinked ancestor.
    SymlinkEscape,
    /// Source file doesn't exist on disk.
    MissingSource,
    /// Source path resolves to a directory rather than a file.
    DirectoryTarget,
}

/// Couldn't bind the patched dependency to a tarball integrity hash.
/// Always blocking — the LPM patch engine re-verifies this on every
/// install, and a missing or mismatched hash is a hard install error
/// (see `lpm.patchedDependencies` docs in `lpm-workspace`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityMiss {
    pub key: String,
    pub name: String,
    pub version: String,
    pub reason: IntegrityMissReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityMissReason {
    /// `(name, version)` not present in the migrated lockfile.
    NotInLockfile,
    /// Lockfile entry exists but its `integrity` field is `None` (e.g.
    /// the source manifest used a workspace link or git dep).
    LockfileMissingIntegrity,
}

impl PnpmPatchesPlan {
    /// True iff anything in this plan should fail the migration before
    /// any disk mutation. All non-`to_apply` buckets are blocking.
    pub fn has_blocking_errors(&self) -> bool {
        !self.conflicts.is_empty()
            || !self.parse_errors.is_empty()
            || !self.unsupported_shapes.is_empty()
            || !self.path_violations.is_empty()
            || !self.integrity_misses.is_empty()
    }

    /// True iff there are translations to apply after validation passed.
    pub fn has_entries(&self) -> bool {
        !self.to_apply.is_empty()
    }

    /// True iff there is nothing to translate AND no errors.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.to_apply.is_empty()
            && self.conflicts.is_empty()
            && self.parse_errors.is_empty()
            && self.unsupported_shapes.is_empty()
            && self.path_violations.is_empty()
            && self.integrity_misses.is_empty()
    }
}

/// Build the patch-translation plan from a parsed `PackageJson` and
/// the migrated lockfile. Pure: reads in-memory structs and the
/// filesystem (only via `Path::exists` / `canonicalize` — never writes).
///
/// Returns an `LpmError` only when `pnpm.patchedDependencies` itself has
/// a fundamentally wrong shape (e.g., it's an array instead of an
/// object). Per-entry problems are non-fatal at the plan-construction
/// layer — they're surfaced as blocking errors via the plan's bucket
/// fields so the caller can render every problem together.
pub fn build_plan(
    pkg: &PackageJson,
    project_dir: &Path,
    lockfile: &Lockfile,
) -> Result<PnpmPatchesPlan, LpmError> {
    let pnpm = match pkg.pnpm.as_ref() {
        Some(p) => p,
        None => return Ok(PnpmPatchesPlan::default()),
    };

    if pnpm.patched_dependencies.is_null() {
        return Ok(PnpmPatchesPlan::default());
    }

    let entries = pnpm.patched_dependencies.as_object().ok_or_else(|| {
        LpmError::Script(format!(
            "package.json > pnpm.patchedDependencies must be an object, got {}",
            json_kind(&pnpm.patched_dependencies)
        ))
    })?;

    let lpm_patches = pkg
        .lpm
        .as_ref()
        .map(|l| &l.patched_dependencies)
        .cloned()
        .unwrap_or_default();

    let mut plan = PnpmPatchesPlan::default();

    for (raw_key, value) in entries {
        // ── Shape ────────────────────────────────────────────────
        let raw_value = match value.as_str() {
            Some(s) => s,
            None => {
                plan.unsupported_shapes.push(UnsupportedShape {
                    key: raw_key.clone(),
                    got: json_kind(value),
                });
                continue;
            }
        };

        // ── Patch-source path validation (stricter than
        //    `resolve_manifest_path`'s rollback-target rules).
        let trimmed = raw_value.trim();
        if trimmed.is_empty() {
            plan.path_violations.push(PathViolation {
                key: raw_key.clone(),
                raw_value: raw_value.to_string(),
                kind: PathViolationKind::Empty,
                detail: "value is empty or whitespace-only".to_string(),
            });
            continue;
        }

        // ── Containment (delegates to the manifest-path helper). ─────────
        let src_absolute = match resolve_manifest_path(project_dir, trimmed) {
            Ok(p) => p,
            Err(e) => {
                let msg = format!("{e}");
                let kind = if msg.contains("absolute path") {
                    PathViolationKind::Absolute
                } else if msg.contains("`..`") {
                    PathViolationKind::ParentDir
                } else {
                    PathViolationKind::SymlinkEscape
                };
                plan.path_violations.push(PathViolation {
                    key: raw_key.clone(),
                    raw_value: raw_value.to_string(),
                    kind,
                    detail: msg,
                });
                continue;
            }
        };

        if !src_absolute.exists() {
            plan.path_violations.push(PathViolation {
                key: raw_key.clone(),
                raw_value: raw_value.to_string(),
                kind: PathViolationKind::MissingSource,
                detail: format!("source patch file not found at `{trimmed}`"),
            });
            continue;
        }

        if src_absolute.is_dir() {
            plan.path_violations.push(PathViolation {
                key: raw_key.clone(),
                raw_value: raw_value.to_string(),
                kind: PathViolationKind::DirectoryTarget,
                detail: format!("`{trimmed}` resolves to a directory, not a file"),
            });
            continue;
        }

        // ── Key parse + integrity lookup ─────────────────────────
        let cleaned_key = clean_pnpm_key(raw_key).to_string();
        let (name, version) = match split_name_version(&cleaned_key) {
            Some(pair) => pair,
            None => {
                plan.parse_errors.push(KeyParseError {
                    key: raw_key.clone(),
                    reason: "key is not `name@version`-shaped",
                });
                continue;
            }
        };

        let integrity = match lookup_integrity(lockfile, &name, &version) {
            IntegrityLookup::Found(integrity) => integrity,
            IntegrityLookup::NotInLockfile => {
                plan.integrity_misses.push(IntegrityMiss {
                    key: raw_key.clone(),
                    name,
                    version,
                    reason: IntegrityMissReason::NotInLockfile,
                });
                continue;
            }
            IntegrityLookup::NoIntegrity => {
                plan.integrity_misses.push(IntegrityMiss {
                    key: raw_key.clone(),
                    name,
                    version,
                    reason: IntegrityMissReason::LockfileMissingIntegrity,
                });
                continue;
            }
        };

        // ── Destination resolution + self-copy / pre-exists flags ─
        let safe_key = cleaned_key.replace('/', "__");
        let dest_relative = format!("patches/{safe_key}.patch");
        let dest_absolute = project_dir.join(&dest_relative);

        let is_self_copy = same_canonical_path(&src_absolute, &dest_absolute);
        let dest_pre_exists = !is_self_copy && dest_absolute.exists();

        // ── Conflict with existing lpm.patchedDependencies ──────
        if let Some(existing) = lpm_patches.get(&cleaned_key) {
            if existing.path == dest_relative {
                // Same key + same path = idempotent. Skip — don't add
                // to to_apply, don't flag as a conflict.
                continue;
            }
            plan.conflicts.push(PatchConflict {
                key: cleaned_key,
                pnpm_dest: dest_relative,
                lpm_path: existing.path.clone(),
            });
            continue;
        }

        plan.to_apply.push(PatchTranslation {
            lpm_key: cleaned_key,
            pnpm_key: raw_key.clone(),
            src_relative: raw_value.to_string(),
            src_absolute,
            dest_relative,
            dest_absolute,
            integrity,
            is_self_copy,
            dest_pre_exists,
        });
    }

    Ok(plan)
}

// ── Helpers ────────────────────────────────────────────────────────

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Split `name@version` at the LAST `@` that isn't position 0 (handles
/// scoped names like `@scope/foo@1.0.0` correctly).
fn split_name_version(key: &str) -> Option<(String, String)> {
    let at_pos = key
        .char_indices()
        .rev()
        .find(|&(i, c)| c == '@' && i > 0)
        .map(|(i, _)| i)?;
    let (name, rest) = key.split_at(at_pos);
    let version = &rest[1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

enum IntegrityLookup {
    Found(String),
    NotInLockfile,
    NoIntegrity,
}

fn lookup_integrity(lockfile: &Lockfile, name: &str, version: &str) -> IntegrityLookup {
    let entry = lockfile
        .packages
        .iter()
        .find(|p| p.name == name && p.version == version);
    match entry {
        None => IntegrityLookup::NotInLockfile,
        Some(p) => match p.integrity.as_deref() {
            Some(i) if !i.is_empty() => IntegrityLookup::Found(i.to_string()),
            _ => IntegrityLookup::NoIntegrity,
        },
    }
}

/// True iff `a` and `b` canonicalize to the same path. If either fails
/// to canonicalize (typically because it doesn't exist), falls back to
/// literal-path equality — safe because the caller already verified
/// `a` exists, so the only way this fires the fallback is when `b`
/// (the destination) doesn't exist yet, in which case literal equality
/// against a non-existent path is fine: it means "they would resolve
/// to the same place if the dest were created."
fn same_canonical_path(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_lockfile::{LockedPackage, Lockfile, LockfileMetadata};

    fn pkg_from(json: &str) -> PackageJson {
        serde_json::from_str(json).expect("test package.json must parse")
    }

    fn lockfile_with(packages: &[(&str, &str, Option<&str>)]) -> Lockfile {
        Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: 1,
                resolved_with: Some("test".to_string()),
                auto_isolated_peer_conflicts: false,
            },
            importers: lpm_lockfile::ImporterSnapshots::new(),
            patches: lpm_lockfile::LockfilePatches::new(),
            catalogs: lpm_lockfile::CatalogSnapshots::new(),
            packages: packages
                .iter()
                .map(|(n, v, integ)| LockedPackage {
                    name: n.to_string(),
                    version: v.to_string(),
                    integrity: integ.map(String::from),
                    ..Default::default()
                })
                .collect(),
            root_aliases: std::collections::BTreeMap::new(),
            ambient_peer_installs: Vec::new(),
        }
    }

    /// Helper: create a temp project dir with `patches/<file>` already
    /// in place so the path-validation passes. Returns the tempdir
    /// (must outlive the test) plus the path.
    fn with_patch_file(content: &str, rel_path: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(rel_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        (dir, path)
    }

    #[test]
    fn build_plan_empty_when_no_pnpm_block() {
        let pkg = pkg_from(r#"{"name": "x"}"#);
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn build_plan_empty_when_no_patched_deps_field() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": { "overrides": {} }
            }"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn build_plan_top_level_patched_deps_array_is_hard_error() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": { "patchedDependencies": ["nope"] }
            }"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with(&[]);
        let err = build_plan(&pkg, dir.path(), &lf).unwrap_err();
        assert!(format!("{err}").contains("must be an object"));
    }

    #[test]
    fn build_plan_translates_clean_entry() {
        let (dir, _) = with_patch_file("diff --git a/x b/y", "patches/react@18.0.0.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": {
                    "react@18.0.0": "patches/react@18.0.0.patch"
                }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[("react", "18.0.0", Some("sha512-abc"))]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.to_apply.len(), 1);
        let t = &plan.to_apply[0];
        assert_eq!(t.lpm_key, "react@18.0.0");
        assert_eq!(t.dest_relative, "patches/react@18.0.0.patch");
        assert_eq!(t.integrity, "sha512-abc");
        assert!(t.is_self_copy, "src already at canonical dest is self-copy");
        assert!(
            !t.dest_pre_exists,
            "self-copy must not flag dest_pre_exists"
        );
        assert!(!plan.has_blocking_errors());
    }

    #[test]
    fn build_plan_translates_scoped_package_key() {
        let (dir, _) = with_patch_file("diff", "vendor/scoped.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": {
                    "@babel/core@7.24.0": "vendor/scoped.patch"
                }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[("@babel/core", "7.24.0", Some("sha512-babel"))]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.to_apply.len(), 1);
        let t = &plan.to_apply[0];
        assert_eq!(t.lpm_key, "@babel/core@7.24.0");
        assert_eq!(t.dest_relative, "patches/@babel__core@7.24.0.patch");
        assert!(!t.is_self_copy);
    }

    #[test]
    fn build_plan_handles_peer_suffix_in_pnpm_key() {
        let (dir, _) = with_patch_file("diff", "patches/r.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": {
                    "react@18.0.0(scheduler@0.23.0)": "patches/r.patch"
                }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[("react", "18.0.0", Some("sha512-x"))]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.to_apply.len(), 1);
        let t = &plan.to_apply[0];
        assert_eq!(t.lpm_key, "react@18.0.0", "peer-suffix must be stripped");
        assert_eq!(t.pnpm_key, "react@18.0.0(scheduler@0.23.0)");
    }

    #[test]
    fn build_plan_idempotent_when_lpm_already_has_same_path() {
        let (dir, _) = with_patch_file("diff", "patches/react@18.0.0.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": { "react@18.0.0": "patches/react@18.0.0.patch" }
            },
            "lpm": {
                "patchedDependencies": {
                    "react@18.0.0": {
                        "path": "patches/react@18.0.0.patch",
                        "originalIntegrity": "sha512-abc"
                    }
                }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[("react", "18.0.0", Some("sha512-abc"))]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert!(
            plan.is_empty(),
            "idempotent merge should produce empty plan"
        );
    }

    #[test]
    fn build_plan_flags_conflict_on_diff_path() {
        let (dir, _) = with_patch_file("diff", "patches/react@18.0.0.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": { "react@18.0.0": "patches/react@18.0.0.patch" }
            },
            "lpm": {
                "patchedDependencies": {
                    "react@18.0.0": {
                        "path": "vendor/different.patch",
                        "originalIntegrity": "sha512-abc"
                    }
                }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[("react", "18.0.0", Some("sha512-abc"))]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert!(plan.has_blocking_errors());
        assert_eq!(plan.conflicts.len(), 1);
        let c = &plan.conflicts[0];
        assert_eq!(c.key, "react@18.0.0");
        assert_eq!(c.pnpm_dest, "patches/react@18.0.0.patch");
        assert_eq!(c.lpm_path, "vendor/different.patch");
    }

    #[test]
    fn build_plan_rejects_object_value_shape() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": {
                        "react@18.0.0": { "path": "patches/x.patch" }
                    }
                }
            }"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.unsupported_shapes.len(), 1);
        assert_eq!(plan.unsupported_shapes[0].got, "object");
    }

    #[test]
    fn build_plan_rejects_array_null_number_shapes() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": {
                        "a@1.0.0": [],
                        "b@1.0.0": null,
                        "c@1.0.0": 4
                    }
                }
            }"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        let kinds: Vec<&'static str> = plan.unsupported_shapes.iter().map(|s| s.got).collect();
        assert!(kinds.contains(&"array"));
        assert!(kinds.contains(&"null"));
        assert!(kinds.contains(&"number"));
    }

    #[test]
    fn build_plan_rejects_empty_string_value() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": { "react@18.0.0": "" }
                }
            }"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.path_violations.len(), 1);
        assert_eq!(plan.path_violations[0].kind, PathViolationKind::Empty);
    }

    #[test]
    fn build_plan_rejects_whitespace_only_value() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": { "react@18.0.0": "   \t  " }
                }
            }"#,
        );
        let dir = tempfile::tempdir().unwrap();
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.path_violations.len(), 1);
        assert_eq!(plan.path_violations[0].kind, PathViolationKind::Empty);
    }

    #[test]
    fn build_plan_rejects_directory_target() {
        // Set up a project dir with a `patches/` directory but the
        // pnpm value points AT the directory instead of a file.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("patches")).unwrap();

        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": { "react@18.0.0": "patches" }
                }
            }"#,
        );
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.path_violations.len(), 1);
        assert_eq!(
            plan.path_violations[0].kind,
            PathViolationKind::DirectoryTarget
        );
    }

    #[test]
    fn build_plan_rejects_missing_source_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("patches")).unwrap();

        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": { "react@18.0.0": "patches/missing.patch" }
                }
            }"#,
        );
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.path_violations.len(), 1);
        assert_eq!(
            plan.path_violations[0].kind,
            PathViolationKind::MissingSource
        );
    }

    #[test]
    fn build_plan_rejects_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": { "react@18.0.0": "/etc/passwd" }
                }
            }"#,
        );
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.path_violations.len(), 1);
        assert_eq!(plan.path_violations[0].kind, PathViolationKind::Absolute);
    }

    #[test]
    fn build_plan_rejects_parent_dir_path() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": { "react@18.0.0": "../escape.patch" }
                }
            }"#,
        );
        let lf = lockfile_with(&[]);
        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.path_violations.len(), 1);
        assert_eq!(plan.path_violations[0].kind, PathViolationKind::ParentDir);
    }

    #[test]
    #[cfg(unix)]
    fn build_plan_rejects_symlinked_ancestor_for_existing_leaf() {
        // patches/ -> /tmp/outside ; the source file actually exists
        // inside outside/, but containment check rejects via canonicalize.
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("patches")).unwrap();
        std::fs::write(outside.path().join("react@18.0.0.patch"), "diff").unwrap();

        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "patchedDependencies": { "react@18.0.0": "patches/react@18.0.0.patch" }
                }
            }"#,
        );
        let lf = lockfile_with(&[("react", "18.0.0", Some("sha512-x"))]);

        let plan = build_plan(&pkg, project.path(), &lf).unwrap();
        assert_eq!(plan.path_violations.len(), 1);
        assert_eq!(
            plan.path_violations[0].kind,
            PathViolationKind::SymlinkEscape,
            "got {:?}",
            plan.path_violations[0]
        );
    }

    #[test]
    fn build_plan_rejects_missing_lockfile_entry() {
        let (dir, _) = with_patch_file("diff", "patches/x.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": { "ghost@1.0.0": "patches/x.patch" }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[]); // empty — ghost isn't here

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.integrity_misses.len(), 1);
        assert_eq!(
            plan.integrity_misses[0].reason,
            IntegrityMissReason::NotInLockfile
        );
    }

    #[test]
    fn build_plan_rejects_lockfile_entry_with_no_integrity() {
        let (dir, _) = with_patch_file("diff", "patches/x.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": { "linkdep@1.0.0": "patches/x.patch" }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        // Lockfile carries the entry but has no integrity hash — common
        // for workspace links / git deps that pnpm doesn't tarball.
        let lf = lockfile_with(&[("linkdep", "1.0.0", None)]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.integrity_misses.len(), 1);
        assert_eq!(
            plan.integrity_misses[0].reason,
            IntegrityMissReason::LockfileMissingIntegrity
        );
    }

    #[test]
    fn build_plan_unparseable_key_no_at() {
        let (dir, _) = with_patch_file("diff", "patches/x.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": { "no-at-sign-key": "patches/x.patch" }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.parse_errors.len(), 1);
        assert_eq!(plan.parse_errors[0].key, "no-at-sign-key");
    }

    #[test]
    fn build_plan_marks_dest_pre_exists_for_non_self_copy() {
        // Source is in vendor/, dest path patches/react@18.0.0.patch
        // already exists from a previous manual port. Plan must mark
        // this so the migrate handler adds the dest to the backup chain.
        let (dir, _) = with_patch_file("source diff", "vendor/react.patch");
        std::fs::create_dir_all(dir.path().join("patches")).unwrap();
        std::fs::write(
            dir.path().join("patches/react@18.0.0.patch"),
            "pre-existing content",
        )
        .unwrap();

        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": { "react@18.0.0": "vendor/react.patch" }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[("react", "18.0.0", Some("sha512-x"))]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.to_apply.len(), 1);
        let t = &plan.to_apply[0];
        assert!(!t.is_self_copy);
        assert!(
            t.dest_pre_exists,
            "dest_pre_exists must be true so migrate adds the path to backup chain"
        );
    }

    #[test]
    fn build_plan_self_copy_does_not_mark_dest_pre_exists() {
        // Source path === canonical dest path, AND it exists. The
        // is_self_copy flag wins; dest_pre_exists must be false because
        // the migrate handler won't write there (no backup needed).
        let (dir, _) = with_patch_file("diff", "patches/react@18.0.0.patch");

        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": { "react@18.0.0": "patches/react@18.0.0.patch" }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[("react", "18.0.0", Some("sha512-x"))]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.to_apply.len(), 1);
        assert!(plan.to_apply[0].is_self_copy);
        assert!(!plan.to_apply[0].dest_pre_exists);
    }

    #[test]
    fn build_plan_collects_multiple_errors_in_one_pass() {
        let (dir, _) = with_patch_file("diff", "patches/ok.patch");
        let pkg_json = r#"{
            "name": "x",
            "pnpm": {
                "patchedDependencies": {
                    "ok@1.0.0": "patches/ok.patch",
                    "bad-shape@1.0.0": { "version": "1.0.0" },
                    "no-at-key": "patches/ok.patch",
                    "absolute@1.0.0": "/etc/passwd",
                    "ghost@1.0.0": "patches/ok.patch"
                }
            }
        }"#;
        let pkg: PackageJson = serde_json::from_str(pkg_json).unwrap();
        let lf = lockfile_with(&[("ok", "1.0.0", Some("sha512-ok"))]);

        let plan = build_plan(&pkg, dir.path(), &lf).unwrap();
        assert_eq!(plan.to_apply.len(), 1);
        assert_eq!(plan.to_apply[0].lpm_key, "ok@1.0.0");
        assert_eq!(plan.unsupported_shapes.len(), 1);
        assert_eq!(plan.parse_errors.len(), 1);
        assert_eq!(plan.path_violations.len(), 1);
        assert_eq!(plan.integrity_misses.len(), 1);
        assert!(plan.has_blocking_errors());
    }
}
