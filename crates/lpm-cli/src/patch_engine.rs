//! **Phase 32 Phase 6 — `lpm patch` engine.**
//!
//! Patches are unified diffs (GNU patch format) generated from the
//! difference between a clean store copy of a package and a user-edited
//! staging copy. Apply runs against the linker's freshly-materialized
//! `node_modules` tree, with strict (no-fuzz) hunk matching and
//! integrity binding to the original store entry.
//!
//! ## Threats this engine defends against
//!
//! - **Store drift.** The patch declares an `originalIntegrity` SRI;
//!   if the store entry's `.integrity` no longer matches, the patch is
//!   refused with a clear error. The user must regenerate the patch
//!   against the new baseline.
//! - **Fuzzy hunks.** `diffy::apply` is used in strict mode (its
//!   default — fuzzy is opt-in). A hunk that doesn't match exactly is
//!   a hard failure.
//! - **Hardlink mutation.** On Linux, the linker hardlinks store files
//!   into `node_modules`, so writing the patched bytes directly would
//!   silently mutate the store. The apply path always `remove_file`s
//!   before writing to break the inode share.
//! - **Internal-file tampering.** The store contains LPM-internal
//!   sentinels (`.integrity`, `.lpm-security.json`) that the linker
//!   copies into `node_modules`. The patch engine never produces or
//!   accepts patches that mention these — `copy_store_to_staging` and
//!   `generate_patch` filter them out, and `apply_patch` defends in
//!   depth by erroring on any patch chunk that names them. Renames
//!   reject sentinel paths at both endpoints.
//! - **Renames.** Git-style `rename from`/`rename to` headers are
//!   recognized in both rename-only and rename+edit chunks. Renames
//!   bind to `originalIntegrity` via the whole-tree drift gate; no
//!   per-file old/new hash binding is needed (the whole-tree SRI
//!   trips on any divergence). LPM's own `generate_patch` still emits
//!   add+delete pairs rather than rename headers; this matters only
//!   when a git-aware tool (or hand-edited patch) is consumed.
//!
//! ## Why no fast-path skip
//!
//! `lpm install` runs the apply pass on every install, even on the
//! lockfile fast path. Reasons:
//! 1. The linker may have re-linked from a fresh hardlink (original
//!    bytes, not patched bytes).
//! 2. The linker may have skipped re-linking entirely (marker present)
//!    but a previous apply might have been rolled back.
//! 3. A user might `rm -rf node_modules/foo/...` between installs.
//!
//! Re-applying is safe because the apply step is byte-level idempotent:
//! every file write is preceded by a content comparison; if the
//! destination already matches the post-patch bytes, the write is
//! skipped. Costs one extra read per patched file per install — small
//! relative to linker work.

use diffy::Patch;
use lpm_common::LpmError;
use lpm_linker::MaterializedPackage;
use lpm_lockfile::{LockedPackage, Lockfile};
use lpm_store::PackageStore;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// Files written by LPM into the store directory itself, NOT part of
/// the upstream package tarball. The patch workflow filters them out
/// of staging copies, generated diffs, and apply targets so the user
/// can never accidentally include them in a patch.
///
/// If the store gains new internal sentinels in the future, add them
/// here AND ensure they live at the top level of the package directory
/// (the filter only matches the file basename at the top level).
///
/// See `crates/lpm-store/src/lib.rs` line 131 (`.integrity`) and
/// line 141 (`.lpm-security.json`).
pub const STORE_INTERNAL_FILES: &[&str] = &[".integrity", ".lpm-security.json"];

/// The breadcrumb file `lpm patch` writes at the staging-dir root so
/// `lpm patch-commit` can recover `(name, version, store_path)` without
/// re-parsing the staging dir. Always excluded from generated patches.
pub const STAGING_BREADCRUMB_FILE: &str = ".lpm-patch.json";

// ── Key parsing ───────────────────────────────────────────────────────

/// Parse a `lpm.patchedDependencies` key like `"lodash@4.17.21"` or
/// `"@types/node@20.10.0"` into `(name, version)`. **Persisted keys
/// are always exact pins** — the `lpm patch` author-time selector
/// resolves ranges and bare names to a concrete version BEFORE the
/// key is written. This parser enforces that invariant on read paths
/// (state file, install-time consumer, upgrade engine).
///
/// **Errors:**
/// - Empty input.
/// - Missing `@` separator.
/// - Empty name or version segment.
/// - Anything that isn't an exact `lpm_semver::Version` — range
///   syntax (`^4.0.0`, `4.x`), dist-tags (`latest`), wildcards, etc.
///   The author-time `parse_patch_selector` accepts those; this
///   parser does not.
pub fn parse_patch_key(key: &str) -> Result<(String, String), LpmError> {
    if key.is_empty() {
        return Err(LpmError::Script(
            "patch key is empty (expected `name@exact-version`)".into(),
        ));
    }
    let (name, version) = split_name_version(key)?;
    // Persisted keys must be exact pins. The `lpm patch` author-time
    // flow resolves any range / bare-name selector to an exact pin
    // before writing — so a non-exact value here means the manifest
    // was hand-edited or produced by an out-of-band tool.
    if lpm_semver::Version::parse(&version).is_err() {
        return Err(LpmError::Script(format!(
            "patch key {key:?} version {version:?} is not an exact pin; \
             `lpm.patchedDependencies` keys must be exact (e.g. `name@1.2.3`). \
             Author with `lpm patch {name}@<exact-version>`."
        )));
    }
    Ok((name, version))
}

/// Split `name@version` into `(name, version)`, validating both halves
/// are non-empty. Used by both [`parse_patch_key`] (persisted keys,
/// exact-pin only) and [`parse_patch_selector`] (CLI input, range or
/// dist-tag allowed).
fn split_name_version(key: &str) -> Result<(String, String), LpmError> {
    // Scoped names start with `@` and contain `/`. The version
    // separator is the LAST `@` in the key.
    let at = key.rfind('@').ok_or_else(|| {
        LpmError::Script(format!(
            "patch key {key:?} missing version separator — expected `name@version`"
        ))
    })?;
    if at == 0 {
        return Err(LpmError::Script(format!(
            "patch key {key:?} missing version segment after `@`"
        )));
    }
    let name = key[..at].to_string();
    let version = key[at + 1..].to_string();
    if name.is_empty() || version.is_empty() {
        return Err(LpmError::Script(format!(
            "patch key {key:?} has empty name or version segment"
        )));
    }
    Ok((name, version))
}

// ── Selector parsing (Slice A — CLI input) ────────────────────────────

/// A `lpm patch <selector>` CLI input, parsed but not yet resolved. The
/// author-time path accepts more shapes than the persisted-key parser
/// — bare names and ranges resolve to an exact pin from the project
/// lockfile, then the exact pin is written to `lpm.patchedDependencies`.
///
/// **What is NOT in scope:** dist-tags (`latest`, `next`, `beta`,
/// `canary`, `rc`, any pure-alphabetic version token). The selector
/// path never consults the registry; mapping `latest` to "any installed
/// version" would silently overload a registry contract. Dist-tags are
/// rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchSelector {
    /// Bare package name like `lodash` or `@types/node` — resolve from
    /// the project lockfile.
    BareName(String),
    /// Exact pin like `lodash@4.17.21` — already final.
    Exact { name: String, version: String },
    /// Semver range like `lodash@^4.0.0` or `lodash@4.x` — resolve
    /// against the lockfile.
    Range { name: String, range: String },
}

impl PatchSelector {
    pub fn name(&self) -> &str {
        match self {
            Self::BareName(name) => name,
            Self::Exact { name, .. } | Self::Range { name, .. } => name,
        }
    }
}

/// Parse a `lpm patch <input>` CLI argument. Accepts:
/// - Bare names: `lodash`, `@types/node` → [`PatchSelector::BareName`]
/// - Exact pins: `lodash@4.17.21`, `@types/node@20.10.0` →
///   [`PatchSelector::Exact`]
/// - Semver ranges: `lodash@^4.0.0`, `lodash@4.x`, `lodash@1 - 2`,
///   `lodash@1 || 2` → [`PatchSelector::Range`]
///
/// Rejects:
/// - Empty input
/// - Empty name or version segment
/// - Dist-tags: `latest`, `next`, `beta`, etc. → see `is_dist_tag`
///
/// `parse_patch_key` (the persisted-key parser) stays strict and only
/// accepts `Exact`-shape inputs.
pub fn parse_patch_selector(input: &str) -> Result<PatchSelector, LpmError> {
    if input.is_empty() {
        return Err(LpmError::Script(
            "patch selector is empty (expected `name`, `name@version`, or `name@range`)".into(),
        ));
    }
    // Bare name: no `@` separator, or a single leading `@` (scoped
    // name without version). We distinguish by checking whether
    // `rfind('@')` returns 0 (leading-only) or None (no `@` at all).
    let at = input.rfind('@');
    let bare = match at {
        None => true,
        Some(0) => true, // scoped name like "@types/node" without version
        Some(_) => false,
    };
    if bare {
        // Reject input that starts with `@` but has no slash — that's
        // a malformed scoped name.
        if input.starts_with('@') && !input.contains('/') {
            return Err(LpmError::Script(format!(
                "patch selector {input:?} is a malformed scoped name (expected `@scope/name`)"
            )));
        }
        return Ok(PatchSelector::BareName(input.to_string()));
    }
    let (name, version) = split_name_version(input)?;
    // Exact pin.
    if lpm_semver::Version::parse(&version).is_ok() {
        return Ok(PatchSelector::Exact { name, version });
    }
    // Semver range. `VersionReq::parse` accepts everything node-semver
    // accepts — including the syntaxes we list in the docstring.
    if lpm_semver::VersionReq::parse(&version).is_ok() {
        return Ok(PatchSelector::Range {
            name,
            range: version,
        });
    }
    // Neither — likely a dist-tag or malformed input.
    if is_dist_tag(&version) {
        return Err(LpmError::Script(format!(
            "patch selector {input:?} uses a dist-tag ({version:?}); \
             `lpm patch` does not consult the registry. \
             Use a version (`{name}@<version>`) or semver range (`{name}@^<version>`)."
        )));
    }
    Err(LpmError::Script(format!(
        "patch selector {input:?} has invalid version segment {version:?}; \
         expected a version, semver range, or bare name"
    )))
}

/// Is `v` a non-semver token like `latest`, `next`, `beta` that npm
/// treats as a dist-tag? Used by `parse_patch_selector` to produce a
/// clearer error than the generic "invalid version segment".
///
/// The well-known dist-tags from npm conventions plus a catch-all for
/// any pure-alphabetic token (since semver parsing would reject those
/// anyway).
fn is_dist_tag(v: &str) -> bool {
    if matches!(
        v,
        "latest" | "next" | "beta" | "canary" | "rc" | "alpha" | "dev" | "experimental"
    ) {
        return true;
    }
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphabetic() || c == '-' || c == '_')
}

/// Resolve a [`PatchSelector`] against the project lockfile, producing
/// the exact `(name, version)` that will be written as the persisted
/// key. Pure function — no I/O, no lock, no registry access.
///
/// Disambiguation rules (modeled on Bun's
/// `pkgInfoForNameAndVersion` but adapted for LPM's source-aware
/// lockfile):
///
/// - **0 matches** → user-facing "not installed" error pointing at
///   `lpm install <name>` as the next step.
/// - **1 match** → return its `(name, version)`.
/// - **N matches, all the same [`PackageKey`] triple** → the same
///   physical package is referenced from multiple dep edges (e.g., a
///   hoisted root + transitive duplicates). Return the shared version
///   silently — this is the legitimate "transitive duplicate" case.
/// - **N matches, distinct versions or distinct source_ids** →
///   list-and-exit. Print every `name@version` (with source URL when
///   it differs) and return an error pointing the user at a more
///   precise selector.
///
/// **Cross-source collisions are unrecoverable here.** A
/// `(name, version)` that appears under two distinct `source_id`s (e.g.
/// registry + tarball-URL — see [`PackageKey`] regression coverage at
/// `lpm-lockfile/src/lib.rs`'s
/// `find_package_by_key_disambiguates_cross_source_collisions`) is a
/// failure mode of the persisted-key shape (which is `name@version`
/// only, no `source_id` — see "Explicitly out of scope" in
/// `private/patch.md`). Rather than silently pick one side, refuse
/// with an explicit "this codebase has multiple sources for X" error.
///
/// Range selectors filter the candidate set by `lpm_semver::VersionReq::matches`
/// before disambiguation runs.
pub fn resolve_patch_selector(
    lockfile: &Lockfile,
    selector: &PatchSelector,
) -> Result<(String, String), LpmError> {
    let name = selector.name();
    let range_filter: Option<lpm_semver::VersionReq> = match selector {
        PatchSelector::Range { range, .. } => Some(
            lpm_semver::VersionReq::parse(range)
                .map_err(|e| LpmError::Script(format!("range {range:?} failed to parse: {e}")))?,
        ),
        _ => None,
    };

    // Collect every locked package matching the name (and the range,
    // if applicable). Preserve insertion order so the list-and-exit
    // output is deterministic (the lockfile is already sorted).
    let mut matches: Vec<&LockedPackage> = Vec::new();
    for pkg in &lockfile.packages {
        if pkg.name != name {
            continue;
        }
        if let Some(req) = &range_filter {
            let Ok(v) = lpm_semver::Version::parse(&pkg.version) else {
                continue;
            };
            if !req.matches(&v) {
                continue;
            }
        }
        matches.push(pkg);
    }

    match matches.len() {
        0 => {
            let detail = match selector {
                PatchSelector::Range { range, .. } => {
                    format!("no installed version of {name} matches {range:?}")
                }
                _ => format!("{name} is not installed in this project"),
            };
            Err(LpmError::Script(format!(
                "{detail}; run `lpm install {name}` first, or pass an exact pin"
            )))
        }
        1 => Ok((matches[0].name.clone(), matches[0].version.clone())),
        _ => {
            // Bucket by the full (name, version, source_id) triple.
            // If every match shares the SAME triple, this is the
            // legitimate transitive-duplicate case (one physical
            // package referenced from multiple dep edges).
            let first_key = matches[0].package_key();
            if matches.iter().all(|p| p.package_key() == first_key) {
                return Ok((matches[0].name.clone(), matches[0].version.clone()));
            }
            // Bucket by version to detect the "multiple versions" vs
            // "single version, multiple sources" failure modes.
            let mut by_version: BTreeMap<String, Vec<&LockedPackage>> = BTreeMap::new();
            for pkg in &matches {
                by_version.entry(pkg.version.clone()).or_default().push(pkg);
            }
            let multiple_versions = by_version.len() > 1;
            let mut listing = String::new();
            for (version, pkgs) in &by_version {
                if pkgs.len() == 1 {
                    listing.push_str(&format!("  - {name}@{version}\n"));
                } else {
                    // Same version, multiple sources — list each source
                    // explicitly so the user can act on it.
                    listing.push_str(&format!("  - {name}@{version} (multiple sources):\n"));
                    for pkg in pkgs {
                        let src = pkg.source.as_deref().unwrap_or("<unknown>");
                        listing.push_str(&format!("      {src}\n"));
                    }
                }
            }
            let hint = if multiple_versions {
                format!(
                    "specify a precise version: `lpm patch {name}@<version>` \
                     (or narrow with `lpm patch {name}@^<version>`)"
                )
            } else {
                // Single version under multiple sources — the persisted-
                // key shape can't distinguish them. Refuse rather than
                // silently pick one (see "Explicitly out of scope" in
                // private/patch.md).
                format!(
                    "this project has multiple sources for `{name}@{}`. \
                     `lpm.patchedDependencies` keys are `name@version` \
                     only and cannot distinguish sources — pin to a \
                     single source in your manifest, then retry",
                    matches[0].version
                )
            };
            Err(LpmError::Script(format!(
                "patch selector matches multiple packages:\n{listing}{hint}"
            )))
        }
    }
}

// ── Staging copy ──────────────────────────────────────────────────────

/// Recursively COPY (never link) a store package into `dest`, EXCLUDING
/// LPM internal sentinels. Used by `lpm patch` to seed the staging
/// directory. Always produces a fresh inode tree so user edits never
/// reach the store.
///
/// On macOS, `std::fs::copy` is fine because we want a real byte copy,
/// not a clone. On Linux this also produces fresh inodes (the source
/// of the F-V2 hardlink mutation trap is the LINKER, not the store
/// extractor).
pub fn copy_store_to_staging(store_path: &Path, dest: &Path) -> Result<(), LpmError> {
    if !store_path.exists() {
        return Err(LpmError::Script(format!(
            "store path {store_path:?} does not exist"
        )));
    }
    if !store_path.is_dir() {
        return Err(LpmError::Script(format!(
            "store path {store_path:?} is not a directory"
        )));
    }
    copy_dir_filtered(store_path, dest)
}

fn copy_dir_filtered(src: &Path, dst: &Path) -> Result<(), LpmError> {
    std::fs::create_dir_all(dst).map_err(LpmError::Io)?;
    for entry in std::fs::read_dir(src).map_err(LpmError::Io)? {
        let entry = entry.map_err(LpmError::Io)?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Exclude store sentinels and the staging breadcrumb at every
        // depth. The store extractor only writes them at the package
        // root, but a global filter is cheap and prevents accidental
        // inclusion if the layout ever changes.
        if STORE_INTERNAL_FILES.contains(&name_str.as_ref()) || name_str == STAGING_BREADCRUMB_FILE
        {
            continue;
        }

        let src_path = entry.path();
        let dst_path = dst.join(&name);
        let file_type = entry.file_type().map_err(LpmError::Io)?;
        if file_type.is_symlink() {
            // Symlinks in the store are not supported by the patch
            // workflow. The store extractor doesn't typically produce
            // symlinks but we're explicit about the policy.
            return Err(LpmError::Script(format!(
                "store entry contains symlink {src_path:?}; symlinks are not \
                 supported by the patch workflow"
            )));
        } else if file_type.is_dir() {
            copy_dir_filtered(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(LpmError::Io)?;
        }
    }
    Ok(())
}

// ── Patch generation ──────────────────────────────────────────────────

/// Result of `generate_patch` — the unified diff text plus stats.
#[derive(Debug, Clone)]
pub struct GeneratedPatch {
    /// Concatenated unified diff. Empty if no text files differ.
    pub diff: String,
    /// Number of files with text diffs (modifications, additions, deletions).
    pub files_changed: usize,
    /// Files where binary content differs. Phase 6 hard-errors on
    /// `patch-commit` if this is non-empty.
    pub binary_files_differ: Vec<String>,
    /// Total `+` lines across all hunks.
    pub insertions: usize,
    /// Total `-` lines across all hunks.
    pub deletions: usize,
}

/// Generate a unified diff from `original_dir` (the store baseline) to
/// `edited_dir` (the user's staging tree). See module docs for filter
/// rules.
pub fn generate_patch(original_dir: &Path, edited_dir: &Path) -> Result<GeneratedPatch, LpmError> {
    if !original_dir.is_dir() {
        return Err(LpmError::Script(format!(
            "patch baseline {original_dir:?} is not a directory"
        )));
    }
    if !edited_dir.is_dir() {
        return Err(LpmError::Script(format!(
            "patch staging {edited_dir:?} is not a directory"
        )));
    }
    let mut original_files: HashSet<PathBuf> = HashSet::new();
    walk_files_for_diff(original_dir, original_dir, &mut original_files)?;
    let mut edited_files: HashSet<PathBuf> = HashSet::new();
    walk_files_for_diff(edited_dir, edited_dir, &mut edited_files)?;

    // Sorted union of relative paths so the diff is deterministic
    // regardless of filesystem iteration order.
    let mut all: Vec<PathBuf> = original_files.union(&edited_files).cloned().collect();
    all.sort();

    let mut diff = String::new();
    let mut files_changed = 0;
    let mut insertions = 0;
    let mut deletions = 0;
    let mut binary_files_differ: Vec<String> = Vec::new();

    for rel in &all {
        let in_orig = original_files.contains(rel);
        let in_edit = edited_files.contains(rel);
        let orig_path = original_dir.join(rel);
        let edit_path = edited_dir.join(rel);

        // Read both sides as bytes; reject binary in either side that
        // appears in the diff. Empty side = "" for added/deleted.
        let orig_bytes: Vec<u8> = if in_orig {
            std::fs::read(&orig_path).map_err(LpmError::Io)?
        } else {
            Vec::new()
        };
        let edit_bytes: Vec<u8> = if in_edit {
            std::fs::read(&edit_path).map_err(LpmError::Io)?
        } else {
            Vec::new()
        };

        // Skip if no change at all (handles unmodified files in the
        // walked union).
        if in_orig && in_edit && orig_bytes == edit_bytes {
            continue;
        }

        // Binary detection: NUL byte in either side that's actually
        // in the diff (the file got modified).
        if has_nul(&orig_bytes) || has_nul(&edit_bytes) {
            binary_files_differ.push(rel.to_string_lossy().to_string());
            continue;
        }

        let orig_text = std::str::from_utf8(&orig_bytes).map_err(|_| {
            LpmError::Script(format!(
                "patch baseline {orig_path:?} is not UTF-8 (use a text editor)"
            ))
        })?;
        let edit_text = std::str::from_utf8(&edit_bytes).map_err(|_| {
            LpmError::Script(format!(
                "patch staging {edit_path:?} is not UTF-8 (use a text editor)"
            ))
        })?;

        // Filenames in the unified diff use git-style `a/` and `b/`
        // prefixes. For added files, original is `/dev/null`; for
        // deleted, modified is `/dev/null`.
        let mut opts = diffy::DiffOptions::default();
        let rel_str = rel.to_string_lossy().to_string();
        if in_orig {
            opts.set_original_filename(format!("a/{rel_str}"));
        } else {
            opts.set_original_filename("/dev/null".to_string());
        }
        if in_edit {
            opts.set_modified_filename(format!("b/{rel_str}"));
        } else {
            opts.set_modified_filename("/dev/null".to_string());
        }
        let patch = opts.create_patch(orig_text, edit_text);
        let patch_text = patch.to_string();
        if patch_text.is_empty() {
            continue;
        }

        // Count +/- lines for the summary stats. Skip the header lines
        // (`---`, `+++`, `@@`) so we don't double-count them as
        // additions/deletions.
        for line in patch_text.lines() {
            if line.starts_with("--- ") || line.starts_with("+++ ") || line.starts_with("@@") {
                continue;
            }
            if let Some(c) = line.chars().next() {
                match c {
                    '+' => insertions += 1,
                    '-' => deletions += 1,
                    _ => {}
                }
            }
        }

        diff.push_str(&patch_text);
        if !diff.ends_with('\n') {
            diff.push('\n');
        }
        files_changed += 1;
    }

    Ok(GeneratedPatch {
        diff,
        files_changed,
        binary_files_differ,
        insertions,
        deletions,
    })
}

fn walk_files_for_diff(
    root: &Path,
    cur: &Path,
    out: &mut HashSet<PathBuf>,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(cur).map_err(LpmError::Io)? {
        let entry = entry.map_err(LpmError::Io)?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Filter store sentinels + staging breadcrumb at every depth.
        // The sentinels live at the package root, but a defensive
        // global filter is cheap and prevents accidental inclusion if
        // the layout ever changes.
        if STORE_INTERNAL_FILES.contains(&name_str.as_ref()) || name_str == STAGING_BREADCRUMB_FILE
        {
            continue;
        }

        let path = entry.path();
        let file_type = entry.file_type().map_err(LpmError::Io)?;
        if file_type.is_symlink() {
            return Err(LpmError::Script(format!(
                "{path:?} is a symlink; symlinks are not supported by the patch workflow"
            )));
        }
        if file_type.is_dir() {
            walk_files_for_diff(root, &path, out)?;
        } else {
            // Compute path relative to root, with forward slashes for
            // cross-platform diff stability.
            let rel = path.strip_prefix(root).unwrap_or(&path);
            out.insert(rel.to_path_buf());
        }
    }
    Ok(())
}

fn has_nul(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

// ── Multi-file patch splitter ─────────────────────────────────────────

/// Split a multi-file unified diff into per-file `&str` slices. Each
/// returned slice is the full per-file section; modify / add / delete
/// chunks are parseable as a single `diffy::Patch<'_, str>`, while
/// rename-only chunks carry no `---`/`+++` lines and must be classified
/// from their `rename from`/`rename to` headers directly (see
/// `classify_patch_op`).
///
/// Boundaries:
/// - `^diff --git ` always starts a new file section (git emits this
///   for every file, including rename-only sections that have no
///   `---`/`+++` headers).
/// - `^--- ` starts a new file section, EXCEPT when the splitter is
///   inside an open `diff --git` section AND the `---` line is the
///   current section's own old-side header (i.e., the path matches
///   either an absent `rename from` or the existing one — the
///   rename+edit case).
/// - The mixed-format case where a rename-only `diff --git` section
///   is followed by a plain `---/+++` chunk for a DIFFERENT file: the
///   `---` path mismatch against `rename from` is the signal that the
///   prior section ended. Without this rule the two sections collapse
///   into one chunk (GPT audit, 2026-05-15).
///
/// Hunk content lines start with ` `, `+`, `-`, or `\` (single
/// character + content), so a line beginning with `diff --git ` or
/// `--- ` cannot appear inside a hunk body — except for the historical
/// edge case of a removed line whose original content begins with
/// `-- ` (matches `^--- `); that ambiguity is pre-existing.
pub fn split_multi_file_patch(text: &str) -> Vec<&str> {
    let mut boundaries: Vec<usize> = Vec::new();
    let mut byte = 0usize;
    // `in_git_header` is set by `diff --git ` and cleared once we've
    // resolved whether the next `---` line is the section's own
    // old-side header or a new section's boundary. `current_rename_from`
    // captures the most recent `rename from <path>` header (None when
    // no rename header has been seen in the current `diff --git`
    // section) — used to decide whether a `---` inside a git header is
    // the same file (rename+edit) or a new file (mixed git→plain).
    let mut in_git_header = false;
    let mut current_rename_from: Option<&str> = None;
    for line in text.split_inclusive('\n') {
        if line.starts_with("diff --git ") {
            boundaries.push(byte);
            in_git_header = true;
            current_rename_from = None;
        } else if let Some(rest) = line.strip_prefix("rename from ") {
            current_rename_from = Some(rest.trim_end_matches(['\r', '\n']));
        } else if line.starts_with("--- ") {
            // A `--- ` line is a new file boundary EXCEPT:
            //   (a) we're inside an open `diff --git` section with no
            //       rename headers — this is the section's own
            //       old-side header.
            //   (b) we're inside an open `diff --git` section WITH a
            //       prior `rename from` and the `---` path matches it
            //       — rename+edit's old-side header.
            // The mismatch case under (b) is the mixed git→plain
            // boundary the GPT audit flagged.
            let emit_boundary = if !in_git_header {
                true
            } else if let Some(rf) = current_rename_from {
                let path = line
                    .trim_end_matches(['\r', '\n'])
                    .strip_prefix("--- ")
                    .unwrap_or("");
                let stripped = path.strip_prefix("a/").unwrap_or(path);
                stripped != rf
            } else {
                false
            };
            if emit_boundary {
                boundaries.push(byte);
                current_rename_from = None;
            }
            in_git_header = false;
        } else if line.starts_with("@@") {
            in_git_header = false;
        }
        byte += line.len();
    }

    if boundaries.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::with_capacity(boundaries.len());
    for (i, &start) in boundaries.iter().enumerate() {
        let end = boundaries.get(i + 1).copied().unwrap_or(text.len());
        chunks.push(&text[start..end]);
    }
    chunks
}

// ── Apply ─────────────────────────────────────────────────────────────

/// Result of applying one `lpm.patchedDependencies` entry. Recorded in
/// the install JSON output and the patch state file.
#[derive(Debug, Clone)]
pub struct AppliedPatch {
    pub name: String,
    pub version: String,
    pub patch_path: PathBuf,
    /// SRI integrity hash (`sha512-...`) of the store baseline the
    /// patch was authored against. Mirrored verbatim from
    /// `lpm.patchedDependencies[<key>].originalIntegrity`. Recorded
    /// here so the install pipeline can plumb it into
    /// `.lpm/patch-state.json` and `lpm graph --why <pkg>` can surface
    /// the real hash instead of a placeholder string.
    pub original_integrity: String,
    pub locations_patched: Vec<PathBuf>,
    pub files_modified: usize,
    pub files_added: usize,
    pub files_deleted: usize,
}

impl AppliedPatch {
    /// Did this apply pass actually write any files this run? Returns
    /// `false` for idempotent reruns where every file already had the
    /// expected post-patch bytes. The install pipeline filters
    /// per-run summaries on this so a no-op rerun doesn't print
    /// "Applied 1 patch" with zero files.
    pub fn touched_anything(&self) -> bool {
        self.files_modified + self.files_added + self.files_deleted > 0
    }
}

/// Decoded operation kind for one patch chunk. Carries the parsed
/// `diffy::Patch` for hunk-bearing variants; `Rename` is hunk-less and
/// stores only the `from`/`to` paths.
#[derive(Debug)]
enum PatchOp<'a> {
    /// Read store baseline, apply hunks, write to destination.
    Modify {
        rel_path: String,
        patch: Patch<'a, str>,
    },
    /// Apply against empty input, write the result as a new file.
    Add {
        rel_path: String,
        patch: Patch<'a, str>,
    },
    /// Unlink the destination file. Store baseline must still exist
    /// (otherwise the drift gate would have already failed). The
    /// classifier discards the diffy `Patch` body after extracting the
    /// path — there are no hunks to re-apply on the destination.
    Delete { rel_path: String },
    /// Move the destination file from `from` to `to`. Bytes are read
    /// from the store baseline at `from` (not from the existing
    /// destination, which may already be mid-rename). No hunk apply.
    Rename { from: String, to: String },
    /// Move the destination file AND apply hunks to the moved bytes.
    /// Single variant rather than a `Rename + Modify` two-pass so the
    /// byte-comparison idempotency short-circuit can precede any write
    /// (the contract from the module docs: every file write is preceded
    /// by a content comparison; a two-pass decomposition would re-read
    /// + re-write the destination on idempotent reruns).
    RenameWithEdit {
        from: String,
        to: String,
        hunks: Patch<'a, str>,
    },
}

fn classify_patch_op(chunk: &str) -> Result<PatchOp<'_>, LpmError> {
    // Pre-scan for git rename-detection headers. These appear BEFORE
    // any `---`/`+++`/`@@` lines, in the per-file header block that
    // follows `diff --git`. Hunk content lines start with one of
    // ` `, `+`, `-`, `\`, so a line beginning with literal
    // `rename from ` or `rename to ` is unambiguously a header.
    let mut rename_from: Option<String> = None;
    let mut rename_to: Option<String> = None;
    let mut has_hunks = false;
    for line in chunk.lines() {
        if let Some(rest) = line.strip_prefix("rename from ") {
            rename_from = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("rename to ") {
            rename_to = Some(rest.to_string());
        } else if line.starts_with("@@") {
            has_hunks = true;
        }
    }

    match (rename_from, rename_to) {
        (Some(from), Some(to)) => {
            if from == to {
                return Err(LpmError::Script(format!(
                    "patch chunk has identical `rename from`/`rename to` paths ({from}); \
                     this is malformed — generators must omit no-op renames"
                )));
            }
            if has_hunks {
                let hunks = Patch::from_str(chunk).map_err(|e| {
                    LpmError::Script(format!(
                        "patch chunk has rename+edit headers but hunks failed to parse: {e}"
                    ))
                })?;
                return Ok(PatchOp::RenameWithEdit { from, to, hunks });
            }
            return Ok(PatchOp::Rename { from, to });
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(LpmError::Script(
                "patch chunk has only one of `rename from`/`rename to` — both required".into(),
            ));
        }
        (None, None) => {}
    }

    // No rename headers — must be a regular modify/add/delete chunk.
    let patch = Patch::from_str(chunk)
        .map_err(|e| LpmError::Script(format!("patch chunk parse error: {e}")))?;
    let original = patch.original();
    let modified = patch.modified();
    let strip = |s: &str| -> String {
        s.strip_prefix("a/")
            .or_else(|| s.strip_prefix("b/"))
            .unwrap_or(s)
            .to_string()
    };
    let is_null = |s: Option<&str>| -> bool { matches!(s, Some("/dev/null") | None) };

    match (is_null(original), is_null(modified)) {
        (true, true) => Err(LpmError::Script(
            "patch chunk has /dev/null on both sides".into(),
        )),
        (true, false) => Ok(PatchOp::Add {
            rel_path: strip(modified.unwrap()),
            patch,
        }),
        (false, true) => Ok(PatchOp::Delete {
            rel_path: strip(original.unwrap()),
        }),
        (false, false) => {
            let o = strip(original.unwrap());
            let m = strip(modified.unwrap());
            if o != m {
                return Err(LpmError::Script(format!(
                    "patch chunk has filename mismatch ({o} → {m}) without \
                     `rename from`/`rename to` headers; regenerate with a git-aware tool"
                )));
            }
            Ok(PatchOp::Modify { rel_path: m, patch })
        }
    }
}

/// Verify that the store entry's recorded SRI matches the
/// `originalIntegrity` recorded in `package.json`. Hard-errors on
/// mismatch — this is the drift gate.
///
/// **Phase 66 confidence-followup S2 (2026-05-08).** Resolves the
/// baseline via [`lpm_store::find_installed_package_baseline`], which
/// prefers the v2 virtual store (link's `meta.source_sri`) and falls
/// back to v1's per-package `.integrity` sentinel. Pre-fix this
/// function read directly from `store.package_dir(name, version)/.integrity`
/// (v1-only) and silently failed under v2 with "store entry ...
/// missing .integrity" even though the package was fully linked in
/// `node_modules/`.
pub fn verify_original_integrity(
    store: &PackageStore,
    name: &str,
    version: &str,
    expected_integrity: &str,
) -> Result<(), LpmError> {
    let lpm_root = store.lpm_root()?;
    let baseline = lpm_store::find_installed_package_baseline(&lpm_root, name, version)?
        .ok_or_else(|| {
            LpmError::Script(format!(
                "no v1 or v2 store entry for {name}@{version} — \
                 cannot verify patch baseline. Run `lpm install {name}@{version}` first."
            ))
        })?;
    if baseline.integrity != expected_integrity {
        return Err(LpmError::Script(format!(
            "patch baseline drift for {name}@{version}: \
             stored integrity {} does not match \
             package.json originalIntegrity {expected_integrity}. \
             Regenerate the patch with `lpm patch {name}@{version}`.",
            baseline.integrity
        )));
    }
    Ok(())
}

/// Apply a single `lpm.patchedDependencies` entry's patch file to every
/// physical destination of the target package.
///
/// `locations` is the slice of [`MaterializedPackage`]s filtered to
/// entries where `name == this_name && version == this_version`. The
/// patch engine does NOT walk `node_modules/` — see Phase 6 status doc
/// F-V4 for the rationale.
///
/// Errors are hard install failures — never warnings.
pub fn apply_patch(
    locations: &[&MaterializedPackage],
    patch_file: &Path,
    expected_integrity: &str,
    store: &PackageStore,
    name: &str,
    version: &str,
) -> Result<AppliedPatch, LpmError> {
    // 1. Drift gate + v2-aware baseline lookup. `find_installed_package_baseline`
    // prefers the v2 link entry (returns `<links/<key>/node_modules/<name>>`)
    // and falls back to v1's `<store>/v1/<safe>@<ver>/`. Both layouts
    // expose a `pristine_dir` field that points at NEVER-mutated bytes:
    // - V1: `<store>/v1/<safe>@<ver>/` (the v1 store dir itself; v1
    //   patches mutate the project-private wrapper, not the store).
    // - V2: `<store>/v2/objects/<sri-segment>/` (the immutable
    //   content-addressed object dir; v2 patches mutate the link
    //   entry at `package_dir`, so reading baseline from
    //   `package_dir` would feed already-patched bytes back into a
    //   subsequent `apply_patch`).
    let lpm_root = store.lpm_root()?;
    let baseline = lpm_store::find_installed_package_baseline(&lpm_root, name, version)?
        .ok_or_else(|| {
            LpmError::Script(format!(
                "no v1 or v2 store entry for {name}@{version} — \
                 cannot apply patch. Run `lpm install {name}@{version}` first."
            ))
        })?;
    if baseline.integrity != expected_integrity {
        return Err(LpmError::Script(format!(
            "patch baseline drift for {name}@{version}: \
             stored integrity {} does not match \
             package.json originalIntegrity {expected_integrity}. \
             Regenerate the patch with `lpm patch {name}@{version}`.",
            baseline.integrity
        )));
    }

    // 2. Read + split into per-file chunks
    let patch_text = std::fs::read_to_string(patch_file)
        .map_err(|e| LpmError::Script(format!("patch file {patch_file:?} unreadable: {e}")))?;
    let chunks = split_multi_file_patch(&patch_text);
    if chunks.is_empty() {
        return Err(LpmError::Script(format!(
            "patch file {patch_file:?} contains no file diffs"
        )));
    }

    if locations.is_empty() {
        return Err(LpmError::Script(format!(
            "{name}@{version} declared in lpm.patchedDependencies but \
             not present in node_modules — re-run `lpm install`"
        )));
    }

    let mut files_modified = 0;
    let mut files_added = 0;
    let mut files_deleted = 0;
    // **F1.** Read baseline bytes (pre-image for MODIFY hunks; existence
    // probes for ADD / DELETE) from the PRISTINE dir, never from
    // `package_dir`. Under v2 the latter is the link entry — where
    // patches are written to — and reading it back would corrupt the
    // re-install idempotency contract.
    let store_dir = baseline.pristine_dir;

    for chunk in chunks {
        let op = classify_patch_op(chunk).map_err(|e| {
            LpmError::Script(format!(
                "patch file {patch_file:?} parse error in chunk: {e}"
            ))
        })?;

        // Defense in depth: never let a patch touch a store sentinel
        // or escape the package root. Renames validate both endpoints.
        let validate = |rel: &str| -> Result<(), LpmError> {
            if STORE_INTERNAL_FILES.contains(&rel) {
                return Err(LpmError::Script(format!(
                    "patch file {patch_file:?} attempts to modify LPM-internal \
                     file {rel}; refusing to apply"
                )));
            }
            if rel.contains("..") || rel.starts_with('/') {
                return Err(LpmError::Script(format!(
                    "patch file {patch_file:?} contains illegal path {rel}; \
                     refusing to apply"
                )));
            }
            Ok(())
        };
        match &op {
            PatchOp::Modify { rel_path, .. }
            | PatchOp::Add { rel_path, .. }
            | PatchOp::Delete { rel_path } => validate(rel_path)?,
            PatchOp::Rename { from, to } | PatchOp::RenameWithEdit { from, to, .. } => {
                validate(from)?;
                validate(to)?;
            }
        }

        for loc in locations {
            match &op {
                PatchOp::Modify { rel_path, patch } => {
                    let nm_file = loc.destination.join(rel_path);
                    let store_file = store_dir.join(rel_path);
                    let store_text = read_text_file(&store_file)?;
                    let patched_text = diffy::apply(&store_text, patch).map_err(|e| {
                        LpmError::Script(format!(
                            "patch hunk failed for {name}@{version} {rel_path}: {e} — \
                             regenerate the patch or fix the upstream"
                        ))
                    })?;
                    if file_already_has_bytes(&nm_file, patched_text.as_bytes()) {
                        continue; // idempotent
                    }
                    write_breaking_hardlink(&nm_file, patched_text.as_bytes())?;
                    files_modified += 1;
                }
                PatchOp::Add { rel_path, patch } => {
                    let nm_file = loc.destination.join(rel_path);
                    let store_file = store_dir.join(rel_path);
                    if store_file.exists() {
                        return Err(LpmError::Script(format!(
                            "patch adds {rel_path} but the store baseline \
                             {store_file:?} already contains it; the patch \
                             may be stale (regenerate with `lpm patch {name}@{version}`)"
                        )));
                    }
                    let patched_text = diffy::apply("", patch).map_err(|e| {
                        LpmError::Script(format!(
                            "patch add hunk failed for {name}@{version} {rel_path}: {e}"
                        ))
                    })?;
                    if file_already_has_bytes(&nm_file, patched_text.as_bytes()) {
                        continue; // idempotent
                    }
                    if let Some(parent) = nm_file.parent() {
                        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
                    }
                    write_breaking_hardlink(&nm_file, patched_text.as_bytes())?;
                    files_added += 1;
                }
                PatchOp::Delete { rel_path } => {
                    let nm_file = loc.destination.join(rel_path);
                    let store_file = store_dir.join(rel_path);
                    if !store_file.exists() {
                        return Err(LpmError::Script(format!(
                            "patch deletes {rel_path} but the store baseline \
                             {store_file:?} no longer contains it; the patch \
                             may be stale (regenerate with `lpm patch {name}@{version}`)"
                        )));
                    }
                    if !nm_file.exists() {
                        continue; // already deleted, idempotent
                    }
                    std::fs::remove_file(&nm_file).map_err(LpmError::Io)?;
                    files_deleted += 1;
                }
                PatchOp::Rename { from, to } => {
                    let nm_file_from = loc.destination.join(from);
                    let nm_file_to = loc.destination.join(to);
                    let store_file_from = store_dir.join(from);
                    if !store_file_from.exists() {
                        return Err(LpmError::Script(format!(
                            "patch renames {from} → {to} but the store baseline \
                             has no {from}; the patch may be stale \
                             (regenerate with `lpm patch {name}@{version}`)"
                        )));
                    }
                    let baseline_bytes = std::fs::read(&store_file_from).map_err(|e| {
                        LpmError::Script(format!(
                            "patch rename baseline {store_file_from:?} unreadable: {e}"
                        ))
                    })?;
                    // Idempotency contract from the module docs: every
                    // file write is preceded by a content comparison.
                    // Full short-circuit only when BOTH endpoints are at
                    // their final state — destination has target bytes
                    // AND source is gone.
                    let dest_ok = file_already_has_bytes(&nm_file_to, &baseline_bytes);
                    let source_gone = !nm_file_from.exists();
                    if dest_ok && source_gone {
                        continue;
                    }
                    if !dest_ok {
                        if let Some(parent) = nm_file_to.parent() {
                            std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
                        }
                        write_breaking_hardlink(&nm_file_to, &baseline_bytes)?;
                        files_added += 1;
                    }
                    if !source_gone {
                        std::fs::remove_file(&nm_file_from).map_err(LpmError::Io)?;
                        files_deleted += 1;
                    }
                }
                PatchOp::RenameWithEdit { from, to, hunks } => {
                    let nm_file_from = loc.destination.join(from);
                    let nm_file_to = loc.destination.join(to);
                    let store_file_from = store_dir.join(from);
                    if !store_file_from.exists() {
                        return Err(LpmError::Script(format!(
                            "patch renames {from} → {to} but the store baseline \
                             has no {from}; the patch may be stale \
                             (regenerate with `lpm patch {name}@{version}`)"
                        )));
                    }
                    let baseline_text = read_text_file(&store_file_from)?;
                    let patched_text = diffy::apply(&baseline_text, hunks).map_err(|e| {
                        LpmError::Script(format!(
                            "patch hunk failed for {name}@{version} rename {from} → {to}: \
                             {e} — regenerate the patch or fix the upstream"
                        ))
                    })?;
                    // Same idempotency rule as Rename: full short-circuit
                    // only when destination has the post-edit bytes AND
                    // the source path is gone.
                    let dest_ok = file_already_has_bytes(&nm_file_to, patched_text.as_bytes());
                    let source_gone = !nm_file_from.exists();
                    if dest_ok && source_gone {
                        continue;
                    }
                    if !dest_ok {
                        if let Some(parent) = nm_file_to.parent() {
                            std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
                        }
                        write_breaking_hardlink(&nm_file_to, patched_text.as_bytes())?;
                        files_added += 1;
                    }
                    if !source_gone {
                        std::fs::remove_file(&nm_file_from).map_err(LpmError::Io)?;
                        files_deleted += 1;
                    }
                }
            }
        }
    }

    Ok(AppliedPatch {
        name: name.to_string(),
        version: version.to_string(),
        patch_path: patch_file.to_path_buf(),
        original_integrity: expected_integrity.to_string(),
        locations_patched: locations.iter().map(|m| m.destination.clone()).collect(),
        files_modified,
        files_added,
        files_deleted,
    })
}

/// Read a UTF-8 text file with a clear error if the contents are not
/// valid UTF-8 (patches can only target text files).
fn read_text_file(path: &Path) -> Result<String, LpmError> {
    let bytes = std::fs::read(path)
        .map_err(|e| LpmError::Script(format!("patch baseline missing: {path:?}: {e}")))?;
    String::from_utf8(bytes)
        .map_err(|_| LpmError::Script(format!("patch baseline {path:?} is not UTF-8")))
}

/// Write `bytes` to `dest`, but `remove_file` first to break any
/// hardlink share with the store. F-V2 hardlink mutation trap.
fn write_breaking_hardlink(dest: &Path, bytes: &[u8]) -> Result<(), LpmError> {
    if dest.exists() {
        std::fs::remove_file(dest).map_err(LpmError::Io)?;
    }
    std::fs::write(dest, bytes).map_err(LpmError::Io)
}

/// Idempotency check: compares destination bytes against the expected
/// post-patch bytes byte-for-byte.
fn file_already_has_bytes(dest: &Path, expected: &[u8]) -> bool {
    std::fs::read(dest).map(|b| b == expected).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_patch_key contracts ────────────────────────────────────

    #[test]
    fn parse_key_unscoped_exact() {
        assert_eq!(
            parse_patch_key("lodash@4.17.21").unwrap(),
            ("lodash".to_string(), "4.17.21".to_string())
        );
    }

    #[test]
    fn parse_key_scoped_exact() {
        assert_eq!(
            parse_patch_key("@types/node@20.10.0").unwrap(),
            ("@types/node".to_string(), "20.10.0".to_string())
        );
    }

    #[test]
    fn parse_key_prerelease_exact() {
        assert_eq!(
            parse_patch_key("foo@1.0.0-rc.1").unwrap(),
            ("foo".to_string(), "1.0.0-rc.1".to_string())
        );
    }

    #[test]
    fn parse_key_missing_at_separator() {
        let err = parse_patch_key("lodash").unwrap_err();
        assert!(format!("{err}").contains("missing version separator"));
    }

    #[test]
    fn parse_key_empty_version() {
        let err = parse_patch_key("lodash@").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn parse_key_only_scope() {
        let err = parse_patch_key("@only-scope").unwrap_err();
        // No `@<version>` after scope name; rfind finds `@` at index 0.
        assert!(
            format!("{err}").contains("missing version segment")
                || format!("{err}").contains("empty")
        );
    }

    /// **Slice A contract.** `parse_patch_key` is the PERSISTED-key
    /// parser — it accepts only exact pins. Range syntax in a
    /// persisted key means the manifest was hand-edited (or produced
    /// by an out-of-band tool); the author-time `lpm patch` flow
    /// resolves ranges to exact pins before writing.
    ///
    /// The error wording deliberately points users at `lpm patch
    /// <name>@<exact>` rather than the legacy "range support isn't
    /// available yet" — because ranges ARE supported now, just as CLI
    /// input, not as persisted keys.
    #[test]
    fn parse_key_rejects_caret_range() {
        let err = parse_patch_key("lodash@^4.17.0").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not an exact pin"),
            "error must point user at exact-pin requirement; got: {msg}"
        );
        assert!(
            msg.contains("lpm patch lodash@"),
            "error must hint at the author-time fix; got: {msg}"
        );
    }

    #[test]
    fn parse_key_rejects_x_wildcard() {
        let err = parse_patch_key("lodash@4.x").unwrap_err();
        assert!(format!("{err}").contains("not an exact pin"));
    }

    #[test]
    fn parse_key_rejects_tilde_range() {
        assert!(parse_patch_key("lodash@~4.17.0").is_err());
    }

    #[test]
    fn parse_key_rejects_star() {
        assert!(parse_patch_key("lodash@*").is_err());
    }

    #[test]
    fn parse_key_rejects_or_range() {
        assert!(parse_patch_key("lodash@1.0.0 || 2.0.0").is_err());
    }

    #[test]
    fn parse_key_rejects_latest_magic_string() {
        assert!(parse_patch_key("lodash@latest").is_err());
    }

    // ── parse_patch_selector contracts (Slice A — CLI input) ─────────

    #[test]
    fn parse_selector_bare_name() {
        assert_eq!(
            parse_patch_selector("lodash").unwrap(),
            PatchSelector::BareName("lodash".to_string())
        );
    }

    #[test]
    fn parse_selector_bare_scoped_name() {
        assert_eq!(
            parse_patch_selector("@types/node").unwrap(),
            PatchSelector::BareName("@types/node".to_string())
        );
    }

    #[test]
    fn parse_selector_exact() {
        assert_eq!(
            parse_patch_selector("lodash@4.17.21").unwrap(),
            PatchSelector::Exact {
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
            }
        );
    }

    #[test]
    fn parse_selector_scoped_exact() {
        assert_eq!(
            parse_patch_selector("@types/node@20.10.0").unwrap(),
            PatchSelector::Exact {
                name: "@types/node".to_string(),
                version: "20.10.0".to_string(),
            }
        );
    }

    #[test]
    fn parse_selector_prerelease_exact() {
        assert_eq!(
            parse_patch_selector("foo@1.0.0-rc.1").unwrap(),
            PatchSelector::Exact {
                name: "foo".to_string(),
                version: "1.0.0-rc.1".to_string(),
            }
        );
    }

    #[test]
    fn parse_selector_caret_range() {
        assert_eq!(
            parse_patch_selector("lodash@^4.0.0").unwrap(),
            PatchSelector::Range {
                name: "lodash".to_string(),
                range: "^4.0.0".to_string(),
            }
        );
    }

    #[test]
    fn parse_selector_tilde_range() {
        assert_eq!(
            parse_patch_selector("lodash@~4.17.0").unwrap(),
            PatchSelector::Range {
                name: "lodash".to_string(),
                range: "~4.17.0".to_string(),
            }
        );
    }

    #[test]
    fn parse_selector_x_wildcard() {
        match parse_patch_selector("lodash@4.x").unwrap() {
            PatchSelector::Range { name, range } => {
                assert_eq!(name, "lodash");
                assert_eq!(range, "4.x");
            }
            other => panic!("expected Range for `4.x`, got {other:?}"),
        }
    }

    #[test]
    fn parse_selector_or_range() {
        match parse_patch_selector("lodash@1.0.0 || 2.0.0").unwrap() {
            PatchSelector::Range { range, .. } => assert!(range.contains("||")),
            other => panic!("expected Range for disjunction, got {other:?}"),
        }
    }

    #[test]
    fn parse_selector_hyphen_range() {
        match parse_patch_selector("lodash@1.0.0 - 2.0.0").unwrap() {
            PatchSelector::Range { .. } => {}
            other => panic!("expected Range for hyphen, got {other:?}"),
        }
    }

    #[test]
    fn parse_selector_greater_than_range() {
        match parse_patch_selector("lodash@>=4.17.0").unwrap() {
            PatchSelector::Range { .. } => {}
            other => panic!("expected Range, got {other:?}"),
        }
    }

    /// `latest`, `next`, `beta` etc. are dist-tags; the selector path
    /// never consults the registry. Reject with a clear message
    /// pointing users at a version / range instead.
    #[test]
    fn parse_selector_rejects_latest() {
        let err = parse_patch_selector("lodash@latest").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("dist-tag"), "got: {msg}");
        assert!(msg.contains("latest"), "got: {msg}");
    }

    #[test]
    fn parse_selector_rejects_next() {
        let err = parse_patch_selector("react@next").unwrap_err();
        assert!(format!("{err}").contains("dist-tag"));
    }

    #[test]
    fn parse_selector_rejects_beta_dist_tag() {
        let err = parse_patch_selector("vue@beta").unwrap_err();
        assert!(format!("{err}").contains("dist-tag"));
    }

    #[test]
    fn parse_selector_rejects_empty() {
        let err = parse_patch_selector("").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn parse_selector_rejects_empty_version_segment() {
        let err = parse_patch_selector("lodash@").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty"), "got: {msg}");
    }

    #[test]
    fn parse_selector_rejects_malformed_scoped_name() {
        // `@malformed` with no `/` is not a valid scoped name.
        let err = parse_patch_selector("@malformed").unwrap_err();
        assert!(format!("{err}").contains("malformed scoped name"));
    }

    // ── resolve_patch_selector contracts (Slice A — pure resolver) ───

    /// Build a synthetic `LockedPackage` for resolver tests. `source`
    /// is the source URL — defaults to a registry source.
    fn lockfile_with(packages: &[(&str, &str, &str)]) -> Lockfile {
        let mut lf = Lockfile::new_with_resolver("test");
        for (name, version, source) in packages {
            lf.add_package(LockedPackage {
                name: name.to_string(),
                version: version.to_string(),
                source: Some(source.to_string()),
                ..Default::default()
            });
        }
        lf
    }

    const NPM: &str = "registry+https://registry.npmjs.org";
    const LPM: &str = "registry+https://lpm.dev";

    #[test]
    fn resolve_selector_unique_match() {
        let lf = lockfile_with(&[("lodash", "4.17.21", NPM)]);
        let sel = PatchSelector::BareName("lodash".to_string());
        let (name, version) = resolve_patch_selector(&lf, &sel).unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(version, "4.17.21");
    }

    #[test]
    fn resolve_selector_range_filters_to_unique() {
        let lf = lockfile_with(&[
            ("lodash", "3.10.0", NPM),
            ("lodash", "4.17.21", NPM),
            ("lodash", "5.0.0", NPM),
        ]);
        let sel = PatchSelector::Range {
            name: "lodash".to_string(),
            range: "^4.0.0".to_string(),
        };
        let (name, version) = resolve_patch_selector(&lf, &sel).unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(version, "4.17.21");
    }

    /// Multiple lockfile entries with the SAME `PackageKey` triple
    /// (single physical package referenced from multiple dep edges)
    /// resolve silently to that shared version.
    #[test]
    fn resolve_selector_multi_same_packagekey_silent() {
        // Two entries with the same name/version/source — represents
        // the legitimate "hoisted root + transitive duplicate" case.
        let lf = lockfile_with(&[("lodash", "4.17.21", NPM), ("lodash", "4.17.21", NPM)]);
        let sel = PatchSelector::BareName("lodash".to_string());
        let (name, version) = resolve_patch_selector(&lf, &sel).unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(version, "4.17.21");
    }

    /// Multiple DISTINCT versions → list-and-exit with a precise-version
    /// hint. Mirrors Bun's `Global.crash()` behavior.
    #[test]
    fn resolve_selector_multi_distinct_versions_errors_with_list() {
        let lf = lockfile_with(&[("lodash", "3.10.0", NPM), ("lodash", "4.17.21", NPM)]);
        let sel = PatchSelector::BareName("lodash".to_string());
        let err = resolve_patch_selector(&lf, &sel).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("multiple packages"), "got: {msg}");
        assert!(msg.contains("lodash@3.10.0"), "got: {msg}");
        assert!(msg.contains("lodash@4.17.21"), "got: {msg}");
        assert!(msg.contains("specify a precise version"), "got: {msg}");
    }

    /// **Cross-source collision** — same `(name, version)` under two
    /// distinct `source_id`s. The persisted-key shape can't
    /// distinguish them, so the selector refuses rather than silently
    /// picking one (see "Explicitly out of scope" in
    /// `private/patch.md`).
    ///
    /// Mirrors the regression coverage at
    /// `lpm-lockfile/src/lib.rs::find_package_by_key_disambiguates_cross_source_collisions`.
    #[test]
    fn resolve_selector_cross_source_collision_errors() {
        let lf = lockfile_with(&[("react", "19.0.0", NPM), ("react", "19.0.0", LPM)]);
        let sel = PatchSelector::Exact {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
        };
        let err = resolve_patch_selector(&lf, &sel).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("multiple sources"),
            "error must surface the cross-source collision; got: {msg}"
        );
        assert!(
            msg.contains(NPM),
            "error must list each source URL; got: {msg}"
        );
        assert!(
            msg.contains(LPM),
            "error must list each source URL; got: {msg}"
        );
        assert!(
            msg.contains("cannot distinguish sources"),
            "error must explain why the resolver refuses; got: {msg}"
        );
    }

    #[test]
    fn resolve_selector_zero_matches_clear_error() {
        let lf = lockfile_with(&[("other-pkg", "1.0.0", NPM)]);
        let sel = PatchSelector::BareName("missing-pkg".to_string());
        let err = resolve_patch_selector(&lf, &sel).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing-pkg"), "got: {msg}");
        assert!(msg.contains("lpm install"), "got: {msg}");
    }

    #[test]
    fn resolve_selector_range_zero_matches_clear_error() {
        let lf = lockfile_with(&[("lodash", "3.10.0", NPM)]);
        let sel = PatchSelector::Range {
            name: "lodash".to_string(),
            range: "^5.0.0".to_string(),
        };
        let err = resolve_patch_selector(&lf, &sel).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("matches"), "got: {msg}");
        assert!(msg.contains("^5.0.0"), "got: {msg}");
    }

    // ── copy_store_to_staging contracts ──────────────────────────────

    #[test]
    fn copy_store_excludes_internal_sentinels() {
        let store = tempfile::tempdir().unwrap();
        let src = store.path().join("lodash@4.17.21");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("package.json"), r#"{"name":"lodash"}"#).unwrap();
        std::fs::write(src.join("lodash.js"), "module.exports = {}").unwrap();
        // Plant the sentinels
        std::fs::write(src.join(".integrity"), "sha512-baseline").unwrap();
        std::fs::write(src.join(".lpm-security.json"), "{}").unwrap();

        let dest_root = tempfile::tempdir().unwrap();
        let dest = dest_root.path().join("lodash");
        copy_store_to_staging(&src, &dest).unwrap();

        // The package files came over
        assert!(dest.join("package.json").exists());
        assert!(dest.join("lodash.js").exists());
        // Sentinels did NOT
        assert!(
            !dest.join(".integrity").exists(),
            ".integrity must be filtered from staging"
        );
        assert!(
            !dest.join(".lpm-security.json").exists(),
            ".lpm-security.json must be filtered from staging"
        );
    }

    #[test]
    fn copy_store_writes_separate_inodes_safe_to_edit() {
        // Editing the staging copy must NEVER mutate the source.
        let store = tempfile::tempdir().unwrap();
        let src = store.path().join("foo");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.js"), "ORIGINAL").unwrap();

        let dest_root = tempfile::tempdir().unwrap();
        let dest = dest_root.path().join("foo");
        copy_store_to_staging(&src, &dest).unwrap();

        // Modify the staging copy
        std::fs::write(dest.join("a.js"), "EDITED").unwrap();

        // Source must be unchanged
        assert_eq!(
            std::fs::read_to_string(src.join("a.js")).unwrap(),
            "ORIGINAL",
            "editing staging mutated the store source — F-V2 trap"
        );
    }

    #[test]
    fn copy_store_handles_nested_dirs() {
        let store = tempfile::tempdir().unwrap();
        let src = store.path().join("foo");
        std::fs::create_dir_all(src.join("lib/inner")).unwrap();
        std::fs::write(src.join("lib/inner/x.js"), "x").unwrap();
        let dest_root = tempfile::tempdir().unwrap();
        let dest = dest_root.path().join("foo");
        copy_store_to_staging(&src, &dest).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("lib/inner/x.js")).unwrap(),
            "x"
        );
    }

    // ── generate_patch contracts ─────────────────────────────────────

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn generate_patch_returns_empty_when_no_changes() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write(&a.path().join("x.js"), "same\n");
        write(&b.path().join("x.js"), "same\n");
        let result = generate_patch(a.path(), b.path()).unwrap();
        assert!(result.diff.is_empty());
        assert_eq!(result.files_changed, 0);
    }

    #[test]
    fn generate_patch_modify_produces_unified_diff() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write(&a.path().join("x.js"), "line1\nline2\nline3\n");
        write(&b.path().join("x.js"), "line1\nlineTWO\nline3\n");
        let result = generate_patch(a.path(), b.path()).unwrap();
        assert!(!result.diff.is_empty());
        assert_eq!(result.files_changed, 1);
        assert!(result.diff.contains("--- a/x.js"));
        assert!(result.diff.contains("+++ b/x.js"));
        assert!(result.diff.contains("-line2"));
        assert!(result.diff.contains("+lineTWO"));
        assert_eq!(result.insertions, 1);
        assert_eq!(result.deletions, 1);
    }

    #[test]
    fn generate_patch_addition_uses_dev_null_header() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write(&b.path().join("new.js"), "brand new\n");
        let result = generate_patch(a.path(), b.path()).unwrap();
        assert_eq!(result.files_changed, 1);
        assert!(result.diff.contains("--- /dev/null"));
        assert!(result.diff.contains("+++ b/new.js"));
        assert!(result.diff.contains("+brand new"));
    }

    #[test]
    fn generate_patch_deletion_uses_dev_null_header() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write(&a.path().join("doomed.js"), "rip\n");
        let result = generate_patch(a.path(), b.path()).unwrap();
        assert_eq!(result.files_changed, 1);
        assert!(result.diff.contains("--- a/doomed.js"));
        assert!(result.diff.contains("+++ /dev/null"));
        assert!(result.diff.contains("-rip"));
    }

    #[test]
    fn generate_patch_excludes_store_internal_files() {
        // Even if `.integrity` differs between the trees, it's filtered.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write(&a.path().join(".integrity"), "sha512-A");
        write(&b.path().join(".integrity"), "sha512-B");
        write(&a.path().join("real.js"), "x");
        write(&b.path().join("real.js"), "x");
        let result = generate_patch(a.path(), b.path()).unwrap();
        assert!(
            result.diff.is_empty(),
            ".integrity drift must NOT appear in the diff"
        );
        assert_eq!(result.files_changed, 0);
    }

    #[test]
    fn generate_patch_records_binary_files_separately() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        // NUL byte makes it binary
        std::fs::write(a.path().join("logo.bin"), b"hello\x00world").unwrap();
        std::fs::write(b.path().join("logo.bin"), b"hello\x00WORLD").unwrap();
        let result = generate_patch(a.path(), b.path()).unwrap();
        assert!(result.diff.is_empty());
        assert_eq!(result.binary_files_differ, vec!["logo.bin".to_string()]);
    }

    #[test]
    fn generate_patch_handles_nested_paths() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write(&a.path().join("lib/util/inner.js"), "old\n");
        write(&b.path().join("lib/util/inner.js"), "new\n");
        let result = generate_patch(a.path(), b.path()).unwrap();
        assert_eq!(result.files_changed, 1);
        assert!(result.diff.contains("--- a/lib/util/inner.js"));
    }

    // ── split_multi_file_patch contracts ─────────────────────────────

    #[test]
    fn split_single_file_patch_returns_one_chunk() {
        let text = "--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-old\n+new\n";
        let chunks = split_multi_file_patch(text);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], text);
    }

    #[test]
    fn split_two_file_patch_returns_two_chunks() {
        let text = "--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-old\n+new\n--- a/y.js\n+++ b/y.js\n@@ -1 +1 @@\n-foo\n+bar\n";
        let chunks = split_multi_file_patch(text);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].starts_with("--- a/x.js"));
        assert!(chunks[1].starts_with("--- a/y.js"));
        // Each chunk parses as a complete diffy::Patch
        assert!(Patch::from_str(chunks[0]).is_ok());
        assert!(Patch::from_str(chunks[1]).is_ok());
    }

    #[test]
    fn split_no_dashes_returns_empty() {
        let text = "this is not a patch";
        assert!(split_multi_file_patch(text).is_empty());
    }

    #[test]
    fn split_handles_dash_dash_in_hunk_body() {
        // A line whose CONTENT contains "---" but doesn't START with
        // it must not be treated as a header. Hunk content lines start
        // with ` `, `+`, `-`, or `\`.
        let text = "--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-old\n+new --- not a header\n";
        let chunks = split_multi_file_patch(text);
        assert_eq!(chunks.len(), 1);
    }

    /// Git rename-only chunks have no `---`/`+++` lines — only
    /// `diff --git`, `similarity index`, `rename from`, `rename to`.
    /// Pre-Slice-B these collapsed into the previous chunk because the
    /// splitter only recognized `^--- ` as a boundary.
    #[test]
    fn split_multi_file_patch_recognizes_diff_git_boundary_for_rename_only() {
        let text = "diff --git a/old.js b/new.js\n\
                    similarity index 100%\n\
                    rename from old.js\n\
                    rename to new.js\n";
        let chunks = split_multi_file_patch(text);
        assert_eq!(chunks.len(), 1, "rename-only chunk must produce one slice");
        assert!(chunks[0].starts_with("diff --git "));
        assert!(chunks[0].contains("rename from old.js"));
        assert!(chunks[0].contains("rename to new.js"));
    }

    /// A multi-file git patch with one rename-only file followed by a
    /// rename+edit file must produce two distinct slices.
    #[test]
    fn split_multi_file_patch_handles_mixed_rename_and_rename_edit_chunks() {
        let text = "diff --git a/a.js b/aa.js\n\
                    similarity index 100%\n\
                    rename from a.js\n\
                    rename to aa.js\n\
                    diff --git a/b.js b/bb.js\n\
                    similarity index 80%\n\
                    rename from b.js\n\
                    rename to bb.js\n\
                    --- a/b.js\n\
                    +++ b/bb.js\n\
                    @@ -1 +1 @@\n\
                    -old\n\
                    +new\n";
        let chunks = split_multi_file_patch(text);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].contains("rename to aa.js"));
        assert!(chunks[0].contains("rename from a.js"));
        assert!(
            !chunks[0].contains("aa.js\n@@"),
            "chunk 0 must not bleed into chunk 1"
        );
        assert!(chunks[1].contains("rename to bb.js"));
        assert!(chunks[1].contains("@@ -1 +1 @@"));
    }

    /// `--- a/X` immediately following a `diff --git` line is the file's
    /// own old-side header, NOT a new file boundary. Without this rule,
    /// every git-style patch would over-slice into duplicate chunks.
    #[test]
    fn split_multi_file_patch_keeps_dash_after_diff_git_in_same_chunk() {
        let text = "diff --git a/x.js b/x.js\n\
                    --- a/x.js\n\
                    +++ b/x.js\n\
                    @@ -1 +1 @@\n\
                    -old\n\
                    +new\n";
        let chunks = split_multi_file_patch(text);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].starts_with("diff --git "));
        assert!(chunks[0].contains("--- a/x.js"));
    }

    /// **GPT audit regression (2026-05-15).** A mixed-format patch with
    /// a git rename-only section followed by a plain `---`/`+++` chunk
    /// for a DIFFERENT file must produce two chunks. Pre-fix the
    /// state-machine kept `in_git_header` true after the rename-only
    /// section (no `@@` to clear it), so the plain `--- a/x.js` got
    /// suppressed as the rename-only section's "own" header and the
    /// two sections collapsed into one chunk.
    ///
    /// The fix: track `rename from` and compare against the `---`
    /// path. Path mismatch → emit boundary.
    #[test]
    fn split_multi_file_patch_mixed_rename_only_then_plain() {
        let text = concat!(
            "diff --git a/old.js b/new.js\n",
            "similarity index 100%\n",
            "rename from old.js\n",
            "rename to new.js\n",
            "--- a/x.js\n",
            "+++ b/x.js\n",
            "@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
        );
        let chunks = split_multi_file_patch(text);
        assert_eq!(
            chunks.len(),
            2,
            "rename-only section + plain chunk for a different file must produce 2 chunks; \
             got chunks:\n{:?}",
            chunks
        );
        assert!(chunks[0].starts_with("diff --git "));
        assert!(chunks[0].contains("rename from old.js"));
        assert!(chunks[0].contains("rename to new.js"));
        assert!(
            !chunks[0].contains("--- a/x.js"),
            "first chunk must not bleed the plain section's old-side header"
        );
        assert!(chunks[1].starts_with("--- a/x.js"));
        assert!(chunks[1].contains("@@ -1 +1 @@"));
    }

    /// Companion to the mixed-format test: a rename+edit chunk where
    /// the `---` path DOES match `rename from` must stay as one chunk
    /// (not be over-sliced by the new path-mismatch rule).
    #[test]
    fn split_multi_file_patch_rename_with_edit_path_matches_stays_one_chunk() {
        let text = concat!(
            "diff --git a/old.js b/new.js\n",
            "similarity index 60%\n",
            "rename from old.js\n",
            "rename to new.js\n",
            "--- a/old.js\n",
            "+++ b/new.js\n",
            "@@ -1 +1 @@\n",
            "-old content\n",
            "+new content\n",
        );
        let chunks = split_multi_file_patch(text);
        assert_eq!(chunks.len(), 1, "rename+edit must remain a single chunk");
        assert!(chunks[0].contains("rename from old.js"));
        assert!(chunks[0].contains("--- a/old.js"));
        assert!(chunks[0].contains("@@ -1 +1 @@"));
    }

    // ── classify_patch_op contracts ──────────────────────────────────

    #[test]
    fn classify_modify() {
        let op = classify_patch_op("--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-old\n+new\n").unwrap();
        match op {
            PatchOp::Modify { rel_path, .. } => assert_eq!(rel_path, "x.js"),
            other => panic!("expected Modify, got {other:?}"),
        }
    }

    #[test]
    fn classify_add() {
        let op =
            classify_patch_op("--- /dev/null\n+++ b/new.js\n@@ -0,0 +1 @@\n+brand new\n").unwrap();
        match op {
            PatchOp::Add { rel_path, .. } => assert_eq!(rel_path, "new.js"),
            other => panic!("expected Add, got {other:?}"),
        }
    }

    #[test]
    fn classify_delete() {
        let op =
            classify_patch_op("--- a/doomed.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-rip\n").unwrap();
        match op {
            PatchOp::Delete { rel_path } => assert_eq!(rel_path, "doomed.js"),
            other => panic!("expected Delete, got {other:?}"),
        }
    }

    /// Filename mismatch without `rename from`/`rename to` headers is
    /// a malformed patch (git would have emitted rename headers for a
    /// real rename). The classifier rejects it with a clear pointer at
    /// a git-aware regenerate path.
    #[test]
    fn classify_filename_mismatch_without_rename_headers_is_rejected() {
        let err =
            classify_patch_op("--- a/old.js\n+++ b/new.js\n@@ -1 +1 @@\n-x\n+x\n").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("filename mismatch"), "got: {msg}");
        assert!(msg.contains("rename from"), "got: {msg}");
    }

    /// Rename-only chunk: both rename headers, no `@@` hunk. The
    /// classifier returns `PatchOp::Rename` without parsing hunks via
    /// `diffy::Patch::from_str` (which would fail on a header-less
    /// chunk).
    #[test]
    fn classify_rename_only() {
        let op = classify_patch_op(
            "diff --git a/old.js b/new.js\n\
             similarity index 100%\n\
             rename from old.js\n\
             rename to new.js\n",
        )
        .unwrap();
        match op {
            PatchOp::Rename { from, to } => {
                assert_eq!(from, "old.js");
                assert_eq!(to, "new.js");
            }
            other => panic!("expected Rename, got {other:?}"),
        }
    }

    /// Rename + edit chunk: both rename headers AND `@@` hunks. The
    /// classifier returns a single `PatchOp::RenameWithEdit` (not a
    /// `Rename + Modify` two-pass — see classifier docs for why).
    #[test]
    fn classify_rename_with_edit() {
        let chunk = concat!(
            "diff --git a/old.js b/new.js\n",
            "similarity index 60%\n",
            "rename from old.js\n",
            "rename to new.js\n",
            "--- a/old.js\n",
            "+++ b/new.js\n",
            "@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
        );
        let op = classify_patch_op(chunk).unwrap();
        match op {
            PatchOp::RenameWithEdit { from, to, .. } => {
                assert_eq!(from, "old.js");
                assert_eq!(to, "new.js");
            }
            other => panic!("expected RenameWithEdit, got {other:?}"),
        }
    }

    /// A `rename from`/`rename to` pair with identical paths is
    /// malformed — generators never emit it. Rejecting at classify
    /// time avoids the apply loop accidentally deleting the destination
    /// after writing it (since `nm_file_from == nm_file_to`).
    #[test]
    fn classify_rejects_identical_rename_from_to() {
        let err = classify_patch_op(
            "diff --git a/x.js b/x.js\n\
             similarity index 100%\n\
             rename from x.js\n\
             rename to x.js\n",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("identical"), "got: {msg}");
    }

    /// Partial rename headers (only one of `rename from`/`rename to`)
    /// is malformed. Generators emit both as a pair.
    #[test]
    fn classify_rejects_partial_rename_headers() {
        let err = classify_patch_op(
            "diff --git a/old.js b/new.js\n\
             similarity index 100%\n\
             rename from old.js\n",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("rename from") || msg.contains("rename to"),
            "got: {msg}"
        );
    }

    // ── verify_original_integrity contracts ──────────────────────────

    fn make_store_with_integrity(name: &str, version: &str, integrity: &str) -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        let store_dir = home
            .path()
            .join(".lpm")
            .join("store")
            .join("v1")
            .join(format!("{}@{}", name.replace(['/', '\\'], "+"), version));
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::write(store_dir.join("package.json"), r#"{"name":"x"}"#).unwrap();
        std::fs::write(store_dir.join(".integrity"), integrity).unwrap();
        home
    }

    fn fixture_store(home: &tempfile::TempDir) -> PackageStore {
        PackageStore::at(home.path().join(".lpm").join("store"))
    }

    #[test]
    fn verify_integrity_passes_on_match() {
        let home = make_store_with_integrity("lodash", "4.17.21", "sha512-aaa");
        let store = fixture_store(&home);
        assert!(verify_original_integrity(&store, "lodash", "4.17.21", "sha512-aaa").is_ok());
    }

    #[test]
    fn verify_integrity_fails_on_mismatch() {
        let home = make_store_with_integrity("lodash", "4.17.21", "sha512-aaa");
        let store = fixture_store(&home);
        let err =
            verify_original_integrity(&store, "lodash", "4.17.21", "sha512-DIFFERENT").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("drift"));
        assert!(msg.contains("sha512-aaa"));
        assert!(msg.contains("sha512-DIFFERENT"));
    }

    /// **Phase 66 confidence-followup S2.** A v2-only install — no v1
    /// dir; package bytes at `<store>/v2/links/<key>/node_modules/<name>/`
    /// alongside a sidecar `.lpm-link-meta.json` — must satisfy the
    /// patch baseline lookup. Pre-fix the resolver only walked v1 and
    /// reported "missing .integrity" for every v2-installed package.
    #[test]
    fn verify_integrity_passes_on_v2_link_entry() {
        use chrono::Utc;
        use lpm_store::v2::{LINK_META_SCHEMA_VERSION, LinkMeta, LinkMetaPlatform};

        let home = tempfile::tempdir().unwrap();
        // Materialize a v2 link entry: <store>/v2/links/<safe>@<ver>+<hash>/node_modules/<name>/
        let link_dir = home
            .path()
            .join(".lpm")
            .join("store")
            .join("v2")
            .join("links")
            .join("lodash@4.17.21+abcdef0123456789");
        let pkg_dir = link_dir.join("node_modules").join("lodash");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("package.json"), r#"{"name":"lodash"}"#).unwrap();

        // Sidecar drives the integrity lookup.
        let sidecar = LinkMeta {
            schema: LINK_META_SCHEMA_VERSION,
            graph_key: "lodash@4.17.21+abcdef0123456789".to_string(),
            graph_key_digest_hex: "abcdef0123456789".repeat(4),
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source_sri: "sha512-v2-baseline".to_string(),
            object_path: "objects/sha512-zzz".to_string(),
            deps: Vec::new(),
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "test".into(),
                cpu: "test".into(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        };
        sidecar.write_to(&link_dir).unwrap();

        let store = fixture_store(&home);
        // Match → Ok. The v2 lookup short-circuits before touching v1.
        assert!(
            verify_original_integrity(&store, "lodash", "4.17.21", "sha512-v2-baseline").is_ok(),
            "v2 sidecar baseline must satisfy the drift gate"
        );
        // Mismatch → drift error citing the sidecar's SRI, not v1's.
        let err =
            verify_original_integrity(&store, "lodash", "4.17.21", "sha512-OTHER").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("drift"),
            "error must mark this as drift: {msg}"
        );
        assert!(
            msg.contains("sha512-v2-baseline"),
            "drift error must surface the v2 baseline SRI: {msg}"
        );
    }

    #[test]
    fn verify_integrity_fails_when_no_store_entry_resolvable() {
        // Phase 66 confidence-followup S2: with the v2-aware lookup,
        // a v1 dir present but missing `.integrity` is treated as "no
        // resolvable baseline" — same outcome as v1+v2 both empty —
        // because `find_installed_package_baseline` only returns Some
        // when an integrity is recoverable. The user-facing error
        // wording shifted from "missing .integrity" to "no v1 or v2
        // store entry"; both convey the same actionable next step
        // ("re-install the package"), but the new message is correct
        // for both store layouts.
        let home = tempfile::tempdir().unwrap();
        let store_dir = home
            .path()
            .join(".lpm")
            .join("store")
            .join("v1")
            .join("lodash@4.17.21");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::write(store_dir.join("package.json"), r#"{"name":"lodash"}"#).unwrap();
        let store = fixture_store(&home);
        let err = verify_original_integrity(&store, "lodash", "4.17.21", "sha512-x").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("no v1 or v2 store entry"),
            "expected v2-aware error wording; got: {msg}"
        );
        assert!(
            msg.contains("lpm install"),
            "error must point user at the fix; got: {msg}"
        );
    }

    // ── apply_patch contracts ────────────────────────────────────────

    /// Build a `MaterializedPackage` whose destination is a fresh
    /// directory containing the given files. Used to drive the apply
    /// loop without needing the linker.
    fn fake_materialized(
        name: &str,
        version: &str,
        files: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, MaterializedPackage) {
        let dir = tempfile::tempdir().unwrap();
        for (rel, bytes) in files {
            let p = dir.path().join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, bytes).unwrap();
        }
        let m = MaterializedPackage {
            name: name.to_string(),
            version: version.to_string(),
            destination: dir.path().to_path_buf(),
        };
        (dir, m)
    }

    /// Set up a fixture HOME with a store entry containing the given
    /// files plus a `.integrity` file. Returns (home, store, integrity).
    fn fake_store_entry(
        name: &str,
        version: &str,
        files: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, PackageStore, String) {
        let home = tempfile::tempdir().unwrap();
        let safe = name.replace(['/', '\\'], "+");
        let store_dir = home
            .path()
            .join(".lpm")
            .join("store")
            .join("v1")
            .join(format!("{safe}@{version}"));
        std::fs::create_dir_all(&store_dir).unwrap();
        for (rel, bytes) in files {
            let p = store_dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, bytes).unwrap();
        }
        let integrity = "sha512-fixture-baseline".to_string();
        std::fs::write(store_dir.join(".integrity"), &integrity).unwrap();
        let store = fixture_store(&home);
        (home, store, integrity)
    }

    fn write_patch(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::Builder::new()
            .suffix(".patch")
            .tempfile()
            .unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn apply_modify_writes_patched_content() {
        let (_home, store, integrity) =
            fake_store_entry("lodash", "4.17.21", &[("x.js", b"line1\nline2\nline3\n")]);
        let (_dir, m) =
            fake_materialized("lodash", "4.17.21", &[("x.js", b"line1\nline2\nline3\n")]);
        let patch = write_patch(
            "--- a/x.js\n+++ b/x.js\n@@ -1,3 +1,3 @@\n line1\n-line2\n+lineTWO\n line3\n",
        );

        let result =
            apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap();
        assert_eq!(result.files_modified, 1);
        assert_eq!(result.files_added, 0);
        assert_eq!(result.files_deleted, 0);
        let written = std::fs::read_to_string(m.destination.join("x.js")).unwrap();
        assert_eq!(written, "line1\nlineTWO\nline3\n");
    }

    #[test]
    fn apply_is_idempotent() {
        let (_home, store, integrity) =
            fake_store_entry("lodash", "4.17.21", &[("x.js", b"a\nb\n")]);
        let (_dir, m) = fake_materialized("lodash", "4.17.21", &[("x.js", b"a\nb\n")]);
        let patch = write_patch("--- a/x.js\n+++ b/x.js\n@@ -1,2 +1,2 @@\n a\n-b\n+B\n");

        let r1 = apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap();
        assert_eq!(r1.files_modified, 1);
        // Second apply finds the destination already matches; nothing
        // happens. Most importantly, it doesn't error.
        let r2 = apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap();
        assert_eq!(r2.files_modified, 0);
        // Bytes unchanged after the second pass.
        let written = std::fs::read_to_string(m.destination.join("x.js")).unwrap();
        assert_eq!(written, "a\nB\n");
    }

    #[test]
    fn apply_handles_add_op() {
        let (_home, store, integrity) =
            fake_store_entry("lodash", "4.17.21", &[("x.js", b"existing\n")]);
        let (_dir, m) = fake_materialized("lodash", "4.17.21", &[("x.js", b"existing\n")]);
        let patch = write_patch("--- /dev/null\n+++ b/new.js\n@@ -0,0 +1 @@\n+brand new\n");

        let result =
            apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap();
        assert_eq!(result.files_added, 1);
        let written = std::fs::read_to_string(m.destination.join("new.js")).unwrap();
        assert_eq!(written, "brand new\n");
    }

    #[test]
    fn apply_handles_delete_op() {
        // Store baseline still has the file (drift gate passed); apply
        // unlinks the destination copy.
        let (_home, store, integrity) =
            fake_store_entry("lodash", "4.17.21", &[("doomed.js", b"rip\n")]);
        let (_dir, m) = fake_materialized("lodash", "4.17.21", &[("doomed.js", b"rip\n")]);
        let patch = write_patch("--- a/doomed.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-rip\n");

        let result =
            apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap();
        assert_eq!(result.files_deleted, 1);
        assert!(
            !m.destination.join("doomed.js").exists(),
            "delete op must unlink the file"
        );
    }

    #[test]
    fn apply_delete_is_idempotent() {
        let (_home, store, integrity) =
            fake_store_entry("lodash", "4.17.21", &[("doomed.js", b"rip\n")]);
        let (_dir, m) = fake_materialized("lodash", "4.17.21", &[("doomed.js", b"rip\n")]);
        let patch = write_patch("--- a/doomed.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-rip\n");

        let _ = apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap();
        // File is gone; second apply does nothing.
        let r2 = apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap();
        assert_eq!(r2.files_deleted, 0);
    }

    #[test]
    fn apply_fails_on_drift() {
        let (_home, store, _integrity) = fake_store_entry("lodash", "4.17.21", &[("x.js", b"a\n")]);
        let (_dir, m) = fake_materialized("lodash", "4.17.21", &[("x.js", b"a\n")]);
        let patch = write_patch("--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-a\n+A\n");

        // Pretend the patch was authored against a different baseline.
        let err = apply_patch(
            &[&m],
            patch.path(),
            "sha512-AUTHOR-TIME-DIFFERENT",
            &store,
            "lodash",
            "4.17.21",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("drift"));
    }

    #[test]
    fn apply_fails_on_fuzzy_hunk() {
        // Store contains different context than the patch was authored
        // against. Strict apply must reject.
        let (_home, store, integrity) =
            fake_store_entry("lodash", "4.17.21", &[("x.js", b"alpha\nbravo\ncharlie\n")]);
        let (_dir, m) =
            fake_materialized("lodash", "4.17.21", &[("x.js", b"alpha\nbravo\ncharlie\n")]);
        // Patch was authored against `apple\nbanana\ncherry\n`
        let patch = write_patch(
            "--- a/x.js\n+++ b/x.js\n@@ -1,3 +1,3 @@\n apple\n-banana\n+BANANA\n cherry\n",
        );

        let err =
            apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("hunk failed") || msg.contains("regenerate"));
    }

    #[test]
    fn apply_rejects_internal_file_modification() {
        let (_home, store, integrity) = fake_store_entry("lodash", "4.17.21", &[("x.js", b"a\n")]);
        let (_dir, m) = fake_materialized("lodash", "4.17.21", &[("x.js", b"a\n")]);
        // Hand-crafted patch that names a sentinel.
        let patch = write_patch(
            "--- a/.integrity\n+++ b/.integrity\n@@ -1 +1 @@\n-sha512-old\n+sha512-attacker\n",
        );

        let err =
            apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap_err();
        assert!(format!("{err}").contains("LPM-internal"));
    }

    #[test]
    fn apply_rejects_path_traversal() {
        let (_home, store, integrity) = fake_store_entry("lodash", "4.17.21", &[("x.js", b"a\n")]);
        let (_dir, m) = fake_materialized("lodash", "4.17.21", &[("x.js", b"a\n")]);
        let patch = write_patch("--- a/../escape.js\n+++ b/../escape.js\n@@ -1 +1 @@\n-a\n+b\n");

        let err =
            apply_patch(&[&m], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap_err();
        assert!(format!("{err}").contains("illegal path"));
    }

    // ── apply rename contracts ───────────────────────────────────────

    /// A rename-only chunk moves the destination file from `from` to
    /// `to`, with baseline bytes preserved at the new path.
    #[test]
    fn apply_rename_moves_file() {
        let (_home, store, integrity) = fake_store_entry(
            "pkg",
            "1.0.0",
            &[("src/old.js", b"contents\n"), ("keep.js", b"k\n")],
        );
        let (_dir, m) = fake_materialized(
            "pkg",
            "1.0.0",
            &[("src/old.js", b"contents\n"), ("keep.js", b"k\n")],
        );
        let patch = write_patch(
            "diff --git a/src/old.js b/src/new.js\n\
             similarity index 100%\n\
             rename from src/old.js\n\
             rename to src/new.js\n",
        );

        let result = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap();
        assert_eq!(result.files_added, 1);
        assert_eq!(result.files_deleted, 1);
        assert!(!m.destination.join("src/old.js").exists());
        assert_eq!(
            std::fs::read_to_string(m.destination.join("src/new.js")).unwrap(),
            "contents\n",
            "destination must carry the baseline bytes"
        );
    }

    /// A rename-only chunk creates the destination's parent directory
    /// if it doesn't exist (the rename may target a new subdirectory).
    #[test]
    fn apply_rename_creates_destination_parent_dir() {
        let (_home, store, integrity) =
            fake_store_entry("pkg", "1.0.0", &[("old.js", b"contents\n")]);
        let (_dir, m) = fake_materialized("pkg", "1.0.0", &[("old.js", b"contents\n")]);
        let patch = write_patch(
            "diff --git a/old.js b/lib/nested/new.js\n\
             similarity index 100%\n\
             rename from old.js\n\
             rename to lib/nested/new.js\n",
        );

        apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap();
        assert!(m.destination.join("lib/nested/new.js").exists());
        assert!(!m.destination.join("old.js").exists());
    }

    /// A rename+edit chunk: destination ends up with HUNK-MODIFIED
    /// bytes (not baseline). Hunk is applied to the baseline pre-image
    /// from the store, NOT to whatever the destination currently holds.
    #[test]
    fn apply_rename_with_edit_writes_patched_bytes() {
        let (_home, store, integrity) =
            fake_store_entry("pkg", "1.0.0", &[("src/old.js", b"line1\nline2\n")]);
        let (_dir, m) = fake_materialized("pkg", "1.0.0", &[("src/old.js", b"line1\nline2\n")]);
        // Context lines in unified diff start with a literal space —
        // Rust string-line-continuation strips leading whitespace, so
        // use `concat!()` instead of `\<newline>` here.
        let patch = write_patch(concat!(
            "diff --git a/src/old.js b/src/new.js\n",
            "similarity index 60%\n",
            "rename from src/old.js\n",
            "rename to src/new.js\n",
            "--- a/src/old.js\n",
            "+++ b/src/new.js\n",
            "@@ -1,2 +1,2 @@\n",
            " line1\n",
            "-line2\n",
            "+lineTWO\n",
        ));

        apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap();
        assert!(!m.destination.join("src/old.js").exists());
        assert_eq!(
            std::fs::read_to_string(m.destination.join("src/new.js")).unwrap(),
            "line1\nlineTWO\n"
        );
    }

    /// Rename idempotency: second apply finds source gone and
    /// destination already carrying target bytes → zero writes.
    #[test]
    fn apply_rename_is_idempotent() {
        let (_home, store, integrity) =
            fake_store_entry("pkg", "1.0.0", &[("old.js", b"contents\n")]);
        let (_dir, m) = fake_materialized("pkg", "1.0.0", &[("old.js", b"contents\n")]);
        let patch = write_patch(
            "diff --git a/old.js b/new.js\n\
             similarity index 100%\n\
             rename from old.js\n\
             rename to new.js\n",
        );

        let r1 = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap();
        assert!(r1.touched_anything(), "first apply must do work");

        let r2 = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap();
        assert_eq!(r2.files_added, 0);
        assert_eq!(r2.files_deleted, 0);
        assert_eq!(r2.files_modified, 0);
        assert!(
            !r2.touched_anything(),
            "rerun must be a structural no-op (idempotency contract)"
        );
    }

    /// **Acceptance criterion.** Idempotency must hold for RenameWithEdit
    /// as well — second run after rename+edit must short-circuit BEFORE
    /// any write. The single-variant design (vs `Rename + Modify`
    /// two-pass) makes this enforceable: byte-comparison precedes the
    /// `write_breaking_hardlink` call.
    ///
    /// On Unix we also assert the destination's inode is unchanged
    /// between runs — `write_breaking_hardlink` does `remove_file` then
    /// `write`, which would mint a new inode, so a stable inode is a
    /// strong "no write happened" signal.
    #[test]
    fn apply_rename_with_edit_is_idempotent() {
        let (_home, store, integrity) =
            fake_store_entry("pkg", "1.0.0", &[("src/old.js", b"line1\nline2\n")]);
        let (_dir, m) = fake_materialized("pkg", "1.0.0", &[("src/old.js", b"line1\nline2\n")]);
        let patch = write_patch(concat!(
            "diff --git a/src/old.js b/src/new.js\n",
            "similarity index 60%\n",
            "rename from src/old.js\n",
            "rename to src/new.js\n",
            "--- a/src/old.js\n",
            "+++ b/src/new.js\n",
            "@@ -1,2 +1,2 @@\n",
            " line1\n",
            "-line2\n",
            "+lineTWO\n",
        ));

        let r1 = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap();
        assert!(r1.touched_anything());

        let dest = m.destination.join("src/new.js");
        #[cfg(unix)]
        let inode_before = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&dest).unwrap().ino()
        };

        let r2 = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap();
        assert_eq!(
            r2.files_added, 0,
            "files_added must be 0 on idempotent rerun"
        );
        assert_eq!(
            r2.files_deleted, 0,
            "files_deleted must be 0 on idempotent rerun"
        );
        assert!(!r2.touched_anything(), "rerun must be a structural no-op");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let inode_after = std::fs::metadata(&dest).unwrap().ino();
            assert_eq!(
                inode_before, inode_after,
                "destination inode changed — write_breaking_hardlink ran despite idempotency"
            );
        }

        // Final post-edit bytes still at the destination.
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "line1\nlineTWO\n");
    }

    /// Partial prior run: destination already has target bytes but the
    /// source path is still in `node_modules`. The apply path completes
    /// the rename by removing the source, without rewriting the
    /// destination.
    #[test]
    fn apply_rename_cleans_up_orphan_source() {
        let (_home, store, integrity) =
            fake_store_entry("pkg", "1.0.0", &[("old.js", b"contents\n")]);
        // Destination already carries the target bytes, but source
        // wasn't cleaned up — simulate a partial prior run.
        let (_dir, m) = fake_materialized(
            "pkg",
            "1.0.0",
            &[("old.js", b"contents\n"), ("new.js", b"contents\n")],
        );
        let patch = write_patch(
            "diff --git a/old.js b/new.js\n\
             similarity index 100%\n\
             rename from old.js\n\
             rename to new.js\n",
        );

        let r = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap();
        assert_eq!(
            r.files_added, 0,
            "destination already had target bytes — no write"
        );
        assert_eq!(r.files_deleted, 1, "source still existed — must be removed");
        assert!(!m.destination.join("old.js").exists());
        assert!(m.destination.join("new.js").exists());
    }

    /// `rename to .integrity` would mutate an LPM-internal sentinel.
    /// Refuse before touching the filesystem.
    #[test]
    fn apply_rename_rejects_sentinel_target() {
        let (_home, store, integrity) = fake_store_entry("pkg", "1.0.0", &[("attack.js", b"x\n")]);
        let (_dir, m) = fake_materialized("pkg", "1.0.0", &[("attack.js", b"x\n")]);
        let patch = write_patch(
            "diff --git a/attack.js b/.integrity\n\
             similarity index 100%\n\
             rename from attack.js\n\
             rename to .integrity\n",
        );

        let err = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("LPM-internal"), "got: {msg}");
    }

    /// `rename to ../escape.js` would escape the package root. Refuse.
    /// (Path-traversal also covers `rename from` paths, but the
    /// destination is the more security-sensitive side because that's
    /// where bytes are written.)
    #[test]
    fn apply_rename_rejects_path_traversal_target() {
        let (_home, store, integrity) = fake_store_entry("pkg", "1.0.0", &[("x.js", b"x\n")]);
        let (_dir, m) = fake_materialized("pkg", "1.0.0", &[("x.js", b"x\n")]);
        let patch = write_patch(
            "diff --git a/x.js b/../escape.js\n\
             similarity index 100%\n\
             rename from x.js\n\
             rename to ../escape.js\n",
        );

        let err = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("illegal path"), "got: {msg}");
    }

    /// Source path absent from the pristine store baseline means the
    /// patch was authored against a different version of the package.
    /// Refuse with a regenerate hint — distinct from the whole-tree
    /// `originalIntegrity` drift gate, this fires at chunk-apply time.
    #[test]
    fn apply_rename_fails_on_missing_baseline_source() {
        // Store has the destination's pristine path but NOT the source.
        let (_home, store, integrity) = fake_store_entry("pkg", "1.0.0", &[("other.js", b"x\n")]);
        let (_dir, m) = fake_materialized("pkg", "1.0.0", &[("other.js", b"x\n")]);
        let patch = write_patch(
            "diff --git a/never-existed.js b/renamed.js\n\
             similarity index 100%\n\
             rename from never-existed.js\n\
             rename to renamed.js\n",
        );

        let err = apply_patch(&[&m], patch.path(), &integrity, &store, "pkg", "1.0.0").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("never-existed.js"), "got: {msg}");
        assert!(
            msg.contains("stale") || msg.contains("regenerate"),
            "got: {msg}"
        );
        assert!(msg.contains("lpm patch pkg@1.0.0"), "got: {msg}");
    }

    #[test]
    fn apply_fails_when_locations_empty() {
        let (_home, store, integrity) = fake_store_entry("lodash", "4.17.21", &[("x.js", b"a\n")]);
        let patch = write_patch("--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-a\n+A\n");

        let err =
            apply_patch(&[], patch.path(), &integrity, &store, "lodash", "4.17.21").unwrap_err();
        assert!(format!("{err}").contains("not present in node_modules"));
    }

    #[test]
    fn apply_fails_when_patch_file_unreadable() {
        let (_home, store, integrity) = fake_store_entry("lodash", "4.17.21", &[("x.js", b"a\n")]);
        let (_dir, m) = fake_materialized("lodash", "4.17.21", &[("x.js", b"a\n")]);
        let err = apply_patch(
            &[&m],
            Path::new("/no/such/patch.patch"),
            &integrity,
            &store,
            "lodash",
            "4.17.21",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("unreadable"));
    }
}
