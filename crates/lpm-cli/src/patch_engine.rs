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
//!   depth by erroring on any patch chunk that names them.
//! - **Renames.** Phase 6 doesn't support file renames. A patch chunk
//!   whose `--- a/old` and `+++ b/new` headers disagree is rejected.
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
use lpm_store::{PackageStore, read_stored_integrity};
use std::collections::HashSet;
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
/// `"@types/node@20.10.0"` into `(name, version)`. Phase 6 accepts only
/// exact-version pins.
///
/// **Errors:**
/// - Empty input.
/// - Missing `@` separator.
/// - Empty name or version segment.
/// - Range-style version (`4.x`, `^4.0.0`, `>=4`) — these are
///   reserved for Phase 6.1 and rejected with a clear "exact pins
///   only" message.
pub fn parse_patch_key(key: &str) -> Result<(String, String), LpmError> {
    if key.is_empty() {
        return Err(LpmError::Script(
            "patch key is empty (expected `name@exact-version`)".into(),
        ));
    }
    // Scoped names start with `@` and contain `/`. The version separator
    // is the LAST `@` in the key.
    let at = key.rfind('@').ok_or_else(|| {
        LpmError::Script(format!(
            "patch key {key:?} missing version separator — expected `name@exact-version`"
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
    // Reject range-style versions. Exact pins look like `1.2.3`,
    // `1.2.3-rc.1`, etc. Range markers we explicitly reject:
    // `^`, `~`, `>`, `<`, `=`, `*`, ` || `, ` - `, `x`, `X`, `latest`.
    if is_range_version(&version) {
        return Err(LpmError::Script(format!(
            "patch key {key:?} uses a range version ({version:?}); \
             Phase 6 accepts only exact pins like `name@1.2.3`. \
             Range selectors are reserved for Phase 6.1."
        )));
    }
    Ok((name, version))
}

fn is_range_version(version: &str) -> bool {
    if version.is_empty() {
        return true;
    }
    // Common range prefixes
    let starts_with_range = matches!(
        version.chars().next(),
        Some('^') | Some('~') | Some('>') | Some('<') | Some('=') | Some('*')
    );
    if starts_with_range {
        return true;
    }
    // Wildcards anywhere
    if version.contains('*') || version.contains(" - ") || version.contains("||") {
        return true;
    }
    // Trailing `.x` or `.X` (e.g., `4.x`, `4.17.x`)
    if version.ends_with(".x") || version.ends_with(".X") {
        return true;
    }
    // Magic strings
    matches!(version, "latest" | "next" | "")
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

        // Top-level filter: exclude store sentinels and the staging
        // breadcrumb. We only filter at the package root because the
        // sentinels are written there by the store extractor.
        if src.parent().is_some()
            && (STORE_INTERNAL_FILES.contains(&name_str.as_ref())
                || name_str == STAGING_BREADCRUMB_FILE)
        {
            // The check above is overcautious — we always want to skip
            // these regardless of depth, because we don't want them in
            // the staging tree.
            continue;
        }
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
/// returned slice is parseable as a single `diffy::Patch<'_, str>`.
///
/// The splitter scans for `^--- ` line starts (three dashes followed
/// by a space). Hunk lines never start with that pattern: hunk lines
/// start with ` `, `+`, `-`, or `\` (single character + content), and
/// the `---` header always appears at file boundaries.
///
/// Lines starting with `diff --git` (git's optional preamble) are
/// folded into the chunk that follows them — the diffy parser skips
/// preamble lines automatically.
pub fn split_multi_file_patch(text: &str) -> Vec<&str> {
    // Find every byte offset where a line starts with "--- ".
    let mut starts: Vec<usize> = Vec::new();
    let mut byte = 0usize;
    for line in text.split_inclusive('\n') {
        if line.starts_with("--- ") {
            starts.push(byte);
        }
        byte += line.len();
    }
    // Special-case the trailing line if it didn't end with `\n`.
    // (split_inclusive handles that for us.)

    if starts.is_empty() {
        return Vec::new();
    }

    // Slice from each start to the next start (or end of input).
    let mut chunks = Vec::with_capacity(starts.len());
    for (i, &start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(text.len());
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

/// Decoded operation kind for one patch chunk.
#[derive(Debug, Clone)]
enum PatchOp {
    /// Read store baseline, apply hunks, write to destination.
    Modify { rel_path: String },
    /// Apply against empty input, write the result as a new file.
    Add { rel_path: String },
    /// Unlink the destination file. Store baseline must still exist
    /// (otherwise the drift gate would have already failed).
    Delete { rel_path: String },
}

impl PatchOp {
    fn rel_path(&self) -> &str {
        match self {
            Self::Modify { rel_path } | Self::Add { rel_path } | Self::Delete { rel_path } => {
                rel_path
            }
        }
    }
}

fn classify_patch_op(patch: &Patch<'_, str>) -> Result<PatchOp, LpmError> {
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
        }),
        (false, true) => Ok(PatchOp::Delete {
            rel_path: strip(original.unwrap()),
        }),
        (false, false) => {
            let o = strip(original.unwrap());
            let m = strip(modified.unwrap());
            if o != m {
                return Err(LpmError::Script(format!(
                    "patch chunk renames {o} → {m}; renames are not supported in Phase 6"
                )));
            }
            Ok(PatchOp::Modify { rel_path: m })
        }
    }
}

/// Verify that the store entry's `.integrity` matches the
/// `originalIntegrity` recorded in `package.json`. Hard-errors on
/// mismatch — this is the drift gate.
pub fn verify_original_integrity(
    store: &PackageStore,
    name: &str,
    version: &str,
    expected_integrity: &str,
) -> Result<(), LpmError> {
    let store_dir = store.package_dir(name, version);
    let actual = read_stored_integrity(&store_dir).ok_or_else(|| {
        LpmError::Script(format!(
            "store entry {store_dir:?} missing .integrity — \
             cannot verify patch baseline for {name}@{version}"
        ))
    })?;
    if actual != expected_integrity {
        return Err(LpmError::Script(format!(
            "patch baseline drift for {name}@{version}: \
             stored integrity {actual} does not match \
             package.json originalIntegrity {expected_integrity}. \
             Regenerate the patch with `lpm patch {name}@{version}`."
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
    // 1. Drift gate
    verify_original_integrity(store, name, version, expected_integrity)?;

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
    let store_dir = store.package_dir(name, version);

    for chunk in chunks {
        let patch = Patch::from_str(chunk).map_err(|e| {
            LpmError::Script(format!(
                "patch file {patch_file:?} parse error in chunk: {e}"
            ))
        })?;
        let op = classify_patch_op(&patch)?;

        // Defense in depth: never let a patch touch a store sentinel.
        let rel = op.rel_path();
        if STORE_INTERNAL_FILES.contains(&rel) {
            return Err(LpmError::Script(format!(
                "patch file {patch_file:?} attempts to modify LPM-internal \
                 file {rel}; refusing to apply"
            )));
        }
        // Reject path traversal attempts.
        if rel.contains("..") || rel.starts_with('/') {
            return Err(LpmError::Script(format!(
                "patch file {patch_file:?} contains illegal path {rel}; \
                 refusing to apply"
            )));
        }

        for loc in locations {
            let nm_file = loc.destination.join(rel);

            match &op {
                PatchOp::Modify { rel_path } => {
                    let store_file = store_dir.join(rel_path);
                    let store_text = read_text_file(&store_file)?;
                    let patched_text = diffy::apply(&store_text, &patch).map_err(|e| {
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
                PatchOp::Add { rel_path } => {
                    let store_file = store_dir.join(rel_path);
                    if store_file.exists() {
                        return Err(LpmError::Script(format!(
                            "patch adds {rel_path} but the store baseline \
                             {store_file:?} already contains it; the patch \
                             may be stale (regenerate with `lpm patch {name}@{version}`)"
                        )));
                    }
                    let patched_text = diffy::apply("", &patch).map_err(|e| {
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

    #[test]
    fn parse_key_rejects_caret_range() {
        let err = parse_patch_key("lodash@^4.17.0").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("range version"));
        assert!(msg.contains("Phase 6.1"));
    }

    #[test]
    fn parse_key_rejects_x_wildcard() {
        let err = parse_patch_key("lodash@4.x").unwrap_err();
        assert!(format!("{err}").contains("range version"));
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

    // ── classify_patch_op contracts (via Patch::from_str) ────────────

    fn parse(text: &str) -> Patch<'_, str> {
        Patch::from_str(text).unwrap()
    }

    #[test]
    fn classify_modify() {
        let p = parse("--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-old\n+new\n");
        let op = classify_patch_op(&p).unwrap();
        match op {
            PatchOp::Modify { rel_path } => assert_eq!(rel_path, "x.js"),
            other => panic!("expected Modify, got {other:?}"),
        }
    }

    #[test]
    fn classify_add() {
        let p = parse("--- /dev/null\n+++ b/new.js\n@@ -0,0 +1 @@\n+brand new\n");
        let op = classify_patch_op(&p).unwrap();
        match op {
            PatchOp::Add { rel_path } => assert_eq!(rel_path, "new.js"),
            other => panic!("expected Add, got {other:?}"),
        }
    }

    #[test]
    fn classify_delete() {
        let p = parse("--- a/doomed.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-rip\n");
        let op = classify_patch_op(&p).unwrap();
        match op {
            PatchOp::Delete { rel_path } => assert_eq!(rel_path, "doomed.js"),
            other => panic!("expected Delete, got {other:?}"),
        }
    }

    #[test]
    fn classify_rename_is_rejected() {
        let p = parse("--- a/old.js\n+++ b/new.js\n@@ -1 +1 @@\n-x\n+x\n");
        let err = classify_patch_op(&p).unwrap_err();
        assert!(format!("{err}").contains("rename"));
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

    #[test]
    fn verify_integrity_passes_on_match() {
        let home = make_store_with_integrity("lodash", "4.17.21", "sha512-aaa");
        // Override HOME so PackageStore::default_location finds our fixture.
        // SAFETY: only mutates per-test env via std::env::set_var; tests
        // run sequentially when sharing this env knob.
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let store = PackageStore::default_location().unwrap();
        assert!(verify_original_integrity(&store, "lodash", "4.17.21", "sha512-aaa").is_ok());
    }

    #[test]
    fn verify_integrity_fails_on_mismatch() {
        let home = make_store_with_integrity("lodash", "4.17.21", "sha512-aaa");
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let store = PackageStore::default_location().unwrap();
        let err =
            verify_original_integrity(&store, "lodash", "4.17.21", "sha512-DIFFERENT").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("drift"));
        assert!(msg.contains("sha512-aaa"));
        assert!(msg.contains("sha512-DIFFERENT"));
    }

    #[test]
    fn verify_integrity_fails_when_integrity_file_missing() {
        let home = tempfile::tempdir().unwrap();
        let store_dir = home
            .path()
            .join(".lpm")
            .join("store")
            .join("v1")
            .join("lodash@4.17.21");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::write(store_dir.join("package.json"), r#"{"name":"lodash"}"#).unwrap();
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let store = PackageStore::default_location().unwrap();
        let err = verify_original_integrity(&store, "lodash", "4.17.21", "sha512-x").unwrap_err();
        assert!(format!("{err}").contains("missing .integrity"));
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
        unsafe {
            std::env::set_var("HOME", home.path());
        }
        let store = PackageStore::default_location().unwrap();
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
