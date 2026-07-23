//! Loader for per-project sandbox configuration: the
//! `package.json > lpm > scripts > sandboxWriteDirs` escape hatch.
//!
//! This is the ONE place the shape of that key is read from disk.
//! `execute_script` calls [`load_sandbox_write_dirs`] once per
//! install and threads the resolved absolute paths into every
//! per-package [`crate::SandboxSpec`].
//!
//! # Path validation
//!
//! Reading the key unvalidated is a trust-boundary hole: a malicious
//! repo can ship `package.json > lpm > scripts > sandboxWriteDirs =
//! ["/"]` or `["/Users/foo/.ssh"]` and those absolute paths were
//! accepted verbatim without validation. Four checks apply:
//!
//! 1. **Dangerous-root denylist** (unconditional): reject any entry
//!    that resolves to `/`, `/etc`, `/var/run`, `/run`,
//!    `$HOME/.ssh`, `$HOME/.aws`, or `$HOME/.lpm` on POSIX, or
//!    `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`,
//!    `C:\ProgramData`, or any bare drive root on Windows (plus the
//!    same home-rooted suffixes). The denylist has final veto over
//!    the allowlist — an entry that IS in the user allowlist is
//!    still rejected if it lands in a dangerous root.
//! 2. **Traversal-escape check** (unconditional, applies only to
//!    authored-as-relative entries): after logical `..` collapse,
//!    relative entries must stay inside `project_dir`. `"../etc"` is
//!    rejected regardless of the user allowlist state.
//! 3. **Containment intersection** (unconditional): every entry must
//!    resolve under the canonical `project_dir` OR one of the
//!    canonical user-allowlist roots (`~/.lpm/config.toml >
//!    max-sandbox-write-roots`).
//! 4. **Filesystem-indirection check** (unconditional): every
//!    existing component below the authorized root must be a real
//!    directory, never a symlink, junction, or reparse point. Missing
//!    suffixes are appended only after their nearest
//!    existing ancestor passes the same check.
//!
//! # Empty-allowlist tightening
//!
//! Previously the empty allowlist was treated as "no constraint": a
//! `package.json` authored as `sandboxWriteDirs: ["~/Documents"]` was
//! accepted verbatim. Because install scripts come from untrusted
//! dependencies, that meant a one-line `package.json` change could
//! hand dependency install scripts write access to user data the
//! dangerous-root denylist does not cover (`~/.bashrc`, `~/.config`,
//! `~/Documents`, `~/.local/share`, …). The empty case now means
//! "no opt-in": absolute paths outside `project_dir` are rejected
//! unless explicitly covered by `max-sandbox-write-roots`. Relative
//! paths are unaffected (already constrained by Step 2 to stay
//! inside `project_dir`).

use crate::SandboxError;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

/// Read `package.json > lpm > scripts > sandboxWriteDirs` and return
/// filesystem-resolved effective paths, rejecting entries that would
/// escape project_dir, match a dangerous-root denylist, fall outside
/// the caller-supplied user allowlist, or traverse filesystem links.
///
/// # Parameters
///
/// - `package_json`: project manifest path.
/// - `project_dir`: project root; relative entries resolve against
///   this, and relative-entry traversal is checked against it.
/// - `user_allowlist`: absolute paths from
///   `~/.lpm/config.toml > max-sandbox-write-roots`. Every entry
///   must descend from `project_dir` or one of these paths.
///   When the allowlist is empty, only paths under `project_dir`
///   are accepted — see the module-level "Empty-allowlist tightening"
///   note for the security rationale.
/// - `home_dir`: the user's `$HOME`. Optional — if `None`, the
///   `$HOME/.ssh`, `$HOME/.aws`, `$HOME/.lpm` branches of the
///   dangerous-root denylist are skipped (the absolute-path
///   branches still run). Callers in production should always pass
///   `Some(dirs::home_dir())`; `None` exists for tests that don't
///   want to make assertions about a real home dir.
///
/// # Resolution rules
///
/// - Missing `package.json`, missing `lpm` section, missing `scripts`
///   key, or missing `sandboxWriteDirs` array: return an empty `Vec`
///   — the absence of the key means "no extras", not an error.
/// - The key must be a JSON array of strings. A non-array value or
///   non-string element surfaces as [`SandboxError::InvalidSpec`] so
///   the user sees a clear typo-level error rather than a silent
///   ignore.
/// - Each string entry: if relative, joined onto the canonical
///   `project_dir`; absolute entries are rebased onto the canonical
///   project or allowlist root that authorizes them. Existing targets
///   are canonicalized. Missing targets use their canonical nearest
///   existing ancestor plus a validated normal-component suffix.
///   Downstream backends receive this effective path, never the
///   unchecked manifest spelling.
/// - Empty strings are rejected: they would resolve to `project_dir`
///   itself, which is already covered by the read allow-list and
///   would silently widen the write set to the entire project tree.
/// - Entries that fail validation (dangerous denylist, traversal
///   escape, containment intersection, or filesystem indirection) surface as
///   [`SandboxError::InvalidSpec`] with an error naming both the
///   project file + the user config source, so the user can tell
///   which side needs fixing.
pub fn load_sandbox_write_dirs(
    package_json: &Path,
    project_dir: &Path,
    user_allowlist: &[PathBuf],
    home_dir: Option<&Path>,
) -> Result<Vec<PathBuf>, SandboxError> {
    let raw = match lpm_common::read_text_file_capped(
        package_json,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(s) => s,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(Vec::new()),
        Err(e) => {
            return Err(SandboxError::InvalidSpec {
                reason: format!("failed to read {}: {e}", package_json.display()),
            });
        }
    };

    let json: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| SandboxError::InvalidSpec {
            reason: format!("{} is not valid JSON: {e}", package_json.display()),
        })?;

    let entries = match json
        .get("lpm")
        .and_then(|v| v.get("scripts"))
        .and_then(|v| v.get("sandboxWriteDirs"))
    {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    let arr = entries
        .as_array()
        .ok_or_else(|| SandboxError::InvalidSpec {
            reason: format!(
                "{}: `lpm.scripts.sandboxWriteDirs` must be an array of strings, got {}",
                package_json.display(),
                entries
            ),
        })?;
    let Some(first_entry) = arr.first() else {
        return Ok(Vec::new());
    };
    let first_authored = first_entry.as_str().unwrap_or("<non-string>");

    let project_root = AuthorizedRoot::resolve(project_dir).map_err(|failure| {
        invalid_root_error(package_json, 0, first_authored, "project_dir", failure)
    })?;
    let user_roots: Vec<(PathBuf, Result<AuthorizedRoot, PathValidationFailure>)> = user_allowlist
        .iter()
        .map(|path| (logical_normalize(path), AuthorizedRoot::resolve(path)))
        .collect();
    let effective_home = home_dir
        .map(AuthorizedRoot::resolve)
        .transpose()
        .map_err(|failure| {
            invalid_root_error(package_json, 0, first_authored, "home_dir", failure)
        })?
        .map(|root| root.effective);

    let mut resolved = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| SandboxError::InvalidSpec {
            reason: format!(
                "{}: `lpm.scripts.sandboxWriteDirs[{i}]` must be a string, got {}",
                package_json.display(),
                item
            ),
        })?;
        if s.is_empty() {
            return Err(SandboxError::InvalidSpec {
                reason: format!(
                    "{}: `lpm.scripts.sandboxWriteDirs[{i}]` is empty; an empty entry \
                     would widen writes to the whole project",
                    package_json.display(),
                ),
            });
        }
        if let Some((idx, ch)) = s.char_indices().find(|(_, c)| {
            let code = *c as u32;
            code <= 0x1F || code == 0x7F || (0x80..=0x9F).contains(&code)
        }) {
            return Err(SandboxError::InvalidSpec {
                reason: format!(
                    "{}: `lpm.scripts.sandboxWriteDirs[{i}]` contains a control character \
                     at byte {idx} (U+{cp:04X}); paths with embedded control bytes are \
                     refused — they have no legitimate filesystem meaning and on macOS \
                     could perturb the rendered SBPL profile.",
                    package_json.display(),
                    cp = ch as u32,
                ),
            });
        }
        let authored = PathBuf::from(s);
        let was_relative = !authored.is_absolute();
        let joined = if was_relative {
            project_dir.join(&authored)
        } else {
            authored.clone()
        };
        let lexical_candidate = logical_normalize(&joined);

        if let Some(dangerous_reason) = matches_dangerous_root(&lexical_candidate, home_dir) {
            return Err(dangerous_root_error(package_json, i, s, dangerous_reason));
        }

        let (authorized_root, suffix, root_kind) = if was_relative {
            let suffix = lexical_candidate
                .strip_prefix(&project_root.configured)
                .map_err(|_| relative_escape_error(package_json, i, s))?;
            (&project_root, suffix, AuthorizedRootKind::Project)
        } else {
            select_authorized_root(
                &lexical_candidate,
                &project_root,
                &user_roots,
                package_json,
                i,
                s,
            )?
        };
        if root_kind == AuthorizedRootKind::Project && suffix.as_os_str().is_empty() {
            return Err(SandboxError::InvalidSpec {
                reason: format!(
                    "{}: `lpm.scripts.sandboxWriteDirs[{i}]` = {s:?} resolves to the \
                     project root; this would widen writes to the whole project",
                    package_json.display()
                ),
            });
        }

        let effective = authorized_root
            .resolve_descendant(suffix)
            .map_err(|failure| invalid_entry_path_error(package_json, i, s, failure))?;

        if let Some(dangerous_reason) =
            matches_dangerous_root(&effective, effective_home.as_deref())
        {
            return Err(dangerous_root_error(package_json, i, s, dangerous_reason));
        }

        resolved.push(effective);
    }

    Ok(resolved)
}

// ── Validation helpers ────────────────────────────────────────────

#[derive(Debug)]
struct AuthorizedRoot {
    configured: PathBuf,
    effective: PathBuf,
    existing_anchor: PathBuf,
}

#[derive(Debug, Clone, Copy)]
enum PathValidationFailure {
    Indirection,
    NotAbsolute,
    NotDirectory,
    EscapesRoot,
    Io(ErrorKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizedRootKind {
    Project,
    User,
}

impl AuthorizedRoot {
    fn resolve(path: &Path) -> Result<Self, PathValidationFailure> {
        let configured = logical_normalize(path);
        if !configured.is_absolute() {
            return Err(PathValidationFailure::NotAbsolute);
        }

        let mut probe = configured.clone();
        loop {
            match std::fs::symlink_metadata(&probe) {
                Ok(metadata) => {
                    if !metadata.is_dir() && !is_filesystem_indirection(&metadata) {
                        return Err(PathValidationFailure::NotDirectory);
                    }
                    let existing_anchor = std::fs::canonicalize(&probe)
                        .map_err(|error| PathValidationFailure::Io(error.kind()))?;
                    if !std::fs::metadata(&existing_anchor)
                        .map_err(|error| PathValidationFailure::Io(error.kind()))?
                        .is_dir()
                    {
                        return Err(PathValidationFailure::NotDirectory);
                    }
                    let suffix = configured
                        .strip_prefix(&probe)
                        .map_err(|_| PathValidationFailure::EscapesRoot)?;
                    validate_relative_suffix(suffix)?;
                    let mut effective = existing_anchor.clone();
                    effective.push(suffix);
                    return Ok(Self {
                        configured,
                        effective,
                        existing_anchor,
                    });
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) =>
                {
                    if !probe.pop() {
                        return Err(PathValidationFailure::Io(error.kind()));
                    }
                }
                Err(error) => return Err(PathValidationFailure::Io(error.kind())),
            }
        }
    }

    fn matched_suffix<'a>(&self, candidate: &'a Path) -> Option<&'a Path> {
        candidate
            .strip_prefix(&self.configured)
            .ok()
            .or_else(|| candidate.strip_prefix(&self.effective).ok())
    }

    fn resolve_descendant(&self, suffix: &Path) -> Result<PathBuf, PathValidationFailure> {
        validate_relative_suffix(suffix)?;
        let mut candidate = self.effective.clone();
        candidate.push(suffix);
        if !is_descendant_of(&candidate, &self.effective)
            || !is_descendant_of(&candidate, &self.existing_anchor)
        {
            return Err(PathValidationFailure::EscapesRoot);
        }

        inspect_path_below(&self.existing_anchor, &candidate)?;
        match std::fs::canonicalize(&candidate) {
            Ok(resolved) => {
                if !is_descendant_of(&resolved, &self.effective) {
                    return Err(PathValidationFailure::EscapesRoot);
                }
                Ok(resolved)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(candidate),
            Err(error) => Err(PathValidationFailure::Io(error.kind())),
        }
    }
}

fn select_authorized_root<'roots, 'candidate>(
    candidate: &'candidate Path,
    project_root: &'roots AuthorizedRoot,
    user_roots: &'roots [(PathBuf, Result<AuthorizedRoot, PathValidationFailure>)],
    package_json: &Path,
    index: usize,
    authored: &str,
) -> Result<(&'roots AuthorizedRoot, &'candidate Path, AuthorizedRootKind), SandboxError> {
    let mut selected = project_root.matched_suffix(candidate).map(|suffix| {
        (
            project_root,
            suffix,
            project_root.configured.components().count(),
            AuthorizedRootKind::Project,
        )
    });

    for (allowlist_index, (configured, resolved)) in user_roots.iter().enumerate() {
        let configured_suffix = candidate.strip_prefix(configured).ok();
        if configured_suffix.is_some()
            && let Err(failure) = resolved
        {
            return Err(invalid_root_error(
                package_json,
                index,
                authored,
                &format!("max-sandbox-write-roots[{allowlist_index}]"),
                *failure,
            ));
        }
        let Ok(root) = resolved else {
            continue;
        };
        let Some(suffix) = configured_suffix.or_else(|| root.matched_suffix(candidate)) else {
            continue;
        };
        let depth = root.configured.components().count();
        if selected.is_none_or(|(_, _, selected_depth, _)| depth > selected_depth) {
            selected = Some((root, suffix, depth, AuthorizedRootKind::User));
        }
    }

    selected
        .map(|(root, suffix, _, kind)| (root, suffix, kind))
        .ok_or_else(|| {
            outside_authorized_roots_error(
                package_json,
                index,
                authored,
                candidate,
                user_roots.is_empty(),
            )
        })
}

fn validate_relative_suffix(path: &Path) -> Result<(), PathValidationFailure> {
    if path
        .components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
    {
        Ok(())
    } else {
        Err(PathValidationFailure::EscapesRoot)
    }
}

fn inspect_path_below(anchor: &Path, candidate: &Path) -> Result<(), PathValidationFailure> {
    let suffix = candidate
        .strip_prefix(anchor)
        .map_err(|_| PathValidationFailure::EscapesRoot)?;
    validate_relative_suffix(suffix)?;

    let mut current = anchor.to_path_buf();
    for component in suffix.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if is_filesystem_indirection(&metadata) {
                    return Err(PathValidationFailure::Indirection);
                }
                if !metadata.is_dir() {
                    return Err(PathValidationFailure::NotDirectory);
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) if error.kind() == ErrorKind::NotADirectory => {
                return Err(PathValidationFailure::NotDirectory);
            }
            Err(error) => return Err(PathValidationFailure::Io(error.kind())),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_filesystem_indirection(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_filesystem_indirection(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn dangerous_root_error(
    package_json: &Path,
    index: usize,
    authored: &str,
    reason: &str,
) -> SandboxError {
    SandboxError::InvalidSpec {
        reason: format!(
            "{pj}: `lpm.scripts.sandboxWriteDirs[{index}]` = {authored:?} {reason}. \
             This path is rejected unconditionally — the dangerous-root denylist has final \
             veto over ~/.lpm/config.toml > max-sandbox-write-roots.",
            pj = package_json.display(),
        ),
    }
}

fn relative_escape_error(package_json: &Path, index: usize, authored: &str) -> SandboxError {
    SandboxError::InvalidSpec {
        reason: format!(
            "{pj}: `lpm.scripts.sandboxWriteDirs[{index}]` = {authored:?} uses `..` to escape \
             project_dir. Relative entries must stay inside the project.",
            pj = package_json.display(),
        ),
    }
}

fn outside_authorized_roots_error(
    package_json: &Path,
    index: usize,
    authored: &str,
    candidate: &Path,
    allowlist_is_empty: bool,
) -> SandboxError {
    SandboxError::InvalidSpec {
        reason: format!(
            "{pj}: `lpm.scripts.sandboxWriteDirs[{index}]` = {authored:?} resolves to {path}, \
             which is outside project_dir and not covered by ~/.lpm/config.toml > \
             max-sandbox-write-roots {allowlist_state}. To opt in, add a covering root to that \
             user-config key.",
            pj = package_json.display(),
            path = candidate.display(),
            allowlist_state = if allowlist_is_empty {
                "(empty — the key is unset)"
            } else {
                ""
            },
        ),
    }
}

pub(crate) fn revalidate_effective_write_dir(
    path: &Path,
    index: usize,
) -> Result<(), SandboxError> {
    if let Err(failure) = revalidate_effective_path(path) {
        let detail = match failure {
            PathValidationFailure::Indirection => {
                "the validated effective path now traverses a symlink, junction, or reparse point"
            }
            PathValidationFailure::NotAbsolute => "the validated effective path is not absolute",
            PathValidationFailure::NotDirectory => {
                "an existing effective-path component is not a directory"
            }
            PathValidationFailure::EscapesRoot => {
                "the validated effective path escapes its authorized root"
            }
            PathValidationFailure::Io(_) => {
                "the validated effective path can no longer be securely inspected"
            }
        };
        return Err(SandboxError::InvalidSpec {
            reason: format!(
                "`lpm.scripts.sandboxWriteDirs[{index}]` is rejected: {detail}; \
                 write-directory symlink/reparse traversal is not permitted"
            ),
        });
    }
    Ok(())
}

fn revalidate_effective_path(path: &Path) -> Result<(), PathValidationFailure> {
    if !path.is_absolute() {
        return Err(PathValidationFailure::NotAbsolute);
    }
    let mut probe = logical_normalize(path);
    loop {
        match std::fs::symlink_metadata(&probe) {
            Ok(metadata) => {
                if is_filesystem_indirection(&metadata) {
                    return Err(PathValidationFailure::Indirection);
                }
                if !metadata.is_dir() {
                    return Err(PathValidationFailure::NotDirectory);
                }
                let canonical = std::fs::canonicalize(&probe)
                    .map_err(|error| PathValidationFailure::Io(error.kind()))?;
                if canonical != probe {
                    return Err(PathValidationFailure::Indirection);
                }
                return Ok(());
            }
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) =>
            {
                if !probe.pop() {
                    return Err(PathValidationFailure::Io(error.kind()));
                }
            }
            Err(error) => return Err(PathValidationFailure::Io(error.kind())),
        }
    }
}

fn invalid_entry_path_error(
    package_json: &Path,
    index: usize,
    authored: &str,
    failure: PathValidationFailure,
) -> SandboxError {
    let detail = match failure {
        PathValidationFailure::Indirection => {
            "write-directory symlink, junction, or reparse-point traversal is not permitted; \
             replace every path component below the authorized root with a real directory"
                .to_string()
        }
        PathValidationFailure::NotAbsolute => {
            "the resolved write directory is not absolute".to_string()
        }
        PathValidationFailure::NotDirectory => {
            "an existing component is not a directory".to_string()
        }
        PathValidationFailure::EscapesRoot => {
            "the resolved write directory escapes its authorized root".to_string()
        }
        PathValidationFailure::Io(kind) => format!(
            "the path could not be securely inspected (filesystem error kind: {kind:?}); \
             refusing to grant write access"
        ),
    };
    SandboxError::InvalidSpec {
        reason: format!(
            "{pj}: `lpm.scripts.sandboxWriteDirs[{index}]` = {authored:?} is rejected: {detail}.",
            pj = package_json.display(),
        ),
    }
}

fn invalid_root_error(
    package_json: &Path,
    index: usize,
    authored: &str,
    root_name: &str,
    failure: PathValidationFailure,
) -> SandboxError {
    let detail = match failure {
        PathValidationFailure::Indirection => "contains unresolved filesystem indirection",
        PathValidationFailure::NotAbsolute => "is not absolute",
        PathValidationFailure::NotDirectory => "is not a directory",
        PathValidationFailure::EscapesRoot => "contains an invalid path suffix",
        PathValidationFailure::Io(_) => "could not be securely resolved",
    };
    SandboxError::InvalidSpec {
        reason: format!(
            "{pj}: `lpm.scripts.sandboxWriteDirs[{index}]` = {authored:?} cannot be validated \
             because {root_name} {detail}; refusing to grant write access.",
            pj = package_json.display(),
        ),
    }
}

/// Logical path normalization — collapses `.` and `..` components
/// before filesystem-backed resolution and component inspection.
fn logical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // Pop only if the last pushed component is a Normal
                // segment. Never pop past the root prefix.
                if !matches!(
                    out.components().next_back(),
                    Some(Component::RootDir) | None
                ) {
                    out.pop();
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Returns `Some(reason_phrase)` iff `path` is equal to or a
/// descendant of a dangerous root.
///
/// Reason phrases are user-facing (rendered into the
/// InvalidSpec message) and name which root matched so the user
/// knows which protection fired.
///
/// The absolute denylist is platform-aware. The POSIX entries
/// (`/`, `/etc`, `/var/run`,
/// `/run`) protect Linux + macOS hosts. The Windows entries
/// (`C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`,
/// `C:\ProgramData`, plus any bare drive root like `C:\`) protect
/// the equivalent system surfaces — `sandboxWriteDirs:
/// ["C:\\Windows\\System32"]` is exactly as dangerous as the POSIX
/// `/etc` case and the validator should refuse both. Home-rooted
/// entries (`.ssh`, `.aws`, `.lpm`) stay the same on both platforms
/// — Git / AWS CLI / LPM use the same conventions everywhere.
fn matches_dangerous_root(path: &Path, home_dir: Option<&Path>) -> Option<&'static str> {
    // Bare drive roots on Windows (`C:\`, `D:\`, etc.) are
    // "writes to the whole drive" — semantically identical to the
    // POSIX `/` case. Match on Component shape rather than a
    // literal because the drive letter varies per host.
    #[cfg(windows)]
    {
        let mut comps = path.components();
        if let (Some(prefix), Some(root), None) = (comps.next(), comps.next(), comps.next())
            && matches!(prefix, std::path::Component::Prefix(_))
            && matches!(root, std::path::Component::RootDir)
        {
            return Some("is a drive root — writes would affect the whole drive's namespace");
        }
    }

    // Platform-specific absolute denylist. The POSIX entries are
    // never hit on Windows (these paths aren't absolute under
    // Windows path resolution, so they take the relative-entry
    // path through `load_sandbox_write_dirs` instead); the Windows
    // entries are likewise inert on POSIX hosts. Keeping both
    // tables compiled on every target keeps the code grep-able
    // even when reading on the "wrong" platform.
    #[cfg(not(windows))]
    let absolute_denylist: &[(&str, &str)] = &[
        (
            "/",
            "is the filesystem root — writes would affect the whole host",
        ),
        ("/etc", "is inside /etc — system-level configuration"),
        ("/var/run", "is inside /var/run — runtime state"),
        ("/run", "is inside /run — runtime state (systemd)"),
    ];

    #[cfg(windows)]
    let absolute_denylist: &[(&str, &str)] = &[
        (
            r"C:\Windows",
            r"is inside C:\Windows — Windows OS install (System32, drivers, registry)",
        ),
        (
            r"C:\Program Files",
            r"is inside C:\Program Files — installed application binaries",
        ),
        (
            r"C:\Program Files (x86)",
            r"is inside C:\Program Files (x86) — installed 32-bit application binaries",
        ),
        (
            r"C:\ProgramData",
            r"is inside C:\ProgramData — system-wide application configuration",
        ),
    ];

    for (dangerous, reason) in absolute_denylist {
        let d = Path::new(dangerous);
        // Exact match OR descendant match. `/` is handled specially
        // because EVERY path descends from it — we only want to
        // reject the literal `/` and not arbitrary paths (the other
        // denylist entries + allowlist + traversal check handle the
        // rest). The Windows drive-root case is handled above.
        #[cfg(not(windows))]
        if *dangerous == "/" {
            if path == d {
                return Some(*reason);
            }
            continue;
        }
        if path == d || path.starts_with(d) {
            return Some(*reason);
        }
        if let Ok(resolved) = std::fs::canonicalize(d)
            && (path == resolved || path.starts_with(&resolved))
        {
            return Some(*reason);
        }
    }

    if let Some(home) = home_dir {
        // Paths under the user's home that hold credentials or LPM
        // state. $HOME-rooted so we match the user who's actually
        // running lpm, not a hardcoded /home/user/.... Same set on
        // every platform — Git / AWS CLI / LPM use the same
        // conventions on Windows.
        let home_denylist: &[(&str, &str)] = &[
            (".ssh", "is inside $HOME/.ssh — SSH private keys and config"),
            (
                ".aws",
                "is inside $HOME/.aws — AWS credentials and session state",
            ),
            (
                ".lpm",
                "is inside $HOME/.lpm — LPM's own state (config, store, approvals)",
            ),
        ];
        for (suffix, reason) in home_denylist {
            let d = home.join(suffix);
            if path == d || path.starts_with(&d) {
                return Some(*reason);
            }
            if let Ok(resolved) = std::fs::canonicalize(&d)
                && (path == resolved || path.starts_with(&resolved))
            {
                return Some(*reason);
            }
        }
    }

    None
}

/// Descendant-of test: returns true if `path` is equal to `ancestor`
/// OR is strictly under it. Used by both the dangerous-root check
/// and the allowlist intersection.
fn is_descendant_of(path: &Path, ancestor: &Path) -> bool {
    path == ancestor || path.starts_with(ancestor)
}

// ── script-read-allow opt-in loader ───────────────────────────────

/// Read `package.json > lpm > scripts > sandboxReadAllow` plus the
/// `user_extra_paths` list (resolved from `~/.lpm/config.toml >
/// script-read-allow`) and return the union as project-rooted
/// absolute paths. Every entry must canonicalize to a path INSIDE
/// `project_dir`; traversal-escape and absolute-outside-project
/// entries are rejected.
///
/// These paths name files that lifecycle scripts are allowed to
/// read despite matching the built-in secret-file deny list
/// (`.env`, `.npmrc`, `*.pem`, etc.). The sandbox backends consume
/// the list to suppress the corresponding deny rule on macOS and
/// skip the corresponding bind-mount on Linux.
///
/// # Parameters
///
/// - `package_json`: project manifest path.
/// - `project_dir`: project root; relative entries resolve against
///   this, and all entries are validated to canonicalize under it.
/// - `user_extra_paths`: project-relative path strings from
///   `~/.lpm/config.toml > script-read-allow`. Each is joined to
///   `project_dir` then validated alongside the package.json
///   entries. Pass empty when the user has no global opt-ins.
///
/// # Resolution rules
///
/// - Missing `package.json`, missing `lpm` / `scripts` /
///   `sandboxReadAllow` keys: the project contributes nothing; the
///   result is the resolved `user_extra_paths` (if any).
/// - The `sandboxReadAllow` key must be a JSON array of strings.
///   Other shapes produce [`SandboxError::InvalidSpec`].
/// - Each entry: if absolute, kept verbatim (after canonicalization);
///   if relative, joined onto `project_dir`. The canonicalized
///   result must remain under `project_dir`.
/// - Empty strings are rejected (same rationale as
///   [`load_sandbox_write_dirs`]: an empty path would resolve to
///   `project_dir` itself, which is meaningless for a per-file
///   opt-in).
/// - Duplicate entries (e.g., `.env` from both the project and
///   user lists) are deduplicated; the result is unique.
///
/// # Return shape
///
/// A `Vec<PathBuf>` of absolute, project-rooted paths suitable for
/// passing as [`crate::SandboxSpec::secret_read_allow`].
pub fn load_sandbox_read_allow(
    package_json: &Path,
    project_dir: &Path,
    user_extra_paths: &[String],
) -> Result<Vec<PathBuf>, SandboxError> {
    let project_dir_canon = logical_normalize(project_dir);

    // Per-project list from package.json.
    let mut entries: Vec<(String, usize, &'static str)> = Vec::new();
    let project_raw = match lpm_common::read_text_file_capped(
        package_json,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(s) => Some(s),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => None,
        Err(e) => {
            return Err(SandboxError::InvalidSpec {
                reason: format!("failed to read {}: {e}", package_json.display()),
            });
        }
    };
    if let Some(raw) = project_raw {
        let json: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| SandboxError::InvalidSpec {
                reason: format!("{} is not valid JSON: {e}", package_json.display()),
            })?;
        if let Some(arr_val) = json
            .get("lpm")
            .and_then(|v| v.get("scripts"))
            .and_then(|v| v.get("sandboxReadAllow"))
        {
            let arr = arr_val
                .as_array()
                .ok_or_else(|| SandboxError::InvalidSpec {
                    reason: format!(
                        "{}: `lpm.scripts.sandboxReadAllow` must be an array of strings, got {}",
                        package_json.display(),
                        arr_val
                    ),
                })?;
            for (i, item) in arr.iter().enumerate() {
                let s = item.as_str().ok_or_else(|| SandboxError::InvalidSpec {
                    reason: format!(
                        "{}: `lpm.scripts.sandboxReadAllow[{i}]` must be a string, got {}",
                        package_json.display(),
                        item
                    ),
                })?;
                entries.push((s.to_string(), i, "package.json"));
            }
        }
    }

    // Per-user list from ~/.lpm/config.toml.
    for (i, s) in user_extra_paths.iter().enumerate() {
        entries.push((s.clone(), i, "~/.lpm/config.toml > script-read-allow"));
    }

    // Validate + resolve each entry.
    let mut resolved: Vec<PathBuf> = Vec::with_capacity(entries.len());
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for (authored, idx, source) in entries {
        if authored.is_empty() {
            return Err(SandboxError::InvalidSpec {
                reason: format!(
                    "{source}[{idx}] is empty; an empty entry would resolve to \
                     project_dir itself, which is not a valid per-file opt-in"
                ),
            });
        }
        let authored_path = PathBuf::from(&authored);
        let joined = if authored_path.is_absolute() {
            authored_path.clone()
        } else {
            project_dir.join(&authored_path)
        };
        let canonical = logical_normalize(&joined);
        if !is_descendant_of(&canonical, &project_dir_canon) {
            return Err(SandboxError::InvalidSpec {
                reason: format!(
                    "{source}[{idx}] = {authored:?} resolves to {path} which is outside \
                     project_dir = {project}. script-read-allow entries must name files \
                     inside the project tree — host-system paths (`~/.ssh`, `/etc/...`) \
                     are not exemptable through this knob.",
                    path = canonical.display(),
                    project = project_dir_canon.display(),
                ),
            });
        }
        // Dedup by canonical form so `.env` from project + user
        // doesn't produce two entries in the spec. Push the
        // canonical (`./.env` → `.env`, `secrets/../foo` →
        // `foo`) so downstream consumers — Seatbelt's
        // `(literal ...)` rule emitter, the Linux overlay
        // enumerator — receive paths in the form the kernel sees
        // at enforcement time.
        if seen.insert(canonical.clone()) {
            resolved.push(canonical);
        }
    }

    Ok(resolved)
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Env {
        _tmp: tempfile::TempDir,
        project: PathBuf,
        package_json: PathBuf,
    }

    fn fixture(package_json_body: &str) -> Env {
        let tmp = tempfile::tempdir().expect("tempdir");
        let project = tmp.path().to_path_buf();
        let package_json = project.join("package.json");
        fs::write(&package_json, package_json_body).expect("write package.json");
        Env {
            _tmp: tmp,
            project,
            package_json,
        }
    }

    /// Minimal call form — empty user allowlist, no home dir. Used
    /// by tests whose assertions don't depend on the allowlist or
    /// home-dir branches of the validator. Tests that exercise
    /// those branches call `load_sandbox_write_dirs` directly.
    fn load_minimal(env: &Env) -> Result<Vec<PathBuf>, SandboxError> {
        load_sandbox_write_dirs(&env.package_json, &env.project, &[], None)
    }

    fn write_single_sandbox_write_dir(package_json: &Path, path: &Path) {
        fs::write(
            package_json,
            format!(
                r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":[{}]}}}}}}"#,
                json_encode_literal(&path.to_string_lossy())
            ),
        )
        .expect("write package.json");
    }

    /// Maps a Unix-shaped path literal to a platform-absolute form
    /// suitable for embedding in a sandboxWriteDirs JSON array.
    /// `/opt/local/share` stays `/opt/local/share` on Unix; on
    /// Windows it becomes `C:/opt/local/share` (forward slashes
    /// because JSON-encoding `\` doubles every character and makes
    /// the test corpus unreadable; Windows path resolution accepts
    /// `/` interchangeably). The drive-letter prefix is what makes
    /// `Path::is_absolute()` return `true` under Windows path
    /// resolution — `/opt/local/share` alone is "current drive's
    /// root + relative", which the validator correctly flags as an
    /// escape attempt on Windows.
    fn unix_abs_str(unix_form: &str) -> String {
        #[cfg(not(target_os = "windows"))]
        {
            unix_form.to_string()
        }
        #[cfg(target_os = "windows")]
        {
            // Keep the Unix shape with forward slashes for
            // readability — Windows accepts both. The `C:` prefix
            // is what flips `is_absolute()` to true.
            assert!(
                unix_form.starts_with('/'),
                "unix_abs_str expects a leading-slash literal: {unix_form}"
            );
            format!("C:{unix_form}")
        }
    }

    /// Companion of `unix_abs_str` that returns a `PathBuf` matching
    /// what `load_sandbox_write_dirs` will produce — used for
    /// roundtrip-equality assertions in the back-compat tests.
    fn unix_abs_pathbuf(unix_form: &str) -> PathBuf {
        PathBuf::from(unix_abs_str(unix_form))
    }

    // ── Pre-slice-5 tests (back-compat: empty allowlist, no
    //    home; none of these entries touches the dangerous denylist) ──

    #[test]
    fn missing_package_json_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().to_path_buf();
        let nonexistent = project.join("package.json");
        let v = load_sandbox_write_dirs(&nonexistent, &project, &[], None).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn package_json_without_lpm_section_returns_empty() {
        let e = fixture(r#"{"name":"x","version":"1.0.0"}"#);
        let v = load_minimal(&e).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn package_json_without_sandbox_write_dirs_returns_empty() {
        let e = fixture(r#"{"lpm":{"scripts":{"autoBuild":true}}}"#);
        let v = load_minimal(&e).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn absolute_entry_returns_filesystem_resolved_effective_path() {
        let abs = unix_abs_str("/home/u/.cache/ms-playwright");
        let e = fixture(&format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":["{abs}"]}}}}}}"#
        ));
        let allowlist = [unix_abs_pathbuf("/home/u/.cache")];
        let v = load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None).unwrap();
        assert_eq!(v.len(), 1);
        let root = AuthorizedRoot::resolve(&allowlist[0]).expect("resolve allowlist root");
        assert_eq!(v[0], root.effective.join("ms-playwright"));
    }

    #[test]
    fn relative_entry_joined_to_project_dir() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#);
        let v = load_minimal(&e).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(
            v[0],
            std::fs::canonicalize(&e.project)
                .expect("canonical project")
                .join("build-output")
        );
        assert!(v[0].is_absolute());
    }

    #[test]
    fn multiple_entries_preserved_in_order() {
        let one = unix_abs_str("/abs/one");
        let three = unix_abs_str("/abs/three");
        let e = fixture(&format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":["{one}","rel-two","{three}"]}}}}}}"#
        ));
        // Absolute entries outside project_dir need a covering
        // allowlist; `/abs` covers both `/abs/one` and `/abs/three`.
        let allowlist = [unix_abs_pathbuf("/abs")];
        let v = load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None).unwrap();
        assert_eq!(v.len(), 3);
        let allowlist_root = AuthorizedRoot::resolve(&allowlist[0]).expect("resolve allowlist");
        assert_eq!(v[0], allowlist_root.effective.join("one"));
        assert_eq!(
            v[1],
            std::fs::canonicalize(&e.project)
                .expect("canonical project")
                .join("rel-two")
        );
        assert_eq!(v[2], allowlist_root.effective.join("three"));
    }

    #[test]
    fn non_array_value_errors_with_actionable_message() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":"not-an-array"}}}"#);
        match load_minimal(&e) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("sandboxWriteDirs"));
                assert!(reason.contains("array"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn non_string_element_errors_with_index() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["ok",42]}}}"#);
        match load_minimal(&e) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("sandboxWriteDirs[1]"));
                assert!(reason.contains("string"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn empty_string_entry_rejected_because_it_widens_project_wide() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[""]}}}"#);
        match load_minimal(&e) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("empty"));
                assert!(reason.contains("widen"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_write_dirs_rejects_relative_path_that_collapses_to_project_root() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["missing/.."]}}}"#);

        let error = load_minimal(&e).expect_err("project-root widening must be rejected");

        assert!(
            error.to_string().contains("whole project"),
            "error explains the write-scope widening: {error}"
        );
    }

    #[test]
    fn sandbox_write_dirs_rejects_absolute_configured_project_root() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[]}}}"#);
        write_single_sandbox_write_dir(&e.package_json, &e.project);

        let error = load_minimal(&e).expect_err("configured project root must be rejected");

        assert!(
            error.to_string().contains("whole project"),
            "error explains the write-scope widening: {error}"
        );
    }

    #[test]
    fn sandbox_write_dirs_rejects_absolute_canonical_project_root() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[]}}}"#);
        let canonical_project = std::fs::canonicalize(&e.project).expect("canonical project");
        write_single_sandbox_write_dir(&e.package_json, &canonical_project);

        let error = load_minimal(&e).expect_err("canonical project root must be rejected");

        assert!(
            error.to_string().contains("whole project"),
            "error explains the write-scope widening: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_write_dirs_rejects_absolute_configured_symlinked_project_root() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let real_project = tmp.path().join("real-project");
        let project_link = tmp.path().join("project-link");
        fs::create_dir(&real_project).expect("create real project");
        symlink(&real_project, &project_link).expect("create project symlink");
        let package_json = real_project.join("package.json");
        write_single_sandbox_write_dir(&package_json, &project_link);

        let error =
            load_sandbox_write_dirs(&project_link.join("package.json"), &project_link, &[], None)
                .expect_err("configured symlinked project root must be rejected");

        assert!(
            error.to_string().contains("whole project"),
            "error explains the write-scope widening: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_write_dirs_rejects_absolute_canonical_symlinked_project_root() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let real_project = tmp.path().join("real-project");
        let project_link = tmp.path().join("project-link");
        fs::create_dir(&real_project).expect("create real project");
        symlink(&real_project, &project_link).expect("create project symlink");
        let package_json = real_project.join("package.json");
        let canonical_project = std::fs::canonicalize(&real_project).expect("canonical project");
        write_single_sandbox_write_dir(&package_json, &canonical_project);

        let error =
            load_sandbox_write_dirs(&project_link.join("package.json"), &project_link, &[], None)
                .expect_err("canonical symlinked project root must be rejected");

        assert!(
            error.to_string().contains("whole project"),
            "error explains the write-scope widening: {error}"
        );
    }

    #[test]
    fn malformed_json_surfaces_as_invalid_spec() {
        let e = fixture(r#"{"lpm": INVALID"#);
        match load_minimal(&e) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("not valid JSON"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    // ── Validation acceptance tests ──

    /// An absolute path outside `project_dir` is rejected when
    /// `max-sandbox-write-roots` is empty. The dangerous-root
    /// denylist alone is not enough — it does not cover user data
    /// dirs (`~/Documents`, `~/.config`, `~/.local/share`, …).
    #[test]
    fn empty_allowlist_rejects_absolute_outside_project() {
        let abs = unix_abs_str("/opt/local/share");
        let e = fixture(&format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":["{abs}"]}}}}}}"#
        ));
        match load_sandbox_write_dirs(&e.package_json, &e.project, &[], None) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains("opt/local/share") || reason.contains("opt\\local\\share"),
                    "error names the rejected path: {reason}"
                );
                assert!(
                    reason.contains("max-sandbox-write-roots"),
                    "error tells the user how to opt in: {reason}"
                );
                assert!(
                    reason.contains("empty") || reason.contains("unset"),
                    "error names the empty-allowlist case explicitly: {reason}"
                );
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// Companion to the rejection test: an absolute path INSIDE
    /// `project_dir` is accepted with an empty allowlist — the
    /// entry descends from `project_dir`, which is always
    /// implicitly trusted regardless of allowlist state.
    #[test]
    fn empty_allowlist_accepts_absolute_inside_project() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[]}}}"#);
        let inside = e.project.join("build-output");
        let body = format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":[{}]}}}}}}"#,
            json_encode_literal(&inside.to_string_lossy())
        );
        fs::write(&e.package_json, body).expect("rewrite fixture");
        let v = load_sandbox_write_dirs(&e.package_json, &e.project, &[], None).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(
            v[0],
            std::fs::canonicalize(&e.project)
                .expect("canonical project")
                .join("build-output")
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_write_dirs_rejects_symlink_to_directory_outside_project() {
        use std::os::unix::fs::symlink;

        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#);
        let outside = tempfile::tempdir().expect("outside tempdir");
        symlink(outside.path(), e.project.join("build-output")).expect("create symlink");

        match load_minimal(&e) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains("sandboxWriteDirs[0]"),
                    "error identifies the rejected entry: {reason}"
                );
                assert!(
                    reason.contains("symlink") || reason.contains("link traversal"),
                    "error explains that link traversal is forbidden: {reason}"
                );
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_write_dirs_rejects_symlink_component_when_leaf_does_not_exist() {
        use std::os::unix::fs::symlink;

        let e =
            fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["linked-parent/missing-leaf"]}}}"#);
        let outside = tempfile::tempdir().expect("outside tempdir");
        symlink(outside.path(), e.project.join("linked-parent")).expect("create symlink");

        let error = load_minimal(&e).expect_err("symlink component must be rejected");
        assert!(
            error.to_string().contains("symlink"),
            "error explains the forbidden traversal: {error}"
        );
    }

    #[test]
    fn sandbox_write_dirs_accepts_existing_real_directory_inside_project() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#);
        let build_output = e.project.join("build-output");
        fs::create_dir(&build_output).expect("create build output");

        let paths = load_minimal(&e).expect("real project directory must be accepted");

        assert_eq!(
            paths,
            vec![std::fs::canonicalize(build_output).expect("canonical build output")]
        );
    }

    #[test]
    fn sandbox_write_dirs_accepts_nonexistent_directory_under_real_project_ancestor() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["real-parent/missing/leaf"]}}}"#);
        fs::create_dir(e.project.join("real-parent")).expect("create real parent");

        let paths = load_minimal(&e).expect("missing suffix under real ancestor must be accepted");

        assert_eq!(
            paths,
            vec![
                std::fs::canonicalize(&e.project)
                    .expect("canonical project")
                    .join("real-parent/missing/leaf")
            ]
        );
    }

    #[test]
    fn sandbox_write_dirs_preserves_explicit_allowlist_behavior_without_link_escape() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[]}}}"#);
        let allow_root = tempfile::tempdir().expect("allowlist tempdir");
        let target = allow_root.path().join("build-output");
        fs::create_dir(&target).expect("create allowlisted target");
        fs::write(
            &e.package_json,
            format!(
                r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":[{}]}}}}}}"#,
                json_encode_literal(&target.to_string_lossy())
            ),
        )
        .expect("write package.json");

        let paths = load_sandbox_write_dirs(
            &e.package_json,
            &e.project,
            &[allow_root.path().to_path_buf()],
            None,
        )
        .expect("real descendant of explicit allowlist root must be accepted");

        assert_eq!(
            paths,
            vec![std::fs::canonicalize(target).expect("canonical target")]
        );
    }

    #[test]
    fn sandbox_write_dirs_accepts_explicit_user_authorized_root_itself() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[]}}}"#);
        let allow_root = tempfile::tempdir().expect("allowlist tempdir");
        write_single_sandbox_write_dir(&e.package_json, allow_root.path());

        let paths = load_sandbox_write_dirs(
            &e.package_json,
            &e.project,
            &[allow_root.path().to_path_buf()],
            None,
        )
        .expect("explicit user-authorized root remains permitted");

        assert_eq!(
            paths,
            vec![std::fs::canonicalize(allow_root.path()).expect("canonical allowlist root")]
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_write_dirs_rejects_symlink_inside_explicit_allowlist() {
        use std::os::unix::fs::symlink;

        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[]}}}"#);
        let allow_root = tempfile::tempdir().expect("allowlist tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let linked = allow_root.path().join("linked");
        symlink(outside.path(), &linked).expect("create allowlist symlink");
        let candidate = linked.join("missing-leaf");
        fs::write(
            &e.package_json,
            format!(
                r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":[{}]}}}}}}"#,
                json_encode_literal(&candidate.to_string_lossy())
            ),
        )
        .expect("write package.json");

        let error = load_sandbox_write_dirs(
            &e.package_json,
            &e.project,
            &[allow_root.path().to_path_buf()],
            None,
        )
        .expect_err("link traversal below an allowlist root must be rejected");

        assert!(
            error.to_string().contains("symlink"),
            "error explains the forbidden traversal: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_write_dirs_accepts_project_root_reached_through_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let real_project = tmp.path().join("real-project");
        let project_link = tmp.path().join("project-link");
        fs::create_dir(&real_project).expect("create real project");
        fs::create_dir(real_project.join("build-output")).expect("create build output");
        fs::write(
            real_project.join("package.json"),
            r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#,
        )
        .expect("write package.json");
        symlink(&real_project, &project_link).expect("create project symlink");

        let paths =
            load_sandbox_write_dirs(&project_link.join("package.json"), &project_link, &[], None)
                .expect("project root symlink itself is permitted");

        assert_eq!(
            paths,
            vec![
                std::fs::canonicalize(real_project.join("build-output"))
                    .expect("canonical build output")
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_write_dirs_rejects_broken_symlink_component() {
        use std::os::unix::fs::symlink;

        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["broken-link/missing-leaf"]}}}"#);
        symlink(
            e.project.join("missing-target"),
            e.project.join("broken-link"),
        )
        .expect("create broken symlink");

        let error = load_minimal(&e).expect_err("broken symlink component must be rejected");
        assert!(
            error.to_string().contains("symlink"),
            "error explains the forbidden traversal: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_write_dirs_revalidation_rejects_link_inserted_before_backend_use() {
        use std::os::unix::fs::symlink;

        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#);
        let paths = load_minimal(&e).expect("missing real directory is initially valid");
        let outside = tempfile::tempdir().expect("outside tempdir");
        symlink(outside.path(), &paths[0]).expect("insert symlink after validation");

        let error = revalidate_effective_write_dir(&paths[0], 0)
            .expect_err("backend revalidation must reject the inserted link");

        assert!(
            error.to_string().contains("sandboxWriteDirs[0]")
                && error.to_string().contains("symlink/reparse traversal"),
            "error identifies the entry and invariant: {error}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn sandbox_write_dirs_rejects_windows_junction_to_directory_outside_project() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#);
        let outside = tempfile::tempdir().expect("outside tempdir");
        let junction = e.project.join("build-output");
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(outside.path())
            .status()
            .expect("run mklink /J");
        assert!(status.success(), "mklink /J failed with {status}");

        let error = load_minimal(&e).expect_err("junction must be rejected");
        assert!(
            error.to_string().contains("reparse") || error.to_string().contains("junction"),
            "error explains the forbidden traversal: {error}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn sandbox_write_dirs_accepts_project_root_reached_through_windows_junction() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real_project = tmp.path().join("real-project");
        let project_junction = tmp.path().join("project-junction");
        fs::create_dir(&real_project).expect("create real project");
        fs::create_dir(real_project.join("build-output")).expect("create build output");
        fs::write(
            real_project.join("package.json"),
            r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#,
        )
        .expect("write package.json");
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&project_junction)
            .arg(&real_project)
            .status()
            .expect("run mklink /J");
        assert!(status.success(), "mklink /J failed with {status}");

        let paths = load_sandbox_write_dirs(
            &project_junction.join("package.json"),
            &project_junction,
            &[],
            None,
        )
        .expect("project root junction itself is permitted");

        assert_eq!(
            paths,
            vec![
                std::fs::canonicalize(real_project.join("build-output"))
                    .expect("canonical build output")
            ]
        );
    }

    /// Descendant path accepted when allowlist is non-empty.
    #[test]
    fn slice5_descendant_of_allowlist_root_accepted() {
        let entry = unix_abs_str("/Users/alice/src/build-output");
        let e = fixture(&format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":["{entry}"]}}}}}}"#
        ));
        let allowlist = [unix_abs_pathbuf("/Users/alice/src")];
        let v = load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None).unwrap();
        let allowlist_root = AuthorizedRoot::resolve(&allowlist[0]).expect("resolve allowlist");
        assert_eq!(v, vec![allowlist_root.effective.join("build-output")]);
    }

    /// Non-descendant absolute path rejected when allowlist is non-empty.
    /// Error names both
    /// project_dir + allowlist so the user can see which side
    /// needs fixing.
    #[test]
    fn slice5_non_descendant_absolute_rejected_when_allowlist_set() {
        let entry = unix_abs_str("/opt/other/path");
        let e = fixture(&format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":["{entry}"]}}}}}}"#
        ));
        let allowlist = [unix_abs_pathbuf("/Users/alice/src")];
        match load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None) {
            Err(SandboxError::InvalidSpec { reason }) => {
                // Use a stable substring that survives the platform
                // path-shape switch. On Unix it'll be "/opt/other/path";
                // on Windows it'll be "C:/opt/other/path" — both
                // contain the suffix.
                assert!(
                    reason.contains("opt/other/path") || reason.contains("opt\\other\\path"),
                    "error names the rejected path: {reason}"
                );
                assert!(
                    reason.contains("max-sandbox-write-roots"),
                    "error names the user config key: {reason}"
                );
                assert!(
                    reason.contains("package.json"),
                    "error names the project source: {reason}"
                );
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// `..` escape rejected. This test runs with an empty allowlist — traversal is an
    /// unconditional check, not gated on the allowlist being set.
    ///
    /// Path choice: `../sibling-outside`. The earlier `../../etc`
    /// fixture was platform-fragile — on Linux CI, tempdir is
    /// `/tmp/<x>` so `../../etc` resolves to a real `/etc` and trips
    /// the **dangerous-root denylist (Step 1)** before the
    /// **traversal-escape check (Step 2)** the test wants to
    /// exercise; the resulting "veto / system-level" error message
    /// doesn't contain "escape" and the assertion fails. On macOS
    /// tempdir lives at `/var/folders/...` so `../../etc` resolves
    /// to a non-existent path that isn't on the denylist, and Step 2
    /// fires as expected — masking the bug. `../sibling-outside`
    /// resolves to a sibling of the tempdir on every platform,
    /// escapes the project, and is never on any dangerous denylist.
    #[test]
    fn slice5_relative_traversal_escape_rejected_unconditionally() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["../sibling-outside"]}}}"#);
        match load_sandbox_write_dirs(&e.package_json, &e.project, &[], None) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains("escape"),
                    "error names the traversal violation: {reason}"
                );
                assert!(reason.contains(".."), "error cites `..`: {reason}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// Dangerous roots rejected even when they would match the allowlist — the dangerous
    /// denylist has final veto.
    ///
    /// The dangerous-system-root literals differ between POSIX
    /// (`/etc`) and Windows (`C:\Windows`), but the veto-over-
    /// allowlist semantic is identical — both cases must reject
    /// even when the allowlist explicitly names the dangerous
    /// root.
    #[test]
    fn slice5_dangerous_root_vetoes_allowlist_match() {
        #[cfg(not(target_os = "windows"))]
        let (entry, root, expected_substr) = ("/etc/foo", PathBuf::from("/etc"), "etc");
        #[cfg(target_os = "windows")]
        let (entry, root, expected_substr) = (
            r"C:\Windows\System32",
            PathBuf::from(r"C:\Windows"),
            "Windows",
        );

        let body = format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":[{}]}}}}}}"#,
            // JSON-encode the entry — Windows paths need backslash
            // doubling, POSIX paths pass through.
            json_encode_literal(entry)
        );
        let e = fixture(&body);
        let allowlist = [root];
        match load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains(expected_substr),
                    "error names the dangerous root ({expected_substr:?}): {reason}"
                );
                assert!(
                    reason.contains("veto")
                        || reason.contains("unconditionally")
                        || reason.contains("system"),
                    "error communicates the denylist has veto: {reason}"
                );
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn dangerous_root_veto_applies_after_home_secret_symlink_resolution() {
        use std::os::unix::fs::symlink;

        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":[]}}}"#);
        let home = tempfile::tempdir().expect("home tempdir");
        let secret_target = tempfile::tempdir().expect("secret target tempdir");
        let ssh_link = home.path().join(".ssh");
        symlink(secret_target.path(), &ssh_link).expect("create .ssh symlink");
        let candidate = ssh_link.join("generated-key");
        fs::write(
            &e.package_json,
            format!(
                r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":[{}]}}}}}}"#,
                json_encode_literal(&candidate.to_string_lossy())
            ),
        )
        .expect("write package.json");

        let error =
            load_sandbox_write_dirs(&e.package_json, &e.project, &[ssh_link], Some(home.path()))
                .expect_err("resolved .ssh target must retain dangerous-root veto");

        assert!(
            error.to_string().contains(".ssh"),
            "error names the protected home root: {error}"
        );
    }

    /// Every dangerous-root denylist member rejected in isolation.
    /// Pins the individual entries so a refactor that drops one
    /// (say `/var/run` on POSIX or `C:\ProgramData` on Windows)
    /// can't quietly ship.
    ///
    /// The cases list differs per platform — there's no value in
    /// asserting that `/etc/passwd` is rejected on Windows because
    /// the validator hits the "not absolute" path first and the
    /// rejection has nothing to do with the dangerous-root logic.
    /// The home-rooted entries (`.ssh`, `.aws`, `.lpm`) are shared
    /// because Git / AWS CLI / LPM use the same conventions on
    /// every platform.
    #[test]
    fn slice5_every_dangerous_root_is_rejected() {
        #[cfg(not(target_os = "windows"))]
        let (fake_home, cases): (PathBuf, &[&str]) = (
            PathBuf::from("/Users/_t"),
            &[
                "/",
                "/etc",
                "/etc/passwd",
                "/var/run",
                "/var/run/docker.sock",
                "/run",
                "/run/user/1000",
                "/Users/_t/.ssh",
                "/Users/_t/.ssh/id_rsa",
                "/Users/_t/.aws",
                "/Users/_t/.aws/credentials",
                "/Users/_t/.lpm",
                "/Users/_t/.lpm/config.toml",
            ],
        );

        #[cfg(target_os = "windows")]
        let (fake_home, cases): (PathBuf, &[&str]) = (
            PathBuf::from(r"C:\Users\_t"),
            &[
                r"C:\",
                r"D:\",
                r"C:\Windows",
                r"C:\Windows\System32",
                r"C:\Windows\System32\drivers\etc\hosts",
                r"C:\Program Files",
                r"C:\Program Files\Some Vendor\app.exe",
                r"C:\Program Files (x86)",
                r"C:\Program Files (x86)\Some Vendor\app.exe",
                r"C:\ProgramData",
                r"C:\ProgramData\ssl\private",
                r"C:\Users\_t\.ssh",
                r"C:\Users\_t\.ssh\id_rsa",
                r"C:\Users\_t\.aws",
                r"C:\Users\_t\.aws\credentials",
                r"C:\Users\_t\.lpm",
                r"C:\Users\_t\.lpm\config.toml",
            ],
        );

        for case in cases {
            let body = format!(
                r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":[{}]}}}}}}"#,
                json_encode_literal(case)
            );
            let e = fixture(&body);
            let result =
                load_sandbox_write_dirs(&e.package_json, &e.project, &[], Some(&fake_home));
            assert!(
                matches!(result, Err(SandboxError::InvalidSpec { .. })),
                "expected {case:?} to be rejected, got {result:?}"
            );
        }
    }

    /// Minimal JSON-string encoder for path literals embedded into
    /// the sandboxWriteDirs corpus. Handles the two characters that
    /// matter for Windows paths (`\` → `\\`, `"` → `\"`); not a
    /// general JSON encoder.
    fn json_encode_literal(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '\\' => out.push_str(r"\\"),
                '"' => out.push_str(r#"\""#),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    }

    /// Acceptance #6: no behavior change when `sandboxWriteDirs`
    /// is absent — the allowlist + home_dir params don't cause any
    /// side-effect. Covers the most common real-world case (no
    /// extra write dirs requested by the project).
    #[test]
    fn slice5_unused_sandbox_write_dirs_means_no_validation_runs() {
        // Absent key → empty Vec, even with a dangerous-looking
        // user allowlist and home dir (neither is consulted when
        // there are no entries to validate).
        let e = fixture(r#"{"name":"quiet-project"}"#);
        let allowlist = [PathBuf::from("/etc"), PathBuf::from("/")];
        let v = load_sandbox_write_dirs(
            &e.package_json,
            &e.project,
            &allowlist,
            Some(&PathBuf::from("/Users/anyone")),
        )
        .unwrap();
        assert!(v.is_empty());
    }

    // ── Unit tests on the helpers ──

    #[test]
    fn logical_normalize_collapses_parent_components() {
        assert_eq!(
            logical_normalize(&PathBuf::from("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(
            logical_normalize(&PathBuf::from("/a/./b")),
            PathBuf::from("/a/b")
        );
        assert_eq!(
            logical_normalize(&PathBuf::from("/a/../../b")),
            PathBuf::from("/b"),
            "cannot pop past root"
        );
    }

    #[test]
    fn is_descendant_of_handles_exact_and_strict_descent() {
        let root = Path::new("/a/b");
        assert!(is_descendant_of(Path::new("/a/b"), root));
        assert!(is_descendant_of(Path::new("/a/b/c"), root));
        assert!(is_descendant_of(Path::new("/a/b/c/d"), root));
        assert!(!is_descendant_of(Path::new("/a"), root));
        assert!(!is_descendant_of(Path::new("/a/bb"), root)); // prefix-but-not-descendant guard
        assert!(!is_descendant_of(Path::new("/c/b"), root));
    }

    #[test]
    fn matches_dangerous_root_returns_none_on_safe_paths() {
        let home = PathBuf::from("/Users/alice");
        assert!(matches_dangerous_root(Path::new("/Users/alice/src"), Some(&home)).is_none());
        assert!(matches_dangerous_root(Path::new("/opt/local"), Some(&home)).is_none());
        assert!(matches_dangerous_root(Path::new("/Users/alice/.cache"), Some(&home)).is_none());
    }

    #[test]
    fn matches_dangerous_root_ignores_home_entries_when_home_is_none() {
        // Without a home dir, $HOME-rooted dangerous checks can't
        // fire — but the absolute-system-root check should still
        // work. The literal varies per platform (POSIX `/etc` vs
        // Windows `C:\Windows`); the underlying contract — "even
        // without a home_dir, fall through to the absolute denylist"
        // — is identical.
        assert!(matches_dangerous_root(Path::new("/Users/alice/.ssh"), None).is_none());
        #[cfg(not(target_os = "windows"))]
        {
            assert!(matches_dangerous_root(Path::new("/etc"), None).is_some());
        }
        #[cfg(target_os = "windows")]
        {
            assert!(
                matches_dangerous_root(Path::new(r"C:\Windows"), None).is_some(),
                "C:\\Windows must hit the Windows absolute-system-root denylist"
            );
            assert!(
                matches_dangerous_root(Path::new(r"C:\"), None).is_some(),
                "a bare drive root must be flagged as 'whole-drive-namespace'"
            );
        }
    }

    // ── script-read-allow loader tests ────────────────────────────

    /// Missing `package.json` + empty user list → empty result, no
    /// error. Common case for projects that don't opt in.
    #[test]
    fn read_allow_missing_package_json_and_empty_user_list() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().to_path_buf();
        let nonexistent = project.join("package.json");
        let v = load_sandbox_read_allow(&nonexistent, &project, &[]).unwrap();
        assert!(v.is_empty());
    }

    /// Project ships `sandboxReadAllow: [".env"]` — entry resolves
    /// to project-rooted absolute path.
    #[test]
    fn read_allow_project_relative_entry_resolves_to_absolute() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxReadAllow":[".env"]}}}"#);
        let v = load_sandbox_read_allow(&e.package_json, &e.project, &[]).unwrap();
        assert_eq!(v, vec![e.project.join(".env")]);
    }

    /// User config `script-read-allow = [".npmrc"]` joins to project.
    #[test]
    fn read_allow_user_entry_resolves_to_project_relative_absolute() {
        let e = fixture(r#"{}"#);
        let user = vec![".npmrc".to_string()];
        let v = load_sandbox_read_allow(&e.package_json, &e.project, &user).unwrap();
        assert_eq!(v, vec![e.project.join(".npmrc")]);
    }

    /// Project + user lists are unioned. Same entry from both is
    /// deduplicated.
    #[test]
    fn read_allow_project_and_user_lists_are_unioned_and_deduped() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxReadAllow":[".env", ".npmrc"]}}}"#);
        let user = vec![".env".to_string(), "secrets/api.pem".to_string()];
        let v = load_sandbox_read_allow(&e.package_json, &e.project, &user).unwrap();
        // `.env` appears in both lists — should be deduplicated.
        assert_eq!(
            v.iter().filter(|p| p == &&e.project.join(".env")).count(),
            1,
            ".env must be deduplicated across project + user lists: {v:?}"
        );
        assert!(v.contains(&e.project.join(".env")));
        assert!(v.contains(&e.project.join(".npmrc")));
        assert!(v.contains(&e.project.join("secrets/api.pem")));
        assert_eq!(v.len(), 3);
    }

    /// `..` traversal escape is rejected — the resolved path
    /// canonicalizes outside `project_dir`.
    #[test]
    fn read_allow_traversal_escape_rejected() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxReadAllow":["../etc/passwd"]}}}"#);
        match load_sandbox_read_allow(&e.package_json, &e.project, &[]) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains("outside") && reason.contains("project_dir"),
                    "error must name the escape: {reason}"
                );
                assert!(
                    reason.contains("script-read-allow") || reason.contains("sandboxReadAllow"),
                    "error must name the config key: {reason}"
                );
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// Absolute path outside `project_dir` is rejected — the
    /// deny block only covers project-rooted secrets, so an
    /// out-of-project entry is meaningless (the file was never
    /// denied) AND would suggest a misconfiguration.
    #[test]
    fn read_allow_absolute_outside_project_rejected() {
        let outside_abs = unix_abs_str("/etc/passwd");
        let e = fixture(&format!(
            r#"{{"lpm":{{"scripts":{{"sandboxReadAllow":["{outside_abs}"]}}}}}}"#
        ));
        match load_sandbox_read_allow(&e.package_json, &e.project, &[]) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("outside"), "rejection message: {reason}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// User-list entry that resolves outside the project is also
    /// rejected. Hardened-clone / dotfile-pollution scenarios.
    #[test]
    fn read_allow_user_entry_traversal_rejected() {
        let e = fixture(r#"{}"#);
        let user = vec!["../escape".to_string()];
        match load_sandbox_read_allow(&e.package_json, &e.project, &user) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains("outside") || reason.contains("script-read-allow"),
                    "rejection message: {reason}"
                );
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// Empty-string entry is rejected (it would resolve to
    /// project_dir itself).
    #[test]
    fn read_allow_empty_entry_rejected() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxReadAllow":[""]}}}"#);
        match load_sandbox_read_allow(&e.package_json, &e.project, &[]) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("empty"), "rejection message: {reason}");
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// Non-array `sandboxReadAllow` value is a clear error.
    #[test]
    fn read_allow_non_array_value_errors() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxReadAllow":"not-an-array"}}}"#);
        match load_sandbox_read_allow(&e.package_json, &e.project, &[]) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains("sandboxReadAllow") && reason.contains("array"),
                    "rejection message: {reason}"
                );
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// Non-string array element is a clear error with index.
    #[test]
    fn read_allow_non_string_element_errors() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxReadAllow":["ok",42]}}}"#);
        match load_sandbox_read_allow(&e.package_json, &e.project, &[]) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("sandboxReadAllow[1]"));
                assert!(reason.contains("string"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    /// Project absent `sandboxReadAllow` but user list non-empty:
    /// user list is what's returned.
    #[test]
    fn read_allow_user_only_works_without_project_key() {
        let e = fixture(r#"{"lpm":{"scripts":{}}}"#);
        let user = vec![".env".to_string(), ".npmrc".to_string()];
        let v = load_sandbox_read_allow(&e.package_json, &e.project, &user).unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.contains(&e.project.join(".env")));
        assert!(v.contains(&e.project.join(".npmrc")));
    }

    /// Order is preserved within each source (project entries
    /// first, then user entries) — useful for reproducible
    /// SBPL profile rendering.
    #[test]
    fn read_allow_preserves_order_project_first_then_user() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxReadAllow":["a.env","b.env"]}}}"#);
        let user = vec!["c.env".to_string(), "d.env".to_string()];
        let v = load_sandbox_read_allow(&e.package_json, &e.project, &user).unwrap();
        assert_eq!(
            v,
            vec![
                e.project.join("a.env"),
                e.project.join("b.env"),
                e.project.join("c.env"),
                e.project.join("d.env"),
            ]
        );
    }

    /// Path nested deeper than 1 level is accepted as long as it
    /// stays inside project_dir.
    #[test]
    fn read_allow_nested_project_path_accepted() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxReadAllow":["services/api/.env"]}}}"#);
        let v = load_sandbox_read_allow(&e.package_json, &e.project, &[]).unwrap();
        assert_eq!(v, vec![e.project.join("services/api/.env")]);
    }
}
