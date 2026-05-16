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
//! accepted verbatim without validation. Three checks apply:
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
//!    descend from `project_dir` OR from one of the user-allowlist
//!    roots (`~/.lpm/config.toml > max-sandbox-write-roots`).
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
use std::path::{Component, Path, PathBuf};

/// Read `package.json > lpm > scripts > sandboxWriteDirs` and return
/// the resolved absolute paths, rejecting entries that would escape
/// project_dir, match a dangerous-root denylist, or fall outside the
/// caller-supplied user allowlist.
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
/// - Each string entry: if absolute, kept verbatim; if relative,
///   joined onto `project_dir`. The result is always absolute so
///   downstream backends can render it without further context.
/// - Empty strings are rejected: they would resolve to `project_dir`
///   itself, which is already covered by the read allow-list and
///   would silently widen the write set to the entire project tree.
/// - Entries that fail validation (dangerous denylist, traversal
///   escape, or containment intersection) surface as
///   [`SandboxError::InvalidSpec`] with an error naming both the
///   project file + the user config source, so the user can tell
///   which side needs fixing.
pub fn load_sandbox_write_dirs(
    package_json: &Path,
    project_dir: &Path,
    user_allowlist: &[PathBuf],
    home_dir: Option<&Path>,
) -> Result<Vec<PathBuf>, SandboxError> {
    let raw = match std::fs::read_to_string(package_json) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
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

    // Pre-normalize the project_dir so descendant checks and
    // traversal-escape comparisons are against a stable form.
    let project_dir_canon = logical_normalize(project_dir);
    let user_allowlist_canon: Vec<PathBuf> = user_allowlist
        .iter()
        .map(|p| logical_normalize(p))
        .collect();

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
        let authored = PathBuf::from(s);
        let was_relative = !authored.is_absolute();
        let joined = if was_relative {
            project_dir.join(&authored)
        } else {
            authored.clone()
        };
        let canonical = logical_normalize(&joined);

        validate_entry(
            s,
            &canonical,
            was_relative,
            &project_dir_canon,
            &user_allowlist_canon,
            home_dir,
            i,
            package_json,
        )?;

        resolved.push(joined);
    }

    Ok(resolved)
}

// ── Validation helpers ────────────────────────────────────────────

/// Validate a single resolved entry against the dangerous-root
/// denylist, the traversal-escape rule, and the containment
/// intersection. Errors name both the project file and the offending
/// path so the user knows which side to edit.
#[allow(clippy::too_many_arguments)]
fn validate_entry(
    authored: &str,
    canonical: &Path,
    was_relative: bool,
    project_dir_canon: &Path,
    user_allowlist_canon: &[PathBuf],
    home_dir: Option<&Path>,
    i: usize,
    package_json: &Path,
) -> Result<(), SandboxError> {
    // Step 1: dangerous-root denylist (unconditional; has veto over
    // the allowlist).
    if let Some(dangerous_reason) = matches_dangerous_root(canonical, home_dir) {
        return Err(SandboxError::InvalidSpec {
            reason: format!(
                "{pj}: `lpm.scripts.sandboxWriteDirs[{i}]` = {authored:?} \
                 resolves to {path} which {reason}. This path is \
                 rejected unconditionally — the dangerous-root denylist \
                 has final veto over ~/.lpm/config.toml > \
                 max-sandbox-write-roots.",
                pj = package_json.display(),
                path = canonical.display(),
                reason = dangerous_reason,
            ),
        });
    }

    // Step 2: traversal-escape check (unconditional; applies to
    // authored-as-relative entries only — absolute entries are
    // explicit user intent, not traversal).
    if was_relative && !is_descendant_of(canonical, project_dir_canon) {
        return Err(SandboxError::InvalidSpec {
            reason: format!(
                "{pj}: `lpm.scripts.sandboxWriteDirs[{i}]` = {authored:?} \
                 uses `..` to escape project_dir = {project}. \
                 Relative entries must stay inside the project; \
                 use an absolute path (and add a matching entry to \
                 ~/.lpm/config.toml > max-sandbox-write-roots if \
                 you've set one) if you want to write outside.",
                pj = package_json.display(),
                project = project_dir_canon.display(),
            ),
        });
    }

    // Step 3: containment intersection (unconditional). Every entry
    // must descend from `project_dir` OR from a user-allowlist root.
    //
    // Empty allowlist means "no opt-in", not "no constraint".
    // Previously the empty case skipped this check, which let a
    // malicious or careless `package.json > sandboxWriteDirs` edit
    // (e.g. `["~/Documents"]`, `["/var/log"]`) widen install-script
    // write access to user data the dangerous-root denylist does
    // not cover (`~/.bashrc`, `~/.config`, `~/.local/share`, …).
    // Install scripts come from untrusted dependencies, so the
    // union of `sandboxWriteDirs` paths IS the dependency attack
    // surface — defaulting that union open made the attack a
    // one-line PR. Absolute paths outside `project_dir` now require
    // an explicit covering entry in
    // `~/.lpm/config.toml > max-sandbox-write-roots`.
    //
    // Relative entries are already covered by Step 2 (traversal
    // escape) — they're guaranteed to stay inside `project_dir`, so
    // this check is a no-op for them.
    let inside_project = is_descendant_of(canonical, project_dir_canon);
    let inside_user_root = user_allowlist_canon
        .iter()
        .any(|root| is_descendant_of(canonical, root));
    if !inside_project && !inside_user_root {
        return Err(SandboxError::InvalidSpec {
            reason: format!(
                "{pj}: `lpm.scripts.sandboxWriteDirs[{i}]` = {authored:?} \
                 resolves to {path} which is outside project_dir = {project} \
                 and not covered by ~/.lpm/config.toml > max-sandbox-write-roots {allowlist}. \
                 To opt in, add a covering root to that user-config key; \
                 to keep the entry project-local, change it to a relative \
                 or project-internal absolute path.",
                pj = package_json.display(),
                path = canonical.display(),
                project = project_dir_canon.display(),
                allowlist = if user_allowlist_canon.is_empty() {
                    "(empty — the key is unset)".to_string()
                } else {
                    format!("= {user_allowlist_canon:?}")
                },
            ),
        });
    }

    Ok(())
}

/// Logical path normalization — collapses `.` and `..` components
/// without consulting the filesystem. Sufficient for the traversal-
/// escape and descendant-of checks; does not resolve symlinks.
///
/// Symlink-based bypass is consistent with the sandbox's existing
/// rule-rendering posture (see the seatbelt.rs canonicalization
/// notes). The dangerous-root denylist + traversal check already
/// cover the high-frequency attack shapes (`..` escape, authored
/// `/etc/foo`). A comprehensive symlink-resolving layer is deferred.
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
    let project_raw = match std::fs::read_to_string(package_json) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
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
        // doesn't produce two entries in the spec.
        if seen.insert(canonical.clone()) {
            resolved.push(joined);
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
    fn absolute_entry_kept_verbatim() {
        // Absolute path outside project_dir requires a covering
        // allowlist root. Verbatim-preservation is what this test pins — the loader keeps the authored
        // path as-is, not joining it onto project_dir or normalizing
        // away segments.
        let abs = unix_abs_str("/home/u/.cache/ms-playwright");
        let e = fixture(&format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":["{abs}"]}}}}}}"#
        ));
        let allowlist = [unix_abs_pathbuf("/home/u/.cache")];
        let v = load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], unix_abs_pathbuf("/home/u/.cache/ms-playwright"));
    }

    #[test]
    fn relative_entry_joined_to_project_dir() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#);
        let v = load_minimal(&e).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], e.project.join("build-output"));
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
        assert_eq!(v[0], unix_abs_pathbuf("/abs/one"));
        assert_eq!(v[1], e.project.join("rel-two"));
        assert_eq!(v[2], unix_abs_pathbuf("/abs/three"));
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
        assert_eq!(v[0], inside);
    }

    /// Reviewer's acceptance #2: descendant path accepted when
    /// allowlist is non-empty.
    #[test]
    fn slice5_descendant_of_allowlist_root_accepted() {
        let entry = unix_abs_str("/Users/alice/src/build-output");
        let e = fixture(&format!(
            r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":["{entry}"]}}}}}}"#
        ));
        let allowlist = [unix_abs_pathbuf("/Users/alice/src")];
        let v = load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None).unwrap();
        assert_eq!(v, vec![unix_abs_pathbuf("/Users/alice/src/build-output")]);
    }

    /// Reviewer's acceptance #3: non-descendant absolute path
    /// rejected when allowlist is non-empty. Error names both
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

    /// Reviewer's acceptance #4: `..` escape rejected. This test
    /// runs with an empty allowlist — traversal is an
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

    /// Reviewer's acceptance #5: dangerous roots rejected even
    /// when they would match the allowlist — the dangerous
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

    // ── script-read-allow loader tests (Phase 3) ──────────────────

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
