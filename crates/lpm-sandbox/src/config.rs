//! Loader for per-project sandbox configuration: the
//! `package.json > lpm > scripts > sandboxWriteDirs` escape hatch
//! (§9.6).
//!
//! This is the ONE place the shape of that key is read from disk.
//! `execute_script` calls [`load_sandbox_write_dirs`] once per
//! install and threads the resolved absolute paths into every
//! per-package [`crate::SandboxSpec`].
//!
//! # Phase 48 P0 slice 5 — path validation
//!
//! Reading the key unvalidated is a trust-boundary hole: a malicious
//! repo can ship `package.json > lpm > scripts > sandboxWriteDirs =
//! ["/"]` or `["/Users/foo/.ssh"]` and those absolute paths were
//! accepted verbatim ([phase48 §2 row 4']). Slice 5 closes this by
//! applying two unconditional checks + one allowlist intersection:
//!
//! 1. **Dangerous-root denylist** (unconditional): reject any entry
//!    that resolves to `/`, `/etc`, `/var/run`, `/run`,
//!    `$HOME/.ssh`, `$HOME/.aws`, or `$HOME/.lpm` (or any descendant
//!    of those roots). The denylist has final veto over the
//!    allowlist — an entry that IS in the user allowlist is still
//!    rejected if it lands in a dangerous root.
//! 2. **Traversal-escape check** (unconditional, applies only to
//!    authored-as-relative entries): after logical `..` collapse,
//!    relative entries must stay inside `project_dir`. `"../etc"` is
//!    rejected regardless of the user allowlist state.
//! 3. **User-allowlist intersection** (when `user_allowlist` is
//!    non-empty): every entry must descend from `project_dir` OR from
//!    one of the allowlist roots. When the allowlist is empty
//!    (absent user key = default), this check is skipped —
//!    back-compat for users who haven't opted into the machine-
//!    wide allowlist.
//!
//! The phase48.md §6 row "Gap 4 sandboxWriteDirs policy" pins the
//! empty-allowlist semantic: **empty means unset, never deny-all.**
//! A future `sandbox-write-policy = "deny-all"` sentinel could layer
//! on top, but is explicitly out of scope for Phase 48.

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
///   `~/.lpm/config.toml > max-sandbox-write-roots`. When non-empty,
///   every entry must descend from `project_dir` or one of these
///   paths. When empty, the allowlist check is skipped
///   (back-compat default).
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
/// - Entries that fail the Phase 48 P0 slice 5 validation
///   (dangerous denylist, traversal escape, or allowlist intersection)
///   surface as [`SandboxError::InvalidSpec`] with an error naming
///   both the project file + the user config source, so the user
///   can tell which side needs fixing.
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

/// Run the Phase 48 P0 slice 5 validation on a single resolved entry.
/// Errors name both the project file and the offending path so the
/// user knows which side to edit.
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

    // Step 3: user-allowlist intersection (applies only when the
    // user has opted in by setting a non-empty
    // max-sandbox-write-roots). Empty allowlist = unset = no
    // constraint — pinned by the phase48.md §6 sandboxWriteDirs
    // policy row.
    if !user_allowlist_canon.is_empty() {
        let inside_project = is_descendant_of(canonical, project_dir_canon);
        let inside_user_root = user_allowlist_canon
            .iter()
            .any(|root| is_descendant_of(canonical, root));
        if !inside_project && !inside_user_root {
            return Err(SandboxError::InvalidSpec {
                reason: format!(
                    "{pj}: `lpm.scripts.sandboxWriteDirs[{i}]` = {authored:?} \
                     resolves to {path} which is outside project_dir = {project} \
                     AND outside every entry in \
                     ~/.lpm/config.toml > max-sandbox-write-roots = {allowlist:?}. \
                     Either add a matching root to the user allowlist, \
                     or remove the entry from the project's package.json.",
                    pj = package_json.display(),
                    path = canonical.display(),
                    project = project_dir_canon.display(),
                    allowlist = user_allowlist_canon,
                ),
            });
        }
    }

    Ok(())
}

/// Logical path normalization — collapses `.` and `..` components
/// without consulting the filesystem. Sufficient for the traversal-
/// escape and descendant-of checks; does not resolve symlinks.
///
/// Symlink-based bypass is consistent with the sandbox's existing
/// rule-rendering posture (see the seatbelt.rs canonicalization
/// notes). A comprehensive symlink-resolving layer is out of scope
/// for Phase 48 P0 slice 5; the dangerous-root denylist + traversal
/// check already cover the high-frequency attack shapes (`..`
/// escape, authored `/etc/foo`).
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
fn matches_dangerous_root(path: &Path, home_dir: Option<&Path>) -> Option<&'static str> {
    // Absolute paths that are always dangerous.
    let absolute_denylist: &[(&str, &str)] = &[
        (
            "/",
            "is the filesystem root — writes would affect the whole host",
        ),
        ("/etc", "is inside /etc — system-level configuration"),
        ("/var/run", "is inside /var/run — runtime state"),
        ("/run", "is inside /run — runtime state (systemd)"),
    ];
    for (dangerous, reason) in absolute_denylist {
        let d = Path::new(dangerous);
        // Exact match OR descendant match. `/` is handled specially
        // because EVERY path descends from it — we only want to
        // reject the literal `/` and not arbitrary paths (the other
        // denylist entries + allowlist + traversal check handle the
        // rest).
        if *dangerous == "/" {
            if path == d {
                return Some(*reason);
            }
        } else if path == d || path.starts_with(d) {
            return Some(*reason);
        }
    }

    if let Some(home) = home_dir {
        // Paths under the user's home that hold credentials or LPM
        // state. $HOME-rooted so we match the user who's actually
        // running lpm, not a hardcoded /home/user/....
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

    /// Convenience wrapper matching the pre-slice-5 call shape so
    /// existing tests stay readable: empty user allowlist, no home
    /// dir. New validation tests call `load_sandbox_write_dirs`
    /// directly to exercise the allowlist + home paths.
    fn load_back_compat(env: &Env) -> Result<Vec<PathBuf>, SandboxError> {
        load_sandbox_write_dirs(&env.package_json, &env.project, &[], None)
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
        let v = load_back_compat(&e).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn package_json_without_sandbox_write_dirs_returns_empty() {
        let e = fixture(r#"{"lpm":{"scripts":{"autoBuild":true}}}"#);
        let v = load_back_compat(&e).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn absolute_entry_kept_verbatim() {
        let e =
            fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["/home/u/.cache/ms-playwright"]}}}"#);
        let v = load_back_compat(&e).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], PathBuf::from("/home/u/.cache/ms-playwright"));
    }

    #[test]
    fn relative_entry_joined_to_project_dir() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["build-output"]}}}"#);
        let v = load_back_compat(&e).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], e.project.join("build-output"));
        assert!(v[0].is_absolute());
    }

    #[test]
    fn multiple_entries_preserved_in_order() {
        let e = fixture(
            r#"{"lpm":{"scripts":{"sandboxWriteDirs":["/abs/one","rel-two","/abs/three"]}}}"#,
        );
        let v = load_back_compat(&e).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], PathBuf::from("/abs/one"));
        assert_eq!(v[1], e.project.join("rel-two"));
        assert_eq!(v[2], PathBuf::from("/abs/three"));
    }

    #[test]
    fn non_array_value_errors_with_actionable_message() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":"not-an-array"}}}"#);
        match load_back_compat(&e) {
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
        match load_back_compat(&e) {
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
        match load_back_compat(&e) {
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
        match load_back_compat(&e) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("not valid JSON"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    // ── Phase 48 P0 slice 5 — new validation acceptance tests ──

    /// Reviewer's acceptance #1: absent/empty `max-sandbox-write-roots`
    /// keeps back-compat. Already covered by the pre-slice-5 tests
    /// above (all of which use `&[]` allowlist and pass). This test
    /// pins the intent explicitly.
    #[test]
    fn slice5_empty_allowlist_behaves_like_no_constraint() {
        // Absolute path outside project_dir, outside dangerous
        // denylist, outside any allowlist → accepted when
        // allowlist is empty (= back-compat).
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["/opt/local/share"]}}}"#);
        let v = load_sandbox_write_dirs(&e.package_json, &e.project, &[], None).unwrap();
        assert_eq!(v, vec![PathBuf::from("/opt/local/share")]);
    }

    /// Reviewer's acceptance #2: descendant path accepted when
    /// allowlist is non-empty.
    #[test]
    fn slice5_descendant_of_allowlist_root_accepted() {
        let e = fixture(
            r#"{"lpm":{"scripts":{"sandboxWriteDirs":["/Users/alice/src/build-output"]}}}"#,
        );
        let allowlist = [PathBuf::from("/Users/alice/src")];
        let v = load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None).unwrap();
        assert_eq!(v, vec![PathBuf::from("/Users/alice/src/build-output")]);
    }

    /// Reviewer's acceptance #3: non-descendant absolute path
    /// rejected when allowlist is non-empty. Error names both
    /// project_dir + allowlist so the user can see which side
    /// needs fixing.
    #[test]
    fn slice5_non_descendant_absolute_rejected_when_allowlist_set() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["/opt/other/path"]}}}"#);
        let allowlist = [PathBuf::from("/Users/alice/src")];
        match load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains("/opt/other/path"),
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
        let e = fixture(
            r#"{"lpm":{"scripts":{"sandboxWriteDirs":["../sibling-outside"]}}}"#,
        );
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
    #[test]
    fn slice5_dangerous_root_vetoes_allowlist_match() {
        let e = fixture(r#"{"lpm":{"scripts":{"sandboxWriteDirs":["/etc/foo"]}}}"#);
        // Allowlist includes `/etc` explicitly — this should NOT
        // override the dangerous-denylist rule for /etc.
        let allowlist = [PathBuf::from("/etc")];
        match load_sandbox_write_dirs(&e.package_json, &e.project, &allowlist, None) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(
                    reason.contains("/etc"),
                    "error names the dangerous root: {reason}"
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
    /// (say `/var/run`) can't quietly ship.
    #[test]
    fn slice5_every_dangerous_root_is_rejected() {
        // Fake home for the $HOME-rooted entries. We use `/Users/_t`
        // which is short enough that the synthesized `.ssh` etc.
        // subpaths are self-contained.
        let fake_home = PathBuf::from("/Users/_t");
        let cases: &[&str] = &[
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
        ];
        for case in cases {
            let body = format!(r#"{{"lpm":{{"scripts":{{"sandboxWriteDirs":["{case}"]}}}}}}"#);
            let e = fixture(&body);
            let result =
                load_sandbox_write_dirs(&e.package_json, &e.project, &[], Some(&fake_home));
            assert!(
                matches!(result, Err(SandboxError::InvalidSpec { .. })),
                "expected {case:?} to be rejected, got {result:?}"
            );
        }
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
        // fire — but the absolute /etc check should still work.
        assert!(matches_dangerous_root(Path::new("/Users/alice/.ssh"), None).is_none());
        assert!(matches_dangerous_root(Path::new("/etc"), None).is_some());
    }
}
