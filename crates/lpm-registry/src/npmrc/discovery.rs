use super::config::NpmrcConfig;
use super::parse::CredentialPolicy;
use lpm_common::{
    BoundedReadError, NPMRC_FILE_SIZE_CAP_BYTES, read_text_file_capped_with_metadata,
};
use std::path::{Path, PathBuf};

impl NpmrcConfig {
    /// Compute the four `.npmrc` paths in **lowest-to-highest precedence
    /// order**, ready to feed `load_from_paths`, plus any warnings raised
    /// during discovery (e.g., a project `.npmrc` that turned out to be a
    /// directory). Pure / no IO beyond `stat`-style probing.
    ///
    /// Layers:
    /// 1. `/usr/etc/npmrc` — npm builtin, rarely present.
    /// 2. `/etc/npmrc` — system-wide, also rare.
    /// 3. `<home>/.npmrc` — user-level, included only if `home` is `Some`.
    ///    Most teams put their auth tokens here.
    /// 4. `<some-ancestor>/.npmrc` — found by `walk_for_project_npmrc`.
    ///    The walker returns the nearest `.npmrc` on the walk-up path
    ///    such that a project marker (regular-file `package.json`) has
    ///    been seen at-or-below that level. This restores the
    ///    monorepo-inheritance pattern (a workspace member without
    ///    its own `.npmrc` inherits the workspace root's one) while
    ///    keeping the security boundary against shared-ancestor
    ///    injection — a `.npmrc` with no marker anywhere on the path
    ///    is never trusted.
    ///
    /// Layers 1–3 are returned even if their files don't exist; the
    /// loader silently skips missing files. Layer 4 is **bounded** to
    /// the project — without a regular-file project marker on the path,
    /// no project layer is included (a planted non-regular marker would
    /// otherwise qualify any directory as a project root).
    pub fn discover_layer_paths(cwd: &Path, home: Option<&Path>) -> LayerDiscovery {
        let mut paths = Vec::with_capacity(4);
        let mut warnings = Vec::new();
        let mut project_layer_index = None;
        paths.push(PathBuf::from("/usr/etc/npmrc"));
        paths.push(PathBuf::from("/etc/npmrc"));
        if let Some(h) = home {
            paths.push(h.join(".npmrc"));
        }
        match walk_for_project_npmrc(cwd, home) {
            ProjectNpmrcOutcome::File(p) => {
                project_layer_index = Some(paths.len());
                paths.push(p);
            }
            ProjectNpmrcOutcome::NotRegular { path, kind } => {
                warnings.push(format!(
                    "{}: project .npmrc {}; project layer skipped",
                    path.display(),
                    kind
                ));
            }
            ProjectNpmrcOutcome::None => {
                // No marker on path → no project layer. Silent — most
                // installs don't have a project layer.
            }
        }
        LayerDiscovery {
            paths,
            warnings,
            project_layer_index,
        }
    }

    /// Read and merge a list of `.npmrc` files in
    /// **lowest-to-highest precedence order**, then `finalize()`.
    ///
    /// File outcomes:
    /// - **Reads OK** — `parse_layer` then `merge_over`.
    /// - **NotFound** — silently skipped. Most users don't have
    ///   `/etc/npmrc` or `/usr/etc/npmrc`; warning every time would be
    ///   pure noise.
    /// - **Oversized or invalid UTF-8** — recorded as a fatal
    ///   configuration error so precedence cannot silently change.
    /// - **Any other IO error** (PermissionDenied, EISDIR, etc.) —
    ///   warned and skipped, preserving the existing compatibility policy.
    ///
    /// The `env_lookup` is threaded through to each file's parse so
    /// `${VAR}` interpolation works the same way the single-file API
    /// does. `load_from_filesystem` wires this to the real process env.
    pub fn load_from_paths(paths: &[PathBuf], env_lookup: &dyn Fn(&str) -> Option<String>) -> Self {
        Self::load_from_paths_with_project_index(paths, None, env_lookup)
    }

    /// Same as [`Self::load_from_paths`] but lets the caller mark which
    /// path is the project-local layer. Used by
    /// [`Self::load_from_filesystem`] so settings like `strict-ssl=false`
    /// committed to a repo's `.npmrc` are refused at parse time.
    pub fn load_from_paths_with_project_index(
        paths: &[PathBuf],
        project_layer_index: Option<usize>,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let mut acc = NpmrcConfig::default();
        for (idx, path) in paths.iter().enumerate() {
            match read_text_file_capped_with_metadata(path, NPMRC_FILE_SIZE_CAP_BYTES) {
                Ok((content, file_metadata)) => {
                    let label = path.display().to_string();
                    let source_dir = path.parent();
                    let is_project = Some(idx) == project_layer_index;

                    #[cfg(unix)]
                    let credential_refusal_warning = {
                        use std::os::unix::fs::PermissionsExt;

                        let permissions = file_metadata.permissions();
                        (!lpm_common::permissions_are_owner_only(&permissions)).then(|| {
                            format!(
                                "{label}: .npmrc mode {:04o} grants group or other access; \
                                 refused credential fields from this layer. Non-secret routing and \
                                 TLS settings remain active. Run `chmod 600 {}` to enable credentials",
                                permissions.mode() & 0o777,
                                path.display(),
                            )
                        })
                    };
                    #[cfg(not(unix))]
                    let credential_refusal_warning: Option<String> = {
                        let _ = file_metadata;
                        None
                    };

                    let credential_policy = match credential_refusal_warning.as_deref() {
                        Some(warning) => CredentialPolicy::Refuse { warning },
                        None => CredentialPolicy::Accept,
                    };
                    let layer = NpmrcConfig::parse_layer_with_credential_policy(
                        &content,
                        &label,
                        source_dir,
                        is_project,
                        credential_policy,
                        env_lookup,
                    );
                    acc.merge_over(layer);
                }
                Err(BoundedReadError::NotFound { .. }) => {
                    // Silent — see method-level comment.
                }
                Err(
                    error @ (BoundedReadError::TooLarge { .. }
                    | BoundedReadError::InvalidUtf8 { .. }),
                ) => {
                    acc.errors.push(error.to_string());
                }
                Err(error) => {
                    acc.warnings.push(format!(
                        "{}: failed to read .npmrc ({}); skipped this layer",
                        path.display(),
                        error
                    ));
                }
            }
        }
        acc.finalize();
        acc
    }

    /// Production wrapper — discover the standard four layers from
    /// disk and load them, with `${VAR}` resolved against the real
    /// process env.
    ///
    /// `cwd` should be the project root (for `lpm install`) or the
    /// home dir (for `lpm install -g`). The walker handles both shapes
    /// via `find_project_root`.
    pub fn load_from_filesystem(cwd: &Path) -> Self {
        let home = dirs::home_dir();
        let discovery = Self::discover_layer_paths(cwd, home.as_deref());
        let mut cfg = Self::load_from_paths_with_project_index(
            &discovery.paths,
            discovery.project_layer_index,
            &|name| std::env::var(name).ok(),
        );
        // Discovery warnings happened first chronologically; prepend so
        // they read in the order the user would expect.
        let mut all = discovery.warnings;
        all.append(&mut cfg.warnings);
        cfg.warnings = all;
        cfg
    }
}

/// Result of [`NpmrcConfig::discover_layer_paths`] — the file paths to
/// load and any non-fatal warnings raised during discovery itself
/// (e.g., a project `.npmrc` that's a directory).
#[derive(Debug, Default)]
pub struct LayerDiscovery {
    pub paths: Vec<PathBuf>,
    pub warnings: Vec<String>,
    /// Index into `paths` of the project-local layer (if any). The
    /// project layer is the `.npmrc` walked-up from cwd with a regular
    /// `package.json` marker. Anything written here is owned by the
    /// repo and may be hostile in a malicious clone — settings like
    /// `strict-ssl=false` are refused at parse time when sourced from
    /// this layer.
    pub project_layer_index: Option<usize>,
}

/// Markers that identify a directory as a project root for the
/// purposes of `.npmrc` discovery. Deliberately narrow — `package.json`
/// is the universal npm-style answer. Adding broader markers like
/// `.git` would re-open the shared-ancestor injection class for any
/// directory inside a git repo.
const PROJECT_MARKERS: &[&str] = &["package.json"];

/// Whether `dir` contains at least one **regular-file** project marker.
/// `metadata().is_file()` follows symlinks (so a symlink to a real
/// `package.json` still counts) but rejects directories and broken
/// symlinks — `mkdir /tmp/package.json` must not qualify `/tmp` as a
/// project root.
fn dir_has_regular_marker(dir: &Path) -> bool {
    PROJECT_MARKERS
        .iter()
        .any(|m| std::fs::metadata(dir.join(m)).is_ok_and(|meta| meta.is_file()))
}

/// Disposition of an `.npmrc` candidate path.
#[derive(Debug)]
enum NpmrcEntry {
    /// Regular file (or symlink resolving to a regular file) — feed
    /// to the loader.
    File(PathBuf),
    /// Entry exists but isn't usable as an `.npmrc` source. Surfaced
    /// as a warning; walker stops here and does NOT fall through to
    /// higher ancestors.
    NotRegular { path: PathBuf, kind: &'static str },
    /// No `.npmrc` entry of any kind at this path.
    Missing,
}

/// Classify a single `.npmrc` candidate path. `symlink_metadata` first
/// so broken symlinks register as entries (`metadata` alone would
/// follow and return `NotFound`, which the caller would silently treat
/// as Missing — that's a silent privilege escalation if left unguarded).
fn inspect_npmrc_at(candidate: &Path) -> NpmrcEntry {
    let lstat = match std::fs::symlink_metadata(candidate) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return NpmrcEntry::Missing,
        Err(_) => {
            return NpmrcEntry::NotRegular {
                path: candidate.to_path_buf(),
                kind: "cannot stat",
            };
        }
    };
    let ft = lstat.file_type();
    if ft.is_file() {
        return NpmrcEntry::File(candidate.to_path_buf());
    }
    if ft.is_symlink() {
        return match std::fs::metadata(candidate) {
            Ok(target_meta) if target_meta.is_file() => NpmrcEntry::File(candidate.to_path_buf()),
            Ok(_) => NpmrcEntry::NotRegular {
                path: candidate.to_path_buf(),
                kind: "is a symlink whose target is not a regular file",
            },
            Err(_) => NpmrcEntry::NotRegular {
                path: candidate.to_path_buf(),
                kind: "is a broken symlink (target unreachable)",
            },
        };
    }
    if ft.is_dir() {
        return NpmrcEntry::NotRegular {
            path: candidate.to_path_buf(),
            kind: "is a directory",
        };
    }
    NpmrcEntry::NotRegular {
        path: candidate.to_path_buf(),
        kind: "is not a regular file",
    }
}

/// Outcome of walking up from `cwd` looking for a project-layer
/// `.npmrc`.
#[derive(Debug)]
enum ProjectNpmrcOutcome {
    /// A regular `.npmrc` was found at an ancestor (including cwd) AND
    /// at least one regular-file project marker was seen at-or-below
    /// that ancestor on the walk path.
    File(PathBuf),
    /// The walker found an `.npmrc` candidate at a level where the
    /// marker requirement was satisfied, but the entry isn't loadable.
    /// Surfaced as a warning by the caller; walker does NOT fall
    /// through to higher ancestors.
    NotRegular { path: PathBuf, kind: &'static str },
    /// No project layer applies. Either no marker was seen on the
    /// walk-up, or the walker exhausted the path without finding a
    /// usable `.npmrc` past a marker.
    None,
}

/// Walk up from `cwd` looking for the project-layer `.npmrc`.
///
/// Algorithm: track `seen_marker` as we walk up. At each level:
/// 1. If `dir == home`: stop.
/// 2. If `dir_has_regular_marker(dir)`: set `seen_marker = true`.
/// 3. If `seen_marker`: classify `dir/.npmrc`.
///    - `File` → return it. Closest-wins: the deepest ancestor whose
///      `.npmrc` we trust is the answer.
///    - `NotRegular` → return it as a warning; do NOT fall through.
///    - `Missing` → continue up. A higher ancestor might still have
///      the workspace-root `.npmrc` (nested member's `package.json`
///      flips the flag, then we walk up to the repo root's `.npmrc`).
/// 4. If not `seen_marker`: do not even look at `dir/.npmrc`. Without
///    a marker on the path, we can't tell a legitimate `.npmrc` from
///    a planted one.
///
/// Why "marker at-or-below" rather than "marker exact-here": npm-style
/// monorepos put `package.json` in each member but `.npmrc` only at
/// the workspace root. A walker that required `.npmrc` and `package.json`
/// in the same directory would miss that pattern entirely.
fn walk_for_project_npmrc(cwd: &Path, home: Option<&Path>) -> ProjectNpmrcOutcome {
    let mut current = Some(cwd);
    let mut seen_marker = false;
    while let Some(dir) = current {
        if Some(dir) == home {
            break;
        }
        if dir_has_regular_marker(dir) {
            seen_marker = true;
        }
        if seen_marker {
            match inspect_npmrc_at(&dir.join(".npmrc")) {
                NpmrcEntry::File(p) => return ProjectNpmrcOutcome::File(p),
                NpmrcEntry::NotRegular { path, kind } => {
                    return ProjectNpmrcOutcome::NotRegular { path, kind };
                }
                NpmrcEntry::Missing => {
                    // Keep walking — repo root might have the workspace .npmrc.
                }
            }
        }
        current = dir.parent();
    }
    ProjectNpmrcOutcome::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npmrc::{NpmrcConfig, RegistryAuth};
    use secrecy::ExposeSecret;
    use std::path::Path;

    fn no_env(_name: &str) -> Option<String> {
        None
    }

    fn fixed_env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    fn encoded_npmrc_password(password: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(password.as_bytes())
    }

    fn encoded_basic_credential(username: &str, password: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}").as_bytes())
    }

    // ---- Walker tests ----

    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Write a `.npmrc` containing `content` at `dir/.npmrc` and return
    /// the file path. Test ergonomics — the panics here are fine because
    /// a test that can't write to its own tempdir is a real failure.
    fn write_npmrc(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join(".npmrc");
        fs::write(&path, content).expect("write npmrc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restrict npmrc permissions");
        }
        path
    }

    #[cfg(unix)]
    fn set_npmrc_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set npmrc mode");
    }

    #[test]
    fn walker_finds_project_only() {
        let proj = TempDir::new().unwrap();
        write_npmrc(proj.path(), "registry=https://project.example/\n");
        let cfg = NpmrcConfig::load_from_paths(&[proj.path().join(".npmrc")], &no_env);
        assert_eq!(
            cfg.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://project.example"
        );
        assert!(cfg.errors.is_empty());
        assert!(cfg.warnings.is_empty());
    }

    #[test]
    fn walker_user_only() {
        let home = TempDir::new().unwrap();
        write_npmrc(home.path(), "registry=https://user.example/\n");
        let cfg = NpmrcConfig::load_from_paths(&[home.path().join(".npmrc")], &no_env);
        assert_eq!(
            cfg.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://user.example"
        );
    }

    #[test]
    fn walker_project_overrides_user_per_key() {
        let home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();
        write_npmrc(home.path(), "registry=https://user.example/\n");
        write_npmrc(proj.path(), "registry=https://project.example/\n");
        // Lowest first, highest last.
        let cfg = NpmrcConfig::load_from_paths(
            &[home.path().join(".npmrc"), proj.path().join(".npmrc")],
            &no_env,
        );
        assert_eq!(
            cfg.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://project.example",
            "project layer must win per-key"
        );
    }

    #[test]
    fn walker_merges_non_overlapping_keys_across_layers() {
        let home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();
        write_npmrc(home.path(), "@a:registry=https://a.example/\n");
        write_npmrc(proj.path(), "@b:registry=https://b.example/\n");
        let cfg = NpmrcConfig::load_from_paths(
            &[home.path().join(".npmrc"), proj.path().join(".npmrc")],
            &no_env,
        );
        assert_eq!(cfg.scope_registries.len(), 2);
        assert!(cfg.scope_registries.contains_key("@a"));
        assert!(cfg.scope_registries.contains_key("@b"));
    }

    #[cfg(unix)]
    #[test]
    fn permissive_layer_keeps_routing_and_refuses_every_credential_form() {
        let dir = TempDir::new().unwrap();
        let path = write_npmrc(
            dir.path(),
            "registry=https://npm.internal/\n\
             //token.example/:_authToken=bearer\n\
             //auth.example/:_auth=dXNlcjpwYXNz\n\
             //pair.example/:_username=user\n\
             //pair.example/:_password=cGFzcw==\n",
        );
        set_npmrc_mode(&path, 0o644);

        let cfg = NpmrcConfig::load_from_paths(&[path], &no_env);

        assert_eq!(
            cfg.default_registry
                .as_ref()
                .map(|target| target.base_url.as_ref()),
            Some("https://npm.internal"),
            "non-secret routing must remain available"
        );
        assert!(
            cfg.origin_auth.is_empty(),
            "permissive files must not materialize credentials: {:?}",
            cfg.origin_auth
        );
        assert_eq!(
            cfg.security_warnings.len(),
            1,
            "one actionable warning must cover the refused layer: {:?}",
            cfg.security_warnings
        );
        assert!(
            cfg.security_warnings[0].contains("mode 0644")
                && cfg.security_warnings[0].contains("chmod 600"),
            "the warning must explain the mode and repair: {:?}",
            cfg.security_warnings
        );
    }

    #[cfg(unix)]
    #[test]
    fn insecure_credential_is_refused_before_missing_env_validation() {
        let dir = TempDir::new().unwrap();
        let path = write_npmrc(
            dir.path(),
            "registry=https://npm.internal/\n//npm.internal/:_authToken=${MISSING_TOKEN}\n",
        );
        set_npmrc_mode(&path, 0o644);

        let cfg = NpmrcConfig::load_from_paths(&[path], &no_env);

        assert!(
            cfg.errors.is_empty(),
            "a refused credential must not evaluate its value: {:?}",
            cfg.errors
        );
        assert!(cfg.origin_auth.is_empty());
        assert_eq!(
            cfg.default_registry
                .as_ref()
                .map(|target| target.base_url.as_ref()),
            Some("https://npm.internal")
        );
        assert_eq!(cfg.security_warnings.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn insecure_higher_layer_cannot_override_secure_lower_credential() {
        let lower = TempDir::new().unwrap();
        let higher = TempDir::new().unwrap();
        let lower_path = write_npmrc(lower.path(), "//npm.internal/:_authToken=secure-lower\n");
        let higher_path = write_npmrc(
            higher.path(),
            "//npm.internal/:_authToken=insecure-higher\n",
        );
        set_npmrc_mode(&higher_path, 0o640);

        let cfg = NpmrcConfig::load_from_paths(&[lower_path, higher_path], &no_env);
        let auth = cfg
            .auth_for_url("https://npm.internal/package")
            .expect("secure lower credential must remain available");

        match auth {
            RegistryAuth::Bearer { token, .. } => {
                assert_eq!(token.expose_secret(), "secure-lower");
            }
            other => panic!("expected bearer credential, got {other:?}"),
        }
    }

    #[test]
    fn walker_skips_missing_files_silently() {
        let nonexistent = PathBuf::from("/definitely/does/not/exist/.npmrc");
        let other = PathBuf::from("/also/missing/.npmrc");
        let cfg = NpmrcConfig::load_from_paths(&[nonexistent, other], &no_env);
        assert!(
            cfg.warnings.is_empty(),
            "NotFound must be silent: {:?}",
            cfg.warnings
        );
        assert!(cfg.errors.is_empty());
        assert!(cfg.default_registry.is_none());
    }

    #[test]
    fn walker_warns_on_other_io_errors() {
        // Pass a directory path. `read_to_string` on a directory errors
        // with EISDIR-ish kind; not NotFound, so we warn (not silent).
        // Cross-platform — directories aren't readable as strings on
        // Unix or Windows.
        let dir = TempDir::new().unwrap();
        let cfg = NpmrcConfig::load_from_paths(&[dir.path().to_path_buf()], &no_env);
        assert_eq!(cfg.warnings.len(), 1, "warnings: {:?}", cfg.warnings);
        assert!(cfg.warnings[0].contains("failed to read"));
        assert!(cfg.errors.is_empty(), "non-fatal — install must continue");
    }

    #[test]
    fn walker_cross_layer_credential_merge_end_to_end() {
        // System layer sets _username, project layer sets _password; walker
        // composes them via merge_over before finalize — must produce one
        // Basic credential with no partial-credential warnings.
        let system_dir = TempDir::new().unwrap();
        let proj_dir = TempDir::new().unwrap();
        write_npmrc(system_dir.path(), "//npm.internal/:_username=alice\n");
        write_npmrc(
            proj_dir.path(),
            &format!(
                "//npm.internal/:_password={}\n",
                encoded_npmrc_password("pass")
            ),
        );
        let cfg = NpmrcConfig::load_from_paths(
            &[
                system_dir.path().join(".npmrc"),
                proj_dir.path().join(".npmrc"),
            ],
            &no_env,
        );
        assert!(
            cfg.warnings.is_empty(),
            "no partial-credential warnings: {:?}",
            cfg.warnings
        );
        let auth = cfg
            .auth_for_url("https://npm.internal/foo")
            .expect("composed Basic credential should resolve");
        match auth {
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), encoded_basic_credential("alice", "pass"))
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    /// Test helper — write a regular-file `package.json` so the dir
    /// counts as a project marker for `walk_for_project_npmrc`. `{}` is
    /// enough; we never parse it.
    fn mark_as_project_root(dir: &Path) {
        fs::write(dir.join("package.json"), "{}").expect("write package.json");
    }

    /// Match a `ProjectNpmrcOutcome::File(_)` and return the path.
    fn expect_outcome_file(outcome: ProjectNpmrcOutcome) -> PathBuf {
        match outcome {
            ProjectNpmrcOutcome::File(p) => p,
            other => panic!("expected ProjectNpmrcOutcome::File, got {other:?}"),
        }
    }

    fn assert_outcome_none(outcome: ProjectNpmrcOutcome) {
        match outcome {
            ProjectNpmrcOutcome::None => {}
            other => panic!("expected ProjectNpmrcOutcome::None, got {other:?}"),
        }
    }

    #[test]
    fn walker_returns_npmrc_when_marker_present_at_same_level() {
        let home = TempDir::new().unwrap();
        let proj = home.path().join("proj");
        fs::create_dir_all(&proj).unwrap();
        mark_as_project_root(&proj);
        let expected = write_npmrc(&proj, "registry=https://here/\n");
        let outcome = walk_for_project_npmrc(&proj, Some(home.path()));
        assert_eq!(
            fs::canonicalize(expect_outcome_file(outcome)).unwrap(),
            fs::canonicalize(&expected).unwrap()
        );
    }

    #[test]
    fn walker_finds_npmrc_at_higher_marker_when_cwd_lacks_one() {
        // cwd is a leaf inside a marked project; the .npmrc lives at
        // the same marker level. Walker walks up: leaf → parent → marker
        // dir, finds .npmrc there.
        let home = TempDir::new().unwrap();
        let project_root = home.path().join("project");
        let leaf = project_root.join("src/utils");
        fs::create_dir_all(&leaf).unwrap();
        mark_as_project_root(&project_root);
        let expected = write_npmrc(&project_root, "registry=https://higher/\n");
        let outcome = walk_for_project_npmrc(&leaf, Some(home.path()));
        assert_eq!(
            fs::canonicalize(expect_outcome_file(outcome)).unwrap(),
            fs::canonicalize(&expected).unwrap()
        );
    }

    #[test]
    fn walker_inherits_repo_root_npmrc_through_workspace_member() {
        // Monorepo layout: workspace member `packages/app` has its own package.json
        // but no .npmrc; workspace root has both. Running from `packages/app` must
        // inherit the workspace-root .npmrc — walker must not stop at the first marker.
        let home = TempDir::new().unwrap();
        let repo = home.path().join("repo");
        let app = repo.join("packages").join("app");
        fs::create_dir_all(&app).unwrap();
        mark_as_project_root(&repo);
        mark_as_project_root(&app);
        let expected = write_npmrc(&repo, "registry=https://workspace-root/\n");
        let outcome = walk_for_project_npmrc(&app, Some(home.path()));
        let found = expect_outcome_file(outcome);
        assert_eq!(
            fs::canonicalize(&found).unwrap(),
            fs::canonicalize(&expected).unwrap(),
            "workspace member must inherit repo-root .npmrc"
        );
    }

    #[test]
    fn walker_app_npmrc_wins_over_repo_npmrc_when_both_present() {
        // Defense for the inheritance fix: when BOTH the member and the
        // workspace root have an .npmrc, the closer one (member) wins.
        // Walker is bottom-up; first match returned.
        let home = TempDir::new().unwrap();
        let repo = home.path().join("repo");
        let app = repo.join("packages").join("app");
        fs::create_dir_all(&app).unwrap();
        mark_as_project_root(&repo);
        mark_as_project_root(&app);
        write_npmrc(&repo, "registry=https://workspace-root/\n");
        let app_npmrc = write_npmrc(&app, "registry=https://app-local/\n");
        let outcome = walk_for_project_npmrc(&app, Some(home.path()));
        assert_eq!(
            fs::canonicalize(expect_outcome_file(outcome)).unwrap(),
            fs::canonicalize(&app_npmrc).unwrap()
        );
    }

    #[test]
    fn walker_stops_at_home() {
        // No marker between cwd and home → None. A marker exactly AT
        // home is ignored (we stop AT home, not past it) so the user-
        // level layer is never double-counted as project.
        let home = TempDir::new().unwrap();
        mark_as_project_root(home.path());
        let child = home.path().join("project");
        fs::create_dir_all(&child).unwrap();
        let outcome = walk_for_project_npmrc(&child, Some(home.path()));
        assert_outcome_none(outcome);
    }

    #[test]
    fn walker_returns_none_when_no_marker_anywhere() {
        // Bounded by tempdir as fake home. No marker anywhere reachable
        // from nested cwd → None even if a planted .npmrc exists below.
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a/b/c");
        fs::create_dir_all(&nested).unwrap();
        // Plant an .npmrc at the deeply-nested cwd. Without a marker,
        // the walker must NOT pick it up.
        write_npmrc(&nested, "registry=https://orphan/\n");
        let outcome = walk_for_project_npmrc(&nested, Some(dir.path()));
        assert_outcome_none(outcome);
    }

    #[test]
    fn walker_rejects_directory_named_package_json_marker() {
        // A directory named `package.json` must NOT qualify as a project-root
        // marker — an attacker could `mkdir /tmp/package.json && touch /tmp/.npmrc`
        // to inject auth into any install run from /tmp/build/.
        let outer = TempDir::new().unwrap();
        let attacker_dir = outer.path().join("planted");
        let cwd = attacker_dir.join("build");
        fs::create_dir_all(&cwd).unwrap();
        // Directory (not a regular file) — must NOT count as a marker.
        fs::create_dir(attacker_dir.join("package.json")).unwrap();
        write_npmrc(&attacker_dir, "registry=https://attacker/\n");
        let outcome = walk_for_project_npmrc(&cwd, Some(outer.path()));
        assert_outcome_none(outcome);
    }

    #[cfg(unix)]
    #[test]
    fn walker_rejects_broken_symlink_named_package_json_marker() {
        // A broken-symlink package.json must not qualify the dir as a project root
        // for the same reason as a directory marker: it's not a regular file.
        use std::os::unix::fs::symlink;
        let outer = TempDir::new().unwrap();
        let attacker_dir = outer.path().join("planted");
        let cwd = attacker_dir.join("build");
        fs::create_dir_all(&cwd).unwrap();
        symlink("/does/not/exist/path", attacker_dir.join("package.json")).unwrap();
        write_npmrc(&attacker_dir, "registry=https://attacker/\n");
        let outcome = walk_for_project_npmrc(&cwd, Some(outer.path()));
        assert_outcome_none(outcome);
    }

    #[test]
    fn discover_layer_paths_omits_project_when_no_marker() {
        // Same security contract at the public-API level: discovery
        // must NOT include a project layer if no marker was found,
        // even if `<cwd>/.npmrc` exists. This is the load-bearing
        // anti-injection guarantee for cwd-outside-home cases.
        let outer = TempDir::new().unwrap();
        let dir = outer.path().join("project-without-marker");
        fs::create_dir_all(&dir).unwrap();
        // Plant a .npmrc but no package.json — must be ignored.
        write_npmrc(&dir, "registry=https://injected/\n");
        let result = NpmrcConfig::discover_layer_paths(&dir, Some(outer.path()));
        // home boundary is the outer tempdir; dir itself has no marker.
        // Expect only builtin + system + user (3 paths) — NO project layer.
        assert_eq!(result.paths.len(), 3, "paths: {:?}", result.paths);
        assert!(
            !result.paths.iter().any(|p| p == &dir.join(".npmrc")),
            "planted .npmrc must NOT be in paths: {:?}",
            result.paths
        );
    }

    #[test]
    fn discover_layer_paths_warns_on_directory_dot_npmrc() {
        // When the project's .npmrc is a directory, surface a warning;
        // do NOT silently fall through to an ancestor.
        let proj = TempDir::new().unwrap();
        mark_as_project_root(proj.path());
        fs::create_dir(proj.path().join(".npmrc")).unwrap();
        // home boundary: the parent of our tempdir, so the walk
        // doesn't hit anything outside our control.
        let home = proj.path().parent().unwrap();
        let result = NpmrcConfig::discover_layer_paths(proj.path(), Some(home));
        assert!(
            !result
                .paths
                .iter()
                .any(|p| p.ends_with(".npmrc") && p.starts_with(proj.path())),
            "directory .npmrc must NOT be in paths: {:?}",
            result.paths
        );
        assert_eq!(result.warnings.len(), 1, "warnings: {:?}", result.warnings);
        assert!(result.warnings[0].contains("is a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn discover_layer_paths_warns_on_broken_symlink() {
        // A broken symlink must surface a warning, not silently fall through.
        // Unix-only — Windows symlink semantics differ enough that a parallel
        // codepath in this test isn't worth maintaining.
        use std::os::unix::fs::symlink;
        let proj = TempDir::new().unwrap();
        mark_as_project_root(proj.path());
        symlink("/nonexistent/target/path", proj.path().join(".npmrc"))
            .expect("create broken symlink");
        let home = proj.path().parent().unwrap();
        let result = NpmrcConfig::discover_layer_paths(proj.path(), Some(home));
        assert!(
            !result.paths.iter().any(|p| p.starts_with(proj.path())),
            "broken-symlink .npmrc must NOT be loaded: {:?}",
            result.paths
        );
        assert_eq!(result.warnings.len(), 1, "warnings: {:?}", result.warnings);
        assert!(
            result.warnings[0].contains("broken symlink"),
            "expected broken-symlink warning, got: {:?}",
            result.warnings[0]
        );
    }

    #[test]
    fn discover_layer_paths_includes_user_when_home_set() {
        let home = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();
        mark_as_project_root(proj.path());
        write_npmrc(proj.path(), "registry=https://p/\n");
        let result = NpmrcConfig::discover_layer_paths(proj.path(), Some(home.path()));
        assert_eq!(result.paths.len(), 4);
        assert_eq!(result.paths[0], PathBuf::from("/usr/etc/npmrc"));
        assert_eq!(result.paths[1], PathBuf::from("/etc/npmrc"));
        assert_eq!(result.paths[2], home.path().join(".npmrc"));
        assert_eq!(result.paths[3], proj.path().join(".npmrc"));
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn discover_layer_paths_omits_user_when_home_none() {
        // Bound the search by giving discover a home-equivalent (the
        // tempdir's own parent) so we don't traverse the dev machine's
        // entire FS looking for an ancestor package.json. The
        // `home: None` argument means no user-level layer is included,
        // not "no home boundary at all".
        //
        // We can't easily test the home=None path in isolation without
        // potentially picking up the real `~/.npmrc` of whoever runs
        // the test. The contract under test here is just "no user layer
        // when home arg is None".
        let proj = TempDir::new().unwrap();
        let result = NpmrcConfig::discover_layer_paths(proj.path(), None);
        // First two are always builtin and system.
        assert!(result.paths.len() >= 2);
        assert_eq!(result.paths[0], PathBuf::from("/usr/etc/npmrc"));
        assert_eq!(result.paths[1], PathBuf::from("/etc/npmrc"));
        // Anything beyond paths[1] would be a project layer that
        // `find_project_root` discovered above our tempdir on the
        // dev machine. None of it should reference our own tempdir
        // (we never wrote a marker there).
        for p in &result.paths[2..] {
            assert!(
                !p.starts_with(proj.path()),
                "no project layer should reference our tempdir: {p:?}"
            );
        }
    }

    #[test]
    fn walker_propagates_env_lookup_per_layer() {
        // Each parsed layer goes through env interpolation independently.
        // System layer references $TOK_A, project references $TOK_B —
        // both must resolve via the same env_lookup we pass in.
        let system = TempDir::new().unwrap();
        let proj = TempDir::new().unwrap();
        write_npmrc(system.path(), "//host-a/:_authToken=${TOK_A}\n");
        write_npmrc(proj.path(), "//host-b/:_authToken=${TOK_B}\n");
        let env = fixed_env(&[("TOK_A", "alpha"), ("TOK_B", "beta")]);
        let cfg = NpmrcConfig::load_from_paths(
            &[system.path().join(".npmrc"), proj.path().join(".npmrc")],
            &env,
        );
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        match cfg.auth_for_url("https://host-a/x").unwrap() {
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "alpha"),
            _ => panic!("expected Bearer A"),
        }
        match cfg.auth_for_url("https://host-b/x").unwrap() {
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "beta"),
            _ => panic!("expected Bearer B"),
        }
    }
}
