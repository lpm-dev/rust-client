use super::config::NpmrcConfig;
use super::parse::CredentialPolicy;
use lpm_common::{
    BoundedReadError, NPMRC_FILE_SIZE_CAP_BYTES, read_text_regular_file_capped_with_metadata,
};
use std::path::{Path, PathBuf};

type OpenedLayer = Result<(String, std::fs::Metadata), BoundedReadError>;

#[derive(Debug)]
struct PreloadedLayer {
    index: usize,
    path: PathBuf,
    opened: OpenedLayer,
}

impl NpmrcConfig {
    /// Compute the four `.npmrc` paths in **lowest-to-highest precedence
    /// order**, plus any warnings raised during discovery (e.g., a project
    /// `.npmrc` that turned out to be a directory). The user layer is opened
    /// once so its content can select npm's prefix-derived global config and
    /// then be reused by [`Self::load_from_discovery`].
    ///
    /// Layers:
    /// 1. `<effective-node-prefix>/etc/npmrc` — npm's global config.
    /// 2. `<home>/.npmrc` — user-level, included only if `home` is `Some`.
    ///    Most teams put their auth tokens here.
    /// 4. `<project-or-workspace-root>/.npmrc` — selected with the same
    ///    workspace discovery used by install. Workspace members use the
    ///    root config; independent nested projects do not inherit an
    ///    unrelated parent's config.
    ///
    /// Layers 1–3 are returned even if their files don't exist; the
    /// loader silently skips missing files. Layer 4 is **bounded** to
    /// the project — without a regular-file project marker on the path,
    /// no project layer is included (a planted non-regular marker would
    /// otherwise qualify any directory as a project root).
    pub fn discover_layer_paths(cwd: &Path, home: Option<&Path>) -> LayerDiscovery {
        let user_config_path = lpm_common::npm_user_config_path(home);
        let opened_user = user_config_path.as_deref().map(|path| {
            read_text_regular_file_capped_with_metadata(path, NPMRC_FILE_SIZE_CAP_BYTES)
        });
        let global_config = lpm_common::npm_global_config_path_from_user_config(
            home,
            opened_user
                .as_ref()
                .and_then(|opened| opened.as_ref().ok())
                .map(|(content, metadata)| (content.as_str(), metadata)),
        );
        let mut discovery = Self::discover_layer_paths_with_global_config(cwd, home, global_config);
        discovery.preloaded_user = match (discovery.user_layer_index, user_config_path, opened_user)
        {
            (Some(index), Some(path), Some(opened)) => Some(PreloadedLayer {
                index,
                path,
                opened,
            }),
            _ => None,
        };
        discovery
    }

    fn discover_layer_paths_with_global_config(
        cwd: &Path,
        home: Option<&Path>,
        global_config: PathBuf,
    ) -> LayerDiscovery {
        let mut paths = Vec::with_capacity(3);
        let mut warnings = Vec::new();
        let mut project_layer_index = None;
        let mut user_layer_index = None;
        paths.push(global_config);
        if let Some(user_config) = lpm_common::npm_config_path_with_home("userconfig", home) {
            user_layer_index = Some(paths.len());
            paths.push(user_config);
        } else if let Some(h) = home {
            user_layer_index = Some(paths.len());
            paths.push(h.join(".npmrc"));
        }
        match npm_project_npmrc(cwd, home) {
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
            user_layer_index,
            preloaded_user: None,
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
        Self::load_from_paths_with_project_index_and_preloaded(
            paths,
            project_layer_index,
            None,
            env_lookup,
        )
    }

    /// Load a discovered configuration while reusing the already-opened user
    /// layer that selected npm's prefix-derived global configuration path.
    pub fn load_from_discovery(
        mut discovery: LayerDiscovery,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let mut config = Self::load_from_paths_with_project_index_and_preloaded(
            &discovery.paths,
            discovery.project_layer_index,
            discovery.preloaded_user.take(),
            env_lookup,
        );
        discovery.warnings.append(&mut config.warnings);
        config.warnings = discovery.warnings;
        config
    }

    fn load_from_paths_with_project_index_and_preloaded(
        paths: &[PathBuf],
        project_layer_index: Option<usize>,
        mut preloaded: Option<PreloadedLayer>,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let mut acc = NpmrcConfig::default();
        for (idx, path) in paths.iter().enumerate() {
            let opened = if preloaded
                .as_ref()
                .is_some_and(|layer| layer.index == idx && layer.path == *path)
            {
                preloaded.take().expect("preloaded layer is present").opened
            } else {
                read_text_regular_file_capped_with_metadata(path, NPMRC_FILE_SIZE_CAP_BYTES)
            };
            match opened {
                Ok((content, file_metadata)) => {
                    let label = path.display().to_string();
                    let source_dir = path.parent();
                    let is_project = Some(idx) == project_layer_index;

                    #[cfg(unix)]
                    let credential_refusal_warning = {
                        use std::os::unix::fs::PermissionsExt;

                        let permissions = file_metadata.permissions();
                        let mode = permissions.mode() & 0o777;
                        if mode & 0o022 != 0 {
                            acc.security_warnings.push(format!(
                                "{label}: .npmrc mode {mode:04o} is writable by group or others; refused the entire layer. Run `chmod 600 {}` before using it",
                                path.display(),
                            ));
                            continue;
                        }
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
        Self::load_from_discovery(discovery, &|name| std::env::var(name).ok())
    }
}

fn npm_project_npmrc(cwd: &Path, home: Option<&Path>) -> ProjectNpmrcOutcome {
    let Some(project) = lpm_workspace::find_project_root(cwd) else {
        return ProjectNpmrcOutcome::None;
    };
    if home.is_some_and(|home| project == home) {
        return ProjectNpmrcOutcome::None;
    }
    let selected = match lpm_workspace::find_workspace_root(&project) {
        Ok(Some(workspace)) => workspace,
        Ok(None) => project,
        Err(_) => project,
    };
    match inspect_npmrc_at(&selected.join(".npmrc")) {
        NpmrcEntry::File(path) => ProjectNpmrcOutcome::File(path),
        NpmrcEntry::NotRegular { path, kind } => ProjectNpmrcOutcome::NotRegular { path, kind },
        NpmrcEntry::Missing => ProjectNpmrcOutcome::None,
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
    user_layer_index: Option<usize>,
    preloaded_user: Option<PreloadedLayer>,
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

#[cfg(test)]
mod tests {
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
    fn discovered_user_layer_is_reused_without_a_second_read() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        write_npmrc(home.path(), "registry=https://opened.example/\n");

        let discovery = NpmrcConfig::discover_layer_paths(project.path(), Some(home.path()));
        write_npmrc(home.path(), "registry=https://replaced.example/\n");
        let config = NpmrcConfig::load_from_discovery(discovery, &no_env);

        assert_eq!(
            config
                .default_registry
                .as_ref()
                .map(|target| target.base_url.as_ref()),
            Some("https://opened.example")
        );
    }

    #[test]
    fn mutated_discovery_path_does_not_relabel_preloaded_user_content() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        write_npmrc(home.path(), "registry=https://opened.example/\n");
        let replacement = home.path().join("replacement.npmrc");
        fs::write(&replacement, "registry=https://replacement.example/\n").unwrap();
        #[cfg(unix)]
        set_npmrc_mode(&replacement, 0o600);

        let mut discovery = NpmrcConfig::discover_layer_paths(project.path(), Some(home.path()));
        let user_index = discovery.user_layer_index.expect("user layer index");
        discovery.paths[user_index] = replacement;
        let config = NpmrcConfig::load_from_discovery(discovery, &no_env);

        assert_eq!(
            config
                .default_registry
                .as_ref()
                .map(|target| target.base_url.as_ref()),
            Some("https://replacement.example")
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
             //pair.example/:username=user\n\
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

    #[cfg(unix)]
    #[test]
    fn filesystem_layer_read_rejects_a_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("config.npmrc");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

        let fifo_for_worker = fifo.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let config = NpmrcConfig::load_from_paths(&[fifo_for_worker], &no_env);
            sender.send(config).unwrap();
        });
        let config = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(config) => config,
            Err(error) => {
                let writer = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                drop(writer);
                let _ = receiver.recv_timeout(std::time::Duration::from_secs(1));
                worker.join().unwrap();
                panic!("registry npmrc loading blocked on a FIFO: {error}");
            }
        };
        worker.join().unwrap();
        assert!(
            config
                .warnings
                .iter()
                .any(|warning| warning.contains("regular file")),
            "a special-file layer must be rejected explicitly: {:?}",
            config.warnings
        );
    }

    #[test]
    fn walker_cross_layer_credential_merge_end_to_end() {
        // System layer sets username, project layer sets _password; walker
        // composes them via merge_over before finalize — must produce one
        // Basic credential with no partial-credential warnings.
        let system_dir = TempDir::new().unwrap();
        let proj_dir = TempDir::new().unwrap();
        write_npmrc(system_dir.path(), "//npm.internal/:username=alice\n");
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

    /// Test helper — write a regular-file `package.json` so workspace
    /// discovery recognizes the directory as a project.
    fn mark_as_project_root(dir: &Path) {
        fs::write(dir.join("package.json"), "{}").expect("write package.json");
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
        assert_eq!(result.paths.len(), 2, "paths: {:?}", result.paths);
        assert_eq!(
            result.paths[0],
            lpm_common::npm_global_config_path(Some(outer.path()))
        );
        assert_eq!(result.paths[1], outer.path().join(".npmrc"));
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
        assert_eq!(result.paths.len(), 3);
        assert_eq!(
            result.paths[0],
            lpm_common::npm_global_config_path(Some(home.path()))
        );
        assert_eq!(result.paths[1], home.path().join(".npmrc"));
        assert_eq!(result.paths[2], proj.path().join(".npmrc"));
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
        assert!(!result.paths.is_empty());
        assert_eq!(result.paths[0], lpm_common::npm_global_config_path(None));
        // Anything beyond paths[0] would be a project layer that
        // `find_project_root` discovered above our tempdir on the
        // dev machine. None of it should reference our own tempdir
        // (we never wrote a marker there).
        for p in &result.paths[1..] {
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

    #[test]
    fn nested_independent_project_does_not_inherit_parent_npmrc() {
        let home = TempDir::new().unwrap();
        let parent = home.path().join("parent");
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(parent.join("package.json"), r#"{"name":"parent"}"#).unwrap();
        fs::write(child.join("package.json"), r#"{"name":"child"}"#).unwrap();
        write_npmrc(&parent, "registry=https://parent.example/\n");

        let discovery = NpmrcConfig::discover_layer_paths(&child, Some(home.path()));
        assert!(
            !discovery
                .paths
                .iter()
                .any(|path| path == &parent.join(".npmrc")),
            "an independent child project must not inherit a parent project's npmrc: {:?}",
            discovery.paths
        );
        assert!(discovery.project_layer_index.is_none());
    }

    #[test]
    fn workspace_member_uses_root_npmrc_and_ignores_member_npmrc() {
        let home = TempDir::new().unwrap();
        let root = home.path().join("workspace");
        let member = root.join("packages/app");
        fs::create_dir_all(&member).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        fs::write(member.join("package.json"), r#"{"name":"app"}"#).unwrap();
        let root_npmrc = write_npmrc(&root, "registry=https://root.example/\n");
        write_npmrc(&member, "registry=https://member.example/\n");

        let discovery = NpmrcConfig::discover_layer_paths(&member, Some(home.path()));
        let project_index = discovery
            .project_layer_index
            .expect("workspace project layer");
        assert_eq!(discovery.paths[project_index], root_npmrc);
    }

    #[cfg(unix)]
    #[test]
    fn writable_npmrc_layer_contributes_no_routing_tls_or_credentials() {
        let dir = TempDir::new().unwrap();
        let path = write_npmrc(
            dir.path(),
            "registry=https://attacker.example/\n\
             ca=-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----\n\
             //attacker.example/:_authToken=secret\n",
        );
        set_npmrc_mode(&path, 0o602);

        let cfg = NpmrcConfig::load_from_paths(&[path], &no_env);
        assert!(cfg.default_registry.is_none());
        assert!(cfg.tls.extra_roots.is_empty());
        assert!(cfg.origin_auth.is_empty());
        assert!(
            cfg.security_warnings
                .iter()
                .any(|warning| warning.contains("writable") && warning.contains("refused")),
            "writable-layer refusal must be visible: {:?}",
            cfg.security_warnings
        );
    }

    #[test]
    fn filesystem_discovery_honors_userconfig_and_globalconfig_overrides() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                for (name, value) in self.0.drain(..) {
                    // SAFETY: this test holds ENV_LOCK for the mutation window.
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(name, value),
                            None => std::env::remove_var(name),
                        }
                    }
                }
            }
        }

        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = TempDir::new().unwrap();
        let project = root.path().join("project");
        fs::create_dir_all(&project).unwrap();
        mark_as_project_root(&project);
        let global = root.path().join("global.npmrc");
        let user = root.path().join("user.npmrc");
        fs::write(&global, "@global:registry=https://global.example/\n").unwrap();
        fs::write(&user, "@user:registry=https://user.example/\n").unwrap();
        #[cfg(unix)]
        {
            set_npmrc_mode(&global, 0o600);
            set_npmrc_mode(&user, 0o600);
        }
        let restore = RestoreEnv(
            ["NPM_CONFIG_GLOBALCONFIG", "NPM_CONFIG_USERCONFIG"]
                .into_iter()
                .map(|name| (name, std::env::var_os(name)))
                .collect(),
        );
        // SAFETY: this test holds ENV_LOCK and restores both values on drop.
        unsafe {
            std::env::set_var("NPM_CONFIG_GLOBALCONFIG", &global);
            std::env::set_var("NPM_CONFIG_USERCONFIG", &user);
        }

        let cfg = NpmrcConfig::load_from_filesystem(&project);
        drop(restore);
        assert_eq!(
            cfg.scope_registries["@global"].base_url.as_ref(),
            "https://global.example"
        );
        assert_eq!(
            cfg.scope_registries["@user"].base_url.as_ref(),
            "https://user.example"
        );
    }

    #[cfg(unix)]
    #[test]
    fn writable_user_config_cannot_redirect_global_config_discovery() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                for (name, value) in self.0.drain(..) {
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(name, value),
                            None => std::env::remove_var(name),
                        }
                    }
                }
            }
        }

        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = TempDir::new().unwrap();
        let project = root.path().join("project");
        fs::create_dir_all(&project).unwrap();
        mark_as_project_root(&project);
        let redirected_prefix = root.path().join("redirected-prefix");
        fs::create_dir_all(redirected_prefix.join("etc")).unwrap();
        fs::write(
            redirected_prefix.join("etc/npmrc"),
            "@redirected:registry=https://redirected.example/\n",
        )
        .unwrap();
        let user = root.path().join("user.npmrc");
        fs::write(&user, format!("prefix={}\n", redirected_prefix.display())).unwrap();
        set_npmrc_mode(&user, 0o622);
        let names = [
            "NPM_CONFIG_USERCONFIG",
            "npm_config_userconfig",
            "NPM_CONFIG_GLOBALCONFIG",
            "npm_config_globalconfig",
            "NPM_CONFIG_PREFIX",
            "npm_config_prefix",
            "PREFIX",
        ];
        let restore = RestoreEnv(
            names
                .into_iter()
                .map(|name| (name, std::env::var_os(name)))
                .collect(),
        );
        unsafe {
            for name in names {
                std::env::remove_var(name);
            }
            std::env::set_var("NPM_CONFIG_USERCONFIG", &user);
        }

        let config = NpmrcConfig::load_from_filesystem(&project);
        drop(restore);

        assert!(!config.scope_registries.contains_key("@redirected"));
        assert!(
            config
                .security_warnings
                .iter()
                .any(|warning| warning.contains("writable") && warning.contains("refused")),
            "the untrusted user layer must be refused: {:?}",
            config.security_warnings
        );
    }
}
