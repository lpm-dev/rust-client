use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Validate that all extracted file paths stay within the target directory.
///
/// Prevents malicious tarballs from writing outside the extraction directory
/// using `../` or symlink tricks.
pub(super) fn validate_extracted_paths(
    files: &[PathBuf],
    target_dir: &Path,
) -> Result<(), LpmError> {
    let target_canonical = target_dir
        .canonicalize()
        .unwrap_or_else(|_| target_dir.to_path_buf());

    for file in files {
        let resolved = target_dir.join(file);
        let canonical = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());
        if !canonical.starts_with(&target_canonical) {
            return Err(LpmError::Registry(format!(
                "path traversal detected: '{}' escapes target directory",
                file.display()
            )));
        }
    }
    Ok(())
}

/// Compose [`resolve_safe_dest_validate`] + [`prepare_safe_dest_parent`]
/// for the test suite that exercises both phases as a single call.
///
/// Production callers hold the two phases apart so a
/// `ManifestTransaction` snapshot opens between validation and the
/// mkdir-during-copy step. See `resolve_safe_dest_validate` for the
/// threat model.
#[cfg(test)]
fn resolve_safe_dest(
    target_root_canonical: &Path,
    target_dir: &Path,
    dest_rel: &str,
) -> Result<PathBuf, LpmError> {
    let dest = resolve_safe_dest_validate(target_root_canonical, target_dir, dest_rel)?;
    let parent = dest.parent().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no parent", dest.display()))
    })?;
    let parent_canonical = prepare_safe_dest_parent(parent, target_root_canonical)?;
    let file_name = dest.file_name().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no file name", dest.display()))
    })?;
    Ok(parent_canonical.join(file_name))
}

/// Validate a write destination under a canonical target root, without
/// any filesystem side effects.
///
/// Destination-side containment for `lpm add`. `validate_extracted_paths`
/// proves the tarball did not escape extraction; this function proves
/// the user-side write does not escape `target_dir` either, including
/// via existing symlinks.
///
/// **Ordering matters.** Every check that can establish "this destination
/// is unsafe" runs BEFORE any filesystem mutation. `create_dir_all`
/// must not run before the canonical-parent containment check, because a malicious
/// `dest = "../../escape/evil.txt"` or an absolute `dest = "/tmp/elsewhere/evil.txt"`
/// would create the directory outside the target before erroring on the
/// file write. The directory side-effect was the bug; the file write was
/// already blocked.
///
/// Defense in depth, in order:
/// 1. **Lexical absolute-path reject.** `Path::join` replaces the base
///    when the join argument is absolute, so an absolute `dest_rel`
///    would route the write to whatever path the tarball asked for.
///    Reject up-front, no filesystem touch.
/// 2. **Lexical `..` / root-component reject.** Any `dest_rel` containing
///    `ParentDir` (`..`), `RootDir` (`/`), or a `Prefix` (Windows drive)
///    component cannot legitimately resolve to a path under `target_dir`.
///    Reject up-front, no filesystem touch. This kills the entire
///    `../../escape` attack class before any mkdir runs.
/// 3. **Existing-symlink reject.** If `dest_rel` resolves to an existing
///    symlink, refuse to follow/overwrite it — even if it points inside
///    target today, it can be repointed before the write.
/// 4. **Pre-mkdir ancestor canonicalization.** Walk up from the
///    destination's parent until we hit an existing ancestor; canonicalize
///    that and require it to live under `target_root_canonical`. Catches
///    the case where some intermediate dir is itself a symlink pointing
///    outside (e.g., `target_dir/foo` → `/tmp/elsewhere`,
///    `dest_rel = "foo/bar.txt"`).
///
/// The mkdir + post-mkdir re-canonicalize pair lives in
/// [`prepare_safe_dest_parent`]. The copy flow splits the two so a
/// `ManifestTransaction` snapshot can record every validated dest path
/// before any directory side effects happen.
pub(super) fn resolve_safe_dest_validate(
    target_root_canonical: &Path,
    target_dir: &Path,
    dest_rel: &str,
) -> Result<PathBuf, LpmError> {
    let rel_path = Path::new(dest_rel);

    // Reject absolute `dest_rel`. `Path::join(absolute)` would
    // discard `target_dir` and route the write to the absolute path.
    if rel_path.is_absolute() {
        return Err(LpmError::Registry(format!(
            "destination '{dest_rel}' is absolute; only paths relative to the target are allowed"
        )));
    }

    // Reject `..`, root, and Windows-prefix components. With this
    // gate, the joined path cannot lexically escape `target_dir`, and the
    // mkdir later cannot create directories outside the target — even
    // if the canonical-parent check that follows would later catch the
    // escape attempt.
    for component in rel_path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(LpmError::Registry(format!(
                    "destination '{dest_rel}' contains '..'; \
                     parent-directory references are not allowed in destination paths"
                )));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(LpmError::Registry(format!(
                    "destination '{dest_rel}' contains a root or drive component; \
                     only relative paths under the target are allowed"
                )));
            }
            _ => {}
        }
    }

    let dest = target_dir.join(rel_path);

    // Refuse to overwrite/follow an existing symlink at the
    // destination itself. `symlink_metadata` does NOT follow links.
    if let Ok(meta) = std::fs::symlink_metadata(&dest)
        && meta.file_type().is_symlink()
    {
        return Err(LpmError::Registry(format!(
            "destination '{}' is a symlink; refusing to write through it",
            dest.display()
        )));
    }

    let parent = dest.parent().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no parent", dest.display()))
    })?;

    // Pre-mkdir ancestor canonicalization: walk up until we hit
    // a path that exists, canonicalize THAT (following any symlinks),
    // and require it to live under `target_root_canonical`. This catches
    // the case where an intermediate directory inside the target is
    // itself a symlink pointing outside.
    let mut probe: PathBuf = parent.to_path_buf();
    let canonical_existing_ancestor = loop {
        match probe.canonicalize() {
            Ok(c) => break c,
            Err(_) => {
                if !probe.pop() {
                    return Err(LpmError::Registry(format!(
                        "could not find any existing ancestor of '{}'",
                        parent.display()
                    )));
                }
            }
        }
    };
    if !canonical_existing_ancestor.starts_with(target_root_canonical) {
        return Err(LpmError::Registry(format!(
            "path containment violation: '{}' resolves outside target '{}'",
            dest.display(),
            target_root_canonical.display()
        )));
    }

    Ok(dest)
}

/// mkdir + post-mkdir re-canonicalize phase of [`resolve_safe_dest`].
///
/// Must be called only after [`resolve_safe_dest_validate`] has passed
/// for the dest path that owns this `parent`. Splitting these phases
/// lets the `lpm add` snapshot see every validated dest path
/// before any directory side effects happen — so a rollback restores
/// only files that legitimately needed to land under the target, not
/// anything created by an unvalidated path probe.
pub(super) fn prepare_safe_dest_parent(
    parent: &Path,
    target_root_canonical: &Path,
) -> Result<PathBuf, LpmError> {
    // Containment is proven before creating the parent.
    std::fs::create_dir_all(parent).map_err(|e| {
        LpmError::Registry(format!(
            "could not create destination parent '{}': {e}",
            parent.display()
        ))
    })?;

    // Post-mkdir re-canonicalize. If a TOCTOU race swapped in a
    // symlink after validation, this surfaces it.
    let parent_canonical = parent.canonicalize().map_err(|e| {
        LpmError::Registry(format!(
            "could not canonicalize destination parent '{}': {e}",
            parent.display()
        ))
    })?;
    if !parent_canonical.starts_with(target_root_canonical) {
        return Err(LpmError::Registry(format!(
            "path containment violation post-create: '{}' resolves outside target '{}'",
            parent.display(),
            target_root_canonical.display()
        )));
    }

    Ok(parent_canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_safe_dest_normal_path_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        let resolved = resolve_safe_dest(&canonical, target, "components/foo.tsx").unwrap();
        assert!(resolved.starts_with(&canonical));
        assert!(resolved.ends_with("foo.tsx"));
    }

    #[test]
    fn resolve_safe_dest_dotdot_in_path_rejected_with_no_external_dir_created() {
        // The path must be rejected before mkdir can leave a stray
        // `target_dir/../escaped/` directory outside the target.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest(&canonical, &target, "../../escaped/evil.txt")
            .expect_err("should reject");
        match err {
            LpmError::Registry(msg) => {
                assert!(
                    msg.contains("'..'") || msg.contains("parent-directory"),
                    "expected lexical `..` reject, got: {msg}"
                );
            }
            other => panic!("expected Registry error, got {other:?}"),
        }

        // No directory is created outside target_dir.
        let escaped_within_project = outer.path().join("project").join("escaped");
        assert!(
            !escaped_within_project.exists(),
            "containment failure: '{}' was created as a side-effect before the error fired",
            escaped_within_project.display(),
        );
        let canonical_outer = outer.path().canonicalize().unwrap();
        for entry in std::fs::read_dir(&canonical_outer).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert_eq!(
                name, "project",
                "containment failure: unexpected entry '{name}' in outer tempdir",
            );
        }
    }

    #[test]
    fn resolve_safe_dest_absolute_dest_rejected_with_no_external_dir_created() {
        // `target_dir.join(absolute)` returns the absolute path verbatim,
        // so the lexical absolute-path reject must fire before any mkdir.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        // Use a deterministic external path inside an UNRELATED tempdir
        // so the test cannot accidentally observe the test harness's
        // own scratch directory.
        let elsewhere =
            std::env::temp_dir().join(format!("lpm-abs-dest-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&elsewhere);
        let abs_dest = elsewhere.join("evil.txt");
        let abs_dest_str = abs_dest.to_string_lossy().to_string();

        let err = resolve_safe_dest(&canonical, &target, &abs_dest_str)
            .expect_err("should reject absolute dest");
        match err {
            LpmError::Registry(msg) => {
                assert!(
                    msg.contains("absolute"),
                    "expected lexical absolute-path reject, got: {msg}"
                );
            }
            other => panic!("expected Registry error, got {other:?}"),
        }

        // The external directory must not be created.
        assert!(
            !elsewhere.exists(),
            "containment failure: absolute-dest mkdir leaked outside target — '{}' was created",
            elsewhere.display(),
        );
    }

    #[test]
    fn resolve_safe_dest_dotdot_in_middle_of_path_also_rejected() {
        // `foo/../bar.txt` lexically resolves back inside target, but we
        // still reject it: legitimate package authors don't need
        // parent-references in their dest paths, and accepting them
        // would force a more complex lexical-resolution path that's
        // easier to get wrong than a blanket reject.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest(&canonical, &target, "foo/../bar.txt")
            .expect_err("should reject `..` in middle");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("'..'") || msg.contains("parent-directory"),
                "expected lexical `..` reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
        // No `foo/` created inside target.
        assert!(
            !target.join("foo").exists(),
            "containment failure: even a benign-looking `foo/../bar.txt` should not mkdir `foo/`"
        );
    }

    #[test]
    fn resolve_safe_dest_existing_symlink_destination_rejected() {
        // Pre-create target_dir/foo as a symlink to /tmp/elsewhere
        // and confirm resolve_safe_dest refuses to write through it.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let target = dir.path();
            let canonical = target.canonicalize().unwrap();
            let symlink_path = target.join("foo");
            std::os::unix::fs::symlink(elsewhere.path(), &symlink_path).unwrap();

            let err = resolve_safe_dest(&canonical, target, "foo").expect_err("should reject");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("symlink"),
                    "expected symlink-refusal error, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_safe_dest_intermediate_symlink_dir_rejected() {
        // target/foo/ is a symlink to /tmp/elsewhere. Writing `foo/bar.txt`
        // would resolve to `/tmp/elsewhere/bar.txt` — outside the target
        // root. The canonical-parent check must catch this.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let target = dir.path();
            let canonical = target.canonicalize().unwrap();
            let symlink_dir = target.join("foo");
            std::os::unix::fs::symlink(elsewhere.path(), &symlink_dir).unwrap();

            let err =
                resolve_safe_dest(&canonical, target, "foo/bar.txt").expect_err("should reject");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("path containment violation"),
                    "expected containment error, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }

    // The validate phase is the half of `resolve_safe_dest` that has
    // NO directory side effects. `lpm add`'s rollback flow opens a
    // `ManifestTransaction` snapshot between validation and the
    // mkdir-during-copy step, so validate must reject every malicious
    // dest_rel without creating ancestor directories. Otherwise a
    // failed `lpm add` would leave empty directories under the
    // target that the rollback can't reach.

    #[test]
    fn resolve_safe_dest_validate_does_not_mkdir_on_success() {
        // Happy path. `dest_rel` points inside an existing target dir;
        // validate must NOT create the `components/` parent that the
        // copy step would later need. That mkdir belongs in the
        // separate prepare phase.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        let dest_path =
            resolve_safe_dest_validate(&canonical, target, "components/foo.tsx").unwrap();
        assert_eq!(dest_path, target.join("components/foo.tsx"));
        assert!(
            !target.join("components").exists(),
            "validate must not create ancestor directories"
        );
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_dotdot_without_mkdir() {
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest_validate(&canonical, &target, "../../escaped/evil.txt")
            .expect_err("should reject");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("'..'") || msg.contains("parent-directory"),
                "expected `..` reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
        assert!(
            !outer.path().join("escaped").exists(),
            "validate must not create directories outside target"
        );
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_absolute_without_mkdir() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        // Build an absolute path that lives outside the target.
        let scratch = tempfile::tempdir().unwrap();
        let abs_dest = scratch.path().join("evil.txt");
        let abs_dest_str = abs_dest.to_string_lossy();

        let err = resolve_safe_dest_validate(&canonical, target, &abs_dest_str)
            .expect_err("should reject absolute path");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("absolute"),
                "expected absolute reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
    }

    #[test]
    fn write_path_pins_canonical_parent_through_intermediate_symlink() {
        // The copy flow must compose the final dest path from the
        // canonicalized parent: `parent_canonical.join(file_name)`.
        // This test reproduces the symlinked-intermediate-parent
        // case (inside target, so validation passes) and asserts
        // that the composed path follows the canonical resolution
        // — i.e., points at the real underlying directory, not the
        // symlinked alias.
        #[cfg(unix)]
        {
            let outer = tempfile::tempdir().unwrap();
            let target = outer.path().join("project").join("components");
            let real_dir = target.join("real");
            std::fs::create_dir_all(&real_dir).unwrap();
            // Create a symlinked alias INSIDE target pointing at real_dir.
            std::os::unix::fs::symlink(&real_dir, target.join("aliased")).unwrap();
            let target_root_canonical = target.canonicalize().unwrap();

            // Validate the path through the symlinked alias. Validation
            // passes because the canonical ancestor (real_dir) lives
            // inside target_root_canonical.
            let validated =
                resolve_safe_dest_validate(&target_root_canonical, &target, "aliased/foo.tsx")
                    .expect("validation should pass for symlink-inside-target");
            // Pre-canonicalize path runs through `aliased/`.
            assert!(
                validated.to_string_lossy().contains("aliased"),
                "validate returns the pre-canonicalize path, got {validated:?}"
            );

            // Prepare phase canonicalizes the parent. Returns the
            // CANONICAL parent — production composes the final dest
            // from this, not from the pre-canonicalize value.
            let parent_canonical =
                prepare_safe_dest_parent(validated.parent().unwrap(), &target_root_canonical)
                    .unwrap();
            let file_name = validated.file_name().unwrap();
            let final_dest = parent_canonical.join(file_name);

            // Production must write through the canonical resolution
            // (`real/foo.tsx`), NOT through the alias (`aliased/foo.tsx`).
            // Using the alias path here would reintroduce a
            // write-through-symlink risk.
            let canonical_target = real_dir.canonicalize().unwrap();
            assert_eq!(
                final_dest,
                canonical_target.join("foo.tsx"),
                "final dest must be canonical-pinned, got {final_dest:?}"
            );
            assert!(
                !final_dest.to_string_lossy().contains("aliased"),
                "final dest must not retain the symlinked-alias name, got {final_dest:?}"
            );
        }
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_dest_that_is_existing_symlink_without_mkdir() {
        // The dest path itself already resolves through a symlink.
        // Validate must reject before mkdir touches the parent chain.
        #[cfg(unix)]
        {
            let outer = tempfile::tempdir().unwrap();
            let target = outer.path().join("target");
            std::fs::create_dir_all(&target).unwrap();
            let canonical = target.canonicalize().unwrap();
            let outside = outer.path().join("outside");
            std::fs::create_dir_all(&outside).unwrap();

            // Create a symlink at `<target>/dest.tsx` → `<outside>`.
            std::os::unix::fs::symlink(&outside, target.join("dest.tsx")).unwrap();

            let err = resolve_safe_dest_validate(&canonical, &target, "dest.tsx")
                .expect_err("should reject existing symlink at dest");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("symlink"),
                    "expected symlink reject, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }
}
