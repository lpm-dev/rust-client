use super::*;

#[test]
fn extraction_removes_a_partial_file_after_a_reader_error() {
    struct FailingReader(std::io::Cursor<Vec<u8>>);
    impl Read for FailingReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.0.position() >= 515 {
                return Err(std::io::Error::other("injected payload read failure"));
            }
            let remaining = (515 - self.0.position()) as usize;
            let len = output.len().min(remaining);
            self.0.read(&mut output[..len])
        }
    }
    let tgz = create_test_tarball("lib/partial.txt", b"sixsix");
    let tar = decompress_gzip(&tgz).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result: Result<Vec<PathBuf>, LpmError> = extract_tar_archive_with_inspector(
        FailingReader(std::io::Cursor::new(tar)),
        dir.path(),
        DEFAULT_EXTRACTION_LIMITS,
        false,
        |_, _| false,
        |_| {},
        InspectionMode::WithCallback,
        |_| Ok(()),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("injected payload read failure")
    );
    assert!(!dir.path().join("lib").exists());
}

#[cfg(unix)]
#[test]
fn extraction_chmod_does_not_follow_a_leaf_replaced_while_reading() {
    use std::os::unix::fs::PermissionsExt;
    struct ReplacingReader<'a> {
        inner: std::io::Cursor<Vec<u8>>,
        target: &'a Path,
        outside: &'a Path,
        replaced: bool,
    }
    impl Read for ReplacingReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.replaced && self.inner.position() >= 512 {
                std::fs::rename(self.target, self.target.with_extension("moved"))?;
                std::os::unix::fs::symlink(self.outside, self.target)?;
                self.replaced = true;
            }
            self.inner.read(output)
        }
    }
    let mut tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar);
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/exec", &b"sixsix"[..])
            .unwrap();
        builder.finish().unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    outside
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    let target = dir.path().join("exec");
    let result: Result<Vec<PathBuf>, LpmError> = extract_tar_archive_with_inspector(
        ReplacingReader {
            inner: std::io::Cursor::new(tar),
            target: &target,
            outside: outside.path(),
            replaced: false,
        },
        dir.path(),
        DEFAULT_EXTRACTION_LIMITS,
        false,
        |_, _| false,
        |_| {},
        InspectionMode::WithCallback,
        |_| Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(
        outside.as_file().metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn extraction_rejects_a_parent_replaced_with_a_real_directory() {
    let tgz = create_test_tarball_with_entries(&[
        ("lib/first.txt", b"first"),
        ("lib/second.txt", b"second"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball_with_inspector(
        &tgz,
        dir.path(),
        |_, _| false,
        |entry| {
            if entry.relative_path == Path::new("lib/first.txt") {
                std::fs::rename(dir.path().join("lib"), dir.path().join("moved")).unwrap();
                std::fs::create_dir(dir.path().join("lib")).unwrap();
            }
        },
    );
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn extract_does_not_follow_a_parent_replaced_after_an_inspection() {
    let tgz = create_test_tarball_with_entries(&[
        ("lib/first.txt", b"first"),
        ("lib/second.txt", b"second"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let result = extract_tarball_with_inspector(
        &tgz,
        dir.path(),
        |_, _| false,
        |entry| {
            if entry.relative_path == Path::new("lib/first.txt") {
                std::fs::rename(dir.path().join("lib"), dir.path().join("moved")).unwrap();
                std::os::unix::fs::symlink(outside.path(), dir.path().join("lib")).unwrap();
            }
        },
    );
    assert!(!outside.path().join("second.txt").exists());
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn extraction_rollback_does_not_follow_a_replaced_parent() {
    let tgz =
        create_test_tarball_with_entries(&[("lib/first.txt", b"first"), ("second.txt", b"second")]);
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("first.txt"), b"keep").unwrap();
    let limits = ExtractionLimits {
        max_extraction_size: 5,
        ..DEFAULT_EXTRACTION_LIMITS
    };
    let result: Result<Vec<PathBuf>, LpmError> =
        extract_tarball_from_slice_with_inspector_with_limits(
            &tgz,
            dir.path(),
            limits,
            false,
            |_, _| false,
            |entry| {
                if entry.relative_path == Path::new("lib/first.txt") {
                    std::fs::rename(dir.path().join("lib"), dir.path().join("moved")).unwrap();
                    std::os::unix::fs::symlink(outside.path(), dir.path().join("lib")).unwrap();
                }
            },
            InspectionMode::WithCallback,
        );
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(outside.path().join("first.txt")).unwrap(),
        b"keep"
    );
}

#[test]
fn duplicate_entries_preserve_an_inspectors_hardlinked_bytes() {
    for buffer in [false, true] {
        let tgz = create_test_tarball_with_entries(&[
            ("lib/duplicate.txt", b"first"),
            ("lib/duplicate.txt", b"second"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let witness = dir.path().join("witness");
        let mut calls = 0;
        let files = extract_tarball_with_inspector(
            &tgz,
            dir.path(),
            |_, _| buffer,
            |entry| {
                if calls == 0 {
                    std::fs::hard_link(dir.path().join(entry.relative_path), &witness).unwrap();
                }
                calls += 1;
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(files.len(), 2);
        assert_eq!(std::fs::read(witness).unwrap(), b"first");
        assert_eq!(
            std::fs::read(dir.path().join("lib/duplicate.txt")).unwrap(),
            b"second"
        );
    }
}

#[test]
fn inspection_can_replace_a_completed_file_with_a_matching_hardlink() {
    for buffer in [false, true] {
        let tgz = create_test_tarball("lib/file.txt", b"content");
        let dir = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let cached = cache.path().join("blob");
        std::fs::write(&cached, b"content").unwrap();
        let files = extract_tarball_with_inspector(
            &tgz,
            dir.path(),
            |_, _| buffer,
            |entry| {
                let path = dir.path().join(entry.relative_path);
                std::fs::remove_file(&path).unwrap();
                std::fs::hard_link(&cached, &path).unwrap();
            },
        )
        .unwrap();
        assert_eq!(files, vec![PathBuf::from("lib/file.txt")]);
        assert_eq!(
            std::fs::read(dir.path().join(&files[0])).unwrap(),
            b"content"
        );
    }
}

#[cfg(unix)]
#[test]
fn replaced_root_prevents_inspection_of_later_entries() {
    let tgz = create_test_tarball_with_entries(&[("first", b"first"), ("second", b"second")]);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let mut calls = 0;
    let result = extract_tarball_with_inspector(
        &tgz,
        &root,
        |_, _| false,
        |_| {
            calls += 1;
            if calls == 1 {
                std::fs::rename(&root, dir.path().join("moved")).unwrap();
                std::fs::create_dir(&root).unwrap();
                std::fs::write(root.join("second"), b"outside").unwrap();
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert_eq!(std::fs::read(root.join("second")).unwrap(), b"outside");
    assert!(!dir.path().join("moved/second").exists());
}

#[cfg(unix)]
#[test]
fn revisiting_an_evicted_parent_rejects_a_different_directory() {
    let tgz = create_test_tarball_with_entries(&[
        ("lib/first", b"first"),
        ("other/file", b"other"),
        ("lib/second", b"second"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball_with_inspector(
        &tgz,
        dir.path(),
        |_, _| false,
        |entry| {
            if entry.relative_path == Path::new("other/file") {
                std::fs::rename(dir.path().join("lib"), dir.path().join("moved")).unwrap();
                std::fs::create_dir(dir.path().join("lib")).unwrap();
                std::fs::write(dir.path().join("lib/first"), b"keep").unwrap();
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(dir.path().join("lib/first")).unwrap(),
        b"keep"
    );
    assert!(!dir.path().join("lib/second").exists());
}

#[cfg(unix)]
#[test]
fn partial_file_cleanup_preserves_a_replacement_leaf() {
    struct ReplacingReader<'a> {
        inner: std::io::Cursor<Vec<u8>>,
        path: &'a Path,
    }
    impl Read for ReplacingReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.inner.position() >= 512 {
                std::fs::rename(self.path, self.path.with_extension("moved"))?;
                std::fs::write(self.path, b"keep")?;
                return Err(std::io::Error::other("injected failure"));
            }
            self.inner.read(output)
        }
    }
    let tgz = create_test_tarball("partial", b"sixsix");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial");
    let result: Result<Vec<PathBuf>, LpmError> = extract_tar_archive_with_inspector(
        ReplacingReader {
            inner: std::io::Cursor::new(decompress_gzip(&tgz).unwrap()),
            path: &path,
        },
        dir.path(),
        DEFAULT_EXTRACTION_LIMITS,
        false,
        |_, _| false,
        |_| {},
        InspectionMode::WithCallback,
        |_| Ok(()),
    );
    assert!(result.unwrap_err().to_string().contains("injected failure"));
    assert_eq!(std::fs::read(path).unwrap(), b"keep");
}

#[test]
fn same_size_leaf_replacement_prevents_inspector_callback() {
    struct ReplacingReader<'a> {
        inner: std::io::Cursor<Vec<u8>>,
        path: &'a Path,
        replaced: bool,
    }
    impl Read for ReplacingReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.replaced && self.inner.position() >= 512 {
                std::fs::rename(self.path, self.path.with_extension("moved"))?;
                std::fs::write(self.path, b"evil!!")?;
                self.replaced = true;
            }
            self.inner.read(output)
        }
    }

    let tgz = create_test_tarball("file", b"sixsix");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    let mut calls = 0;
    let result: Result<Vec<PathBuf>, LpmError> = extract_tar_archive_with_inspector(
        ReplacingReader {
            inner: std::io::Cursor::new(decompress_gzip(&tgz).unwrap()),
            path: &path,
            replaced: false,
        },
        dir.path(),
        DEFAULT_EXTRACTION_LIMITS,
        false,
        |_, _| false,
        |_| calls += 1,
        InspectionMode::WithCallback,
        |_| Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(calls, 0);
    assert_eq!(std::fs::read(path).unwrap(), b"evil!!");
}

#[cfg(unix)]
#[test]
fn retargeted_root_symlink_prevents_inspector_callback() {
    use std::os::unix::fs::symlink;

    struct RetargetingReader<'a> {
        inner: std::io::Cursor<Vec<u8>>,
        alias: &'a Path,
        replacement: &'a Path,
        retargeted: bool,
    }
    impl Read for RetargetingReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.retargeted && self.inner.position() >= 512 {
                std::fs::remove_file(self.alias)?;
                symlink(self.replacement, self.alias)?;
                self.retargeted = true;
            }
            self.inner.read(output)
        }
    }

    let tgz = create_test_tarball("file", b"sixsix");
    let container = tempfile::tempdir().unwrap();
    let original = container.path().join("original");
    let replacement = container.path().join("replacement");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&replacement).unwrap();
    std::fs::write(replacement.join("file"), b"evil!!").unwrap();
    let alias = container.path().join("root");
    symlink(&original, &alias).unwrap();
    let mut calls = 0;
    let result: Result<Vec<PathBuf>, LpmError> = extract_tar_archive_with_inspector(
        RetargetingReader {
            inner: std::io::Cursor::new(decompress_gzip(&tgz).unwrap()),
            alias: &alias,
            replacement: &replacement,
            retargeted: false,
        },
        &alias,
        DEFAULT_EXTRACTION_LIMITS,
        false,
        |_, _| false,
        |_| calls += 1,
        InspectionMode::WithCallback,
        |_| Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(calls, 0);
    assert_eq!(std::fs::read(replacement.join("file")).unwrap(), b"evil!!");
}

#[test]
fn digest_only_routes_match_inspected_digests_and_contents() {
    let tgz = create_test_tarball_with_entries(&[("lib/a.txt", b"alpha"), ("lib/b.txt", b"bravo")]);
    let inspected_dir = tempfile::tempdir().unwrap();
    let direct_dir = tempfile::tempdir().unwrap();
    let streaming_dir = tempfile::tempdir().unwrap();
    let hybrid_dir = tempfile::tempdir().unwrap();

    let inspected =
        extract_tarball_with_entry_digests(&tgz, inspected_dir.path(), |_, _| false, |_| {})
            .unwrap();
    let direct = extract_tarball_digests(&tgz, direct_dir.path()).unwrap();
    let streaming = extract_tarball_from_reader_streaming_digests(
        std::io::Cursor::new(&tgz),
        streaming_dir.path(),
    )
    .unwrap();
    let hybrid =
        extract_tarball_from_reader_hybrid_digests(std::io::Cursor::new(&tgz), hybrid_dir.path())
            .unwrap();

    assert_eq!(direct, inspected);
    assert_eq!(streaming, inspected);
    assert_eq!(hybrid, inspected);
    for file in inspected {
        let expected = std::fs::read(inspected_dir.path().join(&file.relative_path)).unwrap();
        assert_eq!(
            std::fs::read(direct_dir.path().join(&file.relative_path)).unwrap(),
            expected
        );
        assert_eq!(
            std::fs::read(streaming_dir.path().join(&file.relative_path)).unwrap(),
            expected
        );
        assert_eq!(
            std::fs::read(hybrid_dir.path().join(&file.relative_path)).unwrap(),
            expected
        );
    }
}

#[cfg(unix)]
#[test]
fn digest_only_route_retains_final_directory_validation() {
    let tgz = create_test_tarball("lib/file", b"content");
    let tar = decompress_gzip(&tgz).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result: Result<Vec<ExtractedFileDigest>, LpmError> = extract_tar_archive_with_inspector(
        std::io::Cursor::new(tar),
        dir.path(),
        DEFAULT_EXTRACTION_LIMITS,
        true,
        |_, _| false,
        |_| panic!("digest-only extraction invoked a callback"),
        InspectionMode::WithoutCallback,
        |_| {
            std::fs::rename(dir.path().join("lib"), dir.path().join("moved"))?;
            std::fs::create_dir(dir.path().join("lib"))?;
            Ok(())
        },
    );
    assert!(result.is_err());
}

struct FailingSecondPayload<F> {
    action_position: u64,
    inner: std::io::Cursor<Vec<u8>>,
    before_failure: Option<F>,
}

impl<F: FnOnce()> Read for FailingSecondPayload<F> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.inner.position() >= self.action_position
            && let Some(action) = self.before_failure.take()
        {
            action();
        }
        if self.inner.position() >= 1536 {
            return Err(std::io::Error::other("injected second payload failure"));
        }
        let remaining = (1536 - self.inner.position()) as usize;
        let len = output.len().min(remaining);
        self.inner.read(&mut output[..len])
    }
}

#[test]
fn rollback_preserves_a_completed_leaf_replaced_by_a_later_reader() {
    let tgz = create_test_tarball_with_entries(&[("first", b"first"), ("second", b"second")]);
    let tar = decompress_gzip(&tgz).unwrap();
    for mode in [
        InspectionMode::WithCallback,
        InspectionMode::WithoutCallback,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let result: Result<Vec<PathBuf>, LpmError> = extract_tar_archive_with_inspector(
            FailingSecondPayload {
                action_position: 1536,
                inner: std::io::Cursor::new(tar.clone()),
                before_failure: Some(|| {
                    std::fs::rename(&first, dir.path().join("moved")).unwrap();
                    std::fs::write(&first, b"replacement").unwrap();
                }),
            },
            dir.path(),
            DEFAULT_EXTRACTION_LIMITS,
            false,
            |_, _| false,
            |_| {},
            mode,
            |_| Ok(()),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected second payload failure")
        );
        assert_eq!(std::fs::read(&first).unwrap(), b"replacement");
        assert!(!dir.path().join("second").exists());
    }
}

#[test]
fn rollback_removes_an_accepted_inspector_hardlink_without_removing_cached_bytes() {
    let tgz = create_test_tarball_with_entries(&[("first", b"first"), ("second", b"second")]);
    let dir = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let blob = cache.path().join("blob");
    std::fs::write(&blob, b"first").unwrap();
    let first = dir.path().join("first");
    let result: Result<Vec<PathBuf>, LpmError> = extract_tar_archive_with_inspector(
        FailingSecondPayload {
            action_position: 1536,
            inner: std::io::Cursor::new(decompress_gzip(&tgz).unwrap()),
            before_failure: Some(|| {}),
        },
        dir.path(),
        DEFAULT_EXTRACTION_LIMITS,
        false,
        |_, _| false,
        |entry| {
            if entry.relative_path == Path::new("first") {
                std::fs::remove_file(&first).unwrap();
                std::fs::hard_link(&blob, &first).unwrap();
            }
        },
        InspectionMode::WithCallback,
        |_| Ok(()),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("injected second payload failure")
    );
    assert!(!first.exists());
    assert_eq!(std::fs::read(blob).unwrap(), b"first");
}

#[test]
fn rollback_preserves_a_leaf_replaced_before_digest_only_entry_acceptance() {
    let tgz = create_test_tarball_with_entries(&[("first", b"first"), ("second", b"second")]);
    let tar = decompress_gzip(&tgz).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let result: Result<Vec<PathBuf>, LpmError> = extract_tar_archive_with_inspector(
        FailingSecondPayload {
            action_position: 512,
            inner: std::io::Cursor::new(tar),
            before_failure: Some(|| {
                std::fs::rename(&first, dir.path().join("moved")).unwrap();
                std::fs::write(&first, b"replacement").unwrap();
            }),
        },
        dir.path(),
        DEFAULT_EXTRACTION_LIMITS,
        false,
        |_, _| false,
        |_| {},
        InspectionMode::WithoutCallback,
        |_| Ok(()),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("injected second payload failure")
    );
    assert_eq!(std::fs::read(&first).unwrap(), b"replacement");
    assert!(!dir.path().join("second").exists());
}
