use super::*;
use std::fs;

fn remote_artifact(path: &Path, entries: &[(&str, bool)]) {
    let encoder =
        flate2::write::GzEncoder::new(fs::File::create(path).unwrap(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(encoder);
    for (name, directory) in entries {
        if *directory {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o755);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_cksum();
            archive
                .append_data(&mut header, name, std::io::empty())
                .unwrap();
        } else {
            append_bytes(&mut archive, Path::new(name), b"cached").unwrap();
        }
    }
    let meta = CacheMeta {
        command: "build".into(),
        cache_key: "deadbeef".into(),
        duration_ms: 1,
        output_file_count: entries
            .iter()
            .filter(|(name, directory)| !directory && name.starts_with("outputs/"))
            .count(),
    };
    append_bytes(
        &mut archive,
        Path::new(".lpm-cache/meta.json"),
        &serde_json::to_vec(&meta).unwrap(),
    )
    .unwrap();
    append_bytes(&mut archive, Path::new(".lpm-cache/stdout.log"), b"").unwrap();
    append_bytes(&mut archive, Path::new(".lpm-cache/stderr.log"), b"").unwrap();
    archive.into_inner().unwrap().finish().unwrap();
}

fn restore_remote(
    entries: &[(&str, bool)],
    globs: &[String],
    project: &Path,
) -> Result<CacheHit, LpmError> {
    let home = tempfile::tempdir().unwrap();
    let artifact = home.path().join("artifact.tar.gz");
    remote_artifact(&artifact, entries);
    restore_remote_artifact_with_root(
        &LpmRoot::from_dir(home.path()),
        "deadbeef",
        &artifact,
        project,
        globs,
    )
}

#[test]
fn undeclared_remote_output_rejects_entire_restore_without_removing_stale_outputs() {
    let project = tempfile::tempdir().unwrap();
    fs::create_dir(project.path().join("dist")).unwrap();
    for name in ["dist/value.txt", "dist/stale.txt", "secret.txt"] {
        fs::write(project.path().join(name), "original").unwrap();
    }
    let result = restore_remote(
        &[
            ("outputs/dist/value.txt", false),
            ("outputs/secret.txt", false),
        ],
        &["dist/**".into()],
        project.path(),
    );
    assert!(result.is_err(), "an undeclared output was installed");
    for name in ["dist/value.txt", "dist/stale.txt", "secret.txt"] {
        assert_eq!(
            fs::read_to_string(project.path().join(name)).unwrap(),
            "original"
        );
    }
}

#[test]
fn shallow_output_glob_rejects_nested_remote_files() {
    let project = tempfile::tempdir().unwrap();
    let result = restore_remote(
        &[("outputs/dist/nested/value.txt", false)],
        &["dist/*".into()],
        project.path(),
    );
    assert!(result.is_err(), "a shallow glob accepted a nested file");
    assert!(!project.path().join("dist").exists());
}

#[test]
fn empty_output_declarations_reject_remote_files() {
    let project = tempfile::tempdir().unwrap();
    let result = restore_remote(&[("outputs/value.txt", false)], &[], project.path());
    assert!(result.is_err(), "empty declarations accepted a file");
    assert!(!project.path().join("value.txt").exists());
}

#[test]
fn output_globs_do_not_accept_sibling_paths() {
    let project = tempfile::tempdir().unwrap();
    let result = restore_remote(
        &[("outputs/dist-other/value.txt", false)],
        &["dist/**".into()],
        project.path(),
    );
    assert!(result.is_err(), "a sibling path matched the output root");
    assert!(!project.path().join("dist-other").exists());
}

#[test]
fn remote_output_globs_accept_union_recursive_and_literal_exclamation_paths_in_any_order() {
    let project = tempfile::tempdir().unwrap();
    let files = [
        "outputs/!literal.txt",
        "outputs/dist/z.txt",
        "outputs/dist/deep/a.txt",
        "outputs/report.json",
    ];
    let entries: Vec<_> = files.iter().map(|name| (*name, false)).collect();
    let hit = restore_remote(
        &entries,
        &[
            "dist/**".into(),
            "report.json".into(),
            "!literal.txt".into(),
        ],
        project.path(),
    )
    .unwrap();
    assert_eq!(hit.meta.output_file_count, files.len());
    for name in files {
        assert_eq!(
            fs::read_to_string(project.path().join(name.strip_prefix("outputs/").unwrap()))
                .unwrap(),
            "cached"
        );
    }
}

#[test]
fn remote_archives_reject_explicit_directories_and_bare_output_entries() {
    for entry in [
        ("outputs/dist/", true),
        ("outputs", false),
        ("outputs/", true),
    ] {
        let project = tempfile::tempdir().unwrap();
        let result = restore_remote(&[entry], &["dist/**".into()], project.path());
        assert!(result.is_err(), "accepted entry {entry:?}");
        assert!(!project.path().join("dist").exists());
    }
}

#[test]
fn local_restore_enforces_output_declarations_and_preserves_existing_files() {
    let home = tempfile::tempdir().unwrap();
    let root = LpmRoot::from_dir(home.path());
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("value.txt"), "cached").unwrap();
    store_cache_with_root(
        &root,
        "deadbeef",
        source.path(),
        "build",
        &["value.txt".into()],
        "",
        "",
        1,
    )
    .unwrap();
    for globs in [vec![], vec!["other.txt".into()]] {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("value.txt"), "original").unwrap();
        let result = restore_cache_with_root(&root, "deadbeef", project.path(), &globs);
        assert!(
            result.is_err(),
            "local archive bypassed output declarations"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("value.txt")).unwrap(),
            "original"
        );
    }
}

#[test]
fn local_output_can_be_a_regular_file_named_outputs() {
    let home = tempfile::tempdir().unwrap();
    let root = LpmRoot::from_dir(home.path());
    let project = tempfile::tempdir().unwrap();
    let globs = ["outputs".into()];
    fs::write(project.path().join("outputs"), "cached").unwrap();
    store_cache_with_root(
        &root,
        "deadbeef",
        project.path(),
        "build",
        &globs,
        "",
        "",
        1,
    )
    .unwrap();
    fs::remove_file(project.path().join("outputs")).unwrap();
    restore_cache_with_root(&root, "deadbeef", project.path(), &globs).unwrap();
    assert_eq!(
        fs::read_to_string(project.path().join("outputs")).unwrap(),
        "cached"
    );
}
