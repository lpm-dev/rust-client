use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

/// Verify every `file:` and `link:`
/// dep in package.json points at a usable local source.
///
/// What's reported:
/// - **Pass** when every local-source dep resolves to a valid target
///   (regular file for file: tarballs, directory containing
///   package.json for file:/link: directory deps).
/// - **Fail** for paths that don't exist or are unreadable —
///   `lpm install` would error at the manifest boundary; doctor
///   surfaces it pre-install so users can fix the package.json.
/// - **Fail** for `file:` directory targets without `package.json`.
/// - **Fail** for `link:` targets that resolve to a regular file
///   (link: requires a directory).
/// - **Fail** for exotic file types (devices, sockets) — same as
///   the manifest-boundary error in `pre_resolve_non_registry_deps`.
///
/// Each problem produces a separate Check entry so `--fix` /
/// human output / JSON all surface the per-dep detail. No
/// network or extraction work is done — just stat() per dep.
///
/// Returns an empty Vec when there are NO file:/link: deps (the
/// common case for non-monorepo projects). The doctor output stays
/// uncluttered.
pub(super) fn check_local_source_paths(project_dir: &Path) -> Vec<Check> {
    let pkg_json_path = project_dir.join("package.json");
    let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
        return Vec::new();
    };
    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };

    let mut checks = Vec::new();
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(deps) = pkg.get(field).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, raw) in deps {
            let Some(spec) = raw.as_str() else {
                continue;
            };
            // Classify: file: (tarball or dir), link: (dir only),
            // anything else → not our concern.
            let (kind_label, expected_dir, path_str) = if let Some(p) = spec.strip_prefix("file:") {
                ("file:", false, p) // false = could be tarball OR directory
            } else if let Some(p) = spec.strip_prefix("link:") {
                ("link:", true, p) // link: must be a directory
            } else {
                continue;
            };
            let abs = project_dir.join(path_str);
            match std::fs::metadata(&abs) {
                Ok(meta) if meta.is_dir() => {
                    // Directory target — must have package.json.
                    if !abs.join("package.json").is_file() {
                        checks.push(Check::fail(
                            &doctor_catalog::LOCAL_SOURCE_DIR_NO_PKG,
                            &format!(
                                "`{name}`: {kind_label}{path_str} resolves to a directory \
                                 without package.json — install will error",
                            ),
                        ));
                    } else {
                        checks.push(Check::pass(
                            &doctor_catalog::LOCAL_SOURCE_DIR_OK,
                            &format!("`{name}`: {kind_label}{path_str} (directory)"),
                        ));
                    }
                }
                Ok(meta) if meta.is_file() => {
                    if expected_dir {
                        // link: requires a directory.
                        checks.push(Check::fail(
                            &doctor_catalog::LOCAL_SOURCE_LINK_TO_FILE,
                            &format!(
                                "`{name}`: {kind_label}{path_str} resolves to a regular file; \
                                 link: requires a directory. Use file:./<name>.tgz \
                                 for tarballs",
                            ),
                        ));
                    } else {
                        checks.push(Check::pass(
                            &doctor_catalog::LOCAL_SOURCE_TARBALL_OK,
                            &format!("`{name}`: {kind_label}{path_str} (tarball)"),
                        ));
                    }
                }
                Ok(_) => {
                    checks.push(Check::fail(
                        &doctor_catalog::LOCAL_SOURCE_INVALID_TYPE,
                        &format!(
                            "`{name}`: {kind_label}{path_str} resolves to neither a regular \
                             file nor a directory (device/socket/etc.) — install \
                             will error",
                        ),
                    ));
                }
                Err(e) => {
                    checks.push(Check::fail(
                        &doctor_catalog::LOCAL_SOURCE_UNREADABLE,
                        &format!(
                            "`{name}`: {kind_label}{path_str} is unreadable: {e}. Check the \
                             path in package.json",
                        ),
                    ));
                }
            }
        }
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;

    fn write_pkg_json(dir: &Path, content: &str) {
        std::fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn check_local_source_paths_returns_empty_for_no_local_deps() {
        // Project with only registry deps → empty Vec, doctor stays
        // quiet about the file:/link: feature surface.
        let dir = tempfile::tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"lodash":"^4.0.0"}}"#,
        );
        let checks = check_local_source_paths(dir.path());
        assert!(checks.is_empty());
    }

    #[test]
    fn check_local_source_paths_passes_valid_directory_dep() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("packages").join("local-thing");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(
            local.join("package.json"),
            br#"{"name":"local-thing","version":"1.0.0"}"#,
        )
        .unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"local-thing":"file:./packages/local-thing"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(checks[0].passed);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert!(checks[0].detail.contains("directory"));
    }

    #[test]
    fn check_local_source_paths_passes_valid_tarball_dep() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"fake tarball").unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"foo":"file:./foo.tgz"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(checks[0].passed);
        assert!(checks[0].detail.contains("tarball"));
    }

    #[test]
    fn check_local_source_paths_fails_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"missing":"file:./does-not-exist"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Fail));
        assert!(checks[0].detail.contains("unreadable"));
        assert!(checks[0].detail.contains("file:./does-not-exist"));
    }

    #[test]
    fn check_local_source_paths_fails_directory_without_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("packages").join("no-manifest");
        std::fs::create_dir_all(&local).unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"broken":"file:./packages/no-manifest"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Fail));
        assert!(checks[0].detail.contains("without package.json"));
    }

    #[test]
    fn check_local_source_paths_fails_link_pointing_at_regular_file() {
        // link: requires a directory; pointing at a tarball is a
        // user error caught at install time. Doctor surfaces it
        // pre-install with an actionable hint.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"fake").unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"bad":"link:./foo.tgz"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Fail));
        assert!(checks[0].detail.contains("link:"));
        assert!(checks[0].detail.contains("regular file"));
    }

    #[test]
    fn check_local_source_paths_passes_valid_link_dep() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("shared").join("util");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(
            local.join("package.json"),
            br#"{"name":"util","version":"0.1.0"}"#,
        )
        .unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"util":"link:./shared/util"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(checks[0].passed);
    }

    #[test]
    fn check_local_source_paths_reports_multiple_deps_separately() {
        // A mix of pass + fail produces one Check entry per dep so
        // each is individually visible/actionable in doctor output.
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::write(
            good.join("package.json"),
            br#"{"name":"good","version":"1.0.0"}"#,
        )
        .unwrap();
        write_pkg_json(
            dir.path(),
            r#"{
                "name":"app",
                "dependencies":{
                    "good":"file:./good",
                    "missing":"file:./does-not-exist",
                    "lodash":"^4.0.0"
                }
            }"#,
        );

        let checks = check_local_source_paths(dir.path());
        // 2 file: deps → 2 Check entries; lodash registry → ignored.
        assert_eq!(checks.len(), 2);
        let pass_count = checks.iter().filter(|c| c.passed).count();
        let fail_count = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Fail))
            .count();
        assert_eq!(pass_count, 1);
        assert_eq!(fail_count, 1);
    }

    #[test]
    fn check_local_source_paths_walks_all_dep_field_kinds() {
        // dependencies, devDependencies, peerDependencies,
        // optionalDependencies all walked. Each surfaces if it has
        // a file:/link: spec.
        let dir = tempfile::tempdir().unwrap();
        for name in ["a", "b", "c", "d"] {
            let pkg = dir.path().join(name);
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(
                pkg.join("package.json"),
                format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
            )
            .unwrap();
        }
        write_pkg_json(
            dir.path(),
            r#"{
                "name":"app",
                "dependencies":{"a":"file:./a"},
                "devDependencies":{"b":"file:./b"},
                "peerDependencies":{"c":"file:./c"},
                "optionalDependencies":{"d":"file:./d"}
            }"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 4, "all dep field kinds must surface");
    }
}
