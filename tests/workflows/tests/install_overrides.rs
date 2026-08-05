//! Workflow tests for `lpm.overrides` resolution + offline-mode safety.
//!
//! Override-fail-closed acceptance criteria, end-to-end through the binary:
//!
//! 1. **Fail-closed parsing** — invalid overrides in `package.json` are
//!    a hard error at install entry, not a silent no-op. The error
//!    names the offending key.
//! 2. **`.lpm/overrides-state.json` lifecycle** — the state file is
//!    created on first install with overrides, deleted when overrides
//!    are removed, and the fingerprint changes when the override set
//!    changes.
//! 3. **Offline safety** — `--offline` cannot re-resolve, so any
//!    drift between the persisted overrides-state and the current
//!    `lpm.overrides` is a hard error rather than a silent stale-link.
//! 4. **Replacement semantics** — an override replaces each consumer's
//!    declared range, including when a transitive pin excludes the target.
//! 5. **Workspace inheritance** — root overrides apply to every member;
//!    member-local entries can refine the effective map.
//! 6. **Truthful reporting** — unchanged selections are not reported as
//!    applied overrides.
//!
//! In its own file (not appended to `install.rs`) because the helpers
//! — `override_state_fingerprint` mirror, `seed_store_package`, lockfile/state
//! synthesis — are scoped to this gate. install.rs is also already
//! past the file-size review trigger.
//!
//! `lpm graph --why` + overrides-trace coverage lives in `graph.rs`.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

// ─── Helpers ────────────────────────────────────────────────────────────

/// Strip ANSI escapes from captured streams for stable substring assertions.
/// UTF-8 safe: iterates `chars()` and skips CSI sequences without
/// re-encoding bytes individually.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Synthetic `lpm.lock` containing the given `(name, version, deps)` entries.
fn write_lockfile(project: &TempProject, entries: &[(&str, &str, &[&str])]) {
    let package: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).expect("parse fixture manifest");
    let string_map = |value: Option<&serde_json::Value>| {
        value
            .and_then(serde_json::Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(name, value)| {
                value
                    .as_str()
                    .map(|specifier| (name.clone(), specifier.to_string()))
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let root_dependencies = string_map(package.get("dependencies"));
    let catalogs = package
        .get("catalogs")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .map(|(name, entries)| (name.clone(), string_map(Some(entries))))
        .collect();
    let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("pubgrub");
    lockfile.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: root_dependencies.clone(),
            dev_dependencies: string_map(package.get("devDependencies")),
            optional_dependencies: string_map(package.get("optionalDependencies")),
            peer_dependencies: string_map(package.get("peerDependencies")),
            lpm_overrides: string_map(package.pointer("/lpm/overrides")),
            overrides: string_map(package.get("overrides")),
            resolutions: string_map(package.get("resolutions")),
            catalogs,
            auto_install_peers: Some(true),
            ..Default::default()
        },
    );
    for (name, version, package_dependencies) in entries {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: (*name).to_string(),
            version: (*version).to_string(),
            dependencies: package_dependencies
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ..Default::default()
        });
        if root_dependencies.contains_key(*name) {
            lockfile.root_resolutions.insert(
                (*name).to_string(),
                lpm_lockfile::LockedRootResolution {
                    package: (*name).to_string(),
                    version: (*version).to_string(),
                    source: None,
                },
            );
        }
    }
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .expect("write fixture lockfile");
}

/// Seed a valid integrity-keyed v2 object and bind the matching lockfile row
/// to its source integrity.
fn seed_store_package(project: &TempProject, name: &str, version: &str) {
    let store = lpm_store::v2::Store::at(project.store_dir().join("v2"));
    let tarball = make_tarball(name, version);
    let (_, integrity, _) = store
        .extract_object_from_bytes(&tarball, None)
        .expect("seed v2 override fixture object");

    let lockfile_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("read fixture lockfile");
    let package = lockfile
        .packages
        .iter_mut()
        .find(|package| package.name == name && package.version == version)
        .expect("fixture lockfile must contain the seeded package");
    package.integrity = Some(integrity);
    lockfile
        .write_all(&lockfile_path)
        .expect("bind fixture lockfile to seeded v2 object");
}

/// Write a synthetic `.lpm/overrides-state.json`. `parsed` is the
/// `(raw_key, target)` set; `applied` is the `(pkg, from, to, via_parent)`
/// trace.
fn write_overrides_state(
    project: &TempProject,
    fingerprint: &str,
    parsed: &[(&str, &str)],
    applied: &[(&str, &str, &str, Option<&str>)],
) {
    let parsed_json: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(key, target)| {
            serde_json::json!({
                "raw_key": key,
                "source": "lpm.overrides",
                "selector": { "kind": "name", "name": key },
                "target": target,
            })
        })
        .collect();
    let applied_json: Vec<serde_json::Value> = applied
        .iter()
        .map(|(pkg, from, to, via)| {
            serde_json::json!({
                "raw_key": pkg,
                "source": "lpm.overrides",
                "package": pkg,
                "from_version": from,
                "to_version": to,
                "via_parent": via,
            })
        })
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": fingerprint,
        "captured_at": "2026-04-11T00:00:00Z",
        "parsed": parsed_json,
        "applied": applied_json,
    });
    project.write_file(
        ".lpm/overrides-state.json",
        &serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// Mirror of `lpm_resolver::overrides::compute_fingerprint`. The
/// canonical encoding is one line per entry, sorted ASCII, fed through
/// SHA-256 with `\n` after each line. Each line is
/// `{source}|{raw_key}|{selector}|{target}`.
///
/// **MUST stay in sync** with the resolver's `compute_fingerprint`. If
/// the resolver changes, this helper diverges and the matching-fingerprint
/// test will fail loudly.
fn override_state_fingerprint(entries: &[(&str, &str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut canonical: Vec<String> = entries
        .iter()
        .map(|(source, key, target)| format!("{source}|{key}|name:{key}|{target}"))
        .collect();
    canonical.sort();
    let mut hasher = Sha256::new();
    for line in &canonical {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256-{:x}", hasher.finalize())
}

async fn mount_force_override_packages(mock: &MockRegistry) {
    let target_metadata = mock
        .mount_full_package_metadata_routes(
            "override-target",
            "2.0.0",
            &[
                (
                    "2.0.0",
                    serde_json::json!({}),
                    Some(make_tarball("override-target", "2.0.0")),
                ),
                (
                    "1.0.0",
                    serde_json::json!({}),
                    Some(make_tarball("override-target", "1.0.0")),
                ),
            ],
        )
        .await;
    let consumer_metadata = mock
        .mount_full_package_metadata_routes(
            "override-consumer",
            "1.0.0",
            &[(
                "1.0.0",
                serde_json::json!({ "override-target": "1.0.0" }),
                Some(make_tarball("override-consumer", "1.0.0")),
            )],
        )
        .await;
    mock.with_batch_metadata(vec![consumer_metadata, target_metadata])
        .await;
}

fn install_without_optional_setup(
    project: &TempProject,
    registry_url: &str,
) -> std::process::Output {
    lpm_with_registry(project, registry_url)
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install")
}

// ─── Online replacement semantics ─────────────────────────────────────

#[tokio::test]
async fn install_override_replaces_transitive_consumer_range() {
    let mock = MockRegistry::start().await;
    mount_force_override_packages(&mock).await;
    let project = TempProject::empty(
        r#"{
  "name": "force-transitive-override",
  "version": "1.0.0",
  "dependencies": { "override-consumer": "1.0.0" },
  "lpm": { "overrides": { "override-target": "2.0.0" } }
}"#,
    );

    let output = install_without_optional_setup(&project, &mock.url());
    assert!(
        output.status.success(),
        "override install must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read override lockfile");
    assert!(
        lockfile
            .packages
            .iter()
            .any(|package| package.name == "override-target" && package.version == "2.0.0")
            && !lockfile
                .packages
                .iter()
                .any(|package| package.name == "override-target" && package.version == "1.0.0"),
        "the override must replace the consumer's pinned range"
    );
}

#[tokio::test]
async fn install_override_summary_omits_unchanged_selection() {
    let mock = MockRegistry::start().await;
    mount_force_override_packages(&mock).await;
    let project = TempProject::empty(
        r#"{
  "name": "unchanged-override",
  "version": "1.0.0",
  "dependencies": { "override-target": "2.0.0" },
  "lpm": { "overrides": { "override-target": "2.0.0" } }
}"#,
    );

    let output = install_without_optional_setup(&project, &mock.url());
    assert!(
        output.status.success(),
        "override install must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(
        !combined.contains("Applied 1 override") && !combined.contains("2.0.0 → 2.0.0"),
        "an unchanged selection must not be reported as applied:\n{combined}"
    );
}

#[tokio::test]
async fn install_json_omits_unchanged_override_selection() {
    let mock = MockRegistry::start().await;
    mount_force_override_packages(&mock).await;
    let project = TempProject::empty(
        r#"{
  "name": "unchanged-override-json",
  "version": "1.0.0",
  "dependencies": { "override-target": "2.0.0" },
  "lpm": { "overrides": { "override-target": "2.0.0" } }
}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn JSON install");
    assert!(
        output.status.success(),
        "JSON override install must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("install stdout must be JSON");

    assert_eq!(json["success"], true);
    assert!(json.get("applied_overrides").is_none());
}

#[tokio::test]
async fn workspace_member_inherits_root_override() {
    let mock = MockRegistry::start().await;
    mount_force_override_packages(&mock).await;
    let project = TempProject::empty(
        r#"{
  "name": "override-workspace",
  "private": true,
  "workspaces": ["packages/*"],
  "lpm": { "overrides": { "override-target": "1.0.0" } }
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
  "name": "override-app",
  "version": "1.0.0",
  "dependencies": { "override-target": "*" }
}"#,
    );

    let mut command = lpm_with_registry(&project, &mock.url());
    command
        .current_dir(project.path().join("packages/app"))
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ]);
    let output = command.output().expect("spawn workspace member install");
    assert!(
        output.status.success(),
        "workspace member install must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let manifest = std::fs::read_to_string(
        project
            .path()
            .join("packages/app/node_modules/override-target/package.json"),
    )
    .expect("read inherited override target manifest");
    let installed: serde_json::Value = serde_json::from_str(&manifest).expect("parse manifest");
    assert_eq!(installed["version"], "1.0.0");
}

// ─── Fail-closed parsing ────────────────────────────────────────────────

/// Multi-segment path selectors (`a>b>c`) must hard-error at install
/// entry — not silently no-op or warn. Error names the offending key.
#[test]
fn install_overrides_rejects_multi_segment_path_selector() {
    let project = TempProject::empty(
        r#"{
  "name": "multi-segment-path",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": { "overrides": { "a>b>c": "1.0.0" } }
}"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "multi-segment path must error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("a>b>c"),
        "error must name the offending key; got:\n{combined}"
    );
}

/// Invalid target version must hard-error and name the offending override key.
#[test]
fn install_overrides_rejects_invalid_target_version() {
    let project = TempProject::empty(
        r#"{
  "name": "invalid-target",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": { "overrides": { "lodash": "not-a-version-or-range" } }
}"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "invalid target must error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("lodash"),
        "error must name the offending key; got:\n{combined}"
    );
}

/// Invalid range in the selector half must hard-error and surface the
/// validation failure.
#[test]
fn install_overrides_rejects_invalid_range_in_selector() {
    let project = TempProject::empty(
        r#"{
  "name": "invalid-range",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": { "overrides": { "lodash@???": "1.0.0" } }
}"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "invalid range must error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("???") || combined.contains("invalid"),
        "error must surface the validation failure; got:\n{combined}"
    );
}

// ─── Offline safety: state vs current overrides ─────────────────────────

/// Stale state with applied overrides + non-empty deps + EMPTY current
/// overrides → offline must hard-error. We can't re-resolve offline, so
/// silently completing the install would link against the (now-stale)
/// override-shifted lockfile and leave a ghost state file on disk.
#[test]
fn offline_install_hard_errors_when_overrides_removed_with_prior_state() {
    let project = TempProject::empty(
        r#"{
  "name": "offline-overrides-removed",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&project, "lodash", "4.17.20");
    write_overrides_state(
        &project,
        "sha256-stale-fp",
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", None)],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "offline install must hard error when overrides are removed but state lingers; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error must mention overrides/fingerprint; got:\n{combined}"
    );
    assert!(
        combined.contains("online") || combined.contains("re-resolve"),
        "error must point at the recovery path (run online); got:\n{combined}"
    );
}

/// Stale state fingerprint X + non-empty deps + CURRENT overrides whose
/// fingerprint is Y (different) → offline must hard-error rather than
/// silently ignoring the user's override edits.
#[test]
fn offline_install_hard_errors_on_overrides_fingerprint_mismatch() {
    let project = TempProject::empty(
        r#"{
  "name": "offline-fingerprint-mismatch",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" },
  "lpm": { "overrides": { "lodash": "5.0.0" } }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&project, "lodash", "4.17.20");
    write_overrides_state(
        &project,
        "sha256-totally-different-fp-from-current",
        &[("lodash", "4.17.20")],
        &[],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "offline install with fingerprint mismatch must hard error; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error must mention overrides/fingerprint; got:\n{combined}"
    );
}

/// Non-empty deps + CURRENT overrides + NO persisted state file →
/// offline must hard-error. Without a fingerprint to verify against,
/// we can't prove the lockfile was generated under the current
/// override set, so the safe behavior is to refuse.
#[test]
fn offline_install_hard_errors_when_overrides_exist_but_no_state_file() {
    let project = TempProject::empty(
        r#"{
  "name": "offline-no-prior-state",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" },
  "lpm": { "overrides": { "lodash": "4.17.20" } }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&project, "lodash", "4.17.20");
    // Intentionally no overrides-state.json.

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "offline install with overrides but no state file must hard error; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error must mention overrides/fingerprint; got:\n{combined}"
    );
}

/// Positive case: matching fingerprint + non-empty deps + matching
/// overrides → offline install succeeds AND preserves the existing
/// state file on disk. Mirrors the resolver's canonical fingerprint
/// hash; if the resolver's hash function changes, this test fails
/// loudly.
#[test]
fn offline_install_succeeds_when_overrides_fingerprint_matches() {
    let project = TempProject::empty(
        r#"{
  "name": "offline-fp-match",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" },
  "lpm": { "overrides": { "lodash": "4.17.20" } }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&project, "lodash", "4.17.20");
    let fingerprint = override_state_fingerprint(&[("lpm.overrides", "lodash", "4.17.20")]);
    write_overrides_state(
        &project,
        &fingerprint,
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", None)],
    );

    let state_path = project.path().join(".lpm").join("overrides-state.json");
    assert!(
        state_path.exists(),
        "fixture must produce overrides-state.json"
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        out.status.success(),
        "offline install with matching fingerprint must succeed; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        state_path.exists(),
        "state file must be preserved when fingerprints match"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn install_does_not_follow_preplanted_overrides_state_temp_hardlink() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("lodash", "4.17.20");
    mock.with_package("lodash", "4.17.20", &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "lodash",
        "dist-tags": { "latest": "4.17.20" },
        "versions": {
            "4.17.20": {
                "name": "lodash",
                "version": "4.17.20",
                "dist": {
                    "tarball": format!(
                        "{}/tarballs/lodash/-/lodash-4.17.20.tgz",
                        mock.url()
                    ),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "4.17.20": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project = TempProject::empty(
        r#"{
  "name": "state-hardlink",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" },
  "lpm": { "overrides": { "lodash": "4.17.20" } }
}"#,
    );
    std::fs::create_dir_all(project.path().join(".lpm")).unwrap();

    let external = tempfile::tempdir().unwrap();
    let sentinel = external.path().join("sentinel");
    let original = b"external sentinel";
    std::fs::write(&sentinel, original).unwrap();
    std::fs::hard_link(
        &sentinel,
        project.path().join(".lpm").join("overrides-state.json.tmp"),
    )
    .unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm install");

    assert!(
        output.status.success(),
        "install with override must succeed; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&sentinel).unwrap(), original);
}

async fn mount_peer_override_packages(mock: &MockRegistry) {
    mock.with_full_package_metadata(
        "peer-host",
        "1.1.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("peer-host", "1.0.0")),
            ),
            (
                "1.1.0",
                serde_json::json!({}),
                Some(make_tarball("peer-host", "1.1.0")),
            ),
        ],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer",
            "version": "1.0.0",
            "peerDependencies": { "peer-host": "1.1.0" }
        }),
        &[],
    )
    .await;
}

fn peer_override_project() -> TempProject {
    TempProject::empty(
        r#"{
  "name": "override-root-link",
  "version": "1.0.0",
  "dependencies": {
    "peer-consumer": "1.0.0",
    "peer-host": "^1.0.0"
  },
  "lpm": {
    "overrides": { "peer-host": "1.0.0" }
  }
}"#,
    )
}

#[tokio::test]
async fn install_root_link_uses_the_version_selected_by_an_override() {
    let mock = MockRegistry::start().await;
    mount_peer_override_packages(&mock).await;
    let project = peer_override_project();
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install override with a second peer-selected version");
    assert!(
        output.status.success(),
        "override install must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let linked_manifest =
        std::fs::read_to_string(project.path().join("node_modules/peer-host/package.json"))
            .expect("read root-linked peer-host manifest");
    let linked: serde_json::Value =
        serde_json::from_str(&linked_manifest).expect("parse root-linked peer-host manifest");
    assert_eq!(linked["version"], "1.0.0");

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read exact root selection");
    assert_eq!(
        lockfile
            .root_resolutions
            .get("peer-host")
            .map(|selection| selection.version.as_str()),
        Some("1.0.0")
    );

    std::fs::remove_dir_all(project.path().join("node_modules"))
        .expect("remove fresh install layout");
    let replay = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--frozen-lockfile",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("replay override selection from lockfile");
    assert!(
        replay.status.success(),
        "frozen replay must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr),
    );

    let replayed_manifest =
        std::fs::read_to_string(project.path().join("node_modules/peer-host/package.json"))
            .expect("read replayed peer-host manifest");
    let replayed: serde_json::Value =
        serde_json::from_str(&replayed_manifest).expect("parse replayed peer-host manifest");
    assert_eq!(replayed["version"], "1.0.0");
}

#[tokio::test]
async fn install_override_applies_to_required_peer_binding() {
    let mock = MockRegistry::start().await;
    mount_peer_override_packages(&mock).await;
    let project = peer_override_project();

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("install override with a required peer");
    assert!(
        output.status.success(),
        "override install must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read peer override lockfile");
    let peer_consumer = lockfile
        .packages
        .iter()
        .find(|package| package.name == "peer-consumer")
        .expect("peer-consumer must be locked");
    assert_eq!(peer_consumer.peers, ["peer-host@1.0.0"]);
}
