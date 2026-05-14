//! Workflow tests for `lpm upgrade`.
//!
//! `lpm upgrade` is `@lpm.dev/*`-only (same scope as `lpm outdated`,
//! filed at phase-64 finding #67). It rewrites the manifest range and
//! runs install. Tests cover: error paths, dry-run safety, the npm-skip
//! contract, the manifest-rewrite happy path, and the JSON envelope.
//!
//! Non-TTY subprocess mode resolves to `NonInteractive` automatically;
//! `--json` and `-y` also force non-interactive. No TTY-mocking needed.

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

/// Mount `pkg` on the mock with `latest_version` exposed via metadata
/// and a real tarball at the production-shaped path
/// `/tarballs/<name>/-/<name>-<version>.tgz` (see
/// [`MockRegistry::tarball_path`]). Also wires the batch-metadata
/// endpoint that the install pipeline calls when upgrade falls
/// through to it.
async fn mount_lpm_pkg(mock: &MockRegistry, pkg: &str, latest_version: &str) {
    let tarball = make_tarball(pkg, latest_version);
    mock.with_package(pkg, latest_version, &tarball).await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": pkg,
        "dist-tags": { "latest": latest_version },
        "versions": {
            latest_version: {
                "name": pkg,
                "version": latest_version,
                "dist": {
                    "tarball": format!("{}/tarballs/{pkg}/-/{pkg}-{latest_version}.tgz", mock.url()),
                    "integrity": compute_integrity(&tarball),
                },
                "dependencies": {}
            }
        },
        "time": { latest_version: "2025-01-01T00:00:00.000Z" }
    })])
    .await;
}

/// Seed a project with `pkg` listed at `installed_range` and pinned in
/// `lpm.lock` at `installed_version`. The upgrade pipeline reads both.
///
/// Manifest is written with the canonical `"key": "value"` spacing
/// (space after colon) — `lpm upgrade`'s string-replace path at
/// [upgrade.rs:434](crates/lpm-cli/src/commands/upgrade.rs#L434) only
/// matches that exact format.
fn seed_pinned_dep(
    project: &TempProject,
    pkg: &str,
    installed_range: &str,
    installed_version: &str,
) {
    project.write_file(
        "package.json",
        &format!(
            "{{\n  \"name\": \"upgrade-test\",\n  \"version\": \"1.0.0\",\n  \
             \"dependencies\": {{\n    \"{pkg}\": \"{installed_range}\"\n  }}\n}}\n"
        ),
    );
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
             [[packages]]\nname = \"{pkg}\"\nversion = \"{installed_version}\"\n\
             source = \"registry+https://lpm.dev\"\n",
        ),
    );
}

// ─── Error + edge paths ─────────────────────────────────────────────────

#[test]
fn upgrade_without_package_json_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").unwrap();
    cmd.current_dir(dir.path())
        .env("HOME", home.path())
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env_remove("LPM_TOKEN");

    let out = cmd
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn lpm upgrade");
    assert!(!out.status.success());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("package.json"),
        "stderr should mention package.json; got:\n{stderr}"
    );
}

#[tokio::test]
async fn upgrade_emits_zero_upgraded_when_lpm_dep_already_at_latest() {
    let pkg = "@lpm.dev/owner.already-current";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, pkg, "^1.4.2", "1.4.2");

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "1.4.2").await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("spawn lpm upgrade --json");
    assert!(out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["dry_run"], serde_json::json!(false));
    assert_eq!(envelope["upgraded"], serde_json::json!(0));
    assert_eq!(envelope["packages"], serde_json::json!([]));
}

// ─── Behavior contracts ─────────────────────────────────────────────────

/// `lpm upgrade` filters to `@lpm.dev/*` packages — same contract as
/// `lpm outdated` (phase-64 finding #67). Pins the filter so a
/// regression that started rewriting npm dep ranges to "latest" without
/// going through the resolver doesn't slip through.
#[tokio::test]
async fn upgrade_skips_npm_packages_in_dependencies() {
    let project = TempProject::empty(
        r#"{"name":"npm-only-up","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    project.write_file(
        "lpm.lock",
        "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
         [[packages]]\nname = \"ms\"\nversion = \"2.1.3\"\n\
         source = \"registry+https://lpm.dev\"\n",
    );

    let mock = MockRegistry::start().await;
    // Mount ms with a much newer version; the filter regression would
    // rewrite the manifest to ^9.9.9.
    mock.with_package("ms", "9.9.9", &make_tarball("ms", "9.9.9"))
        .await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("spawn lpm upgrade --json");
    assert!(
        out.status.success(),
        "upgrade should exit 0 on npm-only project"
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(
        envelope["upgraded"],
        serde_json::json!(0),
        "npm packages must be filtered out of upgrade candidates; envelope: {envelope:#}"
    );

    // Manifest must be untouched.
    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(pkg_json["dependencies"]["ms"], serde_json::json!("^2.1.3"));
}

/// `--dry-run` reports the planned upgrade in the JSON envelope but
/// MUST NOT mutate `package.json` or `lpm.lock`. Pre-fix regressions
/// that "just write and rollback" would trip this.
#[tokio::test]
async fn upgrade_dry_run_does_not_mutate_manifest_or_lockfile() {
    let pkg = "@lpm.dev/owner.dry-runner";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, pkg, "^1.0.0", "1.0.0");

    let original_manifest = project.read_file("package.json");
    let original_lockfile = project.read_file("lpm.lock");

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "2.0.0").await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--major", "--dry-run", "--json"])
        .output()
        .expect("spawn lpm upgrade --major --dry-run --json");
    assert!(out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    assert_eq!(envelope["upgraded"], serde_json::json!(1));
    assert_eq!(envelope["packages"][0]["name"], serde_json::json!(pkg));

    // Manifest + lockfile must be byte-identical to pre-run state.
    assert_eq!(
        project.read_file("package.json"),
        original_manifest,
        "package.json must be unchanged under --dry-run"
    );
    assert_eq!(
        project.read_file("lpm.lock"),
        original_lockfile,
        "lpm.lock must be unchanged under --dry-run"
    );
}

/// Without `--dry-run`, upgrade rewrites the manifest range and runs
/// install end-to-end. Asserts the new range lands and the lockfile
/// reflects the upgraded version.
#[tokio::test]
async fn upgrade_writes_new_range_to_manifest_and_lockfile() {
    let pkg = "@lpm.dev/owner.really-upgrade";
    // Pretty-printed manifest with `"key": "value"` spacing matches
    // upgrade's string-replace contract. No pre-existing lockfile:
    // install resolves fresh against the new ^2.0.0 range. A stale
    // lockfile pinning v1.0.0 would send the install fast-path looking
    // for a v1.0.0 tarball that isn't mounted.
    let project = TempProject::empty(&format!(
        "{{\n  \"name\": \"upgrade-real\",\n  \"version\": \"1.0.0\",\n  \
         \"dependencies\": {{\n    \"{pkg}\": \"^1.0.0\"\n  }}\n}}\n"
    ));

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "2.0.0").await;

    lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--major"])
        .assert()
        .success();

    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        pkg_json["dependencies"][pkg],
        serde_json::json!("^2.0.0"),
        "manifest dep range must be rewritten to ^2.0.0; got: {pkg_json:#}"
    );

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lpm.lock");
    let entry = lockfile
        .packages
        .iter()
        .find(|p| p.name == pkg)
        .expect("lockfile must still contain the upgraded pkg");
    assert_eq!(
        entry.version, "2.0.0",
        "lockfile must record the upgraded version"
    );
}

/// Minified `package.json` input (`"name":"value"` with no space after
/// the colon) must still be upgraded correctly. The pre-fix
/// string-replace rewrite only matched `"name": "value"` and silently
/// left compact JSON manifests unchanged.
#[tokio::test]
async fn upgrade_rewrites_minified_manifest_json() {
    let pkg = "@lpm.dev/owner.compact-json";
    let project = TempProject::empty(&format!(
        r#"{{"name":"upgrade-compact","version":"1.0.0","dependencies":{{"{pkg}":"^1.0.0"}}}}"#
    ));

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "2.0.0").await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--major"])
        .output()
        .expect("spawn lpm upgrade on minified manifest");
    assert!(
        out.status.success(),
        "upgrade must succeed for minified package.json; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        pkg_json["dependencies"][pkg],
        serde_json::json!("^2.0.0"),
        "minified manifest dep range must still be rewritten; got: {pkg_json:#}"
    );

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lpm.lock");
    let entry = lockfile
        .packages
        .iter()
        .find(|p| p.name == pkg)
        .expect("lockfile must contain the upgraded pkg");
    assert_eq!(entry.version, "2.0.0");
}

// ─── JSON contract ──────────────────────────────────────────────────────

#[tokio::test]
async fn upgrade_dry_run_json_envelope_with_one_candidate_matches_snapshot() {
    let pkg = "@lpm.dev/owner.snap-upgrade";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, pkg, "^1.0.0", "1.0.0");

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "1.5.0").await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .expect("spawn lpm upgrade --dry-run --json");
    assert!(out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    insta::assert_json_snapshot!("upgrade_json_envelope_one_candidate_dry_run", envelope);
}

// ─── Phase 65 Step 6.7 — Phase 7 enriched-dry-run regressions ───────────
//
// 15 tests covering the upgrade enrichment surface:
//  - JSON envelope shape (legacy fields + per-package enrichment)
//  - Peer-impact + install-script + patch-invalidation flags
//  - --dry-run vs real-upgrade manifest mutation
//  - --major flag, no-candidates branch, fail-restore path
//  - Validator rejections (`-i --json`, `-i -y`, `--major -i`)
//  - TTY-less default behavior matches `--yes`
//  - Offline install round-trip after a successful upgrade
//
// Multi-version metadata (current + latest + optional major) is mounted
// directly via `mock.server()` since the standard `MockRegistry` helpers
// only support single-version mounts.

use wiremock::matchers::{method as wm_method, path as wm_path};
use wiremock::{Mock, ResponseTemplate};

const UP7_PKG: &str = "@lpm.dev/acme.widget";
const UP7_CURRENT: &str = "1.2.0";
const UP7_MINOR: &str = "1.3.0";
const UP7_MAJOR: &str = "2.0.0";

#[allow(dead_code)]
struct VersionFixture {
    version: &'static str,
    dependencies: serde_json::Value,
    peer_dependencies: serde_json::Value,
    lifecycle_scripts: Option<serde_json::Value>,
    tarball: Vec<u8>,
}

fn up7_tarball_path(name: &str, version: &str) -> String {
    let slug: String = name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    format!("/tarballs/{slug}/-/{slug}-{version}.tgz")
}

fn up7_metadata(
    registry_url: &str,
    name: &str,
    latest: &str,
    versions: &[VersionFixture],
) -> serde_json::Value {
    let mut versions_map = serde_json::Map::new();
    let mut times_map = serde_json::Map::new();
    for v in versions {
        let tarball_url = format!("{registry_url}{}", up7_tarball_path(name, v.version));
        let mut value = serde_json::json!({
            "name": name,
            "version": v.version,
            "dist": {
                "tarball": tarball_url,
                "integrity": compute_integrity(&v.tarball),
            },
            "dependencies": v.dependencies.clone(),
        });
        if !v.peer_dependencies.is_null() {
            value["peerDependencies"] = v.peer_dependencies.clone();
        }
        if let Some(scripts) = &v.lifecycle_scripts {
            value["_lifecycleScripts"] = scripts.clone();
        }
        versions_map.insert(v.version.to_string(), value);
        times_map.insert(
            v.version.to_string(),
            serde_json::Value::String("2025-01-01T00:00:00.000Z".into()),
        );
    }
    serde_json::json!({
        "name": name,
        "dist-tags": { "latest": latest },
        "versions": versions_map,
        "time": times_map,
    })
}

/// Mount a multi-version package on the mock with optional
/// fail-tarball-version (returns 404 instead of bytes for that
/// specific version). Used by the install-failure restore test.
async fn mount_upgrade_package(
    mock: &MockRegistry,
    name: &str,
    latest: &str,
    versions: &[VersionFixture],
    fail_tarball_version: Option<&str>,
) {
    let server = mock.server();
    let metadata = up7_metadata(&mock.url(), name, latest, versions);

    Mock::given(wm_method("GET"))
        .and(wm_path(format!("/api/registry/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(server)
        .await;

    Mock::given(wm_method("POST"))
        .and(wm_path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json({
            let mut packages = serde_json::Map::new();
            packages.insert(name.to_string(), metadata.clone());
            serde_json::json!({ "packages": packages })
        }))
        .mount(server)
        .await;

    for v in versions {
        let p = up7_tarball_path(name, v.version);
        let response = if Some(v.version) == fail_tarball_version {
            ResponseTemplate::new(404).set_body_string("missing tarball")
        } else {
            ResponseTemplate::new(200)
                .set_body_bytes(v.tarball.clone())
                .insert_header("content-type", "application/octet-stream")
        };
        Mock::given(wm_method("GET"))
            .and(wm_path(p))
            .respond_with(response)
            .mount(server)
            .await;
    }
}

fn up7_manifest_with_dependency(range: &str, include_patch: bool) -> serde_json::Value {
    let mut value = serde_json::json!({
        "name": "upgrade-phase7-test",
        "version": "1.0.0",
        "dependencies": { UP7_PKG: range },
    });
    if include_patch {
        value["lpm"] = serde_json::json!({
            "patchedDependencies": {
                format!("{UP7_PKG}@{UP7_CURRENT}"): {
                    "path": "patches/acme-widget.patch",
                    "originalIntegrity": "sha512-original-fixture"
                }
            }
        });
    }
    value
}

fn up7_write_manifest(project: &TempProject, value: &serde_json::Value) {
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(value).unwrap(),
    );
}

fn up7_write_lockfile(project: &TempProject, entries: &[(&str, &str)]) {
    let pkgs: Vec<String> = entries
        .iter()
        .map(|(n, v)| format!("[[packages]]\nname = \"{n}\"\nversion = \"{v}\"\n"))
        .collect();
    let lf = format!(
        "[metadata]\nlockfile-version = 2\nresolved-with = \"pubgrub\"\n\n{}\n",
        pkgs.join("\n")
    );
    project.write_file("lpm.lock", &lf);
}

fn parse_stdout_json(stdout: &[u8], stderr: &[u8]) -> serde_json::Value {
    let s = String::from_utf8_lossy(stdout);
    serde_json::from_str(&s).unwrap_or_else(|err| {
        panic!(
            "stdout was not valid JSON: {err}\nstdout:\n{s}\nstderr:\n{}",
            String::from_utf8_lossy(stderr)
        )
    })
}

/// Enriched fixture: prior version with no peer/scripts, latest with
/// peer-dependency on react (^18) AND a postinstall script. The
/// project has react 17.0.2 in its lockfile so the peer-impact
/// calculator surfaces a violation. Patch entry in the manifest so
/// patch-invalidation surfaces in the upgrade JSON.
async fn setup_up7_enriched_dry_run_fixture(project: &TempProject) -> MockRegistry {
    up7_write_manifest(project, &up7_manifest_with_dependency("^1.2.0", true));
    up7_write_lockfile(project, &[(UP7_PKG, UP7_CURRENT), ("react", "17.0.2")]);

    let mock = MockRegistry::start().await;
    let versions = vec![
        VersionFixture {
            version: UP7_CURRENT,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(UP7_PKG, UP7_CURRENT),
        },
        VersionFixture {
            version: UP7_MINOR,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::json!({ "react": "^18.0.0" }),
            lifecycle_scripts: Some(serde_json::json!({ "postinstall": "node install.js" })),
            tarball: make_tarball(UP7_PKG, UP7_MINOR),
        },
    ];
    mount_upgrade_package(&mock, UP7_PKG, UP7_MINOR, &versions, None).await;
    mock
}

/// Successful-upgrade fixture: current + minor (or also major if
/// `include_major`). No peer/scripts/patch noise — used for
/// happy-path manifest-write + offline-after tests.
async fn setup_up7_successful_upgrade_fixture(
    project: &TempProject,
    latest: &'static str,
    include_major: bool,
) -> MockRegistry {
    up7_write_manifest(project, &up7_manifest_with_dependency("^1.2.0", false));

    let mock = MockRegistry::start().await;
    let mut versions = vec![
        VersionFixture {
            version: UP7_CURRENT,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(UP7_PKG, UP7_CURRENT),
        },
        VersionFixture {
            version: UP7_MINOR,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(UP7_PKG, UP7_MINOR),
        },
    ];
    if include_major {
        versions.push(VersionFixture {
            version: UP7_MAJOR,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(UP7_PKG, UP7_MAJOR),
        });
    }
    mount_upgrade_package(&mock, UP7_PKG, latest, &versions, None).await;
    mock
}

/// Failed-install fixture: minor version's tarball returns 404 so
/// the install pipeline fails AFTER manifest mutation, exercising the
/// rollback / restore path.
async fn setup_up7_failed_install_fixture(project: &TempProject) -> MockRegistry {
    up7_write_manifest(project, &up7_manifest_with_dependency("^1.2.0", false));
    let mock = MockRegistry::start().await;
    let versions = vec![
        VersionFixture {
            version: UP7_CURRENT,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(UP7_PKG, UP7_CURRENT),
        },
        VersionFixture {
            version: UP7_MINOR,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: make_tarball(UP7_PKG, UP7_MINOR),
        },
    ];
    mount_upgrade_package(&mock, UP7_PKG, UP7_MINOR, &versions, Some(UP7_MINOR)).await;
    mock
}

// ─── Tests ──────────────────────────────────────────────────────────────

/// `upgrade -y --json` against an npm-only project (no `@lpm.dev/*`
/// deps) emits the legacy-success envelope: `success: true`,
/// `upgraded: 0`, empty packages array. Pins the no-network short-circuit
/// — npm packages aren't checked, so no fetch fires.
#[test]
fn upgrade_yes_with_no_lpm_candidates_emits_legacy_success_envelope() {
    let project = TempProject::empty(
        r#"{"name":"no-candidates","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    );

    let out = lpm(&project)
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("spawn lpm upgrade -y --json");
    assert!(
        out.status.success(),
        "upgrade -y --json must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let json = parse_stdout_json(&out.stdout, &out.stderr);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["upgraded"], serde_json::json!(0));
    assert_eq!(json["packages"], serde_json::json!([]));
    assert_eq!(json["fetch_errors"], serde_json::json!(0));
}

/// `upgrade -y --json --dry-run` against the enriched fixture emits
/// the legacy JSON shape unchanged: per-package `from` / `to` /
/// `new_range` + the enrichment fields (`semver_class`,
/// `has_install_scripts`, `peer_impact`, `patch_invalidation`).
#[tokio::test]
async fn upgrade_yes_dry_run_json_shape_unchanged_with_enrichment() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json", "--dry-run"])
        .output()
        .expect("spawn lpm upgrade");
    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let json = parse_stdout_json(&out.stdout, &out.stderr);
    let pkg = &json["packages"][0];
    assert_eq!(pkg["name"], serde_json::json!(UP7_PKG));
    assert_eq!(pkg["from"], serde_json::json!(UP7_CURRENT));
    assert_eq!(pkg["to"], serde_json::json!(UP7_MINOR));
    assert_eq!(pkg["new_range"], serde_json::json!("^1.3.0"));
    assert_eq!(pkg["is_dev"], serde_json::json!(false));
    assert!(pkg.get("semver_class").is_some());
    assert!(pkg.get("has_install_scripts").is_some());
    assert!(pkg.get("peer_impact").is_some());
    assert!(pkg.get("patch_invalidation").is_some());
}

/// `--dry-run` MUST NOT mutate `package.json`. Pre-fix the manifest
/// would be written and then restored, leaking a non-byte-equal
/// intermediate state.
#[tokio::test]
async fn upgrade_yes_dry_run_does_not_mutate_package_json() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;
    let before = project.read_file("package.json");

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run"])
        .output()
        .expect("spawn lpm upgrade --dry-run");
    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(before, project.read_file("package.json"));
}

/// Real (non-dry-run) `upgrade -y` rewrites the manifest range AND
/// runs install — `node_modules/<pkg>` exists, manifest carries the
/// new caret-resolved range.
#[tokio::test]
async fn upgrade_yes_writes_manifest_when_not_dry_run() {
    let project = TempProject::empty("");
    let mock = setup_up7_successful_upgrade_fixture(&project, UP7_MINOR, false).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn lpm upgrade");
    assert!(
        out.status.success(),
        "upgrade -y must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let manifest = project.read_file("package.json");
    assert!(
        manifest.contains(&format!(r#""{UP7_PKG}": "^1.3.0""#)),
        "manifest must carry the new caret-resolved range; got:\n{manifest}"
    );
    assert!(
        project.path().join("node_modules").join(UP7_PKG).exists(),
        "node_modules/{UP7_PKG} must exist after upgrade"
    );
}

/// Bare `upgrade --json --dry-run` (no `-y`) under non-TTY stdin
/// produces the same envelope as `upgrade -y --json --dry-run`.
/// Pins that the auto-detection of non-TTY → non-interactive resolves
/// to the same path as the explicit `-y`.
#[tokio::test]
async fn upgrade_default_in_no_tty_matches_yes_output() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;

    let yes_out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json", "--dry-run"])
        .output()
        .expect("spawn upgrade -y");
    assert!(yes_out.status.success());

    let default_out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "--json", "--dry-run"])
        .output()
        .expect("spawn upgrade (no -y)");
    assert!(default_out.status.success());

    let yes_json = parse_stdout_json(&yes_out.stdout, &yes_out.stderr);
    let default_json = parse_stdout_json(&default_out.stdout, &default_out.stderr);
    assert_eq!(yes_json, default_json);
}

/// `-i --json` is rejected at the validator: interactive prompts can't
/// render JSON. Error message names both modes.
#[test]
fn upgrade_interactive_with_json_is_hard_error() {
    let project = TempProject::empty("");
    up7_write_manifest(&project, &up7_manifest_with_dependency("^1.2.0", false));

    let out = lpm(&project)
        .args(["--json", "upgrade", "-i"])
        .output()
        .expect("spawn lpm --json upgrade -i");
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json upgrade -i must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    let err = envelope["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("interactive") || err.contains("-i"),
        "error must reference interactive mode: {err}"
    );
    assert!(
        err.contains("--json") || err.contains("json"),
        "error must reference --json: {err}"
    );
}

/// `-i -y` is mutually exclusive — clap-level rejection. Error names
/// both flags.
#[test]
fn upgrade_interactive_and_yes_is_hard_error() {
    let project = TempProject::empty("");
    up7_write_manifest(&project, &up7_manifest_with_dependency("^1.2.0", false));

    let out = lpm(&project)
        .args(["upgrade", "-i", "-y"])
        .output()
        .expect("spawn lpm upgrade -i -y");
    assert!(!out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("mutually exclusive"),
        "error must name mutual exclusion: {combined}"
    );
    assert!(combined.contains("-i"));
    assert!(combined.contains("-y"));
}

/// `--major -i` is rejected by `validate_major_for_mode`: major
/// upgrades render as separate rows in interactive mode (toggle-on
/// instead of `--major`). Error names both `--major` and "interactive
/// mode".
#[test]
fn upgrade_major_in_interactive_mode_is_hard_error() {
    let project = TempProject::empty("");
    up7_write_manifest(&project, &up7_manifest_with_dependency("^1.2.0", false));

    let out = lpm(&project)
        .args(["upgrade", "--major", "-i"])
        .output()
        .expect("spawn lpm upgrade --major -i");
    assert!(!out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("--major"),
        "error must name --major: {combined}"
    );
    assert!(
        combined.contains("interactive mode"),
        "error must name interactive mode: {combined}"
    );
}

/// `--major -y` follows the absolute-latest path: target is v2.0.0,
/// new_range becomes `^2.0.0`, semver_class is "major".
#[tokio::test]
async fn upgrade_major_yes_jumps_to_latest_major_version() {
    let project = TempProject::empty("");
    let mock = setup_up7_successful_upgrade_fixture(&project, UP7_MAJOR, true).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "--major", "-y", "--json", "--dry-run"])
        .output()
        .expect("spawn upgrade --major -y");
    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let json = parse_stdout_json(&out.stdout, &out.stderr);
    let pkg = &json["packages"][0];
    assert_eq!(pkg["to"], serde_json::json!(UP7_MAJOR));
    assert_eq!(pkg["new_range"], serde_json::json!("^2.0.0"));
    assert_eq!(pkg["semver_class"], serde_json::json!("major"));

    // Snapshot the full envelope so a future contract widening (new
    // field added or shape rename) fails this test before users notice.
    insta::with_settings!({ filters => vec![
        // Redact the mock registry URL (port-bound) and the absolute
        // manifest path inside `target_set` so the snapshot is portable.
        (r"http://127\.0\.0\.1:\d+", "[MOCK_URL]"),
        (r#""/[^"]+/package\.json""#, r#""[MANIFEST]""#),
        (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", "[TIMESTAMP]"),
    ]}, {
        insta::assert_json_snapshot!("upgrade_major_dry_run_envelope", json);
    });
}

/// `--json` envelope's `has_install_scripts: true` when the candidate
/// version declares lifecycle scripts. Pre-Phase-7 the field was absent.
#[tokio::test]
async fn upgrade_yes_marks_install_scripts_in_json() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json", "--dry-run"])
        .output()
        .expect("spawn upgrade");
    assert!(out.status.success());

    let json = parse_stdout_json(&out.stdout, &out.stderr);
    assert_eq!(
        json["packages"][0]["has_install_scripts"],
        serde_json::json!(true)
    );
}

/// `peer_impact.ok: false` with the violating peer's name + have/want
/// versions — pre-Phase-7 the field was missing entirely.
#[tokio::test]
async fn upgrade_yes_marks_peer_violation_in_json() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json", "--dry-run"])
        .output()
        .expect("spawn upgrade");
    assert!(out.status.success());

    let json = parse_stdout_json(&out.stdout, &out.stderr);
    let peer_impact = &json["packages"][0]["peer_impact"];
    assert_eq!(peer_impact["ok"], serde_json::json!(false));
    assert_eq!(peer_impact["basis"], serde_json::json!("current_lockfile"));
    assert_eq!(
        peer_impact["violations"][0]["name"],
        serde_json::json!("react")
    );
    assert_eq!(
        peer_impact["violations"][0]["have"],
        serde_json::json!("17.0.2")
    );
    assert_eq!(
        peer_impact["violations"][0]["want"],
        serde_json::json!("^18.0.0")
    );
}

/// `patch_invalidation` populated when the upgrade would orphan a
/// `lpm.patchedDependencies` entry whose key matches the prior
/// version. Carries the key, from_version, to_version.
#[tokio::test]
async fn upgrade_yes_marks_patch_invalidation_in_json() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json", "--dry-run"])
        .output()
        .expect("spawn upgrade");
    assert!(out.status.success());

    let json = parse_stdout_json(&out.stdout, &out.stderr);
    let patch = &json["packages"][0]["patch_invalidation"];
    assert_eq!(
        patch["key"],
        serde_json::json!(format!("{UP7_PKG}@{UP7_CURRENT}"))
    );
    assert_eq!(patch["from_version"], serde_json::json!(UP7_CURRENT));
    assert_eq!(patch["to_version"], serde_json::json!(UP7_MINOR));
}

/// When the install pipeline fails after manifest mutation, the
/// manifest is restored byte-equal. Pins the rollback / restore path.
#[tokio::test]
async fn upgrade_yes_install_failure_restores_manifest() {
    let project = TempProject::empty("");
    let mock = setup_up7_failed_install_fixture(&project).await;
    let before = project.read_file("package.json");

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn upgrade");
    assert!(!out.status.success(), "upgrade should have failed");

    assert_eq!(
        before,
        project.read_file("package.json"),
        "package.json must be restored byte-equal on install failure"
    );
}

/// After a successful upgrade, an `--offline` install must succeed
/// against the populated store + new lockfile + restored manifest.
/// JSON envelope is non-empty (offline install reports its own
/// success shape).
#[tokio::test]
async fn upgrade_yes_offline_install_after_upgrade_succeeds() {
    let project = TempProject::empty("");
    let mock = setup_up7_successful_upgrade_fixture(&project, UP7_MINOR, false).await;

    let upgrade_out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn upgrade");
    assert!(
        upgrade_out.status.success(),
        "upgrade must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&upgrade_out.stdout),
        String::from_utf8_lossy(&upgrade_out.stderr)
    );

    let offline_out = lpm_with_registry(&project, &mock.url())
        .args(["install", "--offline", "--json"])
        .output()
        .expect("spawn install --offline");
    assert!(
        offline_out.status.success(),
        "offline install must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&offline_out.stdout),
        String::from_utf8_lossy(&offline_out.stderr)
    );
    let json = parse_stdout_json(&offline_out.stdout, &offline_out.stderr);
    assert!(
        json.as_object().is_some_and(|o| !o.is_empty()),
        "offline install must return structured JSON envelope; got: {json}"
    );
}

/// Comprehensive smoke: top-level envelope + per-package fields all
/// populated for the enriched fixture. One assertion per field —
/// catches regressions where a field gets dropped from one branch but
/// not another.
#[tokio::test]
async fn upgrade_yes_dry_run_json_envelope_with_full_enrichment_smoke() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json", "--dry-run"])
        .output()
        .expect("spawn upgrade");
    assert!(out.status.success());

    let json = parse_stdout_json(&out.stdout, &out.stderr);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["dry_run"], serde_json::json!(true));
    assert_eq!(json["upgraded"], serde_json::json!(1));
    assert_eq!(json["fetch_errors"], serde_json::json!(0));
    assert_eq!(json["packages"].as_array().map(Vec::len), Some(1));

    let pkg = &json["packages"][0];
    assert_eq!(pkg["name"], serde_json::json!(UP7_PKG));
    assert_eq!(pkg["from"], serde_json::json!(UP7_CURRENT));
    assert_eq!(pkg["to"], serde_json::json!(UP7_MINOR));
    assert_eq!(pkg["new_range"], serde_json::json!("^1.3.0"));
    assert_eq!(pkg["is_dev"], serde_json::json!(false));
    assert_eq!(pkg["semver_class"], serde_json::json!("minor"));
    assert_eq!(pkg["has_install_scripts"], serde_json::json!(true));
    assert_eq!(pkg["peer_impact"]["ok"], serde_json::json!(false));
    assert_eq!(
        pkg["patch_invalidation"]["key"],
        serde_json::json!(format!("{UP7_PKG}@{UP7_CURRENT}"))
    );
}
