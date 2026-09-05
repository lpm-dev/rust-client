//! Workflow tests for `lpm upgrade`.
//!
//! `lpm upgrade` rewrites the manifest range and runs install. Tests
//! cover: error paths, dry-run safety, npm/public-source eligibility,
//! the manifest-rewrite happy path, and the JSON envelope.
//!
//! Non-TTY subprocess mode resolves to `NonInteractive` automatically;
//! `--json` and `-y` also force non-interactive. No TTY-mocking needed.

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm, lpm_spawnable_with_registry, lpm_with_registry_and_npm};
use wiremock::matchers::{method, path as wiremock_path, query_param};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

#[derive(Clone)]
struct RecordDelayedUpgradeMetadataStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
}

impl Respond for RecordDelayedUpgradeMetadataStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record upgrade metadata request start")
            .push(std::time::Instant::now());
        let name = request
            .url
            .path()
            .strip_prefix("/api/registry/")
            .unwrap_or_default();
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_json(serde_json::json!({
                "name": name,
                "dist-tags": { "latest": "1.1.0" },
                "versions": {
                    "1.0.0": { "name": name, "version": "1.0.0" },
                    "1.1.0": { "name": name, "version": "1.1.0" }
                },
                "time": {
                    "1.0.0": "2025-01-01T00:00:00.000Z",
                    "1.1.0": "2025-01-01T00:00:00.000Z"
                }
            }))
    }
}

#[derive(Clone)]
struct SequentialUpgradeMetadata {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    first: serde_json::Value,
    second: serde_json::Value,
    batch: bool,
}

impl Respond for SequentialUpgradeMetadata {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let metadata = if call == 0 {
            self.first.clone()
        } else {
            self.second.clone()
        };
        if self.batch {
            let name = metadata["name"].as_str().expect("metadata package name");
            let body = format!(
                "{}\n",
                serde_json::to_string(&serde_json::json!({
                    "name": name,
                    "metadata": metadata,
                }))
                .expect("serialize sequential batch metadata")
            );
            ResponseTemplate::new(200).set_body_raw(body, "application/x-ndjson")
        } else {
            ResponseTemplate::new(200).set_body_json(metadata)
        }
    }
}

#[derive(Clone)]
struct MarkDelayedUpgradeTarball {
    marker: std::path::PathBuf,
    body: Option<Vec<u8>>,
    delay: std::time::Duration,
}

impl Respond for MarkDelayedUpgradeTarball {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        std::fs::write(&self.marker, b"requested").expect("write delayed tarball marker");
        let response = match &self.body {
            Some(body) => ResponseTemplate::new(200).set_body_bytes(body.clone()),
            None => ResponseTemplate::new(404).set_body_string("missing tarball"),
        };
        response.set_delay(self.delay)
    }
}

fn iso8601_n_secs_ago(n_secs: i64) -> String {
    use chrono::SecondsFormat;
    let dt = chrono::Utc::now() - chrono::Duration::seconds(n_secs);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

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
        .env("LPM_HOME", home.path().join(".lpm"))
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_AUTH", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env("LPM_DISABLE_HOST_CLI_AUTH", "1")
        .env(
            "LPM_SECURITY_POLICY_PATH",
            home.path().join(".lpm/security-policy.toml"),
        )
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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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

#[tokio::test]
async fn upgrade_package_argument_limits_json_candidates_to_requested_dependency() {
    let requested = "@lpm.dev/owner.requested-upgrade";
    let unrelated = "@lpm.dev/owner.unrelated-upgrade";
    let project = TempProject::empty(&format!(
        r#"{{
            "name": "targeted-upgrade",
            "version": "1.0.0",
            "dependencies": {{
                "{requested}": "^1.0.0",
                "{unrelated}": "^1.0.0"
            }}
        }}"#
    ));
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
             [[packages]]\nname = \"{requested}\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://lpm.dev\"\n\n\
             [[packages]]\nname = \"{unrelated}\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://lpm.dev\"\n",
        ),
    );

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, requested, "1.1.0").await;
    mount_lpm_pkg(&mock, unrelated, "1.2.0").await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", requested, "-y", "--dry-run", "--json"])
        .output()
        .expect("spawn targeted lpm upgrade --dry-run --json");
    assert!(
        out.status.success(),
        "targeted upgrade must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["upgraded"], serde_json::json!(1));
    assert_eq!(
        envelope["packages"][0]["name"],
        serde_json::json!(requested)
    );
}

#[test]
fn upgrade_package_argument_missing_manifest_dependency_fails_clearly() {
    let project = TempProject::empty(
        r#"{"name":"targeted-missing","version":"1.0.0","dependencies":{"zod":"^3.0.0"}}"#,
    );

    let out = lpm(&project)
        .args(["--json", "upgrade", "react", "-y"])
        .output()
        .expect("spawn targeted lpm upgrade for missing package");
    assert!(!out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON error envelope");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|message| message.contains("react")),
        "error must name missing requested package: {envelope}"
    );
}

#[test]
fn upgrade_package_argument_unknown_registry_source_fails_clearly() {
    let project = TempProject::empty(
        r#"{"name":"targeted-private","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}"#,
    );

    let out = lpm(&project)
        .args(["--json", "upgrade", "left-pad", "-y"])
        .output()
        .expect("spawn targeted lpm upgrade without recorded source");
    assert!(!out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON error envelope");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|message| message.contains("recorded public npm")),
        "error must explain the missing source metadata: {envelope}"
    );
}

// ─── Behavior contracts ─────────────────────────────────────────────────

#[test]
fn upgrade_rejects_a_corrupt_project_lockfile() {
    let project = TempProject::empty(
        r#"{"name":"corrupt-lock-upgrade","version":"1.0.0","dependencies":{"@lpm.dev/acme.corrupt":"^1.0.0"}}"#,
    );
    project.write_file("lpm.lock", "this is not a lockfile");

    let out = lpm(&project)
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("spawn upgrade with corrupt lockfile");

    assert!(!out.status.success());
    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON error envelope");
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("failed to read project lockfile")),
        "error should identify the corrupt lockfile: {envelope:#}",
    );
}

/// A dependency whose lockfile source is the public npm registry should
/// be eligible for `lpm upgrade`, matching `lpm outdated`'s default
/// cross-ecosystem surface.
#[tokio::test]
async fn upgrade_upgrades_npm_packages_with_public_npm_lock_source() {
    let project = TempProject::empty(
        r#"{"name":"npm-only-up","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    project.write_file(
        "lpm.lock",
        "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
         [[packages]]\nname = \"ms\"\nversion = \"2.1.3\"\n\
         source = \"registry+https://registry.npmjs.org\"\n",
    );

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "ms",
        "2.5.0",
        &[
            (
                "2.1.3",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.1.3")),
            ),
            (
                "2.5.0",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.5.0")),
            ),
        ],
    )
    .await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn lpm upgrade");
    assert!(
        out.status.success(),
        "upgrade should succeed on an npm-only project when the lockfile records a public npm source\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        pkg_json["dependencies"]["ms"],
        serde_json::json!("^2.5.0"),
        "manifest must be rewritten to the latest matching npm version; got: {pkg_json:#}"
    );

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lpm.lock after npm upgrade");
    let entry = lockfile
        .packages
        .iter()
        .find(|p| p.name == "ms")
        .expect("lockfile must still contain ms after upgrade");
    assert_eq!(
        entry.version, "2.5.0",
        "lockfile must record the upgraded npm version"
    );
}

#[tokio::test]
async fn upgrade_targeted_npm_alias_uses_canonical_source_and_preserves_alias_spec() {
    let project = TempProject::empty(
        r#"{
            "name": "npm-alias-up",
            "version": "1.0.0",
            "dependencies": {
                "strip-ansi-cjs": "npm:strip-ansi@^6.0.0"
            }
        }"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile
        .root_aliases
        .insert("strip-ansi-cjs".to_string(), "strip-ansi".to_string());
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "strip-ansi".to_string(),
        version: "6.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["strip-ansi@5.0.0".to_string()],
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "strip-ansi".to_string(),
        version: "5.0.0".to_string(),
        source: Some("registry+https://lpm.dev".to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[("strip-ansi-cjs", "strip-ansi", "6.0.0")],
    );
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .expect("write aliased lockfile");

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "strip-ansi",
        "6.1.0",
        &[
            (
                "6.0.0",
                serde_json::json!({}),
                Some(make_tarball("strip-ansi", "6.0.0")),
            ),
            (
                "6.1.0",
                serde_json::json!({}),
                Some(make_tarball("strip-ansi", "6.1.0")),
            ),
        ],
    )
    .await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "strip-ansi-cjs", "-y"])
        .output()
        .expect("spawn targeted alias upgrade");
    assert!(
        out.status.success(),
        "targeted npm alias upgrade must succeed via the canonical target\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        manifest["dependencies"]["strip-ansi-cjs"],
        serde_json::json!("npm:strip-ansi@^6.1.0")
    );

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read upgraded lockfile");
    assert_eq!(
        lockfile.root_aliases.get("strip-ansi-cjs"),
        Some(&"strip-ansi".to_string())
    );
    let received_paths = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock recorded requests")
        .into_iter()
        .map(|request| request.url.path().to_string())
        .collect::<Vec<_>>();
    assert!(received_paths.iter().any(|path| path == "/strip-ansi"));
    assert!(
        !received_paths
            .iter()
            .any(|path| path == "/api/registry/strip-ansi"),
        "the same-name transitive source must not override the exact public root: {received_paths:?}"
    );
    let entry = lockfile
        .packages
        .iter()
        .find(|package| package.name == "strip-ansi")
        .expect("lockfile must record the canonical alias target");
    assert_eq!(entry.version, "6.1.0");
}

#[tokio::test]
async fn upgrade_never_routes_non_registry_manifest_protocols_to_a_registry() {
    for (index, spec) in [
        "workspace:*",
        "file:../local-package",
        "link:../local-package",
        "git+https://example.invalid/repository.git#main",
        "https://example.invalid/package.tgz",
    ]
    .into_iter()
    .enumerate()
    {
        let package = format!("@lpm.dev/acme.local{index}");
        let project = TempProject::empty(&format!(
            r#"{{"name":"local-upgrade","version":"1.0.0","dependencies":{{"{package}":"{spec}"}}}}"#
        ));
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: package.clone(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://lpm.dev".to_string()),
            ..Default::default()
        });
        support::finalize_exact_lockfile_fixture(
            &mut lockfile,
            &[(package.as_str(), package.as_str(), "1.0.0")],
        );
        lockfile
            .write_to_file(&project.path().join("lpm.lock"))
            .expect("write stale registry lockfile");

        let mock = MockRegistry::start().await;
        let output = lpm_with_registry_and_npm(&project, &mock.url())
            .args(["upgrade", "-y", "--dry-run", "--json"])
            .output()
            .expect("run non-registry upgrade plan");

        assert!(
            output.status.success(),
            "{spec} must be skipped without a registry request\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            mock.server()
                .received_requests()
                .await
                .expect("read registry requests")
                .is_empty(),
            "{spec} unexpectedly reached a registry"
        );
    }
}

#[tokio::test]
async fn upgrade_rejects_stale_alias_route_evidence_before_any_registry_request() {
    for manifest_spec in ["^2.0.0", "npm:@company/private-tool@^2.0.0"] {
        let project = TempProject::empty(&format!(
            r#"{{"name":"stale-alias","version":"1.0.0","dependencies":{{"tool":"{manifest_spec}"}}}}"#
        ));
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile
            .root_aliases
            .insert("tool".to_string(), "old-public-tool".to_string());
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "old-public-tool".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            ..Default::default()
        });
        support::finalize_exact_lockfile_fixture(
            &mut lockfile,
            &[("tool", "old-public-tool", "1.0.0")],
        );
        lockfile
            .write_to_file(&project.path().join("lpm.lock"))
            .expect("write stale alias lockfile");

        let mock = MockRegistry::start().await;
        let output = lpm_with_registry_and_npm(&project, &mock.url())
            .args(["upgrade", "tool", "-y", "--dry-run", "--json"])
            .output()
            .expect("run stale alias upgrade");

        assert!(!output.status.success());
        assert!(
            mock.server()
                .received_requests()
                .await
                .expect("read registry requests")
                .is_empty(),
            "stale alias evidence must not authorize any current package lookup"
        );
    }
}

async fn run_tagged_upgrade_case(
    package: &str,
    manifest_spec: &str,
    tag: &str,
    installed: &str,
    target: &str,
    latest: &str,
) -> (serde_json::Value, lpm_lockfile::Lockfile) {
    let project = TempProject::empty(&format!(
        r#"{{"name":"tagged-upgrade","version":"1.0.0","dependencies":{{"{package}":"{manifest_spec}"}}}}"#
    ));
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: package.to_string(),
        version: installed.to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[(package, package, installed)]);
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .expect("write tagged dependency lockfile");

    let mock = MockRegistry::start().await;
    let tarball = make_tarball(package, target);
    let integrity = compute_integrity(&tarball);
    let tarball_path = MockRegistry::tarball_path(package, target);
    Mock::given(method("GET"))
        .and(wiremock_path(format!("/{package}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "dist-tags": { "latest": latest, (tag): target },
            "versions": {
                (installed): { "name": package, "version": installed },
                (target): {
                    "name": package,
                    "version": target,
                    "dist": {
                        "tarball": format!("{}{}", mock.url(), tarball_path),
                        "integrity": integrity,
                    }
                },
                (latest): { "name": package, "version": latest }
            },
            "time": {
                (installed): "2025-01-01T00:00:00.000Z",
                (target): "2025-01-02T00:00:00.000Z",
                (latest): "2025-01-03T00:00:00.000Z"
            }
        })))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(wiremock_path(tarball_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("run tagged dependency upgrade");
    assert!(
        output.status.success(),
        "tag {tag} should upgrade to its mapped version\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest = serde_json::from_str(&project.read_file("package.json"))
        .expect("read tagged dependency manifest");
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read tagged dependency lockfile");
    (manifest, lockfile)
}

#[tokio::test]
async fn upgrade_preserves_custom_stable_and_prerelease_dist_tags() {
    for (index, tag, installed, target, latest) in [
        (0, "legacy", "1.2.0", "1.3.0", "2.0.0"),
        (1, "next", "2.0.0-beta.1", "2.0.0-beta.2", "2.0.0"),
    ] {
        let package = format!("tagged-upgrade-{index}");
        let (manifest, lockfile) =
            run_tagged_upgrade_case(&package, tag, tag, installed, target, latest).await;

        assert_eq!(manifest["dependencies"][&package], serde_json::json!(tag));
        assert_eq!(
            lockfile
                .root_resolutions
                .get(&package)
                .expect("tagged root resolution")
                .version,
            target
        );
    }
}

#[tokio::test]
async fn upgrade_accepts_surrounding_whitespace_in_a_custom_dist_tag() {
    let package = "tagged-upgrade-whitespace";
    let manifest_spec = "  legacy  ";
    let (manifest, lockfile) =
        run_tagged_upgrade_case(package, manifest_spec, "legacy", "1.2.0", "1.3.0", "2.0.0").await;

    assert_eq!(
        manifest["dependencies"][package],
        serde_json::json!(manifest_spec)
    );
    assert_eq!(
        lockfile
            .root_resolutions
            .get(package)
            .expect("tagged root resolution")
            .version,
        "1.3.0"
    );
}

#[tokio::test]
async fn upgrade_peer_preview_ignores_a_missing_optional_peer() {
    let package = "@lpm.dev/acme.optional-peer-preview";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, package, "^1.0.0", "1.0.0");
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(wiremock_path(format!("/api/registry/{package}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": { "name": package, "version": "1.0.0" },
                "1.1.0": {
                    "name": package,
                    "version": "1.1.0",
                    "peerDependencies": { "react": "^18.0.0" },
                    "peerDependenciesMeta": { "react": { "optional": true } }
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z",
                "1.1.0": "2025-01-02T00:00:00.000Z"
            }
        })))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .expect("run optional peer preview");
    assert!(
        output.status.success(),
        "optional peer preview should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["packages"][0]["peer_impact"]["ok"], true);
    assert!(
        envelope["packages"][0]["peer_impact"]["missing"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
}

#[tokio::test]
async fn upgrade_peer_preview_uses_the_exact_root_provider_instance() {
    let package = "@lpm.dev/acme.root-peer-preview";
    let project = TempProject::empty(&format!(
        r#"{{"name":"root-peer-preview","version":"1.0.0","dependencies":{{"{package}":"^1.0.0","react":"^18.0.0"}}}}"#
    ));
    let mut lockfile = lpm_lockfile::Lockfile::new();
    for (name, version, source) in [
        (package, "1.0.0", "registry+https://lpm.dev"),
        ("react", "17.0.2", "registry+https://registry.npmjs.org"),
        ("react", "18.2.0", "registry+https://registry.npmjs.org"),
        ("react", "19.0.0", "registry+https://registry.npmjs.org"),
    ] {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            source: Some(source.to_string()),
            dependencies: if name == package {
                vec!["react-17@17.0.2".to_string(), "react-19@19.0.0".to_string()]
            } else {
                Vec::new()
            },
            alias_dependencies: if name == package {
                vec![
                    ["react-17".to_string(), "react".to_string()],
                    ["react-19".to_string(), "react".to_string()],
                ]
            } else {
                Vec::new()
            },
            ..Default::default()
        });
    }
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[(package, package, "1.0.0"), ("react", "react", "18.2.0")],
    );
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .expect("write duplicate peer lockfile");
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(wiremock_path(format!("/api/registry/{package}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": { "name": package, "version": "1.0.0" },
                "1.1.0": {
                    "name": package,
                    "version": "1.1.0",
                    "peerDependencies": { "react": "^18.0.0" }
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z",
                "1.1.0": "2025-01-02T00:00:00.000Z"
            }
        })))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", package, "-y", "--dry-run", "--json"])
        .output()
        .expect("run exact root peer preview");
    assert!(
        output.status.success(),
        "root peer preview should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["packages"][0]["peer_impact"]["ok"], true);
}

#[tokio::test]
async fn upgrade_runs_root_project_lifecycle_scripts_around_install() {
    let project = TempProject::empty("");
    let mock = setup_up7_successful_upgrade_fixture(&project, UP7_MINOR, false).await;
    let mut manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    manifest["scripts"] = serde_json::json!({
        "pnpm:devPreinstall": "node record-upgrade-lifecycle.js pnpm:devPreinstall",
        "postprepare": "node record-upgrade-lifecycle.js postprepare"
    });
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(&manifest).unwrap(),
    );
    project.write_file(
        "record-upgrade-lifecycle.js",
        &format!(
            r#"const fs = require('fs');
const phase = process.argv[2];
const installed = fs.existsSync('node_modules/{UP7_PKG}/package.json') ? 'installed' : 'missing';
fs.appendFileSync('upgrade-lifecycle.log', `${{phase}}:${{installed}}\n`);
"#
        ),
    );

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("run upgrade with root lifecycle scripts");

    assert!(
        output.status.success(),
        "upgrade with root lifecycle scripts should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("upgrade-lifecycle.log"),
        "pnpm:devPreinstall:missing\npostprepare:installed\n"
    );
}

#[tokio::test]
async fn upgrade_fetches_one_packument_for_multiple_aliases_of_one_package() {
    let project = TempProject::empty(
        r#"{"name":"alias-dedup-upgrade","version":"1.0.0","dependencies":{"ansi-a":"npm:strip-ansi@^6.0.0","ansi-b":"npm:strip-ansi@^6.0.0"}}"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile
        .root_aliases
        .insert("ansi-a".to_string(), "strip-ansi".to_string());
    lockfile
        .root_aliases
        .insert("ansi-b".to_string(), "strip-ansi".to_string());
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "strip-ansi".to_string(),
        version: "6.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[
            ("ansi-a", "strip-ansi", "6.0.0"),
            ("ansi-b", "strip-ansi", "6.0.0"),
        ],
    );
    lockfile
        .write_to_file(&project.path().join("lpm.lock"))
        .expect("write alias-dedup lockfile");

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "strip-ansi",
        "6.1.0",
        &[
            (
                "6.0.0",
                serde_json::json!({}),
                Some(make_tarball("strip-ansi", "6.0.0")),
            ),
            (
                "6.1.0",
                serde_json::json!({}),
                Some(make_tarball("strip-ansi", "6.1.0")),
            ),
        ],
    )
    .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .expect("run deduplicated alias upgrade plan");
    assert!(output.status.success());
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid upgrade envelope");
    assert_eq!(envelope["upgraded"], serde_json::json!(2));
    let request_count = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock recorded requests")
        .into_iter()
        .filter(|request| request.url.path() == "/strip-ansi")
        .count();
    assert_eq!(request_count, 1, "canonical aliases must share one lookup");
}

#[tokio::test]
async fn upgrade_updates_identical_entries_in_both_dependency_sections() {
    let package = "@lpm.dev/owner.cross-section";
    let project = TempProject::empty(&format!(
        r#"{{"name":"cross-section-upgrade","version":"1.0.0","dependencies":{{"{package}":"^1.0.0"}},"devDependencies":{{"{package}":"^1.0.0"}}}}"#,
    ));
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n[[packages]]\nname = \"{package}\"\nversion = \"1.0.0\"\nsource = \"registry+https://lpm.dev\"\n"
        ),
    );
    let mock = MockRegistry::start().await;
    let old_tarball = make_tarball(package, "1.0.0");
    let new_tarball = make_tarball(package, "1.1.0");
    mock.with_full_package_metadata(
        package,
        "1.1.0",
        &[
            ("1.0.0", serde_json::json!({}), Some(old_tarball)),
            ("1.1.0", serde_json::json!({}), Some(new_tarball)),
        ],
    )
    .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("run cross-section upgrade");
    assert!(
        output.status.success(),
        "both dependency sections should upgrade\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        manifest["dependencies"][package],
        serde_json::json!("^1.1.0")
    );
    assert_eq!(
        manifest["devDependencies"][package],
        serde_json::json!("^1.1.0")
    );
}

#[tokio::test]
async fn upgrade_selects_latest_mature_candidate_when_latest_is_inside_release_age_window() {
    let pkg = "@lpm.dev/owner.cooldown-upgrade";
    let project = TempProject::empty("");
    project.write_file(
        "package.json",
        &format!(
            "{{\n  \"name\": \"upgrade-release-age\",\n  \"version\": \"1.0.0\",\n  \
             \"dependencies\": {{\n    \"{pkg}\": \"^1.0.0\"\n  }},\n  \
             \"lpm\": {{ \"minimumReleaseAge\": 86400 }}\n}}\n"
        ),
    );
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
             [[packages]]\nname = \"{pkg}\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://lpm.dev\"\n",
        ),
    );

    let mock = MockRegistry::start().await;
    let v1_0_0 = make_tarball(pkg, "1.0.0");
    let v1_1_0 = make_tarball(pkg, "1.1.0");
    let v1_2_0 = make_tarball(pkg, "1.2.0");
    let metadata = serde_json::json!({
        "name": pkg,
        "dist-tags": { "latest": "1.2.0" },
        "modified": iso8601_n_secs_ago(3_600),
        "versions": {
            "1.0.0": {
                "name": pkg,
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url(pkg, "1.0.0"),
                    "integrity": compute_integrity(&v1_0_0),
                },
                "dependencies": {}
            },
            "1.1.0": {
                "name": pkg,
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url(pkg, "1.1.0"),
                    "integrity": compute_integrity(&v1_1_0),
                },
                "dependencies": {}
            },
            "1.2.0": {
                "name": pkg,
                "version": "1.2.0",
                "dist": {
                    "tarball": mock.tarball_url(pkg, "1.2.0"),
                    "integrity": compute_integrity(&v1_2_0),
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.1.0": iso8601_n_secs_ago(2 * 86_400),
            "1.2.0": iso8601_n_secs_ago(3_600)
        }
    });
    mock.with_package_metadata_and_tarballs(
        pkg,
        metadata,
        &[("1.0.0", v1_0_0), ("1.1.0", v1_1_0), ("1.2.0", v1_2_0)],
    )
    .await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn lpm upgrade");
    assert!(
        out.status.success(),
        "upgrade must choose the newest mature version instead of rewriting to a fresh latest\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(pkg_json["dependencies"][pkg], serde_json::json!("^1.1.0"));
}

#[tokio::test]
async fn upgrade_hydrates_missing_release_times_before_planning() {
    let package = "@lpm.dev/owner.hydrated-upgrade";
    let project = TempProject::empty(&format!(
        r#"{{"name":"hydrated-upgrade","version":"1.0.0","dependencies":{{"{package}":"^1.0.0"}},"lpm":{{"minimumReleaseAge":86400}}}}"#,
    ));
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n[[packages]]\nname = \"{package}\"\nversion = \"1.0.0\"\nsource = \"registry+https://lpm.dev\"\n"
        ),
    );

    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(wiremock_path(format!("/api/registry/{package}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "dist-tags": { "latest": "1.1.0" },
            "modified": iso8601_n_secs_ago(3_600),
            "versions": {
                "1.0.0": { "name": package, "version": "1.0.0" },
                "1.1.0": { "name": package, "version": "1.1.0" }
            }
        })))
        .with_priority(2)
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(wiremock_path(format!("/api/registry/{package}")))
        .and(query_param("release_times", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "time": {
                "1.0.0": iso8601_n_secs_ago(3 * 86_400),
                "1.1.0": iso8601_n_secs_ago(3_600)
            }
        })))
        .with_priority(1)
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .expect("run upgrade with hydrated release times");
    assert!(
        output.status.success(),
        "release-time hydration should produce a clean no-op\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid upgrade envelope");
    assert_eq!(envelope["upgraded"], serde_json::json!(0));
}

#[tokio::test]
async fn upgrade_plans_metadata_in_bounded_parallel_waves() {
    const PACKAGE_COUNT: usize = 8;
    let mut dependencies = serde_json::Map::with_capacity(PACKAGE_COUNT);
    let mut lockfile =
        String::from("[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n");
    for index in 0..PACKAGE_COUNT {
        let name = format!("@lpm.dev/owner.parallel-upgrade-{index}");
        dependencies.insert(name.clone(), serde_json::json!("^1.0.0"));
        lockfile.push_str(&format!(
            "\n[[packages]]\nname = \"{name}\"\nversion = \"1.0.0\"\nsource = \"registry+https://lpm.dev\"\n"
        ));
    }
    let project = TempProject::empty(
        &serde_json::to_string(&serde_json::json!({
            "name": "parallel-upgrade",
            "version": "1.0.0",
            "dependencies": dependencies,
        }))
        .unwrap(),
    );
    project.write_file("lpm.lock", &lockfile);

    let mock = MockRegistry::start().await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(
            r"^/api/registry/@lpm\.dev/owner\.parallel-upgrade-[0-9]+$",
        ))
        .respond_with(RecordDelayedUpgradeMetadataStart {
            starts: std::sync::Arc::clone(&starts),
            delay: std::time::Duration::from_millis(250),
        })
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .expect("run bounded upgrade plan");
    assert!(
        output.status.success(),
        "bounded upgrade plan should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let starts = starts.lock().expect("read upgrade request starts");
    assert_eq!(starts.len(), PACKAGE_COUNT);
    let first = *starts.iter().min().unwrap();
    let mut offsets = starts
        .iter()
        .map(|start| start.duration_since(first))
        .collect::<Vec<_>>();
    offsets.sort();
    assert!(offsets[3] < std::time::Duration::from_millis(150));
    assert!(
        offsets[4] >= std::time::Duration::from_millis(200),
        "more than four metadata requests ran in the first wave: {offsets:?}"
    );
    assert!(
        offsets[7] < std::time::Duration::from_millis(450),
        "the planner did not refill promptly for the second wave: {offsets:?}"
    );
}

#[tokio::test]
async fn upgrade_upgrades_npm_packages_installed_through_configured_lpm_registry() {
    let project = TempProject::empty(
        r#"{"name":"proxy-installed-up","version":"1.0.0","dependencies":{"ms":"2.1.3"}}"#,
    );

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "ms",
        "2.1.4",
        &[
            (
                "2.1.3",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.1.3")),
            ),
            (
                "2.1.4",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.1.4")),
            ),
        ],
    )
    .await;

    lpm_with_registry_and_npm(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    project.write_file(
        "package.json",
        r#"{"name":"proxy-installed-up","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn lpm upgrade");
    assert!(
        out.status.success(),
        "upgrade should include npm packages previously resolved through the configured LPM registry\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(pkg_json["dependencies"]["ms"], serde_json::json!("^2.1.4"));

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read lpm.lock after proxy npm upgrade");
    let entry = lockfile
        .packages
        .iter()
        .find(|p| p.name == "ms")
        .expect("lockfile must still contain ms after upgrade");
    assert_eq!(entry.version, "2.1.4");
    assert!(
        entry.tarball.is_some(),
        "proxy-installed npm package should keep a tarball hint after upgrade",
    );
}

/// A non-`@lpm.dev/*` dependency whose lockfile source is neither
/// public npm nor the configured LPM registry must still be skipped to
/// avoid leaking private package names.
#[tokio::test]
async fn upgrade_skips_non_public_npm_sources_and_reports_them() {
    let project = TempProject::empty(
        r#"{"name":"npm-private-up","version":"1.0.0","dependencies":{"ms":"^2.1.3"}}"#,
    );
    project.write_file(
        "lpm.lock",
        "[metadata]\nlockfile-version = 2\nresolved-with = \"greedy-fusion\"\n\n\
         [[packages]]\nname = \"ms\"\nversion = \"2.1.3\"\n\
         source = \"registry+https://npm.internal.example.com\"\n",
    );

    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        "ms",
        "2.5.0",
        &[
            (
                "2.1.3",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.1.3")),
            ),
            (
                "2.5.0",
                serde_json::json!({}),
                Some(make_tarball("ms", "2.5.0")),
            ),
        ],
    )
    .await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .expect("spawn lpm upgrade --dry-run --json");
    assert!(
        out.status.success(),
        "upgrade should exit 0 when private-source npm names are skipped\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["upgraded"], serde_json::json!(0));
    assert_eq!(envelope["packages"], serde_json::json!([]));
    assert_eq!(envelope["skipped_private"], serde_json::json!(["ms"]));

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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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

#[tokio::test]
async fn upgrade_dry_run_human_output_uses_slim_ui() {
    let pkg = "@lpm.dev/owner.slim-upgrade";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, pkg, "^1.0.0", "1.0.0");

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "1.5.0").await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run"])
        .output()
        .expect("spawn lpm upgrade --dry-run");
    assert!(
        out.status.success(),
        "upgrade --dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.trim().is_empty(),
        "human status output must stay off stdout; got:\n{stdout}"
    );
    assert!(
        stderr.contains("› Checking dependencies for newer matching versions"),
        "stderr must show the slim checking phase; got:\n{stderr}"
    );
    assert!(
        stderr.contains("› Upgrading 1 package"),
        "stderr must show the slim upgrading phase; got:\n{stderr}"
    );
    assert!(
        stderr.contains("↑ @lpm.dev/owner.slim-upgrade") && stderr.contains("1.0.0 → 1.5.0"),
        "stderr must show the slim upgrade row; got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · would upgrade 1 package (dry run)"),
        "stderr must show the slim dry-run terminus; got:\n{stderr}"
    );
    assert!(
        !stderr.contains('│') && !stderr.contains('◇'),
        "dry-run status must not use cliclack's boxed gutter; got:\n{stderr}"
    );
}

#[tokio::test]
async fn upgrade_patch_dry_run_human_output_applies_slim_color_roles_when_forced() {
    let pkg = "@lpm.dev/owner.patch-color";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, pkg, "^1.0.0", "1.0.0");

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "1.0.1").await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["--color=always", "upgrade", "-y", "--dry-run"])
        .output()
        .expect("spawn colored lpm upgrade --dry-run");
    assert!(
        out.status.success(),
        "colored upgrade --dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("\x1b[32m↑\x1b[39m")
            && stderr.contains("\x1b[2m→\x1b[22m")
            && stderr.contains("\x1b[33m1.0.1"),
        "patch upgrade row should color glyph green, arrow dim, and target version yellow, got:\n{stderr:?}",
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

    lpm_with_registry_and_npm(&project, &mock.url())
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

#[tokio::test]
async fn upgrade_executes_the_same_packument_snapshot_it_planned() {
    let package = "@lpm.dev/owner.snapshot-upgrade";
    let project = TempProject::empty(&format!(
        r#"{{"name":"snapshot-upgrade","version":"1.0.0","dependencies":{{"{package}":"^1.0.0"}}}}"#,
    ));
    let mock = MockRegistry::start().await;
    let planned_tarball = make_tarball(package, "1.1.0");
    let later_tarball = make_tarball(package, "1.2.0");
    let planned_integrity = compute_integrity(&planned_tarball);
    let later_integrity = compute_integrity(&later_tarball);
    let planned_metadata = serde_json::json!({
        "name": package,
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.0.0": { "name": package, "version": "1.0.0" },
            "1.1.0": {
                "name": package,
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.1.0"),
                    "integrity": planned_integrity.clone(),
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z",
            "1.1.0": "2025-01-01T00:00:00.000Z"
        }
    });
    let later_metadata = serde_json::json!({
        "name": package,
        "dist-tags": { "latest": "1.2.0" },
        "versions": {
            "1.0.0": { "name": package, "version": "1.0.0" },
            "1.1.0": planned_metadata["versions"]["1.1.0"].clone(),
            "1.2.0": {
                "name": package,
                "version": "1.2.0",
                "dist": {
                    "tarball": mock.tarball_url(package, "1.2.0"),
                    "integrity": later_integrity,
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z",
            "1.1.0": "2025-01-01T00:00:00.000Z",
            "1.2.0": "2025-01-01T00:00:00.000Z"
        }
    });
    let metadata_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let responder = SequentialUpgradeMetadata {
        calls: metadata_calls.clone(),
        first: planned_metadata.clone(),
        second: later_metadata.clone(),
        batch: false,
    };
    Mock::given(method("GET"))
        .and(wiremock_path(format!("/api/registry/{package}")))
        .respond_with(responder)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(wiremock_path("/api/registry/batch-metadata"))
        .respond_with(SequentialUpgradeMetadata {
            calls: metadata_calls.clone(),
            first: planned_metadata,
            second: later_metadata,
            batch: true,
        })
        .mount(mock.server())
        .await;
    for (version, tarball) in [("1.1.0", planned_tarball), ("1.2.0", later_tarball)] {
        let tarball_path = reqwest::Url::parse(&mock.tarball_url(package, version))
            .expect("valid mock tarball URL")
            .path()
            .to_string();
        Mock::given(method("GET"))
            .and(wiremock_path(tarball_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
            .mount(mock.server())
            .await;
    }

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("run snapshot-consistent upgrade");
    assert!(
        output.status.success(),
        "snapshot-consistent upgrade failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let metadata_requests = mock
        .server()
        .received_requests()
        .await
        .expect("mock registry request log")
        .into_iter()
        .filter(|request| {
            request.url.path() == format!("/api/registry/{package}")
                || request.url.path() == "/api/registry/batch-metadata"
        })
        .map(|request| {
            format!(
                "{} {} {}",
                request.method,
                request.url.path(),
                String::from_utf8_lossy(&request.body)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        metadata_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "planning and installation must share one root packument: {metadata_requests:?}"
    );
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read upgraded lockfile");
    let locked = lockfile
        .packages
        .iter()
        .find(|entry| entry.name == package)
        .expect("upgraded package is locked");
    assert_eq!(locked.version, "1.1.0");
    assert_eq!(
        locked.integrity.as_deref(),
        Some(planned_integrity.as_str())
    );
    let installed: serde_json::Value =
        serde_json::from_str(&project.read_file(&format!("node_modules/{package}/package.json")))
            .expect("installed package manifest");
    assert_eq!(installed["version"], "1.1.0");
}

#[tokio::test]
async fn workspace_member_upgrade_preserves_the_sibling_root_lockfile_projection() {
    let pkg = "@lpm.dev/owner.workspace-upgrade";
    let project = TempProject::empty(
        r#"{
  "name": "upgrade-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        &format!(
            "{{\n  \"name\": \"upgrade-app\",\n  \"version\": \"1.0.0\",\n  \
             \"private\": true,\n  \"dependencies\": {{\n    \"{pkg}\": \"^1.0.0\"\n  }}\n}}\n"
        ),
    );
    project.write_file(
        "packages/sibling/package.json",
        r#"{"name":"upgrade-sibling","version":"1.0.0","private":true}"#,
    );

    let mut app_projection = lpm_lockfile::Lockfile::new();
    app_projection.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: pkg.into(),
        version: "1.0.0".into(),
        source: Some("registry+https://lpm.dev".into()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut app_projection, &[(pkg, pkg, "1.0.0")]);
    app_projection.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: std::collections::BTreeMap::from([(
                pkg.to_string(),
                "^1.0.0".to_string(),
            )]),
            ..Default::default()
        },
    );
    let mut sibling_projection = lpm_lockfile::Lockfile::new();
    sibling_projection.patches.insert(
        "sibling@1.0.0".into(),
        lpm_lockfile::LockfilePatch {
            path: "patches/sibling.patch".into(),
            sha256: "sha256-sibling".into(),
            original_integrity: "sha512-sibling".into(),
        },
    );
    let mut root_lockfile = lpm_lockfile::Lockfile::new();
    root_lockfile
        .absorb_importer(".", lpm_lockfile::Lockfile::new())
        .unwrap();
    root_lockfile
        .absorb_importer("packages/app", app_projection)
        .unwrap();
    root_lockfile
        .absorb_importer("packages/sibling", sibling_projection)
        .unwrap();
    root_lockfile
        .write_all(&project.path().join("lpm.lock"))
        .unwrap();
    let sibling_before = root_lockfile.project_importer("packages/sibling").unwrap();

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "2.0.0").await;
    let app_dir = project.path().join("packages/app");
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .current_dir(&app_dir)
        .args(["upgrade", "-y", "--major"])
        .output()
        .expect("upgrade workspace member dependency");
    assert!(
        output.status.success(),
        "workspace member upgrade failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let app_manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("packages/app/package.json")).unwrap();
    assert_eq!(
        app_manifest["dependencies"][pkg],
        serde_json::json!("^2.0.0")
    );
    let updated_root = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
    assert_eq!(
        updated_root
            .project_importer("packages/app")
            .unwrap()
            .find_package(pkg)
            .map(|package| package.version.as_str()),
        Some("2.0.0")
    );
    assert_eq!(
        updated_root.project_importer("packages/sibling").unwrap(),
        sibling_before
    );
    assert!(!app_dir.join("lpm.lock").exists());
    assert!(!app_dir.join("lpm.lockb").exists());
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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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

#[tokio::test]
async fn upgrade_accepts_a_utf8_bom_package_manifest() {
    let pkg = "@lpm.dev/owner.bom-upgrade";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, pkg, "^1.0.0", "1.0.0");
    let manifest = project.read_file("package.json");
    project.write_file("package.json", &format!("\u{feff}{manifest}"));

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "2.0.0").await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--major", "--dry-run", "--json"])
        .output()
        .expect("run upgrade with a BOM manifest");

    assert!(
        output.status.success(),
        "BOM manifest upgrade should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─── JSON contract ──────────────────────────────────────────────────────

#[tokio::test]
async fn upgrade_dry_run_json_envelope_with_one_candidate_matches_snapshot() {
    let pkg = "@lpm.dev/owner.snap-upgrade";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, pkg, "^1.0.0", "1.0.0");

    let mock = MockRegistry::start().await;
    mount_lpm_pkg(&mock, pkg, "1.5.0").await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .expect("spawn lpm upgrade --dry-run --json");
    assert!(out.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    insta::assert_json_snapshot!("upgrade_json_envelope_one_candidate_dry_run", envelope);
}

// ─── enriched-dry-run regressions ───────────
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

async fn setup_up7_delayed_install_fixture(
    project: &TempProject,
    marker: &std::path::Path,
    fail_target_tarball: bool,
) -> MockRegistry {
    up7_write_manifest(project, &up7_manifest_with_dependency("^1.2.0", false));
    up7_write_lockfile(project, &[(UP7_PKG, UP7_CURRENT)]);
    let mock = MockRegistry::start().await;
    let current_tarball = make_tarball(UP7_PKG, UP7_CURRENT);
    let target_tarball = make_tarball(UP7_PKG, UP7_MINOR);
    let versions = vec![
        VersionFixture {
            version: UP7_CURRENT,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: current_tarball.clone(),
        },
        VersionFixture {
            version: UP7_MINOR,
            dependencies: serde_json::json!({}),
            peer_dependencies: serde_json::Value::Null,
            lifecycle_scripts: None,
            tarball: target_tarball.clone(),
        },
    ];
    let metadata = up7_metadata(&mock.url(), UP7_PKG, UP7_MINOR, &versions);
    Mock::given(method("GET"))
        .and(wiremock_path(format!("/api/registry/{UP7_PKG}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(wiremock_path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json({
            let mut packages = serde_json::Map::new();
            packages.insert(UP7_PKG.to_string(), metadata);
            serde_json::json!({ "packages": packages })
        }))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(wiremock_path(up7_tarball_path(UP7_PKG, UP7_CURRENT)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(current_tarball))
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(wiremock_path(up7_tarball_path(UP7_PKG, UP7_MINOR)))
        .respond_with(MarkDelayedUpgradeTarball {
            marker: marker.to_path_buf(),
            body: (!fail_target_tarball).then_some(target_tarball),
            delay: std::time::Duration::from_millis(750),
        })
        .mount(mock.server())
        .await;
    mock
}

fn wait_for_upgrade_tarball_request(marker: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for delayed upgrade tarball request"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn upgrade_json_emits_one_document_after_successful_install() {
    let project = TempProject::empty("");
    let mock = setup_up7_successful_upgrade_fixture(&project, UP7_MINOR, false).await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("spawn JSON upgrade");
    assert!(
        out.status.success(),
        "upgrade must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope = parse_stdout_json(&out.stdout, &out.stderr);
    assert_eq!(envelope["upgraded"], serde_json::json!(1));
}

#[tokio::test]
async fn upgrade_rejects_a_manifest_edit_during_install_and_rolls_back_install_state() {
    let project = TempProject::empty("");
    let marker = project.path().join("target-tarball.requested");
    let mock = setup_up7_delayed_install_fixture(&project, &marker, false).await;
    let original_lockfile = project.read_file("lpm.lock");
    let external_manifest = r#"{"name":"external-edit","version":"1.0.0"}"#;
    let mut command = lpm_spawnable_with_registry(&project, &mock.url());
    command.args(["upgrade", "-y"]);
    let child = command.spawn().expect("spawn delayed successful upgrade");

    wait_for_upgrade_tarball_request(&marker);
    project.write_file("package.json", external_manifest);
    let output = child
        .wait_with_output()
        .expect("wait for delayed successful upgrade");

    assert!(
        !output.status.success(),
        "upgrade must reject a manifest edit made during installation\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("package.json"), external_manifest);
    assert_eq!(project.read_file("lpm.lock"), original_lockfile);
    assert!(!project.file_exists(".lpm/install-hash"));
}

#[tokio::test]
async fn failed_upgrade_does_not_overwrite_a_manifest_edit_made_during_install() {
    let project = TempProject::empty("");
    let marker = project.path().join("target-tarball.requested");
    let mock = setup_up7_delayed_install_fixture(&project, &marker, true).await;
    let external_manifest = r#"{"name":"external-edit","version":"1.0.0"}"#;
    let mut command = lpm_spawnable_with_registry(&project, &mock.url());
    command.args(["upgrade", "-y"]);
    let child = command.spawn().expect("spawn delayed failing upgrade");

    wait_for_upgrade_tarball_request(&marker);
    project.write_file("package.json", external_manifest);
    let output = child
        .wait_with_output()
        .expect("wait for delayed failing upgrade");

    assert!(
        !output.status.success(),
        "upgrade fixture should fail after the manifest edit"
    );
    assert_eq!(project.read_file("package.json"), external_manifest);
}

#[tokio::test]
async fn upgrade_respects_a_direct_dependency_override_that_pins_the_installed_version() {
    let project = TempProject::empty("");
    let mock = setup_up7_successful_upgrade_fixture(&project, UP7_MINOR, false).await;
    let mut manifest = up7_manifest_with_dependency("^1.2.0", false);
    manifest["overrides"] = serde_json::json!({ UP7_PKG: UP7_CURRENT });
    up7_write_manifest(&project, &manifest);
    up7_write_lockfile(&project, &[(UP7_PKG, UP7_CURRENT)]);
    let original_manifest = project.read_file("package.json");

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("run upgrade with a direct dependency override");

    assert!(
        output.status.success(),
        "override-controlled upgrade should succeed without an impossible plan\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope = parse_stdout_json(&output.stdout, &output.stderr);
    assert_eq!(envelope["upgraded"], 0);
    assert_eq!(project.read_file("package.json"), original_manifest);
    let lockfile = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock"))
        .expect("read override-controlled lockfile");
    assert_eq!(
        lockfile
            .find_package(UP7_PKG)
            .map(|package| package.version.as_str()),
        Some(UP7_CURRENT)
    );
}

#[tokio::test]
async fn upgrade_bounds_and_deduplicates_remote_metadata_failure_details() {
    let canonical = "@lpm.dev/acme.failure-budget";
    let dependencies = (0..32)
        .map(|index| {
            (
                format!("failure-alias-{index}"),
                serde_json::Value::String(format!("npm:{canonical}@^1.0.0")),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let project = TempProject::empty(
        &serde_json::to_string(&serde_json::json!({
            "name": "upgrade-failure-budget",
            "version": "1.0.0",
            "dependencies": dependencies
        }))
        .unwrap(),
    );
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(wiremock_path(format!("/api/registry/{canonical}")))
        .respond_with(ResponseTemplate::new(404).set_body_string("x".repeat(1024 * 1024)))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("run upgrade with a large shared metadata failure");

    assert!(!output.status.success());
    assert!(
        output.stderr.len() < 32 * 1024,
        "one shared remote failure must not expand into {} bytes of diagnostics",
        output.stderr.len()
    );
}

#[tokio::test]
async fn upgrade_updates_an_installed_optional_dependency_in_its_original_section() {
    let project = TempProject::empty("");
    let mock = setup_up7_successful_upgrade_fixture(&project, UP7_MINOR, false).await;
    up7_write_manifest(
        &project,
        &serde_json::json!({
            "name": "optional-upgrade",
            "version": "1.0.0",
            "optionalDependencies": { UP7_PKG: "^1.2.0" }
        }),
    );
    up7_write_lockfile(&project, &[(UP7_PKG, UP7_CURRENT)]);

    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("upgrade an optional dependency");

    assert!(
        output.status.success(),
        "optional dependency upgrade should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        manifest["optionalDependencies"][UP7_PKG],
        serde_json::json!("^1.3.0")
    );
    assert!(manifest.get("dependencies").is_none());
}

#[tokio::test]
async fn upgrade_json_emits_one_error_document_when_install_fails() {
    let project = TempProject::empty("");
    let mock = setup_up7_failed_install_fixture(&project).await;
    up7_write_lockfile(&project, &[(UP7_PKG, UP7_CURRENT)]);

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("spawn failing JSON upgrade");
    assert!(!out.status.success(), "upgrade must fail");

    let envelope = parse_stdout_json(&out.stdout, &out.stderr);
    assert_eq!(envelope["success"], serde_json::json!(false));
}

#[tokio::test]
async fn upgrade_metadata_failure_is_not_reported_as_up_to_date() {
    let package = "@lpm.dev/owner.unreachable-upgrade";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, package, "^1.0.0", "1.0.0");
    let mock = MockRegistry::start().await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("spawn upgrade with unavailable metadata");
    assert!(
        !out.status.success(),
        "metadata failure must not be a successful up-to-date result: {}",
        String::from_utf8_lossy(&out.stdout),
    );

    let envelope = parse_stdout_json(&out.stdout, &out.stderr);
    assert_eq!(envelope["success"], serde_json::json!(false));
}

#[test]
fn upgrade_rejects_invalid_lpm_dependency_names() {
    let invalid_name = "@lpm.dev/invalid name";
    let project = TempProject::empty(&format!(
        r#"{{"name":"invalid-upgrade","version":"1.0.0","dependencies":{{"{invalid_name}":"^1.0.0"}}}}"#
    ));

    let out = lpm(&project)
        .args(["upgrade", "-y", "--json"])
        .output()
        .expect("spawn upgrade with invalid dependency name");
    assert!(
        !out.status.success(),
        "invalid dependency must fail upgrade"
    );

    let envelope = parse_stdout_json(&out.stdout, &out.stderr);
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|message| message.contains(invalid_name)),
        "error must name the invalid dependency: {envelope}",
    );
}

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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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

    let yes_out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y", "--json", "--dry-run"])
        .output()
        .expect("spawn upgrade -y");
    assert!(yes_out.status.success());

    let default_out = lpm_with_registry_and_npm(&project, &mock.url())
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

/// `-i -y` is mutually exclusive — parse-layer rejection. Error names
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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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
/// version declares lifecycle scripts.
#[tokio::test]
async fn upgrade_yes_marks_install_scripts_in_json() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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
/// versions — previously the field was missing entirely.
#[tokio::test]
async fn upgrade_yes_marks_peer_violation_in_json() {
    let project = TempProject::empty("");
    let mock = setup_up7_enriched_dry_run_fixture(&project).await;

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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
/// manifest and lockfile are restored byte-equal, and any pre-existing
/// install-hash is invalidated so the next bare install cannot fast-exit
/// against a tree touched by the failed internal install.
#[tokio::test]
async fn upgrade_yes_install_failure_restores_manifest_and_invalidates_install_hash() {
    let project = TempProject::empty("");
    let mock = setup_up7_failed_install_fixture(&project).await;
    up7_write_lockfile(&project, &[(UP7_PKG, UP7_CURRENT)]);
    let install_hash_path = project.path().join(".lpm").join("install-hash");
    std::fs::create_dir_all(install_hash_path.parent().unwrap()).unwrap();
    std::fs::write(&install_hash_path, "old-cache").unwrap();
    let before = project.read_file("package.json");
    let lockfile_before = project.read_file("lpm.lock");

    let out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn upgrade");
    assert!(!out.status.success(), "upgrade should have failed");

    assert_eq!(
        before,
        project.read_file("package.json"),
        "package.json must be restored byte-equal on install failure"
    );
    assert_eq!(
        lockfile_before,
        project.read_file("lpm.lock"),
        "lpm.lock must be restored byte-equal on install failure"
    );
    assert!(
        !install_hash_path.exists(),
        "failed upgrade must invalidate .lpm/install-hash after rollback"
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

    let upgrade_out = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["upgrade", "-y"])
        .output()
        .expect("spawn upgrade");
    assert!(
        upgrade_out.status.success(),
        "upgrade must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&upgrade_out.stdout),
        String::from_utf8_lossy(&upgrade_out.stderr)
    );

    let offline_out = lpm_with_registry_and_npm(&project, &mock.url())
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

    let out = lpm_with_registry_and_npm(&project, &mock.url())
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
