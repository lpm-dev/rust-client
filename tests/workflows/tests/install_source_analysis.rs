//! Install-time source-analysis preferences across package installation and audit.

mod support;

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry_and_npm, write_signed_unlock};

const SCAN_TRACE: &str = "Scanning live package source for install security summary";

fn write_config(project: &TempProject, config: &str) {
    let path = project.home().join(".lpm/config.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, config).unwrap();
}

fn source_tarball(name: &str) -> Vec<u8> {
    make_tarball_from_pkg_json(
        serde_json::json!({"name": name, "version": "1.0.0", "license": "MIT"}),
        &[("index.js", b"module.exports = input => eval(input);\n")],
    )
}

async fn assert_install_skips_source_analysis(config: &str) {
    let mock = MockRegistry::start().await;
    let tarball = source_tarball("source-analysis-preference");
    mock.with_package("source-analysis-preference", "1.0.0", &tarball)
        .await;

    for store in ["v1", "v2", "v3"] {
        for verbose in [false, true] {
            let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
            write_config(&project, config);
            let mut command = lpm_with_registry_and_npm(&project, &mock.url());
            command
                .env("LPM_STORE_VERSION", store)
                .env("RUST_LOG", "lpm_rs::security_check=trace");
            if verbose {
                command.arg("--verbose");
            }
            let output = command
                .args([
                    "install",
                    "source-analysis-preference@1.0.0",
                    "--no-skills",
                    "--no-editor-setup",
                ])
                .output()
                .expect("install package with source analysis disabled");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{store}, verbose={verbose}: {stderr}"
            );
            assert!(
                !stderr.contains(SCAN_TRACE),
                "disabled source analysis must skip the scanner ({store}, verbose={verbose}):\n{stderr}",
            );
            assert!(
                !stderr.contains("Security summary") && !stderr.contains("Behavioral metadata"),
                "disabled source analysis must not produce local findings ({store}, verbose={verbose}):\n{stderr}",
            );
        }
    }
}

#[tokio::test]
async fn install_does_not_analyze_package_source_by_default() {
    assert_install_skips_source_analysis("").await;
}

#[tokio::test]
async fn install_does_not_analyze_package_source_when_explicitly_disabled() {
    assert_install_skips_source_analysis("install-time-source-analysis = false\n").await;
}

#[tokio::test]
async fn firewall_modes_do_not_enable_disabled_source_analysis() {
    let mock = MockRegistry::start().await;
    let name = "source-analysis-preference";
    mock.with_package(name, "1.0.0", &source_tarball(name))
        .await;
    mock.with_npm_firewall_allow_expected(name, "1.0.0", 2..=2)
        .await;
    for mode in ["off", "monitor", "enforce"] {
        let project = TempProject::empty(
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"source-analysis-preference":"1.0.0"}}"#,
        );
        write_config(
            &project,
            &format!("install-time-source-analysis = false\n[firewall]\nmode = \"{mode}\"\n"),
        );
        let output = lpm_with_registry_and_npm(&project, &mock.url())
            .env("RUST_LOG", "lpm_rs::security_check=trace")
            .args(["--verbose", "install", "--no-skills", "--no-editor-setup"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{mode}: {stderr}");
        assert!(!stderr.contains(SCAN_TRACE), "{mode}: {stderr}");
        assert!(!stderr.contains("Security summary"), "{mode}: {stderr}");
        assert!(!stderr.contains("Behavioral metadata"), "{mode}: {stderr}");
    }
}

#[tokio::test]
async fn disabling_source_analysis_skips_warm_install_scan_but_preserves_explicit_audit() {
    let mock = MockRegistry::start().await;
    let name = "source-analysis-preference";
    let tarball = source_tarball(name);
    mock.with_package(name, "1.0.0", &tarball).await;
    mock.with_osv_querybatch(vec![vec![]]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"source-analysis-preference":"1.0.0"}}"#,
    );
    write_signed_unlock(&project, &["source-analysis-disable"]);
    lpm(&project)
        .args(["config", "source-analysis", "--set", "true"])
        .assert()
        .success();

    let enabled = lpm_with_registry_and_npm(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("RUST_LOG", "lpm_rs::security_check=trace")
        .args(["--verbose", "install", "--no-skills", "--no-editor-setup"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&enabled.stderr);
    assert!(enabled.status.success(), "{stderr}");
    assert!(
        stderr.contains(SCAN_TRACE),
        "enabled install must scan: {stderr}"
    );
    assert!(stderr.contains("eval()"), "{stderr}");

    let store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
    let object = store
        .paths()
        .object_dir(&compute_integrity(&tarball))
        .unwrap();
    let cache_path = object.join(".lpm-security.json");
    let cache_before = std::fs::read(&cache_path).unwrap();
    write_config(&project, "install-time-source-analysis = false\n");

    let disabled = lpm_with_registry_and_npm(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .env("RUST_LOG", "lpm_rs::security_check=trace")
        .args(["--verbose", "install", "--no-skills", "--no-editor-setup"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&disabled.stderr);
    assert!(disabled.status.success(), "{stderr}");
    assert!(
        !stderr.contains(SCAN_TRACE),
        "disabled install must not scan: {stderr}"
    );
    assert!(!stderr.contains("Security summary"), "{stderr}");
    assert!(!stderr.contains("Behavioral metadata"), "{stderr}");
    assert_eq!(std::fs::read(&cache_path).unwrap(), cache_before);
    assert_eq!(mock.tarball_request_count(name, "1.0.0").await, 1);

    std::fs::remove_file(cache_path).unwrap();
    let audit = lpm_with_registry_and_npm(&project, &mock.url())
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
        .args(["audit", "--fail-on=behavior"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&audit.stderr);
    assert_eq!(audit.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("eval()"),
        "explicit audit must scan: {stderr}"
    );
}

#[tokio::test]
async fn disabled_source_analysis_preserves_independent_registry_insights() {
    let mock = MockRegistry::start().await;
    let name = "@lpm.dev/test.source-analysis-preference";
    let tarball = source_tarball(name);
    let mut metadata = mock
        .mount_full_package_metadata_routes(
            name,
            "1.0.0",
            &[("1.0.0", serde_json::json!({}), Some(tarball.clone()))],
        )
        .await;
    metadata["versions"]["1.0.0"]["_behavioralTags"] = serde_json::json!({"network": true});
    mock.with_package_metadata_and_tarballs(name, metadata.clone(), &[("1.0.0", tarball)])
        .await;
    mock.with_batch_metadata(vec![metadata]).await;

    for insights in [true, false] {
        let project = TempProject::empty(
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"@lpm.dev/test.source-analysis-preference":"1.0.0"}}"#,
        );
        write_config(
            &project,
            &format!(
                "install-time-source-analysis = false\nfetch-lpm-security-insights = {insights}\n"
            ),
        );
        let output = lpm_with_registry_and_npm(&project, &mock.url())
            .env("RUST_LOG", "lpm_rs::security_check=trace")
            .args(["--verbose", "install", "--no-skills", "--no-editor-setup"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(!stderr.contains(SCAN_TRACE), "{stderr}");
        assert!(!stderr.contains("eval()"), "{stderr}");
        assert_eq!(stderr.contains("network access"), insights, "{stderr}");
        assert_eq!(stderr.contains("Capabilities"), insights, "{stderr}");
        assert!(!stderr.contains("Security summary"), "{stderr}");
    }
}

#[tokio::test]
async fn audit_separates_capabilities_and_preserves_explicit_policy_failures() {
    let mock = MockRegistry::start().await;
    let name = "capability-evidence";
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name": name, "version": "1.0.0", "license": "MIT"}),
        &[("lib/compile.js", b"module.exports = input => eval(input);\nconst values = [\n1,\n2,\n3,\n4,\n5,\n6,\n7,\n8,\n9,\n10\n];\nmodule.exports.values = values;\n")],
    );
    mock.with_package(name, "1.0.0", &tarball).await;
    mock.with_osv_querybatch(vec![vec![]]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"capability-evidence":"1.0.0"}}"#,
    );
    write_config(&project, "install-time-source-analysis = true\n");
    let installed = lpm_with_registry_and_npm(&project, &mock.url())
        .args(["install", "--no-skills", "--no-editor-setup"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&installed.stderr);
    assert!(installed.status.success(), "{stderr}");
    assert!(stderr.contains("Capabilities"), "{stderr}");
    assert!(!stderr.contains("Security summary"), "{stderr}");

    let audit = lpm_with_registry_and_npm(&project, &mock.url())
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
        .args(["--json", "audit"])
        .output()
        .unwrap();
    assert!(
        audit.status.success(),
        "{}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    assert_eq!(envelope["total_issues"], 0);
    assert_eq!(envelope["total_capabilities"], 1);
    assert_eq!(envelope["counts"]["high"], 0);
    let capability = &envelope["packages"][0]["capabilities"][0];
    assert_eq!(capability["rule_id"], "eval");
    assert_eq!(capability["policy_severity"], "high");
    assert_eq!(capability["evidence"][0]["path"], "lib/compile.js");
    assert_eq!(capability["evidence"][0]["line"], 1);
    insta::assert_json_snapshot!("audit_capability_evidence", envelope, {
        ".packages[].path" => "[PACKAGE_PATH]",
        ".packages[].instance_id" => "[INSTANCE_ID]",
    });

    let human = lpm_with_registry_and_npm(&project, &mock.url())
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
        .args(["audit"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(human.status.success(), "{stderr}");
    assert!(stderr.contains("Capabilities"), "{stderr}");
    assert!(stderr.contains("No security issues found"), "{stderr}");
    assert!(!stderr.contains("Behavioral flags"), "{stderr}");

    for policy in ["--fail-on=behavior", "--fail-on=all"] {
        let explicit = lpm_with_registry_and_npm(&project, &mock.url())
            .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
            .args(["--json", "audit", policy])
            .output()
            .unwrap();
        assert_eq!(explicit.status.code(), Some(1), "{policy}");
    }
}

#[tokio::test]
async fn install_cache_and_audit_agree_on_scoped_runtime_evaluation() {
    for (source, expected) in [
        (
            "class Function {} new Function(); const parser = {eval: value => value}; parser.eval(input);",
            false,
        ),
        (
            "const Compile = Function; module.exports = source => new Compile(source);",
            true,
        ),
        (
            "const vm = require('node:vm'); module.exports = source => vm.runInNewContext(source);",
            true,
        ),
    ] {
        let mock = MockRegistry::start().await;
        let name = "evaluation-control";
        let tarball = make_tarball_from_pkg_json(
            serde_json::json!({"name": name, "version": "1.0.0", "license": "MIT"}),
            &[("index.js", source.as_bytes())],
        );
        mock.with_package(name, "1.0.0", &tarball).await;
        mock.with_osv_querybatch(vec![vec![]]).await;
        let project = TempProject::empty(
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"evaluation-control":"1.0.0"}}"#,
        );
        write_config(&project, "install-time-source-analysis = true\n");
        let installed = lpm_with_registry_and_npm(&project, &mock.url())
            .env("LPM_STORE_VERSION", "v2")
            .args(["install", "--no-skills", "--no-editor-setup"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&installed.stderr);
        assert!(installed.status.success(), "{source}: {stderr}");
        assert_eq!(stderr.contains("eval()"), expected, "{source}: {stderr}");
        let store = lpm_store::v2::Store::at(project.home().join(".lpm/store/v2"));
        let object = store
            .paths()
            .object_dir(&compute_integrity(&tarball))
            .unwrap();
        let cached: serde_json::Value =
            serde_json::from_slice(&std::fs::read(object.join(".lpm-security.json")).unwrap())
                .unwrap();
        assert_eq!(cached["source"]["eval"], expected, "{source}");
        assert_eq!(cached["version"], lpm_security::behavioral::SCHEMA_VERSION);
        let audit = lpm_with_registry_and_npm(&project, &mock.url())
            .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
            .args(["--json", "audit", "--fail-on=behavior"])
            .output()
            .unwrap();
        assert_eq!(
            audit.status.code(),
            Some(i32::from(expected)),
            "{source}: {}",
            String::from_utf8_lossy(&audit.stderr)
        );
        let envelope: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
        let found = envelope["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|package| {
                package["capabilities"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|capability| capability["rule_id"] == "eval")
            });
        assert_eq!(found, expected, "{source}");
    }
}
