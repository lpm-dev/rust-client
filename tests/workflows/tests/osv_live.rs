//! Live OSV contract checks, excluded from deterministic workspace tests.
//!
//! Run explicitly with `cargo nextest run --locked -p lpm-workflows --test osv_live
//! --run-ignored only`. Scheduled and manual CI run these against the production endpoint.

mod support;

use std::time::Duration;

use serde_json::Value;
use support::{TempProject, lpm};

const ADVISORY_ID: &str = "GHSA-35jh-r3h4-6jhm";

fn vulnerable_project() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"osv-live-contract","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}"#,
    );
    project.write_file(
        "node_modules/lodash/package.json",
        r#"{"name":"lodash","version":"4.17.20","license":"MIT"}"#,
    );
    project.write_file("node_modules/lodash/index.js", "module.exports = {};\n");
    project
}

fn run_live_osv(project: &TempProject, args: &[&str]) -> std::process::Output {
    lpm(project)
        .env_remove("LPM_OSV_URL")
        .args(args)
        .timeout(Duration::from_secs(60))
        .output()
        .expect("run CLI against the public OSV API")
}

#[test]
#[ignore = "requires the public OSV API; run separately from deterministic tests"]
fn audit_reads_and_hydrates_a_known_advisory_from_the_public_osv_api() {
    let project = vulnerable_project();
    let output = run_live_osv(&project, &["--json", "audit", "--fail-on", "vuln"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "audit must report the known vulnerability\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("audit JSON report");
    assert_eq!(report["success"], true, "{report}");
    assert_eq!(report["osv_degraded"], false, "{report}");
    let advisory = report["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array")
        .iter()
        .find(|advisory| advisory["id"] == ADVISORY_ID)
        .unwrap_or_else(|| panic!("missing known advisory {ADVISORY_ID}: {report}"));
    assert_eq!(advisory["package"], "lodash", "{advisory}");
    assert_eq!(advisory["version"], "4.17.20", "{advisory}");
    assert!(
        advisory["summary"]
            .as_str()
            .is_some_and(|summary| !summary.is_empty()),
        "sparse OSV batch references must be hydrated: {advisory}",
    );
    assert!(
        matches!(
            advisory["severity"].as_str(),
            Some("CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "INFO")
        ),
        "hydrated advisory must have a usable severity: {advisory}",
    );
}

#[test]
#[ignore = "requires the public OSV API; run separately from deterministic tests"]
fn query_matches_a_vulnerable_package_using_the_public_osv_api() {
    let project = vulnerable_project();
    let output = run_live_osv(&project, &["--json", "query", ":vulnerable", "--verbose"]);
    assert!(
        output.status.success(),
        "live vulnerability query must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("query JSON report");
    let matches = report.as_array().expect("matched packages array");
    assert_eq!(matches.len(), 1, "{report}");
    assert_eq!(matches[0]["name"], "lodash", "{report}");
    assert_eq!(matches[0]["version"], "4.17.20", "{report}");
    assert_eq!(matches[0]["isVulnerable"], true, "{report}");
}
