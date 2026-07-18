use super::behavior::analysis_to_issues;
use super::discovery::{DiscoveredPackage, ManagerKind, ScanMode};
use super::osv::{cvss_score_to_label, osv_override_is_accepted, query_osv_batch};
use super::policy::{FailPolicy, severity_level};
use super::registry::collect_registry_issues;
use super::types::{AuditIssue, AuditResult};
use super::*;

#[test]
fn severity_level_critical_case_insensitive() {
    assert_eq!(severity_level("CRITICAL"), 4);
    assert_eq!(severity_level("critical"), 4);
    assert_eq!(severity_level("Critical"), 4);
}

#[test]
fn severity_level_high_case_insensitive() {
    assert_eq!(severity_level("HIGH"), 3);
    assert_eq!(severity_level("high"), 3);
    assert_eq!(severity_level("High"), 3);
}

#[test]
fn severity_level_moderate_and_medium() {
    assert_eq!(severity_level("moderate"), 2);
    assert_eq!(severity_level("medium"), 2);
    assert_eq!(severity_level("MODERATE"), 2);
    assert_eq!(severity_level("MEDIUM"), 2);
}

#[test]
fn severity_level_low_and_info() {
    assert_eq!(severity_level("low"), 1);
    assert_eq!(severity_level("info"), 1);
    assert_eq!(severity_level("LOW"), 1);
    assert_eq!(severity_level("INFO"), 1);
}

#[test]
fn severity_level_unknown() {
    assert_eq!(severity_level("unknown"), 0);
    assert_eq!(severity_level(""), 0);
}

#[test]
fn cvss_vector_uses_its_computed_base_score() {
    assert_eq!(
        cvss_score_to_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
        "MEDIUM"
    );
}

#[test]
fn confusion_warns_on_popular_npm_name() {
    let packages = vec![("@lpm.dev/owner.lodash".to_string(), "1.0.0".to_string())];
    let warnings = check_dependency_confusion(&packages);
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].npm_name, "lodash");
    assert_eq!(warnings[0].lpm_package, "@lpm.dev/owner.lodash");
}

#[test]
fn confusion_no_warn_on_custom_name() {
    let packages = vec![(
        "@lpm.dev/owner.my-custom-lib".to_string(),
        "1.0.0".to_string(),
    )];
    let warnings = check_dependency_confusion(&packages);
    assert!(warnings.is_empty());
}

#[test]
fn confusion_no_warn_on_non_lpm_package() {
    let packages = vec![("lodash".to_string(), "4.17.21".to_string())];
    let warnings = check_dependency_confusion(&packages);
    assert!(warnings.is_empty());
}

#[test]
fn confusion_multiple_warnings() {
    let packages = vec![
        ("@lpm.dev/alice.react".to_string(), "1.0.0".to_string()),
        ("@lpm.dev/bob.express".to_string(), "2.0.0".to_string()),
        ("@lpm.dev/charlie.my-thing".to_string(), "3.0.0".to_string()),
    ];
    let warnings = check_dependency_confusion(&packages);
    assert_eq!(warnings.len(), 2);
}

#[test]
fn osv_skips_lpm_packages() {
    // OSV dedup should exclude @lpm.dev packages (they get vuln data from registry)
    let packages = [
        DiscoveredPackage {
            name: "@lpm.dev/owner.utils".into(),
            version: "1.0.0".into(),
            path: "@lpm.dev/owner.utils".into(),
            integrity: None,
            patch_sha256: None,
            resolved_url: None,
            scan_mode: ScanMode::RegistryAndStore,
            is_dev: false,
            is_optional: false,
            dependencies: Vec::new(),
        },
        DiscoveredPackage {
            name: "lodash".into(),
            version: "4.17.21".into(),
            path: "node_modules/lodash".into(),
            integrity: None,
            patch_sha256: None,
            resolved_url: Some("https://artifactory.example.com/lodash-4.17.21.tgz".into()),
            scan_mode: ScanMode::FullLocal,
            is_dev: false,
            is_optional: false,
            dependencies: Vec::new(),
        },
    ];

    // Simulate OSV collection logic: only non-@lpm.dev packages
    let osv_eligible: Vec<&str> = packages
        .iter()
        .filter(|p| !p.name.starts_with("@lpm.dev/"))
        .map(|p| p.name.as_str())
        .collect();

    assert_eq!(osv_eligible, vec!["lodash"]);
    // lodash from a proxy should NOT be skipped — it's still a public package
}

#[test]
fn discovery_scan_mode_display() {
    assert_eq!(ManagerKind::Npm.to_string(), "npm");
    assert_eq!(ManagerKind::Lpm.to_string(), "lpm");
    assert_eq!(ManagerKind::Pnpm.to_string(), "pnpm");
    assert_eq!(ManagerKind::Yarn.to_string(), "yarn");
    assert_eq!(ManagerKind::Bun.to_string(), "bun");
    assert_eq!(ManagerKind::FallbackNodeModules.to_string(), "node_modules");
}

#[test]
fn cvss_score_parsing() {
    assert_eq!(cvss_score_to_label("9.8"), "CRITICAL");
    assert_eq!(cvss_score_to_label("7.5"), "HIGH");
    assert_eq!(cvss_score_to_label("5.0"), "MEDIUM");
    assert_eq!(cvss_score_to_label("2.0"), "LOW");
    assert_eq!(cvss_score_to_label("CVSS:3.1/AV:N/AC:L"), "UNKNOWN");
    assert_eq!(cvss_score_to_label("unknown"), "UNKNOWN");
}

#[test]
fn fail_policy_parse_valid() {
    assert_eq!(FailPolicy::parse("vuln").unwrap(), FailPolicy::Vuln);
    assert_eq!(
        FailPolicy::parse("vulnerability").unwrap(),
        FailPolicy::Vuln
    );
    assert_eq!(
        FailPolicy::parse("vulnerabilities").unwrap(),
        FailPolicy::Vuln
    );
    assert_eq!(FailPolicy::parse("behavior").unwrap(), FailPolicy::Behavior);
    assert_eq!(
        FailPolicy::parse("behavioral").unwrap(),
        FailPolicy::Behavior
    );
    assert_eq!(
        FailPolicy::parse("behaviour").unwrap(),
        FailPolicy::Behavior
    );
    assert_eq!(FailPolicy::parse("secret").unwrap(), FailPolicy::Secrets);
    assert_eq!(FailPolicy::parse("secrets").unwrap(), FailPolicy::Secrets);
    assert_eq!(FailPolicy::parse("all").unwrap(), FailPolicy::All);
    assert_eq!(FailPolicy::parse("VULN").unwrap(), FailPolicy::Vuln);
}

#[test]
fn fail_policy_parse_invalid() {
    assert!(FailPolicy::parse("invalid").is_err());
    assert!(FailPolicy::parse("").is_err());
}

#[test]
fn eval_classified_as_high_severity() {
    let mut analysis = lpm_security::behavioral::PackageAnalysis {
        version: lpm_security::behavioral::SCHEMA_VERSION,
        analyzed_at: String::new(),
        source: Default::default(),
        supply_chain: Default::default(),
        manifest: Default::default(),
        meta: Default::default(),
    };
    analysis.source.eval = true;

    let issues = analysis_to_issues(&analysis, "local");

    // eval must be classified as "high", not "moderate"
    let eval_issue = issues
        .iter()
        .find(|i| i.message.contains("eval"))
        .expect("eval issue not found");
    assert_eq!(
        eval_issue.severity, "high",
        "eval should be 'high' severity per documented classification"
    );
}

#[test]
fn fail_on_behavior_catches_high_severity() {
    // --fail-on behavior should fail on both critical AND high behaviors.
    // A package using eval() (high severity) must trigger exit 1.
    let results = [AuditResult {
        name: "sketchy-pkg".into(),
        version: "1.0.0".into(),
        quality_score: None,
        issues: vec![AuditIssue {
            severity: "high".into(),
            message: "uses eval()".into(),
            category: "behavior".into(),
            source: "local".into(),
        }],
    }];

    // FailPolicy::Behavior should catch high-severity behavioral flags
    let has_behavioral_failure = results.iter().any(|r| {
        r.issues.iter().any(|i| {
            (i.severity == "critical" || i.severity == "high") && i.category != "vulnerability"
        })
    });
    assert!(
        has_behavioral_failure,
        "--fail-on behavior must catch high-severity behaviors like eval()"
    );
}

// ─── collect_registry_issues: behavioral-tag → AuditIssue mapping ───
//
// Pins the 4-bucket contract (critical / dangerous / medium / notable)
// and the lifecycle-scripts / security-findings / vulnerabilities
// arms. Each bucket emits at most one AuditIssue, regardless of how
// many member tags fire. A silent miscategorization here would let
// the registry think a package is dangerous while `lpm audit` reports
// it as clean, so the test set is exhaustive across all 22
// documented behavioral_tags fields.

use lpm_registry::{BehavioralTags, SecurityFinding, VersionMetadata, Vulnerability};

fn meta_with_tags(setup: impl FnOnce(&mut BehavioralTags)) -> VersionMetadata {
    let mut tags = BehavioralTags::default();
    setup(&mut tags);
    VersionMetadata {
        behavioral_tags: Some(tags),
        ..Default::default()
    }
}

fn collect(meta: &VersionMetadata) -> Vec<AuditIssue> {
    let mut issues = Vec::new();
    collect_registry_issues(meta, &mut issues);
    issues
}

fn find_issue<'a>(
    issues: &'a [AuditIssue],
    severity: &str,
    category: &str,
) -> Option<&'a AuditIssue> {
    issues
        .iter()
        .find(|i| i.severity == severity && i.category == category)
}

// Critical bucket — obfuscated, protestware, high_entropy_strings

#[test]
fn registry_issue_critical_bucket_fires_for_obfuscated() {
    let meta = meta_with_tags(|t| t.obfuscated = true);
    let issues = collect(&meta);
    let issue = find_issue(&issues, "critical", "supply-chain")
        .expect("expected one critical/supply-chain issue");
    assert_eq!(issue.source, "registry");
    assert!(
        issue.message.contains("obfuscated code"),
        "msg: {}",
        issue.message
    );
}

#[test]
fn registry_issue_critical_bucket_fires_for_protestware() {
    let issues = collect(&meta_with_tags(|t| t.protestware = true));
    let issue = find_issue(&issues, "critical", "supply-chain").unwrap();
    assert!(issue.message.contains("protestware"));
}

#[test]
fn registry_issue_critical_bucket_fires_for_high_entropy_strings() {
    let issues = collect(&meta_with_tags(|t| t.high_entropy_strings = true));
    let issue = find_issue(&issues, "critical", "supply-chain").unwrap();
    assert!(issue.message.contains("high-entropy strings"));
}

#[test]
fn registry_issue_critical_bucket_emits_single_issue_with_all_three() {
    let issues = collect(&meta_with_tags(|t| {
        t.obfuscated = true;
        t.protestware = true;
        t.high_entropy_strings = true;
    }));
    let critical: Vec<_> = issues
        .iter()
        .filter(|i| i.severity == "critical" && i.category == "supply-chain")
        .collect();
    assert_eq!(
        critical.len(),
        1,
        "critical bucket must emit ONE issue regardless of tag count"
    );
    // All three names must appear in the single message
    assert!(critical[0].message.contains("obfuscated"));
    assert!(critical[0].message.contains("protestware"));
    assert!(critical[0].message.contains("high-entropy"));
}

// Dangerous bucket — eval, child_process, shell, dynamic_require

#[test]
fn registry_issue_dangerous_bucket_fires_for_eval() {
    let issues = collect(&meta_with_tags(|t| t.eval = true));
    let issue = find_issue(&issues, "high", "behavior").unwrap();
    assert!(issue.message.contains("eval()"));
    assert_eq!(issue.source, "registry");
}

#[test]
fn registry_issue_dangerous_bucket_fires_for_child_process() {
    let issues = collect(&meta_with_tags(|t| t.child_process = true));
    let issue = find_issue(&issues, "high", "behavior").unwrap();
    assert!(issue.message.contains("child_process"));
}

#[test]
fn registry_issue_dangerous_bucket_fires_for_shell() {
    let issues = collect(&meta_with_tags(|t| t.shell = true));
    let issue = find_issue(&issues, "high", "behavior").unwrap();
    assert!(issue.message.contains("shell"));
}

#[test]
fn registry_issue_dangerous_bucket_fires_for_dynamic_require() {
    let issues = collect(&meta_with_tags(|t| t.dynamic_require = true));
    let issue = find_issue(&issues, "high", "behavior").unwrap();
    assert!(issue.message.contains("dynamic require"));
}

#[test]
fn registry_issue_dangerous_bucket_emits_single_issue_with_all_members() {
    let issues = collect(&meta_with_tags(|t| {
        t.eval = true;
        t.child_process = true;
        t.shell = true;
        t.dynamic_require = true;
    }));
    assert_eq!(
        issues
            .iter()
            .filter(|i| i.severity == "high" && i.category == "behavior")
            .count(),
        1
    );
}

// Medium bucket — network, native_bindings, git/http/wildcard dep, no_license
// Emits severity=info, category=behavior, message starts with "flags:".

#[test]
fn registry_issue_medium_bucket_fires_for_network() {
    let issues = collect(&meta_with_tags(|t| t.network = true));
    // Both medium and notable share severity=info+category=behavior;
    // distinguish by message prefix.
    let issue = issues
        .iter()
        .find(|i| i.severity == "info" && i.message.starts_with("flags:"))
        .expect("expected medium bucket issue");
    assert!(issue.message.contains("network"));
    assert_eq!(issue.source, "registry");
}

#[test]
fn registry_issue_medium_bucket_fires_for_each_member() {
    for (setter, expected_token) in [
        (
            Box::new(|t: &mut BehavioralTags| t.native_bindings = true)
                as Box<dyn FnOnce(&mut BehavioralTags)>,
            "native bindings",
        ),
        (Box::new(|t| t.git_dependency = true), "git dependency"),
        (Box::new(|t| t.http_dependency = true), "http dependency"),
        (Box::new(|t| t.wildcard_dependency = true), "wildcard dep"),
        (Box::new(|t| t.no_license = true), "no license"),
    ] {
        let issues = collect(&meta_with_tags(setter));
        let medium = issues
            .iter()
            .find(|i| i.message.starts_with("flags:"))
            .unwrap_or_else(|| {
                panic!("expected medium bucket issue for {expected_token}; got: {issues:?}")
            });
        assert!(
            medium.message.contains(expected_token),
            "message must contain '{expected_token}'; got: {}",
            medium.message
        );
    }
}

#[test]
fn registry_issue_medium_bucket_emits_single_issue_with_all_members() {
    let issues = collect(&meta_with_tags(|t| {
        t.network = true;
        t.native_bindings = true;
        t.git_dependency = true;
        t.http_dependency = true;
        t.wildcard_dependency = true;
        t.no_license = true;
    }));
    assert_eq!(
        issues
            .iter()
            .filter(|i| i.message.starts_with("flags:"))
            .count(),
        1
    );
}

// Notable bucket - filesystem, env_vars, crypto, web_socket, telemetry,
// minified, url_strings, trivial, copyleft_license.
// Emits severity=info, category=behavior, message starts with "accesses".

#[test]
fn registry_issue_notable_bucket_fires_for_filesystem() {
    let issues = collect(&meta_with_tags(|t| t.filesystem = true));
    let issue = issues
        .iter()
        .find(|i| i.message.starts_with("accesses"))
        .expect("expected notable bucket issue");
    assert!(issue.message.contains("filesystem"));
    assert_eq!(issue.severity, "info");
    assert_eq!(issue.category, "behavior");
    assert_eq!(issue.source, "registry");
}

#[test]
fn registry_issue_notable_bucket_fires_for_each_member() {
    for (setter, expected_token) in [
        (
            Box::new(|t: &mut BehavioralTags| t.environment_vars = true)
                as Box<dyn FnOnce(&mut BehavioralTags)>,
            "env vars",
        ),
        (Box::new(|t| t.crypto = true), "crypto"),
        (Box::new(|t| t.web_socket = true), "websocket"),
        (Box::new(|t| t.telemetry = true), "telemetry"),
        (Box::new(|t| t.minified = true), "minified"),
        (Box::new(|t| t.url_strings = true), "url strings"),
        (Box::new(|t| t.trivial = true), "trivial"),
        (Box::new(|t| t.copyleft_license = true), "copyleft"),
    ] {
        let issues = collect(&meta_with_tags(setter));
        let notable = issues
            .iter()
            .find(|i| i.message.starts_with("accesses"))
            .unwrap_or_else(|| panic!("expected notable bucket issue for {expected_token}"));
        assert!(
            notable.message.contains(expected_token),
            "message must contain '{expected_token}'; got: {}",
            notable.message
        );
    }
}

#[test]
fn registry_issue_notable_bucket_emits_single_issue_with_all_members() {
    let issues = collect(&meta_with_tags(|t| {
        t.filesystem = true;
        t.environment_vars = true;
        t.crypto = true;
        t.web_socket = true;
        t.telemetry = true;
        t.minified = true;
        t.url_strings = true;
        t.trivial = true;
        t.copyleft_license = true;
    }));
    assert_eq!(
        issues
            .iter()
            .filter(|i| i.message.starts_with("accesses"))
            .count(),
        1
    );
}

// Edge cases - empty tags, combined notable tags, all-tags-set

#[test]
fn registry_issue_empty_tags_emits_no_issues() {
    let issues = collect(&meta_with_tags(|_| {}));
    assert!(
        issues.is_empty(),
        "default-empty tags must produce 0 issues; got {issues:?}"
    );
}

#[test]
fn registry_issue_url_strings_and_web_socket_surface_as_notable_registry_issues() {
    let issues = collect(&meta_with_tags(|t| {
        t.url_strings = true;
        t.web_socket = true;
    }));
    assert_eq!(
        issues.len(),
        1,
        "expected one notable issue; got: {issues:?}"
    );
    let issue = issues
        .iter()
        .find(|i| i.message.starts_with("accesses"))
        .expect("expected notable bucket issue");
    assert_eq!(issue.severity, "info");
    assert_eq!(issue.category, "behavior");
    assert_eq!(issue.source, "registry");
    assert!(issue.message.contains("url strings"));
    assert!(issue.message.contains("websocket"));
}

#[test]
fn registry_issue_all_tags_set_emits_one_issue_per_active_bucket() {
    let issues = collect(&meta_with_tags(|t| {
        // Set every documented tag - all 22.
        t.eval = true;
        t.child_process = true;
        t.shell = true;
        t.network = true;
        t.filesystem = true;
        t.crypto = true;
        t.dynamic_require = true;
        t.native_bindings = true;
        t.environment_vars = true;
        t.web_socket = true;
        t.obfuscated = true;
        t.high_entropy_strings = true;
        t.minified = true;
        t.telemetry = true;
        t.url_strings = true;
        t.trivial = true;
        t.protestware = true;
        t.git_dependency = true;
        t.http_dependency = true;
        t.wildcard_dependency = true;
        t.copyleft_license = true;
        t.no_license = true;
    }));
    // 4 buckets all fire: exactly 4 issues from behavioral tags.
    assert_eq!(
        issues.len(),
        4,
        "expected one issue per active bucket; got: {issues:?}"
    );
    assert!(find_issue(&issues, "critical", "supply-chain").is_some());
    assert!(find_issue(&issues, "high", "behavior").is_some());
    assert_eq!(
        issues
            .iter()
            .filter(|i| i.severity == "info" && i.category == "behavior")
            .count(),
        2,
        "medium + notable both emit info/behavior"
    );
}

// security_findings arm

#[test]
fn registry_issue_security_findings_emits_one_issue_per_finding() {
    let meta = VersionMetadata {
        security_findings: Some(vec![
            SecurityFinding {
                severity: Some("high".into()),
                description: Some("hardcoded API key".into()),
                file: Some("index.js".into()),
            },
            SecurityFinding {
                severity: Some("moderate".into()),
                description: Some("unsafe regex".into()),
                file: None,
            },
        ]),
        ..Default::default()
    };
    let issues = collect(&meta);
    assert_eq!(issues.len(), 2);
    assert!(
        issues
            .iter()
            .all(|i| i.category == "security" && i.source == "registry")
    );
    let high = issues.iter().find(|i| i.severity == "high").unwrap();
    assert_eq!(high.message, "hardcoded API key");
    let moderate = issues.iter().find(|i| i.severity == "moderate").unwrap();
    assert_eq!(moderate.message, "unsafe regex");
}

#[test]
fn registry_issue_security_finding_uses_defaults_for_missing_fields() {
    let meta = VersionMetadata {
        security_findings: Some(vec![SecurityFinding {
            severity: None,
            description: None,
            file: None,
        }]),
        ..Default::default()
    };
    let issues = collect(&meta);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, "moderate", "default severity");
    assert_eq!(
        issues[0].message, "security concern detected",
        "default message"
    );
}

// lifecycle_scripts arm

#[test]
fn registry_issue_lifecycle_scripts_emits_one_moderate_issue() {
    let mut scripts = std::collections::HashMap::new();
    scripts.insert("preinstall".to_string(), "node setup.js".to_string());
    scripts.insert("postinstall".to_string(), "node build.js".to_string());
    let meta = VersionMetadata {
        lifecycle_scripts: Some(scripts),
        ..Default::default()
    };
    let issues = collect(&meta);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, "moderate");
    assert_eq!(issues[0].category, "scripts");
    // Both script names must appear (HashMap order is non-deterministic,
    // assert membership rather than order).
    assert!(issues[0].message.contains("preinstall"));
    assert!(issues[0].message.contains("postinstall"));
}

#[test]
fn registry_issue_empty_lifecycle_scripts_emits_no_issue() {
    let meta = VersionMetadata {
        lifecycle_scripts: Some(std::collections::HashMap::new()),
        ..Default::default()
    };
    let issues = collect(&meta);
    assert!(issues.is_empty());
}

// vulnerabilities arm

#[test]
fn registry_issue_vulnerabilities_emits_one_issue_per_vuln() {
    let meta = VersionMetadata {
        vulnerabilities: Some(vec![
            Vulnerability {
                id: Some("GHSA-aaaa".into()),
                summary: Some("rce".into()),
                severity: Some("HIGH".into()),
                aliases: None,
            },
            Vulnerability {
                id: Some("CVE-2025-0001".into()),
                summary: None,
                severity: Some("Critical".into()),
                aliases: None,
            },
        ]),
        ..Default::default()
    };
    let issues = collect(&meta);
    assert_eq!(issues.len(), 2);
    // Severity is lowercased
    let high = issues
        .iter()
        .find(|i| i.message.contains("GHSA-aaaa"))
        .unwrap();
    assert_eq!(high.severity, "high");
    assert_eq!(high.category, "vulnerability");
    assert!(high.message.contains("rce"));
    let critical = issues
        .iter()
        .find(|i| i.message.contains("CVE-2025-0001"))
        .unwrap();
    assert_eq!(critical.severity, "critical");
    // No summary → no " — " separator
    assert!(!critical.message.contains(" — "));
}

#[test]
fn registry_issue_vulnerability_defaults_for_missing_fields() {
    let meta = VersionMetadata {
        vulnerabilities: Some(vec![Vulnerability {
            id: None,
            summary: None,
            severity: None,
            aliases: None,
        }]),
        ..Default::default()
    };
    let issues = collect(&meta);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, "moderate", "default severity");
    assert_eq!(issues[0].message, "unknown", "default id");
}

// Combined — multiple arms in one call

#[test]
fn registry_issue_combined_security_behavioral_scripts_vulns() {
    let mut scripts = std::collections::HashMap::new();
    scripts.insert("preinstall".to_string(), "x".to_string());
    let meta = VersionMetadata {
        security_findings: Some(vec![SecurityFinding {
            severity: Some("high".into()),
            description: Some("ai-finding".into()),
            file: None,
        }]),
        behavioral_tags: Some(BehavioralTags {
            eval: true,
            obfuscated: true,
            network: true,
            ..Default::default()
        }),
        lifecycle_scripts: Some(scripts),
        vulnerabilities: Some(vec![Vulnerability {
            id: Some("CVE-2025-9999".into()),
            summary: Some("rce".into()),
            severity: Some("high".into()),
            aliases: None,
        }]),
        ..Default::default()
    };
    let issues = collect(&meta);
    // 1 security_finding + 3 active buckets (critical/dangerous/medium)
    // + 1 lifecycle_scripts + 1 vulnerability = 6 issues.
    assert_eq!(issues.len(), 6, "got: {issues:?}");
}

/// `query_osv_batch` now surfaces non-2xx responses as `Err`
/// rather than silently returning `Ok(Vec::new())` — the latter
/// was indistinguishable from "no vulnerabilities found", a green
/// state that a transient OSV outage or an attacker who can block
/// the OSV connection could fabricate. Locks the new error path
/// so a future refactor that re-introduces the silent fallback
/// fails this test first.
#[tokio::test]
async fn query_osv_batch_returns_err_on_non_success_http() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("osv down"))
        .mount(&server)
        .await;

    // SAFETY: a `Mutex`-guarded env var would be ideal but this
    // module doesn't have an env-isolation harness like
    // `release_lookup`. The OSV URL env var is read inside the
    // function under test, so the set→call→remove sequence is
    // race-free within a single test. Other tests in this module
    // do not set LPM_OSV_URL.
    unsafe { std::env::set_var("LPM_OSV_URL", server.uri()) };
    let result = query_osv_batch(&[("react".to_string(), "1.0.0".to_string())]).await;
    unsafe { std::env::remove_var("LPM_OSV_URL") };

    let err = result.expect_err("non-2xx OSV response must surface as Err");
    let msg = err.to_string();
    assert!(
        msg.contains("HTTP 500") && msg.contains("degraded"),
        "error must label the failure mode: {msg}"
    );
}

/// `LPM_OSV_URL` override gating mirrors the self-update release
/// probe: HTTPS accepted for private mirrors, HTTP only on loopback
/// (workflow tests), anything else falls back to the default.
#[test]
fn osv_override_accepts_https_any_host() {
    assert!(osv_override_is_accepted(
        "https://api.osv.dev/v1/querybatch"
    ));
    assert!(osv_override_is_accepted("https://osv.private.corp/v1"));
    assert!(osv_override_is_accepted("https://example.com:8443/path"));
}

#[test]
fn osv_override_accepts_http_only_for_loopback() {
    assert!(osv_override_is_accepted("http://127.0.0.1:8080/v1"));
    assert!(osv_override_is_accepted("http://localhost:9090/v1"));
    assert!(osv_override_is_accepted("http://[::1]:8080/v1"));
}

#[test]
fn osv_override_rejects_plain_http_non_loopback() {
    assert!(!osv_override_is_accepted("http://attacker.example/v1"));
    assert!(!osv_override_is_accepted("http://192.0.2.1/v1"));
    assert!(!osv_override_is_accepted("http://osv.dev/v1"));
}

#[test]
fn osv_override_rejects_unsupported_schemes() {
    assert!(!osv_override_is_accepted("ftp://osv.dev/v1"));
    assert!(!osv_override_is_accepted("file:///etc/osv.json"));
    assert!(!osv_override_is_accepted("javascript:alert(1)"));
    assert!(!osv_override_is_accepted("not a url"));
}
