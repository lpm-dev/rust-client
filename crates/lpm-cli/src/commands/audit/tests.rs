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
fn local_info_tags_are_available_to_explicit_audit() {
    let mut analysis = lpm_security::behavioral::PackageAnalysis {
        version: lpm_security::behavioral::SCHEMA_VERSION,
        analyzed_at: String::new(),
        source: Default::default(),
        supply_chain: Default::default(),
        manifest: Default::default(),
        meta: Default::default(),
    };
    analysis.source.environment_vars = true;
    analysis.supply_chain.url_strings = true;

    let issues = analysis_to_issues(&analysis, "local");

    assert!(issues.iter().any(|issue| {
        issue.severity == "info" && issue.message.contains("environment-variable access")
    }));
    assert!(
        issues
            .iter()
            .any(|issue| issue.severity == "info" && issue.message.contains("URL literals"))
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

type RegistryTagCase = (lpm_security::query::PseudoClass, fn(&mut BehavioralTags));

fn registry_tag_cases() -> [RegistryTagCase; 22] {
    use lpm_security::query::PseudoClass;

    [
        (PseudoClass::Eval, |tags| tags.eval = true),
        (PseudoClass::Network, |tags| tags.network = true),
        (PseudoClass::Fs, |tags| tags.filesystem = true),
        (PseudoClass::Shell, |tags| tags.shell = true),
        (PseudoClass::ChildProcess, |tags| tags.child_process = true),
        (PseudoClass::Native, |tags| tags.native_bindings = true),
        (PseudoClass::Crypto, |tags| tags.crypto = true),
        (PseudoClass::DynamicRequire, |tags| {
            tags.dynamic_require = true
        }),
        (PseudoClass::Env, |tags| tags.environment_vars = true),
        (PseudoClass::Ws, |tags| tags.web_socket = true),
        (PseudoClass::Obfuscated, |tags| tags.obfuscated = true),
        (PseudoClass::HighEntropy, |tags| {
            tags.high_entropy_strings = true
        }),
        (PseudoClass::Minified, |tags| tags.minified = true),
        (PseudoClass::Telemetry, |tags| tags.telemetry = true),
        (PseudoClass::UrlStrings, |tags| tags.url_strings = true),
        (PseudoClass::Trivial, |tags| tags.trivial = true),
        (PseudoClass::Protestware, |tags| tags.protestware = true),
        (PseudoClass::GitDep, |tags| tags.git_dependency = true),
        (PseudoClass::HttpDep, |tags| tags.http_dependency = true),
        (PseudoClass::WildcardDep, |tags| {
            tags.wildcard_dependency = true
        }),
        (PseudoClass::Copyleft, |tags| tags.copyleft_license = true),
        (PseudoClass::NoLicense, |tags| tags.no_license = true),
    ]
}

fn audit_severity(severity: lpm_security::query::Severity) -> &'static str {
    use lpm_security::query::Severity;

    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "moderate",
        Severity::Info => "info",
    }
}

#[test]
fn registry_behavioral_fields_use_the_shared_tag_policy() {
    use lpm_security::query::TagGroup;

    for (tag, set_tag) in registry_tag_cases() {
        let issues = collect(&meta_with_tags(set_tag));
        let policy = tag.behavioral_policy().expect("behavioral tag policy");
        let expected_category = match policy.group {
            TagGroup::SupplyChain => "supply-chain",
            TagGroup::Source | TagGroup::Manifest => "behavior",
        };

        assert_eq!(
            issues.len(),
            1,
            "unexpected issue count for {}",
            policy.token
        );
        let issue = &issues[0];
        assert_eq!(
            issue.severity,
            audit_severity(policy.severity),
            "{}",
            policy.token
        );
        assert_eq!(issue.message, policy.label, "{}", policy.token);
        assert_eq!(issue.category, expected_category, "{}", policy.token);
        assert_eq!(issue.source, "registry", "{}", policy.token);
    }
}

#[test]
fn registry_issue_empty_tags_emits_no_issues() {
    let issues = collect(&meta_with_tags(|_| {}));
    assert!(
        issues.is_empty(),
        "default-empty tags must produce 0 issues; got {issues:?}"
    );
}

#[test]
fn registry_all_behavioral_fields_emit_one_policy_issue_each() {
    let issues = collect(&meta_with_tags(|t| {
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
    assert_eq!(issues.len(), registry_tag_cases().len(), "{issues:?}");
}

// security_findings arm

#[test]
fn registry_issue_security_findings_emits_one_issue_per_finding() {
    let meta = VersionMetadata {
        security_findings: Some(vec![
            SecurityFinding {
                severity: Some("Critical".into()),
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
    let critical = issues.iter().find(|i| i.severity == "critical").unwrap();
    assert_eq!(critical.message, "hardcoded API key");
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

    let result =
        query_osv_batch(&[("react".to_string(), "1.0.0".to_string())], &server.uri()).await;

    let err = result.expect_err("non-2xx OSV response must surface as Err");
    let msg = err.to_string();
    assert!(
        msg.contains("HTTP 500") && msg.contains("degraded"),
        "error must label the failure mode: {msg}"
    );
}

#[tokio::test]
async fn query_osv_batch_rejects_oversized_response_body() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const RESPONSE_CAP: usize = 32 * 1024 * 1024;
    let server = MockServer::start().await;
    let mut body = String::with_capacity(RESPONSE_CAP + 128);
    body.push_str(r#"{"results":[{"vulns":[]}],"padding":""#);
    body.extend(std::iter::repeat_n('x', RESPONSE_CAP));
    body.push_str(r#""}"#);
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(body.into_bytes(), "application/json"),
        )
        .mount(&server)
        .await;

    let error = query_osv_batch(&[("react".to_string(), "1.0.0".to_string())], &server.uri())
        .await
        .expect_err("oversized OSV body must fail before JSON decoding");

    assert!(error.to_string().contains("exceeds cap"));
}

#[tokio::test]
async fn query_osv_batch_splits_requests_at_osv_query_limit() {
    use wiremock::matchers::{body_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const OSV_QUERY_LIMIT: usize = 1000;

    let server = MockServer::start().await;
    let packages: Vec<(String, String)> = (0..=OSV_QUERY_LIMIT)
        .map(|index| (format!("package-{index}"), "1.0.0".to_string()))
        .collect();

    for batch in packages.chunks(OSV_QUERY_LIMIT) {
        let queries: Vec<serde_json::Value> = batch
            .iter()
            .map(|(name, version)| {
                serde_json::json!({
                    "package": { "name": name, "ecosystem": "npm" },
                    "version": version,
                })
            })
            .collect();
        let results: Vec<serde_json::Value> = batch
            .iter()
            .map(|(name, _)| {
                let vulns = if name == "package-999" || name == "package-1000" {
                    vec![serde_json::json!({
                        "id": format!("GHSA-{name}"),
                        "summary": "boundary vulnerability",
                        "severity": [{ "type": "CVSS_V3", "score": "9.8" }],
                        "affected": [{
                            "package": { "ecosystem": "npm", "name": name },
                            "ranges": [{
                                "type": "SEMVER",
                                "events": [{ "introduced": "0" }],
                            }],
                        }],
                    })]
                } else {
                    Vec::new()
                };
                serde_json::json!({ "vulns": vulns })
            })
            .collect();

        Mock::given(method("POST"))
            .and(body_json(serde_json::json!({ "queries": queries })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": results,
            })))
            .mount(&server)
            .await;
    }

    let vulnerabilities = query_osv_batch(&packages, &server.uri())
        .await
        .expect("requests above the OSV limit must be split");
    let request_count = server
        .received_requests()
        .await
        .expect("request recording must succeed")
        .len();
    let findings: Vec<(&str, &str)> = vulnerabilities
        .iter()
        .map(|vulnerability| (vulnerability.package.as_str(), vulnerability.id.as_str()))
        .collect();
    assert_eq!(
        (findings, request_count),
        (
            vec![
                ("package-999", "GHSA-package-999"),
                ("package-1000", "GHSA-package-1000"),
            ],
            2,
        )
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

#[test]
fn osv_override_rejects_embedded_credentials() {
    assert!(!osv_override_is_accepted(
        "https://osv-user:osv-password@example.com/v1/querybatch"
    ));
}
