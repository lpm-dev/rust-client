//! Human firewall verdict output during package installation.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry, write_npm_firewall_global_config};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

async fn install_with_verdict(
    action: &str,
    mode: &str,
    color: &str,
    packages: &[&str],
) -> std::process::Output {
    let mock = MockRegistry::start().await;
    let mut decisions = Vec::with_capacity(packages.len());
    let blocked = action == "block";
    for name in packages {
        mock.with_package(name, "1.0.0", &make_tarball(name, "1.0.0"))
            .await;
        decisions.push(serde_json::json!({
            "decisionId": name,
            "name": name,
            "version": "1.0.0",
            "action": action,
            "verdict": if blocked { "malicious" } else { "suspicious" },
            "reason": "Local policy reason",
            "matchSource": "package",
            "policyMode": mode,
            "enqueueScan": false,
            "display": {
                "summary": "Package source requires review.",
                "reportUrl": format!("https://firewall.lpm.dev/npm/{name}/v/1.0.0")
            }
        }));
    }
    Mock::given(method("POST"))
        .and(path("/api/registry/-/npm-firewall/verdicts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requestId": "firewall-output",
            "policyMode": mode,
            "summary": {
                "total": packages.len(), "allow": 0,
                "warn": if blocked { 0 } else { packages.len() },
                "block": if blocked { packages.len() } else { 0 },
                "unknown": 0, "matched": packages.len()
            },
            "decisions": decisions
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_npm_firewall_global_config(&project, mode);
    lpm_with_registry(&project, &mock.url())
        .args([
            "--color",
            color,
            "install",
            "--no-skills",
            "--no-editor-setup",
        ])
        .args(packages.iter().map(|name| format!("{name}@1.0.0")))
        .output()
        .unwrap()
}

#[tokio::test]
async fn firewall_block_output_uses_product_name_and_indented_package_marker() {
    let output = install_with_verdict("block", "enforce", "never", &["firewall-output"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("! LPM Firewall blocked 1 package:\n"),
        "{stderr}"
    );
    assert!(
        stderr.contains("  › firewall-output@1.0.0 - block: Package source requires review.\n    report: https://firewall.lpm.dev/npm/firewall-output/v/1.0.0\n"),
        "{stderr}",
    );
    assert!(
        stderr.contains("1 package blocked by LPM Firewall"),
        "{stderr}"
    );
    assert!(
        !stderr.contains('\x1b'),
        "plain output must contain no terminal escapes: {stderr:?}"
    );
}

#[tokio::test]
async fn firewall_warning_output_stays_a_warning_and_allows_installation() {
    let output = install_with_verdict("warn", "enforce", "never", &["firewall-output"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("! LPM Firewall warned for 1 package:\n"),
        "{stderr}"
    );
    assert!(
        stderr.contains("  › firewall-output@1.0.0 - warn: Package source requires review."),
        "{stderr}"
    );
    assert!(
        stderr.contains("report: https://firewall.lpm.dev/npm/firewall-output/v/1.0.0"),
        "{stderr}"
    );
    assert!(!stderr.contains("LPM Firewall blocked"), "{stderr}");
}

#[tokio::test]
async fn firewall_package_and_action_colors_follow_the_verdict() {
    for (action, color) in [("block", 31), ("warn", 33)] {
        let output = install_with_verdict(action, "enforce", "always", &["firewall-output"]).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.success(), action == "warn", "{stderr}");
        assert!(
            stderr.contains(&format!("\x1b[{color}mfirewall-output@1.0.0\x1b[39m")),
            "{stderr:?}"
        );
        assert!(
            stderr.contains(&format!("\x1b[{color}m{action}\x1b[39m")),
            "{stderr:?}"
        );
        assert!(
            !stderr.contains("\x1b]8;"),
            "piped output must retain a visible URL without hyperlink escapes: {stderr:?}"
        );
    }
}

#[tokio::test]
async fn firewall_monitor_output_reports_would_block_and_continues() {
    let output = install_with_verdict("block", "monitor", "never", &["firewall-output"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("! LPM Firewall monitor: 1 would-block, 0 warned; command continues because monitor mode is active."), "{stderr}");
    assert!(
        stderr.contains("  › firewall-output@1.0.0 - block: Package source requires review."),
        "{stderr}"
    );
    assert!(!stderr.contains("LPM Firewall blocked"), "{stderr}");
}

#[tokio::test]
async fn firewall_headings_use_plural_packages_for_multiple_verdicts() {
    for (action, heading) in [("block", "blocked"), ("warn", "warned for")] {
        let output = install_with_verdict(
            action,
            "enforce",
            "never",
            &["firewall-output", "firewall-output-extra"],
        )
        .await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.success(), action == "warn", "{stderr}");
        assert!(
            stderr.contains(&format!("! LPM Firewall {heading} 2 packages:")),
            "{stderr}"
        );
        for name in ["firewall-output", "firewall-output-extra"] {
            assert!(
                stderr.contains(&format!("  › {name}@1.0.0 - {action}:")),
                "{stderr}"
            );
        }
        if action == "block" {
            assert!(
                stderr.contains("2 packages blocked by LPM Firewall"),
                "{stderr}"
            );
        }
    }
}

#[tokio::test]
async fn firewall_monitor_continues_after_oidc_exchange_failure_but_enforce_stops() {
    for status in [401, 503] {
        for mode in ["monitor", "enforce"] {
            let mock = MockRegistry::start().await;
            mock.with_package(
                "firewall-oidc",
                "1.0.0",
                &make_tarball("firewall-oidc", "1.0.0"),
            )
            .await;
            Mock::given(method("POST"))
                .and(path("/api/registry/-/token/oidc"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(serde_json::json!({
                        "error": "OIDC exchange unavailable"
                    })),
                )
                .expect(1)
                .mount(mock.server())
                .await;
            let project =
                TempProject::empty(r#"{"name":"firewall-oidc-consumer","version":"1.0.0"}"#);
            write_npm_firewall_global_config(&project, mode);
            let output = lpm_with_registry(&project, &mock.url())
                .env("LPM_OIDC_TOKEN", "unusable-ci-assertion")
                .args([
                    "install",
                    "firewall-oidc@1.0.0",
                    "--no-skills",
                    "--no-editor-setup",
                ])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                output.status.success(),
                mode == "monitor",
                "{mode}/{status}: {stderr}"
            );
            assert_eq!(
                project
                    .path()
                    .join("node_modules/firewall-oidc/package.json")
                    .is_file(),
                mode == "monitor",
                "{mode}/{status}: {stderr}",
            );
            assert!(stderr.contains("OIDC"), "{stderr}");
        }
    }
}
