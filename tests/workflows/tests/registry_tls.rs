//! Workflow tests for `.npmrc` TLS settings on commands that read the LPM
//! registry API without a project install: each one must reach a registry
//! whose certificate only `~/.npmrc`'s `cafile=` makes trustworthy, without
//! loading the TLS files of a registry it doesn't contact.

mod support;

use support::TempProject;
use support::mock_registry::MockRegistry;
use support::tls_front::TlsFront;

#[tokio::test]
async fn registry_api_reads_trust_the_npmrc_cafile_of_the_registry() {
    let project = TempProject::empty(r#"{"name":"registry-tls","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health().await;
    mock.with_whoami("tls-user", "tls-user@example.com").await;
    mock.with_pool_stats(
        "tls-session-token",
        serde_json::json!({
            "billingPeriod": "2026-11",
            "totalWeightedDownloads": 0,
            "estimatedEarningsCents": 0,
            "packages": []
        }),
    )
    .await;
    mock.with_quality_report(
        "owner.widget",
        serde_json::json!({
            "name": "owner.widget",
            "status": "complete",
            "rulesVersion": 1,
            "score": 50,
            "maxScore": 100,
            "tier": "fair",
            "ecosystem": "js",
            "categories": {},
            "checks": []
        }),
    )
    .await;
    mock.with_package_skills(
        "owner.package",
        vec![serde_json::json!({
            "name": "guide",
            "description": "Use package-specific conventions",
            "rawContent": "---\nname: guide\ndescription: Use package-specific conventions\n---\nFollow the package guide.",
            "sizeBytes": 96,
        })],
    )
    .await;
    let front = TlsFront::start(&mock, project.home());
    let unreadable = project.home().join("missing-npm-ca.pem");
    front.write_user_npmrc(
        project.home(),
        &format!("//registry.npmjs.org/:cafile={}\n", unreadable.display()),
    );

    let failures: Vec<String> = [
        &["--json", "health"][..],
        &["--json", "whoami"][..],
        &["--json", "pool"][..],
        &["--json", "quality", "owner.widget"][..],
        &["skills", "add", "@lpm.dev/owner.package", "--yes"][..],
    ]
    .into_iter()
    .filter_map(|args| {
        let output = support::lpm(&project)
            .env("LPM_TOKEN", "tls-session-token")
            .args(["--registry", &front.url])
            .args(args)
            .output()
            .expect("run lpm");
        (!output.status.success()).then(|| {
            format!(
                "lpm {args:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
        })
    })
    .collect();
    assert!(
        failures.is_empty(),
        "every command must reach a registry its .npmrc cafile trusts:\n{}",
        failures.join("\n")
    );
    assert!(project.file_exists(".lpm/skills/owner.package/guide.md"));
}
