mod support;

use support::assertions::parse_json_output;
use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn whoami_human_output_uses_slim_logged_out_guidance() {
    let project = TempProject::empty(r#"{"name":"whoami","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let output = lpm_with_registry(&project, &mock.url())
        .arg("whoami")
        .output()
        .expect("failed to run lpm whoami");

    assert!(
        output.status.success(),
        "logged-out whoami must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human whoami should not write to stdout when logged out, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("› Not logged in to {}.", mock.url())),
        "logged-out whoami should use the slim guidance line, got:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "› Run `lpm login --registry {}` to authenticate.",
            mock.url()
        )),
        "logged-out whoami should keep the registry-specific login hint, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from whoami stderr, got:\n{stderr}"
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "logged-out human whoami should not hit the network, got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn whoami_human_output_uses_slim_account_summary() {
    let project = TempProject::empty(r#"{"name":"whoami","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", "Bearer access-primary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "testuser",
            "email": "test@example.com",
            "plan_tier": "pro",
            "mfa_enabled": false,
            "has_pool_access": true,
            "usage": {
                "storage_bytes": 1024 * 1024 * 512 + 1024 * 100,
                "private_packages": 3
            },
            "limits": {
                "storageBytes": 1024_u64 * 1024 * 1024 * 5,
                "privatePackages": 100
            },
            "organizations": [
                {
                    "slug": "acme",
                    "name": "Acme",
                    "role": "admin"
                }
            ]
        })))
        .mount(mock.server())
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-primary"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("whoami")
        .output()
        .expect("failed to run authenticated lpm whoami");

    assert!(
        output.status.success(),
        "authenticated whoami must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human whoami should not write to stdout when authenticated, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("username       testuser")
            && stderr.contains("email          t...t@example.com")
            && !stderr.contains("email          test@example.com")
            && !stderr.contains("Logged in as"),
        "authenticated whoami should render aligned username and masked email details, got:\n{stderr}"
    );
    assert!(
        stderr.contains("plan           Pro"),
        "authenticated whoami should show the plan as an aligned detail row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("pool access    yes"),
        "authenticated whoami should show pool access as an aligned detail row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("mfa            no"),
        "authenticated whoami should show MFA status as an aligned detail row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("secure storage backend: encrypted file fallback"),
        "authenticated whoami should show the active secure storage backend, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Encrypted file fallback is active"),
        "authenticated whoami should warn when auth storage uses the encrypted file fallback, got:\n{stderr}"
    );
    assert!(
        stderr.contains("usage")
            && stderr.contains("storage        512.09 MiB / 5 GiB  ██░░░░░░░░"),
        "authenticated whoami should show storage usage with a quota bar, got:\n{stderr}"
    );
    assert!(
        stderr.contains("private pkgs   3 / 100  █░░░░░░░░░"),
        "authenticated whoami should show package usage with a quota bar, got:\n{stderr}"
    );
    assert!(
        stderr.contains("scopes"),
        "authenticated whoami should show the scopes section, got:\n{stderr}"
    );
    assert!(
        stderr.contains("@lpm.dev/testuser.*"),
        "authenticated whoami should list the personal scope, got:\n{stderr}"
    );
    assert!(
        stderr.contains("@lpm.dev/acme.*  admin "),
        "authenticated whoami should render admin as a padded badge label, got:\n{stderr}"
    );
    assert!(
        stderr.contains("registries") && stderr.contains("● lpm.dev authenticated"),
        "authenticated whoami should include lpm.dev in the human registries list, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Identity loaded"),
        "authenticated whoami should finish with the identity-loaded terminus, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("(admin)"),
        "authenticated whoami should not render the admin role as the old parenthesized label, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from whoami stderr, got:\n{stderr}"
    );

    let colored_output = lpm_with_registry(&project, &mock.url())
        .arg("whoami")
        .env_remove("NO_COLOR")
        .env("FORCE_COLOR", "1")
        .output()
        .expect("failed to run color-forced lpm whoami");
    assert!(
        colored_output.status.success(),
        "color-forced whoami must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&colored_output.stdout),
        String::from_utf8_lossy(&colored_output.stderr),
    );
    let colored_stderr = String::from_utf8_lossy(&colored_output.stderr);
    assert!(
        colored_stderr.contains("\u{1b}[1;33;48;5;236m admin \u{1b}[0m"),
        "color-forced whoami should render admin with a badge background, got:\n{colored_stderr:?}"
    );
}

/// Human `lpm whoami` stderr for an account the registry describes as
/// `account`.
async fn whoami_stderr(account: serde_json::Value) -> String {
    let project = TempProject::empty(r#"{"name":"whoami","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", "Bearer access-primary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(account))
        .mount(mock.server())
        .await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-primary"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("whoami")
        .output()
        .expect("failed to run lpm whoami");
    assert!(
        output.status.success(),
        "whoami must exit 0, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const GIB: u64 = 1024 * 1024 * 1024;

#[tokio::test]
async fn whoami_tells_a_pro_account_past_its_storage_that_it_is_billed_not_restricted() {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 5 * GIB + 51 * 1024 * 1024, "private_packages": 3 },
        "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
        "storage_overage": "billed",
    }))
    .await;

    assert!(
        stderr.contains("storage        5.05 GiB / 5 GiB")
            && stderr.contains(
                "overage        storage past 5 GiB is billed per GiB a month, rounded up"
            ),
        "a Pro account past its storage should read as past it and billed, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("OVER LIMIT")
            && !stderr.contains("restricted")
            && !stderr.contains("Upgrade"),
        "a Pro account's billed storage must not read as restricted, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_tells_a_pro_account_at_its_storage_that_the_next_publish_is_billed() {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 5 * GIB, "private_packages": 3 },
        "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
        "storage_overage": "billed",
    }))
    .await;

    assert!(
        stderr.contains("storage        5 GiB / 5 GiB")
            && stderr.contains(
                "overage        storage past 5 GiB is billed per GiB a month, rounded up"
            ),
        "a Pro account at its storage should be told what past it costs, got:\n{stderr}"
    );
    let below = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 5 * GIB - 1, "private_packages": 3 },
        "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
        "storage_overage": "billed",
    }))
    .await;
    assert!(!below.contains("overage "), "{below}");
}

#[tokio::test]
async fn whoami_says_whether_storage_already_past_the_limit_is_billed_while_billing_isnt_active() {
    for (billed, said) in [
        (
            serde_json::json!(true),
            Some("Storage already past it is still billed while the payment is retried."),
        ),
        (
            serde_json::json!(false),
            Some("Storage already past it isn't billed meanwhile."),
        ),
        (serde_json::Value::Null, None),
    ] {
        let stderr = whoami_stderr(serde_json::json!({
            "username": "testuser",
            "plan_tier": "pro",
            "usage": { "storage_bytes": 5 * GIB + 1, "private_packages": 3 },
            "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
            "storage_overage": "paused",
            "storage_excess_billed": billed,
        }))
        .await;

        match said {
            Some(said) => assert!(stderr.contains(said), "{billed}: {stderr}"),
            None => assert!(!stderr.contains("Storage already past it"), "{stderr}"),
        }
    }

    // At the limit, nothing is past it yet, but the next publish is refused.
    let at = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 5 * GIB, "private_packages": 3 },
        "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
        "storage_overage": "paused",
        "storage_excess_billed": true,
    }))
    .await;
    assert!(
        at.contains("Publishing past 5 GiB is refused until billing is active again.")
            && !at.contains("Storage already past it"),
        "{at}"
    );
}

#[tokio::test]
async fn whoami_tells_a_pro_account_without_a_subscription_at_its_storage_that_past_it_is_refused()
{
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 5 * GIB, "private_packages": 3 },
        "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
        "storage_overage": "blocked",
    }))
    .await;

    assert!(
        stderr.contains(
            "Storage past 5 GiB isn't billed on this plan, so publishing to your personal scope past it is refused."
        ) && !stderr.contains("OVER LIMIT"),
        "{stderr}"
    );
}

#[tokio::test]
async fn whoami_tells_a_free_account_past_its_storage_that_publishing_is_restricted() {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "free",
        "usage": { "storage_bytes": 100 * 1024 * 1024 + 1, "private_packages": 1 },
        "limits": { "storageBytes": 100 * 1024 * 1024, "privatePackages": 2 },
        "storage_overage": "blocked",
    }))
    .await;

    assert!(
        stderr.contains("Storage: 100.01 MiB / 100 MiB")
            && stderr.contains("(OVER LIMIT)")
            && stderr.contains(
                "Publishing to your personal scope is refused while its storage is at or past 100 MiB."
            ),
        "a free account past its storage should read as over its limit and refused, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("New private packages"),
        "an account within its private packages is told nothing of them, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("inviting members"),
        "a personal account invites no members, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Hobby") && !stderr.contains("Free") && !stderr.contains("exempt"),
        "the free plan reads as Hobby, and storage nothing exempts shows no exempt line, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_reads_a_free_account_s_storage_as_its_limit_counts_it() {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "free",
        "usage": {
            "storage_bytes": 150 * 1024 * 1024,
            "counted_storage_bytes": 50 * 1024 * 1024,
            "private_packages": 1,
        },
        "limits": { "storageBytes": 100 * 1024 * 1024, "privatePackages": 2 },
        "storage_overage": "blocked",
    }))
    .await;

    assert!(
        stderr.contains("storage        50 MiB / 100 MiB")
            && stderr.contains(
                "exempt         100 MiB more, the tarballs of packages whose sales exempt them"
            ),
        "storage the limit doesn't count should read apart from it, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("OVER LIMIT") && !stderr.contains("refused"),
        "exempt storage takes no account past its limit, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_tells_an_account_past_its_private_packages_that_only_new_ones_are_refused() {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "free",
        "usage": { "storage_bytes": 1024, "private_packages": 3 },
        "limits": { "storageBytes": 100 * 1024 * 1024, "privatePackages": 2 },
        "storage_overage": "blocked",
    }))
    .await;

    assert!(
        stderr.contains("Private Packages: 3 / 2")
            && stderr.contains(
                "New private packages in your personal scope are refused once it holds 2."
            ),
        "an account past its private packages should read as refusing new ones, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Publishing to your personal scope is refused"),
        "storage within its limit refuses nothing, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_tells_an_account_whose_billing_isnt_active_that_publishing_past_its_storage_waits_for_it()
 {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 5 * GIB + 1, "private_packages": 3 },
        "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
        "storage_overage": "paused",
    }))
    .await;

    assert!(
        stderr.contains("Storage: 5.01 GiB / 5 GiB")
            && stderr.contains("Publishing past 5 GiB is refused until billing is active again.")
            && stderr.contains("Manage billing"),
        "an account whose billing isn't active should read as refused until it is, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("payment") && !stderr.contains("overage is paused"),
        "a subscription that ended in its grace owes no payment, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("is billed per GiB") && !stderr.contains("Upgrade your plan"),
        "publishing past storage that waits for billing is neither billed nor an upgrade's to fix, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_claims_nothing_of_storage_past_its_limit_when_the_registry_doesnt_say() {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 5 * GIB + 1, "private_packages": 3 },
        "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
    }))
    .await;

    assert!(
        stderr.contains("storage        5.01 GiB / 5 GiB")
            && stderr.contains("limit          past the 5 GiB limit"),
        "storage past its limit should read as past it, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("billed")
            && !stderr.contains("overage")
            && !stderr.contains("included")
            && !stderr.contains("OVER LIMIT")
            && !stderr.contains("restricted"),
        "without the Registry's word, whoami should claim neither billing nor a refusal, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_tells_a_free_account_past_its_storage_that_publishing_is_restricted_when_the_registry_doesnt_say()
 {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "free",
        "usage": { "storage_bytes": 100 * 1024 * 1024 + 1, "private_packages": 1 },
        "limits": { "storageBytes": 100 * 1024 * 1024, "privatePackages": 2 },
    }))
    .await;

    assert!(
        stderr.contains("Storage: 100.01 MiB / 100 MiB")
            && stderr.contains("(OVER LIMIT)")
            && stderr.contains(
                "Publishing to your personal scope is refused while its storage is at or past 100 MiB."
            ),
        "every Registry refuses the free plan's storage past its limit, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_tells_a_pro_account_without_a_subscription_that_its_storage_past_the_limit_isnt_billed()
 {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 5 * GIB + 1, "private_packages": 3 },
        "limits": { "storageBytes": 5 * GIB, "privatePackages": 100 },
        "storage_overage": "blocked",
    }))
    .await;

    assert!(
        stderr.contains("Storage: 5.01 GiB / 5 GiB")
            && stderr.contains("(OVER LIMIT)")
            && stderr.contains(
                "Storage past 5 GiB isn't billed on this plan, so publishing to your personal scope past it is refused."
            ),
        "a Pro account without a subscription should read as refused past its storage, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Upgrade your plan") && !stderr.contains("Subscribe"),
        "an account on Pro without a subscription can neither upgrade nor take one out, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_tells_an_account_at_its_private_packages_that_new_ones_are_refused() {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "free",
        "usage": { "storage_bytes": 1024, "private_packages": 2 },
        "limits": { "storageBytes": 100 * 1024 * 1024, "privatePackages": 2 },
        "storage_overage": "blocked",
    }))
    .await;

    assert!(
        stderr.contains("private pkgs   2 / 2")
            && stderr.contains(
                "New private packages in your personal scope are refused once it holds 2."
            )
            && stderr.contains("Upgrade your plan"),
        "an account at its private packages should read as refusing new ones, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("OVER LIMIT") && !stderr.contains("over its plan limits"),
        "an account at its limit isn't over it, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_reads_storage_at_its_limit_as_within_it() {
    let stderr = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "free",
        "usage": { "storage_bytes": 100 * 1024 * 1024, "private_packages": 1 },
        "limits": { "storageBytes": 100 * 1024 * 1024, "privatePackages": 2 },
        "storage_overage": "blocked",
    }))
    .await;

    assert!(
        stderr.contains("storage        100 MiB / 100 MiB"),
        "storage at its limit should read as within it, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("OVER LIMIT")
            && !stderr.contains("restricted")
            && !stderr.contains("over its plan limits"),
        "storage at its limit isn't past it, got:\n{stderr}"
    );
    // But any publish would take it past.
    assert!(
        stderr.contains(
            "Publishing to your personal scope is refused while its storage is at or past 100 MiB."
        ),
        "storage at its limit refuses the next publish, got:\n{stderr}"
    );
}

#[tokio::test]
async fn whoami_shows_storage_alone_without_a_storage_limit() {
    let with_other_limits = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 3 * GIB + GIB / 2, "private_packages": 3 },
        "limits": { "privatePackages": 100 },
    }))
    .await;
    let without_limits = whoami_stderr(serde_json::json!({
        "username": "testuser",
        "plan_tier": "pro",
        "usage": { "storage_bytes": 3 * GIB + GIB / 2, "private_packages": 3 },
    }))
    .await;

    for stderr in [with_other_limits, without_limits] {
        assert!(
            stderr.contains("storage        3.5 GiB") && !stderr.contains("3.5 GiB /"),
            "storage without a limit should read as its size alone, got:\n{stderr}"
        );
    }
}

#[tokio::test]
async fn whoami_json_reports_file_backed_auth_storage_backend() {
    let project = TempProject::empty(r#"{"name":"whoami","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", "Bearer access-primary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "test@example.com",
            "profile_username": "testuser",
            "email": "test@example.com",
            "storage_overage": "paused",
            "storage_excess_billed": false,
            "usage": {
                "storage_bytes": 150 * 1024 * 1024,
                "counted_storage_bytes": 50 * 1024 * 1024,
                "private_packages": 1,
            },
        })))
        .mount(mock.server())
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-primary"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run lpm whoami --json");

    assert!(
        output.status.success(),
        "authenticated whoami --json must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(
        json["storage_backend"],
        serde_json::json!("encrypted_file_fallback")
    );
    assert_eq!(json["storage_degraded"], serde_json::json!(true));
    assert_eq!(json["storage_overage"], serde_json::json!("paused"));
    assert_eq!(json["storage_excess_billed"], serde_json::json!(false));
    assert_eq!(
        json["usage"]["counted_storage_bytes"],
        serde_json::json!(50 * 1024 * 1024)
    );
    assert_eq!(
        json["registries"][0]["storage_backend"],
        serde_json::json!("encrypted_file_fallback")
    );
    assert_eq!(
        json["registries"][0]["storage_degraded"],
        serde_json::json!(true)
    );
}
