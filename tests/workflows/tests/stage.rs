mod support;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use flate2::read::GzDecoder;
use std::io::Read;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const STAGE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const NPM_TOKEN: &str = "stage-token";
const NPM_ID_TOKEN: &str = "stage-oidc-id-token";
const OIDC_NPM_TOKEN: &str = "stage-oidc-exchanged-token";
const CUSTOM_STAGE_TOKEN: &str = "stage-custom-registry-token";

#[tokio::test]
async fn stage_publish_posts_rewritten_payload_to_npm_stage_endpoint() {
    let mock = MockRegistry::start().await;
    mount_package_metadata(&mock, "@scope/staged-pkg", serde_json::json!({"0.9.0": {}})).await;
    mount_stage_publish(&mock, "@scope/staged-pkg").await;
    let project = stage_project();

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "--json",
            "stage",
            "publish",
            "--yes",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage publish --json");

    assert!(
        output.status.success(),
        "stage publish must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json(&output.stdout);
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["stageId"], serde_json::json!(STAGE_ID));

    insta::with_settings!({ filters => stage_json_filters() }, {
        insta::assert_json_snapshot!("stage_publish_json_envelope", envelope);
    });

    let payload = recorded_stage_publish_payload(&mock).await;
    assert_eq!(payload["_id"], serde_json::json!("@scope/staged-pkg"));
    assert_eq!(
        payload["versions"]["1.0.0"]["name"],
        serde_json::json!("@scope/staged-pkg")
    );

    let attachment = payload["_attachments"]
        .as_object()
        .and_then(|attachments| attachments.values().next())
        .expect("stage payload must contain tarball attachment");
    let tarball = BASE64
        .decode(
            attachment["data"]
                .as_str()
                .expect("tarball data must be base64"),
        )
        .expect("tarball data must decode");
    let manifest = extract_package_json(&tarball);
    assert_eq!(manifest["name"], serde_json::json!("@scope/staged-pkg"));
}

#[tokio::test]
async fn stage_publish_human_output_uses_slim_upload_transcript() {
    let mock = MockRegistry::start().await;
    mount_package_metadata(&mock, "@scope/staged-pkg", serde_json::json!({"0.9.0": {}})).await;
    mount_stage_publish(&mock, "@scope/staged-pkg").await;
    let project = stage_project();

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args(["stage", "publish", "--yes", "--npm-registry", &mock.url()])
        .output()
        .expect("failed to run lpm stage publish");

    assert!(
        output.status.success(),
        "stage publish must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.trim().is_empty(),
        "stage publish human status must stay off stdout, got:\n{stdout}"
    );
    assert!(
        stderr.contains("✓ Secret scan passed")
            && stderr.contains("✓ Quality score:")
            && stderr.contains("› Staging @scope/staged-pkg@1.0.0 to npm")
            && stderr.contains("✓ Done · staged @scope/staged-pkg@1.0.0 with id 123e4567-e89b-12d3-a456-426614174000 in"),
        "stage publish human output should use the slim contract, got:\n{stderr}"
    );
}

#[tokio::test]
async fn stage_publish_uses_npm_trusted_publishing_token_exchange() {
    let mock = MockRegistry::start().await;
    mount_npm_oidc_exchange(&mock, "@scope/staged-pkg").await;
    mount_package_metadata_with_token(
        &mock,
        "@scope/staged-pkg",
        serde_json::json!({"0.9.0": {}}),
        OIDC_NPM_TOKEN,
    )
    .await;
    mount_stage_publish_with_token(&mock, "@scope/staged-pkg", OIDC_NPM_TOKEN).await;
    let project = stage_project();

    let output = lpm(&project)
        .env("NPM_ID_TOKEN", NPM_ID_TOKEN)
        .args([
            "--json",
            "stage",
            "publish",
            "--yes",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage publish with npm OIDC");

    assert!(
        output.status.success(),
        "stage publish must succeed with npm Trusted Publishing\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json(&output.stdout);
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["auth"], serde_json::json!("oidc"));
    assert_eq!(envelope["stageId"], serde_json::json!(STAGE_ID));

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let exchange = requests
        .iter()
        .find(|request| request.url.path().contains("/oidc/token/exchange/package/"))
        .expect("OIDC exchange request must be recorded");
    assert_eq!(
        exchange
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(format!("Bearer {NPM_ID_TOKEN}").as_str()),
    );

    let upload = requests
        .iter()
        .find(|request| {
            request.method.as_str() == "POST" && request.url.path().contains("/-/stage/package/")
        })
        .expect("stage publish upload must be recorded");
    assert_eq!(
        upload
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(format!("Bearer {OIDC_NPM_TOKEN}").as_str()),
    );
}

#[tokio::test]
async fn stage_publish_provenance_restricted_access_fails_before_oidc_exchange() {
    let mock = MockRegistry::start().await;
    let project = stage_project();
    project.write_file(
        "lpm.json",
        r#"{"publish":{"npm":{"name":"@scope/staged-pkg","access":"restricted"}}}"#,
    );

    let output = lpm(&project)
        .env("NPM_ID_TOKEN", NPM_ID_TOKEN)
        .args([
            "stage",
            "publish",
            "--yes",
            "--provenance",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage publish --provenance");

    assert!(
        !output.status.success(),
        "restricted stage provenance must fail before npm auth"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm provenance requires public access")
            && stderr.contains("@scope/staged-pkg"),
        "expected public-access provenance error, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "restricted stage provenance precondition must fail before npm registry contact; got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn stage_publish_dry_run_provenance_restricted_access_fails_before_registry_contact() {
    let mock = MockRegistry::start().await;
    let project = stage_project();
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"name":"@scope/staged-pkg","registry":"{}","access":"restricted"}}}}}}"#,
            mock.url()
        ),
    );

    let output = lpm(&project)
        .args(["stage", "publish", "--dry-run", "--provenance", "--yes"])
        .output()
        .expect("failed to run lpm stage publish --dry-run --provenance");

    assert!(
        !output.status.success(),
        "restricted stage provenance must fail even during dry-run"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm provenance requires public access"),
        "expected public-access provenance error, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "dry-run restricted provenance must fail before registry contact; got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn stage_publish_provenance_file_invalid_json_fails_before_npm_auth() {
    let mock = MockRegistry::start().await;
    let project = stage_project();
    project.write_file("bundle.sigstore", "not json");
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"name":"@scope/staged-pkg","registry":"{}"}}}}}}"#,
            mock.url()
        ),
    );

    let output = lpm(&project)
        .env("NPM_ID_TOKEN", NPM_ID_TOKEN)
        .args([
            "stage",
            "publish",
            "--provenance-file",
            "bundle.sigstore",
            "--yes",
        ])
        .output()
        .expect("failed to run lpm stage publish --provenance-file");

    assert!(
        !output.status.success(),
        "invalid stage provenance file must fail before npm auth"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid provenance file"),
        "expected provenance file parse error, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "invalid stage provenance file must fail before npm registry contact; got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn stage_publish_provenance_file_restricted_access_fails_before_file_validation() {
    let mock = MockRegistry::start().await;
    let project = stage_project();
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"name":"@scope/staged-pkg","registry":"{}","access":"restricted"}}}}}}"#,
            mock.url()
        ),
    );

    let output = lpm(&project)
        .args([
            "stage",
            "publish",
            "--provenance-file",
            "missing.sigstore",
            "--yes",
        ])
        .output()
        .expect("failed to run lpm stage publish --provenance-file");

    assert!(
        !output.status.success(),
        "restricted stage file provenance must fail before npm auth"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm provenance requires public access")
            && stderr.contains("@scope/staged-pkg"),
        "expected public-access provenance error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("missing.sigstore"),
        "restricted access must fail before file validation, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "restricted stage file-provenance precondition must fail before npm registry contact; got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn stage_publish_repo_configured_custom_registry_uses_registry_scoped_token() {
    let mock = MockRegistry::start().await;
    mount_package_metadata_with_token(
        &mock,
        "@scope/staged-pkg",
        serde_json::json!({"0.9.0": {}}),
        CUSTOM_STAGE_TOKEN,
    )
    .await;
    mount_stage_publish_with_token(&mock, "@scope/staged-pkg", CUSTOM_STAGE_TOKEN).await;
    let project = stage_project();
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"name":"@scope/staged-pkg","registry":"{}"}}}}}}"#,
            mock.url()
        ),
    );

    let login = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &mock.url(),
            "--token",
            CUSTOM_STAGE_TOKEN,
        ])
        .output()
        .expect("failed to store custom stage registry token");
    assert!(
        login.status.success(),
        "custom registry login must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&login.stdout),
        String::from_utf8_lossy(&login.stderr),
    );

    let output = lpm(&project)
        .env("NPM_TOKEN", "ambient-stage-npm-token")
        .args(["--json", "stage", "publish", "--yes"])
        .output()
        .expect("failed to run lpm stage publish with custom registry token");

    assert!(
        output.status.success(),
        "repo-configured stage registry must use registry-scoped token\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json(&output.stdout);
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["stageId"], serde_json::json!(STAGE_ID));
}

#[tokio::test]
async fn stage_publish_repo_configured_custom_registry_refuses_ambient_npm_token() {
    let mock = MockRegistry::start().await;
    let project = stage_project();
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"name":"@scope/staged-pkg","registry":"{}"}}}}}}"#,
            mock.url()
        ),
    );

    let output = lpm(&project)
        .env("NPM_TOKEN", "ambient-stage-npm-token")
        .args(["stage", "publish", "--yes"])
        .output()
        .expect("failed to run lpm stage publish with ambient token");

    assert!(
        !output.status.success(),
        "repo-configured custom stage registry must reject ambient NPM_TOKEN"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("registry-scoped token") && stderr.contains("lpm login --login-registry"),
        "error must direct the user to scoped custom-registry auth, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "ambient NPM_TOKEN must be rejected before contacting repo-configured stage registry; got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn stage_publish_preserves_provenance_fields_in_payload() {
    let mock = MockRegistry::start().await;
    mount_package_metadata(
        &mock,
        "@scope/provenance-pkg",
        serde_json::json!({"0.9.0": {}}),
    )
    .await;
    mount_stage_publish(&mock, "@scope/provenance-pkg").await;
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.provenance-pkg",
        "version": "1.0.0",
        "description": "A staged publish provenance package",
        "main": "index.js",
        "license": "MIT",
        "_provenance": {"bundle": "kept"},
        "_npmProvenanceAttestations": {"attestations": [{"bundle": {"kept": true}}]}
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"npm":{"name":"@scope/provenance-pkg"}}}"#,
    );

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "--json",
            "stage",
            "publish",
            "--yes",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run provenance-preserving lpm stage publish");

    assert!(
        output.status.success(),
        "stage publish must preserve provenance payload\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let payload = recorded_stage_publish_payload(&mock).await;
    let version = &payload["versions"]["1.0.0"];
    assert_eq!(
        version["_provenance"],
        serde_json::json!({"bundle": "kept"})
    );
    assert_eq!(
        version["_npmProvenanceAttestations"],
        serde_json::json!({"attestations": [{"bundle": {"kept": true}}]})
    );
}

#[tokio::test]
async fn stage_publish_dry_run_does_not_contact_npm_registry() {
    let mock = MockRegistry::start().await;
    let project = stage_project();

    let output = lpm(&project)
        .args([
            "--json",
            "stage",
            "publish",
            "--dry-run",
            "--yes",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage publish --dry-run --json");

    assert!(
        output.status.success(),
        "stage publish dry-run must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json(&output.stdout);
    assert_eq!(envelope["dry_run"], serde_json::json!(true));
    insta::with_settings!({ filters => stage_json_filters() }, {
        insta::assert_json_snapshot!("stage_publish_dry_run_json_envelope", envelope);
    });

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "dry-run must not contact npm registry, got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn stage_publish_blocks_implicit_latest_when_higher_version_exists() {
    let mock = MockRegistry::start().await;
    mount_package_metadata(&mock, "@scope/staged-pkg", serde_json::json!({"2.0.0": {}})).await;
    let project = stage_project();

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args(["stage", "publish", "--yes", "--npm-registry", &mock.url()])
        .output()
        .expect("failed to run lpm stage publish");

    assert!(
        !output.status.success(),
        "implicit latest guard must fail when a higher version exists"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Cannot implicitly apply the \"latest\" tag"),
        "expected latest-tag guard, got:\n{stderr}"
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() != "POST"),
        "version guard must run before upload"
    );
}

#[tokio::test]
async fn stage_list_returns_json_envelope() {
    let mock = MockRegistry::start().await;
    mount_stage_list_page(&mock, 0, "pkg", vec![stage_item("a")], 1).await;
    let project = TempProject::empty(r#"{"name":"stage-list","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "--json",
            "stage",
            "list",
            "pkg",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage list --json");

    assert!(
        output.status.success(),
        "stage list must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json(&output.stdout);
    assert_eq!(envelope["total"], serde_json::json!(1));
    insta::with_settings!({ filters => stage_json_filters() }, {
        insta::assert_json_snapshot!("stage_list_json_envelope", envelope);
    });
}

#[tokio::test]
async fn stage_list_human_output_prints_stage_items_on_stdout() {
    let mock = MockRegistry::start().await;
    mount_stage_list_page(&mock, 0, "pkg", vec![stage_item("a")], 1).await;
    let project = TempProject::empty(r#"{"name":"stage-list","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args(["stage", "list", "pkg", "--npm-registry", &mock.url()])
        .output()
        .expect("failed to run lpm stage list");

    assert!(
        output.status.success(),
        "stage list must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("a @scope/staged-pkg@1.0.0 latest"),
        "stage list human answer must print the staged item, got:\n{stdout}"
    );
}

#[tokio::test]
async fn stage_list_fetches_second_page_when_first_page_is_full() {
    let mock = MockRegistry::start().await;
    let first_page: Vec<_> = (0..100)
        .map(|index| stage_item(&format!("page-a-{index}")))
        .collect();
    mount_stage_list_page(&mock, 0, "pkg", first_page, 101).await;
    mount_stage_list_page(&mock, 1, "pkg", vec![stage_item("page-b")], 101).await;
    let project = TempProject::empty(r#"{"name":"stage-list-pages","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "--json",
            "stage",
            "list",
            "pkg",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run paginated lpm stage list --json");

    assert!(
        output.status.success(),
        "paginated stage list must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope = parse_json(&output.stdout);
    assert_eq!(
        envelope["data"]
            .as_array()
            .expect("data must be array")
            .len(),
        101
    );
}

#[tokio::test]
async fn stage_view_returns_json_envelope() {
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/-/stage/{STAGE_ID}")))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(stage_item(STAGE_ID)))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"stage-view","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "--json",
            "stage",
            "view",
            STAGE_ID,
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage view --json");

    assert!(output.status.success(), "stage view must succeed");
    let envelope = parse_json(&output.stdout);
    insta::with_settings!({ filters => stage_json_filters() }, {
        insta::assert_json_snapshot!("stage_view_json_envelope", envelope);
    });
}

#[tokio::test]
async fn stage_view_human_output_prints_stage_item_on_stdout() {
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/-/stage/{STAGE_ID}")))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(stage_item(STAGE_ID)))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"stage-view","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args(["stage", "view", STAGE_ID, "--npm-registry", &mock.url()])
        .output()
        .expect("failed to run lpm stage view");

    assert!(
        output.status.success(),
        "stage view must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("123e4567-e89b-12d3-a456-426614174000 @scope/staged-pkg@1.0.0 latest"),
        "stage view human answer must print the staged item, got:\n{stdout}"
    );
}

#[tokio::test]
async fn stage_approve_sends_otp_to_approve_endpoint() {
    let mock = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/-/stage/{STAGE_ID}/approve")))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .and(header("npm-otp", "123456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true
        })))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"stage-approve","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "--json",
            "stage",
            "approve",
            STAGE_ID,
            "--otp",
            "123456",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage approve --json");

    assert!(output.status.success(), "stage approve must succeed");
    let envelope = parse_json(&output.stdout);
    insta::with_settings!({ filters => stage_json_filters() }, {
        insta::assert_json_snapshot!("stage_approve_json_envelope", envelope);
    });
}

#[tokio::test]
async fn stage_approve_human_output_reports_approved_stage() {
    let mock = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/-/stage/{STAGE_ID}/approve")))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .and(header("npm-otp", "123456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true
        })))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"stage-approve","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "stage",
            "approve",
            STAGE_ID,
            "--otp",
            "123456",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage approve");

    assert!(output.status.success(), "stage approve must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.trim().is_empty(),
        "stage approve human status must stay off stdout, got:\n{stdout}"
    );
    assert!(
        stderr.contains("✓ Staged package 123e4567-e89b-12d3-a456-426614174000 approved"),
        "stage approve human output must report approval, got:\n{stderr}"
    );
}

#[tokio::test]
async fn stage_reject_deletes_stage_endpoint_with_otp() {
    let mock = MockRegistry::start().await;
    Mock::given(method("DELETE"))
        .and(path(format!("/-/stage/{STAGE_ID}")))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .and(header("npm-otp", "123456"))
        .respond_with(ResponseTemplate::new(200))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"stage-reject","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "--json",
            "stage",
            "reject",
            STAGE_ID,
            "--otp",
            "123456",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage reject --json");

    assert!(output.status.success(), "stage reject must succeed");
    let envelope = parse_json(&output.stdout);
    insta::with_settings!({ filters => stage_json_filters() }, {
        insta::assert_json_snapshot!("stage_reject_json_envelope", envelope);
    });
}

#[tokio::test]
async fn stage_reject_human_output_reports_rejected_stage() {
    let mock = MockRegistry::start().await;
    Mock::given(method("DELETE"))
        .and(path(format!("/-/stage/{STAGE_ID}")))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .and(header("npm-otp", "123456"))
        .respond_with(ResponseTemplate::new(200))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"stage-reject","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "stage",
            "reject",
            STAGE_ID,
            "--otp",
            "123456",
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage reject");

    assert!(output.status.success(), "stage reject must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.trim().is_empty(),
        "stage reject human status must stay off stdout, got:\n{stdout}"
    );
    assert!(
        stderr.contains("✓ Staged package 123e4567-e89b-12d3-a456-426614174000 rejected"),
        "stage reject human output must report rejection, got:\n{stderr}"
    );
}

#[tokio::test]
async fn stage_download_writes_tarball_named_from_manifest() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("@scope/staged-pkg", "1.0.0");
    Mock::given(method("GET"))
        .and(path(format!("/-/stage/{STAGE_ID}/tarball")))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"stage-download","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "--json",
            "stage",
            "download",
            STAGE_ID,
            "--npm-registry",
            &mock.url(),
        ])
        .output()
        .expect("failed to run lpm stage download --json");

    assert!(output.status.success(), "stage download must succeed");
    let expected = project
        .path()
        .join(format!("scope-staged-pkg-1.0.0-{STAGE_ID}.tgz"));
    assert!(
        expected.exists(),
        "downloaded tarball must exist at {expected:?}"
    );
    let envelope = parse_json(&output.stdout);
    insta::with_settings!({ filters => vec![
        (r#"http://127\.0\.0\.1:\d+"#, "http://mock.registry"),
        (
            r#""path":\s*"[^"]+scope-staged-pkg-1\.0\.0-123e4567-e89b-12d3-a456-426614174000\.tgz""#,
            r#""path": "[PROJECT]/scope-staged-pkg-1.0.0-123e4567-e89b-12d3-a456-426614174000.tgz""#,
        ),
    ]}, {
        insta::assert_json_snapshot!("stage_download_json_envelope", envelope);
    });
}

#[tokio::test]
async fn stage_download_human_output_reports_downloaded_tarball_path() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("@scope/staged-pkg", "1.0.0");
    Mock::given(method("GET"))
        .and(path(format!("/-/stage/{STAGE_ID}/tarball")))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"stage-download","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args(["stage", "download", STAGE_ID, "--npm-registry", &mock.url()])
        .output()
        .expect("failed to run lpm stage download");

    assert!(output.status.success(), "stage download must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.trim().is_empty(),
        "stage download human status must stay off stdout, got:\n{stdout}"
    );
    assert!(
        stderr.contains("✓ Downloaded staged package to")
            && stderr.contains("scope-staged-pkg-1.0.0-123e4567-e89b-12d3-a456-426614174000.tgz"),
        "stage download human output must report the written tarball, got:\n{stderr}"
    );
}

#[test]
fn stage_rejects_global_registry_flag() {
    let project = TempProject::empty(r#"{"name":"stage-registry-flag","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["--registry", "https://lpm.example.test", "stage", "list"])
        .output()
        .expect("failed to run lpm stage list with --registry");

    assert!(
        !output.status.success(),
        "stage must reject global --registry"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--npm-registry"),
        "error must point users to --npm-registry, got:\n{stderr}"
    );
}

#[test]
fn stage_publish_missing_npm_token_fails_before_upload() {
    let project = stage_project();
    let output = lpm(&project)
        .args([
            "stage",
            "publish",
            "--yes",
            "--npm-registry",
            "http://127.0.0.1:9",
        ])
        .output()
        .expect("failed to run lpm stage publish without NPM_TOKEN");

    assert!(
        !output.status.success(),
        "stage publish without npm token must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no npm token found"),
        "expected missing npm token guidance, got:\n{stderr}"
    );
}

#[tokio::test]
async fn stage_list_requires_npm_token_when_npm_id_token_is_present() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(r#"{"name":"stage-list-auth","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("NPM_ID_TOKEN", NPM_ID_TOKEN)
        .args(["stage", "list", "--npm-registry", &mock.url()])
        .output()
        .expect("failed to run lpm stage list with only NPM_ID_TOKEN");

    assert!(
        !output.status.success(),
        "stage list must not use npm Trusted Publishing OIDC"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no npm token found"),
        "expected normal npm token guidance, got:\n{stderr}"
    );
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "stage list without npm token must fail before contacting registry"
    );
}

fn stage_project() -> TempProject {
    let project = TempProject::empty(
        r#"{
        "name": "@lpm.dev/testuser.staged-pkg",
        "version": "1.0.0",
        "description": "A staged publish test package",
        "main": "index.js",
        "license": "MIT"
    }"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file(
        "lpm.json",
        r#"{"publish":{"npm":{"name":"@scope/staged-pkg"}}}"#,
    );
    project
}

async fn mount_package_metadata(mock: &MockRegistry, package: &str, versions: serde_json::Value) {
    mount_package_metadata_with_token(mock, package, versions, NPM_TOKEN).await;
}

async fn mount_package_metadata_with_token(
    mock: &MockRegistry,
    package: &str,
    versions: serde_json::Value,
    token: &str,
) {
    Mock::given(method("GET"))
        .and(path(format!("/{}", encoded_package(package))))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": package,
            "versions": versions
        })))
        .mount(mock.server())
        .await;
}

async fn mount_stage_publish(mock: &MockRegistry, package: &str) {
    mount_stage_publish_with_token(mock, package, NPM_TOKEN).await;
}

async fn mount_stage_publish_with_token(mock: &MockRegistry, package: &str, token: &str) {
    Mock::given(method("POST"))
        .and(path(format!(
            "/-/stage/package/{}",
            encoded_package(package)
        )))
        .and(header("authorization", format!("Bearer {token}")))
        .and(header("npm-command", "stage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "stageId": STAGE_ID
        })))
        .mount(mock.server())
        .await;
}

async fn mount_npm_oidc_exchange(mock: &MockRegistry, package: &str) {
    Mock::given(method("POST"))
        .and(path(format!(
            "/-/npm/v1/oidc/token/exchange/package/{}",
            encoded_package(package)
        )))
        .and(header("authorization", format!("Bearer {NPM_ID_TOKEN}")))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token_type": "oidc",
            "token": OIDC_NPM_TOKEN,
        })))
        .mount(mock.server())
        .await;
}

async fn mount_stage_list_page(
    mock: &MockRegistry,
    page: u32,
    package: &str,
    items: Vec<serde_json::Value>,
    total: u32,
) {
    Mock::given(method("GET"))
        .and(path("/-/stage"))
        .and(query_param("page", page.to_string()))
        .and(query_param("perPage", "100"))
        .and(query_param("package", package))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": items,
            "total": total
        })))
        .mount(mock.server())
        .await;
}

fn stage_item(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "packageName": "@scope/staged-pkg",
        "version": "1.0.0",
        "tag": "latest",
        "createdAt": "2026-06-04T00:00:00.000Z",
        "actor": "testuser",
        "actorType": "user",
        "shasum": "abc123"
    })
}

fn parse_json(stdout: &[u8]) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(stdout).into_owned();
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stage JSON output must be valid JSON: {e}\n---\n{stdout}"))
}

fn extract_package_json(tarball: &[u8]) -> serde_json::Value {
    let decoder = GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().expect("tarball entries must read") {
        let mut entry = entry.expect("tarball entry must read");
        if entry.path().expect("entry path must read")
            == std::path::Path::new("package/package.json")
        {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .expect("package.json entry must read");
            return serde_json::from_str(&content).expect("package.json must parse");
        }
    }
    panic!("tarball missing package/package.json");
}

async fn recorded_stage_publish_payload(mock: &MockRegistry) -> serde_json::Value {
    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    let publish_request = requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .expect("stage publish POST must be recorded");
    serde_json::from_slice(&publish_request.body).expect("stage payload must be JSON")
}

fn stage_json_filters() -> Vec<(&'static str, &'static str)> {
    vec![
        (r#"http://127\.0\.0\.1:\d+"#, "http://mock.registry"),
        (r#""duration_ms":\s*\d+"#, r#""duration_ms": 0"#),
        (r#""tarball_size":\s*\d+"#, r#""tarball_size": 0"#),
    ]
}

fn encoded_package(package: &str) -> String {
    package.replace('@', "%40").replace('/', "%2F")
}
