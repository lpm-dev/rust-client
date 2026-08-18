use super::orchestrator::lpm_package_url;
use super::output::{
    format_dry_run_files_value, format_lpm_publication_notice,
    format_multi_publish_success_summary, format_publish_retry_detail,
    format_single_publish_success_summary, publish_check_json, publish_result_json,
};
use super::prepare::{
    MAX_PUBLISH_TARBALL_BYTES, prepare_publish_project_from_manifest, read_publish_manifest,
    validate_publish_tarball_size,
};
use super::secret_scan::{SecretScanLine, format_secret_scan_human, secret_scan_json};
use super::skills::{ManifestWriteMode, compute_published_skills_digest, ensure_lpm_in_files};
use super::swift::extract_swift_metadata;
use super::target::{deduplicate_targets, resolve_targets, validate_custom_publish_registry_url};
use super::types::{LpmPublicationStatus, PublicationWaitResult, PublishResult, PublishTarget};
use super::version_data::integrity_to_sha512_hex;
use super::wait::poll_publication_status;
use crate::commands::publish_common;
use crate::commands::skills::author;
use lpm_runner::lpm_json;
use lpm_security::behavioral::secrets::{SecretMatch, SecretScanResult};

#[test]
fn secret_scan_human_renderer_uses_slim_lines_with_expected_content() {
    let scan = SecretScanResult {
        matches: vec![SecretMatch {
            pattern_name: "stripe_live_secret".to_string(),
            description: "Stripe live secret key".to_string(),
            line: 7,
            severity: "critical".to_string(),
        }],
        files_scanned: 1,
        limit_exceeded: None,
    };

    let lines = format_secret_scan_human(&scan);
    let joined = lines
        .iter()
        .map(|line| match line {
            SecretScanLine::Warn(message)
            | SecretScanLine::Failed(message)
            | SecretScanLine::Detail(message) => message.as_ref(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let joined = console::strip_ansi_codes(&joined).into_owned();

    assert!(
        matches!(lines.first(), Some(SecretScanLine::Warn(_))),
        "secret scan headline should render as an install_ui warning"
    );
    assert!(
        matches!(lines.get(2), Some(SecretScanLine::Failed(_))),
        "blocking result should render as an install_ui failure"
    );
    assert!(
        joined.contains("Secret scan found 1 potential leak")
            && joined.contains("critical:7  stripe_live_secret")
            && joined.contains("Publish blocked. Remove secrets before publishing.")
            && joined.contains("use --allow-secrets"),
        "secret scan slim output missing expected detail:\n{joined}"
    );
}

#[test]
fn secret_scan_json_envelope_preserves_machine_fields() {
    let scan = SecretScanResult {
        matches: vec![SecretMatch {
            pattern_name: "github_pat".to_string(),
            description: "GitHub personal access token".to_string(),
            line: 3,
            severity: "critical".to_string(),
        }],
        files_scanned: 1,
        limit_exceeded: None,
    };

    let json = secret_scan_json(&scan);

    assert_eq!(json["error"], "secret_scan_failed");
    assert_eq!(json["matches"][0]["pattern"], "github_pat");
    assert_eq!(json["matches"][0]["line"], 3);
    assert!(json["matches"][0].get("matchedText").is_none());
    assert_eq!(
        json["hint"],
        "Use --allow-secrets to bypass (not recommended)"
    );
}

#[test]
fn ensure_lpm_in_files_preserves_tabs() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_json_path = dir.path().join("package.json");
    let original = "{\n\t\"name\": \"test\",\n\t\"version\": \"1.0.0\",\n\t\"files\": [\n\t\t\"src/\"\n\t]\n}\n";
    std::fs::write(&pkg_json_path, original).unwrap();

    let mut manifest = read_publish_manifest(dir.path()).unwrap();
    ensure_lpm_in_files(&mut manifest, ManifestWriteMode::Persist).unwrap();

    let result = std::fs::read_to_string(&pkg_json_path).unwrap();
    assert!(result.contains("\".lpm/skills\""), "should add .lpm/skills");
    assert!(
        result.contains("\t\"src/\""),
        "should preserve tab indentation"
    );
    assert!(
        result.find("\"name\"").unwrap() < result.find("\"files\"").unwrap(),
        "key order preserved"
    );
}

#[test]
fn ensure_lpm_in_files_already_present() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_json_path = dir.path().join("package.json");
    let original = "{\n\t\"name\": \"test\",\n\t\"version\": \"1.0.0\",\n\t\"files\": [\".lpm/skills\", \"src/\"]\n}\n";
    std::fs::write(&pkg_json_path, original).unwrap();

    let mut manifest = read_publish_manifest(dir.path()).unwrap();
    ensure_lpm_in_files(&mut manifest, ManifestWriteMode::Persist).unwrap();

    let result = std::fs::read_to_string(&pkg_json_path).unwrap();
    assert_eq!(result, original, "file should be untouched");
}

#[test]
fn ensure_lpm_in_files_updates_an_empty_array_with_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_json_path = dir.path().join("package.json");
    let original = "{\n  \"name\": \"test\",\n  \"version\": \"1.0.0\",\n  \"files\": []\n}\n";
    std::fs::write(&pkg_json_path, original).unwrap();

    let mut manifest = read_publish_manifest(dir.path()).unwrap();
    assert!(ensure_lpm_in_files(&mut manifest, ManifestWriteMode::Persist).unwrap());

    let updated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap()).unwrap();
    assert_eq!(updated["files"], serde_json::json!([".lpm/skills"]));
}

#[test]
fn ensure_lpm_in_files_only_updates_the_top_level_field() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_json_path = dir.path().join("package.json");
    let original = r#"{
  "name": "test",
  "version": "1.0.0",
  "metadata": {"files": ["leave-me-alone"]},
  "files": ["src/"]
}
"#;
    std::fs::write(&pkg_json_path, original).unwrap();

    let mut manifest = read_publish_manifest(dir.path()).unwrap();
    assert!(ensure_lpm_in_files(&mut manifest, ManifestWriteMode::Persist).unwrap());

    let updated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pkg_json_path).unwrap()).unwrap();
    assert_eq!(
        updated["metadata"]["files"],
        serde_json::json!(["leave-me-alone"])
    );
    assert_eq!(updated["files"], serde_json::json!(["src/", ".lpm/skills"]));
}

#[test]
fn real_publish_preparation_persists_and_packs_authored_skills() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    std::fs::create_dir_all(project.join(".lpm/skills")).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{
  "name": "@lpm.dev/owner.package",
  "version": "1.0.0",
  "files": ["index.js"]
}
"#,
    )
    .unwrap();
    std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();
    std::fs::write(
        project.join(".lpm/skills/usage.md"),
        format!(
            "---\nname: usage\ndescription: Complete package usage guidance\n---\n# Usage\n\n{}",
            "Use this package through its documented public API. This guidance includes enough detail for an agent to follow the supported workflow safely."
        ),
    )
    .unwrap();

    let mut manifest = read_publish_manifest(project).unwrap();
    assert!(
        ensure_lpm_in_files(&mut manifest, ManifestWriteMode::Persist).unwrap(),
        "the restrictive files array should be updated before tarball creation"
    );
    let prepared = prepare_publish_project_from_manifest(project, manifest, None, true).unwrap();

    assert!(
        prepared
            .tarball_files
            .iter()
            .any(|file| file.path == ".lpm/skills/usage.md"),
        "the current publish tarball must include publisher-authored skills"
    );
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join("package.json")).unwrap()).unwrap();
    assert_eq!(
        persisted["files"],
        serde_json::json!(["index.js", ".lpm/skills"])
    );
}

#[test]
fn read_only_publish_preparation_packs_effective_manifest_without_writing_it() {
    use std::io::Read;

    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    std::fs::create_dir_all(project.join(".lpm/skills")).unwrap();
    let original = r#"{
  "name": "@lpm.dev/owner.read-only",
  "version": "1.0.0",
  "files": ["index.js"]
}
"#;
    std::fs::write(project.join("package.json"), original).unwrap();
    std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();
    std::fs::write(
        project.join(".lpm/skills/usage.md"),
        "---\nname: usage\ndescription: Complete usage guidance\n---\n# Usage\n",
    )
    .unwrap();

    let mut manifest = read_publish_manifest(project).unwrap();
    assert!(ensure_lpm_in_files(&mut manifest, ManifestWriteMode::ReadOnly).unwrap());
    let prepared = prepare_publish_project_from_manifest(project, manifest, None, true).unwrap();

    assert_eq!(
        std::fs::read_to_string(project.join("package.json")).unwrap(),
        original
    );
    assert!(
        prepared
            .tarball_files
            .iter()
            .any(|file| file.path == ".lpm/skills/usage.md")
    );

    let decoder = flate2::read::GzDecoder::new(prepared.tarball_data.as_slice());
    let mut archive = tar::Archive::new(decoder);
    let mut entries = std::collections::BTreeMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().into_owned();
        let mut content = Vec::new();
        entry.read_to_end(&mut content).unwrap();
        entries.insert(path, content);
    }

    assert!(entries.contains_key(std::path::Path::new("package/.lpm/skills/usage.md")));
    let packed_manifest: serde_json::Value = serde_json::from_slice(
        entries
            .get(std::path::Path::new("package/package.json"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        packed_manifest["files"],
        serde_json::json!(["index.js", ".lpm/skills"])
    );
}

#[test]
fn skills_digest_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    std::fs::write(
        skills_dir.join("a.md"),
        "---\nname: alpha\ndescription: Alpha package guidance\n---\nalpha body",
    )
    .unwrap();
    std::fs::write(
        skills_dir.join("b.md"),
        "---\nname: beta\ndescription: Beta package guidance\n---\nbeta body",
    )
    .unwrap();

    let d1 = author::compute_digest(&skills_dir).unwrap();
    let d2 = author::compute_digest(&skills_dir).unwrap();
    assert_eq!(d1, d2, "same content must produce same digest");

    std::fs::write(
        skills_dir.join("b.md"),
        "---\nname: beta\ndescription: Beta package guidance\n---\ngamma body",
    )
    .unwrap();
    let d3 = author::compute_digest(&skills_dir).unwrap();
    assert_ne!(d1, d3, "different content must produce different digest");
}

#[test]
fn local_and_published_skill_digests_use_frontmatter_names() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    let raw_content =
        "---\nname: usage\ndescription: Complete package usage guidance\n---\npackage guidance";
    std::fs::write(skills_dir.join("guide.md"), raw_content).unwrap();
    let published = vec![lpm_registry::Skill {
        name: "usage".into(),
        description: Some("Complete package usage guidance".into()),
        version: None,
        globs: Vec::new(),
        content: Some("package guidance".into()),
        raw_content: Some(raw_content.into()),
        size_bytes: Some(raw_content.len() as u64),
    }];

    assert_eq!(
        author::compute_digest(&skills_dir).unwrap(),
        compute_published_skills_digest(&published)
    );
}

#[test]
fn resolve_targets_cli_flags_override() {
    // --npm only
    let targets = resolve_targets(true, false, false, false, None, None).unwrap();
    assert_eq!(targets, vec![PublishTarget::Npm]);

    // --lpm only
    let targets = resolve_targets(false, true, false, false, None, None).unwrap();
    assert_eq!(targets, vec![PublishTarget::Lpm]);

    // --npm --lpm
    let targets = resolve_targets(true, true, false, false, None, None).unwrap();
    assert_eq!(targets, vec![PublishTarget::Lpm, PublishTarget::Npm]);

    // --github
    let targets = resolve_targets(false, false, true, false, None, None).unwrap();
    assert_eq!(targets, vec![PublishTarget::GitHub]);

    // --registry <url>
    let targets = resolve_targets(
        false,
        false,
        false,
        false,
        Some("https://npm.corp.com"),
        None,
    )
    .unwrap();
    assert_eq!(
        targets,
        vec![PublishTarget::Custom("https://npm.corp.com".into())]
    );
}

#[test]
fn custom_publish_registry_rejects_embedded_credentials() {
    let error = validate_custom_publish_registry_url(
        "https://publish-user:publish-password@example.com/registry",
        "--publish-registry",
    )
    .expect_err("userinfo must not be accepted in a publish URL");

    let message = error.to_string();
    assert!(!message.contains("publish-user"));
    assert!(!message.contains("publish-password"));
}

#[test]
fn custom_publish_registry_rejects_query_and_fragment_components() {
    for url in [
        "https://registry.example.test/npm?token=secret",
        "https://registry.example.test/npm#secret",
    ] {
        let error = validate_custom_publish_registry_url(url, "publish.registries")
            .expect_err("query and fragment components must be rejected");
        assert!(!error.to_string().contains("secret"), "{url}");
    }
}

#[test]
fn resolve_targets_from_config() {
    let config = lpm_json::PublishConfig {
        registries: vec!["npm".into(), "lpm".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
    assert_eq!(targets, vec![PublishTarget::Npm, PublishTarget::Lpm]);
}

#[test]
fn resolve_targets_default_lpm() {
    let targets = resolve_targets(false, false, false, false, None, None).unwrap();
    assert_eq!(targets, vec![PublishTarget::Lpm]);
}

#[test]
fn resolve_targets_cli_overrides_config() {
    let config = lpm_json::PublishConfig {
        registries: vec!["lpm".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    // CLI --npm should ignore config
    let targets = resolve_targets(true, false, false, false, None, Some(&config)).unwrap();
    assert_eq!(targets, vec![PublishTarget::Npm]);
}

#[test]
fn resolve_targets_config_with_custom_url() {
    let config = lpm_json::PublishConfig {
        registries: vec!["lpm".into(), "https://npm.corp.com".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
    assert_eq!(
        targets,
        vec![
            PublishTarget::Lpm,
            PublishTarget::Custom("https://npm.corp.com".into()),
        ]
    );
}

#[test]
fn resolve_targets_rejects_unknown_entries() {
    let config = lpm_json::PublishConfig {
        registries: vec!["nmm".into(), "typo".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let result = resolve_targets(false, false, false, false, None, Some(&config));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("unknown publish registries"));
    assert!(err.contains("nmm"));
    assert!(err.contains("typo"));
}

#[test]
fn resolve_targets_rejects_http_urls() {
    let config = lpm_json::PublishConfig {
        registries: vec!["http://insecure.com".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let result = resolve_targets(false, false, false, false, None, Some(&config));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("HTTPS"));
}

#[test]
fn resolve_targets_rejects_http_cli_registry_url() {
    let result = resolve_targets(
        false,
        false,
        false,
        false,
        Some("http://insecure.com"),
        None,
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("HTTPS"));
}

#[test]
fn resolve_targets_deduplicates() {
    let config = lpm_json::PublishConfig {
        registries: vec!["npm".into(), "npm".into(), "lpm".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
    assert_eq!(targets, vec![PublishTarget::Npm, PublishTarget::Lpm]);
}

#[test]
fn publish_result_display() {
    assert_eq!(PublishTarget::Lpm.display_name(), "LPM");
    assert_eq!(PublishTarget::Npm.display_name(), "npm");
    assert_eq!(PublishTarget::GitHub.display_name(), "GitHub Packages");
    assert_eq!(
        PublishTarget::Custom("https://x.com".into()).key(),
        "https://x.com"
    );
    assert_eq!(PublishTarget::Npm.retry_flag(), "--npm");
    assert_eq!(PublishTarget::GitHub.retry_flag(), "--github");
}

#[test]
fn dry_run_files_value_uses_slim_value_roles() {
    assert_eq!(
        console::strip_ansi_codes(&format_dry_run_files_value(3, 2048)).into_owned(),
        "3 files (2.0 KB)"
    );
}

#[test]
fn publish_retry_detail_uses_slim_detail_shape() {
    assert_eq!(
        console::strip_ansi_codes(&format_publish_retry_detail(&PublishTarget::Npm)).into_owned(),
        "  Retry: lpm publish --npm"
    );
}

#[test]
fn custom_publish_retry_detail_does_not_expose_registry_path() {
    let detail = console::strip_ansi_codes(&format_publish_retry_detail(&PublishTarget::Custom(
        "https://packages.example.test/npm/private-path".into(),
    )))
    .into_owned();

    assert!(detail.contains("--publish-registry"));
    assert!(!detail.contains("private-path"), "{detail}");
}

#[test]
fn custom_publish_check_json_exposes_only_registry_origin() {
    let target = PublishTarget::Custom("https://packages.example.test/npm/private-path".into());
    let target_names =
        std::collections::HashMap::from([(target.key(), "custom-package".to_string())]);

    let json = publish_check_json(None, &[target], &target_names);

    assert_eq!(
        json["targets"][0]["registry"],
        serde_json::json!("https://packages.example.test")
    );
    assert_eq!(
        json["targets"][0]["name"],
        serde_json::json!("custom-package")
    );
}

#[test]
fn publish_tarball_size_accepts_the_500_mib_boundary() {
    assert!(validate_publish_tarball_size(MAX_PUBLISH_TARBALL_BYTES).is_ok());
}

#[test]
fn publish_tarball_size_rejects_one_byte_over_with_mib_wording() {
    let error = validate_publish_tarball_size(MAX_PUBLISH_TARBALL_BYTES + 1).unwrap_err();

    assert!(
        error.to_string().contains("(max 500 MiB)"),
        "unexpected tarball limit error: {error}"
    );
}

#[test]
fn lpm_package_url_preserves_the_canonical_dotted_name() {
    assert_eq!(
        lpm_package_url("@lpm.dev/acme.widget").as_deref(),
        Some("https://lpm.dev/acme.widget")
    );
}

#[test]
fn lpm_package_url_rejects_malformed_names_without_panicking() {
    assert_eq!(lpm_package_url("@lpm.dev/"), None);
}

#[test]
fn pending_review_is_exposed_in_lpm_publish_result_json() {
    let publication_status = LpmPublicationStatus::from_registry_response(&serde_json::json!({
        "publicationStatus": "pending_review"
    }));
    let result = PublishResult {
        target: "lpm".into(),
        success: true,
        error: None,
        auth: None,
        publication_status,
        current_latest_version: Some("1.1.0".to_string()),
        publication_wait: None,
        duration: std::time::Duration::ZERO,
    };

    let json = publish_result_json(&result);

    assert_eq!(json["publication_status"], "pending_review");
    assert_eq!(json["current_latest_version"], "1.1.0");
    assert_eq!(json["success"], true);
}

#[test]
fn missing_publication_status_remains_absent_from_lpm_publish_result_json() {
    let publication_status =
        LpmPublicationStatus::from_registry_response(&serde_json::json!({ "success": true }));
    let result = PublishResult {
        target: "lpm".into(),
        success: true,
        error: None,
        auth: None,
        publication_status,
        current_latest_version: None,
        publication_wait: None,
        duration: std::time::Duration::ZERO,
    };

    let json = publish_result_json(&result);

    assert!(json.get("publication_status").is_none());
}

#[test]
fn rejected_quarantined_and_unpublished_statuses_are_terminal_rejections() {
    for status in [
        LpmPublicationStatus::Rejected,
        LpmPublicationStatus::Quarantined,
        LpmPublicationStatus::Unpublished,
    ] {
        assert!(status.is_terminal_rejection(), "{}", status.as_str());
    }
}

#[test]
fn pending_and_unknown_publication_statuses_are_not_terminal_rejections() {
    for status in [
        LpmPublicationStatus::Active,
        LpmPublicationStatus::PendingReview,
        LpmPublicationStatus::Processing,
        LpmPublicationStatus::ManualReview,
        LpmPublicationStatus::Other("future_status".to_string()),
    ] {
        assert!(!status.is_terminal_rejection(), "{}", status.as_str());
    }
}

#[test]
fn unrelated_publish_result_does_not_gain_lpm_publication_status() {
    let result = PublishResult {
        target: "npm".into(),
        success: true,
        error: None,
        auth: Some("token"),
        publication_status: None,
        current_latest_version: None,
        publication_wait: None,
        duration: std::time::Duration::ZERO,
    };

    let json = publish_result_json(&result);

    assert!(json.get("publication_status").is_none());
}

#[test]
fn pending_review_human_notice_says_upload_succeeded_and_review_is_pending() {
    let notice = format_lpm_publication_notice(&LpmPublicationStatus::PendingReview).unwrap();
    let notice = console::strip_ansi_codes(&notice).into_owned();

    assert_eq!(
        notice,
        "Upload succeeded. The public version is awaiting LPM.dev Registry publication review."
    );
}

#[test]
fn pending_review_single_target_summary_does_not_claim_publication() {
    let summary = format_single_publish_success_summary(
        "@lpm.dev/acme.widget",
        "1.0.0",
        "10ms",
        Some(&LpmPublicationStatus::PendingReview),
    );
    let summary = console::strip_ansi_codes(&summary).into_owned();

    assert_eq!(
        summary,
        "Done · uploaded @lpm.dev/acme.widget@1.0.0 in 10ms; awaiting LPM.dev Registry publication review"
    );
}

#[test]
fn pending_review_multi_target_summary_does_not_claim_full_publication() {
    let summary =
        format_multi_publish_success_summary(2, "10ms", Some(&LpmPublicationStatus::PendingReview));
    let summary = console::strip_ansi_codes(&summary).into_owned();

    assert_eq!(
        summary,
        "Done · completed 2 registry uploads in 10ms; LPM.dev Registry publication review pending"
    );
}

#[test]
fn active_publication_retains_the_normal_success_summary() {
    let status = LpmPublicationStatus::from_registry_response(&serde_json::json!({
        "publicationStatus": "active"
    }))
    .expect("active Registry response has a publication status");
    let summary = format_single_publish_success_summary(
        "@lpm.dev/acme.widget",
        "1.0.0",
        "10ms",
        Some(&status),
    );
    let summary = console::strip_ansi_codes(&summary).into_owned();

    assert_eq!(
        summary,
        "Done · published @lpm.dev/acme.widget@1.0.0 in 10ms"
    );
}

#[test]
fn unknown_publication_status_stays_successful_without_rendering_registry_text() {
    let status = LpmPublicationStatus::from_registry_value("future\u{1b}[31mstatus");
    let result = PublishResult {
        target: "lpm".into(),
        success: true,
        error: None,
        auth: None,
        publication_status: Some(status),
        current_latest_version: None,
        publication_wait: None,
        duration: std::time::Duration::ZERO,
    };

    let notice = format_lpm_publication_notice(
        result
            .publication_status
            .as_ref()
            .expect("test result has publication status"),
    )
    .expect("unknown status has a safe human notice");
    let notice = console::strip_ansi_codes(&notice).into_owned();
    let json = publish_result_json(&result);

    assert!(result.success);
    assert_eq!(json["publication_status"], "future\u{1b}[31mstatus");
    assert!(!notice.contains("future"));
    assert!(!notice.contains('\u{1b}'));
}

#[tokio::test]
async fn publication_wait_completes_after_pending_processing_and_active_states() {
    let statuses = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from([
        Ok(LpmPublicationStatus::PendingReview),
        Ok(LpmPublicationStatus::Processing),
        Ok(LpmPublicationStatus::Active),
    ])));
    let fetch_status = || {
        let statuses = std::sync::Arc::clone(&statuses);
        async move {
            statuses
                .lock()
                .expect("status queue lock")
                .pop_front()
                .expect("one status per poll")
        }
    };

    let result = poll_publication_status(fetch_status, 3, std::time::Duration::ZERO).await;

    assert_eq!(result, PublicationWaitResult::active());
}

#[tokio::test]
async fn publication_wait_stops_immediately_for_manual_review() {
    let result = poll_publication_status(
        || async { Ok(LpmPublicationStatus::ManualReview) },
        3,
        std::time::Duration::ZERO,
    )
    .await;

    assert_eq!(result.status, Some(LpmPublicationStatus::ManualReview),);
    assert!(!result.success);
}

#[tokio::test]
async fn publication_wait_stops_immediately_for_rejected_or_quarantined_versions() {
    for status in [
        LpmPublicationStatus::Rejected,
        LpmPublicationStatus::Quarantined,
    ] {
        let result = poll_publication_status(
            || {
                let status = status.clone();
                async move { Ok(status) }
            },
            3,
            std::time::Duration::ZERO,
        )
        .await;

        assert!(!result.success, "{status:?} must be terminal");
        assert_eq!(result.status, Some(status));
    }
}

#[tokio::test]
async fn publication_wait_times_out_with_the_last_observed_state() {
    let result = poll_publication_status(
        || async { Ok(LpmPublicationStatus::PendingReview) },
        2,
        std::time::Duration::ZERO,
    )
    .await;

    assert_eq!(result.status, Some(LpmPublicationStatus::PendingReview),);
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("timed out")),
    );
}

#[test]
fn publication_wait_failure_preserves_successful_upload_in_json() {
    let result = PublishResult {
        target: "lpm".into(),
        success: true,
        error: None,
        auth: None,
        publication_status: Some(LpmPublicationStatus::PendingReview),
        current_latest_version: Some("1.1.0".to_string()),
        publication_wait: Some(PublicationWaitResult::timed_out(Some(
            LpmPublicationStatus::PendingReview,
        ))),
        duration: std::time::Duration::ZERO,
    };

    let json = publish_result_json(&result);

    assert_eq!(json["success"], true);
    assert_eq!(json["publication_wait"]["success"], false);
    assert_eq!(json["publication_wait"]["status"], "pending_review");
}

#[test]
fn extract_swift_metadata_from_raw_dump() {
    // Realistic raw `swift package dump-package` output
    let raw = serde_json::json!({
        "name": "Hue",
        "toolsVersion": {
            "_version": "5.9.0",
            "experimentalFeatures": []
        },
        "platforms": [
            { "platformName": "ios", "version": "13.0", "options": [] },
            { "platformName": "macos", "version": "10.15", "options": [] },
            { "platformName": "watchos", "version": "6.0", "options": [] },
            { "platformName": "tvos", "version": "13.0", "options": [] },
            { "platformName": "visionos", "version": "1.0", "options": [] }
        ],
        "products": [
            {
                "name": "Hue",
                "type": { "library": ["automatic"] },
                "targets": ["Hue"],
                "settings": []
            }
        ],
        "targets": [
            {
                "name": "Hue",
                "type": "regular",
                "dependencies": [],
                "path": "Sources/Hue"
            },
            {
                "name": "HueTests",
                "type": "test",
                "dependencies": [{ "byName": ["Hue", null] }],
                "path": "Tests/HueTests"
            }
        ],
        "dependencies": [
            {
                "sourceControl": [{
                    "identity": "swift-argument-parser",
                    "location": { "remote": ["https://github.com/apple/swift-argument-parser.git"] },
                    "requirement": { "range": [{ "lowerBound": "1.0.0", "upperBound": "2.0.0" }] }
                }]
            }
        ]
    });

    let result = extract_swift_metadata(&raw);

    // toolsVersion: extracted as string
    assert_eq!(result["toolsVersion"], "5.9.0");

    // platforms: platformName → name
    let platforms = result["platforms"].as_array().unwrap();
    assert_eq!(platforms.len(), 5);
    assert_eq!(platforms[0]["name"], "ios");
    assert_eq!(platforms[0]["version"], "13.0");
    assert_eq!(platforms[1]["name"], "macos");
    assert_eq!(platforms[4]["name"], "visionos");

    // products: type object → string
    let products = result["products"].as_array().unwrap();
    assert_eq!(products[0]["name"], "Hue");
    assert_eq!(products[0]["type"], "library");

    // targets: byName array → { type, name }
    let targets = result["targets"].as_array().unwrap();
    assert_eq!(targets[0]["name"], "Hue");
    assert_eq!(targets[0]["type"], "regular");
    assert_eq!(targets[1]["name"], "HueTests");
    let test_deps = targets[1]["dependencies"].as_array().unwrap();
    assert_eq!(test_deps[0]["type"], "byName");
    assert_eq!(test_deps[0]["name"], "Hue");

    // dependencies: sourceControl array → flat
    let deps = result["dependencies"].as_array().unwrap();
    assert_eq!(deps[0]["type"], "sourceControl");
    assert_eq!(deps[0]["identity"], "swift-argument-parser");
    assert_eq!(
        deps[0]["location"],
        "https://github.com/apple/swift-argument-parser.git"
    );
}

#[test]
fn extract_swift_metadata_already_normalized() {
    // Pre-extracted format (from JS CLI) should pass through unchanged
    let extracted = serde_json::json!({
        "toolsVersion": "5.9.0",
        "platforms": [
            { "name": "ios", "version": "13.0" },
            { "name": "macos", "version": "10.15" }
        ],
        "products": [
            { "name": "Hue", "type": "library", "targets": ["Hue"] }
        ],
        "targets": [
            {
                "name": "HueTests",
                "type": "test",
                "dependencies": [{ "type": "byName", "name": "Hue" }]
            }
        ],
        "dependencies": [
            {
                "type": "sourceControl",
                "identity": "swift-argument-parser",
                "location": "https://github.com/apple/swift-argument-parser.git",
                "requirement": null
            }
        ]
    });

    let result = extract_swift_metadata(&extracted);

    assert_eq!(result["toolsVersion"], "5.9.0");
    assert_eq!(result["platforms"][0]["name"], "ios");
    assert_eq!(result["products"][0]["type"], "library");
    assert_eq!(result["targets"][0]["dependencies"][0]["type"], "byName");
    assert_eq!(result["dependencies"][0]["type"], "sourceControl");
    assert_eq!(
        result["dependencies"][0]["identity"],
        "swift-argument-parser"
    );
}

#[test]
fn extract_swift_metadata_empty_manifest() {
    let empty = serde_json::json!({});
    let result = extract_swift_metadata(&empty);

    assert!(result["toolsVersion"].is_null());
    assert_eq!(result["platforms"].as_array().unwrap().len(), 0);
    assert_eq!(result["products"].as_array().unwrap().len(), 0);
    assert_eq!(result["targets"].as_array().unwrap().len(), 0);
    assert_eq!(result["dependencies"].as_array().unwrap().len(), 0);
}

#[test]
fn extract_swift_metadata_filesystem_dependency() {
    let manifest = serde_json::json!({
        "toolsVersion": { "_version": "5.8.0" },
        "platforms": [],
        "products": [],
        "targets": [],
        "dependencies": [
            {
                "fileSystem": [{
                    "identity": "local-utils",
                    "path": "../local-utils"
                }]
            }
        ]
    });

    let result = extract_swift_metadata(&manifest);
    let deps = result["dependencies"].as_array().unwrap();
    assert_eq!(deps[0]["type"], "fileSystem");
    assert_eq!(deps[0]["identity"], "local-utils");
    assert_eq!(deps[0]["path"], "../local-utils");
}

// ─── Orchestration: config validation edge cases ─────────────

#[test]
fn resolve_targets_all_invalid_entries_errors() {
    // All entries are typos — should error, not silently produce empty vec
    let config = lpm_json::PublishConfig {
        registries: vec!["nmm".into(), "githb".into(), "foobar".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let result = resolve_targets(false, false, false, false, None, Some(&config));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("nmm"));
    assert!(err.contains("githb"));
    assert!(err.contains("foobar"));
}

#[test]
fn resolve_targets_mixed_valid_and_invalid_errors() {
    // One valid + one invalid — should still error (strict validation)
    let config = lpm_json::PublishConfig {
        registries: vec!["npm".into(), "typo".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let result = resolve_targets(false, false, false, false, None, Some(&config));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("typo"));
}

#[test]
fn resolve_targets_empty_registries_defaults_to_lpm() {
    // Empty registries array falls through to default LPM
    let config = lpm_json::PublishConfig {
        registries: vec![],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
    assert_eq!(targets, vec![PublishTarget::Lpm]);
}

#[test]
fn resolve_targets_custom_https_url_accepted() {
    let config = lpm_json::PublishConfig {
        registries: vec!["https://npm.corp.com".into(), "lpm".into()],
        lpm: None,
        npm: None,
        github: None,
        gitlab: None,
    };
    let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(
        targets[0],
        PublishTarget::Custom("https://npm.corp.com".into())
    );
    assert_eq!(targets[1], PublishTarget::Lpm);
}

// ─── Orchestration: integrity_to_sha512_hex ──────────────────

#[test]
fn integrity_to_sha512_hex_roundtrips() {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use sha2::{Digest, Sha512};

    let data = b"test tarball data";
    let mut hasher = Sha512::new();
    hasher.update(data);
    let hash_bytes = hasher.finalize();
    let integrity = format!("sha512-{}", BASE64.encode(hash_bytes));

    let hex = integrity_to_sha512_hex(&integrity);

    // Should be 128 hex chars (512 bits / 4 bits per char)
    assert_eq!(hex.len(), 128);
    // Should match direct hex encoding
    assert_eq!(hex, format!("{:x}", hash_bytes));
}

// ─── Orchestration: deduplicate_targets ───────────────────────

#[test]
fn deduplicate_preserves_order() {
    let targets = vec![
        PublishTarget::Npm,
        PublishTarget::Lpm,
        PublishTarget::Npm,
        PublishTarget::GitHub,
        PublishTarget::Lpm,
    ];
    let deduped = deduplicate_targets(targets);
    assert_eq!(
        deduped,
        vec![
            PublishTarget::Npm,
            PublishTarget::Lpm,
            PublishTarget::GitHub
        ]
    );
}

#[test]
fn deduplicate_custom_urls_by_value() {
    let targets = vec![
        PublishTarget::Custom("https://a.com".into()),
        PublishTarget::Custom("https://b.com".into()),
        PublishTarget::Custom("https://a.com".into()),
    ];
    let deduped = deduplicate_targets(targets);
    assert_eq!(deduped.len(), 2);
    assert_eq!(deduped[0].key(), "https://a.com");
    assert_eq!(deduped[1].key(), "https://b.com");
}

// ─── Orchestration: provenance hash binding ──────────────────

#[test]
fn provenance_hash_matches_rewritten_tarball() {
    // This proves the core invariant: after tarball rewriting, the hash
    // used for provenance must match the actual uploaded artifact.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();

    std::fs::write(
        project.join("package.json"),
        r#"{"name": "@lpm.dev/neo.pkg", "version": "1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(project.join("index.js"), "exports.x = 1").unwrap();

    let pkg_json: serde_json::Value =
        serde_json::from_str(r#"{"name": "@lpm.dev/neo.pkg", "version": "1.0.0"}"#).unwrap();
    let (original_tarball, _) = publish_common::create_tarball(project, &pkg_json).unwrap();

    // Simulate what the publish loop does for a renamed npm target
    let npm_name = "@tolga/pkg";
    let rewritten =
        publish_common::rewrite_tarball_name(&original_tarball, "@lpm.dev/neo.pkg", npm_name)
            .unwrap();

    // Compute hashes the way provenance does (via integrity_to_sha512_hex)
    let final_hashes = publish_common::compute_hashes(&rewritten);
    let provenance_hex = integrity_to_sha512_hex(&final_hashes.integrity);

    // Independently compute SHA-512 hex directly from the rewritten bytes
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(&rewritten);
    let direct_hex = format!("{:x}", hasher.finalize());

    assert_eq!(
        provenance_hex, direct_hex,
        "provenance hash must match direct SHA-512 of the rewritten tarball"
    );
}

#[test]
fn lpm_renamed_publish_dist_hashes_match_rewritten_tarball() {
    // When the LPM name differs, version_data.dist must be recomputed
    // from the rewritten tarball.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();

    std::fs::write(
        project.join("package.json"),
        r#"{"name": "original-name", "version": "2.0.0"}"#,
    )
    .unwrap();
    std::fs::write(project.join("lib.js"), "module.exports = {}").unwrap();

    let pkg_json: serde_json::Value =
        serde_json::from_str(r#"{"name": "original-name", "version": "2.0.0"}"#).unwrap();
    let (original_tarball, _) = publish_common::create_tarball(project, &pkg_json).unwrap();

    let original_hashes = publish_common::compute_hashes(&original_tarball);

    // Rewrite to LPM name
    let lpm_name = "@lpm.dev/neo.pkg";
    let lpm_tarball =
        publish_common::rewrite_tarball_name(&original_tarball, "original-name", lpm_name).unwrap();
    let lpm_hashes = publish_common::compute_hashes(&lpm_tarball);

    // The dist hashes on the LPM version data should use lpm_hashes, not original_hashes
    assert_ne!(
        original_hashes.shasum, lpm_hashes.shasum,
        "original and rewritten hashes must differ"
    );

    // Simulate what the publish loop now does: recompute dist
    let mut version_data = serde_json::json!({
        "dist": {
            "shasum": original_hashes.shasum,
            "integrity": original_hashes.integrity,
        }
    });

    // Recompute dist metadata from the bytes that will be uploaded.
    if lpm_name != "original-name" {
        version_data["dist"] = serde_json::json!({
            "shasum": lpm_hashes.shasum,
            "integrity": lpm_hashes.integrity,
        });
    }

    assert_eq!(
        version_data["dist"]["shasum"].as_str().unwrap(),
        lpm_hashes.shasum,
        "dist.shasum must match rewritten LPM tarball"
    );
}
