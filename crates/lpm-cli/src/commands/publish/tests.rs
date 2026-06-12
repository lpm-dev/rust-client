use super::output::{format_dry_run_files_value, format_publish_retry_detail};
use super::secret_scan::{SecretScanLine, format_secret_scan_human, secret_scan_json};
use super::skills::{compute_skills_digest, ensure_lpm_in_files};
use super::swift::extract_swift_metadata;
use super::target::{deduplicate_targets, resolve_targets};
use super::types::PublishTarget;
use super::version_data::integrity_to_sha512_hex;
use crate::commands::publish_common;
use lpm_runner::lpm_json;
use lpm_security::behavioral::secrets::{SecretMatch, SecretScanResult};

#[test]
fn secret_scan_human_renderer_uses_slim_lines_with_expected_content() {
    let scan = SecretScanResult {
        matches: vec![SecretMatch {
            pattern_name: "stripe_live_secret".to_string(),
            description: "Stripe live secret key".to_string(),
            matched_text: "sk_live_********1234".to_string(),
            line: 7,
            severity: "critical".to_string(),
        }],
        files_scanned: 1,
    };

    let lines = format_secret_scan_human(&scan);
    let joined = lines
        .iter()
        .map(|line| match line {
            SecretScanLine::Warn(message)
            | SecretScanLine::Failed(message)
            | SecretScanLine::Detail(message) => message.as_str(),
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
            && joined.contains("critical sk_live_********1234:7  stripe_live_secret")
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
            matched_text: "ghp_********1234".to_string(),
            line: 3,
            severity: "critical".to_string(),
        }],
        files_scanned: 1,
    };

    let json = secret_scan_json(&scan);

    assert_eq!(json["error"], "secret_scan_failed");
    assert_eq!(json["matches"][0]["pattern"], "github_pat");
    assert_eq!(json["matches"][0]["line"], 3);
    assert_eq!(
        json["hint"],
        "Use --allow-secrets to bypass (not recommended)"
    );
}

#[test]
fn ensure_lpm_in_files_preserves_tabs() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_json_path = dir.path().join("package.json");
    let original = "{\n\t\"name\": \"test\",\n\t\"files\": [\n\t\t\"src/\"\n\t]\n}\n";
    std::fs::write(&pkg_json_path, original).unwrap();

    let pkg_json: serde_json::Value = serde_json::from_str(original).unwrap();
    ensure_lpm_in_files(&pkg_json_path, &pkg_json).unwrap();

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
    let original = "{\n\t\"files\": [\".lpm/skills\", \"src/\"]\n}\n";
    std::fs::write(&pkg_json_path, original).unwrap();

    let pkg_json: serde_json::Value = serde_json::from_str(original).unwrap();
    ensure_lpm_in_files(&pkg_json_path, &pkg_json).unwrap();

    let result = std::fs::read_to_string(&pkg_json_path).unwrap();
    assert_eq!(result, original, "file should be untouched");
}

#[test]
fn skills_digest_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    std::fs::write(skills_dir.join("a.md"), "alpha").unwrap();
    std::fs::write(skills_dir.join("b.md"), "beta").unwrap();

    let d1 = compute_skills_digest(&skills_dir);
    let d2 = compute_skills_digest(&skills_dir);
    assert_eq!(d1, d2, "same content must produce same digest");

    std::fs::write(skills_dir.join("b.md"), "gamma").unwrap();
    let d3 = compute_skills_digest(&skills_dir);
    assert_ne!(d1, d3, "different content must produce different digest");
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
