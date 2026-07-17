use super::*;

#[tokio::test]
async fn lpm_install_preflight_refetches_when_requested_version_is_missing_from_fresh_cache() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let cache_dir = tempfile::tempdir().unwrap();
    let package_name = lpm_common::PackageName::parse("@lpm.dev/acme.swift-logger").unwrap();
    let client = lpm_registry::RegistryClient::new()
        .with_base_url(server.uri())
        .with_cache_dir(Some(cache_dir.path().to_path_buf()));

    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/acme.swift-logger"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_metadata(&["1.0.0"], "1.0.0")))
        .expect(1)
        .mount(&server)
        .await;
    client.get_package_metadata(&package_name).await.unwrap();

    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/acme.swift-logger"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(make_metadata(&["1.0.0", "1.0.1"], "1.0.1")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let (metadata, resolved_version) =
        resolve_lpm_install_preflight(&client, &package_name, "1.0.1")
            .await
            .unwrap();

    assert_eq!(resolved_version, "1.0.1");
    assert!(metadata.versions.contains_key(&resolved_version));
}

// ── stage_packages_to_manifest behavior ─────────────────────
//
// These tests cover the stage step in isolation (no install pipeline,
// no transaction guard). The contract for stage:
//
// - Explicit Exact/Range/Wildcard/Workspace user input → write
// verbatim, mark `StagedKind::Final`.
// - Bare reinstall of an existing dep with no rewrite-forcing flag →
// do not touch the manifest, mark `StagedKind::Skipped` (no churn).
// - Bare or dist-tag for a new dep, OR existing dep with a flag →
// write `STAGE_PLACEHOLDER` ("*"), mark `StagedKind::Placeholder`.
// The placeholder is replaced by `finalize_packages_in_manifest`
// once the resolver returns the concrete version.
//
// The end-to-end smoke (placeholder → final spec) is exercised by the
// workflow tests in `tests/workflows/tests/install.rs`; these unit
// tests are the per-branch coverage for the stage logic.

#[test]
fn stage_explicit_exact_writes_to_dependencies_when_save_dev_false() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["react@18.2.0".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    assert_eq!(after["dependencies"]["react"], "18.2.0");
    assert!(after.get("devDependencies").is_none());
    assert_eq!(staged.entries.len(), 1);
    assert!(matches!(staged.entries[0].kind, StagedKind::Final));
    assert!(!staged.needs_finalize());
}

#[test]
fn stage_explicit_exact_writes_to_dev_dependencies_when_save_dev_true() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["vitest@1.0.0".to_string()],
        true,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    assert_eq!(after["devDependencies"]["vitest"], "1.0.0");
    assert!(after.get("dependencies").is_none());
    assert!(matches!(staged.entries[0].kind, StagedKind::Final));
}

#[test]
fn stage_preserves_existing_unrelated_entries() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(
        &pkg_path,
        &serde_json::json!({
            "name": "demo",
            "version": "1.0.0",
            "scripts": {"build": "tsup"},
            "dependencies": {"existing": "1.0.0"},
            "lpm": {"trustedDependencies": ["esbuild"]},
        }),
    );

    // Bare new dep → placeholder.
    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["new-pkg".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    assert_eq!(after["name"], "demo");
    assert_eq!(after["version"], "1.0.0");
    assert_eq!(after["scripts"]["build"], "tsup");
    assert_eq!(after["dependencies"]["existing"], "1.0.0");
    // Bare staging → placeholder, not the legacy `*` final write.
    assert_eq!(after["dependencies"]["new-pkg"], STAGE_PLACEHOLDER);
    assert_eq!(after["lpm"]["trustedDependencies"][0], "esbuild");
    assert!(matches!(staged.entries[0].kind, StagedKind::Placeholder));
    assert!(staged.needs_finalize());
}

#[test]
fn stage_handles_mixed_explicit_and_bare_specs() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &[
            "react@18.2.0".to_string(),
            "lodash@^4.17.0".to_string(),
            "no-version-spec".to_string(),
        ],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    // Explicit Exact + Range → preserved verbatim.
    assert_eq!(after["dependencies"]["react"], "18.2.0");
    assert_eq!(after["dependencies"]["lodash"], "^4.17.0");
    // Bare → placeholder (NOT the legacy `*` final write — finalize
    // would replace this with `^<resolved>`).
    assert_eq!(after["dependencies"]["no-version-spec"], STAGE_PLACEHOLDER);

    assert_eq!(staged.entries.len(), 3);
    assert!(matches!(staged.entries[0].kind, StagedKind::Final));
    assert!(matches!(staged.entries[1].kind, StagedKind::Final));
    assert!(matches!(staged.entries[2].kind, StagedKind::Placeholder));
}

#[test]
fn stage_explicit_spec_overwrites_existing_entry_with_same_name() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(
        &pkg_path,
        &serde_json::json!({
            "name": "demo",
            "dependencies": {"react": "17.0.0"},
        }),
    );

    // Explicit user spec → always rewrites, even when an entry exists.
    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["react@18.2.0".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    assert_eq!(after["dependencies"]["react"], "18.2.0");
    assert!(matches!(staged.entries[0].kind, StagedKind::Final));
}

/// row 12 (no churn): bare reinstall of an existing dep, no
/// rewrite-forcing flag → manifest is NOT touched, entry is Skipped.
#[test]
fn stage_bare_reinstall_of_existing_dep_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(
        &pkg_path,
        &serde_json::json!({
            "name": "demo",
            "dependencies": {"ms": "~2.1.3"},
        }),
    );

    let pre_bytes = std::fs::read(&pkg_path).unwrap();

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["ms".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let post_bytes = std::fs::read(&pkg_path).unwrap();
    // The entry stays exactly as-is.
    assert_eq!(
        post_bytes, pre_bytes,
        "no-churn rule: bare reinstall of an existing dep must not rewrite the manifest"
    );
    let after = read_manifest(&pkg_path);
    assert_eq!(after["dependencies"]["ms"], "~2.1.3");
    assert!(matches!(staged.entries[0].kind, StagedKind::Skipped));
    assert!(!staged.needs_finalize());
}

/// A dist-tag install against an existing dep is NOT a "bare
/// reinstall" — the user typed `@latest`/`@beta`/`@next`, which is
/// explicit input asking for the current value of that tag. Stage must
/// keep the tag literal in the manifest so the resolver honors it, then
/// finalize rewrites the manifest with the resolved version.
///
/// Previously: `lpm install react@latest` on an existing `react: "17.0.0"`
/// entry would hit the Skipped branch and never update the manifest,
/// even though the resolver picked a new version.
#[test]
fn stage_dist_tag_on_existing_dep_writes_tag_literal_not_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(
        &pkg_path,
        &serde_json::json!({
            "name": "demo",
            "dependencies": {"react": "17.0.0"},
        }),
    );

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["react@latest".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    assert_eq!(
        after["dependencies"]["react"], "latest",
        "dist-tag against existing dep must stage the tag literal, not skip — \
         the resolver needs that literal to honor the user's requested tag"
    );
    assert!(
        matches!(staged.entries[0].kind, StagedKind::DistTag),
        "dist-tag intent must produce StagedKind::DistTag, not Skipped; \
         got: {:?}",
        staged.entries[0].kind
    );
}

/// bare reinstall of an existing dep WITH a rewrite-forcing
/// flag → write a placeholder, finalize will replace with the new
/// resolved-version-derived spec. This is the `--exact` opt-in path.
#[test]
fn stage_bare_reinstall_with_exact_flag_writes_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(
        &pkg_path,
        &serde_json::json!({
            "name": "demo",
            "dependencies": {"ms": "~2.1.3"},
        }),
    );

    let flags = crate::save_spec::SaveFlags {
        exact: true,
        ..Default::default()
    };
    let staged = stage_packages_to_manifest(&pkg_path, &["ms".to_string()], false, flags).unwrap();

    let after = read_manifest(&pkg_path);
    // Existing entry was overwritten with the placeholder; finalize
    // would then replace it with the resolved exact version.
    assert_eq!(after["dependencies"]["ms"], STAGE_PLACEHOLDER);
    assert!(matches!(staged.entries[0].kind, StagedKind::Placeholder));
}

#[test]
fn stage_errors_when_manifest_missing() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("does-not-exist").join("package.json");

    let result = stage_packages_to_manifest(
        &absent,
        &["foo".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    );

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("no package.json"));
}

#[test]
fn stage_errors_on_malformed_input_without_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    std::fs::write(&pkg_path, "{not valid json").unwrap();
    let original = std::fs::read_to_string(&pkg_path).unwrap();

    let result = stage_packages_to_manifest(
        &pkg_path,
        &["foo".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    );

    assert!(result.is_err(), "malformed manifest must error");
    // The corrupt file must be left unchanged.
    assert_eq!(std::fs::read_to_string(&pkg_path).unwrap(), original);
}

#[test]
fn stage_writes_atomic_pretty_json_with_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    stage_packages_to_manifest(
        &pkg_path,
        &["foo".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    let raw = std::fs::read_to_string(&pkg_path).unwrap();
    // Pretty-printed with indentation.
    assert!(raw.contains("  \"dependencies\""));
    // Trailing newline.
    assert!(raw.ends_with('\n'));
}

// ── finalize_packages_in_manifest behavior ──────────────────

/// Helper: build a `name → Version` map from `(name, version_str)` pairs.
fn make_resolved(pairs: &[(&str, &str)]) -> HashMap<String, lpm_semver::Version> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_string(), lpm_semver::Version::parse(v).unwrap()))
        .collect()
}

/// end-to-end (stage → finalize): bare install of a fresh dep
/// gets a placeholder at stage, then `^<resolved>` after finalize.
#[test]
fn finalize_bare_replaces_placeholder_with_caret_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["ms".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();
    // Sanity: stage left a placeholder.
    assert_eq!(
        read_manifest(&pkg_path)["dependencies"]["ms"],
        STAGE_PLACEHOLDER
    );

    let resolved = make_resolved(&[("ms", "2.1.3")]);
    finalize_packages_in_manifest(
        &staged,
        &resolved,
        crate::save_spec::SaveFlags::default(),
        crate::save_spec::SaveConfig::default(),
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    assert_eq!(
        after["dependencies"]["ms"], "^2.1.3",
        "finalize must replace `*` placeholder with `^<resolved>`"
    );
}

#[test]
fn finalize_prefer_catalog_policy_rewrites_matching_dep_to_catalog_reference() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["is-positive".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();
    let resolved = make_resolved(&[("is-positive", "2.0.0")]);
    let policy = CatalogSavePolicy {
        mode: lpm_workspace::CatalogMode::Prefer,
        catalogs: HashMap::from([(
            "default".to_string(),
            HashMap::from([("is-positive".to_string(), "^2.0.0".to_string())]),
        )]),
        forced_catalog: None,
    };

    finalize_packages_in_manifest_with_catalog_policy(
        &staged,
        &resolved,
        crate::save_spec::SaveFlags::default(),
        crate::save_spec::SaveConfig::default(),
        &policy,
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    assert_eq!(after["dependencies"]["is-positive"], "catalog:");
}

#[test]
fn finalize_forced_named_catalog_policy_rewrites_matching_dep_to_named_catalog_reference() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["is-positive@2.0.0".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();
    let resolved = make_resolved(&[("is-positive", "2.0.0")]);
    let policy = CatalogSavePolicy {
        mode: lpm_workspace::CatalogMode::Manual,
        catalogs: HashMap::from([(
            "testing".to_string(),
            HashMap::from([("is-positive".to_string(), "^2.0.0".to_string())]),
        )]),
        forced_catalog: Some("testing".to_string()),
    };

    finalize_packages_in_manifest_with_catalog_policy(
        &staged,
        &resolved,
        crate::save_spec::SaveFlags::default(),
        crate::save_spec::SaveConfig::default(),
        &policy,
    )
    .unwrap();

    let after = read_manifest(&pkg_path);
    assert_eq!(after["dependencies"]["is-positive"], "catalog:testing");
}

#[test]
fn finalize_strict_catalog_policy_errors_when_resolved_version_mismatches_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["is-positive@2.0.0".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();
    let resolved = make_resolved(&[("is-positive", "2.0.0")]);
    let policy = CatalogSavePolicy {
        mode: lpm_workspace::CatalogMode::Strict,
        catalogs: HashMap::from([(
            "default".to_string(),
            HashMap::from([("is-positive".to_string(), "^1.0.0".to_string())]),
        )]),
        forced_catalog: None,
    };

    let err = finalize_packages_in_manifest_with_catalog_policy(
        &staged,
        &resolved,
        crate::save_spec::SaveFlags::default(),
        crate::save_spec::SaveConfig::default(),
        &policy,
    )
    .unwrap_err();
    let message = err.to_string();

    assert!(message.contains("catalogMode strict"));
    assert!(message.contains("is-positive@2.0.0"));
    assert!(message.contains("catalog:^1.0.0"));
}

/// Finalize is a no-op when no entries are placeholders.
#[test]
fn finalize_is_noop_when_no_placeholders() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    // Stage explicit-only specs → no deferred finalize entries.
    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["react@18.2.0".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();
    let pre = std::fs::read_to_string(&pkg_path).unwrap();

    finalize_packages_in_manifest(
        &staged,
        &HashMap::new(),
        crate::save_spec::SaveFlags::default(),
        crate::save_spec::SaveConfig::default(),
    )
    .unwrap();

    // Manifest is byte-identical — finalize never opened the file.
    let post = std::fs::read_to_string(&pkg_path).unwrap();
    assert_eq!(pre, post);
}

// ── direct dependency version selection ─────────────────
//
// `collect_direct_versions` avoids a flat name scan over the lockfile,
// which would pick the wrong version (transitive instead of direct) if
// the lockfile ever had multiple entries for the same name. It uses the resolver's
// `is_direct: bool` flag, which is set per `InstallPackage` based on
// membership in the staged manifest's `dependencies` map — so the
// direct/transitive distinction is unambiguous.
//
// These tests build hand-crafted `Vec<InstallPackage>` fixtures that
// include both direct AND transitive entries for the same name, then
// assert that the helper picks ONLY the direct entry. This is the
// load-bearing correctness test for direct dependency version selection.

/// When the same package name has both a direct entry and a transitive
/// entry at different versions, the helper must pick the direct version,
/// regardless of input order.
#[test]
fn collect_direct_versions_picks_direct_over_transitive_same_name() {
    let packages = vec![
        // Transitive `ms@1.5.0` first (e.g., from a legacy-pkg
        // depending on ms@~1.5.0).
        fake_pkg("ms", "1.5.0", false),
        // Direct `ms@2.1.3` second (the user's `lpm install ms`).
        fake_pkg("ms", "2.1.3", true),
        // Unrelated direct dep.
        fake_pkg("legacy-pkg", "1.0.0", true),
    ];

    let map = collect_direct_versions(&packages);

    // The previously flat name scan would have last-write-wins on `ms`,
    // so the result depends on iteration order. Post-fix, only the
    // direct entry is considered, and there's exactly one.
    assert_eq!(
        map.get("ms").map(|v| v.to_string()),
        Some("2.1.3".to_string()),
        "collect_direct_versions must pick the DIRECT ms@2.1.3, \
         not the transitive ms@1.5.0. Got: {:?}",
        map.get("ms").map(|v| v.to_string()),
    );
    assert_eq!(
        map.get("legacy-pkg").map(|v| v.to_string()),
        Some("1.0.0".to_string())
    );
    assert_eq!(
        map.len(),
        2,
        "transitive ms@1.5.0 must NOT appear in the map"
    );
}

/// Reverse the input order: transitive entry comes AFTER the direct
/// entry. The helper still picks the direct one — order-independent.
#[test]
fn collect_direct_versions_picks_direct_regardless_of_input_order() {
    let packages = vec![
        fake_pkg("ms", "2.1.3", true),
        fake_pkg("ms", "1.5.0", false),
    ];
    let map = collect_direct_versions(&packages);
    assert_eq!(
        map.get("ms").map(|v| v.to_string()),
        Some("2.1.3".to_string()),
        "input-order independence: direct entry must be picked even when \
         it appears before the transitive in the input list"
    );
    assert_eq!(map.len(), 1);
}

#[test]
fn strict_integrity_rejects_registry_package_without_integrity() {
    let packages = vec![fake_pkg("legacy-registry-pkg", "1.0.0", true)];
    let err = enforce_registry_integrity_policy(&packages, true, true).unwrap_err();
    assert!(
        err.to_string().contains("legacy-registry-pkg@1.0.0"),
        "error should identify the unverified package, got {err}"
    );
}

#[test]
fn strict_integrity_does_not_apply_to_non_registry_install_packages() {
    let mut package = fake_pkg("local-pkg", "1.0.0", true);
    package.source = "directory+./vendor/local-pkg".to_string();
    enforce_registry_integrity_policy(&[package], true, true).unwrap();
}

#[test]
fn registry_signature_key_match_detects_missing_custom_registry_keys() {
    let signatures = vec![lpm_registry::RegistrySignature {
        keyid: Some("SHA256:npm".to_string()),
        sig: Some("MEUCIQD".to_string()),
    }];
    let custom_keys = vec![lpm_registry::RegistrySigningKey {
        expires: None,
        keyid: "SHA256:custom".to_string(),
        keytype: "ecdsa-sha2-nistp256".to_string(),
        scheme: "ecdsa-sha2-nistp256".to_string(),
        key: String::new(),
    }];
    let npm_keys = vec![lpm_registry::RegistrySigningKey {
        expires: None,
        keyid: "SHA256:npm".to_string(),
        keytype: "ecdsa-sha2-nistp256".to_string(),
        scheme: "ecdsa-sha2-nistp256".to_string(),
        key: String::new(),
    }];

    assert!(
        !crate::registry_signatures::registry_signatures_have_matching_key(
            &signatures,
            &custom_keys
        )
    );
    assert!(
        crate::registry_signatures::registry_signatures_have_matching_key(&signatures, &npm_keys)
    );
}

#[test]
fn parse_bool_env_value_accepts_common_flag_spellings() {
    for value in ["1", "true", "TRUE", " yes ", "on"] {
        assert!(parse_bool_env_value(value, false), "{value:?}");
    }
    for value in ["0", "false", "FALSE", " no ", "off"] {
        assert!(!parse_bool_env_value(value, true), "{value:?}");
    }
    assert!(parse_bool_env_value("maybe", true));
    assert!(!parse_bool_env_value("maybe", false));
}

#[test]
fn parse_positive_usize_or_default_rejects_zero_and_invalid_values() {
    assert_eq!(parse_positive_usize_or_default("8", 3), 8);
    assert_eq!(parse_positive_usize_or_default("0", 3), 3);
    assert_eq!(parse_positive_usize_or_default("not-a-number", 3), 3);
}

#[tokio::test]
async fn registry_signing_keys_for_route_falls_back_to_npm_keys_on_custom_endpoint_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let custom_registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/npm/v1/keys"))
        .respond_with(ResponseTemplate::new(400).set_body_string("custom keys unavailable"))
        .expect(1)
        .mount(&custom_registry)
        .await;

    let npm_registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/npm/v1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [{
                "expires": null,
                "keyid": "SHA256:npm",
                "keytype": "ecdsa-sha2-nistp256",
                "scheme": "ecdsa-sha2-nistp256",
                "key": ""
            }]
        })))
        .expect(1)
        .mount(&npm_registry)
        .await;

    let client = Arc::new(RegistryClient::new().with_npm_registry_url(npm_registry.uri()));
    let route = UpstreamRoute::Custom {
        target: lpm_registry::RegistryTarget {
            base_url: Arc::from(custom_registry.uri()),
            kind: lpm_registry::RegistryKind::NpmCompatible,
        },
        auth: None,
    };
    let signatures = vec![lpm_registry::RegistrySignature {
        keyid: Some("SHA256:npm".to_string()),
        sig: Some("MEUCIQD".to_string()),
    }];

    let keys = crate::registry_signatures::registry_signing_keys_for_route(
        client.as_ref(),
        &route,
        &signatures,
    )
    .await
    .expect("npm keyid match should allow npm key fallback");

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].keyid, "SHA256:npm");
}

#[tokio::test]
async fn registry_signing_keys_for_route_preserves_custom_error_when_npm_keys_do_not_match() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let custom_registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/npm/v1/keys"))
        .respond_with(ResponseTemplate::new(400).set_body_string("custom keys unavailable"))
        .expect(1)
        .mount(&custom_registry)
        .await;

    let npm_registry = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/npm/v1/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [{
                "expires": null,
                "keyid": "SHA256:other",
                "keytype": "ecdsa-sha2-nistp256",
                "scheme": "ecdsa-sha2-nistp256",
                "key": ""
            }]
        })))
        .expect(1)
        .mount(&npm_registry)
        .await;

    let client = Arc::new(RegistryClient::new().with_npm_registry_url(npm_registry.uri()));
    let route = UpstreamRoute::Custom {
        target: lpm_registry::RegistryTarget {
            base_url: Arc::from(custom_registry.uri()),
            kind: lpm_registry::RegistryKind::NpmCompatible,
        },
        auth: None,
    };
    let signatures = vec![lpm_registry::RegistrySignature {
        keyid: Some("SHA256:npm".to_string()),
        sig: Some("MEUCIQD".to_string()),
    }];

    let error = crate::registry_signatures::registry_signing_keys_for_route(
        client.as_ref(),
        &route,
        &signatures,
    )
    .await
    .expect_err("non-matching npm keys must not hide the custom registry error");

    assert!(
        matches!(error, LpmError::Http { status: 400, .. }),
        "expected original custom-registry HTTP 400, got {error:?}"
    );
}

/// Transitive-only packages are EXCLUDED from the map entirely.
/// (They're not eligible for finalize anyway, but the map should be
/// minimal so finalize's missing-version error is meaningful.)
#[test]
fn collect_direct_versions_excludes_pure_transitives() {
    let packages = vec![
        fake_pkg("ms", "1.5.0", false),
        fake_pkg("legacy-pkg", "1.0.0", true),
    ];
    let map = collect_direct_versions(&packages);
    assert!(
        !map.contains_key("ms"),
        "transitive-only entry must not appear"
    );
    assert!(map.contains_key("legacy-pkg"));
    assert_eq!(map.len(), 1);
}

/// Empty input → empty map.
#[test]
fn collect_direct_versions_empty_input_returns_empty_map() {
    let map = collect_direct_versions(&[]);
    assert!(map.is_empty());
}

/// All transitives → empty map. Used by finalize to detect
/// "the resolver dropped my staged dep" via the missing-version error.
#[test]
fn collect_direct_versions_all_transitive_returns_empty_map() {
    let packages = vec![
        fake_pkg("ms", "1.5.0", false),
        fake_pkg("debug", "4.3.4", false),
    ];
    let map = collect_direct_versions(&packages);
    assert!(map.is_empty());
}

/// Versions with prerelease tags must parse correctly.
#[test]
fn collect_direct_versions_handles_prerelease_versions() {
    let packages = vec![fake_pkg("react", "19.0.0-rc.1", true)];
    let map = collect_direct_versions(&packages);
    let v = map.get("react").unwrap();
    assert!(v.is_prerelease());
    assert_eq!(v.to_string(), "19.0.0-rc.1");
}

/// Unparseable versions are silently dropped (with a tracing warn).
/// Finalize will then surface a clean missing-version error for the
/// affected name, instead of panicking on a malformed semver.
#[test]
fn collect_direct_versions_drops_unparseable_versions() {
    let packages = vec![
        fake_pkg("react", "18.2.0", true),
        fake_pkg("broken", "not-a-version", true),
    ];
    let map = collect_direct_versions(&packages);
    assert!(map.contains_key("react"));
    assert!(
        !map.contains_key("broken"),
        "unparseable version must be dropped (finalize will surface a clean error)"
    );
}

/// Finalize errors loudly if a deferred entry has no resolved
/// version in the map. Better to surface this than to silently leave
/// a provisional spec in the manifest.
#[test]
fn finalize_errors_when_resolved_version_missing_for_deferred_entry() {
    let dir = tempfile::tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");
    write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

    let staged = stage_packages_to_manifest(
        &pkg_path,
        &["ms".to_string()],
        false,
        crate::save_spec::SaveFlags::default(),
    )
    .unwrap();

    // Empty resolved map.
    let result = finalize_packages_in_manifest(
        &staged,
        &HashMap::new(),
        crate::save_spec::SaveFlags::default(),
        crate::save_spec::SaveConfig::default(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("ms"));
    assert!(err.contains("provisional spec"));
}

// ── invariant: migration hint on filtered install no-match ──

#[tokio::test]
async fn run_install_filtered_add_no_match_with_fail_flag_includes_d2_hint_for_bare_names() {
    // Filtered install must surface the substring-to-glob migration hint when
    // --fail-if-no-match fires and a filter looks like a bare name.
    let dir = tempfile::tempdir().unwrap();
    write_workspace_for_install_tests(dir.path(), &[("foo", "packages/foo")]);
    let client = lpm_registry::RegistryClient::new();

    let result = run_install_filtered_add(
        &client,
        dir.path(),
        &["react".to_string()],
        false,                // save_dev
        &["app".to_string()], // bare-name filter that matches nothing
        &[],                  // filter_prod
        &[],                  // changed_files_ignore_pattern
        &[],                  // test_pattern
        false,                // workspace_root_flag
        true,                 // fail_if_no_match — required for the error path
        false,                // yes — not exercising the prompt here
        true,                 // json_output
        false,                // allow_new
        false,                // force
        crate::save_spec::SaveFlags::default(),
        None, // catalog_name_override
        None, // script_policy_override
        None, // advisor_override
        None, // min_release_age_override
        &[],
        crate::provenance_fetch::DriftIgnorePolicy::default(), // drift_ignore_policy
        crate::provenance_fetch::VerifyPolicy::default(),      // verify_policy
        None,                                                  // strict_peer_dependencies_override
        false,                                                 // no_engine_strict
        InstallOmitPolicy::default(),
        false, // strict_sandbox
        false, // no_sandbox
        false, // verbose
        false, // audit_after_install
        false, // timing
        crate::lpm_skills_config::LpmSkillsPreference::Config,
    )
    .await;

    assert!(result.is_err(), "fail_if_no_match must error on no match");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("D2"),
        "error must reference design decision D2, got: {err}"
    );
    assert!(
        err.contains("\"*app*\"") || err.contains("\"*/app\""),
        "error must suggest at least one glob form, got: {err}"
    );
}

#[tokio::test]
async fn run_install_filtered_add_no_match_for_glob_filter_does_not_emit_d2_hint() {
    // Negative case: glob filter is already migrated, no hint needed.
    let dir = tempfile::tempdir().unwrap();
    write_workspace_for_install_tests(dir.path(), &[("foo", "packages/foo")]);
    let client = lpm_registry::RegistryClient::new();

    let result = run_install_filtered_add(
        &client,
        dir.path(),
        &["react".to_string()],
        false,
        &["nonexistent-*".to_string()],
        &[],
        &[],
        &[],
        false,
        true,
        false, // yes
        true,
        false,
        false,
        crate::save_spec::SaveFlags::default(),
        None, // catalog_name_override
        None, // script_policy_override
        None, // advisor_override
        None, // min_release_age_override
        &[],
        crate::provenance_fetch::DriftIgnorePolicy::default(), // drift_ignore_policy
        crate::provenance_fetch::VerifyPolicy::default(),      // verify_policy
        None,                                                  // strict_peer_dependencies_override
        false,                                                 // no_engine_strict
        InstallOmitPolicy::default(),
        false, // strict_sandbox
        false, // no_sandbox
        false, // verbose
        false, // audit_after_install
        false, // timing
        crate::lpm_skills_config::LpmSkillsPreference::Config,
    )
    .await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        !err.contains("D2"),
        "glob-only filter must NOT trigger the D2 hint, got: {err}"
    );
}
