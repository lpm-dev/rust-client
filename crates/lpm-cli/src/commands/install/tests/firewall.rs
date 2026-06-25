use super::*;
use crate::commands::install::firewall::{
    DEFAULT_NPM_FIREWALL_CHUNK_SIZE, NpmFirewallLookupMode, NpmFirewallPreflightStats,
    npm_firewall_chunk_size, npm_firewall_package, npm_firewall_package_from_selected_event,
};
use crate::npm_firewall_config::NpmFirewallMode;

fn package_with_source(name: &str, source: &str) -> InstallPackage {
    InstallPackage {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        source: source.to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct: false,
        is_lpm: false,
        peers: Vec::new(),
        integrity: Some("sha512-test".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: Some("2025-01-01T00:00:00.000Z".to_string()),
        platform: None,
        optional: false,
        tarball_url: Some("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz".to_string()),
        metadata_checked_for_tarball: true,
    }
}

fn firewall_client() -> lpm_registry::RegistryClient {
    lpm_registry::RegistryClient::new().with_base_url("https://lpm.dev")
}

#[test]
fn npm_firewall_mode_parses_report_and_enforce_values() {
    assert_eq!(
        NpmFirewallMode::parse("report"),
        Some(NpmFirewallMode::Report)
    );
    assert_eq!(NpmFirewallMode::parse("1"), Some(NpmFirewallMode::Enforce));
    assert_eq!(
        NpmFirewallMode::parse("TRUE"),
        Some(NpmFirewallMode::Enforce)
    );
    assert_eq!(
        NpmFirewallMode::parse(" Report "),
        Some(NpmFirewallMode::Report)
    );
}

#[test]
fn npm_firewall_mode_rejects_unrecognized_values() {
    assert_eq!(NpmFirewallMode::parse("maybe"), None);
}

#[test]
fn npm_firewall_lookup_mode_parses_package_only_values() {
    assert_eq!(
        NpmFirewallLookupMode::from_env_value(Some("package-only")),
        NpmFirewallLookupMode::PackageOnly
    );
    assert_eq!(
        NpmFirewallLookupMode::from_env_value(Some("package_version")),
        NpmFirewallLookupMode::PackageOnly
    );
}

#[test]
fn npm_firewall_lookup_mode_defaults_to_package_only() {
    assert_eq!(
        NpmFirewallLookupMode::from_env_value(Some("maybe")),
        NpmFirewallLookupMode::PackageOnly
    );
}

#[test]
fn npm_firewall_lookup_mode_accepts_integrity_debug_values() {
    assert_eq!(
        NpmFirewallLookupMode::from_env_value(Some("package-and-integrity")),
        NpmFirewallLookupMode::PackageAndIntegrity
    );
}

#[test]
fn npm_firewall_chunk_size_uses_positive_values_or_default() {
    assert_eq!(npm_firewall_chunk_size("128"), 128);
    assert_eq!(
        npm_firewall_chunk_size("0"),
        DEFAULT_NPM_FIREWALL_CHUNK_SIZE
    );
    assert_eq!(
        npm_firewall_chunk_size("not-a-number"),
        DEFAULT_NPM_FIREWALL_CHUNK_SIZE
    );
}

#[test]
fn npm_firewall_mode_disables_tarball_prefetch_when_enabled() {
    assert!(NpmFirewallMode::Report.disables_tarball_prefetch());
    assert!(NpmFirewallMode::Enforce.disables_tarball_prefetch());
    assert!(!NpmFirewallMode::Off.disables_tarball_prefetch());
}

#[test]
fn npm_firewall_mode_uses_auth_only_for_enforce_mode() {
    assert_eq!(
        NpmFirewallMode::Report.auth_posture(),
        lpm_registry::client::AuthPosture::AnonymousPreferred
    );
    assert_eq!(
        NpmFirewallMode::Enforce.auth_posture(),
        lpm_registry::client::AuthPosture::AuthRequired
    );
}

#[test]
fn npm_firewall_stats_serializes_timing_and_verdict_counts() {
    let mut stats = NpmFirewallPreflightStats {
        mode: NpmFirewallMode::Report,
        checked_count: 12,
        batch_ms: 34,
        chunk_count: 2,
        chunk_sum_ms: 30,
        chunk_max_ms: 21,
        ..NpmFirewallPreflightStats::default()
    };
    stats.record_summary(lpm_registry::client::NpmFirewallSummary {
        total: 12,
        allow: 9,
        warn: 1,
        block: 0,
        unknown: 2,
        matched: 1,
    });
    stats.record_worker_diagnostics(Some(lpm_registry::client::NpmFirewallDiagnostics {
        package_count: 12,
        lookup_concurrency: 64,
        kv_read_count: 14,
        kv_lookup_ms: 8.0,
        entitlement_ms: 1.0,
        parse_ms: 2.0,
        total_ms: 11.0,
        matched_count: 1,
        decision_detail: Some("actionable".to_string()),
        returned_decision_count: 1,
        kv_namespace_label: Some("test".to_string()),
        flagged_package_index: Some(
            lpm_registry::client::NpmFirewallFlaggedPackageIndexDiagnostics {
                enabled: true,
                used: true,
                status: Some("hit".to_string()),
                cache_status: Some("miss-l1".to_string()),
                key: Some("test-index".to_string()),
                read_ms: 2.0,
                package_key_count: 1,
                candidate_count: 1,
                detail_read_count: 1,
                skipped_package_lookup_count: 11,
                generated_at: Some("2026-06-24T00:00:00.000Z".to_string()),
            },
        ),
        match_sources: lpm_registry::client::NpmFirewallMatchSources {
            integrity: 1,
            package: 0,
            none: 11,
        },
        lookup_duration: lpm_registry::client::NpmFirewallLookupDuration {
            count: 12,
            sum_ms: 70.0,
            max_ms: 9.0,
            p50_ms: 5.0,
            p95_ms: 9.0,
        },
    }));
    stats.record_client_timing(Some(lpm_registry::client::NpmFirewallClientTiming {
        request_ms: 21,
        body_read_ms: 3,
        json_parse_ms: 4,
        total_ms: 28,
        request_body_bytes: 2048,
        response_body_bytes: 4096,
    }));

    let json = stats.to_json();

    assert_eq!(json["enabled"], true);
    assert_eq!(json["mode"], "report");
    assert_eq!(json["lookup_mode"], "package_only");
    assert_eq!(json["checked_count"], 12);
    assert_eq!(json["batch_ms"], 34);
    assert_eq!(json["chunk_count"], 2);
    assert_eq!(json["chunk_sum_ms"], 30);
    assert_eq!(json["chunk_max_ms"], 21);
    assert_eq!(json["allow_count"], 9);
    assert_eq!(json["warn_count"], 1);
    assert_eq!(json["block_count"], 0);
    assert_eq!(json["unknown_count"], 2);
    assert_eq!(json["matched_count"], 1);
    assert_eq!(json["worker"]["lookupConcurrency"], 64);
    assert_eq!(json["worker"]["kvReadCount"], 14);
    assert_eq!(json["worker"]["decisionDetail"], "actionable");
    assert_eq!(json["worker"]["returnedDecisionCount"], 1);
    assert_eq!(json["worker"]["kvNamespaceLabel"], "test");
    assert_eq!(json["worker"]["flaggedPackageIndex"]["enabled"], true);
    assert_eq!(json["worker"]["flaggedPackageIndex"]["used"], true);
    assert_eq!(json["worker"]["flaggedPackageIndex"]["status"], "hit");
    assert_eq!(
        json["worker"]["flaggedPackageIndex"]["skippedPackageLookupCount"],
        11
    );
    assert_eq!(json["worker"]["matchSources"]["integrity"], 1);
    assert_eq!(json["worker"]["lookupDuration"]["p95Ms"], 9.0);
    assert_eq!(json["client"]["requestMs"], 21);
    assert_eq!(json["client"]["bodyReadMs"], 3);
    assert_eq!(json["client"]["jsonParseMs"], 4);
    assert_eq!(json["client"]["totalMs"], 28);
    assert_eq!(json["client"]["requestBodyBytes"], 2048);
    assert_eq!(json["client"]["responseBodyBytes"], 4096);
}

#[test]
fn npm_firewall_package_includes_public_npm_registry_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("left-pad", "registry+https://registry.npmjs.org");

    let verdict_package = npm_firewall_package(
        &package,
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageAndIntegrity,
    )
    .expect("public npm package is eligible");

    assert_eq!(verdict_package.name, "left-pad");
    assert_eq!(verdict_package.integrity.as_deref(), Some("sha512-test"));
    assert_eq!(
        verdict_package.published_at.as_deref(),
        Some("2025-01-01T00:00:00.000Z")
    );
}

#[test]
fn npm_firewall_package_includes_public_npm_registry_from_npmrc() {
    let client = firewall_client();
    for (registry, source) in [
        (
            "https://registry.npmjs.org/",
            "registry+https://registry.npmjs.org",
        ),
        (
            "https://registry.npmjs.org:443/",
            "registry+https://registry.npmjs.org:443",
        ),
        (
            "https://registry.npmjs.com/",
            "registry+https://registry.npmjs.com",
        ),
        (
            "https://registry.npmjs.com:443/",
            "registry+https://registry.npmjs.com:443",
        ),
        (
            "https://REGISTRY.NPMJS.ORG/",
            "registry+https://REGISTRY.NPMJS.ORG",
        ),
    ] {
        let npmrc = lpm_registry::NpmrcConfig::parse(
            &format!("registry={registry}\n"),
            "test-npmrc",
            &|_| None,
        );
        let route_table = RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let package = package_with_source("left-pad", source);

        let verdict_package = npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity,
        )
        .expect("explicit public npm registry is eligible");

        assert_eq!(verdict_package.name, "left-pad");
        assert_eq!(verdict_package.integrity.as_deref(), Some("sha512-test"));
    }
}

#[test]
fn npm_firewall_package_includes_public_npm_routed_through_lpm_proxy() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("left-pad", "registry+https://lpm.dev");

    let verdict_package = npm_firewall_package(
        &package,
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageOnly,
    )
    .expect("public npm through lpm.dev proxy is eligible");

    assert_eq!(verdict_package.name, "left-pad");
    assert_eq!(verdict_package.version, "1.0.0");
}

#[test]
fn npm_firewall_package_can_omit_integrity_for_package_only_lookup() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("left-pad", "registry+https://registry.npmjs.org");

    let verdict_package = npm_firewall_package(
        &package,
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageOnly,
    )
    .expect("public npm package is eligible");

    assert_eq!(verdict_package.name, "left-pad");
    assert_eq!(verdict_package.integrity.as_deref(), None);
}

#[test]
fn npm_firewall_package_skips_custom_registry_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("private-pkg", "registry+https://registry.internal.test");

    assert!(
        npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[test]
fn npm_firewall_package_skips_lpm_same_origin_custom_registry_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("private-pkg", "registry+https://lpm.dev/private-registry");

    assert!(
        npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[test]
fn npm_firewall_package_skips_lpm_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let package = package_with_source("@lpm.dev/private", "registry+https://lpm.dev");

    assert!(
        npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[test]
fn npm_firewall_package_skips_incompatible_platform_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let mut package = package_with_source("left-pad", "registry+https://registry.npmjs.org");
    package.platform = Some(lpm_resolver::PlatformMeta {
        os: vec!["definitely-not-this-os".to_string()],
        cpu: Vec::new(),
        libc: Vec::new(),
    });

    assert!(
        npm_firewall_package(
            &package,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}

#[test]
fn npm_firewall_package_from_selected_event_uses_package_only_lookup() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let event = lpm_resolver::SelectedPackageEvent {
        name: "left-pad".to_string(),
        version: "1.0.0".to_string(),
        is_lpm: false,
        tarball_url: None,
        integrity: Some("sha512-test".to_string()),
        platform: None,
        optional: false,
    };

    let verdict_package = npm_firewall_package_from_selected_event(
        &event,
        &route_table,
        &client,
        NpmFirewallLookupMode::PackageOnly,
    )
    .expect("public npm package is eligible");

    assert_eq!(verdict_package.name, "left-pad");
    assert_eq!(verdict_package.version, "1.0.0");
    assert_eq!(verdict_package.integrity.as_deref(), None);
}

#[test]
fn npm_firewall_package_from_selected_event_includes_public_npm_registry_from_npmrc() {
    let client = firewall_client();
    for registry in [
        "https://registry.npmjs.org/",
        "https://registry.npmjs.org:443/",
        "https://registry.npmjs.com/",
        "https://registry.npmjs.com:443/",
        "https://REGISTRY.NPMJS.ORG/",
    ] {
        let npmrc = lpm_registry::NpmrcConfig::parse(
            &format!("registry={registry}\n"),
            "test-npmrc",
            &|_| None,
        );
        let route_table = RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let event = lpm_resolver::SelectedPackageEvent {
            name: "left-pad".to_string(),
            version: "1.0.0".to_string(),
            is_lpm: false,
            tarball_url: None,
            integrity: Some("sha512-test".to_string()),
            platform: None,
            optional: false,
        };

        let verdict_package = npm_firewall_package_from_selected_event(
            &event,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageOnly,
        )
        .expect("explicit public npm registry is eligible");

        assert_eq!(verdict_package.name, "left-pad");
        assert_eq!(verdict_package.integrity.as_deref(), None);
    }
}

#[test]
fn npm_firewall_package_from_selected_event_skips_incompatible_platform_package() {
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = firewall_client();
    let event = lpm_resolver::SelectedPackageEvent {
        name: "left-pad".to_string(),
        version: "1.0.0".to_string(),
        is_lpm: false,
        tarball_url: None,
        integrity: Some("sha512-test".to_string()),
        platform: Some(lpm_resolver::PlatformMeta {
            os: vec!["definitely-not-this-os".to_string()],
            cpu: Vec::new(),
            libc: Vec::new(),
        }),
        optional: true,
    };

    assert!(
        npm_firewall_package_from_selected_event(
            &event,
            &route_table,
            &client,
            NpmFirewallLookupMode::PackageAndIntegrity
        )
        .is_none()
    );
}
