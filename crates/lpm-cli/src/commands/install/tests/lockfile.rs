use super::*;

// ─── split-context dedup ────────────────────────────
//
// Bug: `resolved_to_install_packages` maps `ResolverPackage` → canonical
// name via `canonical_name()`, which strips the split
// `context` suffix. When the resolver emits multiple ResolvedPackage
// rows for the same `(canonical_name, version)` — one per split scope
// — the previously implementation produced N identical `InstallPackage`
// rows. Downstream, `link_finalize` spawned N parallel // symlink-creation tasks for the same root path, which raced on
// `std::os::unix::fs::symlink` and returned `EEXIST` to whichever
// thread lost, aborting the install with
// "IO error: File exists (os error 17)".
//
// Reproduced on the decision-gate fixture (`eslint@^9` + `ajv@^8`
// restored) in ~4 of 5 `--json` cold installs before this fix.
//
// Contract: `resolved_to_install_packages` must collapse duplicates
// by `(canonical_name, version)` so every downstream stage sees one
// row per physical package.

use lpm_resolver::NpmVersion;
use lpm_resolver::ResolverPackage;

fn fake_resolved(name: &str, version: &str, context: Option<&str>) -> ResolvedPackage {
    let pkg = match context {
        Some(ctx) => ResolverPackage::npm(name).with_context(ctx),
        None => ResolverPackage::npm(name),
    };
    ResolvedPackage {
        package: pkg,
        version: NpmVersion::parse(version).expect("valid version"),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        peers: Vec::new(),
        tarball_url: None,
        integrity: None,
        platform: None,
        node_engine: None,
        optional: false,
    }
}

#[test]
fn prepare_override_resolution_state_resolves_catalog_backed_override_maps() {
    let mut package = lpm_workspace::PackageJson {
        catalogs: HashMap::from([
            (
                "default".to_string(),
                HashMap::from([("react".to_string(), "^19.0.0".to_string())]),
            ),
            (
                "testing".to_string(),
                HashMap::from([("left-pad".to_string(), "~1.3.0".to_string())]),
            ),
        ]),
        overrides: HashMap::from([("left-pad".to_string(), "catalog:testing".to_string())]),
        resolutions: HashMap::from([("chalk".to_string(), "^5.0.0".to_string())]),
        ..Default::default()
    };
    package.lpm = Some(lpm_workspace::LpmConfig {
        overrides: HashMap::from([("react".to_string(), "catalog:".to_string())]),
        ..Default::default()
    });
    let mut catalog_resolutions = vec![lpm_workspace::CatalogProtocolResolution {
        catalog_name: "default".to_string(),
        package_name: "existing".to_string(),
        reference: "catalog:".to_string(),
        specifier: "^1.0.0".to_string(),
    }];

    let state = prepare_override_resolution_state(OverrideResolutionInput {
        package: &package,
        workspace: None,
        catalog_resolutions: &mut catalog_resolutions,
    })
    .expect("catalog-backed overrides should resolve");

    assert_eq!(
        state.lpm_overrides.get("react").map(String::as_str),
        Some("^19.0.0")
    );
    assert_eq!(
        state.overrides.as_ref().get("left-pad").map(String::as_str),
        Some("~1.3.0")
    );
    assert_eq!(
        state.resolutions.as_ref().get("chalk").map(String::as_str),
        Some("^5.0.0")
    );
    assert_eq!(state.override_set.len(), 3);
    assert_eq!(state.dependency_catalog_resolution_count, 1);
    assert_eq!(state.override_catalog_resolutions.len(), 2);
    assert_eq!(catalog_resolutions.len(), 3);
}

#[test]
fn resolved_to_install_packages_dedups_p4_split_duplicates() {
    // Four resolver outputs for `cross-spawn@7.0.6`: one un-scoped
    // + three scoped under different parents. `canonical_name()`
    // collapses all four to `"cross-spawn"`.
    let resolved = vec![
        fake_resolved("cross-spawn", "7.0.6", None),
        fake_resolved("cross-spawn", "7.0.6", Some("parent1")),
        fake_resolved("cross-spawn", "7.0.6", Some("parent2")),
        fake_resolved("cross-spawn", "7.0.6", Some("parent3")),
    ];
    let deps: HashMap<String, String> = [("cross-spawn".to_string(), "^7.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        &RegistryClient::new(),
    );

    assert_eq!(
        installed.len(),
        1,
        "split contexts for the same (canonical_name, version) \
         MUST dedup to exactly one InstallPackage row — got {} rows. \
         Duplicates cascade into link_pairs and race link_finalize's \
         root symlink creation.",
        installed.len(),
    );
    assert_eq!(installed[0].name, "cross-spawn");
    assert_eq!(installed[0].version, "7.0.6");
    assert!(
        installed[0].is_direct,
        "direct_target_names contains 'cross-spawn', merged row must be direct"
    );
    assert_eq!(
        installed[0].root_link_names.as_deref(),
        Some(&["cross-spawn".to_string()][..]),
        "root_link_names comes from root_link_map keyed on \
         (canonical_name, version) — must survive dedup"
    );
}

// ──.5 lockfile repair gate ─────────────────
//
// The gate's contract:
// - v2+ lockfile (authoritative schema): trust empty
// `ambient-peer-installs` as "no ambient installs."
// - v1 lockfile + `auto_install_peers = true`: discard.
// - v1 lockfile + `auto_install_peers = false`: trust (no
// ambient installs were ever performed under opt-out).
//
// These tests pin the four-way truth table so a future schema
// bump or precedence change can't silently re-open the hole.

fn make_lockfile_with_version(v: u32) -> lpm_lockfile::Lockfile {
    let mut lf = lpm_lockfile::Lockfile::new();
    lf.metadata.lockfile_version = v;
    lf
}

#[test]
fn peer_state_repair_gate_v2_lockfile_with_auto_install_takes_fast_path() {
    // The current happy path: v2 lockfile, auto-install on,
    // schema is authoritative. Don't repair.
    let lf = make_lockfile_with_version(MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE);
    assert!(
        !lockfile_needs_peer_state_repair(&lf, true),
        "v2 lockfile with auto-install on must take fast path — \
         empty ambient-peer-installs is authoritative"
    );
}

#[test]
fn peer_state_repair_gate_v1_lockfile_with_auto_install_forces_repair() {
    // The load-bearing test. A v1 lockfile under
    // `auto_install_peers = true` is suspect: it may be missing
    // peer-tracking state. Discard fast path so a
    // fresh resolve repopulates the new fields.
    let lf = make_lockfile_with_version(1);
    assert!(
        lockfile_needs_peer_state_repair(&lf, true),
        "v1 lockfile under auto_install_peers=true must force \
         fresh resolve — the silent ambient-peer-installs hole \
         that cannot be repaired any other way"
    );
}

#[test]
fn peer_state_repair_gate_v1_lockfile_with_auto_install_off_takes_fast_path() {
    // The opt-out path: with `auto_install_peers = false`, no
    // ambient installs were ever performed, so a v1 lockfile is
    // correct as-is. Honor it.
    let lf = make_lockfile_with_version(1);
    assert!(
        !lockfile_needs_peer_state_repair(&lf, false),
        "v1 lockfile under auto_install_peers=false must take \
         fast path — opt-out installs never produced ambient peers"
    );
}

#[test]
fn peer_state_repair_gate_v2_lockfile_with_auto_install_off_takes_fast_path() {
    // Sanity baseline: v2 + opt-out → trust fast path. Symmetric
    // with the v2 + on case above; covered for completeness so
    // no future logic branch can silently invert it.
    let lf = make_lockfile_with_version(MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE);
    assert!(!lockfile_needs_peer_state_repair(&lf, false));
}

#[test]
fn fresh_lockfiles_use_current_schema_version() {
    assert_eq!(
        lpm_lockfile::LOCKFILE_VERSION,
        lpm_lockfile::LOCKFILE_VERSION_WITH_PROVENANCE
    );
    let lf = lpm_lockfile::Lockfile::new();
    assert_eq!(lf.metadata.lockfile_version, lpm_lockfile::LOCKFILE_VERSION);
}

#[test]
fn resolved_to_install_packages_keeps_distinct_versions() {
    // Different versions of the same name must NOT be deduped — only
    // the (canonical_name, version) tuple is the dedup key. Both
    // 5.6.2 and 4.1.2 need their own `.lpm/` store entries.
    let resolved = vec![
        fake_resolved("chalk", "5.6.2", None),
        fake_resolved("chalk", "4.1.2", Some("parent1")),
    ];
    let deps: HashMap<String, String> = [("chalk".to_string(), "^5.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        &RegistryClient::new(),
    );

    assert_eq!(installed.len(), 2, "distinct versions must be preserved");
    let mut versions: Vec<String> = installed.iter().map(|p| p.version.clone()).collect();
    versions.sort();
    assert_eq!(versions, vec!["4.1.2".to_string(), "5.6.2".to_string()]);
}

#[test]
fn resolved_to_install_packages_keeps_direct_root_link_when_ambient_peer_has_same_name() {
    let resolved = vec![
        fake_resolved("vite", "6.3.5", None),
        fake_resolved("@vitejs/plugin-react", "1.0.0", None),
        fake_resolved("vite", "8.0.16", Some("@vitejs/plugin-react")),
    ];
    let deps: HashMap<String, String> = [
        ("vite".to_string(), "6.3.5".to_string()),
        ("@vitejs/plugin-react".to_string(), "1.0.0".to_string()),
    ]
    .into();
    let ambient_peer_installs = vec!["vite".to_string()];

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &ambient_peer_installs,
        &HashMap::new(),
        &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        &RegistryClient::new(),
    );

    let direct = installed
        .iter()
        .find(|package| package.name == "vite" && package.version == "6.3.5")
        .expect("direct vite version should be installed");
    assert_eq!(
        direct.root_link_names.as_deref(),
        Some(&["vite".to_string()][..])
    );
    assert!(direct.is_direct);

    let ambient = installed
        .iter()
        .find(|package| package.name == "vite" && package.version == "8.0.16")
        .expect("ambient peer vite version should be installed");
    assert_eq!(ambient.root_link_names.as_deref(), None);
    assert!(!ambient.is_direct);
}

#[test]
fn resolved_to_install_packages_prefers_unscoped_root_candidate_for_non_semver_direct_spec() {
    let resolved = vec![
        fake_resolved("vite", "6.3.5", None),
        fake_resolved("@vitejs/plugin-react", "1.0.0", None),
        fake_resolved("vite", "8.0.16", Some("@vitejs/plugin-react")),
    ];
    let deps: HashMap<String, String> = [
        ("vite".to_string(), "file:../local-vite".to_string()),
        ("@vitejs/plugin-react".to_string(), "1.0.0".to_string()),
    ]
    .into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &[],
        &HashMap::new(),
        &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        &RegistryClient::new(),
    );

    let direct = installed
        .iter()
        .find(|package| package.name == "vite" && package.version == "6.3.5")
        .expect("unscoped vite candidate should be installed");
    assert_eq!(
        direct.root_link_names.as_deref(),
        Some(&["vite".to_string()][..])
    );
    assert!(direct.is_direct);

    let transitive = installed
        .iter()
        .find(|package| package.name == "vite" && package.version == "8.0.16")
        .expect("scoped transitive vite candidate should be installed");
    assert_eq!(transitive.root_link_names.as_deref(), None);
    assert!(!transitive.is_direct);
}

#[test]
fn resolved_to_install_packages_dedups_preserves_first_order() {
    // When the resolver emits the un-scoped entry first, that's the
    // one whose fields we keep. Later scoped copies are discarded.
    // Stability matters — downstream consumers (lockfile writer,
    // snapshot tests) assume a deterministic order.
    let resolved = vec![
        fake_resolved("nanoid", "3.3.11", None),
        fake_resolved("nanoid", "3.3.11", Some("parent1")),
        fake_resolved("nanoid", "3.3.11", Some("parent2")),
    ];
    let deps: HashMap<String, String> = [("nanoid".to_string(), "^3.3.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        &RegistryClient::new(),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].version, "3.3.11");
}

// ── (reviewed): route-table-aware source URL ──────────────
// Confirms `resolved_to_install_packages` now produces source
// strings that reflect the active RouteTable instead of a
// hardcoded npmjs.org default. This realizes the
// motivation for URL-keyed source_id at the install pipeline
// layer.

#[test]
fn registry_source_url_for_uses_lpm_dev_for_lpm_scope() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    assert_eq!(
        registry_source_url_for("@lpm.dev/foo.bar", &route_table, &RegistryClient::new()),
        "https://lpm.dev"
    );
}

#[test]
fn registry_source_url_for_uses_npmjs_default_for_unscoped() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    assert_eq!(
        registry_source_url_for("react", &route_table, &RegistryClient::new()),
        "https://registry.npmjs.org"
    );
}

#[test]
fn registry_source_url_for_uses_active_client_origins() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let client = RegistryClient::new()
        .with_base_url("https://lpm.internal.example/api")
        .with_npm_registry_url("https://npm.internal.example");

    assert_eq!(
        registry_source_url_for("@lpm.dev/foo.bar", &route_table, &client),
        "https://lpm.internal.example/api"
    );
    assert_eq!(
        registry_source_url_for("react", &route_table, &client),
        "https://npm.internal.example"
    );
}

#[test]
fn registry_source_url_for_treats_worker_proxy_as_npm_transport() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Proxy);
    let client = RegistryClient::new()
        .with_base_url("https://lpm.internal.example")
        .with_npm_registry_url("https://npm.internal.example");

    assert_eq!(
        registry_source_url_for("react", &route_table, &client),
        "https://npm.internal.example",
        "the Worker proxy and its direct fallback are transports for one logical npm source"
    );
}

#[test]
fn resolved_to_install_packages_uses_lpm_dev_for_lpm_scope() {
    let resolved = vec![fake_resolved("@lpm.dev/foo.bar", "1.0.0", None)];
    let deps: HashMap<String, String> =
        [("@lpm.dev/foo.bar".to_string(), "^1.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        &RegistryClient::new(),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].source, "registry+https://lpm.dev");
}

#[test]
fn resolved_to_install_packages_default_npmjs_for_non_lpm_no_npmrc() {
    // Without an `.npmrc` override, non-`@lpm.dev` packages get
    // the npmjs.org default — preserving previously behavior.
    let resolved = vec![fake_resolved("react", "19.0.0", None)];
    let deps: HashMap<String, String> = [("react".to_string(), "^19.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        &RegistryClient::new(),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(
        installed[0].source, "registry+https://registry.npmjs.org",
        "no .npmrc override → npmjs.org default"
    );
}

#[test]
fn resolved_to_install_packages_carries_registry_signature_metadata() {
    let signature = lpm_registry::RegistrySignature {
        keyid: Some("SHA256:test-key".to_string()),
        sig: Some("base64-signature".to_string()),
    };
    let mut dist = HashMap::new();
    dist.insert(
        "1.0.0".to_string(),
        lpm_resolver::CachedDistInfo {
            tarball_url: Some("https://registry.npmjs.org/signed/-/signed-1.0.0.tgz".into()),
            integrity: Some("sha512-test".to_string()),
            signatures: vec![signature.clone()],
            published_at: Some("2026-01-02T03:04:05.000Z".to_string()),
            published_at_unix: Some(1_767_323_045),
            trust_evidence: None,
        },
    );
    let mut resolver_cache = HashMap::new();
    resolver_cache.insert(
        lpm_resolver::CanonicalKey::npm("signed"),
        Arc::new(lpm_resolver::CachedPackageInfo {
            modified: None,
            modified_unix: None,
            trust_metadata_complete: false,
            versions_complete: true,
            covered_ranges: std::collections::HashSet::new(),
            latest_version: None,
            versions: vec![NpmVersion::parse("1.0.0").unwrap()],
            deps: HashMap::new(),
            peer_deps: HashMap::new(),
            optional_dep_names: HashMap::new(),
            optional_peer_names: HashMap::new(),
            node_engines: HashMap::new(),
            bundled_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist,
            aliases: HashMap::new(),
        }),
    );

    let resolved = vec![fake_resolved("signed", "1.0.0", None)];
    let deps: HashMap<String, String> = [("signed".to_string(), "^1.0.0".to_string())].into();
    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &[],
        &resolver_cache,
        &lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
        &RegistryClient::new(),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].registry_signatures, vec![signature]);
    assert_eq!(
        installed[0].registry_published_at.as_deref(),
        Some("2026-01-02T03:04:05.000Z")
    );
}

#[test]
fn resolved_to_install_packages_uses_npmrc_override_when_present() {
    // The headline reviewed fix: an `.npmrc`-mapped package
    // gets filed under the actual mirror URL, so its source_id
    // distinguishes a mirror copy from an npmjs.org copy.
    use lpm_registry::NpmrcConfig;

    let mirror = "https://npm.internal.example";
    let npmrc_text = format!("registry={mirror}\n");
    let npmrc = NpmrcConfig::parse(&npmrc_text, "test-npmrc", &|_| None);
    let route_table =
        lpm_registry::RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();

    let resolved = vec![fake_resolved("react", "19.0.0", None)];
    let deps: HashMap<String, String> = [("react".to_string(), "^19.0.0".to_string())].into();

    let installed = resolved_to_install_packages(
        &resolved,
        &deps,
        &HashMap::new(),
        &[], // tests don't exercise ambient peer installs
        &HashMap::new(),
        &route_table,
        &RegistryClient::new(),
    );

    assert_eq!(installed.len(), 1);
    assert_eq!(
        installed[0].source,
        format!("registry+{mirror}"),
        ".npmrc default-registry override must reach the InstallPackage source"
    );

    // The corresponding source_id must reflect the mirror URL —
    // proving the motivation now holds end-to-end.
    let mirror_id = lpm_lockfile::Source::Registry {
        url: mirror.to_string(),
    }
    .source_id();
    let npmjs_id = lpm_lockfile::Source::Registry {
        url: "https://registry.npmjs.org".to_string(),
    }
    .source_id();
    assert_ne!(
        mirror_id, npmjs_id,
        "mirror and npmjs source_ids must be distinct (regression check)"
    );
}

// ── lockfile repair and URL gate tests ───────────────────────

#[test]
fn tarball_not_found_error_preserves_project_lockfiles_byte_for_byte() {
    let proj = tempfile::tempdir().unwrap();
    let project_dir = proj.path();

    let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lockb_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
    let lock_bytes = b"# existing lockfile\n";
    let lockb_bytes = b"LPMBfake\0bytes";
    std::fs::write(&lock_path, lock_bytes).unwrap();
    std::fs::write(&lockb_path, lockb_bytes).unwrap();

    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let deps = HashMap::from([("some-pkg".to_string(), "1.0.0".to_string())]);
    let packages = resolved_to_install_packages(
        &[fake_resolved("some-pkg", "1.0.0", None)],
        &deps,
        &HashMap::new(),
        &[],
        &HashMap::new(),
        &route_table,
        &RegistryClient::new(),
    );
    let client = Arc::new(RegistryClient::new());
    let err = artifact_unavailable_error(
        &client,
        &route_table,
        &packages[0],
        ArtifactSelection::LockfileReplay,
    );

    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_bytes,
        "tarball failures must preserve lpm.lock byte-for-byte"
    );
    assert_eq!(
        std::fs::read(&lockb_path).unwrap(),
        lockb_bytes,
        "tarball failures must preserve lpm.lockb byte-for-byte"
    );
    assert!(
        matches!(
            err,
            LpmError::ArtifactUnavailable(ref context)
                if context.package == "some-pkg"
                    && context.version == "1.0.0"
                    && context.lockfiles_preserved
                    && context.suggested_command.as_deref() == Some("lpm upgrade some-pkg")
        ) && err.to_string().contains("pins were preserved"),
        "error must identify the pinned artifact and preserved lockfiles: {err}"
    );
}

#[test]
fn fresh_resolution_artifact_failure_preserves_existing_project_lockfiles() {
    let proj = tempfile::tempdir().unwrap();
    let project_dir = proj.path();

    let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lockb_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
    let lock_bytes = b"# stale existing lockfile\n";
    let lockb_bytes = b"LPMBstale-existing";
    std::fs::write(&lock_path, lock_bytes).unwrap();
    std::fs::write(&lockb_path, lockb_bytes).unwrap();

    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let deps = HashMap::from([("overlap-pkg".to_string(), "1.0.0".to_string())]);
    let packages = resolved_to_install_packages(
        &[fake_resolved("overlap-pkg", "1.0.0", None)],
        &deps,
        &HashMap::new(),
        &[],
        &HashMap::new(),
        &route_table,
        &RegistryClient::new(),
    );
    let client = Arc::new(RegistryClient::new());
    let err = artifact_unavailable_error(
        &client,
        &route_table,
        &packages[0],
        ArtifactSelection::FreshResolution,
    );

    assert_eq!(
        std::fs::read(lock_path).unwrap(),
        lock_bytes,
        "fresh resolution failure must preserve stale lpm.lock byte-for-byte"
    );
    assert_eq!(
        std::fs::read(lockb_path).unwrap(),
        lockb_bytes,
        "fresh resolution failure must preserve stale lpm.lockb byte-for-byte"
    );
    assert!(
        matches!(
            err,
            LpmError::ArtifactUnavailable(ref context)
                if context.kind == lpm_common::ArtifactUnavailableKind::Selected
                    && context.lockfiles_preserved
        ),
        "fresh resolution must retain its own artifact classification: {err}"
    );
}

#[test]
fn artifact_unavailable_error_redacts_registry_credentials_and_url_components() {
    let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let deps = HashMap::from([("secret-source".to_string(), "1.0.0".to_string())]);
    let mut packages = resolved_to_install_packages(
        &[fake_resolved("secret-source", "1.0.0", None)],
        &deps,
        &HashMap::new(),
        &[],
        &HashMap::new(),
        &route_table,
        &RegistryClient::new(),
    );
    packages[0].source = "registry+https://user:password@example.test/private/token-value?auth=query-secret#fragment-secret".to_string();

    let err = artifact_unavailable_error(
        &Arc::new(RegistryClient::new()),
        &route_table,
        &packages[0],
        ArtifactSelection::LockfileReplay,
    );
    let rendered = err.to_string();

    assert!(rendered.contains("registry+https://example.test"));
    for secret in [
        "user",
        "password",
        "private",
        "token-value",
        "query-secret",
        "fragment-secret",
    ] {
        assert!(
            !rendered.contains(secret),
            "artifact error exposed secret-bearing URL component {secret:?}: {rendered}"
        );
    }
}

/// The fast-path writeback trigger fires on v1 → v2 binary migration
/// even when no URL diverged. We can't easily test the full install here
/// without a mock server, but we can test the trigger condition:
/// `try_lockfile_fast_path` returns `needs_binary_upgrade = true`
/// when the on-disk `lpm.lockb` is version 1.
#[test]
fn lockfile_fast_path_flags_v1_binary_for_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
    let binary_path = dir.path().join(lpm_lockfile::BINARY_LOCKFILE_NAME);

    // Write a valid TOML lockfile with one package matching the
    // single declared root dep.
    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_to_file(&lockfile_path).unwrap();

    // Hand-roll a v1 `lpm.lockb` header — just the magic + v1 +
    // zero packages + header-sized string table. `open` rejects
    // with `UnsupportedVersion`, triggering the `needs_binary_upgrade`
    // branch.
    let mut v1_bytes = Vec::with_capacity(16);
    v1_bytes.extend_from_slice(b"LPMB");
    v1_bytes.extend_from_slice(&1u32.to_le_bytes());
    v1_bytes.extend_from_slice(&0u32.to_le_bytes());
    v1_bytes.extend_from_slice(&16u32.to_le_bytes());
    // Write bytes AFTER the TOML so `read_fast` prefers binary
    // (mtime-wise).
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::write(&binary_path, &v1_bytes).unwrap();

    // `read_fast` in the 2nd-round follow-up deletes v1 binaries
    // (`found < BINARY_VERSION`), so by the time `try_lockfile_fast_path`
    // gets to the `BinaryLockfileReader::open` probe, the binary
    // might have been deleted already. Either way,
    // `needs_binary_upgrade` should be true (missing or stale).
    //
    // `try_lockfile_fast_path` loads the lockfile, then probes the
    // binary to decide whether a representable lockfile should be
    // rewritten. The stale v1 file must still trigger the writeback.

    let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], &client, &gate_stats, false)
        .expect("fast path should succeed via TOML fallback");

    assert!(
        result.needs_binary_upgrade,
        "v1 binary on disk must set needs_binary_upgrade=true so the \
         writeback trigger fires"
    );
    assert_eq!(result.packages.len(), 1);
    assert_eq!(result.packages[0].name, "lodash");
}

/// `try_lockfile_fast_path` returns `needs_binary_upgrade = true` when `lpm.lockb` is
/// missing entirely (no binary ever written). Same code path as
/// the v1→v2 migration case but covers fresh projects that
/// ship only the TOML lockfile.
#[test]
fn lockfile_fast_path_flags_missing_binary_for_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_to_file(&lockfile_path).unwrap();
    // NO binary file written.

    let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], &client, &gate_stats, false)
        .expect("fast path should succeed with only TOML");

    assert!(
        result.needs_binary_upgrade,
        "missing lpm.lockb must set needs_binary_upgrade=true"
    );
}

#[test]
fn try_lockfile_fast_path_flags_stale_binary_for_writeback() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_all(&lockfile_path).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));
    lf.write_to_file(&lockfile_path).unwrap();

    let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], &client, &gate_stats, false)
        .expect("fast path should succeed via TOML");

    assert!(
        result.needs_binary_upgrade,
        "stale lpm.lockb must trigger writeback"
    );
}

#[test]
fn try_lockfile_fast_path_flags_corrupt_binary_for_writeback() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
    let binary_path = dir.path().join(lpm_lockfile::BINARY_LOCKFILE_NAME);

    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_to_file(&lockfile_path).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::write(&binary_path, b"not-a-binary-lockfile").unwrap();

    let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], &client, &gate_stats, false)
        .expect("fast path should succeed via TOML");

    assert!(
        result.needs_binary_upgrade,
        "corrupt lpm.lockb must trigger writeback"
    );
}

/// The writeback trigger skips when the binary is current AND no URL diverged (true happy
/// path). `needs_binary_upgrade` is false when a v2 binary
/// exists and opens cleanly.
#[test]
fn lockfile_fast_path_skips_upgrade_when_binary_current() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    // `write_all` writes BOTH the TOML and the v2 binary, so the
    // binary is current by construction.
    lf.write_all(&lockfile_path).unwrap();

    let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], &client, &gate_stats, false)
        .expect("fast path should succeed with both TOML + v2 binary");

    assert!(
        !result.needs_binary_upgrade,
        "current v2 binary must NOT trigger needs_binary_upgrade"
    );
}

/// Core contract: when the lockfile stores a tarball
/// URL and the gate accepts it, `try_lockfile_fast_path` MUST
/// populate `InstallPackage.tarball_url = Some(url)`. Without
/// this, every warm install still pays the per-package metadata
/// round-trip — i.e., is a no-op.
#[test]
fn accepted_gate_url_populates_tarball_url() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let canonical_url = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "lodash".to_string(),
        version: "4.17.21".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-test".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: Some(canonical_url.to_string()),
    });
    lf.write_all(&lockfile_path).unwrap();

    let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], &client, &gate_stats, false)
        .expect("fast path should succeed on valid lockfile");

    assert_eq!(result.packages.len(), 1);
    assert_eq!(
        result.packages[0].tarball_url.as_deref(),
        Some(canonical_url),
        "gate-accepted cached URL must flow into InstallPackage.tarball_url \
         so the fetch pipeline can skip the metadata round-trip"
    );

    use std::sync::atomic::Ordering;
    assert_eq!(gate_stats.origin_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(gate_stats.shape_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(gate_stats.scheme_mismatch.load(Ordering::Relaxed), 0);
}

#[test]
fn try_lockfile_fast_path_restores_registry_signature_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
    let signature = lpm_lockfile::LockedRegistrySignature {
        keyid: Some("SHA256:test-key".to_string()),
        sig: Some("base64-signature".to_string()),
    };

    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "signed-pkg".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-test".to_string()),
        registry_signatures: vec![signature.clone()],
        registry_published_at: Some("2025-01-01T00:00:00.000Z".to_string()),
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_all(&lockfile_path).unwrap();

    let deps: HashMap<String, String> = [("signed-pkg".to_string(), "^1.0.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], &client, &gate_stats, false)
        .expect("fast path should succeed on signed lockfile");

    assert_eq!(result.packages.len(), 1);
    assert_eq!(
        result.packages[0].registry_signatures,
        vec![lpm_registry::RegistrySignature {
            keyid: signature.keyid,
            sig: signature.sig,
        }]
    );
    assert_eq!(
        result.packages[0].registry_published_at.as_deref(),
        Some("2025-01-01T00:00:00.000Z")
    );
}

/// Complement to the acceptance test: gate-REJECTED URLs must
/// downgrade to `None` AND bump the matching mismatch counter.
/// Three sub-cases: RejectedShape, RejectedOrigin, RejectedScheme.
#[test]
fn rejected_gate_urls_downgrade_to_none_with_telemetry() {
    use std::sync::atomic::Ordering;

    let run_gate = |tarball: &str, client: &RegistryClient| {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "victim".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-test".to_string()),
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            tarball: Some(tarball.to_string()),
        });
        lf.write_all(&lockfile_path).unwrap();

        let deps: HashMap<String, String> = [("victim".to_string(), "^1.0.0".to_string())].into();
        let gate_stats = GateStats::default();
        let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], client, &gate_stats, false)
            .expect("fast path should succeed even with a gate-rejected URL");
        (result, gate_stats, dir)
    };

    // (1) RejectedShape — `.tgz` suffix + matching origin +
    // HTTPS, but no `/-/` segment. H1 SSRF defense.
    let client = RegistryClient::new();
    let (result, stats, _dir) = run_gate("https://registry.npmjs.org/api/admin/foo.tgz", &client);
    assert_eq!(result.packages[0].tarball_url, None);
    assert_eq!(stats.shape_mismatch.load(Ordering::Relaxed), 1);
    assert_eq!(stats.origin_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(stats.scheme_mismatch.load(Ordering::Relaxed), 0);

    // (2) RejectedOrigin — canonical shape but origin doesn't
    // match the client's `base_url` / `npm_registry_url`.
    let mirror_client = RegistryClient::new().with_base_url("http://localhost:9999");
    let (result, stats, _dir) = run_gate(
        "https://some-other-mirror.com/foo/-/foo-1.0.0.tgz",
        &mirror_client,
    );
    assert_eq!(result.packages[0].tarball_url, None);
    assert_eq!(stats.origin_mismatch.load(Ordering::Relaxed), 1);
    assert_eq!(stats.shape_mismatch.load(Ordering::Relaxed), 0);

    // (3) RejectedScheme — HTTP (non-localhost) at a matching
    // host is scheme-rejected.
    let (result, stats, _dir) = run_gate(
        "http://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
        &RegistryClient::new(),
    );
    assert_eq!(result.packages[0].tarball_url, None);
    assert_eq!(stats.scheme_mismatch.load(Ordering::Relaxed), 1);
}

/// Pre-lockfile shape: `tarball = None`. Fast path
/// must produce `InstallPackage.tarball_url = None` with no
/// counters bumped.
#[test]
fn lockfile_package_without_stored_tarball_has_no_install_url() {
    let dir = tempfile::tempdir().unwrap();
    let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

    let mut lf = lpm_lockfile::Lockfile::new();
    lf.add_package(lpm_lockfile::LockedPackage {
        name: "old-entry".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-test".to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        os: Vec::new(),
        cpu: Vec::new(),
        libc: Vec::new(),
        node_engine: None,
        optional: false,
        dependencies: vec![],
        alias_dependencies: vec![],
        peers: vec![],
        tarball: None,
    });
    lf.write_all(&lockfile_path).unwrap();

    let deps: HashMap<String, String> = [("old-entry".to_string(), "^1.0.0".to_string())].into();
    let client = RegistryClient::new();
    let gate_stats = GateStats::default();
    let result = try_lockfile_fast_path(&lockfile_path, &deps, &[], &client, &gate_stats, false)
        .expect("fast path should succeed on pre-existing lockfile");

    assert_eq!(result.packages[0].tarball_url, None);

    use std::sync::atomic::Ordering;
    assert_eq!(gate_stats.origin_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(gate_stats.shape_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(gate_stats.scheme_mismatch.load(Ordering::Relaxed), 0);
}
