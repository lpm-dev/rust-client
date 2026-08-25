use super::prelude::*;
use super::*;

// === Validation tests ===

#[test]
fn valid_dep_names() {
    assert!(is_valid_dep_name("express"));
    assert!(is_valid_dep_name("@scope/name"));
    assert!(is_valid_dep_name("lodash"));
    assert!(is_valid_dep_name("@lpm.dev/neo.highlight"));
    assert!(is_valid_dep_name("my-package"));
    assert!(is_valid_dep_name("a"));
}

#[test]
fn invalid_dep_names() {
    assert!(!is_valid_dep_name(""));
    assert!(!is_valid_dep_name("../../../etc"));
    assert!(!is_valid_dep_name("a\0b"));
    assert!(!is_valid_dep_name(&"a".repeat(300)));
    assert!(!is_valid_dep_name("foo/bar")); // unscoped with slash
    assert!(!is_valid_dep_name("foo\\bar"));
    assert!(!is_valid_dep_name("@scope")); // missing /name
    assert!(!is_valid_dep_name("@/name")); // empty scope
    assert!(!is_valid_dep_name("@scope/")); // empty name
    assert!(!is_valid_dep_name("foo..bar")); // contains ..
}

#[test]
fn valid_version_strings() {
    assert!(is_valid_version_string("1.0.0"));
    assert!(is_valid_version_string("1.0.0-beta.1"));
    assert!(is_valid_version_string("1.0.0+build.123"));
}

#[test]
fn invalid_version_strings() {
    assert!(!is_valid_version_string(""));
    assert!(!is_valid_version_string(&"1".repeat(300)));
    assert!(!is_valid_version_string("1.0.0; rm -rf /"));
    assert!(!is_valid_version_string("1.0.0\0"));
}

#[test]
fn registry_attestation_pointer_is_not_trust_evidence_before_verification() {
    let metadata: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name": "claimed-provenance",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "claimed-provenance",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://registry.npmjs.org/claimed-provenance/-/claimed-provenance-1.0.0.tgz",
                    "integrity": "sha512-YWJj",
                    "attestations": {
                        "url": "https://registry.npmjs.org/-/npm/v1/attestations/claimed-provenance@1.0.0",
                        "provenance": {
                            "predicateType": "https://slsa.dev/provenance/v1"
                        }
                    }
                }
            }
        }
    }))
    .expect("valid registry metadata fixture");

    let info = parse_full_metadata_to_cache_info(&metadata);
    assert_eq!(
        info.trust_evidence("1.0.0"),
        None,
        "a registry-controlled URL and predicate marker are only a claim; install must verify the bundle before recording provenance"
    );
}

// === Peer deps are stored per-version in cache for post-resolution checking ===

#[test]
fn peer_deps_stored_per_version() {
    // Verify that peer deps are stored separately per version in CachedPackageInfo,
    // so post-resolution check_unmet_peers() can look up the exact version's peers.
    let manifest = |version: &str, range: &str| super::ManifestVersion {
        version: NpmVersion::parse(version).unwrap(),
        dependencies: Vec::new(),
        peer_dependencies: vec![super::ManifestPeerDependency {
            name: "react".to_string(),
            range: range.to_string(),
            alias: None,
            optional: false,
        }],
        node_engine: None,
        platform: None,
        dist: CachedDistInfo::default(),
    };
    let info = CachedPackageInfo::from_manifest_versions(
        None,
        false,
        true,
        HashSet::new(),
        HashSet::new(),
        true,
        None,
        vec![manifest("2.0.0", "^18"), manifest("1.0.0", "^16")],
    );

    // Version 1.0.0 peers on react@^16
    let v1_peer = info.peer_dependency("1.0.0", "react").unwrap();
    assert_eq!(v1_peer.range, "^16");

    // Version 2.0.0 peers on react@^18
    let v2_peer = info.peer_dependency("2.0.0", "react").unwrap();
    assert_eq!(v2_peer.range, "^18");

    // They are independent — no union, no aggregation
    assert_ne!(
        v1_peer.range, v2_peer.range,
        "per-version peers must not be merged"
    );
}

// === Mixed include/exclude in os/cpu ===

#[test]
fn platform_filter_inclusion_only() {
    let entries = vec!["darwin".to_string(), "linux".to_string()];
    assert!(check_platform_filter(&entries, "darwin", "os"));
    assert!(check_platform_filter(&entries, "linux", "os"));
    assert!(!check_platform_filter(&entries, "win32", "os"));
}

#[test]
fn platform_filter_exclusion_only() {
    let entries = vec!["!win32".to_string()];
    assert!(check_platform_filter(&entries, "darwin", "os"));
    assert!(check_platform_filter(&entries, "linux", "os"));
    assert!(!check_platform_filter(&entries, "win32", "os"));
}

#[test]
fn platform_filter_mixed_requires_a_positive_match_and_no_negative_match() {
    let entries = vec!["darwin".to_string(), "!win32".to_string()];
    assert!(check_platform_filter(&entries, "darwin", "os"));
    assert!(!check_platform_filter(&entries, "linux", "os"));
    assert!(!check_platform_filter(&entries, "win32", "os"));
}

#[test]
fn platform_filter_single_any_entry_allows_every_value() {
    let entries = vec!["any".to_string()];

    assert!(check_platform_filter(&entries, "darwin", "os"));
    assert!(check_platform_filter(&entries, "linux", "os"));
    assert!(check_platform_filter(&entries, "win32", "os"));
}

#[test]
fn platform_filter_empty_allows_all() {
    let entries: Vec<String> = vec![];
    assert!(check_platform_filter(&entries, "anything", "os"));
}

#[test]
fn platform_compatible_no_restrictions() {
    let meta = PlatformMeta {
        os: vec![],
        cpu: vec![],
        libc: vec![],
    };
    assert!(is_platform_compatible(&meta));
}

// === libc filter (npm package.json field) ===
//
// The bug these tests pin: before libc plumbing, the resolver picked
// glibc-built optional native binaries on Alpine because the os+cpu
// filter alone matched ("linux" + "x64") on both flavors. The store
// layer keyed by `(os, cpu, libc)` correctly, so what landed in the
// store was musl-built while what got linked was glibc-built — a
// load-time `Error: not a valid ELF interpreter` on first import.
//
// The npm spec (<https://docs.npmjs.com/cli/v9/configuring-npm/package-json#libc>)
// treats `libc` identically to `os`/`cpu`: inclusion list, `!`-prefix
// exclusion, mixed entries enter exclusion mode.

/// Bug-first test: a package that ships separate musl and glibc
/// versions on linux-x64 must select the version matching the
/// host's libc. With libc unplumbed both versions look identical
/// at the os+cpu filter and the resolver picks the newest, which
/// silently mismatches the host on Alpine.
#[test]
fn libc_filter_routes_musl_host_to_musl_only_version() {
    let musl_only = PlatformMeta {
        os: vec!["linux".to_string()],
        cpu: vec!["x64".to_string()],
        libc: vec!["musl".to_string()],
    };
    let glibc_only = PlatformMeta {
        os: vec!["linux".to_string()],
        cpu: vec!["x64".to_string()],
        libc: vec!["glibc".to_string()],
    };

    let musl_host = Platform {
        os: "linux",
        cpu: "x64",
        libc: Some("musl"),
    };
    let glibc_host = Platform {
        os: "linux",
        cpu: "x64",
        libc: Some("glibc"),
    };

    assert!(
        is_platform_compatible_for(&musl_only, &musl_host),
        "musl-only package must install on musl host"
    );
    assert!(
        !is_platform_compatible_for(&musl_only, &glibc_host),
        "musl-only package must NOT install on glibc host"
    );
    assert!(
        !is_platform_compatible_for(&glibc_only, &musl_host),
        "glibc-only package must NOT install on musl host"
    );
    assert!(
        is_platform_compatible_for(&glibc_only, &glibc_host),
        "glibc-only package must install on glibc host"
    );
}

/// Inclusion form: `libc: ["musl"]` is satisfied only by `musl`.
#[test]
fn libc_filter_inclusion_only() {
    let entries = vec!["musl".to_string()];
    assert!(check_platform_filter(&entries, "musl", "libc"));
    assert!(!check_platform_filter(&entries, "glibc", "libc"));
}

/// Exclusion form: `libc: ["!glibc"]` matches every libc except glibc.
#[test]
fn libc_filter_exclusion_only() {
    let entries = vec!["!glibc".to_string()];
    assert!(check_platform_filter(&entries, "musl", "libc"));
    assert!(!check_platform_filter(&entries, "glibc", "libc"));
}

#[test]
fn libc_filter_mixed_requires_a_positive_match_and_no_negative_match() {
    let entries = vec!["musl".to_string(), "!glibc".to_string()];
    assert!(check_platform_filter(&entries, "musl", "libc"));
    assert!(!check_platform_filter(&entries, "glibc", "libc"));
    assert!(!check_platform_filter(&entries, "bionic", "libc"));
}

/// Empty `meta.libc` always passes regardless of host libc value —
/// no restriction declared means no restriction enforced.
#[test]
fn libc_filter_unspecified_passes_on_every_host() {
    let meta = PlatformMeta {
        os: vec![],
        cpu: vec![],
        libc: vec![],
    };
    for host_libc in [None, Some("musl"), Some("glibc"), Some("uclibc")] {
        let platform = Platform {
            os: "linux",
            cpu: "x64",
            libc: host_libc,
        };
        assert!(
            is_platform_compatible_for(&meta, &platform),
            "empty meta.libc must pass on host libc {host_libc:?}"
        );
    }
}

/// Mixed os + cpu + libc filters all compose: every axis must accept
/// the host for the package to be compatible.
#[test]
fn libc_filter_composes_with_os_and_cpu() {
    let meta = PlatformMeta {
        os: vec!["linux".to_string()],
        cpu: vec!["x64".to_string()],
        libc: vec!["musl".to_string()],
    };
    let matching = Platform {
        os: "linux",
        cpu: "x64",
        libc: Some("musl"),
    };
    let wrong_cpu = Platform {
        os: "linux",
        cpu: "arm64",
        libc: Some("musl"),
    };
    let wrong_os = Platform {
        os: "darwin",
        cpu: "x64",
        libc: Some("musl"),
    };
    assert!(is_platform_compatible_for(&meta, &matching));
    assert!(!is_platform_compatible_for(&meta, &wrong_cpu));
    assert!(!is_platform_compatible_for(&meta, &wrong_os));
}

/// Host libc unknown × package libc declared: refuse the package.
/// The package opted into a libc-dependent build; we can't verify
/// the host satisfies it, so failing closed avoids materializing
/// a binary that may not load. If `meta.libc` is non-empty the package is at minimum
/// linux-only, and the os filter independently rejects it on
/// non-linux hosts — this rule only kicks in on linux hosts where
/// libc probing failed (e.g., distroless without `ld-musl-*` or
/// `libc.so.6` symlinks and a cross-compiled lpm binary).
#[test]
fn libc_filter_unknown_host_rejects_libc_declared_package() {
    let meta = PlatformMeta {
        os: vec![],
        cpu: vec![],
        libc: vec!["musl".to_string()],
    };
    let unknown = Platform {
        os: "linux",
        cpu: "x64",
        libc: None,
    };
    assert!(
        !is_platform_compatible_for(&meta, &unknown),
        "package declares libc requirement but host libc is unknown — must fail closed"
    );
}

/// Symmetric to the prior test for the exclusion form: even an
/// exclusion list against a None host fails closed, because we
/// can't tell whether the unknown libc is or is not the excluded
/// flavor. This is stricter than `check_platform_filter`'s pure
/// string semantics would yield, and is the policy decision the
/// libc plumb-in makes explicit.
#[test]
fn libc_filter_unknown_host_rejects_libc_exclusion_too() {
    let meta = PlatformMeta {
        os: vec![],
        cpu: vec![],
        libc: vec!["!glibc".to_string()],
    };
    let unknown = Platform {
        os: "linux",
        cpu: "x64",
        libc: None,
    };
    assert!(
        !is_platform_compatible_for(&meta, &unknown),
        "package declares libc exclusion but host libc is unknown — must fail closed"
    );
}

// === Platform struct returns known values ===

#[test]
fn platform_current_returns_known_values() {
    let p = Platform::current();
    let known_os = ["darwin", "linux", "win32", "freebsd"];
    let known_cpu = ["x64", "arm64", "ia32", "arm"];
    // On CI/dev machines, we should always get a known value (not "unknown")
    assert!(known_os.contains(&p.os), "expected known OS, got: {}", p.os);
    assert!(
        known_cpu.contains(&p.cpu),
        "expected known CPU, got: {}",
        p.cpu
    );
}

// === Deep follow-up env-var contract ===
//
// These tests mutate `LPM_DEEP_FOLLOWUP` via `SafeScopedEnv`, a
// tiny RAII guard that restores the original value on drop. We
// deliberately avoid `set_var` without a guard: tests run in
// parallel and another test could observe a half-set variable.
// The guard takes a module-local `Mutex` so the env mutations
// are serialized against each other (but not against unrelated
// tests that don't touch `LPM_DEEP_FOLLOWUP`).

struct ScopedEnv {
    key: &'static str,
    original: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl ScopedEnv {
    fn set(key: &'static str, value: Option<&str>) -> Self {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // SAFETY: the lock serializes `LPM_DEEP_FOLLOWUP`
        // mutations across tests in this module; unrelated
        // tests don't touch this variable.
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let original = std::env::var(key).ok();
        // SAFETY: `set_var`/`remove_var` are unsafe in Rust
        // 2024; we hold the module lock, so concurrent reads
        // in other threads of this process are the caller's
        // responsibility (see LOCK above).
        unsafe {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        Self {
            key,
            original,
            _lock: guard,
        }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        // SAFETY: see `set`.
        unsafe {
            match &self.original {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

#[test]
fn deep_followup_default_is_on() {
    let _g = ScopedEnv::set("LPM_DEEP_FOLLOWUP", None);
    assert!(
        deep_followup_enabled(),
        "default must be ON so cold installs get the in-loop deep-batch win"
    );
}

#[test]
fn deep_followup_zero_disables() {
    let _g = ScopedEnv::set("LPM_DEEP_FOLLOWUP", Some("0"));
    assert!(
        !deep_followup_enabled(),
        "LPM_DEEP_FOLLOWUP=0 must flip off, matching the rollback escape hatch"
    );
}

#[test]
fn deep_followup_one_stays_on() {
    let _g = ScopedEnv::set("LPM_DEEP_FOLLOWUP", Some("1"));
    assert!(deep_followup_enabled());
}

#[test]
fn deep_followup_arbitrary_string_stays_on() {
    // Future-proof: any non-"0" value must keep it on so a
    // stray `=true` or `=yes` doesn't accidentally disable the
    // fast path.
    let _g = ScopedEnv::set("LPM_DEEP_FOLLOWUP", Some("true"));
    assert!(deep_followup_enabled());
}

// === Helper: build a provider with pre-populated cache (no network) ===

fn make_provider_with_cache(
    root_deps: HashMap<String, String>,
    cache_entries: Vec<(ResolverPackage, CachedPackageInfo)>,
) -> LpmDependencyProvider {
    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), root_deps);
    // Canonicalize at the test-helper boundary so existing tests keep
    // working unchanged — they still pass `ResolverPackage` values (with
    // or without context), we stash them under their canonical keys,
    // which is what the provider reads.
    for (pkg, info) in cache_entries {
        provider
            .cache
            .insert(CanonicalKey::from(&pkg), Arc::new(info));
    }
    provider
}

fn make_info(
    versions: &[&str],
    deps: Vec<(&str, Vec<(&str, &str)>)>,
    optional_names: Vec<(&str, Vec<&str>)>,
    platform: Vec<(&str, Vec<&str>, Vec<&str>)>,
) -> CachedPackageInfo {
    let mut deps = deps.into_iter().collect::<HashMap<_, _>>();
    let optional_names = optional_names
        .into_iter()
        .map(|(version, names)| (version, names.into_iter().collect::<HashSet<_>>()))
        .collect::<HashMap<_, _>>();
    let mut platform = platform
        .into_iter()
        .map(|(version, os, cpu)| (version, (os, cpu)))
        .collect::<HashMap<_, _>>();
    let manifests = versions
        .iter()
        .filter_map(|version| {
            let parsed = NpmVersion::parse(version).ok()?;
            let optional = optional_names.get(version).cloned().unwrap_or_default();
            let dependencies = deps
                .remove(version)
                .unwrap_or_default()
                .into_iter()
                .map(|(name, range)| super::ManifestDependency {
                    optional: optional.contains(name),
                    name: name.to_owned(),
                    range: range.to_owned(),
                    alias: None,
                    bundled: false,
                })
                .collect();
            let platform = platform.remove(version).map(|(os, cpu)| PlatformMeta {
                os: os.into_iter().map(str::to_owned).collect(),
                cpu: cpu.into_iter().map(str::to_owned).collect(),
                libc: Vec::new(),
            });
            Some(super::ManifestVersion {
                version: parsed,
                dependencies,
                peer_dependencies: Vec::new(),
                node_engine: None,
                platform,
                dist: CachedDistInfo::default(),
            })
        })
        .collect();
    CachedPackageInfo::from_manifest_versions(
        None,
        false,
        true,
        HashSet::new(),
        HashSet::new(),
        true,
        None,
        manifests,
    )
}

fn set_published_at(info: &mut CachedPackageInfo, version: &str, published_at: &str) {
    assert!(info.update_manifest_version(version, |manifest| {
        manifest.dist.published_at = Some(published_at.to_string());
        manifest.dist.published_at_unix = parse_npm_time_unix(published_at);
    }));
}

/// Build a minimal PackageMetadata fixture with the given versions
/// (each version gets the same trivial deps map). Used by
/// [`parse_metadata_keeps_prerelease_versions`] and friends to
/// exercise [`parse_metadata_to_cache_info`] directly.
fn metadata_with_versions(
    name: &str,
    versions: &[(&str, &[(&str, &str)])],
) -> lpm_registry::PackageMetadata {
    let mut versions_map = serde_json::Map::new();
    for (ver, deps) in versions {
        let deps_obj: serde_json::Map<String, serde_json::Value> = deps
            .iter()
            .map(|(n, r)| (n.to_string(), serde_json::Value::String(r.to_string())))
            .collect();
        versions_map.insert(
            ver.to_string(),
            serde_json::json!({
                "name": name,
                "version": ver,
                "dist": {
                    "tarball": format!("https://example.com/{name}-{ver}.tgz"),
                    "integrity": "sha512-test"
                },
                "dependencies": deps_obj,
            }),
        );
    }
    let value = serde_json::json!({
        "name": name,
        "dist-tags": { "latest": versions[0].0 },
        "versions": serde_json::Value::Object(versions_map),
    });
    serde_json::from_value(value).expect("valid PackageMetadata")
}

#[test]
fn owned_metadata_projection_preserves_dependency_and_dist_values() {
    let metadata = metadata_with_versions(
        "owned-projection",
        &[("1.0.0", &[("large-dependency-name", "^123.456.789")])],
    );
    let original_range = metadata.versions["1.0.0"].dependencies["large-dependency-name"].clone();
    let original_integrity = metadata.versions["1.0.0"]
        .dist
        .as_ref()
        .unwrap()
        .integrity
        .as_ref()
        .unwrap()
        .clone();

    let info = parse_owned_metadata_to_cache_info(metadata);

    let projected_range = info
        .dependency("1.0.0", "large-dependency-name")
        .expect("projected dependency")
        .range;
    let projected_integrity = info.integrity("1.0.0").expect("projected integrity");
    assert_eq!(
        projected_range, original_range,
        "owned parsing must preserve dependency ranges"
    );
    assert_eq!(
        projected_integrity, original_integrity,
        "owned parsing must preserve integrity metadata"
    );
}

#[test]
fn metadata_projection_preserves_registry_unpacked_size() {
    let metadata: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name": "large-package",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "large-package",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/large-package-1.0.0.tgz",
                    "integrity": "sha512-test",
                    "unpackedSize": 184624992
                }
            }
        }
    }))
    .unwrap();

    let borrowed = parse_metadata_to_cache_info(&metadata);
    let owned = parse_owned_metadata_to_cache_info(metadata);
    assert_eq!(
        borrowed
            .unpacked_size("1.0.0")
            .map(std::num::NonZeroU64::get),
        Some(184_624_992)
    );
    assert_eq!(
        borrowed.unpacked_size("1.0.0"),
        owned.unpacked_size("1.0.0")
    );
}

#[test]
fn owned_and_borrowed_metadata_projection_have_the_same_contract() {
    let metadata: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name": "projection-contract",
        "modified": "2026-08-20T00:00:00.000Z",
        "dist-tags": { "latest": "2.0.0" },
        "time": { "2.0.0": "2026-08-19T00:00:00.000Z" },
        "versions": {
            "2.0.0": {
                "name": "projection-contract",
                "version": "2.0.0",
                "dependencies": {
                    "regular": "^1.0.0",
                    "aliased": "npm:canonical@^2.0.0"
                },
                "optionalDependencies": { "optional": "^3.0.0" },
                "peerDependencies": { "peer": "^4.0.0" },
                "peerDependenciesMeta": { "peer": { "optional": true } },
                "bundleDependencies": ["bundled"],
                "engines": { "node": ">=22" },
                "os": ["darwin"],
                "cpu": ["arm64"],
                "libc": ["glibc"],
                "_npmUser": { "trustedPublisher": true },
                "dist": {
                    "tarball": "https://example.invalid/projection-contract.tgz",
                    "integrity": "sha512-projection-contract",
                    "signatures": [{ "keyid": "key", "sig": "signature" }]
                }
            }
        }
    }))
    .expect("valid metadata fixture");
    let expected = parse_metadata_to_cache_info(&metadata);

    let actual = parse_owned_metadata_to_cache_info(metadata);

    assert_eq!(actual, expected);
}

#[test]
fn parse_metadata_keeps_dependency_cache_sparse_for_empty_versions() {
    let meta = metadata_with_versions(
        "sparse-deps",
        &[("1.0.1", &[]), ("1.0.0", &[("left-pad", "^1.0.0")])],
    );
    let info = parse_metadata_to_cache_info(&meta);

    assert_eq!(info.dependencies("1.0.1").unwrap().len(), 0);
    assert_eq!(
        info.dependency("1.0.0", "left-pad")
            .map(|dependency| dependency.range),
        Some("^1.0.0")
    );
}

#[test]
fn parse_metadata_keeps_peer_dependencies_when_regular_dependency_cache_is_sparse() {
    let value = serde_json::json!({
        "name": "peer-only",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "peer-only",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.com/peer-only-1.0.0.tgz",
                    "integrity": "sha512-test"
                },
                "peerDependencies": {
                    "react": "^18.0.0"
                }
            }
        },
    });
    let meta: lpm_registry::PackageMetadata =
        serde_json::from_value(value).expect("valid PackageMetadata");
    let info = parse_metadata_to_cache_info(&meta);

    assert_eq!(info.dependencies("1.0.0").unwrap().len(), 0);
    assert_eq!(
        info.peer_dependency("1.0.0", "react")
            .map(|peer| peer.range),
        Some("^18.0.0")
    );
}

#[test]
fn parse_metadata_normalizes_npm_aliased_peer_to_canonical_target() {
    let value = serde_json::json!({
        "name": "aliased-peer-host",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "aliased-peer-host",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.com/aliased-peer-host-1.0.0.tgz",
                    "integrity": "sha512-test"
                },
                "peerDependencies": {
                    "react-compat": "npm:react@^18.0.0"
                }
            }
        }
    });
    let metadata: lpm_registry::PackageMetadata =
        serde_json::from_value(value).expect("valid PackageMetadata");

    let info = parse_metadata_to_cache_info(&metadata);

    assert_eq!(
        info.peer_dependency("1.0.0", "react-compat")
            .map(|peer| peer.range),
        Some("^18.0.0"),
        "peer ranges must be normalized before semver parsing"
    );
    assert_eq!(
        info.peer_dependency("1.0.0", "react-compat")
            .and_then(|peer| peer.alias),
        Some("react"),
        "the local peer slot must retain its canonical provider name"
    );
}

#[test]
fn parse_metadata_regular_dependency_shadows_same_named_peer_requirement() {
    let value = serde_json::json!({
        "name": "dual-role-dependency",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "dual-role-dependency",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.com/dual-role-dependency-1.0.0.tgz",
                    "integrity": "sha512-test"
                },
                "dependencies": {
                    "zod": "^4.3.6"
                },
                "peerDependencies": {
                    "zod": "^4.0.0"
                }
            }
        },
    });
    let meta: lpm_registry::PackageMetadata =
        serde_json::from_value(value).expect("valid PackageMetadata");
    let info = parse_metadata_to_cache_info(&meta);

    assert_eq!(
        info.dependency("1.0.0", "zod")
            .map(|dependency| dependency.range),
        Some("^4.3.6")
    );
    assert!(
        info.peer_dependency("1.0.0", "zod").is_none(),
        "a regular dependency must not also become peer context"
    );
}

#[test]
fn merge_release_times_fills_missing_platform_axes_without_losing_abbreviated_metadata() {
    let abbreviated: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name": "native-linux",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "native-linux",
                "version": "1.0.0",
                "os": ["linux"],
                "cpu": ["arm64"],
                "dependencies": { "runtime-helper": "^2.0.0" },
                "dist": {
                    "tarball": "https://registry.npmjs.org/native-linux/-/native-linux-1.0.0.tgz",
                    "integrity": "sha512-test"
                }
            }
        }
    }))
    .expect("valid abbreviated metadata");
    let release_times: lpm_registry::ReleaseTimeMetadata =
        serde_json::from_value(serde_json::json!({
            "name": "native-linux",
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" },
            "versions": {
                "1.0.0": {
                    "os": ["linux"],
                    "cpu": ["arm64"],
                    "libc": ["glibc"]
                }
            }
        }))
        .expect("valid full metadata projected to release-time fields");

    let mut info = parse_owned_partial_metadata_to_cache_info(abbreviated);
    merge_release_times_into_cache_info(&mut info, &release_times);

    assert!(info.platform_metadata_complete);

    assert_eq!(
        (
            info.platform("1.0.0"),
            info.dependency("1.0.0", "runtime-helper")
                .map(|dependency| dependency.range),
            info.tarball_url("1.0.0"),
            info.published_at("1.0.0"),
        ),
        (
            Some(PlatformMeta {
                os: vec!["linux".to_string()],
                cpu: vec!["arm64".to_string()],
                libc: vec!["glibc".to_string()],
            }),
            Some("^2.0.0"),
            Some("https://registry.npmjs.org/native-linux/-/native-linux-1.0.0.tgz"),
            Some("2025-01-01T00:00:00.000Z"),
        ),
        "release-time merging should fill missing platform axes while retaining abbreviated dependency and distribution data"
    );
}

#[test]
fn abbreviated_linux_platform_requires_full_platform_metadata() {
    let abbreviated: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name": "native-linux",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "native-linux",
                "version": "1.0.0",
                "os": ["linux"],
                "cpu": ["x64"]
            }
        }
    }))
    .expect("valid abbreviated metadata");

    let info = parse_metadata_to_cache_info(&abbreviated);

    assert!(info.needs_platform_metadata());
}

#[test]
fn abbreviated_darwin_only_platform_does_not_require_libc_hydration() {
    let abbreviated: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name": "native-darwin",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "native-darwin",
                "version": "1.0.0",
                "os": ["darwin"],
                "cpu": ["arm64"]
            }
        }
    }))
    .expect("valid abbreviated metadata");

    let info = parse_metadata_to_cache_info(&abbreviated);

    assert!(!info.needs_platform_metadata());
}

#[test]
fn abbreviated_cpu_only_platform_requires_libc_hydration() {
    let abbreviated: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name": "native-cpu",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "native-cpu",
                "version": "1.0.0",
                "cpu": ["x64"]
            }
        }
    }))
    .expect("valid abbreviated metadata");

    let info = parse_metadata_to_cache_info(&abbreviated);

    assert!(info.needs_platform_metadata());
}

#[test]
fn time_only_release_metadata_does_not_complete_platform_metadata() {
    let abbreviated: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
        "name": "native-linux",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "native-linux",
                "version": "1.0.0",
                "os": ["linux"],
                "cpu": ["x64"]
            }
        }
    }))
    .expect("valid abbreviated metadata");
    let release_times: lpm_registry::ReleaseTimeMetadata =
        serde_json::from_value(serde_json::json!({
            "name": "native-linux",
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        }))
        .expect("valid time-only metadata");
    let mut info = parse_metadata_to_cache_info(&abbreviated);

    merge_release_times_into_cache_info(&mut info, &release_times);

    assert!(info.needs_platform_metadata());
}

/// Regression test for the prerelease-stripping bug found in the
/// hoisted-mode compatibility audit (vite-react,
/// nextjs-minimal, babel-presets fixtures all failed with
/// `no version satisfies range (versions available: 1)` when a
/// dependency declared a prerelease range like `^1.0.0-beta.27`).
///
/// Pre-fix, [`parse_metadata_to_cache_info`] unconditionally
/// Earlier parsing stripped prereleases for npm packages. All versions,
/// including prereleases, are kept
/// — the range matcher (`NpmRange::satisfies`) handles npm
/// prerelease semantics correctly per
/// [`crate::ranges`] and the `lpm-semver` crate's
/// `prerelease_only_matches_same_major_minor_patch` rule.
#[test]
fn parse_metadata_keeps_prerelease_versions() {
    let meta = metadata_with_versions(
        "pluginutils",
        &[
            ("1.0.0-beta.27", &[]),
            ("1.0.0-beta.26", &[]),
            ("0.9.0", &[]),
        ],
    );
    let info = parse_metadata_to_cache_info(&meta);
    let strs: Vec<String> = info.versions.iter().map(|v| v.to_string()).collect();
    assert!(
        strs.contains(&"1.0.0-beta.27".to_string()),
        "1.0.0-beta.27 must remain in cache after parse so ^1.0.0-beta.27 ranges can resolve"
    );
    assert!(strs.contains(&"1.0.0-beta.26".to_string()));
    assert!(strs.contains(&"0.9.0".to_string()));
    assert_eq!(info.versions.len(), 3);
}

/// The kept-prerelease must actually satisfy a prerelease range
/// of its own major.minor.patch — otherwise we've kept the data
/// but the range matcher still misses (defense-in-depth check).
#[test]
fn parse_metadata_prerelease_satisfies_explicit_prerelease_range() {
    let meta = metadata_with_versions("gensync", &[("1.0.0-beta.2", &[])]);
    let info = parse_metadata_to_cache_info(&meta);
    let range = NpmRange::parse("^1.0.0-beta.2").expect("valid range");
    let any = info.versions.iter().any(|v| range.satisfies(v));
    assert!(
        any,
        "prerelease 1.0.0-beta.2 must satisfy ^1.0.0-beta.2 — this is what \
         unblocks the resolver for deps like gensync@^1.0.0-beta.2 (Babel chain)"
    );
}

/// And the inverse — a non-prerelease range must NOT match a
/// prerelease that happens to be in the cache. This pins npm
/// semver's "prereleases excluded from non-prerelease ranges"
/// rule from inside the resolver, not just the lpm-semver crate.
#[test]
fn parse_metadata_non_prerelease_range_skips_prereleases() {
    let meta = metadata_with_versions("ambient", &[("2.0.0-beta.1", &[]), ("1.5.0", &[])]);
    let info = parse_metadata_to_cache_info(&meta);
    let range = NpmRange::parse("^1.0.0").expect("valid range");
    let chosen = info.versions.iter().find(|v| range.satisfies(v));
    assert_eq!(
        chosen.map(|v| v.to_string()),
        Some("1.5.0".to_string()),
        "^1.0.0 must skip 2.0.0-beta.1 and pick 1.5.0 — the \
         prerelease stays in the cache and the range matcher \
         (correctly) refuses to match a different-major prerelease"
    );
}

// === choose_version: override warning behavior ===

#[test]
fn choose_version_prefers_satisfying_latest_dist_tag() {
    let pkg = ResolverPackage::npm("dist-tag-range-preference");
    let mut info = make_info(&["1.0.0-next.28", "1.0.0-next.25"], vec![], vec![], vec![]);
    info.latest_version = Some(NpmVersion::parse("1.0.0-next.25").unwrap());
    let provider = make_provider_with_cache(HashMap::new(), vec![(pkg.clone(), info)]);
    let range = NpmRange::parse("^1.0.0-next.25")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&pkg));

    let chosen = provider.choose_version(&pkg, &range).unwrap();

    assert_eq!(
        chosen.map(|version| version.to_string()),
        Some("1.0.0-next.25".to_string())
    );
}

/// Build an OverrideSet from a single `lpm.overrides` entry. Test
/// helper that mirrors the `OverrideSet::parse` call site in
/// install.rs without dragging the full `package.json` schema in.
fn override_set_with(key: &str, target: &str) -> OverrideSet {
    let mut lpm = HashMap::new();
    lpm.insert(key.to_string(), target.to_string());
    OverrideSet::parse(&lpm, &HashMap::new(), &HashMap::new()).unwrap()
}

#[test]
fn choose_version_override_in_range_applies() {
    let pkg = ResolverPackage::npm("lodash");
    let info = make_info(&["4.17.21", "4.17.20", "4.17.19"], vec![], vec![], vec![]);

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_overrides(override_set_with("lodash", "4.17.20"));
    provider
        .cache
        .insert(CanonicalKey::from(&pkg), Arc::new(info));

    // Range ^4.17.0 — override 4.17.20 is in range → should be selected
    let range = NpmRange::parse("^4.17.0")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&pkg));
    let chosen = provider.choose_version(&pkg, &range).unwrap();
    assert_eq!(
        chosen.map(|v| v.to_string()),
        Some("4.17.20".to_string()),
        "override 4.17.20 should be selected over newest 4.17.21"
    );

    // Verify the apply trace was recorded.
    let hits = provider.overrides.take_hits();
    assert_eq!(hits.len(), 1, "exactly one override hit should be recorded");
    assert_eq!(hits[0].package, "lodash");
    assert_eq!(hits[0].from_version, "4.17.21");
    assert_eq!(hits[0].to_version, "4.17.20");
    assert_eq!(hits[0].via_parent, None);
}

#[test]
fn choose_version_pinned_override_replaces_consumer_range() {
    let pkg = ResolverPackage::npm("lodash");
    let info = make_info(&["4.17.21", "4.17.20", "3.0.0"], vec![], vec![], vec![]);

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_overrides(override_set_with("lodash", "3.0.0"));
    provider
        .cache
        .insert(CanonicalKey::from(&pkg), Arc::new(info));

    let range = NpmRange::parse("^4.17.0")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&pkg));
    let chosen = provider.choose_version(&pkg, &range).unwrap();
    assert_eq!(
        chosen.map(|v| v.to_string()),
        Some("3.0.0".to_string()),
        "the pinned override replaces the consumer's declared range"
    );

    let hits = provider.overrides.take_hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].from_version, "4.17.21");
    assert_eq!(hits[0].to_version, "3.0.0");
}

#[test]
fn choose_version_override_range_target_picks_newest_target_match() {
    // `^2.0.0` selects the newest 2.x target rather than one fixed version.
    let pkg = ResolverPackage::npm("foo");
    let info = make_info(
        &["2.5.0", "2.4.0", "2.0.0", "1.0.0"],
        vec![],
        vec![],
        vec![],
    );

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_overrides(override_set_with("foo", "^2.0.0"));
    provider
        .cache
        .insert(CanonicalKey::from(&pkg), Arc::new(info));

    // Without the override, `*` selects 2.5.0. The override also selects
    // 2.5.0, so this is a matched override with no effective version change.
    let range = NpmRange::parse("*")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&pkg));
    let chosen = provider.choose_version(&pkg, &range).unwrap();
    assert_eq!(chosen.map(|v| v.to_string()), Some("2.5.0".to_string()));

    let hits = provider.overrides.take_hits();
    assert!(
        hits.is_empty(),
        "an override that does not change the selected version is not applied work"
    );
}

#[test]
fn choose_version_override_range_target_replaces_consumer_range() {
    let pkg = ResolverPackage::npm("foo");
    let info = make_info(&["3.0.0", "2.5.0", "2.0.0"], vec![], vec![], vec![]);

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_overrides(override_set_with("foo", "^2.0.0"));
    provider
        .cache
        .insert(CanonicalKey::from(&pkg), Arc::new(info));

    let range = NpmRange::parse("^3.0.0")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&pkg));
    let chosen = provider.choose_version(&pkg, &range).unwrap();
    assert_eq!(chosen.map(|v| v.to_string()), Some("2.5.0".to_string()));

    let hits = provider.overrides.take_hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].from_version, "3.0.0");
    assert_eq!(hits[0].to_version, "2.5.0");
}

#[test]
fn choose_version_unpublished_override_target_falls_back_to_natural_version() {
    let pkg = ResolverPackage::npm("foo");
    let info = make_info(&["2.0.0"], vec![], vec![], vec![]);

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_overrides(override_set_with("foo", "99.0.0"));
    provider
        .cache
        .insert(CanonicalKey::from(&pkg), Arc::new(info));

    let range = NpmRange::parse("^2.0.0")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&pkg));
    let chosen = provider.choose_version(&pkg, &range).unwrap();

    assert_eq!(
        chosen.map(|version| version.to_string()),
        Some("2.0.0".to_string())
    );
    assert!(provider.overrides.take_hits().is_empty());
}

#[test]
fn choose_version_path_selector_only_applies_to_matching_parent() {
    // Path selector `baz>qar@1` should ONLY apply when `qar` is
    // reached through `baz` AND the natural version satisfies `^1.0.0`.
    // The split mechanism gives us per-parent identities (`qar[baz]` vs
    // `qar[other]`), so the resolver looks up overrides with the right
    // parent context.
    //
    // Available qar versions: 2.0.0, 1.2.0, 1.1.0.
    // Consumer range: `^1.0.0` → natural pick is 1.2.0 (newest 1.x).
    // Path selector range filter: `1` (= ^1.0.0) → matches 1.2.0.
    // The target replaces the consumer range, while the selector's `@1`
    // filter still evaluates the natural version. The fixture keeps the
    // natural version in 1.x so the selector matches.
    let qar_baz = ResolverPackage::npm("qar").with_context("baz");
    let qar_other = ResolverPackage::npm("qar").with_context("other");
    let info = make_info(&["1.5.0", "1.2.0", "1.1.0"], vec![], vec![], vec![]);

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut splits = HashSet::new();
    splits.insert("qar".to_string());
    let provider =
        LpmDependencyProvider::new_with_splits(client, rt.handle().clone(), HashMap::new(), splits)
            .with_overrides(override_set_with("baz>qar@1", "1.1.0"));
    provider
        .cache
        .insert(CanonicalKey::from(&qar_baz), Arc::new(info.clone()));
    provider
        .cache
        .insert(CanonicalKey::from(&qar_other), Arc::new(info));

    let consumer_range = NpmRange::parse("^1.0.0")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&qar_baz));

    // Through `baz`: natural is 1.5.0; selector range filter `1`
    // (= ^1.0.0) matches 1.5.0 → override forces 1.1.0.
    let chosen_baz = provider.choose_version(&qar_baz, &consumer_range).unwrap();
    assert_eq!(
        chosen_baz.map(|v| v.to_string()),
        Some("1.1.0".to_string()),
        "qar via baz should be forced to the override target 1.1.0"
    );

    // Through `other`: path selector does not match (wrong parent).
    // Natural pick wins.
    let chosen_other = provider
        .choose_version(&qar_other, &consumer_range)
        .unwrap();
    assert_eq!(
        chosen_other.map(|v| v.to_string()),
        Some("1.5.0".to_string()),
        "qar via other should get the natural newest (1.5.0) — path selector skipped"
    );

    // Drain the apply trace — only the baz hit should be recorded.
    let hits = provider.overrides.take_hits();
    assert_eq!(hits.len(), 1, "only the baz path should record a hit");
    assert_eq!(hits[0].package, "qar");
    assert_eq!(hits[0].via_parent, Some("baz".to_string()));
    assert_eq!(hits[0].from_version, "1.5.0");
    assert_eq!(hits[0].to_version, "1.1.0");
}

// === choose_version: platform filtering skips incompatible, selects next ===

#[test]
fn choose_version_selects_newest_satisfying_before_platform_filtering() {
    let pkg = ResolverPackage::npm("win-pkg");
    let info = make_info(
        &["1.3.0", "1.2.0", "1.1.0"],
        vec![],
        vec![],
        vec![("1.3.0", vec!["win32"], vec![])],
    );

    let provider = make_provider_with_cache(HashMap::new(), vec![(pkg.clone(), info)]);
    let range = NpmRange::parse("^1.0.0")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&pkg));

    let chosen = provider.choose_version(&pkg, &range).unwrap();
    assert_eq!(
        chosen.map(|v| v.to_string()),
        Some("1.3.0".to_string()),
        "version choice is semver-first; install-time reify handles platform metadata"
    );
}

#[test]
fn choose_version_all_incompatible_still_selects_newest_satisfying() {
    let pkg = ResolverPackage::npm("win-only");
    let info = make_info(
        &["2.0.0", "1.0.0"],
        vec![],
        vec![],
        vec![
            ("2.0.0", vec!["win32"], vec![]),
            ("1.0.0", vec!["win32"], vec![]),
        ],
    );

    let provider = make_provider_with_cache(HashMap::new(), vec![(pkg.clone(), info)]);
    let range = NpmRange::parse("*")
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&pkg));

    let chosen = provider.choose_version(&pkg, &range).unwrap();
    assert_eq!(
        chosen.map(|v| v.to_string()),
        Some("2.0.0".to_string()),
        "platform metadata must not hide the newest satisfying version from the lockfile"
    );
}

// === get_dependencies: optional deps skip on failure ===

#[test]
fn get_dependencies_includes_optional_deps_when_cached() {
    // Package with both regular and optional deps — both present in cache
    let pkg = ResolverPackage::npm("my-app");
    let opt_dep = ResolverPackage::npm("fsevents");
    let reg_dep = ResolverPackage::npm("express");

    let pkg_info = make_info(
        &["1.0.0"],
        vec![("1.0.0", vec![("express", "^4.0.0"), ("fsevents", "^2.0.0")])],
        vec![("1.0.0", vec!["fsevents"])],
        vec![],
    );
    let express_info = make_info(&["4.18.0"], vec![], vec![], vec![]);
    let fsevents_info = make_info(&["2.3.0"], vec![], vec![], vec![]);

    let provider = make_provider_with_cache(
        HashMap::new(),
        vec![
            (pkg.clone(), pkg_info),
            (reg_dep, express_info),
            (opt_dep, fsevents_info),
        ],
    );

    let deps = provider
        .get_dependencies(&pkg, &NpmVersion::parse("1.0.0").unwrap())
        .unwrap();

    match deps {
        Dependencies::Available(map) => {
            assert!(
                map.contains_key(&ResolverPackage::npm("express")),
                "regular dep should be present"
            );
            assert!(
                map.contains_key(&ResolverPackage::npm("fsevents")),
                "optional dep should be present when available in cache"
            );
        }
        _ => panic!("expected Available dependencies"),
    }
}

#[test]
fn get_dependencies_skips_optional_with_no_versions() {
    // Package has optional dep "fsevents" but fsevents has no compatible versions
    // (e.g., all versions are platform-incompatible → empty version list)
    let pkg = ResolverPackage::npm("my-app");
    let opt_dep = ResolverPackage::npm("fsevents");
    let reg_dep = ResolverPackage::npm("express");

    let pkg_info = make_info(
        &["1.0.0"],
        vec![("1.0.0", vec![("express", "^4.0.0"), ("fsevents", "^2.0.0")])],
        vec![("1.0.0", vec!["fsevents"])],
        vec![],
    );
    let express_info = make_info(&["4.18.0"], vec![], vec![], vec![]);
    // fsevents has NO versions (simulates platform-filtered-out)
    let fsevents_info = make_info(&[], vec![], vec![], vec![]);

    let provider = make_provider_with_cache(
        HashMap::new(),
        vec![
            (pkg.clone(), pkg_info),
            (reg_dep, express_info),
            (opt_dep, fsevents_info),
        ],
    );

    let deps = provider
        .get_dependencies(&pkg, &NpmVersion::parse("1.0.0").unwrap())
        .unwrap();

    match deps {
        Dependencies::Available(map) => {
            assert!(
                map.contains_key(&ResolverPackage::npm("express")),
                "regular dep should be present"
            );
            assert!(
                !map.contains_key(&ResolverPackage::npm("fsevents")),
                "optional dep with no versions should be silently skipped"
            );
        }
        _ => panic!("expected Available dependencies"),
    }
}

#[test]
fn get_dependencies_keeps_optional_with_only_platform_incompatible_versions() {
    let pkg = ResolverPackage::npm("my-app");
    let opt_dep = ResolverPackage::npm("fsevents");
    let reg_dep = ResolverPackage::npm("express");

    let pkg_info = make_info(
        &["1.0.0"],
        vec![("1.0.0", vec![("express", "^4.0.0"), ("fsevents", "^2.0.0")])],
        vec![("1.0.0", vec!["fsevents"])],
        vec![],
    );
    let express_info = make_info(&["4.18.0"], vec![], vec![], vec![]);
    let fsevents_info = make_info(
        &["2.3.0"],
        vec![],
        vec![],
        vec![("2.3.0", vec!["definitely-not-this-os"], vec![])],
    );

    let provider = make_provider_with_cache(
        HashMap::new(),
        vec![
            (pkg.clone(), pkg_info),
            (reg_dep, express_info),
            (opt_dep, fsevents_info),
        ],
    );

    let deps = provider
        .get_dependencies(&pkg, &NpmVersion::parse("1.0.0").unwrap())
        .unwrap();

    match deps {
        Dependencies::Available(map) => {
            assert!(
                map.contains_key(&ResolverPackage::npm("express")),
                "regular dep should be present"
            );
            assert!(
                map.contains_key(&ResolverPackage::npm("fsevents")),
                "resolver keeps platform metadata; install-time filtering skips incompatible optional deps"
            );
        }
        _ => panic!("expected Available dependencies"),
    }
}

// ── workspace: defense-in-depth on the PubGrub arm ─────────────
//
// `workspace:<rest>` is rewritten upstream by `lpm-workspace`
// before any resolver runs. If a raw `workspace:` slips through
// (future refactor drops the upstream layer, hand-edited manifest,
// malformed cache entry), `NpmRange::parse` would fail with an
// opaque semver-error surface. These two tests pin the workspace-
// specific diagnostic at both root and transitive sites so a
// future regression points the maintainer at the actual cause.

#[test]
fn get_dependencies_root_rejects_workspace_specifier() {
    // Root dep declares `workspace:*` — pubgrub arm must hard-fail
    // with a workspace-specific message, not the generic semver
    // parse error.
    let mut root_deps = HashMap::new();
    root_deps.insert("internal-pkg".to_string(), "workspace:*".to_string());

    // Pre-populate the cache so `ensure_cached` short-circuits and
    // we reach the range-parse step. The version list doesn't
    // matter — we error before pubgrub ever sees the constraint.
    let pkg = ResolverPackage::npm("internal-pkg");
    let info = make_info(&["1.0.0"], vec![], vec![], vec![]);
    let provider = make_provider_with_cache(root_deps, vec![(pkg, info)]);

    // The DependencyProvider trait's `get_dependencies` is what
    // pubgrub calls during resolution. Driving it through the root
    // path is what the integration would do.
    let root_pkg = ResolverPackage::Root;
    let result = provider.get_dependencies(&root_pkg, &NpmVersion::new(0, 0, 0));
    // `Dependencies<...>` doesn't implement Debug, so match
    // explicitly rather than `expect_err`.
    let err = match result {
        Ok(_) => panic!("workspace: root dep must produce an error"),
        Err(e) => e,
    };
    let msg = format!("{err:?}");
    assert!(
        msg.contains("workspace:") && msg.contains("lpm-workspace"),
        "expected workspace-specific diagnostic, got: {msg}"
    );
}

#[test]
fn get_dependencies_transitive_skips_workspace_specifier() {
    // Transitive dep manifest declares `workspace:*` — pubgrub arm
    // must skip it (a registry-published package shouldn't have
    // such a dep) and continue resolving siblings.
    let pkg = ResolverPackage::npm("buggy-published");
    let info = make_info(
        &["1.0.0"],
        vec![(
            "1.0.0",
            vec![("legit-sibling", "^1.0.0"), ("internal", "workspace:*")],
        )],
        vec![],
        vec![],
    );
    let sibling = ResolverPackage::npm("legit-sibling");
    let sibling_info = make_info(&["1.2.3"], vec![], vec![], vec![]);

    let provider = make_provider_with_cache(
        HashMap::new(),
        vec![(pkg.clone(), info), (sibling, sibling_info)],
    );

    let deps = provider
        .get_dependencies(&pkg, &NpmVersion::parse("1.0.0").unwrap())
        .expect("workspace: transitive dep must be skipped, not error");
    match deps {
        Dependencies::Available(map) => {
            assert!(
                map.contains_key(&ResolverPackage::npm("legit-sibling")),
                "non-workspace sibling must still resolve"
            );
            assert!(
                !map.contains_key(&ResolverPackage::npm("internal")),
                "workspace: dep must be skipped from constraints"
            );
        }
        // Dependencies isn't Debug, so use a generic message.
        _ => panic!("expected Available dependencies"),
    }
}

// Classifier round-trip.
//
// The optional-dep-skip path differentiates auth/entitlement
// failures from everything else by matching on
// `ProviderError::AuthRequired`. These tests pin the
// `LpmError → ProviderError` translation so future refactors
// can't accidentally swallow auth signals back into
// `Registry(String)`.

#[test]
fn classify_registry_error_auth_required_maps_to_auth_required() {
    let p = classify_registry_error(lpm_common::LpmError::AuthRequired);
    assert!(
        matches!(p, ProviderError::AuthRequired(_)),
        "AuthRequired must round-trip to ProviderError::AuthRequired so the \
         optional-dep skip path can warn-and-skip"
    );
}

#[test]
fn classify_registry_error_session_expired_maps_to_auth_required() {
    let p = classify_registry_error(lpm_common::LpmError::SessionExpired);
    assert!(matches!(p, ProviderError::AuthRequired(_)));
}

#[test]
fn classify_registry_error_forbidden_maps_to_auth_required() {
    let p = classify_registry_error(lpm_common::LpmError::Forbidden("nope".into()));
    assert!(matches!(p, ProviderError::AuthRequired(_)));
}

#[test]
fn classify_registry_error_network_maps_to_registry() {
    let p = classify_registry_error(lpm_common::LpmError::Network("ETIMEDOUT".into()));
    assert!(
        matches!(p, ProviderError::Registry(_)),
        "non-auth failures must stay as Registry so they remain silent debug skips"
    );
}

#[test]
fn classify_registry_error_not_found_maps_to_registry() {
    let p = classify_registry_error(lpm_common::LpmError::NotFound("missing".into()));
    assert!(matches!(p, ProviderError::Registry(_)));
}

#[test]
fn direct_fetch_uses_direct_full_when_worker_full_omits_release_time() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let rt = tokio::runtime::Runtime::new().unwrap();
    let tmp = tempfile::tempdir().expect("cache temp dir");
    let worker_requests = Arc::new(AtomicUsize::new(0));
    let worker_requests_for_responder = Arc::clone(&worker_requests);

    let (proxy_server, npm_server) = rt.block_on(async {
        let proxy_server = MockServer::start().await;
        let npm_server = MockServer::start().await;
        let worker_missing_time = serde_json::json!({
            "name": "provider-release-age-worker",
            "modified": "2025-01-03T00:00:00.000Z",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "provider-release-age-worker",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.invalid/provider-release-age-worker.tgz",
                        "integrity": "sha512-release-age"
                    },
                    "dependencies": {}
                }
            }
        });
        let direct_full = serde_json::json!({
            "name": "provider-release-age-worker",
            "modified": "2025-01-03T00:00:00.000Z",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "provider-release-age-worker",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.invalid/provider-release-age-worker.tgz",
                        "integrity": "sha512-release-age"
                    },
                    "dependencies": {}
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z"
            }
        });

        Mock::given(method("GET"))
            .and(path("/api/registry/provider-release-age-worker"))
            .respond_with(move |request: &wiremock::Request| {
                let attempt = worker_requests_for_responder.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    assert_ne!(
                        request
                            .headers
                            .get("accept")
                            .and_then(|value| value.to_str().ok()),
                        Some("application/json")
                    );
                } else {
                    assert_eq!(
                        request
                            .headers
                            .get("accept")
                            .and_then(|value| value.to_str().ok()),
                        Some("application/json")
                    );
                }
                ResponseTemplate::new(200).set_body_json(worker_missing_time.clone())
            })
            .expect(2)
            .mount(&proxy_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/provider-release-age-worker"))
            .and(header("Accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(direct_full))
            .expect(1)
            .mount(&npm_server)
            .await;

        (proxy_server, npm_server)
    });

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri())
            .with_cache_dir(Some(tmp.path().to_path_buf())),
    );
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_policy(policy)
        .with_route_mode(RouteMode::Proxy);
    let pkg = ResolverPackage::npm("provider-release-age-worker");
    let key = CanonicalKey::from(&pkg);

    provider
        .direct_fetch_and_cache(&pkg)
        .expect("provider fetch should recover direct full metadata when Worker omits time");

    assert_eq!(worker_requests.load(Ordering::SeqCst), 2);
    let cached = provider.cache.get(&key).expect("cache entry should exist");
    assert_eq!(
        cached.published_at("1.0.0"),
        Some("2025-01-01T00:00:00.000Z")
    );
}

#[test]
fn ensure_policy_metadata_trace_records_cached_release_time_hydration() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _timing_guard = rt.block_on(crate::metadata_fetch_detail_test_lock().lock());
    lpm_registry::timing::reset_metadata_detail();

    let tmp = tempfile::tempdir().expect("cache temp dir");
    let (npm_server, full_metadata) = rt.block_on(async {
        let npm_server = MockServer::start().await;
        let full_metadata = serde_json::json!({
            "name": "cached-policy-hydration",
            "modified": "2025-01-03T00:00:00.000Z",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "cached-policy-hydration",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.invalid/cached-policy-hydration.tgz",
                        "integrity": "sha512-policy"
                    },
                    "dependencies": {}
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z"
            }
        });

        Mock::given(method("GET"))
            .and(path("/cached-policy-hydration"))
            .and(header("Accept", "application/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(full_metadata.clone())
                    .set_delay(Duration::from_millis(5)),
            )
            .expect(1)
            .mount(&npm_server)
            .await;

        (npm_server, full_metadata)
    });

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(npm_server.uri())
            .with_cache_dir(Some(tmp.path().to_path_buf())),
    );
    let policy = ResolverPolicy::with_cutoff_unix(
        86_400,
        parse_npm_time_unix("2025-01-02T00:00:00.000Z").unwrap(),
        TrustPolicyMode::Off,
    );
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_policy(policy)
        .with_route_mode(RouteMode::Direct);
    let pkg = ResolverPackage::npm("cached-policy-hydration");
    let key = CanonicalKey::from(&pkg);
    let mut cached = make_info(&["1.0.0"], vec![], vec![], vec![]);
    cached.modified = Some("2025-01-03T00:00:00.000Z".to_string());
    cached.modified_unix = parse_npm_time_unix("2025-01-03T00:00:00.000Z");
    provider.cache.insert(key.clone(), Arc::new(cached));

    provider
        .ensure_policy_metadata_with_trace(&pkg, &key, true)
        .expect("cached abbreviated metadata should hydrate release-time metadata");

    let snapshot = lpm_registry::timing::snapshot_metadata_fetch_detail();
    lpm_registry::timing::reset_metadata_detail();
    drop(full_metadata);

    assert_eq!(snapshot.calls, 1);
    assert_eq!(snapshot.route_npm_direct_count, 1);
    assert!(snapshot.attribution.policy_release_time_sum_ms > 0);
    assert!(snapshot.attribution.policy_release_time_fetch_sum_ms > 0);
    assert!(
        snapshot
            .top_slow_packages
            .by_policy_release_time_fetch
            .iter()
            .any(|row| row.package == key.to_string()
                && row.route == "npm_direct"
                && row.policy_release_time_fetch_ms > 0)
    );
    let hydrated = provider.cache.get(&key).expect("hydrated cache entry");
    assert_eq!(
        hydrated.published_at("1.0.0"),
        Some("2025-01-01T00:00:00.000Z")
    );
}

#[test]
fn release_age_package_scope_skips_unlisted_transitive_metadata_hydration() {
    let transitive = CanonicalKey::npm("transitive");
    let direct = CanonicalKey::npm("direct");
    let mut info = make_info(&["1.0.0"], vec![], vec![], vec![]);
    info.modified = Some("2025-01-03T00:00:00.000Z".to_string());
    info.modified_unix = parse_npm_time_unix("2025-01-03T00:00:00.000Z");
    let policy = ResolverPolicy::with_cutoff_unix_and_release_age_packages(
        86_400,
        parse_npm_time_unix("2025-01-02T00:00:00.000Z").unwrap(),
        TrustPolicyMode::Off,
        [direct.clone()],
    );

    assert!(!info.needs_release_time_metadata(&transitive, &policy));
    assert!(info.needs_release_time_metadata(&direct, &policy));
}

#[test]
fn release_age_package_scope_allows_unlisted_transitive_version() {
    let transitive = CanonicalKey::npm("transitive");
    let direct = CanonicalKey::npm("direct");
    let mut info = make_info(&["1.0.0"], vec![], vec![], vec![]);
    set_published_at(&mut info, "1.0.0", "2025-01-03T00:00:00.000Z");
    let policy = ResolverPolicy::with_cutoff_unix_and_release_age_packages(
        86_400,
        parse_npm_time_unix("2025-01-02T00:00:00.000Z").unwrap(),
        TrustPolicyMode::Off,
        [direct],
    );
    let version = NpmVersion::parse("1.0.0").unwrap();

    assert!(matches!(
        release_age_status_for_version(&transitive, &info, &version, &policy),
        ReleaseTimeStatus::Allowed
    ));
    assert!(matches!(
        release_age_status_for_version(&CanonicalKey::npm("direct"), &info, &version, &policy),
        ReleaseTimeStatus::TooNew { .. }
    ));
}

// ─── Range memoization ───────────────────────────────────────
//
// `NpmRange::to_pubgrub_ranges(&available_versions)` is O(N) in the
// version count for a given package. PubGrub backtracking calls
// `get_dependencies` multiple times per package during a single
// resolve pass, each call re-evaluating every declared dep's range
// against the same `available_versions` list.
//
// The contract: `(package, raw_range_str) → Ranges<NpmVersion>`
// must produce identical output on repeated calls within a single
// provider instance, and the second call MUST hit the cache
// instead of recomputing. `available_versions` is fixed for a
// given `ResolverPackage` once `ensure_cached` has run, so there's
// no staleness concern within a resolve pass.

#[test]
fn latest_range_fallback_never_exceeds_dist_tag_target() {
    let pkg = ResolverPackage::npm("rolled-back-latest");
    let mut info = make_info(&["4.0.0", "3.1.0", "3.0.0"], vec![], vec![], vec![]);
    info.latest_version = Some(NpmVersion::parse("3.1.0").unwrap());
    for (version, published_at) in [
        ("4.0.0", "2025-01-01T00:00:00.000Z"),
        ("3.1.0", "2025-01-03T00:00:00.000Z"),
        ("3.0.0", "2025-01-01T00:00:00.000Z"),
    ] {
        set_published_at(&mut info, version, published_at);
    }

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_policy(ResolverPolicy::with_cutoff_unix(
            86_400,
            parse_npm_time_unix("2025-01-02T00:00:00.000Z").unwrap(),
            TrustPolicyMode::Off,
        ));
    provider
        .cache
        .insert(CanonicalKey::from(&pkg), Arc::new(info));

    let available = provider.available_versions(&pkg);
    let latest = NpmRange::parse("latest").unwrap();
    let range = provider.to_pubgrub_ranges_cached(&pkg, &latest, &available);
    let chosen = provider.choose_version(&pkg, &range).unwrap();

    assert_eq!(
        chosen.map(|version| version.to_string()),
        Some("3.0.0".into())
    );
}

#[test]
fn to_pubgrub_ranges_cached_hits_on_repeated_query() {
    let pkg = ResolverPackage::npm("lodash");
    let info = make_info(
        &["4.17.21", "4.17.20", "4.17.19", "4.16.0", "3.10.1"],
        vec![],
        vec![],
        vec![],
    );

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());
    provider
        .cache
        .insert(CanonicalKey::from(&pkg), Arc::new(info));

    let npm_range = NpmRange::parse("^4.17.0").unwrap();
    let available = provider.available_versions(&pkg);

    // Miss path — first call computes + caches.
    let r1 = provider.to_pubgrub_ranges_cached(&pkg, &npm_range, &available);
    assert_eq!(
        provider.range_cache.lock().len(),
        1,
        "first call must populate exactly one entry"
    );

    // Hit path — second call returns the SAME Ranges without a
    // recompute. We assert structural equality (Ranges<V>: Eq)
    // plus that no new cache entry appeared.
    let r2 = provider.to_pubgrub_ranges_cached(&pkg, &npm_range, &available);
    assert_eq!(
        r1, r2,
        "memoized Ranges must equal the freshly-computed Ranges"
    );
    assert_eq!(
        provider.range_cache.lock().len(),
        1,
        "repeated query with identical (pkg, range) must NOT add a second cache entry"
    );

    // Different range → separate entry.
    let npm_range2 = NpmRange::parse("~4.17.0").unwrap();
    provider.to_pubgrub_ranges_cached(&pkg, &npm_range2, &available);
    assert_eq!(
        provider.range_cache.lock().len(),
        2,
        "different raw-range string must key a new entry"
    );
}

#[test]
fn available_versions_cached_hits_on_repeated_query() {
    let pkg = ResolverPackage::npm("lodash");
    let info = make_info(
        &["4.17.21", "4.17.20", "4.17.19", "4.16.0", "3.10.1"],
        vec![],
        vec![],
        vec![],
    );

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());
    provider.insert_and_notify(CanonicalKey::from(&pkg), info);

    let first = provider.available_versions(&pkg);
    assert_eq!(provider.available_versions_cache.lock().len(), 1);

    let second = provider.available_versions(&pkg);
    assert_eq!(first, second);
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(provider.available_versions_cache.lock().len(), 1);
}

#[test]
fn available_versions_cache_invalidates_when_metadata_is_upgraded() {
    let pkg = ResolverPackage::npm("age-gated");
    let mut upgraded = make_info(&["2.0.0", "1.0.0"], vec![], vec![], vec![]);
    set_published_at(&mut upgraded, "2.0.0", "2025-01-03T00:00:00.000Z");
    set_published_at(&mut upgraded, "1.0.0", "2025-01-01T00:00:00.000Z");

    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_policy(ResolverPolicy::with_cutoff_unix(
            86_400,
            parse_npm_time_unix("2025-01-02T00:00:00.000Z").unwrap(),
            TrustPolicyMode::Off,
        ));
    provider.insert_and_notify(
        CanonicalKey::from(&pkg),
        make_info(&["2.0.0", "1.0.0"], vec![], vec![], vec![]),
    );
    let before_upgrade = provider.available_versions(&pkg);
    provider.insert_and_notify(CanonicalKey::from(&pkg), upgraded);

    let after_upgrade = provider.available_versions(&pkg);

    assert_eq!(
        before_upgrade.as_ref(),
        &[
            NpmVersion::parse("2.0.0").unwrap(),
            NpmVersion::parse("1.0.0").unwrap()
        ]
    );
    assert_eq!(
        after_upgrade.as_ref(),
        &[NpmVersion::parse("1.0.0").unwrap()]
    );
}

#[test]
fn to_pubgrub_ranges_cached_distinguishes_split_packages() {
    // Split packages (same canonical name, different `context`) are
    // distinct `ResolverPackage` identities. Their `available_versions`
    // SET is typically the same (splits copy from canonical via
    // `ensure_cached`), but the cache keys are distinct because the
    // linker and PubGrub treat them as separate identities. Ensure
    // the cache honors that: a hit for `ajv[eslint]` must NOT serve
    // a query for `ajv` (bare), even at the same raw range string —
    // because future changes might introduce per-split platform
    // differences and silently serving across contexts would mask
    // that. Keep keys distinct.
    let pkg_plain = ResolverPackage::npm("ajv");
    let pkg_split = ResolverPackage::npm("ajv").with_context("eslint");
    assert_ne!(pkg_plain, pkg_split, "split and plain are distinct keys");

    let info = make_info(&["8.18.0", "7.2.4", "6.14.0"], vec![], vec![], vec![]);
    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());
    provider
        .cache
        .insert(CanonicalKey::from(&pkg_plain), Arc::new(info.clone()));
    provider
        .cache
        .insert(CanonicalKey::from(&pkg_split), Arc::new(info));

    let npm_range = NpmRange::parse("^6.0.0").unwrap();
    let available_plain = provider.available_versions(&pkg_plain);
    let available_split = provider.available_versions(&pkg_split);

    provider.to_pubgrub_ranges_cached(&pkg_plain, &npm_range, &available_plain);
    provider.to_pubgrub_ranges_cached(&pkg_split, &npm_range, &available_split);
    assert_eq!(
        provider.range_cache.lock().len(),
        2,
        "split and plain keys must live in separate cache entries"
    );
}

// ─── Canonical-keyed cache regressions ─────────────────────────────

/// When `ensure_cached` is asked for a split-retry identity
/// (`ajv[eslint]`), it MUST hit the canonical cache entry (`ajv`) the
/// walker inserted — not time out and fall through to the escape-hatch
/// fetch.
///
/// Previously the cache was keyed by `ResolverPackage` including context,
/// with an explicit `is_split()` branch that recursively fetched the
/// canonical form and copied its info into the split cell. The current
/// approach uses canonicalization at the cache boundary: one entry per
/// canonical name, reads canonicalize `ResolverPackage → CanonicalKey`
/// first.
///
/// If anyone ever regresses this — e.g. re-introducing a context-
/// bearing key on the cache or skipping canonicalization in
/// `ensure_cached` — this test times out 0 s (no walker attached,
/// fetch_wait_timeout is ZERO) and then fails trying to fetch from
/// a dummy `RegistryClient`. The network-dependent failure mode is
/// intentional: a pure in-memory assertion could mask the exact
/// bug the invariant prevents.
#[test]
fn ensure_cached_split_retry_hits_canonical_entry() {
    let info = make_info(&["4.17.21"], vec![], vec![], vec![]);
    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());

    // Simulate a walker having inserted under the canonical key.
    provider
        .cache
        .insert(CanonicalKey::npm("lodash"), Arc::new(info));

    // Ask `ensure_cached` for a split-context version of lodash —
    // this is what PubGrub does on multi-version retries. The
    // canonical-keyed cache MUST serve this from the existing
    // entry via CanonicalKey::from(&split) collapsing to the same
    // cell as the walker's insert.
    let split = ResolverPackage::npm("lodash").with_context("eslint");
    assert!(
        provider.cache.contains_key(&CanonicalKey::from(&split)),
        "canonicalization must map the split identity to the walker-inserted key"
    );

    // Call ensure_cached: must return Ok without touching the
    // network. If canonicalization regressed, this would fall to
    // direct_fetch_and_cache and blow up on the default (unconfigured)
    // RegistryClient because the pool isn't wired to a live server.
    provider
        .ensure_cached(&split)
        .expect("ensure_cached must resolve via the canonical cache entry without fetching");

    // available_versions must also see the canonical entry via the
    // split identity — this is the load-bearing downstream
    // consequence that `format_solution` and `check_unmet_peers`
    // depend on.
    let avail = provider.available_versions(&split);
    assert_eq!(
        avail.len(),
        1,
        "split identity must see canonical versions through canonicalization"
    );
}

/// Second boundary test: the same invariant from the other direction —
/// a `ResolverPackage::npm("lodash")` (canonical) lookup must hit an
/// entry inserted under a `ResolverPackage::npm("lodash").with_context(...)`
/// identity. Both sides of the canonicalization must agree.
#[test]
fn ensure_cached_canonical_hits_split_insertion_symmetric() {
    let info = make_info(&["4.17.21"], vec![], vec![], vec![]);
    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());

    // Insert from the SPLIT side (as a test helper might). Note:
    // the walker in production only ever inserts canonical keys,
    // but the test helper canonicalizes at its boundary, so both
    // directions are functionally equivalent.
    let split = ResolverPackage::npm("lodash").with_context("eslint");
    provider
        .cache
        .insert(CanonicalKey::from(&split), Arc::new(info));

    // Canonical lookup — must hit.
    let canonical = ResolverPackage::npm("lodash");
    provider
        .ensure_cached(&canonical)
        .expect("canonical lookup must resolve via the split-inserted canonical key");
}

// StreamingBfsMetrics counter behavior regression tests. These tests
// pin the provider-side counter semantics directly (walker-side fields
// are already covered by walker.rs tests), so the JSON shape and its
// healthy-vs-degraded narrative rest on verified foundations.

#[test]
fn streaming_metrics_cache_hit_does_not_increment_waits() {
    // Pre-seed the canonical cache entry. `ensure_cached` fast-
    // path short-circuits without touching the wait-loop, so no
    // counter should move.
    let info = make_info(&["4.17.21"], vec![], vec![], vec![]);
    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let metrics = StreamingBfsMetrics::new();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_streaming_metrics(metrics.clone());
    provider
        .cache
        .insert(CanonicalKey::npm("lodash"), Arc::new(info));

    let pkg = ResolverPackage::npm("lodash");
    provider.ensure_cached(&pkg).expect("cache hit");

    assert_eq!(metrics.cache_waits(), 0);
    assert_eq!(metrics.cache_wait_timeouts(), 0);
    assert_eq!(metrics.escape_hatch_fetches(), 0);
}

#[test]
fn streaming_metrics_miss_with_zero_timeout_increments_only_escape_hatch() {
    // No-walker shape: `fetch_wait_timeout == ZERO`. Cache miss
    // short-circuits the wait-loop and routes straight to the
    // escape hatch. `cache_waits` MUST stay zero (wait-loop
    // never entered); `escape_hatch_fetches` increments by one.
    //
    // `direct_fetch_and_cache` will then fail because the
    // default RegistryClient isn't wired to a live server — we
    // assert the counter AFTER the expected error, so the
    // failing fetch is orthogonal to the counter check.
    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let metrics = StreamingBfsMetrics::new();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_streaming_metrics(metrics.clone());

    let pkg = ResolverPackage::npm("definitely-not-on-npmjs-abc-xyz-12345");
    let _ = provider.ensure_cached(&pkg); // expected to error — we want the counter, not the result

    assert_eq!(
        metrics.cache_waits(),
        0,
        "zero-timeout short-circuit must NOT enter the wait-loop"
    );
    assert_eq!(metrics.cache_wait_timeouts(), 0);
    assert_eq!(
        metrics.escape_hatch_fetches(),
        1,
        "every non-root ensure_cached miss on zero-timeout must route to the escape hatch"
    );
}

#[test]
fn streaming_metrics_root_package_does_not_count() {
    // Root returns `Ok(())` before any counter interaction.
    // `ensure_cached(Root)` must leave all three at zero.
    let client = Arc::new(RegistryClient::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let metrics = StreamingBfsMetrics::new();
    let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
        .with_streaming_metrics(metrics.clone());

    provider
        .ensure_cached(&ResolverPackage::Root)
        .expect("root ok");
    assert_eq!(metrics.cache_waits(), 0);
    assert_eq!(metrics.cache_wait_timeouts(), 0);
    assert_eq!(metrics.escape_hatch_fetches(), 0);
}

#[test]
fn streaming_metrics_shared_across_clones() {
    // The metrics type is a newtype of Arc<AtomicU64>s. Cloning
    // MUST share the underlying counters — cross-pass accumulation
    // in the split-retry resolver relies on this.
    let a = StreamingBfsMetrics::new();
    let b = a.clone();
    a.incr_cache_wait();
    a.incr_cache_wait_timeout();
    b.incr_escape_hatch_fetch();
    b.incr_escape_hatch_fetch();

    // Observations from EITHER handle see the full aggregated counts.
    assert_eq!(a.cache_waits(), 1);
    assert_eq!(b.cache_waits(), 1);
    assert_eq!(a.cache_wait_timeouts(), 1);
    assert_eq!(a.escape_hatch_fetches(), 2);
    assert_eq!(b.escape_hatch_fetches(), 2);
}

// Blocking-pool saturation smoke. PubGrub runs inside a single
// `spawn_blocking` task (not one per miss), so the pool concern is
// low — but a tiny smoke test is still useful: if a future refactor
// accidentally moves an `rt.block_on` into a hot per-package call site,
// a 2-thread blocking pool would deadlock.
//
// The test constructs a multi-thread tokio runtime with
// `max_blocking_threads(2)`, pre-seeds the provider's shared
// cache with every needed entry (so `ensure_cached` always hits
// the fast path), then runs `resolve` against it. If the
// provider accidentally spawns `block_on` calls outside the
// outer `spawn_blocking`, this test will hang + time out.
#[test]
fn blocking_pool_saturation_smoke_max_2_threads() {
    use std::time::Duration as StdDuration;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()
        .expect("tokio rt");

    let info = make_info(&["1.0.0"], vec![], vec![], vec![]);
    rt.block_on(async {
        let client = Arc::new(RegistryClient::new());
        let handle = tokio::runtime::Handle::current();
        let provider = LpmDependencyProvider::new(client, handle, HashMap::new());
        // Pre-seed 8 entries so ensure_cached hits the fast path
        // without triggering any rt.block_on calls.
        for i in 0..8 {
            provider.cache.insert(
                CanonicalKey::npm(&format!("pkg-{i}")),
                Arc::new(info.clone()),
            );
        }

        // Concurrently call `ensure_cached` 16 times across 4
        // spawn_blocking tasks. With max_blocking_threads=2, two
        // tasks run at a time; if any of them transitively
        // `block_on` a fetch that needs a blocking slot, the
        // whole pool deadlocks and the timeout below fires.
        let mut handles = Vec::new();
        for i in 0..4 {
            let p = provider.cache.clone();
            let notify = provider.notify_map.clone();
            let walker_done = provider.walker_done.clone();
            // Build a NEW provider inside the blocking task —
            // sharing the Arc<DashMap>s means the fast-path reads
            // hit the pre-seeded entries.
            let client = Arc::new(RegistryClient::new());
            let rt_handle = tokio::runtime::Handle::current();
            handles.push(tokio::task::spawn_blocking(move || {
                let prov = LpmDependencyProvider::new(client, rt_handle, HashMap::new())
                    .with_shared_cache(p, notify, walker_done, StdDuration::ZERO);
                for j in 0..4 {
                    let pkg = ResolverPackage::npm(&format!("pkg-{}", (i + j) % 8));
                    prov.ensure_cached(&pkg).expect("fast-path hit");
                }
            }));
        }
        // Wrap in a 10s timeout so a genuine deadlock fails
        // the test rather than hanging CI.
        let all = async {
            for h in handles {
                h.await.expect("no task panic");
            }
        };
        tokio::time::timeout(StdDuration::from_secs(10), all)
            .await
            .expect("blocking-pool must not deadlock on cache-hit fast-path");
    });
}
