use super::prelude::*;

/// Shared metadata → CachedPackageInfo parser.
///
/// Extracts versions, deps, peer_deps, optional_deps, platform, and dist
/// from a `PackageMetadata` response. Shared by `ensure_cached` (provider
/// escape-hatch fetches) and the walker (`BfsWalker::commit_manifest`).
///
/// **Prerelease handling.** All versions, including prereleases, are kept
/// in the cache. The range matcher (`NpmRange::satisfies` in lpm-semver)
/// implements correct npm prerelease semantics — prereleases only match
/// ranges that explicitly include a prerelease on the same
/// major.minor.patch tuple, so a non-prerelease range like `^1.0.0`
/// correctly skips `1.0.0-beta.27` even when both are in the cache.
/// Previously, prereleases were unconditionally stripped for npm packages,
/// which broke any dep that declared an explicit prerelease range (e.g.
/// `@rolldown/pluginutils@^1.0.0-beta.27`, `gensync@^1.0.0-beta.2`) —
/// the cache had zero candidates and the resolver returned
/// `no version satisfies range (versions available: 1)`.
pub(crate) fn parse_metadata_to_cache_info(
    metadata: &lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    parse_metadata_to_cache_info_inner(metadata, false, true, false)
}

pub(crate) fn parse_owned_metadata_to_cache_info(
    metadata: lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    parse_owned_metadata_to_cache_info_inner(metadata, false, true, false)
}

pub(crate) fn parse_owned_partial_metadata_to_cache_info(
    metadata: lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    parse_owned_metadata_to_cache_info_inner(metadata, false, false, false)
}

#[cfg(any(test, feature = "bench-internals"))]
pub(crate) fn parse_full_metadata_to_cache_info(
    metadata: &lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    parse_metadata_to_cache_info_inner(metadata, true, true, true)
}

pub(crate) fn parse_owned_full_metadata_to_cache_info(
    metadata: lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    parse_owned_metadata_to_cache_info_inner(metadata, true, true, true)
}

pub(crate) fn merge_release_times_into_cache_info(
    info: &mut CachedPackageInfo,
    release_times: &lpm_registry::ReleaseTimeMetadata,
) {
    for (version, dist) in &mut info.dist {
        if dist.published_at.is_none()
            && let Some(published_at) = release_times.time.get(version)
        {
            dist.published_at = Some(published_at.clone());
            dist.published_at_unix = parse_npm_time_unix(published_at);
        }
    }

    if let Some(release_platforms) = &release_times.versions {
        for (version, release_platform) in release_platforms {
            if !info.dist.contains_key(version) {
                continue;
            }
            let platform = info.platform.entry(version.clone()).or_default();
            if platform.os.is_empty() {
                platform.os.clone_from(&release_platform.os);
            }
            if platform.cpu.is_empty() {
                platform.cpu.clone_from(&release_platform.cpu);
            }
            if platform.libc.is_empty() {
                platform.libc.clone_from(&release_platform.libc);
            }
        }
        info.platform_metadata_complete = true;
    }
}

fn parse_metadata_to_cache_info_inner(
    metadata: &lpm_registry::PackageMetadata,
    trust_metadata_complete: bool,
    versions_complete: bool,
    platform_metadata_complete: bool,
) -> CachedPackageInfo {
    let version_count = metadata.versions.len();
    let dependency_entry_count = metadata
        .versions
        .values()
        .filter(|version| {
            !version.dependencies.is_empty() || !version.optional_dependencies.is_empty()
        })
        .count();
    let latest_version = metadata
        .latest_version_tag()
        .and_then(|version| NpmVersion::parse(version).ok());
    let projected_versions = metadata
        .versions
        .iter()
        .map(|(version, metadata)| project_borrowed_version(version, metadata));
    parse_projected_metadata(
        metadata.modified.clone(),
        latest_version,
        ReleaseTimes::Borrowed(&metadata.time),
        projected_versions,
        version_count,
        dependency_entry_count,
        trust_metadata_complete,
        versions_complete,
        platform_metadata_complete,
    )
}

fn parse_owned_metadata_to_cache_info_inner(
    metadata: lpm_registry::PackageMetadata,
    trust_metadata_complete: bool,
    versions_complete: bool,
    platform_metadata_complete: bool,
) -> CachedPackageInfo {
    let latest_version = metadata
        .latest_version_tag()
        .and_then(|version| NpmVersion::parse(version).ok());
    let dependency_entry_count = metadata
        .versions
        .values()
        .filter(|version| {
            !version.dependencies.is_empty() || !version.optional_dependencies.is_empty()
        })
        .count();
    let lpm_registry::PackageMetadata {
        modified,
        versions,
        time,
        ..
    } = metadata;
    let version_count = versions.len();
    let projected_versions = versions
        .into_iter()
        .map(|(version, metadata)| project_owned_version(version, metadata));
    parse_projected_metadata(
        modified,
        latest_version,
        ReleaseTimes::Owned(time),
        projected_versions,
        version_count,
        dependency_entry_count,
        trust_metadata_complete,
        versions_complete,
        platform_metadata_complete,
    )
}

struct ProjectedVersion {
    version: String,
    dependencies: HashMap<String, String>,
    optional_dependencies: HashMap<String, String>,
    peer_dependencies: HashMap<String, String>,
    peer_dependencies_meta: HashMap<String, lpm_registry::PeerDependencyMeta>,
    bundle_dependencies: Vec<String>,
    node_engine: Option<String>,
    os: Vec<String>,
    cpu: Vec<String>,
    libc: Vec<String>,
    dist: CachedDistInfo,
}

fn project_borrowed_version(
    version: &str,
    metadata: &lpm_registry::VersionMetadata,
) -> ProjectedVersion {
    ProjectedVersion {
        version: version.to_owned(),
        dependencies: metadata.dependencies.clone(),
        optional_dependencies: metadata.optional_dependencies.clone(),
        peer_dependencies: metadata.peer_dependencies.clone(),
        peer_dependencies_meta: metadata.peer_dependencies_meta.clone(),
        bundle_dependencies: metadata.bundle_dependencies.clone(),
        node_engine: metadata.engines.get("node").cloned(),
        os: metadata.os.clone(),
        cpu: metadata.cpu.clone(),
        libc: metadata.libc.clone(),
        dist: CachedDistInfo {
            tarball_url: metadata.tarball_url().map(str::to_owned),
            integrity: metadata
                .integrity_or_shasum()
                .map(std::borrow::Cow::into_owned),
            signatures: metadata
                .dist
                .as_ref()
                .and_then(|dist| dist.signatures.clone())
                .unwrap_or_default(),
            trust_evidence: detect_trust_evidence(metadata),
            ..CachedDistInfo::default()
        },
    }
}

fn project_owned_version(
    version: String,
    metadata: lpm_registry::VersionMetadata,
) -> ProjectedVersion {
    let trust_evidence = detect_trust_evidence(&metadata);
    let lpm_registry::VersionMetadata {
        dependencies,
        peer_dependencies,
        peer_dependencies_meta,
        bundle_dependencies,
        optional_dependencies,
        mut engines,
        os,
        cpu,
        libc,
        dist,
        ..
    } = metadata;
    let (tarball_url, integrity, signatures) = dist.map_or_else(
        || (None, None, Vec::new()),
        |mut dist| {
            let integrity = dist.take_integrity_or_shasum();
            (dist.tarball, integrity, dist.signatures.unwrap_or_default())
        },
    );
    ProjectedVersion {
        version,
        dependencies,
        optional_dependencies,
        peer_dependencies,
        peer_dependencies_meta,
        bundle_dependencies,
        node_engine: engines.remove("node"),
        os,
        cpu,
        libc,
        dist: CachedDistInfo {
            tarball_url,
            integrity,
            signatures,
            trust_evidence,
            ..CachedDistInfo::default()
        },
    }
}

enum ReleaseTimes<'a> {
    Borrowed(&'a HashMap<String, String>),
    Owned(HashMap<String, String>),
}

impl ReleaseTimes<'_> {
    fn published_at(&mut self, version: &str) -> Option<String> {
        match self {
            Self::Borrowed(times) => times.get(version).cloned(),
            Self::Owned(times) => times.remove(version),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_projected_metadata(
    modified: Option<String>,
    latest_version: Option<NpmVersion>,
    mut release_times: ReleaseTimes<'_>,
    projected_versions: impl Iterator<Item = ProjectedVersion>,
    version_count: usize,
    dependency_entry_count: usize,
    trust_metadata_complete: bool,
    versions_complete: bool,
    platform_metadata_complete: bool,
) -> CachedPackageInfo {
    let mut versions: Vec<NpmVersion> = Vec::with_capacity(version_count);
    let mut deps: HashMap<String, HashMap<String, String>> =
        HashMap::with_capacity(dependency_entry_count);
    let mut peer_deps: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut peer_aliases: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut optional_dep_names: HashMap<String, HashSet<String>> = HashMap::new();
    let mut optional_peer_names: HashMap<String, HashSet<String>> = HashMap::new();
    let mut node_engines: HashMap<String, String> = HashMap::new();
    let mut bundled_dep_names: HashMap<String, HashSet<String>> = HashMap::new();
    let mut platform: HashMap<String, PlatformMeta> = HashMap::new();
    let mut dist_info: HashMap<String, CachedDistInfo> = HashMap::with_capacity(version_count);
    // Per-version alias map: local_name → target_canonical_name.
    // Only populated when the version declares at least one `npm:<target>@<range>`
    // dep. The `deps` map above stores local_name → INNER range (range after
    // the `npm:<target>@` prefix) so downstream range parsing is identical to
    // the non-aliased path. Lookup is the single source of truth for
    // "is this local name an alias and if so, what's the target".
    let mut aliases: HashMap<String, HashMap<String, String>> = HashMap::new();

    // Helper: normalize a `(local_name, raw_range)` dep declaration through
    // the alias rewrite. Returns `(inner_range_string, target_name_if_alias)`.
    // The inner range string is always safe to hand to `NpmRange::parse`;
    // the target is recorded in the per-version aliases map when present.
    fn split_alias(raw_range: String) -> (String, Option<String>) {
        match crate::ranges::parse_npm_alias(&raw_range) {
            Some(alias) => (alias.range, Some(alias.target)),
            None => (raw_range, None),
        }
    }

    for projected in projected_versions {
        let ver_str = projected.version;
        if !is_valid_version_string(&ver_str) {
            tracing::warn!("skipping invalid version string: {ver_str:?}");
            continue;
        }
        if let Ok(v) = NpmVersion::parse(&ver_str) {
            let mut ver_deps = HashMap::with_capacity(
                projected.dependencies.len() + projected.optional_dependencies.len(),
            );
            let mut ver_aliases: HashMap<String, String> = HashMap::new();

            for (dep_name, dep_range) in projected.dependencies {
                if !is_valid_dep_name(&dep_name) {
                    tracing::debug!("skipping invalid dep name: {dep_name:?}");
                    continue;
                }
                let (inner_range, target) = split_alias(dep_range);
                if let Some(target) = target {
                    if !is_valid_dep_name(&target) {
                        tracing::debug!(
                            "skipping alias dep {dep_name:?}: invalid target name {target:?}"
                        );
                        continue;
                    }
                    ver_aliases.insert(dep_name.clone(), target);
                }
                ver_deps.insert(dep_name, inner_range);
            }

            let mut opt_names = HashSet::new();
            for (dep_name, dep_range) in projected.optional_dependencies {
                if !is_valid_dep_name(&dep_name) {
                    tracing::debug!("skipping invalid optional dep name: {dep_name:?}");
                    continue;
                }
                let (inner_range, target) = split_alias(dep_range);
                if let Some(target) = target {
                    if !is_valid_dep_name(&target) {
                        tracing::debug!(
                            "skipping optional alias dep {dep_name:?}: invalid target name {target:?}"
                        );
                        continue;
                    }
                    ver_aliases.insert(dep_name.clone(), target);
                }
                ver_deps.insert(dep_name.clone(), inner_range);
                opt_names.insert(dep_name);
            }
            if !opt_names.is_empty() {
                optional_dep_names.insert(ver_str.clone(), opt_names);
            }
            if !ver_aliases.is_empty() {
                aliases.insert(ver_str.clone(), ver_aliases);
            }

            if !ver_deps.is_empty() {
                deps.insert(ver_str.clone(), ver_deps);
            }

            if !projected.peer_dependencies.is_empty() {
                let mut ver_peers = HashMap::with_capacity(projected.peer_dependencies.len());
                let mut ver_peer_aliases = HashMap::new();
                for (dep_name, dep_range) in projected.peer_dependencies {
                    if !is_valid_dep_name(&dep_name) {
                        tracing::debug!("skipping invalid peer dep name: {dep_name:?}");
                        continue;
                    }
                    let (inner_range, target) = split_alias(dep_range);
                    if let Some(target) = target {
                        if !is_valid_dep_name(&target) {
                            tracing::debug!(
                                "skipping peer alias {dep_name:?}: invalid target name {target:?}"
                            );
                            continue;
                        }
                        ver_peer_aliases.insert(dep_name.clone(), target);
                    }
                    ver_peers.insert(dep_name, inner_range);
                }
                if !ver_peers.is_empty() {
                    peer_deps.insert(ver_str.clone(), ver_peers);
                }
                if !ver_peer_aliases.is_empty() {
                    peer_aliases.insert(ver_str.clone(), ver_peer_aliases);
                }
            }

            // Collect bundled dep names. The extractor preserves
            // the bundled subtree implicitly; this set lets the
            // resolver skip enqueuing those names as separate fetches
            // so the registry copy can't shadow the vendored one
            // depending on hoisting precedence.
            if !projected.bundle_dependencies.is_empty() {
                let mut bundled = HashSet::new();
                for name in projected.bundle_dependencies {
                    if !is_valid_dep_name(&name) {
                        tracing::debug!("skipping invalid bundleDependency name: {name:?}");
                        continue;
                    }
                    bundled.insert(name);
                }
                if !bundled.is_empty() {
                    bundled_dep_names.insert(ver_str.clone(), bundled);
                }
            }

            // Collect optional peer names from `peerDependenciesMeta`.
            // Only entries whose `optional` flag is true are stored; the
            // open-ended npm spec allows other keys today, none of which
            // the resolver consumes. Filtering by name validity matches
            // the peer-deps loop above so a malformed key in one source
            // can't poison the other.
            if !projected.peer_dependencies_meta.is_empty() {
                let mut opt_peers = HashSet::new();
                for (peer_name, peer_meta) in projected.peer_dependencies_meta {
                    if !peer_meta.optional {
                        continue;
                    }
                    if !is_valid_dep_name(&peer_name) {
                        tracing::debug!("skipping invalid optional-peer name: {peer_name:?}");
                        continue;
                    }
                    opt_peers.insert(peer_name);
                }
                if !opt_peers.is_empty() {
                    optional_peer_names.insert(ver_str.clone(), opt_peers);
                }
            }

            if let Some(required) = projected.node_engine {
                node_engines.insert(ver_str.clone(), required);
            }

            if !projected.os.is_empty() || !projected.cpu.is_empty() || !projected.libc.is_empty() {
                platform.insert(
                    ver_str.clone(),
                    PlatformMeta {
                        os: projected.os,
                        cpu: projected.cpu,
                        libc: projected.libc,
                    },
                );
            }

            let mut dist = projected.dist;
            dist.published_at = release_times.published_at(&ver_str);
            dist.published_at_unix = dist.published_at.as_deref().and_then(parse_npm_time_unix);
            dist_info.insert(ver_str, dist);

            versions.push(v);
        }
    }

    versions.sort();
    versions.reverse(); // Newest first

    let modified_unix = modified.as_deref().and_then(parse_npm_time_unix);
    let mut info = CachedPackageInfo {
        modified,
        modified_unix,
        trust_metadata_complete,
        versions_complete,
        covered_ranges: HashSet::new(),
        workspace_versions: HashSet::new(),
        platform_metadata_complete,
        latest_version,
        versions,
        deps,
        peer_deps,
        peer_aliases,
        optional_dep_names,
        optional_peer_names,
        node_engines,
        bundled_dep_names,
        platform,
        dist: dist_info,
        aliases,
    };
    info.remove_shadowed_peer_requirements();
    info
}

fn detect_trust_evidence(ver_meta: &lpm_registry::VersionMetadata) -> Option<TrustEvidence> {
    if ver_meta
        .npm_user
        .as_ref()
        .is_some_and(lpm_registry::NpmUserMetadata::has_approver)
    {
        return Some(TrustEvidence::StagedPublish);
    }
    if ver_meta
        .npm_user
        .as_ref()
        .is_some_and(lpm_registry::NpmUserMetadata::has_trusted_publisher)
    {
        return Some(TrustEvidence::TrustedPublisher);
    }
    None
}

/// Validate a dependency name from registry metadata.
/// Rejects path traversal, null bytes, excessive length, and invalid formats.
///
/// `pub(crate)` so the peer-rules selector parser in `resolve::peers` can
/// reuse the same npm-name validity gate without duplicating the
/// scope / unscoped logic.
pub(crate) fn is_valid_dep_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    if name.contains('\0') || name.contains("..") {
        return false;
    }
    // Scoped packages: @scope/name
    if name.starts_with('@') {
        let Some(slash_pos) = name.find('/') else {
            return false;
        };
        let scope = &name[1..slash_pos]; // strip the leading '@'
        let pkg = &name[slash_pos + 1..];
        return !scope.is_empty() && !pkg.is_empty() && !pkg.contains('/') && !pkg.contains('\\');
    }
    // Unscoped: no path separators
    !name.contains('/') && !name.contains('\\')
}

/// Validate a version string from registry metadata.
/// Must contain only semver-compatible characters.
pub(super) fn is_valid_version_string(v: &str) -> bool {
    if v.is_empty() || v.len() > 256 {
        return false;
    }
    v.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}
