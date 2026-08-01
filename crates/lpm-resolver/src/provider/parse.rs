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

pub(crate) fn parse_partial_metadata_to_cache_info(
    metadata: &lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    parse_metadata_to_cache_info_inner(metadata, false, false, false)
}

pub(crate) fn parse_full_metadata_to_cache_info(
    metadata: &lpm_registry::PackageMetadata,
) -> CachedPackageInfo {
    parse_metadata_to_cache_info_inner(metadata, true, true, true)
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
    let mut dependency_entry_count = 0usize;
    for ver_meta in metadata.versions.values() {
        if !ver_meta.dependencies.is_empty() || !ver_meta.optional_dependencies.is_empty() {
            dependency_entry_count += 1;
        }
    }
    let mut versions: Vec<NpmVersion> = Vec::with_capacity(version_count);
    let mut deps: HashMap<String, HashMap<String, String>> =
        HashMap::with_capacity(dependency_entry_count);
    let mut peer_deps: HashMap<String, HashMap<String, String>> = HashMap::new();
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
    fn split_alias(raw_range: &str) -> (String, Option<String>) {
        match crate::ranges::parse_npm_alias(raw_range) {
            Some(alias) => (alias.range, Some(alias.target)),
            None => (raw_range.to_string(), None),
        }
    }

    for (ver_str, ver_meta) in &metadata.versions {
        if !is_valid_version_string(ver_str) {
            tracing::warn!("skipping invalid version string: {ver_str:?}");
            continue;
        }
        if let Ok(v) = NpmVersion::parse(ver_str) {
            let mut ver_deps = HashMap::with_capacity(
                ver_meta.dependencies.len() + ver_meta.optional_dependencies.len(),
            );
            let mut ver_aliases: HashMap<String, String> = HashMap::new();

            for (dep_name, dep_range) in &ver_meta.dependencies {
                if !is_valid_dep_name(dep_name) {
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
                ver_deps.insert(dep_name.clone(), inner_range);
            }

            let mut opt_names = HashSet::new();
            for (dep_name, dep_range) in &ver_meta.optional_dependencies {
                if !is_valid_dep_name(dep_name) {
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
                opt_names.insert(dep_name.clone());
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

            if !ver_meta.peer_dependencies.is_empty() {
                let mut ver_peers = HashMap::with_capacity(ver_meta.peer_dependencies.len());
                for (dep_name, dep_range) in &ver_meta.peer_dependencies {
                    if !is_valid_dep_name(dep_name) {
                        tracing::debug!("skipping invalid peer dep name: {dep_name:?}");
                        continue;
                    }
                    ver_peers.insert(dep_name.clone(), dep_range.clone());
                }
                peer_deps.insert(ver_str.clone(), ver_peers);
            }

            // Collect bundled dep names. The extractor preserves
            // the bundled subtree implicitly; this set lets the
            // resolver skip enqueuing those names as separate fetches
            // so the registry copy can't shadow the vendored one
            // depending on hoisting precedence.
            if !ver_meta.bundle_dependencies.is_empty() {
                let mut bundled = HashSet::new();
                for name in &ver_meta.bundle_dependencies {
                    if !is_valid_dep_name(name) {
                        tracing::debug!("skipping invalid bundleDependency name: {name:?}");
                        continue;
                    }
                    bundled.insert(name.clone());
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
            if !ver_meta.peer_dependencies_meta.is_empty() {
                let mut opt_peers = HashSet::new();
                for (peer_name, peer_meta) in &ver_meta.peer_dependencies_meta {
                    if !peer_meta.optional {
                        continue;
                    }
                    if !is_valid_dep_name(peer_name) {
                        tracing::debug!("skipping invalid optional-peer name: {peer_name:?}");
                        continue;
                    }
                    opt_peers.insert(peer_name.clone());
                }
                if !opt_peers.is_empty() {
                    optional_peer_names.insert(ver_str.clone(), opt_peers);
                }
            }

            if let Some(required) = ver_meta.engines.get("node") {
                node_engines.insert(ver_str.clone(), required.clone());
            }

            if !ver_meta.os.is_empty() || !ver_meta.cpu.is_empty() || !ver_meta.libc.is_empty() {
                platform.insert(
                    ver_str.clone(),
                    PlatformMeta {
                        os: ver_meta.os.clone(),
                        cpu: ver_meta.cpu.clone(),
                        libc: ver_meta.libc.clone(),
                    },
                );
            }

            dist_info.insert(
                ver_str.clone(),
                CachedDistInfo {
                    tarball_url: ver_meta.tarball_url().map(str::to_string),
                    integrity: ver_meta.integrity_or_shasum().map(|s| s.into_owned()),
                    signatures: ver_meta
                        .dist
                        .as_ref()
                        .and_then(|dist| dist.signatures.clone())
                        .unwrap_or_default(),
                    published_at: metadata.time.get(ver_str).cloned(),
                    published_at_unix: metadata
                        .time
                        .get(ver_str)
                        .and_then(|published_at| parse_npm_time_unix(published_at)),
                    trust_evidence: detect_trust_evidence(ver_meta),
                },
            );

            versions.push(v);
        }
    }

    versions.sort();
    versions.reverse(); // Newest first

    let mut info = CachedPackageInfo {
        modified: metadata.modified.clone(),
        modified_unix: metadata.modified.as_deref().and_then(parse_npm_time_unix),
        trust_metadata_complete,
        versions_complete,
        covered_ranges: HashSet::new(),
        workspace_versions: HashSet::new(),
        platform_metadata_complete,
        latest_version: metadata
            .latest_version_tag()
            .and_then(|version| NpmVersion::parse(version).ok()),
        versions,
        deps,
        peer_deps,
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
