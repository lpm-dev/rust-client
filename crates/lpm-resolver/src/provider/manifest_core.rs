use std::collections::{HashMap, HashSet};
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;

use ahash::AHashMap;

use crate::npm_version::NpmVersion;
use crate::package::CanonicalKey;
use crate::policy::{ResolverPolicy, TrustEvidence, parse_npm_time_unix};
use crate::ranges::NpmRange;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachedDistInfo {
    pub tarball_url: Option<String>,
    pub integrity: Option<String>,
    pub unpacked_size: Option<NonZeroU64>,
    pub signatures: Vec<lpm_registry::RegistrySignature>,
    pub published_at: Option<String>,
    pub published_at_unix: Option<i64>,
    pub trust_evidence: Option<TrustEvidence>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformMeta {
    pub os: Vec<String>,
    pub cpu: Vec<String>,
    pub libc: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDependency {
    pub name: String,
    pub range: String,
    pub alias: Option<String>,
    pub optional: bool,
    pub bundled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPeerDependency {
    pub name: String,
    pub range: String,
    pub alias: Option<String>,
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestVersion {
    pub version: NpmVersion,
    pub dependencies: Vec<ManifestDependency>,
    pub peer_dependencies: Vec<ManifestPeerDependency>,
    pub node_engine: Option<String>,
    pub platform: Option<PlatformMeta>,
    pub dist: CachedDistInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedPackageInfo {
    pub modified: Option<String>,
    pub modified_unix: Option<i64>,
    pub trust_metadata_complete: bool,
    pub versions_complete: bool,
    pub covered_ranges: HashSet<String>,
    pub workspace_versions: HashSet<NpmVersion>,
    pub platform_metadata_complete: bool,
    pub latest_version: Option<NpmVersion>,
    pub versions: Arc<[NpmVersion]>,
    core: Arc<ManifestCore>,
    release: Arc<ReleaseOverlay>,
    platform: Arc<PlatformOverlay>,
    trust: Arc<[TrustRecord]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestCore {
    strings: StringPool,
    versions: Box<[VersionRecord]>,
    version_lookup: Box<[u32]>,
    dependencies: Box<[DependencyRecord]>,
    peers: Box<[PeerRecord]>,
    signatures: Box<[lpm_registry::RegistrySignature]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VersionRecord {
    text: StringId,
    dependencies: RecordSpan,
    peers: RecordSpan,
    node_engine: Option<StringId>,
    tarball_url: Option<StringId>,
    integrity: Option<StringId>,
    unpacked_size: Option<NonZeroU64>,
    signatures: RecordSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DependencyRecord {
    name: StringId,
    range: StringId,
    alias: Option<StringId>,
    optional: bool,
    bundled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerRecord {
    name: StringId,
    range: StringId,
    alias: Option<StringId>,
    optional: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ReleaseOverlay {
    strings: StringPool,
    records: Box<[ReleaseRecord]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReleaseRecord {
    version: u32,
    published_at: StringId,
    published_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PlatformOverlay {
    strings: StringPool,
    values: Box<[StringId]>,
    records: Box<[PlatformRecord]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlatformRecord {
    version: u32,
    os: RecordSpan,
    cpu: RecordSpan,
    libc: RecordSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustRecord {
    version: u32,
    evidence: TrustEvidence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StringPool {
    data: Box<str>,
    spans: Box<[TextSpan]>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TextSpan {
    start: u32,
    len: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RecordSpan {
    start: u32,
    len: u32,
}

#[derive(Default)]
struct StringPoolBuilder {
    ids: AHashMap<String, StringId>,
    next_id: u32,
    total_len: usize,
}

pub(super) struct ManifestCacheBuilder {
    modified: Option<String>,
    trust_metadata_complete: bool,
    versions_complete: bool,
    covered_ranges: HashSet<String>,
    workspace_versions: HashSet<NpmVersion>,
    platform_metadata_complete: bool,
    latest_version: Option<NpmVersion>,
    strings: StringPoolBuilder,
    versions: Vec<StagedVersion>,
    dependencies: Vec<DependencyRecord>,
    peers: Vec<PeerRecord>,
    signatures: Vec<lpm_registry::RegistrySignature>,
}

struct StagedVersion {
    version: NpmVersion,
    record: VersionRecord,
    published_at: Option<String>,
    published_at_unix: Option<i64>,
    platform: Option<PlatformMeta>,
    trust_evidence: Option<TrustEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StringId(NonZeroU32);

impl StringId {
    #[inline]
    fn from_index(index: u32) -> Self {
        Self(
            NonZeroU32::new(
                index
                    .checked_add(1)
                    .expect("metadata string count is bounded by the response size cap"),
            )
            .expect("metadata string IDs start at one"),
        )
    }

    #[inline]
    fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestDependencyRef<'a> {
    pub name: &'a str,
    pub range: &'a str,
    pub alias: Option<&'a str>,
    pub optional: bool,
    pub bundled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestPeerDependencyRef<'a> {
    pub name: &'a str,
    pub range: &'a str,
    pub alias: Option<&'a str>,
    pub optional: bool,
}

pub struct ManifestDependencyIter<'a> {
    core: &'a ManifestCore,
    iter: std::slice::Iter<'a, DependencyRecord>,
}

pub struct ManifestPeerDependencyIter<'a> {
    core: &'a ManifestCore,
    iter: std::slice::Iter<'a, PeerRecord>,
}

impl StringPoolBuilder {
    fn intern(&mut self, value: String) -> StringId {
        if let Some(id) = self.ids.get(value.as_str()) {
            return *id;
        }
        let id = StringId::from_index(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("metadata string count is bounded by the response size cap");
        self.total_len = self
            .total_len
            .checked_add(value.len())
            .expect("metadata string bytes are bounded by the response size cap");
        self.ids.insert(value, id);
        id
    }

    fn finish(self) -> StringPool {
        let mut ordered = self.ids.into_iter().collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|(_, id)| id.0);
        let mut data = String::with_capacity(self.total_len);
        let mut spans = Vec::with_capacity(ordered.len());
        for (value, _) in ordered {
            let start = u32::try_from(data.len())
                .expect("metadata string bytes are bounded by the response size cap");
            let len = u32::try_from(value.len())
                .expect("one metadata string is bounded by the response size cap");
            data.push_str(&value);
            spans.push(TextSpan { start, len });
        }
        StringPool {
            data: data.into_boxed_str(),
            spans: spans.into_boxed_slice(),
        }
    }
}

impl StringPool {
    #[inline]
    fn get(&self, id: StringId) -> &str {
        let span = self.spans[id.index()];
        &self.data[span.start as usize..(span.start + span.len) as usize]
    }
}

impl RecordSpan {
    fn from_start_and_end(start: usize, end: usize) -> Self {
        Self {
            start: u32::try_from(start)
                .expect("metadata record count is bounded by the response size cap"),
            len: u32::try_from(end - start)
                .expect("metadata record count is bounded by the response size cap"),
        }
    }

    #[inline]
    fn range(self) -> std::ops::Range<usize> {
        self.start as usize..(self.start + self.len) as usize
    }
}

impl ManifestCore {
    fn empty() -> Self {
        Self {
            strings: StringPool::default(),
            versions: Box::default(),
            version_lookup: Box::default(),
            dependencies: Box::default(),
            peers: Box::default(),
            signatures: Box::default(),
        }
    }

    fn version_id(&self, version: &str) -> Option<usize> {
        self.version_lookup
            .binary_search_by(|index| self.version_text(*index as usize).cmp(version))
            .ok()
            .map(|position| self.version_lookup[position] as usize)
    }

    #[inline]
    fn version_text(&self, version: usize) -> &str {
        self.strings.get(self.versions[version].text)
    }

    fn dependency_records(&self, version: usize) -> &[DependencyRecord] {
        &self.dependencies[self.versions[version].dependencies.range()]
    }

    fn peer_records(&self, version: usize) -> &[PeerRecord] {
        &self.peers[self.versions[version].peers.range()]
    }
}

impl<'a> Iterator for ManifestDependencyIter<'a> {
    type Item = ManifestDependencyRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let record = self.iter.next()?;
        Some(ManifestDependencyRef {
            name: self.core.strings.get(record.name),
            range: self.core.strings.get(record.range),
            alias: record.alias.map(|id| self.core.strings.get(id)),
            optional: record.optional,
            bundled: record.bundled,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl ExactSizeIterator for ManifestDependencyIter<'_> {}

impl<'a> Iterator for ManifestPeerDependencyIter<'a> {
    type Item = ManifestPeerDependencyRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let record = self.iter.next()?;
        Some(ManifestPeerDependencyRef {
            name: self.core.strings.get(record.name),
            range: self.core.strings.get(record.range),
            alias: record.alias.map(|id| self.core.strings.get(id)),
            optional: record.optional,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl ExactSizeIterator for ManifestPeerDependencyIter<'_> {}

impl CachedPackageInfo {
    #[expect(
        clippy::too_many_arguments,
        reason = "the constructor preserves independent cache provenance flags"
    )]
    pub fn from_manifest_versions(
        modified: Option<String>,
        trust_metadata_complete: bool,
        versions_complete: bool,
        covered_ranges: HashSet<String>,
        workspace_versions: HashSet<NpmVersion>,
        platform_metadata_complete: bool,
        latest_version: Option<NpmVersion>,
        manifest_versions: Vec<ManifestVersion>,
    ) -> Self {
        let mut builder = ManifestCacheBuilder::new(
            modified,
            trust_metadata_complete,
            versions_complete,
            covered_ranges,
            workspace_versions,
            platform_metadata_complete,
            latest_version,
            manifest_versions.len(),
        );
        for manifest in manifest_versions {
            builder.push(manifest);
        }
        builder.finish()
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the builder preserves independent cache provenance flags"
    )]
    pub(super) fn builder(
        modified: Option<String>,
        trust_metadata_complete: bool,
        versions_complete: bool,
        covered_ranges: HashSet<String>,
        workspace_versions: HashSet<NpmVersion>,
        platform_metadata_complete: bool,
        latest_version: Option<NpmVersion>,
        version_capacity: usize,
    ) -> ManifestCacheBuilder {
        ManifestCacheBuilder::new(
            modified,
            trust_metadata_complete,
            versions_complete,
            covered_ranges,
            workspace_versions,
            platform_metadata_complete,
            latest_version,
            version_capacity,
        )
    }

    pub fn empty() -> Self {
        Self {
            modified: None,
            modified_unix: None,
            trust_metadata_complete: false,
            versions_complete: true,
            covered_ranges: HashSet::new(),
            workspace_versions: HashSet::new(),
            platform_metadata_complete: false,
            latest_version: None,
            versions: Arc::from([]),
            core: Arc::new(ManifestCore::empty()),
            release: Arc::new(ReleaseOverlay::default()),
            platform: Arc::new(PlatformOverlay::default()),
            trust: Arc::from([]),
        }
    }

    #[inline]
    pub fn dependencies(&self, version: &str) -> Option<ManifestDependencyIter<'_>> {
        let version = self.core.version_id(version)?;
        Some(ManifestDependencyIter {
            core: &self.core,
            iter: self.core.dependency_records(version).iter(),
        })
    }

    #[inline]
    pub fn peer_dependencies(&self, version: &str) -> Option<ManifestPeerDependencyIter<'_>> {
        let version = self.core.version_id(version)?;
        Some(ManifestPeerDependencyIter {
            core: &self.core,
            iter: self.core.peer_records(version).iter(),
        })
    }

    pub fn dependency(&self, version: &str, name: &str) -> Option<ManifestDependencyRef<'_>> {
        let version = self.core.version_id(version)?;
        let records = self.core.dependency_records(version);
        let position = records
            .binary_search_by(|record| self.core.strings.get(record.name).cmp(name))
            .ok()?;
        let record = records[position];
        Some(ManifestDependencyRef {
            name: self.core.strings.get(record.name),
            range: self.core.strings.get(record.range),
            alias: record.alias.map(|id| self.core.strings.get(id)),
            optional: record.optional,
            bundled: record.bundled,
        })
    }

    pub fn peer_dependency(
        &self,
        version: &str,
        name: &str,
    ) -> Option<ManifestPeerDependencyRef<'_>> {
        let version = self.core.version_id(version)?;
        let records = self.core.peer_records(version);
        let position = records
            .binary_search_by(|record| self.core.strings.get(record.name).cmp(name))
            .ok()?;
        let record = records[position];
        Some(ManifestPeerDependencyRef {
            name: self.core.strings.get(record.name),
            range: self.core.strings.get(record.range),
            alias: record.alias.map(|id| self.core.strings.get(id)),
            optional: record.optional,
        })
    }

    pub fn dependency_aliases(&self, version: &str) -> HashMap<String, String> {
        self.dependencies(version)
            .into_iter()
            .flatten()
            .filter_map(|dependency| {
                dependency
                    .alias
                    .map(|alias| (dependency.name.to_owned(), alias.to_owned()))
            })
            .collect()
    }

    pub fn optional_dependency_names(&self, version: &str) -> HashSet<String> {
        self.dependencies(version)
            .into_iter()
            .flatten()
            .filter(|dependency| dependency.optional)
            .map(|dependency| dependency.name.to_owned())
            .collect()
    }

    pub fn bundled_dependency_names(&self, version: &str) -> HashSet<String> {
        self.dependencies(version)
            .into_iter()
            .flatten()
            .filter(|dependency| dependency.bundled)
            .map(|dependency| dependency.name.to_owned())
            .collect()
    }

    pub fn optional_peer_names(&self, version: &str) -> HashSet<String> {
        self.peer_dependencies(version)
            .into_iter()
            .flatten()
            .filter(|peer| peer.optional)
            .map(|peer| peer.name.to_owned())
            .collect()
    }

    pub fn peer_aliases(&self, version: &str) -> HashMap<String, String> {
        self.peer_dependencies(version)
            .into_iter()
            .flatten()
            .filter_map(|peer| {
                peer.alias
                    .map(|alias| (peer.name.to_owned(), alias.to_owned()))
            })
            .collect()
    }

    pub fn node_engine(&self, version: &str) -> Option<&str> {
        let version = self.core.version_id(version)?;
        self.core.versions[version]
            .node_engine
            .map(|id| self.core.strings.get(id))
    }

    pub fn tarball_url(&self, version: &str) -> Option<&str> {
        let version = self.core.version_id(version)?;
        self.core.versions[version]
            .tarball_url
            .map(|id| self.core.strings.get(id))
    }

    pub fn integrity(&self, version: &str) -> Option<&str> {
        let version = self.core.version_id(version)?;
        self.core.versions[version]
            .integrity
            .map(|id| self.core.strings.get(id))
    }

    pub fn unpacked_size(&self, version: &str) -> Option<NonZeroU64> {
        let version = self.core.version_id(version)?;
        self.core.versions[version].unpacked_size
    }

    pub fn signatures(&self, version: &str) -> &[lpm_registry::RegistrySignature] {
        let Some(version) = self.core.version_id(version) else {
            return &[];
        };
        &self.core.signatures[self.core.versions[version].signatures.range()]
    }

    pub fn published_at(&self, version: &str) -> Option<&str> {
        let version = self.core.version_id(version)? as u32;
        let record = find_version_record(&self.release.records, version, |record| record.version)?;
        Some(self.release.strings.get(record.published_at))
    }

    pub fn published_at_unix(&self, version: &str) -> Option<i64> {
        let version = self.core.version_id(version)? as u32;
        find_version_record(&self.release.records, version, |record| record.version)?
            .published_at_unix
    }

    pub fn trust_evidence(&self, version: &str) -> Option<TrustEvidence> {
        let version = self.core.version_id(version)? as u32;
        find_version_record(&self.trust, version, |record| record.version)
            .map(|record| record.evidence)
    }

    pub fn dist(&self, version: &str) -> Option<CachedDistInfo> {
        let version_id = self.core.version_id(version)?;
        let record = self.core.versions[version_id];
        Some(CachedDistInfo {
            tarball_url: record
                .tarball_url
                .map(|id| self.core.strings.get(id).to_owned()),
            integrity: record
                .integrity
                .map(|id| self.core.strings.get(id).to_owned()),
            unpacked_size: record.unpacked_size,
            signatures: self.core.signatures[record.signatures.range()].to_vec(),
            published_at: self.published_at(version).map(str::to_owned),
            published_at_unix: self.published_at_unix(version),
            trust_evidence: self.trust_evidence(version),
        })
    }

    pub fn platform(&self, version: &str) -> Option<PlatformMeta> {
        let version = self.core.version_id(version)? as u32;
        let record = find_version_record(&self.platform.records, version, |record| record.version)?;
        Some(PlatformMeta {
            os: platform_values(&self.platform, record.os),
            cpu: platform_values(&self.platform, record.cpu),
            libc: platform_values(&self.platform, record.libc),
        })
    }

    pub fn platform_is_compatible(&self, version: &str) -> Option<bool> {
        let version = self.core.version_id(version)? as u32;
        let record = find_version_record(&self.platform.records, version, |record| record.version)?;
        Some(super::platform::is_platform_compatible_values(
            platform_value_refs(&self.platform, record.os),
            platform_value_refs(&self.platform, record.cpu),
            platform_value_refs(&self.platform, record.libc),
        ))
    }

    pub fn has_platform_metadata(&self) -> bool {
        !self.platform.records.is_empty()
    }

    pub fn merge_release_times(&mut self, release_times: &lpm_registry::ReleaseTimeMetadata) {
        let mut releases = self
            .release
            .records
            .iter()
            .map(|record| {
                (
                    record.version as usize,
                    self.release.strings.get(record.published_at).to_owned(),
                    record.published_at_unix,
                )
            })
            .collect::<Vec<_>>();
        let mut known_release_versions = releases
            .iter()
            .map(|(version, _, _)| *version)
            .collect::<HashSet<_>>();
        for (version, published_at) in &release_times.time {
            let Some(version) = self.core.version_id(version) else {
                continue;
            };
            if known_release_versions.insert(version) {
                releases.push((
                    version,
                    published_at.clone(),
                    parse_npm_time_unix(published_at),
                ));
            }
        }
        self.release = Arc::new(build_release_overlay(releases));

        if let Some(release_platforms) = &release_times.versions {
            let mut platforms = self.platforms_owned();
            for (version, incoming) in release_platforms {
                let Some(version) = self.core.version_id(version) else {
                    continue;
                };
                let platform = platforms.entry(version).or_default();
                if platform.os.is_empty() {
                    platform.os.clone_from(&incoming.os);
                }
                if platform.cpu.is_empty() {
                    platform.cpu.clone_from(&incoming.cpu);
                }
                if platform.libc.is_empty() {
                    platform.libc.clone_from(&incoming.libc);
                }
            }
            self.platform = Arc::new(build_platform_overlay(platforms));
            self.platform_metadata_complete = true;
        }
    }

    #[cfg(test)]
    pub(crate) fn manifest_versions_owned(&self) -> Vec<ManifestVersion> {
        (0..self.versions.len())
            .map(|version| self.manifest_version_owned(version))
            .collect()
    }

    pub(super) fn manifest_version_owned_for(
        &self,
        version: &NpmVersion,
    ) -> Option<ManifestVersion> {
        let version = self.core.version_id(&version.to_string())?;
        Some(self.manifest_version_owned(version))
    }

    pub(crate) fn share_manifest_core_from_if_equivalent(&mut self, other: &Self) -> bool {
        if !self.manifest_core_content_eq(other) {
            return false;
        }
        self.versions = Arc::clone(&other.versions);
        self.core = Arc::clone(&other.core);
        true
    }

    #[cfg(test)]
    pub(crate) fn update_manifest_version(
        &mut self,
        version: &str,
        update: impl FnOnce(&mut ManifestVersion),
    ) -> bool {
        let mut manifests = self.manifest_versions_owned();
        let Some(manifest) = manifests
            .iter_mut()
            .find(|manifest| manifest.version.to_string() == version)
        else {
            return false;
        };
        update(manifest);
        let replacement = Self::from_manifest_versions(
            self.modified.clone(),
            self.trust_metadata_complete,
            self.versions_complete,
            self.covered_ranges.clone(),
            self.workspace_versions.clone(),
            self.platform_metadata_complete,
            self.latest_version.clone(),
            manifests,
        );
        *self = replacement;
        true
    }

    fn manifest_version_owned(&self, version: usize) -> ManifestVersion {
        let version_text = self.core.version_text(version);
        ManifestVersion {
            version: self.versions[version].clone(),
            dependencies: self
                .dependencies(version_text)
                .into_iter()
                .flatten()
                .map(|dependency| ManifestDependency {
                    name: dependency.name.to_owned(),
                    range: dependency.range.to_owned(),
                    alias: dependency.alias.map(str::to_owned),
                    optional: dependency.optional,
                    bundled: dependency.bundled,
                })
                .collect(),
            peer_dependencies: self
                .peer_dependencies(version_text)
                .into_iter()
                .flatten()
                .map(|peer| ManifestPeerDependency {
                    name: peer.name.to_owned(),
                    range: peer.range.to_owned(),
                    alias: peer.alias.map(str::to_owned),
                    optional: peer.optional,
                })
                .collect(),
            node_engine: self.node_engine(version_text).map(str::to_owned),
            platform: self.platform(version_text),
            dist: self.dist(version_text).unwrap_or_default(),
        }
    }

    fn manifest_core_content_eq(&self, other: &Self) -> bool {
        if self.versions.as_ref() != other.versions.as_ref() {
            return false;
        }
        for version in 0..self.versions.len() {
            let left = self.core.versions[version];
            let right = other.core.versions[version];
            if left.unpacked_size != right.unpacked_size
                || optional_pool_value(&self.core.strings, left.node_engine)
                    != optional_pool_value(&other.core.strings, right.node_engine)
                || optional_pool_value(&self.core.strings, left.tarball_url)
                    != optional_pool_value(&other.core.strings, right.tarball_url)
                || optional_pool_value(&self.core.strings, left.integrity)
                    != optional_pool_value(&other.core.strings, right.integrity)
                || self.core.signatures[left.signatures.range()]
                    != other.core.signatures[right.signatures.range()]
            {
                return false;
            }
            let left_dependencies = ManifestDependencyIter {
                core: &self.core,
                iter: self.core.dependency_records(version).iter(),
            };
            let right_dependencies = ManifestDependencyIter {
                core: &other.core,
                iter: other.core.dependency_records(version).iter(),
            };
            if !left_dependencies.eq(right_dependencies) {
                return false;
            }
            let left_peers = ManifestPeerDependencyIter {
                core: &self.core,
                iter: self.core.peer_records(version).iter(),
            };
            let right_peers = ManifestPeerDependencyIter {
                core: &other.core,
                iter: other.core.peer_records(version).iter(),
            };
            if !left_peers.eq(right_peers) {
                return false;
            }
        }
        true
    }

    fn platforms_owned(&self) -> HashMap<usize, PlatformMeta> {
        self.platform
            .records
            .iter()
            .map(|record| {
                (
                    record.version as usize,
                    PlatformMeta {
                        os: platform_values(&self.platform, record.os),
                        cpu: platform_values(&self.platform, record.cpu),
                        libc: platform_values(&self.platform, record.libc),
                    },
                )
            })
            .collect()
    }

    pub fn needs_metadata_for_range(&self, range: &NpmRange) -> bool {
        if self.versions_complete {
            return false;
        }
        if !self.workspace_versions.is_empty() {
            return true;
        }
        if let Some(exact) = range.exact_version() {
            return !self.versions.contains(&exact);
        }
        !self.covered_ranges.contains(range.raw())
            || !self.versions.iter().any(|version| {
                range.satisfies_with_latest_bound(version, self.latest_version.as_ref())
            })
    }

    pub fn workspace_version_satisfies(&self, range: &NpmRange) -> bool {
        self.workspace_versions
            .iter()
            .any(|version| range.satisfies_with_latest_bound(version, self.latest_version.as_ref()))
    }

    pub fn needs_trust_metadata(&self, policy: &ResolverPolicy) -> bool {
        policy.requires_trust_history() && !self.trust_metadata_complete
    }

    pub fn needs_release_time_metadata(
        &self,
        package: &CanonicalKey,
        policy: &ResolverPolicy,
    ) -> bool {
        if !policy.release_age_active() || policy.release_age_excluded(package) {
            return false;
        }
        let missing_version_time = self.release.records.len() < self.core.versions.len();
        missing_version_time
            && policy.metadata_modified_after_cutoff_for_package(
                package,
                self.modified.as_deref(),
                self.modified_unix,
            )
    }

    pub fn needs_policy_metadata(&self, package: &CanonicalKey, policy: &ResolverPolicy) -> bool {
        self.needs_trust_metadata(policy) || self.needs_release_time_metadata(package, policy)
    }

    pub fn needs_platform_metadata(&self) -> bool {
        !self.platform_metadata_complete
            && self.platform.records.iter().any(|record| {
                let os = platform_value_refs(&self.platform, record.os);
                let cpu_is_empty = record.cpu.len == 0;
                let libc_is_empty = record.libc.len == 0;
                libc_is_empty
                    && (record.os.len != 0 || !cpu_is_empty)
                    && platform_may_target_linux(os)
            })
    }

    pub fn needs_supplemental_metadata(
        &self,
        package: &CanonicalKey,
        policy: &ResolverPolicy,
    ) -> bool {
        self.needs_policy_metadata(package, policy) || self.needs_platform_metadata()
    }
}

impl ManifestCacheBuilder {
    #[expect(
        clippy::too_many_arguments,
        reason = "the builder preserves independent cache provenance flags"
    )]
    fn new(
        modified: Option<String>,
        trust_metadata_complete: bool,
        versions_complete: bool,
        covered_ranges: HashSet<String>,
        workspace_versions: HashSet<NpmVersion>,
        platform_metadata_complete: bool,
        latest_version: Option<NpmVersion>,
        version_capacity: usize,
    ) -> Self {
        Self {
            modified,
            trust_metadata_complete,
            versions_complete,
            covered_ranges,
            workspace_versions,
            platform_metadata_complete,
            latest_version,
            strings: StringPoolBuilder::default(),
            versions: Vec::with_capacity(version_capacity),
            dependencies: Vec::new(),
            peers: Vec::new(),
            signatures: Vec::new(),
        }
    }

    pub(super) fn push(&mut self, mut manifest: ManifestVersion) {
        manifest
            .dependencies
            .sort_unstable_by(|left, right| left.name.cmp(&right.name));
        manifest
            .dependencies
            .dedup_by(|left, right| left.name == right.name);
        manifest.peer_dependencies.retain(|peer| {
            manifest
                .dependencies
                .binary_search_by(|dependency| dependency.name.as_str().cmp(&peer.name))
                .is_err()
        });
        manifest
            .peer_dependencies
            .sort_unstable_by(|left, right| left.name.cmp(&right.name));
        manifest
            .peer_dependencies
            .dedup_by(|left, right| left.name == right.name);

        let text = self.strings.intern(manifest.version.to_string());
        let dependency_start = self.dependencies.len();
        for dependency in manifest.dependencies {
            self.dependencies.push(DependencyRecord {
                name: self.strings.intern(dependency.name),
                range: self.strings.intern(dependency.range),
                alias: dependency.alias.map(|alias| self.strings.intern(alias)),
                optional: dependency.optional,
                bundled: dependency.bundled,
            });
        }
        let dependencies =
            RecordSpan::from_start_and_end(dependency_start, self.dependencies.len());

        let peer_start = self.peers.len();
        for peer in manifest.peer_dependencies {
            self.peers.push(PeerRecord {
                name: self.strings.intern(peer.name),
                range: self.strings.intern(peer.range),
                alias: peer.alias.map(|alias| self.strings.intern(alias)),
                optional: peer.optional,
            });
        }
        let peers = RecordSpan::from_start_and_end(peer_start, self.peers.len());

        let signature_start = self.signatures.len();
        self.signatures.extend(manifest.dist.signatures);
        let signatures = RecordSpan::from_start_and_end(signature_start, self.signatures.len());

        self.versions.push(StagedVersion {
            version: manifest.version,
            record: VersionRecord {
                text,
                dependencies,
                peers,
                node_engine: manifest.node_engine.map(|value| self.strings.intern(value)),
                tarball_url: manifest
                    .dist
                    .tarball_url
                    .map(|value| self.strings.intern(value)),
                integrity: manifest
                    .dist
                    .integrity
                    .map(|value| self.strings.intern(value)),
                unpacked_size: manifest.dist.unpacked_size,
                signatures,
            },
            published_at: manifest.dist.published_at,
            published_at_unix: manifest.dist.published_at_unix,
            platform: manifest.platform,
            trust_evidence: manifest.dist.trust_evidence,
        });
    }

    pub(super) fn finish(mut self) -> CachedPackageInfo {
        self.versions
            .sort_unstable_by(|left, right| right.version.cmp(&left.version));
        self.versions
            .dedup_by(|left, right| left.version == right.version);

        let version_count = self.versions.len();
        let mut versions = Vec::with_capacity(version_count);
        let mut version_records = Vec::with_capacity(version_count);
        let mut release_inputs = Vec::new();
        let mut platform_inputs = Vec::new();
        let mut trust = Vec::new();
        for (version_id, staged) in self.versions.into_iter().enumerate() {
            versions.push(staged.version);
            version_records.push(staged.record);
            if let Some(published_at) = staged.published_at {
                release_inputs.push((version_id, published_at, staged.published_at_unix));
            }
            if let Some(platform) = staged.platform {
                platform_inputs.push((version_id, platform));
            }
            if let Some(evidence) = staged.trust_evidence {
                trust.push(TrustRecord {
                    version: version_id as u32,
                    evidence,
                });
            }
        }

        let pool = self.strings.finish();
        let mut version_lookup = (0..version_records.len() as u32).collect::<Vec<_>>();
        version_lookup.sort_unstable_by(|left, right| {
            pool.get(version_records[*left as usize].text)
                .cmp(pool.get(version_records[*right as usize].text))
        });
        let modified_unix = self.modified.as_deref().and_then(parse_npm_time_unix);
        CachedPackageInfo {
            modified: self.modified,
            modified_unix,
            trust_metadata_complete: self.trust_metadata_complete,
            versions_complete: self.versions_complete,
            covered_ranges: self.covered_ranges,
            workspace_versions: self.workspace_versions,
            platform_metadata_complete: self.platform_metadata_complete,
            latest_version: self.latest_version,
            versions: Arc::from(versions),
            core: Arc::new(ManifestCore {
                strings: pool,
                versions: version_records.into_boxed_slice(),
                version_lookup: version_lookup.into_boxed_slice(),
                dependencies: self.dependencies.into_boxed_slice(),
                peers: self.peers.into_boxed_slice(),
                signatures: self.signatures.into_boxed_slice(),
            }),
            release: Arc::new(build_release_overlay(release_inputs)),
            platform: Arc::new(build_platform_overlay(platform_inputs)),
            trust: Arc::from(trust),
        }
    }
}

fn build_release_overlay(mut inputs: Vec<(usize, String, Option<i64>)>) -> ReleaseOverlay {
    inputs.sort_unstable_by_key(|(version, _, _)| *version);
    let mut strings = StringPoolBuilder::default();
    let records = inputs
        .into_iter()
        .map(|(version, published_at, published_at_unix)| ReleaseRecord {
            version: version as u32,
            published_at: strings.intern(published_at),
            published_at_unix,
        })
        .collect::<Vec<_>>();
    ReleaseOverlay {
        strings: strings.finish(),
        records: records.into_boxed_slice(),
    }
}

fn build_platform_overlay(
    inputs: impl IntoIterator<Item = (usize, PlatformMeta)>,
) -> PlatformOverlay {
    let mut inputs = inputs.into_iter().collect::<Vec<_>>();
    inputs.sort_unstable_by_key(|(version, _)| *version);
    let mut strings = StringPoolBuilder::default();
    let mut values = Vec::new();
    let mut records = Vec::with_capacity(inputs.len());
    for (version, platform) in inputs {
        let os = push_platform_values(&mut strings, &mut values, platform.os);
        let cpu = push_platform_values(&mut strings, &mut values, platform.cpu);
        let libc = push_platform_values(&mut strings, &mut values, platform.libc);
        records.push(PlatformRecord {
            version: version as u32,
            os,
            cpu,
            libc,
        });
    }
    PlatformOverlay {
        strings: strings.finish(),
        values: values.into_boxed_slice(),
        records: records.into_boxed_slice(),
    }
}

fn push_platform_values(
    strings: &mut StringPoolBuilder,
    values: &mut Vec<StringId>,
    input: Vec<String>,
) -> RecordSpan {
    let start = values.len();
    values.extend(input.into_iter().map(|value| strings.intern(value)));
    RecordSpan::from_start_and_end(start, values.len())
}

fn platform_values(overlay: &PlatformOverlay, span: RecordSpan) -> Vec<String> {
    platform_value_refs(overlay, span)
        .map(str::to_owned)
        .collect()
}

fn platform_value_refs(overlay: &PlatformOverlay, span: RecordSpan) -> impl Iterator<Item = &str> {
    overlay.values[span.range()]
        .iter()
        .map(|id| overlay.strings.get(*id))
}

fn optional_pool_value(pool: &StringPool, id: Option<StringId>) -> Option<&str> {
    id.map(|id| pool.get(id))
}

fn find_version_record<T>(records: &[T], version: u32, key: impl Fn(&T) -> u32) -> Option<&T> {
    records
        .binary_search_by_key(&version, key)
        .ok()
        .map(|index| &records[index])
}

fn platform_may_target_linux<'a>(os: impl Iterator<Item = &'a str>) -> bool {
    let mut saw_entry = false;
    let mut saw_exclusion = false;
    let mut excludes_linux = false;
    let mut includes_linux = false;
    for entry in os {
        saw_entry = true;
        saw_exclusion |= entry.starts_with('!');
        excludes_linux |= entry == "!linux";
        includes_linux |= entry == "linux";
    }
    if !saw_entry {
        return true;
    }
    if saw_exclusion {
        return !excludes_linux;
    }
    includes_linux
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str) -> ManifestVersion {
        ManifestVersion {
            version: NpmVersion::parse(version).unwrap(),
            dependencies: Vec::new(),
            peer_dependencies: Vec::new(),
            node_engine: None,
            platform: None,
            dist: CachedDistInfo::default(),
        }
    }

    fn info_from(manifests: Vec<ManifestVersion>) -> CachedPackageInfo {
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

    #[test]
    fn repeated_dependency_strings_share_one_pool_entry() {
        let mut first = manifest("1.0.0");
        first.dependencies.push(ManifestDependency {
            name: "shared-dependency".to_string(),
            range: "^2.0.0".to_string(),
            alias: None,
            optional: false,
            bundled: false,
        });
        let mut second = manifest("2.0.0");
        second.dependencies.clone_from(&first.dependencies);

        let info = info_from(vec![first, second]);

        assert_eq!(
            info.core.dependencies[0].name,
            info.core.dependencies[1].name
        );
        assert_eq!(
            info.core.dependencies[0].range,
            info.core.dependencies[1].range
        );
    }

    #[test]
    fn manifest_accessors_preserve_all_compact_record_fields() {
        let mut rich = manifest("1.2.3");
        rich.dependencies.push(ManifestDependency {
            name: "local-slot".to_string(),
            range: "^4.0.0".to_string(),
            alias: Some("canonical-target".to_string()),
            optional: true,
            bundled: true,
        });
        rich.peer_dependencies.push(ManifestPeerDependency {
            name: "peer-slot".to_string(),
            range: "^18.0.0".to_string(),
            alias: Some("react".to_string()),
            optional: true,
        });
        rich.node_engine = Some(">=22".to_string());
        rich.platform = Some(PlatformMeta {
            os: vec!["darwin".to_string()],
            cpu: vec!["arm64".to_string()],
            libc: vec!["glibc".to_string()],
        });
        rich.dist = CachedDistInfo {
            tarball_url: Some("https://registry.invalid/pkg.tgz".to_string()),
            integrity: Some("sha512-fixture".to_string()),
            unpacked_size: NonZeroU64::new(42),
            signatures: vec![lpm_registry::RegistrySignature {
                keyid: Some("SHA256:key".to_string()),
                sig: Some("signature".to_string()),
            }],
            published_at: Some("2026-01-02T03:04:05.000Z".to_string()),
            published_at_unix: Some(1_767_323_045),
            trust_evidence: Some(TrustEvidence::TrustedPublisher),
        };

        let info = info_from(vec![rich.clone()]);

        assert_eq!(info.manifest_versions_owned(), vec![rich]);
    }

    #[test]
    fn release_time_hydration_reuses_the_immutable_manifest_core() {
        let mut info = info_from(vec![manifest("1.0.0")]);
        let original_core = Arc::clone(&info.core);
        let original_release = Arc::clone(&info.release);
        let release_times = lpm_registry::ReleaseTimeMetadata {
            name: Some("fixture".to_string()),
            time: HashMap::from([("1.0.0".to_string(), "2025-01-01T00:00:00.000Z".to_string())]),
            versions: None,
        };

        info.merge_release_times(&release_times);

        assert!(Arc::ptr_eq(&info.core, &original_core));
        assert!(!Arc::ptr_eq(&info.release, &original_release));
        assert_eq!(info.published_at("1.0.0"), Some("2025-01-01T00:00:00.000Z"));
    }

    #[test]
    fn equivalent_policy_hydration_shares_the_original_manifest_core() {
        let base = info_from(vec![manifest("1.0.0")]);
        let mut hydrated_manifest = manifest("1.0.0");
        hydrated_manifest.dist.published_at = Some("2025-01-01T00:00:00.000Z".to_string());
        hydrated_manifest.dist.published_at_unix = Some(1_735_689_600);
        hydrated_manifest.dist.trust_evidence = Some(TrustEvidence::TrustedPublisher);
        let mut hydrated = info_from(vec![hydrated_manifest]);

        assert!(hydrated.share_manifest_core_from_if_equivalent(&base));
        assert!(Arc::ptr_eq(&hydrated.core, &base.core));
        assert_eq!(
            hydrated.published_at("1.0.0"),
            Some("2025-01-01T00:00:00.000Z")
        );
        assert_eq!(
            hydrated.trust_evidence("1.0.0"),
            Some(TrustEvidence::TrustedPublisher)
        );
    }

    #[test]
    fn policy_hydration_keeps_its_core_when_distribution_fields_changed() {
        let base = info_from(vec![manifest("1.0.0")]);
        let mut changed_manifest = manifest("1.0.0");
        changed_manifest.dist.integrity = Some("sha512-new".to_string());
        let mut changed = info_from(vec![changed_manifest]);
        let changed_core = Arc::clone(&changed.core);

        assert!(!changed.share_manifest_core_from_if_equivalent(&base));
        assert!(Arc::ptr_eq(&changed.core, &changed_core));
        assert!(!Arc::ptr_eq(&changed.core, &base.core));
    }

    #[test]
    fn compact_record_layout_stays_below_one_cache_line() {
        assert_eq!(std::mem::size_of::<StringId>(), 4);
        assert_eq!(std::mem::size_of::<Option<StringId>>(), 4);
        assert!(std::mem::size_of::<VersionRecord>() <= 48);
        assert!(std::mem::size_of::<DependencyRecord>() <= 16);
        assert!(std::mem::size_of::<PeerRecord>() <= 16);
    }
}
