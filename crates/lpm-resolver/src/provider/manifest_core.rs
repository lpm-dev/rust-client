use std::collections::{HashMap, HashSet};
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;

use crate::npm_version::NpmVersion;
use crate::package::CanonicalKey;
use crate::policy::{ResolverPolicy, TrustEvidence, parse_npm_time_unix};
use crate::ranges::NpmRange;

mod codec;

pub(crate) use codec::ManifestProjection;

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
    pub release_metadata_complete: bool,
    pub versions_complete: bool,
    pub covered_ranges: HashSet<String>,
    pub workspace_versions: HashSet<NpmVersion>,
    pub platform_metadata_complete: bool,
    pub(crate) platform_hydrated_versions: HashSet<String>,
    pub latest_version: Option<NpmVersion>,
    pub latest_version_hint: Option<NpmVersion>,
    pub(crate) preferred_latest: Option<NpmVersion>,
    pub versions: Arc<[NpmVersion]>,
    dist_tags: Arc<HashMap<String, NpmVersion>>,
    core: Arc<ManifestCore>,
    release: Arc<ReleaseOverlay>,
    platform: Arc<PlatformOverlay>,
    trust: Arc<[TrustRecord]>,
    trust_timeline: TrustTimeline,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TrustTimeline {
    pub(crate) earliest_trusted_stable: Option<i64>,
    pub(crate) earliest_trusted_any: Option<i64>,
    pub(crate) earliest_staged_stable: Option<i64>,
    pub(crate) earliest_staged_any: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestCore {
    strings: StringPool,
    versions: Box<[VersionRecord]>,
    version_lookup: Box<[u32]>,
    dependencies: Box<[DependencyRecord]>,
    peers: Box<[PeerRecord]>,
    signatures: Box<[SignatureRecord]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SignatureRecord {
    keyid: Option<StringId>,
    sig: Option<StringId>,
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

struct StringPoolBuilder {
    data: String,
    spans: Vec<TextSpan>,
    /// Open-addressing index table storing `StringId.0.get()` (`0` = empty).
    /// Power-of-two length whenever non-empty; avoids per-string heap
    /// allocations and produces a deterministic ID-ordered arena directly.
    table: Vec<u32>,
    hasher: ahash::RandomState,
}

impl Default for StringPoolBuilder {
    fn default() -> Self {
        Self {
            data: String::new(),
            spans: Vec::new(),
            table: Vec::new(),
            hasher: ahash::RandomState::with_seeds(
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ),
        }
    }
}

pub(super) struct ManifestCacheBuilder {
    modified: Option<String>,
    trust_metadata_complete: bool,
    versions_complete: bool,
    covered_ranges: HashSet<String>,
    workspace_versions: HashSet<NpmVersion>,
    platform_metadata_complete: bool,
    latest_version: Option<NpmVersion>,
    dist_tags: HashMap<String, NpmVersion>,
    strings: StringPoolBuilder,
    versions: Vec<StagedVersion>,
    dependencies: Vec<DependencyRecord>,
    peers: Vec<PeerRecord>,
    signatures: Vec<SignatureRecord>,
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
    #[inline]
    fn span_str(&self, id_raw: u32) -> &str {
        let span = self.spans[(id_raw - 1) as usize];
        &self.data[span.start as usize..(span.start + span.len) as usize]
    }

    fn grow_table(&mut self) {
        let new_cap = (self.table.len() * 2).max(16);
        let mask = new_cap - 1;
        let mut next = vec![0u32; new_cap];
        for (idx, span) in self.spans.iter().enumerate() {
            let s = &self.data[span.start as usize..(span.start + span.len) as usize];
            let mut slot = (self.hasher.hash_one(s) as usize) & mask;
            while next[slot] != 0 {
                slot = (slot + 1) & mask;
            }
            next[slot] = (idx as u32) + 1;
        }
        self.table = next;
    }

    fn intern(&mut self, value: &str) -> StringId {
        if self.table.is_empty() || (self.spans.len() + 1) * 10 > self.table.len() * 7 {
            self.grow_table();
        }
        let mask = self.table.len() - 1;
        let mut slot = (self.hasher.hash_one(value) as usize) & mask;
        loop {
            let existing = self.table[slot];
            if existing == 0 {
                let index = u32::try_from(self.spans.len())
                    .expect("metadata string count is bounded by the response size cap");
                let id = StringId::from_index(index);
                let start = u32::try_from(self.data.len())
                    .expect("metadata string bytes are bounded by the response size cap");
                let len = u32::try_from(value.len())
                    .expect("one metadata string is bounded by the response size cap");
                self.data.push_str(value);
                self.spans.push(TextSpan { start, len });
                self.table[slot] = id.0.get();
                return id;
            }
            if self.span_str(existing) == value {
                return StringId(
                    NonZeroU32::new(existing).expect("occupied table entries are non-zero"),
                );
            }
            slot = (slot + 1) & mask;
        }
    }

    fn finish(self) -> StringPool {
        StringPool {
            data: self.data.into_boxed_str(),
            spans: self.spans.into_boxed_slice(),
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
            release_metadata_complete: false,
            versions_complete: true,
            covered_ranges: HashSet::new(),
            workspace_versions: HashSet::new(),
            platform_metadata_complete: false,
            platform_hydrated_versions: HashSet::new(),
            latest_version: None,
            latest_version_hint: None,
            preferred_latest: None,
            versions: Arc::from([]),
            dist_tags: Arc::new(HashMap::new()),
            core: Arc::new(ManifestCore::empty()),
            release: Arc::new(ReleaseOverlay::default()),
            platform: Arc::new(PlatformOverlay::default()),
            trust: Arc::from([]),
            trust_timeline: TrustTimeline::default(),
        }
    }

    #[inline]
    pub(crate) fn version_id_for(&self, version: &NpmVersion) -> Option<usize> {
        if version.as_inner().build.is_empty() {
            let idx = self
                .versions
                .binary_search_by(|candidate| version.cmp(candidate))
                .ok()?;
            if self.versions[idx].as_inner().build.is_empty() {
                return Some(idx);
            }
        }
        self.core.version_id(&version.to_string())
    }

    #[inline]
    pub(crate) fn version_view(&self, version: &str) -> Option<VersionView<'_>> {
        let id = self.core.version_id(version)?;
        Some(VersionView { info: self, id })
    }

    #[inline]
    pub(crate) fn release_records_empty(&self) -> bool {
        self.release.records.is_empty()
    }

    #[inline]
    pub(crate) fn trust_is_empty(&self) -> bool {
        self.trust.is_empty()
    }

    #[inline]
    pub(crate) fn trust_timeline(&self) -> TrustTimeline {
        self.trust_timeline
    }

    #[inline]
    pub(crate) fn published_at_unix_for(&self, version: &NpmVersion) -> Option<i64> {
        let version = self.version_id_for(version)? as u32;
        find_version_record(&self.release.records, version, |record| record.version)?
            .published_at_unix
    }

    #[inline]
    pub(crate) fn trust_evidence_for(&self, version: &NpmVersion) -> Option<TrustEvidence> {
        let version = self.version_id_for(version)? as u32;
        find_version_record(&self.trust, version, |record| record.version)
            .map(|record| record.evidence)
    }

    #[inline]
    pub(crate) fn platform_is_compatible_for(&self, version: &NpmVersion) -> Option<bool> {
        let version = self.version_id_for(version)? as u32;
        let record = find_version_record(&self.platform.records, version, |record| record.version)?;
        Some(super::platform::is_platform_compatible_values(
            platform_value_refs(&self.platform, record.os),
            platform_value_refs(&self.platform, record.cpu),
            platform_value_refs(&self.platform, record.libc),
        ))
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

    pub fn signatures(&self, version: &str) -> Vec<lpm_registry::RegistrySignature> {
        let Some(version) = self.core.version_id(version) else {
            return Vec::new();
        };
        self.signatures_by_id(version)
    }

    fn signatures_by_id(&self, version: usize) -> Vec<lpm_registry::RegistrySignature> {
        self.core.signatures[self.core.versions[version].signatures.range()]
            .iter()
            .map(|record| lpm_registry::RegistrySignature {
                keyid: record.keyid.map(|id| self.core.strings.get(id).to_owned()),
                sig: record.sig.map(|id| self.core.strings.get(id).to_owned()),
            })
            .collect()
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

    #[inline]
    pub fn dist_tag_version(&self, tag: &str) -> Option<&NpmVersion> {
        if tag == "latest" {
            self.latest_version.as_ref()
        } else {
            self.dist_tags.get(tag)
        }
    }

    pub(crate) fn dist_tags(&self) -> &HashMap<String, NpmVersion> {
        &self.dist_tags
    }

    #[inline]
    pub fn tagged_version_for_range(&self, range: &NpmRange) -> Option<&NpmVersion> {
        range.dist_tag().and_then(|tag| self.dist_tag_version(tag))
    }

    #[inline]
    pub fn range_satisfies(&self, range: &NpmRange, version: &NpmVersion) -> bool {
        range.satisfies_with_dist_tag(version, self.tagged_version_for_range(range))
    }

    pub fn dist(&self, version: &str) -> Option<CachedDistInfo> {
        let version_id = self.core.version_id(version)?;
        Some(self.dist_by_id(version_id))
    }

    fn dist_by_id(&self, version_id: usize) -> CachedDistInfo {
        let record = self.core.versions[version_id];
        let version_u32 = version_id as u32;
        let release =
            find_version_record(&self.release.records, version_u32, |record| record.version);
        let trust_evidence = find_version_record(&self.trust, version_u32, |record| record.version)
            .map(|record| record.evidence);
        CachedDistInfo {
            tarball_url: record
                .tarball_url
                .map(|id| self.core.strings.get(id).to_owned()),
            integrity: record
                .integrity
                .map(|id| self.core.strings.get(id).to_owned()),
            unpacked_size: record.unpacked_size,
            signatures: self.signatures_by_id(version_id),
            published_at: release
                .map(|record| self.release.strings.get(record.published_at).to_owned()),
            published_at_unix: release.and_then(|record| record.published_at_unix),
            trust_evidence,
        }
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

    #[inline]
    pub(crate) fn version_strs(&self) -> Vec<&str> {
        self.core
            .versions
            .iter()
            .map(|record| self.core.strings.get(record.text))
            .collect()
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
        self.trust_timeline =
            build_trust_timeline(&self.versions, &self.release.records, &self.trust);
        let modified_matches = self.modified.as_deref().is_some_and(|expected| {
            release_times.time.get("modified").map(String::as_str) == Some(expected)
        });
        let all_versions_covered = self.core.versions.is_empty()
            || (0..self.core.versions.len()).all(|idx| known_release_versions.contains(&idx));
        if !release_times.time.is_empty() && (all_versions_covered || modified_matches) {
            self.release_metadata_complete = true;
        }

        if let Some(release_platforms) = &release_times.versions {
            let mut platforms = self.platforms_owned();
            let mut known_platform_versions = HashSet::with_capacity(release_platforms.len());
            for (version_text, incoming) in release_platforms {
                let Some(version) = self.core.version_id(version_text) else {
                    continue;
                };
                known_platform_versions.insert(version);
                self.platform_hydrated_versions.insert(version_text.clone());
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
            let all_platform_versions_covered = self.core.versions.is_empty()
                || (0..self.core.versions.len()).all(|idx| known_platform_versions.contains(&idx));
            if all_platform_versions_covered || modified_matches {
                self.platform_metadata_complete = true;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn manifest_versions_owned(&self) -> Vec<ManifestVersion> {
        (0..self.versions.len())
            .map(|version| self.manifest_version_owned(version))
            .collect()
    }

    #[cfg(test)]
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
        let mut replacement = Self::from_manifest_versions(
            self.modified.clone(),
            self.trust_metadata_complete,
            self.versions_complete,
            self.covered_ranges.clone(),
            self.workspace_versions.clone(),
            self.platform_metadata_complete,
            self.latest_version.clone(),
            manifests,
        );
        replacement.latest_version_hint = self.latest_version_hint.clone();
        *self = replacement;
        true
    }

    #[cfg(test)]
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
                || !signatures_slice_eq(
                    &self.core.strings,
                    &self.core.signatures[left.signatures.range()],
                    &other.core.strings,
                    &other.core.signatures[right.signatures.range()],
                )
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

    /// Returns whether the retained authoritative latest manifest satisfies this
    /// range. Callers must separately enforce release-age and trust policies.
    #[inline]
    pub fn preferred_latest_satisfies(&self, range: &NpmRange) -> bool {
        self.workspace_versions.is_empty()
            && range.dist_tag().is_none_or(|tag| tag == "latest")
            && self.preferred_latest.as_ref().is_some_and(|latest| {
                self.latest_version.as_ref() == Some(latest)
                    && self.versions.contains(latest)
                    && self.range_satisfies(range, latest)
            })
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
            || !self
                .versions
                .iter()
                .any(|version| self.range_satisfies(range, version))
    }

    pub fn workspace_version_satisfies(&self, range: &NpmRange) -> bool {
        self.workspace_versions
            .iter()
            .any(|version| self.range_satisfies(range, version))
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
        if self.release_metadata_complete {
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
            && self
                .platform
                .records
                .iter()
                .any(|record| self.platform_record_needs_libc(record))
    }

    fn platform_record_needs_libc(&self, record: &PlatformRecord) -> bool {
        let os = platform_value_refs(&self.platform, record.os);
        let cpu_is_empty = record.cpu.len == 0;
        let libc_is_empty = record.libc.len == 0;
        libc_is_empty && (record.os.len != 0 || !cpu_is_empty) && platform_may_target_linux(os)
    }

    pub fn needs_platform_metadata_for_version(&self, version: &str) -> bool {
        if self.platform_metadata_complete || self.platform_hydrated_versions.contains(version) {
            return false;
        }
        let Some(version_id) = self.core.version_id(version) else {
            return false;
        };
        let Some(record) =
            find_version_record(&self.platform.records, version_id as u32, |r| r.version)
        else {
            return false;
        };
        self.platform_record_needs_libc(record)
    }

    pub fn merge_exact_version_platform(
        &mut self,
        version: &str,
        os: &[String],
        cpu: &[String],
        libc: &[String],
    ) {
        if let Some(version_id) = self.core.version_id(version) {
            let mut platforms = self.platforms_owned();
            let platform = platforms.entry(version_id).or_default();
            if platform.os.is_empty() && !os.is_empty() {
                platform.os = os.to_vec();
            }
            if platform.cpu.is_empty() && !cpu.is_empty() {
                platform.cpu = cpu.to_vec();
            }
            if platform.libc.is_empty() && !libc.is_empty() {
                platform.libc = libc.to_vec();
            }
            self.platform = Arc::new(build_platform_overlay(platforms));
            self.platform_hydrated_versions.insert(version.to_owned());
        }
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
        let mut dist_tags = HashMap::with_capacity(usize::from(latest_version.is_some()));
        if let Some(latest) = latest_version.as_ref() {
            dist_tags.insert("latest".to_string(), latest.clone());
        }
        Self {
            modified,
            trust_metadata_complete,
            versions_complete,
            covered_ranges,
            workspace_versions,
            platform_metadata_complete,
            latest_version,
            dist_tags,
            strings: StringPoolBuilder::default(),
            versions: Vec::with_capacity(version_capacity),
            dependencies: Vec::new(),
            peers: Vec::new(),
            signatures: Vec::new(),
        }
    }

    pub(super) fn set_dist_tags(&mut self, dist_tags: HashMap<String, NpmVersion>) {
        self.dist_tags = dist_tags;
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

        let text = self.strings.intern(&manifest.version.to_string());
        let dependency_start = self.dependencies.len();
        for dependency in manifest.dependencies {
            self.dependencies.push(DependencyRecord {
                name: self.strings.intern(&dependency.name),
                range: self.strings.intern(&dependency.range),
                alias: dependency
                    .alias
                    .as_deref()
                    .map(|alias| self.strings.intern(alias)),
                optional: dependency.optional,
                bundled: dependency.bundled,
            });
        }
        let dependencies =
            RecordSpan::from_start_and_end(dependency_start, self.dependencies.len());

        let peer_start = self.peers.len();
        for peer in manifest.peer_dependencies {
            self.peers.push(PeerRecord {
                name: self.strings.intern(&peer.name),
                range: self.strings.intern(&peer.range),
                alias: peer
                    .alias
                    .as_deref()
                    .map(|alias| self.strings.intern(alias)),
                optional: peer.optional,
            });
        }
        let peers = RecordSpan::from_start_and_end(peer_start, self.peers.len());

        let signature_start = self.signatures.len();
        for signature in manifest.dist.signatures {
            self.signatures.push(SignatureRecord {
                keyid: signature
                    .keyid
                    .as_deref()
                    .map(|value| self.strings.intern(value)),
                sig: signature
                    .sig
                    .as_deref()
                    .map(|value| self.strings.intern(value)),
            });
        }
        let signatures = RecordSpan::from_start_and_end(signature_start, self.signatures.len());

        self.versions.push(StagedVersion {
            version: manifest.version,
            record: VersionRecord {
                text,
                dependencies,
                peers,
                node_engine: manifest
                    .node_engine
                    .as_deref()
                    .map(|value| self.strings.intern(value)),
                tarball_url: manifest
                    .dist
                    .tarball_url
                    .as_deref()
                    .map(|value| self.strings.intern(value)),
                integrity: manifest
                    .dist
                    .integrity
                    .as_deref()
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

    #[expect(
        clippy::too_many_arguments,
        reason = "borrows every manifest field directly into the compact arena without an intermediate owned struct"
    )]
    pub(super) fn push_borrowed_version(
        &mut self,
        version: NpmVersion,
        version_text: &str,
        mut dependencies: Vec<ManifestDependencyRef<'_>>,
        mut peers: Vec<ManifestPeerDependencyRef<'_>>,
        node_engine: Option<&str>,
        tarball_url: Option<&str>,
        integrity: Option<&str>,
        unpacked_size: Option<NonZeroU64>,
        signatures: &[lpm_registry::RegistrySignature],
        published_at: Option<String>,
        published_at_unix: Option<i64>,
        platform: Option<PlatformMeta>,
        trust_evidence: Option<TrustEvidence>,
    ) {
        dependencies.sort_unstable_by(|left, right| left.name.cmp(right.name));
        dependencies.dedup_by(|left, right| left.name == right.name);
        peers.retain(|peer| {
            dependencies
                .binary_search_by(|dependency| dependency.name.cmp(peer.name))
                .is_err()
        });
        peers.sort_unstable_by(|left, right| left.name.cmp(right.name));
        peers.dedup_by(|left, right| left.name == right.name);

        let text = self.strings.intern(version_text);
        let dependency_start = self.dependencies.len();
        for dependency in dependencies {
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
        for peer in peers {
            self.peers.push(PeerRecord {
                name: self.strings.intern(peer.name),
                range: self.strings.intern(peer.range),
                alias: peer.alias.map(|alias| self.strings.intern(alias)),
                optional: peer.optional,
            });
        }
        let peers = RecordSpan::from_start_and_end(peer_start, self.peers.len());

        let signature_start = self.signatures.len();
        for signature in signatures {
            self.signatures.push(SignatureRecord {
                keyid: signature
                    .keyid
                    .as_deref()
                    .map(|value| self.strings.intern(value)),
                sig: signature
                    .sig
                    .as_deref()
                    .map(|value| self.strings.intern(value)),
            });
        }
        let signatures = RecordSpan::from_start_and_end(signature_start, self.signatures.len());

        self.versions.push(StagedVersion {
            version,
            record: VersionRecord {
                text,
                dependencies,
                peers,
                node_engine: node_engine.map(|value| self.strings.intern(value)),
                tarball_url: tarball_url.map(|value| self.strings.intern(value)),
                integrity: integrity.map(|value| self.strings.intern(value)),
                unpacked_size,
                signatures,
            },
            published_at,
            published_at_unix,
            platform,
            trust_evidence,
        });
    }

    pub(super) fn push_merged_from_cache(
        &mut self,
        existing: Option<(&CachedPackageInfo, usize)>,
        incoming: Option<(&CachedPackageInfo, usize)>,
        preserve_existing: bool,
    ) {
        let (
            version,
            version_text,
            dep_source,
            peer_source,
            node_engine,
            tarball_url,
            integrity,
            unpacked_size,
            sig_source,
            published_at,
            published_at_unix,
            platform,
            trust_evidence,
        ) = match (existing, incoming, preserve_existing) {
            (Some((ex, ex_id)), _, true) | (Some((ex, ex_id)), None, false) => {
                let rec = ex.core.versions[ex_id];
                let rel = find_version_record(&ex.release.records, ex_id as u32, |r| r.version);
                let tr =
                    find_version_record(&ex.trust, ex_id as u32, |r| r.version).map(|r| r.evidence);
                (
                    ex.versions[ex_id].clone(),
                    ex.core.version_text(ex_id),
                    (ex, ex_id),
                    (ex, ex_id),
                    optional_pool_value(&ex.core.strings, rec.node_engine),
                    optional_pool_value(&ex.core.strings, rec.tarball_url),
                    optional_pool_value(&ex.core.strings, rec.integrity),
                    rec.unpacked_size,
                    (ex, ex_id),
                    rel.map(|r| ex.release.strings.get(r.published_at).to_owned()),
                    rel.and_then(|r| r.published_at_unix),
                    ex.platform_by_id(ex_id),
                    tr,
                )
            }
            (None, Some((inc, inc_id)), _) => {
                let rec = inc.core.versions[inc_id];
                let rel = find_version_record(&inc.release.records, inc_id as u32, |r| r.version);
                let tr = find_version_record(&inc.trust, inc_id as u32, |r| r.version)
                    .map(|r| r.evidence);
                (
                    inc.versions[inc_id].clone(),
                    inc.core.version_text(inc_id),
                    (inc, inc_id),
                    (inc, inc_id),
                    optional_pool_value(&inc.core.strings, rec.node_engine),
                    optional_pool_value(&inc.core.strings, rec.tarball_url),
                    optional_pool_value(&inc.core.strings, rec.integrity),
                    rec.unpacked_size,
                    (inc, inc_id),
                    rel.map(|r| inc.release.strings.get(r.published_at).to_owned()),
                    rel.and_then(|r| r.published_at_unix),
                    inc.platform_by_id(inc_id),
                    tr,
                )
            }
            (Some((ex, ex_id)), Some((inc, inc_id)), false) => {
                let ex_rec = ex.core.versions[ex_id];
                let inc_rec = inc.core.versions[inc_id];
                let dep_source = if inc_rec.dependencies.len == 0 {
                    (ex, ex_id)
                } else {
                    (inc, inc_id)
                };
                let peer_source = if inc_rec.peers.len == 0 {
                    (ex, ex_id)
                } else {
                    (inc, inc_id)
                };
                let sig_source = if inc_rec.signatures.len == 0 {
                    (ex, ex_id)
                } else {
                    (inc, inc_id)
                };
                let ex_rel = find_version_record(&ex.release.records, ex_id as u32, |r| r.version);
                let inc_rel =
                    find_version_record(&inc.release.records, inc_id as u32, |r| r.version);
                let published_at = inc_rel
                    .map(|r| inc.release.strings.get(r.published_at).to_owned())
                    .or_else(|| ex_rel.map(|r| ex.release.strings.get(r.published_at).to_owned()));
                let published_at_unix = inc_rel
                    .and_then(|r| r.published_at_unix)
                    .or_else(|| ex_rel.and_then(|r| r.published_at_unix));
                let trust_evidence = find_version_record(&inc.trust, inc_id as u32, |r| r.version)
                    .map(|r| r.evidence)
                    .or_else(|| {
                        find_version_record(&ex.trust, ex_id as u32, |r| r.version)
                            .map(|r| r.evidence)
                    });
                let platform = merge_platform_by_id(ex, ex_id, inc, inc_id);
                (
                    inc.versions[inc_id].clone(),
                    inc.core.version_text(inc_id),
                    dep_source,
                    peer_source,
                    optional_pool_value(&inc.core.strings, inc_rec.node_engine)
                        .or_else(|| optional_pool_value(&ex.core.strings, ex_rec.node_engine)),
                    optional_pool_value(&inc.core.strings, inc_rec.tarball_url)
                        .or_else(|| optional_pool_value(&ex.core.strings, ex_rec.tarball_url)),
                    optional_pool_value(&inc.core.strings, inc_rec.integrity)
                        .or_else(|| optional_pool_value(&ex.core.strings, ex_rec.integrity)),
                    inc_rec.unpacked_size.or(ex_rec.unpacked_size),
                    sig_source,
                    published_at,
                    published_at_unix,
                    platform,
                    trust_evidence,
                )
            }
            (None, None, _) => return,
        };

        let text = self.strings.intern(version_text);
        let dep_start = self.dependencies.len();
        for rec in dep_source.0.core.dependency_records(dep_source.1) {
            self.dependencies.push(DependencyRecord {
                name: self.strings.intern(dep_source.0.core.strings.get(rec.name)),
                range: self
                    .strings
                    .intern(dep_source.0.core.strings.get(rec.range)),
                alias: rec
                    .alias
                    .map(|id| self.strings.intern(dep_source.0.core.strings.get(id))),
                optional: rec.optional,
                bundled: rec.bundled,
            });
        }
        let dependencies = RecordSpan::from_start_and_end(dep_start, self.dependencies.len());

        let peer_start = self.peers.len();
        for rec in peer_source.0.core.peer_records(peer_source.1) {
            let name = peer_source.0.core.strings.get(rec.name);
            let shadowed = self.dependencies[dependencies.range()]
                .binary_search_by(|d| self.strings.span_str(d.name.0.get()).cmp(name))
                .is_ok();
            if shadowed {
                continue;
            }
            self.peers.push(PeerRecord {
                name: self.strings.intern(name),
                range: self
                    .strings
                    .intern(peer_source.0.core.strings.get(rec.range)),
                alias: rec
                    .alias
                    .map(|id| self.strings.intern(peer_source.0.core.strings.get(id))),
                optional: rec.optional,
            });
        }
        let peers = RecordSpan::from_start_and_end(peer_start, self.peers.len());

        let sig_start = self.signatures.len();
        let sig_span = sig_source.0.core.versions[sig_source.1].signatures;
        for rec in &sig_source.0.core.signatures[sig_span.range()] {
            self.signatures.push(SignatureRecord {
                keyid: rec
                    .keyid
                    .map(|id| self.strings.intern(sig_source.0.core.strings.get(id))),
                sig: rec
                    .sig
                    .map(|id| self.strings.intern(sig_source.0.core.strings.get(id))),
            });
        }
        let signatures = RecordSpan::from_start_and_end(sig_start, self.signatures.len());

        self.versions.push(StagedVersion {
            version,
            record: VersionRecord {
                text,
                dependencies,
                peers,
                node_engine: node_engine.map(|v| self.strings.intern(v)),
                tarball_url: tarball_url.map(|v| self.strings.intern(v)),
                integrity: integrity.map(|v| self.strings.intern(v)),
                unpacked_size,
                signatures,
            },
            published_at,
            published_at_unix,
            platform,
            trust_evidence,
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
        let versions_arc: Arc<[NpmVersion]> = Arc::from(versions);
        let release = Arc::new(build_release_overlay(release_inputs));
        let platform = Arc::new(build_platform_overlay(platform_inputs));
        let trust: Arc<[TrustRecord]> = Arc::from(trust);
        let trust_timeline = build_trust_timeline(&versions_arc, &release.records, &trust);
        CachedPackageInfo {
            modified: self.modified,
            modified_unix,
            trust_metadata_complete: self.trust_metadata_complete,
            release_metadata_complete: !version_records.is_empty()
                && release.records.len() >= version_records.len(),
            versions_complete: self.versions_complete,
            covered_ranges: self.covered_ranges,
            workspace_versions: self.workspace_versions,
            platform_metadata_complete: self.platform_metadata_complete,
            platform_hydrated_versions: HashSet::new(),
            latest_version_hint: None,
            latest_version: self.latest_version,
            preferred_latest: None,
            versions: versions_arc,
            dist_tags: Arc::new(self.dist_tags),
            core: Arc::new(ManifestCore {
                strings: pool,
                versions: version_records.into_boxed_slice(),
                version_lookup: version_lookup.into_boxed_slice(),
                dependencies: self.dependencies.into_boxed_slice(),
                peers: self.peers.into_boxed_slice(),
                signatures: self.signatures.into_boxed_slice(),
            }),
            release,
            platform,
            trust,
            trust_timeline,
        }
    }
}

/// Borrowed view of one resolved version inside [`CachedPackageInfo`],
/// avoiding repeated version-string formatting and binary searches.
#[derive(Clone, Copy)]
pub(crate) struct VersionView<'a> {
    info: &'a CachedPackageInfo,
    id: usize,
}

impl<'a> VersionView<'a> {
    #[inline]
    pub(crate) fn dependencies(self) -> ManifestDependencyIter<'a> {
        ManifestDependencyIter {
            core: &self.info.core,
            iter: self.info.core.dependency_records(self.id).iter(),
        }
    }

    #[inline]
    pub(crate) fn peer_dependencies(self) -> ManifestPeerDependencyIter<'a> {
        ManifestPeerDependencyIter {
            core: &self.info.core,
            iter: self.info.core.peer_records(self.id).iter(),
        }
    }

    #[inline]
    pub(crate) fn has_dependency_aliases(self) -> bool {
        self.info
            .core
            .dependency_records(self.id)
            .iter()
            .any(|record| record.alias.is_some())
    }

    #[inline]
    pub(crate) fn node_engine(self) -> Option<&'a str> {
        self.info.core.versions[self.id]
            .node_engine
            .map(|id| self.info.core.strings.get(id))
    }

    #[inline]
    pub(crate) fn tarball_url(self) -> Option<&'a str> {
        self.info.core.versions[self.id]
            .tarball_url
            .map(|id| self.info.core.strings.get(id))
    }

    #[inline]
    pub(crate) fn integrity(self) -> Option<&'a str> {
        self.info.core.versions[self.id]
            .integrity
            .map(|id| self.info.core.strings.get(id))
    }

    #[inline]
    pub(crate) fn platform(self) -> Option<PlatformMeta> {
        self.info.platform_by_id(self.id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OverlayMergeDiff {
    pub(super) core_changed: bool,
    pub(super) release_changed: bool,
    pub(super) platform_changed: bool,
    pub(super) trust_changed: bool,
}

impl CachedPackageInfo {
    fn platform_by_id(&self, version_id: usize) -> Option<PlatformMeta> {
        let record = find_version_record(&self.platform.records, version_id as u32, |r| r.version)?;
        Some(PlatformMeta {
            os: platform_values(&self.platform, record.os),
            cpu: platform_values(&self.platform, record.cpu),
            libc: platform_values(&self.platform, record.libc),
        })
    }

    pub(super) fn analyze_subset_merge(&self, incoming: &Self) -> OverlayMergeDiff {
        let mut diff = OverlayMergeDiff {
            core_changed: false,
            release_changed: false,
            platform_changed: false,
            trust_changed: false,
        };
        if Arc::ptr_eq(&self.core, &incoming.core)
            && Arc::ptr_eq(&self.release, &incoming.release)
            && Arc::ptr_eq(&self.platform, &incoming.platform)
            && Arc::ptr_eq(&self.trust, &incoming.trust)
        {
            return diff;
        }
        let core_same_arc = Arc::ptr_eq(&self.core, &incoming.core);
        for (inc_id, version) in incoming.versions.iter().enumerate() {
            if self.workspace_versions.contains(version) {
                continue;
            }
            let Some(ex_id) = self.version_id_for(version) else {
                diff.core_changed = true;
                return diff;
            };
            if !core_same_arc && !self.core_version_merge_is_noop(ex_id, incoming, inc_id) {
                diff.core_changed = true;
                return diff;
            }
            if !diff.release_changed {
                let ex_rel =
                    find_version_record(&self.release.records, ex_id as u32, |r| r.version);
                let inc_rel =
                    find_version_record(&incoming.release.records, inc_id as u32, |r| r.version);
                if let Some(ir) = inc_rel {
                    let same = ex_rel.is_some_and(|er| {
                        self.release.strings.get(er.published_at)
                            == incoming.release.strings.get(ir.published_at)
                            && (ir.published_at_unix.is_none()
                                || er.published_at_unix == ir.published_at_unix)
                    });
                    if !same {
                        diff.release_changed = true;
                    }
                }
            }
            if !diff.platform_changed && !platform_merge_is_noop(self, ex_id, incoming, inc_id) {
                diff.platform_changed = true;
            }
            if !diff.trust_changed
                && let Some(inc_tr) =
                    find_version_record(&incoming.trust, inc_id as u32, |r| r.version)
            {
                let ex_tr = find_version_record(&self.trust, ex_id as u32, |r| r.version);
                if ex_tr.map(|r| r.evidence) != Some(inc_tr.evidence) {
                    diff.trust_changed = true;
                }
            }
        }
        diff
    }

    fn core_version_merge_is_noop(&self, ex_id: usize, incoming: &Self, inc_id: usize) -> bool {
        let ex = self.core.versions[ex_id];
        let inc = incoming.core.versions[inc_id];
        if inc.node_engine.is_some()
            && optional_pool_value(&self.core.strings, ex.node_engine)
                != optional_pool_value(&incoming.core.strings, inc.node_engine)
        {
            return false;
        }
        if inc.tarball_url.is_some()
            && optional_pool_value(&self.core.strings, ex.tarball_url)
                != optional_pool_value(&incoming.core.strings, inc.tarball_url)
        {
            return false;
        }
        if inc.integrity.is_some()
            && optional_pool_value(&self.core.strings, ex.integrity)
                != optional_pool_value(&incoming.core.strings, inc.integrity)
        {
            return false;
        }
        if inc.unpacked_size.is_some() && ex.unpacked_size != inc.unpacked_size {
            return false;
        }
        if inc.signatures.len > 0
            && !signatures_slice_eq(
                &self.core.strings,
                &self.core.signatures[ex.signatures.range()],
                &incoming.core.strings,
                &incoming.core.signatures[inc.signatures.range()],
            )
        {
            return false;
        }
        if inc.dependencies.len > 0 {
            let ex_deps = ManifestDependencyIter {
                core: &self.core,
                iter: self.core.dependency_records(ex_id).iter(),
            };
            let inc_deps = ManifestDependencyIter {
                core: &incoming.core,
                iter: incoming.core.dependency_records(inc_id).iter(),
            };
            if !ex_deps.eq(inc_deps) {
                return false;
            }
        }
        if inc.peers.len > 0 {
            let ex_peers = ManifestPeerDependencyIter {
                core: &self.core,
                iter: self.core.peer_records(ex_id).iter(),
            };
            let inc_peers = ManifestPeerDependencyIter {
                core: &incoming.core,
                iter: incoming.core.peer_records(inc_id).iter(),
            };
            if !ex_peers.eq(inc_peers) {
                return false;
            }
        }
        true
    }

    pub(super) fn merge_overlays_from(&mut self, incoming: &Self, diff: OverlayMergeDiff) {
        if diff.release_changed {
            let mut releases: HashMap<usize, (String, Option<i64>)> = self
                .release
                .records
                .iter()
                .map(|r| {
                    (
                        r.version as usize,
                        (
                            self.release.strings.get(r.published_at).to_owned(),
                            r.published_at_unix,
                        ),
                    )
                })
                .collect();
            for rec in &incoming.release.records {
                let inc_id = rec.version as usize;
                let version = &incoming.versions[inc_id];
                if self.workspace_versions.contains(version) {
                    continue;
                }
                let Some(ex_id) = self.version_id_for(version) else {
                    continue;
                };
                let existing_unix = releases.get(&ex_id).and_then(|(_, u)| *u);
                releases.insert(
                    ex_id,
                    (
                        incoming.release.strings.get(rec.published_at).to_owned(),
                        rec.published_at_unix.or(existing_unix),
                    ),
                );
            }
            let inputs = releases.into_iter().map(|(v, (s, u))| (v, s, u)).collect();
            self.release = Arc::new(build_release_overlay(inputs));
        }

        if diff.platform_changed {
            let mut platforms = self.platforms_owned();
            for rec in &incoming.platform.records {
                let inc_id = rec.version as usize;
                let version = &incoming.versions[inc_id];
                if self.workspace_versions.contains(version) {
                    continue;
                }
                let Some(ex_id) = self.version_id_for(version) else {
                    continue;
                };
                if let Some(merged) = merge_platform_by_id(self, ex_id, incoming, inc_id) {
                    platforms.insert(ex_id, merged);
                }
            }
            self.platform = Arc::new(build_platform_overlay(platforms));
        }

        if diff.trust_changed {
            let mut trust_map: HashMap<u32, TrustEvidence> =
                self.trust.iter().map(|r| (r.version, r.evidence)).collect();
            for rec in incoming.trust.iter() {
                let inc_id = rec.version as usize;
                let version = &incoming.versions[inc_id];
                if self.workspace_versions.contains(version) {
                    continue;
                }
                if let Some(ex_id) = self.version_id_for(version) {
                    trust_map.insert(ex_id as u32, rec.evidence);
                }
            }
            let mut trust_vec: Vec<TrustRecord> = trust_map
                .into_iter()
                .map(|(version, evidence)| TrustRecord { version, evidence })
                .collect();
            trust_vec.sort_unstable_by_key(|r| r.version);
            self.trust = Arc::from(trust_vec);
        }

        if diff.release_changed || diff.trust_changed {
            self.trust_timeline =
                build_trust_timeline(&self.versions, &self.release.records, &self.trust);
        }
    }

    pub(super) fn set_dist_tags(&mut self, dist_tags: HashMap<String, NpmVersion>) {
        self.dist_tags = Arc::new(dist_tags);
    }
}

fn signatures_slice_eq(
    left_pool: &StringPool,
    left: &[SignatureRecord],
    right_pool: &StringPool,
    right: &[SignatureRecord],
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right.iter()).all(|(l, r)| {
            optional_pool_value(left_pool, l.keyid) == optional_pool_value(right_pool, r.keyid)
                && optional_pool_value(left_pool, l.sig) == optional_pool_value(right_pool, r.sig)
        })
}

fn platform_merge_is_noop(
    ex: &CachedPackageInfo,
    ex_id: usize,
    inc: &CachedPackageInfo,
    inc_id: usize,
) -> bool {
    let Some(inc_rec) = find_version_record(&inc.platform.records, inc_id as u32, |r| r.version)
    else {
        return true;
    };
    let Some(ex_rec) = find_version_record(&ex.platform.records, ex_id as u32, |r| r.version)
    else {
        return false;
    };
    (inc_rec.os.len == 0
        || platform_value_refs(&ex.platform, ex_rec.os)
            .eq(platform_value_refs(&inc.platform, inc_rec.os)))
        && (inc_rec.cpu.len == 0
            || platform_value_refs(&ex.platform, ex_rec.cpu)
                .eq(platform_value_refs(&inc.platform, inc_rec.cpu)))
        && (inc_rec.libc.len == 0
            || platform_value_refs(&ex.platform, ex_rec.libc)
                .eq(platform_value_refs(&inc.platform, inc_rec.libc)))
}

fn merge_platform_by_id(
    ex: &CachedPackageInfo,
    ex_id: usize,
    inc: &CachedPackageInfo,
    inc_id: usize,
) -> Option<PlatformMeta> {
    let ex_rec = find_version_record(&ex.platform.records, ex_id as u32, |r| r.version);
    let inc_rec = find_version_record(&inc.platform.records, inc_id as u32, |r| r.version);
    match (ex_rec, inc_rec) {
        (Some(er), Some(ir)) => Some(PlatformMeta {
            os: if ir.os.len == 0 {
                platform_values(&ex.platform, er.os)
            } else {
                platform_values(&inc.platform, ir.os)
            },
            cpu: if ir.cpu.len == 0 {
                platform_values(&ex.platform, er.cpu)
            } else {
                platform_values(&inc.platform, ir.cpu)
            },
            libc: if ir.libc.len == 0 {
                platform_values(&ex.platform, er.libc)
            } else {
                platform_values(&inc.platform, ir.libc)
            },
        }),
        (Some(er), None) => Some(PlatformMeta {
            os: platform_values(&ex.platform, er.os),
            cpu: platform_values(&ex.platform, er.cpu),
            libc: platform_values(&ex.platform, er.libc),
        }),
        (None, Some(ir)) => Some(PlatformMeta {
            os: platform_values(&inc.platform, ir.os),
            cpu: platform_values(&inc.platform, ir.cpu),
            libc: platform_values(&inc.platform, ir.libc),
        }),
        (None, None) => None,
    }
}

fn build_trust_timeline(
    versions: &[NpmVersion],
    release_records: &[ReleaseRecord],
    trust: &[TrustRecord],
) -> TrustTimeline {
    if trust.is_empty() || release_records.is_empty() {
        return TrustTimeline::default();
    }
    let mut timeline = TrustTimeline::default();
    for record in trust {
        let Some(published_unix) =
            find_version_record(release_records, record.version, |r| r.version)
                .and_then(|r| r.published_at_unix)
        else {
            continue;
        };
        let is_stable = versions
            .get(record.version as usize)
            .is_some_and(|version| !version.is_prerelease());
        let update_min = |slot: &mut Option<i64>| {
            if slot.is_none_or(|current| published_unix < current) {
                *slot = Some(published_unix);
            }
        };
        match record.evidence {
            TrustEvidence::TrustedPublisher => {
                update_min(&mut timeline.earliest_trusted_any);
                if is_stable {
                    update_min(&mut timeline.earliest_trusted_stable);
                }
            }
            TrustEvidence::StagedPublish => {
                update_min(&mut timeline.earliest_staged_any);
                if is_stable {
                    update_min(&mut timeline.earliest_staged_stable);
                }
            }
        }
    }
    timeline
}

fn build_release_overlay(mut inputs: Vec<(usize, String, Option<i64>)>) -> ReleaseOverlay {
    inputs.sort_unstable_by_key(|(version, _, _)| *version);
    let mut strings = StringPoolBuilder::default();
    let records = inputs
        .into_iter()
        .map(|(version, published_at, published_at_unix)| ReleaseRecord {
            version: version as u32,
            published_at: strings.intern(&published_at),
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
    values.extend(input.iter().map(|value| strings.intern(value)));
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

    #[test]
    fn finalized_string_pool_preserves_ids_duplicates_and_utf8_boundaries() {
        let values = ["zebra", "", "résolve", "alpha", "🦀", "zebra", "alpha"];
        let mut builder = StringPoolBuilder::default();
        let ids: Vec<_> = values.iter().map(|value| builder.intern(value)).collect();
        let pool = builder.finish();

        for (id, expected) in ids.iter().zip(values) {
            assert_eq!(pool.get(*id), expected);
        }
        assert_eq!(ids[0], ids[5]);
        assert_eq!(ids[3], ids[6]);
        assert_eq!(pool.spans.len(), 5);
        assert_eq!(pool.data.as_ref(), values[..5].concat());
        assert_eq!(
            pool.data.len(),
            values[..5].iter().map(|value| value.len()).sum::<usize>()
        );
        assert!(StringPoolBuilder::default().finish().spans.is_empty());
    }

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
    fn skewed_partial_release_times_do_not_mark_release_metadata_complete() {
        let mut info = info_from(vec![manifest("1.0.0"), manifest("2.0.0")]);
        info.modified = Some("2026-11-22T12:00:00.000Z".to_string());
        info.modified_unix = Some(1_795_348_800);
        let skewed = lpm_registry::ReleaseTimeMetadata {
            name: Some("fixture".to_string()),
            time: HashMap::from([
                (
                    "modified".to_string(),
                    "2026-11-20T00:00:00.000Z".to_string(),
                ),
                ("1.0.0".to_string(), "2025-01-01T00:00:00.000Z".to_string()),
            ]),
            versions: None,
        };

        info.merge_release_times(&skewed);

        assert!(
            !info.release_metadata_complete,
            "missing timestamp for 2.0.0 with mismatched modified must not mark release metadata complete"
        );
    }

    #[test]
    fn skewed_partial_platform_metadata_does_not_mark_platform_metadata_complete() {
        let mut m1 = manifest("1.0.0");
        m1.platform = Some(PlatformMeta {
            os: vec!["linux".to_string()],
            cpu: vec!["x64".to_string()],
            libc: Vec::new(),
        });
        let mut m2 = manifest("2.0.0");
        m2.platform = Some(PlatformMeta {
            os: vec!["linux".to_string()],
            cpu: vec!["x64".to_string()],
            libc: Vec::new(),
        });
        let mut info = info_from(vec![m1, m2]);
        info.platform_metadata_complete = false;
        info.modified = Some("2026-11-22T12:00:00.000Z".to_string());
        info.modified_unix = Some(1_795_348_800);
        let skewed = lpm_registry::ReleaseTimeMetadata {
            name: Some("fixture".to_string()),
            time: HashMap::from([(
                "modified".to_string(),
                "2026-11-20T00:00:00.000Z".to_string(),
            )]),
            versions: Some(HashMap::from([(
                "1.0.0".to_string(),
                lpm_registry::ReleaseTimeVersionMetadata {
                    os: vec!["linux".to_string()],
                    cpu: vec!["x64".to_string()],
                    libc: vec!["glibc".to_string()],
                },
            )])),
        };

        info.merge_release_times(&skewed);

        assert!(
            !info.platform_metadata_complete,
            "stale platform map missing 2.0.0 must not mark platform metadata complete"
        );
        assert!(!info.needs_platform_metadata_for_version("1.0.0"));
        assert!(info.needs_platform_metadata_for_version("2.0.0"));
    }

    #[test]
    fn manifest_projection_codec_persists_platform_hydrated_versions() {
        use lpm_registry::MetadataProjection as _;

        let mut m1 = manifest("1.0.0");
        m1.platform = Some(PlatformMeta {
            os: vec!["linux".to_string()],
            cpu: vec!["x64".to_string()],
            libc: Vec::new(),
        });
        let mut info = info_from(vec![m1]);
        info.platform_metadata_complete = false;
        assert!(info.needs_platform_metadata_for_version("1.0.0"));
        info.merge_exact_version_platform("1.0.0", &["linux".to_string()], &[], &[]);
        assert!(!info.needs_platform_metadata_for_version("1.0.0"));

        let encoded = ManifestProjection::encode(&info, &HashMap::new(), 1);
        let decoded = ManifestProjection::decode(&encoded).expect("valid projection");
        assert!(decoded.info.platform_hydrated_versions.contains("1.0.0"));
        assert!(!decoded.info.needs_platform_metadata_for_version("1.0.0"));
    }

    #[test]
    fn compact_record_layout_stays_below_one_cache_line() {
        assert_eq!(std::mem::size_of::<StringId>(), 4);
        assert_eq!(std::mem::size_of::<Option<StringId>>(), 4);
        assert_eq!(std::mem::size_of::<SignatureRecord>(), 8);
        assert!(std::mem::size_of::<VersionRecord>() <= 48);
        assert!(std::mem::size_of::<DependencyRecord>() <= 16);
        assert!(std::mem::size_of::<PeerRecord>() <= 16);
    }

    #[test]
    fn shared_signature_keyids_are_interned_once_in_manifest_core() {
        let mut m1 = manifest("1.0.0");
        m1.dist.signatures.push(lpm_registry::RegistrySignature {
            keyid: Some("SHA256:shared-npm-key".to_string()),
            sig: Some("sig-one".to_string()),
        });
        let mut m2 = manifest("2.0.0");
        m2.dist.signatures.push(lpm_registry::RegistrySignature {
            keyid: Some("SHA256:shared-npm-key".to_string()),
            sig: Some("sig-two".to_string()),
        });
        let info = info_from(vec![m1, m2]);

        let keyid_occurrences = info
            .core
            .strings
            .spans
            .iter()
            .filter(|span| {
                &info.core.strings.data[span.start as usize..(span.start + span.len) as usize]
                    == "SHA256:shared-npm-key"
            })
            .count();
        assert_eq!(keyid_occurrences, 1);
        assert_eq!(info.signatures("1.0.0")[0].sig.as_deref(), Some("sig-one"));
        assert_eq!(info.signatures("2.0.0")[0].sig.as_deref(), Some("sig-two"));
    }

    #[test]
    fn overlay_only_merge_preserves_manifest_core_arc() {
        let mut base_v1 = manifest("1.0.0");
        base_v1.dist.tarball_url = Some("https://registry.invalid/pkg-1.0.0.tgz".to_string());
        let existing = info_from(vec![base_v1.clone()]);

        let mut hydrated_v1 = base_v1;
        hydrated_v1.dist.published_at = Some("2025-01-01T00:00:00.000Z".to_string());
        hydrated_v1.dist.published_at_unix = parse_npm_time_unix("2025-01-01T00:00:00.000Z");
        hydrated_v1.dist.trust_evidence = Some(TrustEvidence::TrustedPublisher);
        let incoming = info_from(vec![hydrated_v1]);

        let merged = crate::provider::merge_cached_package_info(&existing, &incoming);
        assert!(
            Arc::ptr_eq(&merged.core, &existing.core),
            "overlay-only merge must reuse ManifestCore Arc without rebuilding"
        );
        assert!(Arc::ptr_eq(&merged.versions, &existing.versions));
        assert_eq!(
            merged.published_at("1.0.0"),
            Some("2025-01-01T00:00:00.000Z")
        );
        assert_eq!(
            merged.trust_evidence("1.0.0"),
            Some(TrustEvidence::TrustedPublisher)
        );
        assert_eq!(
            merged.trust_timeline().earliest_trusted_stable,
            parse_npm_time_unix("2025-01-01T00:00:00.000Z")
        );
    }

    #[test]
    fn trust_timeline_matches_downgrade_rules_for_ties_prereleases_and_backports() {
        let make = |ver: &str, ts: Option<&str>, trust: Option<TrustEvidence>| {
            let mut m = manifest(ver);
            m.dist.published_at = ts.map(str::to_owned);
            m.dist.published_at_unix = ts.and_then(parse_npm_time_unix);
            m.dist.trust_evidence = trust;
            m
        };
        let info = info_from(vec![
            make(
                "1.0.0-alpha.1",
                Some("2025-01-01T00:00:00.000Z"),
                Some(TrustEvidence::StagedPublish),
            ),
            make(
                "1.0.0",
                Some("2025-01-02T00:00:00.000Z"),
                Some(TrustEvidence::TrustedPublisher),
            ),
            // Equal timestamp tie with 1.0.0 is NOT strictly earlier
            make("1.0.1", Some("2025-01-02T00:00:00.000Z"), None),
            // Strictly later than 1.0.0 with no trust -> downgrade
            make("1.1.0", Some("2025-01-03T00:00:00.000Z"), None),
            // Prerelease later than 1.0.0-alpha.1 (StagedPublish) with only TrustedPublisher -> downgrade
            make(
                "2.0.0-beta.1",
                Some("2025-01-04T00:00:00.000Z"),
                Some(TrustEvidence::TrustedPublisher),
            ),
            // Stable later than 1.0.0-alpha.1 ignores prerelease StagedPublish
            make(
                "2.0.0",
                Some("2025-01-05T00:00:00.000Z"),
                Some(TrustEvidence::TrustedPublisher),
            ),
        ]);

        let check = |ver: &str| {
            crate::provider::trust_downgrade_violation_unprofiled(
                &info,
                &NpmVersion::parse(ver).unwrap(),
            )
        };
        assert!(
            check("1.0.1").is_none(),
            "equal timestamp is not strictly earlier"
        );
        assert!(
            check("1.1.0").is_some(),
            "untrusted after trusted must reject"
        );
        assert!(
            check("2.0.0-beta.1").is_some(),
            "prerelease sees earlier prerelease StagedPublish"
        );
        assert!(
            check("2.0.0").is_none(),
            "stable release must ignore earlier prerelease StagedPublish"
        );
    }

    #[test]
    fn release_age_short_circuit_preserves_contradictory_timestamp_rejection() {
        let pkg = CanonicalKey::from_dep_name("example");
        let mut m = manifest("1.0.0");
        // Explicit timestamp is AFTER cutoff even though package `modified` is older.
        m.dist.published_at = Some("2026-01-10T00:00:00.000Z".to_string());
        m.dist.published_at_unix = parse_npm_time_unix("2026-01-10T00:00:00.000Z");
        let mut info = info_from(vec![m]);
        info.modified = Some("2025-01-01T00:00:00.000Z".to_string());
        info.modified_unix = parse_npm_time_unix("2025-01-01T00:00:00.000Z");

        let policy = ResolverPolicy::new_with_release_age_excludes_at_unix(
            7 * 86_400,
            crate::policy::TrustPolicyMode::Off,
            std::iter::empty(),
            parse_npm_time_unix("2026-01-11T00:00:00.000Z").unwrap(),
        );
        let status = crate::provider::release_age_status_for_version_unprofiled(
            &pkg,
            &info,
            &NpmVersion::parse("1.0.0").unwrap(),
            &policy,
        );
        assert!(matches!(status, crate::ReleaseTimeStatus::TooNew { .. }));

        // Disabled policy returns Allowed without touching timestamps.
        let disabled = ResolverPolicy::default();
        assert_eq!(
            crate::provider::release_age_status_for_version_unprofiled(
                &pkg,
                &info,
                &NpmVersion::parse("1.0.0").unwrap(),
                &disabled,
            ),
            crate::ReleaseTimeStatus::Allowed
        );
    }
}
