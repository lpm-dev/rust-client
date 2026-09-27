//! Lossless binary snapshot of [`CachedPackageInfo`].
//!
//! The accessors index the compact tables without checks, so decoding
//! validates every string ID, record span, UTF-8 boundary and ordering
//! invariant and rejects the snapshot when any of them fails.

use super::*;

const TRUST_METADATA_COMPLETE: u8 = 1;
const VERSIONS_COMPLETE: u8 = 1 << 1;
const PLATFORM_METADATA_COMPLETE: u8 = 1 << 2;
const KNOWN_FLAGS: u8 = TRUST_METADATA_COMPLETE | VERSIONS_COMPLETE | PLATFORM_METADATA_COMPLETE;

const TRUSTED_PUBLISHER: u8 = 0;
const STAGED_PUBLISH: u8 = 1;

/// The resolver's stored projection of one cached package history: the
/// parsed manifest tables plus the document fields the resolver reads beside
/// them.
#[derive(Debug)]
pub(crate) struct ManifestProjection {
    pub(crate) info: CachedPackageInfo,
    pub(crate) dist_tags: HashMap<String, String>,
    pub(crate) version_count: u64,
}

impl ManifestProjection {
    pub(crate) fn encode(
        info: &CachedPackageInfo,
        dist_tags: &HashMap<String, String>,
        version_count: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut writer = Writer(&mut out);
        writer.u64(version_count);
        let mut dist_tags = dist_tags.iter().collect::<Vec<_>>();
        dist_tags.sort_unstable();
        writer.len(dist_tags.len());
        for (tag, version) in dist_tags {
            writer.str(tag);
            writer.str(version);
        }
        info.encode_snapshot(&mut out);
        out
    }
}

impl lpm_registry::MetadataProjection for ManifestProjection {
    /// Includes the crate version, so a release that changes how metadata is
    /// parsed never reads projections an older parser derived.
    const FORMAT: &'static str = concat!("lpm-resolver-manifest/", env!("CARGO_PKG_VERSION"), "/1");

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader(bytes);
        let version_count = reader.u64()?;
        let dist_tag_count = reader.count(8)?;
        let mut dist_tags = HashMap::with_capacity(dist_tag_count);
        for _ in 0..dist_tag_count {
            let tag = reader.str()?.to_owned();
            dist_tags.insert(tag, reader.str()?.to_owned());
        }
        Some(Self {
            info: CachedPackageInfo::decode_snapshot(reader.0)?,
            dist_tags,
            version_count,
        })
    }
}

impl CachedPackageInfo {
    pub(crate) fn encode_snapshot(&self, out: &mut Vec<u8>) {
        let mut writer = Writer(out);
        let mut flags = 0;
        for (set, flag) in [
            (self.trust_metadata_complete, TRUST_METADATA_COMPLETE),
            (self.versions_complete, VERSIONS_COMPLETE),
            (self.platform_metadata_complete, PLATFORM_METADATA_COMPLETE),
        ] {
            if set {
                flags |= flag;
            }
        }
        writer.u8(flags);
        writer.optional_str(self.modified.as_deref());
        let mut covered_ranges = self.covered_ranges.iter().collect::<Vec<_>>();
        covered_ranges.sort_unstable();
        writer.len(covered_ranges.len());
        for range in covered_ranges {
            writer.str(range);
        }
        let mut workspace_versions = self.workspace_versions.iter().collect::<Vec<_>>();
        workspace_versions.sort_unstable();
        writer.len(workspace_versions.len());
        for version in workspace_versions {
            writer.str(&version.to_string());
        }
        for version in [
            &self.latest_version,
            &self.latest_version_hint,
            &self.preferred_latest,
        ] {
            writer.optional_str(version.as_ref().map(ToString::to_string).as_deref());
        }
        let mut dist_tags = self.dist_tags.iter().collect::<Vec<_>>();
        dist_tags.sort_unstable_by(|left, right| left.0.cmp(right.0));
        writer.len(dist_tags.len());
        for (tag, version) in dist_tags {
            writer.str(tag);
            writer.str(&version.to_string());
        }

        let core = &*self.core;
        writer.pool(&core.strings);
        writer.len(core.dependencies.len());
        for dependency in &core.dependencies {
            writer.id(dependency.name);
            writer.id(dependency.range);
            writer.optional_id(dependency.alias);
            writer.u8(u8::from(dependency.optional) | (u8::from(dependency.bundled) << 1));
        }
        writer.len(core.peers.len());
        for peer in &core.peers {
            writer.id(peer.name);
            writer.id(peer.range);
            writer.optional_id(peer.alias);
            writer.u8(u8::from(peer.optional));
        }
        writer.len(core.signatures.len());
        for signature in &core.signatures {
            writer.optional_str(signature.keyid.as_deref());
            writer.optional_str(signature.sig.as_deref());
        }
        writer.len(core.versions.len());
        for version in &core.versions {
            writer.id(version.text);
            writer.span(version.dependencies);
            writer.span(version.peers);
            writer.optional_id(version.node_engine);
            writer.optional_id(version.tarball_url);
            writer.optional_id(version.integrity);
            writer.u64(version.unpacked_size.map_or(0, NonZeroU64::get));
            writer.span(version.signatures);
        }
        for index in &core.version_lookup {
            writer.u32(*index);
        }

        writer.pool(&self.release.strings);
        writer.len(self.release.records.len());
        for record in &self.release.records {
            writer.u32(record.version);
            writer.id(record.published_at);
            match record.published_at_unix {
                Some(seconds) => {
                    writer.u8(1);
                    writer.u64(seconds as u64);
                }
                None => writer.u8(0),
            }
        }

        writer.pool(&self.platform.strings);
        writer.len(self.platform.values.len());
        for value in &self.platform.values {
            writer.id(*value);
        }
        writer.len(self.platform.records.len());
        for record in &self.platform.records {
            writer.u32(record.version);
            writer.span(record.os);
            writer.span(record.cpu);
            writer.span(record.libc);
        }

        writer.len(self.trust.len());
        for record in self.trust.iter() {
            writer.u32(record.version);
            writer.u8(match record.evidence {
                TrustEvidence::TrustedPublisher => TRUSTED_PUBLISHER,
                TrustEvidence::StagedPublish => STAGED_PUBLISH,
            });
        }
    }

    pub(crate) fn decode_snapshot(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader(bytes);
        let flags = reader.u8()?;
        if flags & !KNOWN_FLAGS != 0 {
            return None;
        }
        let modified = reader.optional_str()?.map(str::to_owned);
        let covered_range_count = reader.count(4)?;
        let mut covered_ranges = HashSet::with_capacity(covered_range_count);
        for _ in 0..covered_range_count {
            covered_ranges.insert(reader.str()?.to_owned());
        }
        let workspace_count = reader.count(4)?;
        let mut workspace_versions = HashSet::with_capacity(workspace_count);
        for _ in 0..workspace_count {
            workspace_versions.insert(NpmVersion::parse(reader.str()?).ok()?);
        }
        let mut optional_version = || -> Option<Option<NpmVersion>> {
            reader
                .optional_str()?
                .map(|text| NpmVersion::parse(text).ok())
                .map_or(Some(None), |version| version.map(Some))
        };
        let latest_version = optional_version()?;
        let latest_version_hint = optional_version()?;
        let preferred_latest = optional_version()?;
        let dist_tag_count = reader.count(8)?;
        let mut dist_tags = HashMap::with_capacity(dist_tag_count);
        for _ in 0..dist_tag_count {
            let tag = reader.str()?.to_owned();
            dist_tags.insert(tag, NpmVersion::parse(reader.str()?).ok()?);
        }

        let strings = reader.pool()?;
        let string_count = strings.spans.len();
        let dependencies = (0..reader.count(13)?)
            .map(|_| {
                let name = reader.id(string_count)?;
                let range = reader.id(string_count)?;
                let alias = reader.optional_id(string_count)?;
                let flags = reader.u8()?;
                (flags & !0b11 == 0).then_some(DependencyRecord {
                    name,
                    range,
                    alias,
                    optional: flags & 1 != 0,
                    bundled: flags & 0b10 != 0,
                })
            })
            .collect::<Option<Box<[_]>>>()?;
        let peers = (0..reader.count(13)?)
            .map(|_| {
                let name = reader.id(string_count)?;
                let range = reader.id(string_count)?;
                let alias = reader.optional_id(string_count)?;
                let optional = reader.bool()?;
                Some(PeerRecord {
                    name,
                    range,
                    alias,
                    optional,
                })
            })
            .collect::<Option<Box<[_]>>>()?;
        let signatures = (0..reader.count(2)?)
            .map(|_| {
                let keyid = reader.optional_str()?.map(str::to_owned);
                let sig = reader.optional_str()?.map(str::to_owned);
                Some(lpm_registry::RegistrySignature { keyid, sig })
            })
            .collect::<Option<Box<[_]>>>()?;
        let version_count = reader.count(48)?;
        let mut version_records = Vec::with_capacity(version_count);
        let mut versions = Vec::with_capacity(version_count);
        for _ in 0..version_count {
            let record = VersionRecord {
                text: reader.id(string_count)?,
                dependencies: reader.span(dependencies.len())?,
                peers: reader.span(peers.len())?,
                node_engine: reader.optional_id(string_count)?,
                tarball_url: reader.optional_id(string_count)?,
                integrity: reader.optional_id(string_count)?,
                unpacked_size: NonZeroU64::new(reader.u64()?),
                signatures: reader.span(signatures.len())?,
            };
            if !names_strictly_ascending(
                &strings,
                dependencies[record.dependencies.range()]
                    .iter()
                    .map(|dependency| dependency.name),
            ) || !names_strictly_ascending(
                &strings,
                peers[record.peers.range()].iter().map(|peer| peer.name),
            ) {
                return None;
            }
            let version = NpmVersion::parse(strings.get(record.text)).ok()?;
            if versions.last().is_some_and(|newer| *newer <= version) {
                return None;
            }
            versions.push(version);
            version_records.push(record);
        }
        let version_lookup = (0..version_count)
            .map(|_| {
                reader
                    .u32()
                    .filter(|index| (*index as usize) < version_count)
            })
            .collect::<Option<Box<[_]>>>()?;
        if !version_lookup.windows(2).all(|pair| {
            strings.get(version_records[pair[0] as usize].text)
                < strings.get(version_records[pair[1] as usize].text)
        }) {
            return None;
        }

        let release_strings = reader.pool()?;
        let release_records = (0..reader.count(9)?)
            .map(|_| {
                let version = reader.u32()?;
                let published_at = reader.id(release_strings.spans.len())?;
                let published_at_unix = match reader.u8()? {
                    0 => None,
                    1 => Some(reader.u64()? as i64),
                    _ => return None,
                };
                Some(ReleaseRecord {
                    version,
                    published_at,
                    published_at_unix,
                })
            })
            .collect::<Option<Box<[_]>>>()?;
        if !version_indexes_strictly_ascending(
            release_records.iter().map(|record| record.version),
            version_count,
        ) {
            return None;
        }

        let platform_strings = reader.pool()?;
        let platform_values = (0..reader.count(4)?)
            .map(|_| reader.id(platform_strings.spans.len()))
            .collect::<Option<Box<[_]>>>()?;
        let platform_records = (0..reader.count(28)?)
            .map(|_| {
                Some(PlatformRecord {
                    version: reader.u32()?,
                    os: reader.span(platform_values.len())?,
                    cpu: reader.span(platform_values.len())?,
                    libc: reader.span(platform_values.len())?,
                })
            })
            .collect::<Option<Box<[_]>>>()?;
        if !version_indexes_strictly_ascending(
            platform_records.iter().map(|record| record.version),
            version_count,
        ) {
            return None;
        }

        let trust = (0..reader.count(5)?)
            .map(|_| {
                let version = reader.u32()?;
                let evidence = match reader.u8()? {
                    TRUSTED_PUBLISHER => TrustEvidence::TrustedPublisher,
                    STAGED_PUBLISH => TrustEvidence::StagedPublish,
                    _ => return None,
                };
                Some(TrustRecord { version, evidence })
            })
            .collect::<Option<Arc<[_]>>>()?;
        if !version_indexes_strictly_ascending(
            trust.iter().map(|record| record.version),
            version_count,
        ) || !reader.0.is_empty()
        {
            return None;
        }

        let modified_unix = modified.as_deref().and_then(parse_npm_time_unix);
        Some(Self {
            modified,
            modified_unix,
            trust_metadata_complete: flags & TRUST_METADATA_COMPLETE != 0,
            versions_complete: flags & VERSIONS_COMPLETE != 0,
            covered_ranges,
            workspace_versions,
            platform_metadata_complete: flags & PLATFORM_METADATA_COMPLETE != 0,
            latest_version,
            latest_version_hint,
            preferred_latest,
            versions: Arc::from(versions),
            dist_tags: Arc::new(dist_tags),
            core: Arc::new(ManifestCore {
                strings,
                versions: version_records.into_boxed_slice(),
                version_lookup,
                dependencies,
                peers,
                signatures,
            }),
            release: Arc::new(ReleaseOverlay {
                strings: release_strings,
                records: release_records,
            }),
            platform: Arc::new(PlatformOverlay {
                strings: platform_strings,
                values: platform_values,
                records: platform_records,
            }),
            trust,
        })
    }
}

fn names_strictly_ascending(pool: &StringPool, mut names: impl Iterator<Item = StringId>) -> bool {
    let Some(mut previous) = names.next() else {
        return true;
    };
    names.all(|name| {
        let ascending = pool.get(previous) < pool.get(name);
        previous = name;
        ascending
    })
}

fn version_indexes_strictly_ascending(
    mut indexes: impl Iterator<Item = u32>,
    version_count: usize,
) -> bool {
    let mut previous = None;
    indexes.all(|index| {
        let valid = (index as usize) < version_count && previous.is_none_or(|last| last < index);
        previous = Some(index);
        valid
    })
}

struct Writer<'a>(&'a mut Vec<u8>);

impl Writer<'_> {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn len(&mut self, len: usize) {
        self.u32(u32::try_from(len).expect("snapshot tables are bounded by u32 record indexes"));
    }

    fn str(&mut self, value: &str) {
        self.len(value.len());
        self.0.extend_from_slice(value.as_bytes());
    }

    fn optional_str(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.str(value);
            }
            None => self.u8(0),
        }
    }

    fn id(&mut self, id: StringId) {
        self.u32(id.0.get());
    }

    fn optional_id(&mut self, id: Option<StringId>) {
        self.u32(id.map_or(0, |id| id.0.get()));
    }

    fn span(&mut self, span: RecordSpan) {
        self.u32(span.start);
        self.u32(span.len);
    }

    fn pool(&mut self, pool: &StringPool) {
        self.str(&pool.data);
        self.len(pool.spans.len());
        for span in &pool.spans {
            self.u32(span.start);
            self.u32(span.len);
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(len)?;
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        let (&value, tail) = self.0.split_first()?;
        self.0 = tail;
        Some(value)
    }

    fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// Reads a table length whose items occupy at least `item_bytes` each, so
    /// a damaged length cannot request more memory than the snapshot holds.
    fn count(&mut self, item_bytes: usize) -> Option<usize> {
        let count = self.u32()? as usize;
        (count.checked_mul(item_bytes)? <= self.0.len()).then_some(count)
    }

    fn str(&mut self) -> Option<&'a str> {
        let len = self.u32()? as usize;
        std::str::from_utf8(self.take(len)?).ok()
    }

    fn optional_str(&mut self) -> Option<Option<&'a str>> {
        match self.u8()? {
            0 => Some(None),
            1 => self.str().map(Some),
            _ => None,
        }
    }

    fn id(&mut self, string_count: usize) -> Option<StringId> {
        self.optional_id(string_count)?
    }

    fn optional_id(&mut self, string_count: usize) -> Option<Option<StringId>> {
        let raw = self.u32()?;
        if raw as usize > string_count {
            return None;
        }
        Some(NonZeroU32::new(raw).map(StringId))
    }

    fn span(&mut self, table_len: usize) -> Option<RecordSpan> {
        let start = self.u32()?;
        let len = self.u32()?;
        (start as usize)
            .checked_add(len as usize)
            .filter(|end| *end <= table_len)
            .map(|_| RecordSpan { start, len })
    }

    fn pool(&mut self) -> Option<StringPool> {
        let data = self.str()?;
        let spans = (0..self.count(8)?)
            .map(|_| {
                let start = self.u32()?;
                let len = self.u32()?;
                let end = (start as usize).checked_add(len as usize)?;
                (end <= data.len()
                    && data.is_char_boundary(start as usize)
                    && data.is_char_boundary(end))
                .then_some(TextSpan { start, len })
            })
            .collect::<Option<Box<[_]>>>()?;
        Some(StringPool {
            data: data.into(),
            spans,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_registry::MetadataProjection as _;

    fn rich_info() -> CachedPackageInfo {
        let metadata: lpm_registry::PackageMetadata = serde_json::from_value(serde_json::json!({
            "name": "pkg",
            "modified": "2026-01-02T03:04:05.000Z",
            "dist-tags": {"latest": "2.0.0", "next": "3.0.0-rc.1", "broken": "not-a-version"},
            "time": {"2.0.0": "2025-12-01T00:00:00.000Z"},
            "versions": {
                "1.0.0+build.7": {
                    "name": "pkg", "version": "1.0.0+build.7",
                    "dependencies": {"shared": "^1.0.0", "alias": "npm:target@^2.0.0"},
                    "dist": {"tarball": "https://registry.invalid/pkg-1.0.0.tgz", "integrity": "sha512-one"}
                },
                "2.0.0": {
                    "name": "pkg", "version": "2.0.0",
                    "dependencies": {"shared": "^1.0.0", "résumé": "~1.2.3"},
                    "optionalDependencies": {"native": "^3.0.0"},
                    "peerDependencies": {"react": "^19.0.0", "peer-alias": "npm:react@^18"},
                    "peerDependenciesMeta": {"react": {"optional": true}},
                    "bundleDependencies": ["shared"],
                    "engines": {"node": ">=20"},
                    "os": ["darwin", "!win32"], "cpu": ["arm64"], "libc": ["glibc"],
                    "_npmUser": {"trustedPublisher": {"id": "github"}},
                    "dist": {
                        "tarball": "https://registry.invalid/pkg-2.0.0.tgz",
                        "integrity": "sha512-two",
                        "unpackedSize": 4096,
                        "signatures": [{"keyid": "SHA256:key", "sig": "signed"}, {"sig": "no-key"}]
                    }
                },
                "3.0.0-rc.1": {
                    "name": "pkg", "version": "3.0.0-rc.1",
                    "_npmUser": {"approver": "reviewer"},
                    "dist": {"tarball": "https://registry.invalid/pkg-3.0.0-rc.1.tgz", "shasum": "0123456789abcdef0123456789abcdef01234567"}
                }
            }
        }))
        .unwrap();
        let mut info = crate::provider::parse_owned_full_metadata_to_cache_info(metadata);
        info.covered_ranges
            .extend(["^2".to_owned(), "=1.0.0".to_owned()]);
        info.workspace_versions
            .insert(NpmVersion::parse("9.9.9").unwrap());
        info.preferred_latest = info.latest_version.clone();
        info
    }

    fn round_trip(info: &CachedPackageInfo) -> Option<CachedPackageInfo> {
        let mut bytes = Vec::new();
        info.encode_snapshot(&mut bytes);
        CachedPackageInfo::decode_snapshot(&bytes)
    }

    #[test]
    fn snapshots_round_trip_every_manifest_table() {
        let info = rich_info();
        assert_eq!(info.versions.len(), 3);
        assert!(info.has_platform_metadata());
        assert!(info.published_at("2.0.0").is_some());
        assert_eq!(
            info.trust_evidence("3.0.0-rc.1"),
            Some(TrustEvidence::StagedPublish)
        );
        assert_eq!(info.signatures("2.0.0").len(), 2);
        assert_eq!(
            info.dependency("1.0.0+build.7", "alias").unwrap().alias,
            Some("target")
        );
        assert_eq!(round_trip(&info).as_ref(), Some(&info));
        assert_eq!(
            round_trip(&CachedPackageInfo::empty()).as_ref(),
            Some(&CachedPackageInfo::empty())
        );
    }

    #[test]
    fn projections_carry_the_document_fields_beside_the_tables() {
        let info = rich_info();
        let dist_tags = HashMap::from([
            ("latest".to_owned(), "2.0.0".to_owned()),
            ("broken".to_owned(), "not-a-version".to_owned()),
        ]);
        let bytes = ManifestProjection::encode(&info, &dist_tags, 4);
        let projection = ManifestProjection::decode(&bytes).unwrap();
        assert_eq!(projection.info, info);
        assert_eq!(projection.dist_tags, dist_tags);
        assert_eq!(projection.version_count, 4);
    }

    #[test]
    fn damaged_snapshots_are_rejected_or_stay_safe_to_read() {
        let info = rich_info();
        let mut bytes = Vec::new();
        info.encode_snapshot(&mut bytes);
        for len in 0..bytes.len() {
            assert!(
                CachedPackageInfo::decode_snapshot(&bytes[..len]).is_none(),
                "truncated to {len}"
            );
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(CachedPackageInfo::decode_snapshot(&extended).is_none());
        for index in 0..bytes.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut damaged = bytes.clone();
                damaged[index] ^= mask;
                if let Some(decoded) = CachedPackageInfo::decode_snapshot(&damaged) {
                    for version in decoded.versions.iter() {
                        let text = version.to_string();
                        let _ = decoded.manifest_version_owned_for(version);
                        let _ = decoded.dependencies(&text).map(Iterator::count);
                        let _ = decoded.peer_dependencies(&text).map(Iterator::count);
                        let _ = decoded.platform_is_compatible(&text);
                        let _ = decoded.trust_evidence(&text);
                        let _ = decoded.published_at_unix(&text);
                    }
                }
            }
        }
    }
}
