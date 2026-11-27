//! Caller-defined projections stored beside cached metadata documents.
//!
//! A projection is a consumer's own encoding of one cached document, such as
//! the resolver's parsed manifest tables. It is stored in `<entry>.projection`
//! and bound to the content ID that the document's cache header records, so it
//! is used only while that exact document is the cached entry. A rewritten
//! document gets a new content ID, which orphans the old projection; a 304
//! revalidation changes only the entry's freshness, so its projection stays
//! valid.

use super::*;

const PROJECTION_MAGIC: &[u8] = b"LPM-MP-V1\n";
const VERSIONS_COMPLETE: u8 = 1;
const LATEST_PRESENT: u8 = 1 << 1;

/// A consumer's encoding of one cached metadata document.
pub trait MetadataProjection: Sized + Send + 'static {
    /// Identifies the encoding and the derivation that produced it. Stored
    /// projections with another format are ignored, so the value must change
    /// whenever either changes.
    const FORMAT: &'static str;

    fn decode(bytes: &[u8]) -> Option<Self>;
}

/// Reads documents only.
pub enum NoProjection {}

impl MetadataProjection for NoProjection {
    const FORMAT: &'static str = "";

    fn decode(_: &[u8]) -> Option<Self> {
        None
    }
}

/// The document, or its stored projection, that answered a resolution request.
#[derive(Debug)]
pub enum ResolutionMetadata<P> {
    Document {
        metadata: Box<PackageMetadata>,
        /// Present when the document is the cached entry, so the caller can
        /// store its projection for later reads.
        projection: Option<ProjectionSlot>,
    },
    Projected(P),
}

impl ResolutionMetadata<NoProjection> {
    pub fn into_document(self) -> PackageMetadata {
        match self {
            Self::Document { metadata, .. } => *metadata,
            Self::Projected(never) => match never {},
        }
    }
}

/// Identifies the cached document a projection is derived from.
#[derive(Clone)]
pub struct ProjectionSlot {
    entry: std::path::PathBuf,
    content_id: u128,
    mutation: Arc<MetadataCacheMutation>,
    content_revision: u64,
    write_revision: Option<u64>,
    format: &'static str,
    facts: ProjectionFacts,
}

impl std::fmt::Debug for ProjectionSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionSlot")
            .field("entry", &self.entry)
            .field("content_id", &self.content_id)
            .field("content_revision", &self.content_revision)
            .field("write_revision", &self.write_revision)
            .field("format", &self.format)
            .field("facts", &self.facts)
            .finish()
    }
}

/// Projection payload parked while its cold packument write is still in flight.
pub(super) struct PendingProjection {
    pub(super) packument_revision: u64,
    pub(super) content_revision: u64,
    pub(super) projection_revision: u64,
    pub(super) entry: std::path::PathBuf,
    pub(super) header: Vec<u8>,
    pub(super) body: Vec<u8>,
    pub(super) _reservation: tokio::sync::OwnedSemaphorePermit,
}

/// What the registry needs from a document to choose it without decoding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectionFacts {
    pub(super) versions_complete: bool,
    pub(super) latest: Option<String>,
}

/// The entry that holds a decoded document, for binding its projection.
#[derive(Clone)]
pub(super) struct ProjectionSource {
    pub(super) entry: std::path::PathBuf,
    pub(super) content_id: u128,
    pub(super) mutation: Arc<MetadataCacheMutation>,
    pub(super) content_revision: u64,
    pub(super) write_revision: Option<u64>,
}

impl ProjectionSource {
    pub(super) fn slot<P: MetadataProjection>(
        self,
        facts: ProjectionFacts,
    ) -> Option<ProjectionSlot> {
        (!P::FORMAT.is_empty()).then_some(ProjectionSlot {
            entry: self.entry,
            content_id: self.content_id,
            mutation: self.mutation,
            content_revision: self.content_revision,
            write_revision: self.write_revision,
            format: P::FORMAT,
            facts,
        })
    }
}

pub(super) fn projection_path(entry: &std::path::Path) -> std::path::PathBuf {
    entry.with_extension("projection")
}

/// Read the projection bound to `content_id` in `format`.
///
/// Validates the bounded header from the open file before allocating or reading
/// the projection body, so stale or format-mismatched files avoid reading large
/// sidecar payloads into memory.
pub(super) fn read_projection<P: MetadataProjection>(
    entry: &std::path::Path,
    content_id: u128,
) -> Option<(P, ProjectionFacts)> {
    use std::io::Read as _;

    if P::FORMAT.is_empty() {
        return None;
    }
    let file = std::fs::File::open(projection_path(entry)).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len > cache::METADATA_CACHE_FILE_CAP {
        return None;
    }
    let mut reader = std::io::BufReader::new(file.take(cache::METADATA_CACHE_FILE_CAP));
    let (facts, header_bytes) = read_projection_header(&mut reader, content_id, P::FORMAT)?;
    let remaining_est = usize::try_from(file_len.saturating_sub(header_bytes as u64))
        .unwrap_or(0)
        .min(cache::METADATA_CACHE_FILE_CAP as usize);
    let mut body = Vec::with_capacity(remaining_est);
    reader.read_to_end(&mut body).ok()?;
    Some((P::decode(&body)?, facts))
}

fn read_projection_header<R: std::io::Read>(
    reader: &mut R,
    content_id: u128,
    format: &str,
) -> Option<(ProjectionFacts, usize)> {
    let mut magic = [0u8; PROJECTION_MAGIC.len()];
    reader.read_exact(&mut magic).ok()?;
    if magic != *PROJECTION_MAGIC {
        return None;
    }
    let mut stored_id = [0u8; 16];
    reader.read_exact(&mut stored_id).ok()?;
    if u128::from_le_bytes(stored_id) != content_id {
        return None;
    }
    let mut flags_buf = [0u8; 1];
    reader.read_exact(&mut flags_buf).ok()?;
    let flags = flags_buf[0];
    if flags & !(VERSIONS_COMPLETE | LATEST_PRESENT) != 0 {
        return None;
    }
    let mut header_bytes = PROJECTION_MAGIC.len() + 16 + 1;
    let latest = if flags & LATEST_PRESENT != 0 {
        let (latest, consumed) = read_text(reader)?;
        header_bytes += consumed;
        Some(latest)
    } else {
        None
    };
    let (stored_format, consumed) = read_text(reader)?;
    header_bytes += consumed;
    if stored_format != format {
        return None;
    }
    Some((
        ProjectionFacts {
            versions_complete: flags & VERSIONS_COMPLETE != 0,
            latest,
        },
        header_bytes,
    ))
}

fn read_text<R: std::io::Read>(reader: &mut R) -> Option<(String, usize)> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).ok()?;
    let len = usize::from(u16::from_le_bytes(len_buf));
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    Some((text, 2 + len))
}

#[cfg(test)]
fn parse_projection<'a>(
    bytes: &'a [u8],
    content_id: u128,
    format: &str,
) -> Option<(ProjectionFacts, &'a [u8])> {
    let mut cursor = std::io::Cursor::new(bytes);
    let (facts, consumed) = read_projection_header(&mut cursor, content_id, format)?;
    Some((facts, &bytes[consumed..]))
}

fn projection_header(slot: &ProjectionSlot) -> Option<Vec<u8>> {
    let latest = slot.facts.latest.as_deref();
    let text_len = |text: &str| u16::try_from(text.len()).ok().map(u16::to_le_bytes);
    let format_len = text_len(slot.format)?;
    let mut header = Vec::with_capacity(
        PROJECTION_MAGIC.len() + 21 + slot.format.len() + latest.map_or(0, str::len),
    );
    header.extend_from_slice(PROJECTION_MAGIC);
    header.extend_from_slice(&slot.content_id.to_le_bytes());
    let mut flags = 0;
    if slot.facts.versions_complete {
        flags |= VERSIONS_COMPLETE;
    }
    if latest.is_some() {
        flags |= LATEST_PRESENT;
    }
    header.push(flags);
    if let Some(latest) = latest {
        header.extend_from_slice(&text_len(latest)?);
        header.extend_from_slice(latest.as_bytes());
    }
    header.extend_from_slice(&format_len);
    header.extend_from_slice(slot.format.as_bytes());
    Some(header)
}

pub(super) fn write_projection_file(
    entry: &std::path::Path,
    header: &[u8],
    body: &[u8],
) -> std::io::Result<()> {
    use std::io::Write as _;

    let parent = entry.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "cache path has no parent")
    })?;
    cache::ensure_private_metadata_cache_dir(parent)?;
    lpm_common::write_file_atomic_with(
        &projection_path(entry),
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
        |file| {
            file.write_all(header)?;
            file.write_all(body)
        },
    )
}

impl RegistryClient {
    /// Store `body`, the caller's projection of the document `slot` names.
    ///
    /// The write is best-effort and runs off the calling thread. It is skipped
    /// when the pending cache-write budget is exhausted.
    pub fn store_metadata_projection(&self, slot: ProjectionSlot, body: Vec<u8>) {
        self.store_metadata_projection_with_hook(slot, body, || {});
    }

    pub(super) fn store_metadata_projection_with_hook(
        &self,
        slot: ProjectionSlot,
        mut body: Vec<u8>,
        before_lock: impl FnOnce() + Send + 'static,
    ) {
        let Some(mut header) = projection_header(&slot) else {
            return;
        };
        let bytes = header.len().saturating_add(body.len());
        if bytes as u64 > cache::METADATA_CACHE_FILE_CAP {
            return;
        }
        if body.capacity().saturating_sub(body.len()) > 4096 {
            body.shrink_to_fit();
        }
        if header.capacity().saturating_sub(header.len()) > 256 {
            header.shrink_to_fit();
        }
        let retained_capacity = header.capacity().saturating_add(body.capacity());
        let Some(reservation) = cache::reserve_pending_metadata_cache_bytes(
            &self.pending_cache_write_bytes,
            retained_capacity,
        ) else {
            tracing::debug!(
                "skipping metadata projection write because the allocation budget is full"
            );
            return;
        };
        // Share the packument's mutation coordinator so awaited `no-store` /
        // invalidation removals serialize against in-flight projection writes,
        // cold packument writes pick up projections that arrive before
        // publication, and delayed slots from superseded documents are dropped.
        let mutation = slot.mutation;
        let content_revision = slot.content_revision;
        if mutation
            .content_revision
            .load(std::sync::atomic::Ordering::Acquire)
            != content_revision
        {
            return;
        }
        let projection_revision = mutation
            .projection_revision
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1;
        let write = move || {
            before_lock();
            let mut state = mutation
                .operation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if mutation
                .projection_revision
                .load(std::sync::atomic::Ordering::Acquire)
                != projection_revision
                || mutation
                    .content_revision
                    .load(std::sync::atomic::Ordering::Acquire)
                    != content_revision
            {
                return;
            }
            if let Some(packument_revision) = slot.write_revision {
                if mutation
                    .completed_revision
                    .load(std::sync::atomic::Ordering::Acquire)
                    < packument_revision
                {
                    state.pending_projection = Some(PendingProjection {
                        packument_revision,
                        content_revision,
                        projection_revision,
                        entry: slot.entry,
                        header,
                        body,
                        _reservation: reservation,
                    });
                    return;
                }
                if mutation
                    .published_revision
                    .load(std::sync::atomic::Ordering::Acquire)
                    != packument_revision
                    || !slot.entry.is_file()
                {
                    return;
                }
            } else if mutation
                .completed_content_revision
                .load(std::sync::atomic::Ordering::Acquire)
                < content_revision
                || !cache::open_metadata_cache_entry(&slot.entry)
                    .is_some_and(|entry| entry.header.content_id == slot.content_id)
            {
                return;
            }
            let _reservation = reservation;
            if let Err(error) = write_projection_file(&slot.entry, &header, &body) {
                tracing::debug!(%error, "failed to write metadata projection");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) if !self.synchronous_cache_writes => {
                let pending_guard = self.pending_cache_writes.enter();
                drop(runtime.spawn_blocking(move || {
                    let _pending_guard = pending_guard;
                    write();
                }));
            }
            _ => write(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(latest: Option<&str>) -> ProjectionSlot {
        ProjectionSlot {
            entry: std::path::PathBuf::from("entry"),
            content_id: 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
            mutation: Arc::new(MetadataCacheMutation::new()),
            content_revision: 0,
            write_revision: None,
            format: "format/1",
            facts: ProjectionFacts {
                versions_complete: latest.is_none(),
                latest: latest.map(str::to_owned),
            },
        }
    }

    #[test]
    fn projection_header_round_trips_its_binding_and_facts() {
        for latest in [None, Some("2.0.0"), Some("")] {
            let slot = slot(latest);
            let mut bytes = projection_header(&slot).unwrap();
            bytes.extend_from_slice(b"body");
            let (facts, body) = parse_projection(&bytes, slot.content_id, slot.format).unwrap();
            assert_eq!(facts, slot.facts);
            assert_eq!(body, b"body");
        }
    }

    #[test]
    fn projections_of_another_document_or_format_are_ignored() {
        let slot = slot(Some("2.0.0"));
        let mut bytes = projection_header(&slot).unwrap();
        bytes.extend_from_slice(b"body");
        assert!(parse_projection(&bytes, slot.content_id + 1, slot.format).is_none());
        assert!(parse_projection(&bytes, slot.content_id, "format/2").is_none());
        for len in 0..bytes.len() - 4 {
            assert!(
                parse_projection(&bytes[..len], slot.content_id, slot.format).is_none(),
                "{len}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_projection_write_cannot_outlive_no_store_removal() {
        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));
        client.write_metadata_cache("proj-race", &serde_json::json!({"name": "proj-race"}), None);
        client.flush_pending_cache_writes().await;

        let entry_path = client.cache_path("proj-race").expect("cache path");
        let proj_path = projection_path(&entry_path);
        let mutation = client.metadata_cache_mutation(&entry_path);
        let content_revision = mutation
            .content_revision
            .load(std::sync::atomic::Ordering::Acquire);
        let opened = cache::open_metadata_cache_entry(&entry_path).expect("seeded packument");
        let slot = ProjectionSlot {
            entry: entry_path.clone(),
            content_id: opened.header.content_id,
            mutation,
            content_revision,
            write_revision: None,
            format: "test/1",
            facts: ProjectionFacts {
                versions_complete: true,
                latest: None,
            },
        };
        drop(opened);

        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        client.store_metadata_projection_with_hook(slot, b"derived-body".to_vec(), move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("projection worker must start");

        let _ = client
            .write_metadata_cache_entry_async(
                "proj-race",
                serde_json::json!({"name": "proj-race"}),
                None,
                cache::MetadataCacheDirective::NoStore,
                None,
            )
            .await
            .unwrap();

        release_tx.send(()).unwrap();
        client.flush_pending_cache_writes().await;

        assert!(
            !entry_path.exists(),
            "packument cache file must remain absent after no-store removal"
        );
        assert!(
            !proj_path.exists(),
            "paused projection write must not recreate an orphaned projection after no-store"
        );
    }

    #[test]
    fn read_projection_rejects_mismatched_content_id_without_decoding_body() {
        struct PanicOnDecode;
        impl MetadataProjection for PanicOnDecode {
            const FORMAT: &'static str = "format/1";

            fn decode(_bytes: &[u8]) -> Option<Self> {
                panic!("projection body must not be decoded when header content_id mismatches");
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path().join("entry");
        let slot = slot(Some("2.0.0"));
        let mut bytes = projection_header(&slot).unwrap();
        bytes.extend_from_slice(&[0xff; 64]);
        std::fs::write(projection_path(&entry), bytes).unwrap();

        assert!(read_projection::<PanicOnDecode>(&entry, slot.content_id + 1).is_none());
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RawBody(Vec<u8>);

    impl MetadataProjection for RawBody {
        const FORMAT: &'static str = "raw-body/1";

        fn decode(bytes: &[u8]) -> Option<Self> {
            Some(Self(bytes.to_vec()))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cold_async_cache_write_keeps_projection_when_projection_runs_before_packument_publish()
    {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));

        let (packument_paused_tx, packument_paused_rx) = std::sync::mpsc::sync_channel(1);
        let (release_packument_tx, release_packument_rx) = std::sync::mpsc::sync_channel(1);

        let (_meta, written) = client
            .write_metadata_cache_entry_async_with_hook(
                "cold-proj-race",
                serde_json::json!({"name": "cold-proj-race"}),
                None,
                cache::MetadataCacheDirective::Unspecified,
                None,
                move || {
                    let _ = packument_paused_tx.send(());
                    let _ = release_packument_rx.recv();
                },
            )
            .await
            .unwrap();

        packument_paused_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("packument writer must pause before publishing");

        let source = written
            .and_then(|w| w.source)
            .expect("cold write must yield a projection source");
        let entry_path = source.entry.clone();
        let content_id = source.content_id;
        let slot = source
            .slot::<RawBody>(ProjectionFacts {
                versions_complete: true,
                latest: None,
            })
            .expect("projection slot");

        // Run the projection write while the cold packument file has not yet been published.
        client.synchronous_cache_writes = true;
        client.store_metadata_projection(slot, b"cold-derived-body".to_vec());
        client.synchronous_cache_writes = false;

        release_packument_tx.send(()).unwrap();
        client.flush_pending_cache_writes().await;

        assert!(
            entry_path.is_file(),
            "packument cache file must be published"
        );
        let projected = read_projection::<RawBody>(&entry_path, content_id);
        assert_eq!(
            projected.map(|(body, _)| body),
            Some(RawBody(b"cold-derived-body".to_vec())),
            "cold fetch must not drop its projection when the projection runs before packument publication"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delayed_projection_slot_cannot_overwrite_newer_packument_projection() {
        let cache_dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new()
            .with_cache_dir(Some(cache_dir.path().to_path_buf()))
            .with_synchronous_cache_writes(true);

        let (_m1, w1) = client
            .write_metadata_cache_entry_async(
                "delayed-proj",
                serde_json::json!({"name": "delayed-proj", "version": "1.0.0"}),
                None,
                cache::MetadataCacheDirective::Unspecified,
                None,
            )
            .await
            .unwrap();
        let stale_slot = w1
            .and_then(|w| w.source)
            .and_then(|source| {
                source.slot::<RawBody>(ProjectionFacts {
                    versions_complete: true,
                    latest: Some("1.0.0".to_string()),
                })
            })
            .expect("v1 slot");

        // A newer packument replaces v1 and writes its own projection.
        let (_m2, w2) = client
            .write_metadata_cache_entry_async(
                "delayed-proj",
                serde_json::json!({"name": "delayed-proj", "version": "2.0.0"}),
                None,
                cache::MetadataCacheDirective::Unspecified,
                None,
            )
            .await
            .unwrap();
        let v2_source = w2.and_then(|w| w.source).expect("v2 source");
        let v2_entry = v2_source.entry.clone();
        let v2_content_id = v2_source.content_id;
        let v2_slot = v2_source
            .slot::<RawBody>(ProjectionFacts {
                versions_complete: true,
                latest: Some("2.0.0".to_string()),
            })
            .expect("v2 slot");
        client.store_metadata_projection(v2_slot, b"v2-body".to_vec());

        // Now the stale v1 slot is submitted late — it must not clobber v2's projection.
        client.store_metadata_projection(stale_slot, b"stale-v1-body".to_vec());

        let projected = read_projection::<RawBody>(&v2_entry, v2_content_id);
        assert_eq!(
            projected.map(|(body, _)| body),
            Some(RawBody(b"v2-body".to_vec())),
            "delayed projection slot from superseded packument must not overwrite newer projection"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parked_cold_projection_is_cancelled_when_no_store_arrives_before_packument_publish() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new().with_cache_dir(Some(cache_dir.path().to_path_buf()));
        let permits_before = client.pending_cache_write_bytes.available_permits();

        let (packument_paused_tx, packument_paused_rx) = std::sync::mpsc::sync_channel(1);
        let (release_packument_tx, release_packument_rx) = std::sync::mpsc::sync_channel(1);

        let (_meta, written) = client
            .write_metadata_cache_entry_async_with_hook(
                "parked-no-store",
                serde_json::json!({"name": "parked-no-store"}),
                None,
                cache::MetadataCacheDirective::Unspecified,
                None,
                move || {
                    let _ = packument_paused_tx.send(());
                    let _ = release_packument_rx.recv();
                },
            )
            .await
            .unwrap();

        packument_paused_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("packument writer must pause before publishing");

        let source = written
            .and_then(|w| w.source)
            .expect("cold write must yield a projection source");
        let entry_path = source.entry.clone();
        let proj_path = projection_path(&entry_path);
        let slot = source
            .slot::<RawBody>(ProjectionFacts {
                versions_complete: true,
                latest: None,
            })
            .expect("projection slot");

        // Park the projection while the cold packument write is still in flight.
        client.synchronous_cache_writes = true;
        client.store_metadata_projection(slot, b"parked-body".to_vec());
        client.synchronous_cache_writes = false;

        // Now `no-store` arrives before the packument publishes.
        let _ = client
            .write_metadata_cache_entry_async(
                "parked-no-store",
                serde_json::json!({"name": "parked-no-store"}),
                None,
                cache::MetadataCacheDirective::NoStore,
                None,
            )
            .await
            .unwrap();

        release_packument_tx.send(()).unwrap();
        client.flush_pending_cache_writes().await;

        assert!(
            !entry_path.exists(),
            "superseded cold packument must not be written after no-store"
        );
        assert!(
            !proj_path.exists(),
            "parked cold projection must not be written after no-store"
        );
        assert_eq!(
            client.pending_cache_write_bytes.available_permits(),
            permits_before,
            "cancelled parked projection must release its pending-write budget permit"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_read_slot_from_old_document_cannot_overwrite_newer_packument_projection() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut client = RegistryClient::new()
            .with_cache_dir(Some(cache_dir.path().to_path_buf()))
            .with_synchronous_cache_writes(true);

        client
            .write_metadata_cache_entry_async(
                "read-race",
                serde_json::json!({"name": "read-race", "version": "1.0.0"}),
                None,
                cache::MetadataCacheDirective::Unspecified,
                None,
            )
            .await
            .unwrap();

        // Pause V2's write after `prepare_metadata_cache_write` increments `content_revision`
        // but before V2 replaces V1 on disk.
        client.synchronous_cache_writes = false;
        let (v2_paused_tx, v2_paused_rx) = std::sync::mpsc::sync_channel(1);
        let (release_v2_tx, release_v2_rx) = std::sync::mpsc::sync_channel(1);
        let (_m2, w2) = client
            .write_metadata_cache_entry_async_with_hook(
                "read-race",
                serde_json::json!({"name": "read-race", "version": "2.0.0"}),
                None,
                cache::MetadataCacheDirective::Unspecified,
                None,
                move || {
                    let _ = v2_paused_tx.send(());
                    let _ = release_v2_rx.recv();
                },
            )
            .await
            .unwrap();

        v2_paused_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("v2 writer must pause before publishing");

        // Reader samples V2's incremented `content_revision` while V1 is still on disk.
        let cached = client
            .read_metadata_cache_resolution_async::<serde_json::Value, RawBody>("read-race")
            .await
            .expect("v1 entry must still be readable before v2 publishes");
        let stale_read_slot = match cached.value {
            cache::CachedResolution::Document { source, .. } => source
                .expect("v1 read source")
                .slot::<RawBody>(ProjectionFacts {
                    versions_complete: true,
                    latest: Some("1.0.0".to_string()),
                })
                .expect("v1 read slot"),
            cache::CachedResolution::Projected { .. } => panic!("expected unprojected document"),
        };

        // Now V2 finishes publishing and stores its projection.
        release_v2_tx.send(()).unwrap();
        client.flush_pending_cache_writes().await;

        let v2_source = w2.and_then(|w| w.source).expect("v2 source");
        let v2_entry = v2_source.entry.clone();
        let v2_content_id = v2_source.content_id;
        let v2_slot = v2_source
            .slot::<RawBody>(ProjectionFacts {
                versions_complete: true,
                latest: Some("2.0.0".to_string()),
            })
            .expect("v2 slot");
        client.synchronous_cache_writes = true;
        client.store_metadata_projection(v2_slot, b"v2-body".to_vec());

        // The delayed V1 read slot must not clobber V2's projection sidecar.
        client.store_metadata_projection(stale_read_slot, b"stale-v1-read-body".to_vec());

        let projected = read_projection::<RawBody>(&v2_entry, v2_content_id);
        assert_eq!(
            projected.map(|(body, _)| body),
            Some(RawBody(b"v2-body".to_vec())),
            "delayed cache-read slot from older document must not overwrite newer projection"
        );
    }
}
