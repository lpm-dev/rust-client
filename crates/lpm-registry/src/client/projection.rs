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
#[derive(Debug, Clone)]
pub struct ProjectionSlot {
    entry: std::path::PathBuf,
    content_id: u128,
    format: &'static str,
    facts: ProjectionFacts,
}

/// What the registry needs from a document to choose it without decoding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectionFacts {
    pub(super) versions_complete: bool,
    pub(super) latest: Option<String>,
}

/// The entry that holds a decoded document, for binding its projection.
#[derive(Debug, Clone)]
pub(super) struct ProjectionSource {
    pub(super) entry: std::path::PathBuf,
    pub(super) content_id: u128,
}

impl ProjectionSource {
    pub(super) fn slot<P: MetadataProjection>(
        self,
        facts: ProjectionFacts,
    ) -> Option<ProjectionSlot> {
        (!P::FORMAT.is_empty()).then_some(ProjectionSlot {
            entry: self.entry,
            content_id: self.content_id,
            format: P::FORMAT,
            facts,
        })
    }
}

pub(super) fn projection_path(entry: &std::path::Path) -> std::path::PathBuf {
    entry.with_extension("projection")
}

/// Read the projection bound to `content_id` in `format`.
pub(super) fn read_projection<P: MetadataProjection>(
    entry: &std::path::Path,
    content_id: u128,
) -> Option<(P, ProjectionFacts)> {
    if P::FORMAT.is_empty() {
        return None;
    }
    let bytes =
        lpm_common::read_file_capped(&projection_path(entry), cache::METADATA_CACHE_FILE_CAP)
            .ok()?;
    let (facts, body) = parse_projection(&bytes, content_id, P::FORMAT)?;
    Some((P::decode(body)?, facts))
}

fn parse_projection<'a>(
    bytes: &'a [u8],
    content_id: u128,
    format: &str,
) -> Option<(ProjectionFacts, &'a [u8])> {
    let rest = bytes.strip_prefix(PROJECTION_MAGIC)?;
    let (stored_id, rest) = rest.split_first_chunk::<16>()?;
    if u128::from_le_bytes(*stored_id) != content_id {
        return None;
    }
    let (&flags, rest) = rest.split_first()?;
    if flags & !(VERSIONS_COMPLETE | LATEST_PRESENT) != 0 {
        return None;
    }
    let (latest, rest) = if flags & LATEST_PRESENT != 0 {
        let (latest, rest) = take_text(rest)?;
        (Some(latest.to_owned()), rest)
    } else {
        (None, rest)
    };
    let (stored_format, body) = take_text(rest)?;
    (stored_format == format).then_some((
        ProjectionFacts {
            versions_complete: flags & VERSIONS_COMPLETE != 0,
            latest,
        },
        body,
    ))
}

fn take_text(bytes: &[u8]) -> Option<(&str, &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<2>()?;
    let (text, rest) = rest.split_at_checked(usize::from(u16::from_le_bytes(*len)))?;
    Some((std::str::from_utf8(text).ok()?, rest))
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

fn write_projection_file(
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
        let Some(header) = projection_header(&slot) else {
            return;
        };
        let bytes = header.len() + body.len();
        if bytes as u64 > cache::METADATA_CACHE_FILE_CAP {
            return;
        }
        let Some(reservation) =
            cache::reserve_pending_metadata_cache_bytes(&self.pending_cache_write_bytes, bytes)
        else {
            tracing::debug!(
                "skipping metadata projection write because the allocation budget is full"
            );
            return;
        };
        let write = move || {
            let _reservation = reservation;
            if let Err(error) = write_projection_file(&slot.entry, &header, &body) {
                tracing::debug!(%error, "failed to write metadata projection");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) if !self.synchronous_cache_writes => {
                let join = runtime.spawn_blocking(write);
                if let Ok(mut pending) = self.pending_cache_writes.lock() {
                    pending.push(join);
                }
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
}
