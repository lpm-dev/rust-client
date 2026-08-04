//! File-level content-addressable storage for the experimental v3 virtual store.
//!
//! Blob identity covers file content plus normalized executable mode. Tree
//! manifests map portable relative paths to blobs or symlink targets, and
//! source records map registry integrity to a tree. A materialized hardlink
//! farm can be created on demand per tree digest as a reusable whole-tree
//! source for filesystem clone/copy operations.
//!
//! Per-source `objects/` directories remain as compatibility projections for
//! shared v2 readers. Their regular files hardlink to the same blobs, so this
//! tier costs directory entries and metadata sidecars without duplicating file
//! content blocks. Writable link entries never hardlink directly to blobs or
//! these projections.

mod cas;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileCasVerification {
    pub sources: usize,
    pub trees: usize,
    pub blobs: usize,
    pub blobs_rehashed: usize,
    pub materialized: usize,
    pub orphaned_sources: usize,
    pub orphaned_trees: usize,
    pub orphaned_blobs: usize,
    pub orphaned_materialized: usize,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileCasPrunePlan {
    pub trees_total: usize,
    pub tree_files_orphaned: Vec<std::path::PathBuf>,
    pub blobs_total: usize,
    pub blob_files_orphaned: Vec<std::path::PathBuf>,
    pub source_record_files_orphaned: Vec<std::path::PathBuf>,
    pub source_validation_files_orphaned: Vec<std::path::PathBuf>,
    pub materialized_total: usize,
    pub materialized_entries_orphaned: Vec<std::path::PathBuf>,
}

pub use cas::{BlobKey, CasEntryKind, CasManifest, CasManifestEntry, SourceRecord};
pub(crate) use cas::{
    FileCas, FileCasReuseTimings, FileCasValidationBatch, PreparedSourceRecord, SourceReuseStatus,
};

pub use crate::v2::{
    BUILD_ARTIFACT_COMPLETE_FILENAME, BuildArtifact, BuildArtifactManifest, BuildArtifactPublish,
    BuildCacheKey, BuildKeyInputs, BuildPlatformFingerprint, BuildRuntimeFingerprint,
    BuildSandboxFingerprint, BuildScriptFingerprint, COMPAT_ISLAND_COMPLETE_FILENAME,
    CompatIslandKeyEntry, DepEdge, DepLink, ENV_V2_OBJECT_INTEGRITY, ExtractedObject,
    FreshObjectIntegrity, GraphKey, GraphKeyInputs, LINK_META_FILENAME, LINK_META_SCHEMA_VERSION,
    LinkEntry, LinkEntryRequest, LinkEntryTimings, LinkMeta, LinkMetaDep, LinkMetaPlatform,
    LinkerModeTag, ObjectIntegrityPolicy, PeerEntry, PlatformTuple, ReusableObject,
    ReusableObjectCheckTimings, Store, StoreV2Paths as StoreV3Paths, VerifiedObjectIntegrity,
    compat_island_key,
};
