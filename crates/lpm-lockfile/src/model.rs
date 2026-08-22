use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::LockfileError;
use crate::source::{Source, SourceParseError};

/// Three-tuple package identity for cross-source collision avoidance.
///
/// The legacy install pipeline coordinated state on `(name, version)`
/// keys (fetch locks, integrity map, fresh-URL writeback, root-link
/// reconstruction, lockfile sort + lookup). That was correct under
/// the registry-only invariant of "one registry per package name
/// within a single graph". Once a `Source::Tarball` package can land
/// in the same graph as a `Source::Registry` package with the same
/// `(name, version)` — e.g. a forked tarball whose package.json
/// claims an upstream name + version — the two-tuple key collapses
/// identity and makes the install attach state to the wrong package.
///
/// `source_id` is [`Source::source_id`] for parsed sources, or
/// the literal string `"unknown"` for malformed/missing sources
/// (the lockfile reader gate already rejects unparseable sources;
/// this fallback keeps the helper total).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageKey {
    pub name: String,
    pub version: String,
    pub source_id: String,
}

impl PackageKey {
    /// Build a key from raw fields. Use [`LockedPackage::package_key`]
    /// or callers' equivalent helpers when possible — they handle
    /// the source parsing.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            source_id: source_id.into(),
        }
    }

    /// Sentinel source_id used when the `source` field is `None` or
    /// malformed. Matches no real `Source::source_id` output (which
    /// always has a `<prefix>-<hex>` shape), so it can't collide
    /// with a parsed source.
    pub const UNKNOWN_SOURCE_ID: &'static str = "unknown";

    pub fn lockfile_id(&self) -> String {
        let mut id =
            String::with_capacity(self.name.len() + self.version.len() + self.source_id.len() + 2);
        id.push_str(&self.name);
        id.push('@');
        id.push_str(&self.version);
        id.push('#');
        id.push_str(&self.source_id);
        id
    }
}

/// Current lockfile schema version.
///
/// **Version history:**
/// - **v1**: everything up through the peer-unaware schema. May or may
///   not contain `ambient-peer-installs` / per-package `peers`
///   depending on when the lockfile was written. The
///   `ambient-peer-installs` field defaults to empty when absent, which
///   is INDISTINGUISHABLE from "auto-install was off and there were no
///   ambient installs."
/// - **v2**: explicit signal that the writer was peer-schema-aware.
///   `ambient-peer-installs` field is authoritative — empty means
///   "no ambient installs," NOT "field absent." Per-package `peers`
///   is also authoritative for v2 lockfiles, enabling deterministic
///   graph-key reproduction across cold-and-warm installs.
/// - **v3**: per-package platform metadata (`os`, `cpu`, `libc`) and
///   optional-reachability state. Warm installs can replay host
///   filtering instead of reconstructing every locked package blindly.
/// - **v4**: per-package registry signature metadata
///   (`registry-signatures`, `registry-published-at`). Warm installs
///   can verify package signatures from the lockfile without
///   rehydrating package metadata.
/// - **v5**: importer snapshots and patch evidence. Frozen installs
///   compare the current manifest's graph-affecting dependency
///   declarations against importer snapshots before any resolve/write
///   path can run. Patch records bind `lpm.patchedDependencies` to
///   patch file SHA-256 digests so replayed installs can verify the
///   bytes they apply.
/// - **v6**: per-package `engines.node` constraints. Warm and frozen installs
///   can revalidate dependency compatibility when the effective Node.js
///   version or `engine-strict` setting changes.
/// - **v7**: artifact-bound Sigstore provenance evidence. Frozen installs can
///   replay a previously verified publisher identity without fetching the
///   attestation again.
/// - **v8**: exact root-link selections. Warm installs replay the resolver's
///   chosen direct and ambient root packages instead of inferring versions.
/// - **v9**: Git dependency sources are pinned to an exact commit.
/// - **v10**: recursive workspace installs use one root lockfile. Importers
///   carry graph projections into a content-addressed union package table.
/// - **v11**: mutable directory/link rows carry semantic manifest fingerprints.
/// - **v12**: peer edges preserve local, canonical, version, and source identity.
/// - **v13**: package rows, dependency edges, peer edges, and root selections
///   carry exact package-instance IDs. Multiple graph instances may share one
///   artifact identity without being collapsed.
///
/// **Why this matters:** install.rs's lockfile fast path uses the
/// version to decide whether the absence of `ambient-peer-installs`
/// is meaningful. On v1 + `auto_install_peers = true`, the absence
/// could be a buggy-writer artifact, so the fast path is invalidated
/// and a fresh resolve runs (which writes a current lockfile, restoring
/// fast-path eligibility on subsequent installs).
pub const LOCKFILE_VERSION_WITH_DEPENDENCY_ENGINES: u32 = 6;
pub const LOCKFILE_VERSION_WITH_PROVENANCE: u32 = 7;
pub const LOCKFILE_VERSION_WITH_ROOT_RESOLUTIONS: u32 = 8;
pub const LOCKFILE_VERSION_WITH_GIT_RESOLUTIONS: u32 = 9;
pub const LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS: u32 = 10;
pub const LOCKFILE_VERSION_WITH_LOCAL_MANIFEST_FINGERPRINTS: u32 = 11;
pub const LOCKFILE_VERSION_WITH_STRUCTURED_PEERS: u32 = 12;
pub const LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES: u32 = 13;
pub const LOCKFILE_VERSION: u32 = LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES;

/// Default lockfile filename.
pub const LOCKFILE_NAME: &str = "lpm.lock";

/// Catalog resolutions used by this install, grouped by catalog name and package name.
pub type CatalogSnapshots = BTreeMap<String, BTreeMap<String, CatalogSnapshotEntry>>;

/// Importer snapshots keyed by importer path relative to the lockfile root.
pub type ImporterSnapshots = BTreeMap<String, ImporterSnapshot>;

type WorkspaceUnionRows = (
    BTreeMap<String, LockedPackage>,
    BTreeMap<String, ImporterSnapshot>,
);

/// Lockfile-recorded patch evidence keyed by `<package-name>@<version>`.
pub type LockfilePatches = BTreeMap<String, LockfilePatch>;

/// Exact root-link selections keyed by the project-side link name.
pub type RootResolutions = BTreeMap<String, LockedRootResolution>;

/// One exact package identity selected for a project root link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LockedRootResolution {
    /// Exact selected graph instance.
    #[serde(
        default,
        rename = "instance-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_id: Option<lpm_common::PackageInstanceId>,
    /// Canonical package name after npm-alias resolution.
    pub package: String,
    /// Exact selected package version.
    pub version: String,
    /// Package source identity used to disambiguate cross-source collisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// One patch file bound to the package bytes it is allowed to modify.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LockfilePatch {
    /// Patch file path relative to the project root.
    pub path: String,
    /// SHA-256 digest of the patch file contents, formatted as `sha256-<hex>`.
    pub sha256: String,
    /// Original package SRI integrity recorded when the patch was authored.
    #[serde(rename = "original-integrity")]
    pub original_integrity: String,
}

/// The manifest state a frozen install compares against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ImporterSnapshot {
    /// `package.json > dependencies`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    /// `package.json > devDependencies`.
    #[serde(
        default,
        rename = "dev-dependencies",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub dev_dependencies: BTreeMap<String, String>,
    /// `package.json > optionalDependencies`.
    #[serde(
        default,
        rename = "optional-dependencies",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub optional_dependencies: BTreeMap<String, String>,
    /// `package.json > peerDependencies`.
    #[serde(
        default,
        rename = "peer-dependencies",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub peer_dependencies: BTreeMap<String, String>,
    /// `package.json > lpm.overrides`, after any catalog protocol references are resolved.
    #[serde(
        default,
        rename = "lpm-overrides",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub lpm_overrides: BTreeMap<String, String>,
    /// Top-level npm-compatible `overrides`, after catalog protocol resolution.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, String>,
    /// Yarn-compatible `resolutions`, after catalog protocol resolution.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resolutions: BTreeMap<String, String>,
    /// Centralized catalog declarations visible to this importer.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub catalogs: BTreeMap<String, BTreeMap<String, String>>,
    /// Fingerprint for `package.json > lpm.patchedDependencies`.
    #[serde(
        default,
        rename = "patches-fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub patches_fingerprint: Option<String>,
    /// Fingerprint for `package.json > lpm.peerDependencyRules`.
    #[serde(
        default,
        rename = "peer-dependency-rules-fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub peer_dependency_rules_fingerprint: Option<String>,
    /// Resolved `lpm.autoInstallPeers` value used for this graph.
    #[serde(
        default,
        rename = "auto-install-peers",
        skip_serializing_if = "Option::is_none"
    )]
    pub auto_install_peers: Option<bool>,
    /// Fingerprint of the workspace root's exact provider graph used to
    /// satisfy peers for this importer during a recursive install.
    #[serde(
        default,
        rename = "workspace-root-peer-providers-fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub workspace_root_peer_providers_fingerprint: Option<String>,
    /// Content-addressed package rows reachable from this importer in a
    /// workspace union lockfile.
    #[serde(
        default,
        rename = "locked-packages",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub locked_packages: Vec<String>,
    /// Importer-local npm alias links.
    #[serde(
        default,
        rename = "root-aliases",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub root_aliases: BTreeMap<String, String>,
    /// Importer-local exact root selections.
    #[serde(
        default,
        rename = "root-resolutions",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub root_resolutions: RootResolutions,
    /// Importer-local peer packages linked at its install root.
    #[serde(
        default,
        rename = "ambient-peer-installs",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ambient_peer_installs: Vec<String>,
    /// Importer-local patch evidence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub patches: LockfilePatches,
    /// Importer-local catalog resolutions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub catalog_resolutions: CatalogSnapshots,
    /// Importer-local provenance evidence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance: BTreeMap<String, LockedProvenance>,
    /// Importer-local automatic isolated-linker decision.
    #[serde(
        default,
        rename = "auto-isolated-peer-conflicts",
        skip_serializing_if = "is_false"
    )]
    pub auto_isolated_peer_conflicts: bool,
}

impl ImporterSnapshot {
    fn without_projection(&self) -> Self {
        let mut snapshot = self.clone();
        snapshot.locked_packages.clear();
        snapshot.root_aliases.clear();
        snapshot.root_resolutions.clear();
        snapshot.ambient_peer_installs.clear();
        snapshot.patches.clear();
        snapshot.catalog_resolutions.clear();
        snapshot.provenance.clear();
        snapshot.auto_isolated_peer_conflicts = false;
        snapshot
    }
}

fn validate_importer_path(importer: &str) -> Result<(), LockfileError> {
    if importer == "." {
        return Ok(());
    }
    if importer.is_empty()
        || importer.starts_with('/')
        || importer.ends_with('/')
        || importer.contains('\\')
        || importer
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(LockfileError::Deserialize(format!(
            "invalid workspace importer path {importer:?}"
        )));
    }
    Ok(())
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn hash_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_length_prefixed(hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn hash_strings(hasher: &mut Sha256, values: &[String]) {
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        hash_length_prefixed(hasher, value.as_bytes());
    }
}

fn valid_sha256_prefixed_hex(value: &str) -> bool {
    value.strip_prefix("sha256-").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn workspace_package_id_for_version(package: &LockedPackage, lockfile_version: u32) -> String {
    #[cfg(test)]
    WORKSPACE_PACKAGE_ID_CALLS.with(|calls| calls.set(calls.get() + 1));
    let LockedPackage {
        instance_id,
        name,
        version,
        source,
        integrity,
        manifest_fingerprint,
        registry_signatures,
        registry_published_at,
        os,
        cpu,
        libc,
        node_engine,
        optional,
        dependencies,
        dependency_targets,
        alias_dependencies,
        peers,
        peer_edges,
        peer_targets,
        tarball,
    } = package;
    let mut hasher = Sha256::new();
    if lockfile_version >= LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
        hasher.update(b"lpm-workspace-package-v3\0");
    } else if lockfile_version >= LOCKFILE_VERSION_WITH_LOCAL_MANIFEST_FINGERPRINTS {
        hasher.update(b"lpm-workspace-package-v2\0");
    } else {
        hasher.update(b"lpm-workspace-package-v1\0");
    }
    hash_length_prefixed(&mut hasher, name.as_bytes());
    hash_length_prefixed(&mut hasher, version.as_bytes());
    hash_optional_string(&mut hasher, source.as_deref());
    if lockfile_version >= LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
        match instance_id {
            Some(instance_id) => {
                hasher.update([1]);
                hasher.update(instance_id.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hash_optional_string(&mut hasher, integrity.as_deref());
    if lockfile_version >= LOCKFILE_VERSION_WITH_LOCAL_MANIFEST_FINGERPRINTS {
        hash_optional_string(&mut hasher, manifest_fingerprint.as_deref());
    }
    hasher.update((registry_signatures.len() as u64).to_le_bytes());
    for signature in registry_signatures {
        hash_optional_string(&mut hasher, signature.keyid.as_deref());
        hash_optional_string(&mut hasher, signature.sig.as_deref());
    }
    hash_optional_string(&mut hasher, registry_published_at.as_deref());
    hash_strings(&mut hasher, os);
    hash_strings(&mut hasher, cpu);
    hash_strings(&mut hasher, libc);
    hash_optional_string(&mut hasher, node_engine.as_deref());
    hasher.update([u8::from(*optional)]);
    hash_strings(&mut hasher, dependencies);
    if lockfile_version >= LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
        hasher.update((dependency_targets.len() as u64).to_le_bytes());
        for (local_name, target) in dependency_targets {
            hash_length_prefixed(&mut hasher, local_name.as_bytes());
            hasher.update(target.as_bytes());
        }
    }
    hasher.update((alias_dependencies.len() as u64).to_le_bytes());
    for alias in alias_dependencies {
        hash_length_prefixed(&mut hasher, alias[0].as_bytes());
        hash_length_prefixed(&mut hasher, alias[1].as_bytes());
    }
    hash_strings(&mut hasher, peers);
    if lockfile_version >= LOCKFILE_VERSION_WITH_STRUCTURED_PEERS {
        hasher.update((peer_edges.len() as u64).to_le_bytes());
        for peer in peer_edges {
            hash_length_prefixed(&mut hasher, peer.local_name.as_bytes());
            hash_length_prefixed(&mut hasher, peer.target_name.as_bytes());
            hash_length_prefixed(&mut hasher, peer.target_version.as_bytes());
            hash_optional_string(&mut hasher, peer.target_wrapper_id.as_deref());
        }
    }
    if lockfile_version >= LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
        hasher.update((peer_targets.len() as u64).to_le_bytes());
        for (local_name, target) in peer_targets {
            hash_length_prefixed(&mut hasher, local_name.as_bytes());
            hasher.update(target.as_bytes());
        }
    }
    hash_optional_string(&mut hasher, tarball.as_deref());
    let digest = hasher.finalize();
    let mut id = String::with_capacity(7 + digest.len() * 2);
    id.push_str("sha256:");
    id.push_str(&hex::encode(digest));
    id
}

#[cfg(test)]
thread_local! {
    static WORKSPACE_PACKAGE_ID_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_workspace_package_id_call_count() {
    WORKSPACE_PACKAGE_ID_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn workspace_package_id_call_count() -> usize {
    WORKSPACE_PACKAGE_ID_CALLS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn workspace_package_id_for_test(
    package: &LockedPackage,
    lockfile_version: u32,
) -> String {
    workspace_package_id_for_version(package, lockfile_version)
}

/// One lockfile-recorded catalog resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CatalogSnapshotEntry {
    /// Range/specifier stored in the catalog entry at resolve time.
    pub specifier: String,
    /// Concrete package version selected by the resolver.
    pub version: String,
    /// Consumer-side catalog protocol reference, e.g. `catalog:` or `catalog:testing`.
    pub reference: String,
}

/// One npm registry package signature persisted from a package's
/// `dist.signatures` metadata.
///
/// Fields are optional for serde tolerance, matching the registry wire
/// type. Signature verification treats partial entries as unusable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LockedRegistrySignature {
    #[serde(default)]
    pub keyid: Option<String>,
    #[serde(default)]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedProvenance {
    pub snapshot: lpm_common::ProvenanceSnapshot,
    #[serde(rename = "subject-name")]
    pub subject_name: String,
    #[serde(rename = "subject-sha512")]
    pub subject_sha512: String,
    #[serde(rename = "integrated-time-secs")]
    pub integrated_time_secs: u64,
    #[serde(rename = "log-id")]
    pub log_id: String,
    #[serde(rename = "log-index")]
    pub log_index: i64,
    /// Deterministic digest of the verified, artifact-bound bundle evidence.
    /// The serialized key retains its original name for lockfile compatibility.
    #[serde(rename = "bundle-sha256")]
    pub bundle_sha256: String,
}

/// The full lockfile structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lockfile {
    pub metadata: LockfileMetadata,
    /// Manifest/importer snapshots used by frozen installs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub importers: ImporterSnapshots,
    /// Patch files that change installed package bytes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub patches: LockfilePatches,
    /// Catalog protocol resolutions used by direct dependencies in this lockfile.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub catalogs: CatalogSnapshots,
    /// Cryptographically verified provenance evidence, keyed by the
    /// package's `(name, version, source_id)` identity.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance: BTreeMap<String, LockedProvenance>,
    /// Resolved packages, sorted by name for deterministic output.
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
    /// Content-addressed union of workspace importer package rows.
    #[serde(
        default,
        rename = "workspace-packages",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub workspace_packages: BTreeMap<String, LockedPackage>,
    /// Root-level npm-alias edges preserved so warm installs can match
    /// the original `node_modules/<local>/` layout without re-resolving.
    /// Shape: `local_name → target_canonical_name`. Empty when no root
    /// dep uses `npm:<target>@<range>` syntax; skipped in serialized
    /// output when empty (backwards-compatible with older lockfiles).
    #[serde(
        default,
        rename = "root-aliases",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub root_aliases: std::collections::BTreeMap<String, String>,
    /// Exact root-link selections captured from resolver output.
    #[serde(
        default,
        rename = "root-resolutions",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub root_resolutions: RootResolutions,
    /// Canonical names of packages the resolver auto-installed at root
    /// scope to satisfy unmet `peerDependencies` (eager peer
    /// auto-install).
    /// Persisted so the lockfile fast path on warm installs reproduces
    /// the same top-level `node_modules/<peer>/` symlinks the
    /// fresh-resolve install produced.
    ///
    /// **Why this is a separate top-level field, not folded into
    /// `packages` somehow:** `packages` is keyed on `(name, version,
    /// source_id)`. An ambient peer install IS already in `packages`
    /// (it was extracted into the v2 store and resolved like any
    /// other dep). What `packages` does NOT carry is the
    /// "this is a top-level link target even though it's not in
    /// `pkg.dependencies`" signal. That signal is symmetric with
    /// [`Self::root_aliases`] — it's project-side install-orchestration
    /// metadata, not per-package state. Hence sibling field.
    ///
    /// Empty + skipped from serialization on the common no-auto-
    /// install path (project's `pkg.dependencies` already covers all
    /// declared peers).
    #[serde(
        default,
        rename = "ambient-peer-installs",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ambient_peer_installs: Vec<String>,
}

/// A lockfile whose workspace package addresses and importer projections have
/// passed the complete reader-side validation gate.
///
/// The wrapper exposes immutable access and validation-preserving union
/// operations so trusted importer projections can avoid re-hashing package
/// rows that were already checked while loading the lockfile.
#[derive(Debug)]
pub struct ValidatedLockfile(pub(crate) Lockfile);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockfileMetadata {
    #[serde(rename = "lockfile-version")]
    pub lockfile_version: u32,
    /// Which resolver produced this lockfile.
    #[serde(default, rename = "resolved-with")]
    pub resolved_with: Option<String>,
    /// True when a default-hoisted install detected peer conflicts and
    /// materialized the project with the isolated linker instead.
    ///
    /// This is install-orchestration metadata, not resolver identity:
    /// warm installs need it before fresh resolution so they can keep
    /// using the peer-preserving layout while the manifest and lockfile
    /// are unchanged.
    #[serde(
        default,
        rename = "auto-isolated-peer-conflicts",
        skip_serializing_if = "is_false"
    )]
    pub auto_isolated_peer_conflicts: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A single resolved package in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LockedPackage {
    /// Exact identity of this row in the resolved graph.
    #[serde(
        default,
        rename = "instance-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_id: Option<lpm_common::PackageInstanceId>,
    /// Package name (e.g., `@lpm.dev/neo.highlight` or `react`).
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Source registry (e.g., `registry+https://lpm.dev` or `registry+https://registry.npmjs.org`).
    #[serde(default)]
    pub source: Option<String>,
    /// SRI integrity hash (sha512-...). Populated when registry provides it.
    #[serde(default)]
    pub integrity: Option<String>,
    /// Semantic manifest digest for mutable directory/link sources.
    #[serde(
        default,
        rename = "manifest-fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub manifest_fingerprint: Option<String>,
    /// Registry package signatures from npm-compatible `dist.signatures`.
    #[serde(
        default,
        rename = "registry-signatures",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub registry_signatures: Vec<LockedRegistrySignature>,
    /// Version publish timestamp used when checking registry signing-key expiry.
    #[serde(
        default,
        rename = "registry-published-at",
        skip_serializing_if = "Option::is_none"
    )]
    pub registry_published_at: Option<String>,
    /// OS restrictions from the package version's manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os: Vec<String>,
    /// CPU restrictions from the package version's manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpu: Vec<String>,
    /// libc restrictions from the package version's manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libc: Vec<String>,
    /// Node.js compatibility range from the package version's manifest.
    #[serde(
        default,
        rename = "node-engine",
        skip_serializing_if = "Option::is_none"
    )]
    pub node_engine: Option<String>,
    /// True when the package is only reachable through optional
    /// dependency edges.
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
    /// Direct dependencies of this package: `<local_name>@<version>`
    /// where `local_name` is what this package uses in its own
    /// `dependencies` map. For non-aliased deps the local name equals
    /// the dep's canonical registry name; for npm-alias edges the
    /// local name diverges from the target and the target is recorded
    /// in [`Self::alias_dependencies`] below.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    /// Exact target instance for each dependency-local name.
    #[serde(
        default,
        rename = "dependency-targets",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub dependency_targets: BTreeMap<String, lpm_common::PackageInstanceId>,
    /// Npm-alias dep edges. Each entry is `[local_name,
    /// target_canonical_name]`. The matching `<local_name>@<version>`
    /// entry in `dependencies` keys the resolved version; this map
    /// keys the alias TARGET for lookup of the
    /// `.lpm/<target>@<version>/` store path. Empty and skipped from
    /// serialization for the common non-aliased case.
    #[serde(
        default,
        rename = "alias-dependencies",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub alias_dependencies: Vec<[String; 2]>,
    /// Resolved peer dependencies for this
    /// package. Each entry is `<peer_name>@<resolved_version>` (same
    /// format as [`Self::dependencies`]) and represents one entry
    /// from the package's `peerDependencies` map intersected with the
    /// install set's resolved versions.
    ///
    /// **Why this is load-bearing for warm-install correctness:** the
    /// v2 store's [`GraphKey`] derivation hashes peer pinning into
    /// the link-entry identity (`lpm-store::v2::graph_key.rs`). Two
    /// projects with the same dep tree but different peer ranges
    /// produce DISTINCT `links/<key>/` entries, and the v2 linker
    /// reproduces those keys deterministically per install. If the
    /// lockfile fast path forgets the peer pinning and reconstructs
    /// the package with empty peers, the warm install computes a
    /// different graph key than the cold install, materializes a
    /// fresh link entry, and silently breaks peer-isolation
    /// invariants (worse: a sibling project sharing the dep tree but
    /// not the peer pinning could now share the link entry).
    ///
    /// Sorted by peer name for deterministic lockfile output, then
    /// skipped from serialization for packages without peer
    /// dependencies (the common case — keeps older lockfiles
    /// byte-identical).
    ///
    /// [`GraphKey`]: <internal v2 store identity type — see lpm-store crate>
    #[serde(default, rename = "peers", skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<String>,
    /// Exact peer identities. Legacy `peers` entries remain readable for
    /// pre-v12 lockfiles; current writers use this field exclusively.
    #[serde(default, rename = "peer-edges", skip_serializing_if = "Vec::is_empty")]
    pub peer_edges: Vec<lpm_common::PeerEdge>,
    /// Exact target instance for each peer-local name.
    #[serde(
        default,
        rename = "peer-targets",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub peer_targets: BTreeMap<String, lpm_common::PackageInstanceId>,
    /// Tarball URL as returned by the registry at resolve time (e.g.,
    /// `https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`).
    /// Populated by the writer from `InstallPackage.tarball_url`;
    /// consumed by `try_lockfile_fast_path` to skip the per-package
    /// metadata round-trip on warm installs (gated behind
    /// `evaluate_cached_url` for scheme/shape/origin safety).
    /// `None` on old lockfiles — callers fall back to on-demand lookup.
    ///
    /// **Disjointness with `Source::Tarball`:** this field is a
    /// *dist-URL hint cache* valid only for `Source::Registry`
    /// packages. For non-Registry sources (`Source::Tarball`,
    /// `Source::Git`, etc.) the URL is part of source identity (lives
    /// inside the source variant). Pairing a non-Registry source with
    /// this hint is rejected by [`Lockfile::from_toml`] — see
    /// [`LockedPackage::tarball_field_hint_is_consistent`] and
    /// [`LockfileError::InvalidTarballHint`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tarball: Option<String>,
}

impl LockedPackage {
    /// Parse the [`Self::source`] string into a typed [`Source`].
    ///
    /// Returns `None` when [`Self::source`] is `None`. Returns
    /// `Some(Err(_))` for malformed source strings — the legacy
    /// [`is_safe_source`] would also reject the same input.
    ///
    /// This is an *additive* accessor — the underlying `source: Option<String>`
    /// field is preserved for backwards compatibility; consumers
    /// migrate to typed access site-by-site.
    pub fn source_kind(&self) -> Option<Result<Source, SourceParseError>> {
        self.source.as_deref().map(Source::parse)
    }

    /// Three-tuple identity for cross-source collision avoidance.
    /// See [`PackageKey`].
    ///
    /// The lockfile's bookkeeping (sort order, lookup, install
    /// pipeline coordination) keys on this triple to prevent a
    /// registry package and a tarball-URL package with the same
    /// `(name, version)` from clobbering each other's state.
    pub fn package_key(&self) -> PackageKey {
        #[cfg(test)]
        PACKAGE_KEY_CALLS.with(|calls| calls.set(calls.get() + 1));
        let source_id = match self.source_kind() {
            Some(Ok(s)) => s.source_id(),
            _ => PackageKey::UNKNOWN_SOURCE_ID.to_string(),
        };
        PackageKey::new(self.name.clone(), self.version.clone(), source_id)
    }

    /// Whether the `tarball` field-hint is consistent with the parsed
    /// source kind.
    ///
    /// The `tarball` field is a dist-URL hint populated when
    /// resolving a Registry package — it lets warm installs skip a
    /// metadata round-trip. For non-Registry sources the URL is
    /// already part of the source identity (e.g. `Source::Tarball
    /// { url }`); a `tarball` hint on those is ill-formed and likely
    /// a sign of conflation between the identity slot and the
    /// optimization slot.
    ///
    /// Returns `true` when consistent:
    /// - source is `None`, OR
    /// - source is `Source::Registry` (any hint is valid), OR
    /// - tarball is `None` / empty (no hint to conflict).
    ///
    /// Returns `false` only for the conflation case: a non-Registry
    /// source kind paired with a non-empty `tarball` hint.
    ///
    /// This is a documented invariant enforced at both writer and
    /// reader: invalid lockfile shapes drop to error, not silent
    /// acceptance (manifest-as-truth).
    pub fn tarball_field_hint_is_consistent(&self) -> bool {
        let Some(hint) = self.tarball.as_deref() else {
            return true;
        };
        if hint.is_empty() {
            return true;
        }
        match self.source_kind() {
            None | Some(Err(_)) => true,
            Some(Ok(Source::Registry { .. })) => true,
            Some(Ok(_)) => false,
        }
    }

    /// Returns a safe source identity if this is a `@lpm.dev/*`
    /// package pointing at a non-lpm.dev origin. Scoped names must always resolve
    /// through the LPM origin (or `http://localhost` for dev),
    /// regardless of what other registries the client is configured to
    /// talk to.
    pub fn lpm_scope_origin_mismatch(&self) -> Option<String> {
        if !self.name.starts_with("@lpm.dev/") {
            return None;
        }
        let source = self.source.as_deref()?;
        let Ok(Source::Registry { url }) = Source::parse(source) else {
            return None;
        };
        if is_lpm_origin(&url) {
            None
        } else {
            Some(crate::safe_source_identity(source))
        }
    }

    pub fn git_metadata_error(&self) -> Option<&'static str> {
        match self.source_kind() {
            Some(Ok(Source::Git { url })) => {
                if !is_safe_github_source(&url) {
                    return Some("git source is not a pinned public GitHub repository");
                }
                if self.integrity.as_deref().is_none_or(str::is_empty) {
                    return Some("git source is missing archive integrity");
                }
                None
            }
            Some(Ok(_)) | None => None,
            Some(Err(_)) => None,
        }
    }
}

#[cfg(test)]
thread_local! {
    static PACKAGE_KEY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_package_key_call_count() {
    PACKAGE_KEY_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn package_key_call_count() -> usize {
    PACKAGE_KEY_CALLS.with(std::cell::Cell::get)
}

/// `https://lpm.dev` (+ subdomains) and `http://localhost` /
/// `127.0.0.1` for local dev. Strict so `https://lpm.dev.evil.com`
/// does NOT match.
fn is_lpm_origin(url_str: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url_str) else {
        return false;
    };
    let scheme = parsed.scheme();
    let host = match parsed.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => return false,
    };

    if scheme == "https" {
        return host == "lpm.dev" || host.ends_with(".lpm.dev");
    }
    if scheme == "http" {
        return host == "localhost" || host == "127.0.0.1";
    }
    false
}

fn validate_package_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name is empty".to_string());
    }
    if name.len() > 214 {
        return Err(format!("name is {} bytes; maximum is 214", name.len()));
    }
    if name.chars().any(|character| {
        character.is_control()
            || matches!(character, '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*')
    }) {
        return Err("name contains a control character or unsafe path character".to_string());
    }

    let mut components = name.split('/');
    if name.starts_with('@') {
        let scope = components.next().unwrap_or_default();
        let package = components.next().unwrap_or_default();
        if scope.len() == 1 || package.is_empty() || components.next().is_some() {
            return Err("scoped name must have exactly the form @scope/package".to_string());
        }
        validate_package_name_component(scope)?;
        validate_package_name_component(package)?;
    } else {
        if components.clone().count() != 1 {
            return Err("unscoped name must contain exactly one path component".to_string());
        }
        validate_package_name_component(name)?;
    }
    Ok(())
}

fn validate_package_name_component(component: &str) -> Result<(), String> {
    if component.is_empty() || matches!(component, "." | "..") {
        return Err("name contains an empty, `.` or `..` path component".to_string());
    }
    if component.ends_with([' ', '.']) {
        return Err("name component cannot end with a space or dot".to_string());
    }
    let device_stem = component
        .trim_start_matches('@')
        .split('.')
        .next()
        .unwrap_or_default();
    let upper = device_stem.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
    {
        return Err("name contains a reserved Windows path component".to_string());
    }
    Ok(())
}

/// Default resolver-name string baked into [`Lockfile::new`]. Matches
/// the current install default (greedy-fusion). Production write sites
/// should pass an explicit name via [`Lockfile::new_with_resolver`] —
/// this constant is the fallback for tests and library consumers that
/// don't care which resolver "produced" the in-memory lockfile.
pub const DEFAULT_RESOLVED_WITH: &str = "greedy-fusion";

impl Lockfile {
    /// Create a new empty lockfile, tagged with the default resolver
    /// name. Production install sites should call
    /// [`Lockfile::new_with_resolver`] instead so the on-disk
    /// `resolved-with` field reflects which engine actually ran
    /// (matters with `LPM_RESOLVER=pubgrub` or `LPM_GREEDY_FUSION=0`).
    pub fn new() -> Self {
        Self::new_with_resolver(DEFAULT_RESOLVED_WITH)
    }

    /// Create a new empty lockfile that records `resolver` as the
    /// engine that produced it. The dispatch at `install.rs` hands
    /// the actually-taken resolver arm name through here so the
    /// on-disk field reflects which engine ran.
    ///
    /// `resolver` is purely informational. Reading it has never been
    /// part of the lockfile contract; consumers must not branch on it.
    pub fn new_with_resolver(resolver: &str) -> Self {
        Lockfile {
            metadata: LockfileMetadata {
                lockfile_version: LOCKFILE_VERSION,
                resolved_with: Some(resolver.to_string()),
                auto_isolated_peer_conflicts: false,
            },
            importers: ImporterSnapshots::new(),
            patches: LockfilePatches::new(),
            catalogs: CatalogSnapshots::new(),
            provenance: BTreeMap::new(),
            packages: Vec::new(),
            workspace_packages: BTreeMap::new(),
            root_aliases: BTreeMap::new(),
            root_resolutions: RootResolutions::new(),
            // Populated by `install.rs` from
            // `ResolveResult.ambient_peer_installs` on cold-resolve
            // lockfile writes; empty on warm/lockfile-fast-path
            // returns from `Lockfile::read_fast` until the writer
            // updates an existing lockfile.
            ambient_peer_installs: Vec::new(),
        }
    }

    /// Add a resolved package. Maintains sorted order by
    /// artifact identity and then exact instance ID. Distinct graph instances
    /// of one artifact occupy separate rows.
    pub fn add_package(&mut self, pkg: LockedPackage) {
        let key = pkg.package_key();
        let instance_id = pkg.instance_id;
        match self.packages.binary_search_by(|p| {
            let other = p.package_key();
            other
                .name
                .cmp(&key.name)
                .then_with(|| other.version.cmp(&key.version))
                .then_with(|| other.source_id.cmp(&key.source_id))
                .then_with(|| p.instance_id.cmp(&instance_id))
        }) {
            Ok(pos) => self.packages[pos] = pkg,
            Err(pos) => self.packages.insert(pos, pkg),
        }
    }

    /// Add one standalone importer graph to a workspace union lockfile.
    pub fn absorb_importer(
        &mut self,
        importer: &str,
        mut standalone: Lockfile,
    ) -> Result<(), LockfileError> {
        validate_importer_path(importer)?;
        let union_version = self
            .metadata
            .lockfile_version
            .min(standalone.metadata.lockfile_version)
            .clamp(
                LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS,
                LOCKFILE_VERSION,
            );
        let mut existing_packages = self.packages.iter().chain(self.workspace_packages.values());
        let existing_has_legacy_peers = existing_packages
            .clone()
            .any(|package| !package.peers.is_empty());
        let existing_has_structured_peers =
            existing_packages.any(|package| !package.peer_edges.is_empty());
        let incoming_has_legacy_peers = standalone
            .packages
            .iter()
            .any(|package| !package.peers.is_empty());
        let incoming_has_structured_peers = standalone
            .packages
            .iter()
            .any(|package| !package.peer_edges.is_empty());
        let mixes_incompatible_peer_schemas =
            if union_version >= LOCKFILE_VERSION_WITH_STRUCTURED_PEERS {
                existing_has_legacy_peers || incoming_has_legacy_peers
            } else {
                existing_has_structured_peers || incoming_has_structured_peers
            };
        if mixes_incompatible_peer_schemas {
            return Err(LockfileError::Serialize(format!(
                "workspace importer {importer:?} cannot be combined without losing exact peer identity; fresh resolution is required"
            )));
        }
        if union_version < LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
            let mut artifact_identities = HashSet::with_capacity(standalone.packages.len());
            if let Some(package) = standalone
                .packages
                .iter()
                .find(|package| !artifact_identities.insert(package.package_key()))
            {
                return Err(LockfileError::Serialize(format!(
                    "workspace importer {importer:?} contains an ambiguous package identity {:?}",
                    package.package_key().lockfile_id()
                )));
            }
        }
        standalone.metadata.lockfile_version = union_version;
        for package in &mut standalone.packages {
            Self::downgrade_package_to_version(package, union_version);
        }
        let mut snapshot = standalone
            .importers
            .get(".")
            .cloned()
            .unwrap_or_default()
            .without_projection();
        snapshot.root_aliases = standalone.root_aliases;
        snapshot.root_resolutions = standalone.root_resolutions;
        snapshot.ambient_peer_installs = standalone.ambient_peer_installs;
        snapshot.patches = standalone.patches;
        snapshot.catalog_resolutions = standalone.catalogs;
        snapshot.provenance = standalone.provenance;
        snapshot.auto_isolated_peer_conflicts = standalone.metadata.auto_isolated_peer_conflicts;
        if union_version < LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
            for root in snapshot.root_resolutions.values_mut() {
                root.instance_id = None;
            }
        }

        let mut addressed_packages = Vec::with_capacity(standalone.packages.len());
        for package in standalone.packages {
            let key = package.package_key();
            let id = workspace_package_id_for_version(&package, union_version);
            addressed_packages.push((key, id, package));
        }
        addressed_packages.sort_unstable_by(
            |(left, _, left_package), (right, _, right_package)| {
                left.name
                    .cmp(&right.name)
                    .then_with(|| left.version.cmp(&right.version))
                    .then_with(|| left.source_id.cmp(&right.source_id))
                    .then_with(|| left_package.instance_id.cmp(&right_package.instance_id))
            },
        );
        addressed_packages.dedup_by(|right, left| right.1 == left.1);

        if union_version < self.metadata.lockfile_version {
            let (mut workspace_packages, mut importers) =
                self.workspace_union_remapped_to_version(union_version)?;
            Self::insert_workspace_importer(
                &mut workspace_packages,
                &mut importers,
                importer,
                snapshot,
                addressed_packages,
            )?;
            self.workspace_packages = workspace_packages;
            self.importers = importers;
        } else {
            Self::insert_workspace_importer(
                &mut self.workspace_packages,
                &mut self.importers,
                importer,
                snapshot,
                addressed_packages,
            )?;
        }
        self.metadata.lockfile_version = union_version;
        Ok(())
    }

    fn insert_workspace_importer(
        workspace_packages: &mut BTreeMap<String, LockedPackage>,
        importers: &mut BTreeMap<String, ImporterSnapshot>,
        importer: &str,
        mut snapshot: ImporterSnapshot,
        addressed_packages: Vec<(PackageKey, String, LockedPackage)>,
    ) -> Result<(), LockfileError> {
        for (_, id, package) in &addressed_packages {
            if let Some(existing) = workspace_packages.get(id)
                && existing != package
            {
                return Err(LockfileError::Serialize(format!(
                    "workspace package id collision for {id}"
                )));
            }
        }

        let mut ids = Vec::with_capacity(addressed_packages.len());
        for (_, id, package) in addressed_packages {
            if !workspace_packages.contains_key(&id) {
                workspace_packages.insert(id.clone(), package);
            }
            ids.push(id);
        }
        snapshot.locked_packages = ids;
        importers.insert(importer.to_string(), snapshot);
        Ok(())
    }

    fn workspace_union_remapped_to_version(
        &self,
        lockfile_version: u32,
    ) -> Result<WorkspaceUnionRows, LockfileError> {
        let mut remapped_ids = HashMap::with_capacity(self.workspace_packages.len());
        let mut downgraded = BTreeMap::new();
        for (old_id, existing_package) in &self.workspace_packages {
            let mut package = existing_package.clone();
            Self::downgrade_package_to_version(&mut package, lockfile_version);
            let new_id = workspace_package_id_for_version(&package, lockfile_version);
            if let Some(existing) = downgraded.get(&new_id)
                && existing != &package
            {
                return Err(LockfileError::Serialize(format!(
                    "workspace package id collision for {new_id}"
                )));
            }
            remapped_ids.insert(old_id.clone(), new_id.clone());
            downgraded.insert(new_id, package);
        }
        let mut remapped_importers = self.importers.clone();
        for snapshot in remapped_importers.values_mut() {
            let mut remapped_snapshot_ids = HashSet::with_capacity(snapshot.locked_packages.len());
            for id in &mut snapshot.locked_packages {
                *id = remapped_ids.get(id.as_str()).cloned().ok_or_else(|| {
                    LockfileError::Serialize(format!(
                        "workspace importer references missing package id {id:?}"
                    ))
                })?;
                if !remapped_snapshot_ids.insert(id.clone()) {
                    return Err(LockfileError::Serialize(
                        "workspace importer contains package instances that cannot be represented by the downgraded lockfile schema"
                            .to_string(),
                    ));
                }
            }
            if lockfile_version < LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
                for root in snapshot.root_resolutions.values_mut() {
                    root.instance_id = None;
                }
            }
        }
        Ok((downgraded, remapped_importers))
    }

    fn downgrade_package_to_version(package: &mut LockedPackage, lockfile_version: u32) {
        if lockfile_version < LOCKFILE_VERSION_WITH_LOCAL_MANIFEST_FINGERPRINTS {
            package.manifest_fingerprint = None;
        }
        if lockfile_version < LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
            package.instance_id = None;
            package.dependency_targets.clear();
            package.peer_targets.clear();
        }
    }

    /// Replace one importer projection and prune union rows no longer
    /// reachable from any importer.
    pub fn replace_importer(
        &mut self,
        importer: &str,
        standalone: Lockfile,
    ) -> Result<(), LockfileError> {
        let is_union = !self.workspace_packages.is_empty()
            || self.importers.keys().any(|key| key != ".")
            || importer != ".";
        if !is_union {
            *self = standalone;
            return Ok(());
        }

        let mut updated = self.clone();
        updated.replace_workspace_importer_in_place(importer, standalone)?;
        *self = updated;
        Ok(())
    }

    fn replace_workspace_importer_in_place(
        &mut self,
        importer: &str,
        standalone: Lockfile,
    ) -> Result<(), LockfileError> {
        validate_importer_path(importer)?;
        self.importers.remove(importer);
        self.prune_unreachable_workspace_packages();
        self.absorb_importer(importer, standalone)
    }

    fn retain_workspace_importers(&mut self, retained_importers: &BTreeSet<String>) {
        self.importers
            .retain(|importer, _| retained_importers.contains(importer));
        self.prune_unreachable_workspace_packages();
    }

    fn prune_unreachable_workspace_packages(&mut self) {
        let referenced = self
            .importers
            .values()
            .flat_map(|snapshot| snapshot.locked_packages.iter().map(String::as_str))
            .collect::<HashSet<_>>();
        self.workspace_packages
            .retain(|id, _| referenced.contains(id.as_str()));
    }

    /// Materialize the standalone lockfile view consumed by one importer.
    pub fn project_importer(&self, importer: &str) -> Result<Self, LockfileError> {
        self.project_importer_impl(importer, true)
    }

    pub(crate) fn project_root_importer(&self) -> Result<Self, LockfileError> {
        if self.metadata.lockfile_version < LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS
            || self.workspace_packages.is_empty() && self.importers.keys().all(|key| key == ".")
            || self.importers.contains_key(".")
        {
            return self.project_importer(".");
        }
        Ok(self.project_importer_metadata_from_snapshot(&ImporterSnapshot::default()))
    }

    fn project_validated_importer(&self, importer: &str) -> Result<Self, LockfileError> {
        self.project_importer_impl(importer, false)
    }

    fn project_importer_impl(
        &self,
        importer: &str,
        validate_package_addresses: bool,
    ) -> Result<Self, LockfileError> {
        if self.metadata.lockfile_version < LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS
            || self.workspace_packages.is_empty() && self.importers.keys().all(|key| key == ".")
        {
            if importer == "." {
                return Ok(self.clone());
            }
            return Err(LockfileError::Deserialize(format!(
                "lockfile has no workspace importer {importer:?}"
            )));
        }

        validate_importer_path(importer)?;
        let snapshot = self.importers.get(importer).ok_or_else(|| {
            LockfileError::Deserialize(format!("lockfile has no workspace importer {importer:?}"))
        })?;
        let mut projected = self.project_importer_metadata_from_snapshot(snapshot);

        let mut packages = Vec::with_capacity(snapshot.locked_packages.len());
        if !validate_package_addresses {
            for id in &snapshot.locked_packages {
                let package = self.workspace_packages.get(id).ok_or_else(|| {
                    LockfileError::Deserialize(format!(
                        "workspace importer {importer:?} references missing package id {id:?}"
                    ))
                })?;
                packages.push(package.clone());
            }
            projected.packages = packages;
            return Ok(projected);
        }

        let mut keyed_packages = Vec::with_capacity(snapshot.locked_packages.len());
        for id in &snapshot.locked_packages {
            let package = self.workspace_packages.get(id).ok_or_else(|| {
                LockfileError::Deserialize(format!(
                    "workspace importer {importer:?} references missing package id {id:?}"
                ))
            })?;
            if workspace_package_id_for_version(package, self.metadata.lockfile_version) != *id {
                return Err(LockfileError::Deserialize(format!(
                    "workspace package {id:?} does not match its content address"
                )));
            }
            keyed_packages.push((package.package_key(), package.clone()));
        }
        keyed_packages.sort_unstable_by(|(left, left_package), (right, right_package)| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.version.cmp(&right.version))
                .then_with(|| left.source_id.cmp(&right.source_id))
                .then_with(|| left_package.instance_id.cmp(&right_package.instance_id))
        });
        if self.metadata.lockfile_version < LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
            && keyed_packages.windows(2).any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(LockfileError::Deserialize(format!(
                "workspace importer {importer:?} contains an ambiguous package identity"
            )));
        }
        packages.extend(keyed_packages.into_iter().map(|(_, package)| package));
        projected.packages = packages;
        projected.validate_peer_edge_targets()?;
        projected.validate_instance_graph()?;
        Ok(projected)
    }

    fn project_validated_importer_metadata(&self, importer: &str) -> Result<Self, LockfileError> {
        if self.metadata.lockfile_version < LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS
            || self.workspace_packages.is_empty() && self.importers.keys().all(|key| key == ".")
        {
            if importer == "." {
                let mut projected = self.clone();
                projected.packages.clear();
                return Ok(projected);
            }
            return Err(LockfileError::Deserialize(format!(
                "lockfile has no workspace importer {importer:?}"
            )));
        }

        validate_importer_path(importer)?;
        let snapshot = self.importers.get(importer).ok_or_else(|| {
            LockfileError::Deserialize(format!("lockfile has no workspace importer {importer:?}"))
        })?;
        Ok(self.project_importer_metadata_from_snapshot(snapshot))
    }

    fn project_importer_metadata_from_snapshot(&self, snapshot: &ImporterSnapshot) -> Self {
        let mut projected = Lockfile::new_with_resolver(
            self.metadata
                .resolved_with
                .as_deref()
                .unwrap_or(DEFAULT_RESOLVED_WITH),
        );
        projected.metadata.lockfile_version = self.metadata.lockfile_version;
        projected.metadata.auto_isolated_peer_conflicts = snapshot.auto_isolated_peer_conflicts;
        projected.root_aliases = snapshot.root_aliases.clone();
        projected.root_resolutions = snapshot.root_resolutions.clone();
        projected.ambient_peer_installs = snapshot.ambient_peer_installs.clone();
        projected.patches = snapshot.patches.clone();
        projected.catalogs = snapshot.catalog_resolutions.clone();
        projected.provenance = snapshot.provenance.clone();
        projected
            .importers
            .insert(".".to_string(), snapshot.without_projection());
        projected
    }

    fn validated_importer_packages(
        &self,
        importer: &str,
    ) -> Result<Vec<&LockedPackage>, LockfileError> {
        if self.metadata.lockfile_version < LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS
            || self.workspace_packages.is_empty() && self.importers.keys().all(|key| key == ".")
        {
            if importer == "." {
                return Ok(self.packages.iter().collect());
            }
            return Err(LockfileError::Deserialize(format!(
                "lockfile has no workspace importer {importer:?}"
            )));
        }

        validate_importer_path(importer)?;
        let snapshot = self.importers.get(importer).ok_or_else(|| {
            LockfileError::Deserialize(format!("lockfile has no workspace importer {importer:?}"))
        })?;
        let mut packages = Vec::with_capacity(snapshot.locked_packages.len());
        for id in &snapshot.locked_packages {
            packages.push(self.workspace_packages.get(id).ok_or_else(|| {
                LockfileError::Deserialize(format!(
                    "workspace importer {importer:?} references missing package id {id:?}"
                ))
            })?);
        }
        Ok(packages)
    }

    pub(crate) fn validate_workspace_projections(&self) -> Result<(), LockfileError> {
        if self.metadata.lockfile_version < LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS {
            if !self.workspace_packages.is_empty() {
                return Err(LockfileError::Deserialize(format!(
                    "workspace package projections require lockfile version {}",
                    LOCKFILE_VERSION_WITH_WORKSPACE_PROJECTIONS
                )));
            }
            return Ok(());
        }

        let mut validated_packages = HashMap::with_capacity(self.workspace_packages.len());
        for (id, package) in &self.workspace_packages {
            if workspace_package_id_for_version(package, self.metadata.lockfile_version) != *id {
                return Err(LockfileError::Deserialize(format!(
                    "workspace package {id:?} does not match its content address"
                )));
            }
            validated_packages.insert(id.as_str(), (package.package_key(), package.instance_id));
        }

        let mut referenced = HashSet::with_capacity(self.workspace_packages.len());
        for (importer, snapshot) in &self.importers {
            validate_importer_path(importer)?;
            let mut previous: Option<(&str, &(PackageKey, Option<lpm_common::PackageInstanceId>))> =
                None;
            let mut importer_packages = Vec::with_capacity(snapshot.locked_packages.len());
            for id in &snapshot.locked_packages {
                let package_identity = validated_packages.get(id.as_str()).ok_or_else(|| {
                    LockfileError::Deserialize(format!(
                        "workspace importer {importer:?} references missing package id {id:?}"
                    ))
                })?;
                if let Some((previous_id, previous_key)) = previous {
                    if previous_id == id {
                        return Err(LockfileError::Deserialize(format!(
                            "workspace importer {importer:?} contains duplicate package id {id:?}"
                        )));
                    }
                    let ordering = previous_key
                        .0
                        .name
                        .cmp(&package_identity.0.name)
                        .then_with(|| previous_key.0.version.cmp(&package_identity.0.version))
                        .then_with(|| previous_key.0.source_id.cmp(&package_identity.0.source_id))
                        .then_with(|| previous_key.1.cmp(&package_identity.1));
                    if ordering.is_eq()
                        || self.metadata.lockfile_version < LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
                            && previous_key.0 == package_identity.0
                    {
                        return Err(LockfileError::Deserialize(format!(
                            "workspace importer {importer:?} contains an ambiguous package identity"
                        )));
                    }
                    if ordering.is_gt() {
                        return Err(LockfileError::Deserialize(format!(
                            "workspace importer {importer:?} package ids are not in package identity order"
                        )));
                    }
                }
                previous = Some((id, package_identity));
                referenced.insert(id.as_str());
                importer_packages.push(&self.workspace_packages[id]);
            }
            Self::validate_peer_edge_targets_in_packages(
                Some(importer),
                importer_packages.iter().copied(),
            )?;
            if self.metadata.lockfile_version >= LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
                Self::validate_instance_graph_in_packages(
                    Some(importer),
                    importer_packages.iter().copied(),
                    &snapshot.root_resolutions,
                    &snapshot.ambient_peer_installs,
                    Some(snapshot),
                )?;
            }
            if !snapshot.provenance.is_empty() {
                self.project_validated_importer(importer)?
                    .validate_provenance()
                    .map_err(LockfileError::Deserialize)?;
            }
        }
        if let Some(id) = self
            .workspace_packages
            .keys()
            .find(|id| !referenced.contains(id.as_str()))
        {
            return Err(LockfileError::Deserialize(format!(
                "workspace package {id:?} is unreachable from every importer"
            )));
        }
        Ok(())
    }

    pub(crate) fn git_schema_error(&self) -> Option<String> {
        if self.metadata.lockfile_version >= LOCKFILE_VERSION_WITH_GIT_RESOLUTIONS {
            return None;
        }
        self.packages
            .iter()
            .chain(self.workspace_packages.values())
            .find_map(|package| {
                matches!(package.source_kind(), Some(Ok(Source::Git { .. }))).then(|| {
                    format!(
                        "package {:?} uses Git metadata, which requires lockfile version {}",
                        package.name, LOCKFILE_VERSION_WITH_GIT_RESOLUTIONS
                    )
                })
            })
    }

    /// Package-shape invariants that hold for both the TOML and
    /// binary read sides.
    pub fn validate_loaded_package(pkg: &LockedPackage) -> Result<(), LockfileError> {
        Self::validate_package_identity(pkg)?;
        match pkg.source_kind() {
            Some(Err(error)) => {
                return Err(LockfileError::InvalidPackageField {
                    package: pkg.name.clone(),
                    field: "source",
                    reason: error.to_string(),
                });
            }
            Some(Ok(Source::Tarball { .. })) if pkg.integrity.is_none() => {
                return Err(LockfileError::MissingPackageIntegrity {
                    package: pkg.name.clone(),
                    source_kind: "tarball",
                });
            }
            Some(Ok(Source::Git { .. })) if pkg.integrity.is_none() => {
                return Err(LockfileError::MissingPackageIntegrity {
                    package: pkg.name.clone(),
                    source_kind: "Git",
                });
            }
            Some(Ok(Source::Directory { .. })) if pkg.integrity.is_some() => {
                return Err(LockfileError::UnexpectedPackageIntegrity {
                    package: pkg.name.clone(),
                    source_kind: "directory",
                });
            }
            Some(Ok(Source::Link { .. })) if pkg.integrity.is_some() => {
                return Err(LockfileError::UnexpectedPackageIntegrity {
                    package: pkg.name.clone(),
                    source_kind: "link",
                });
            }
            Some(Ok(Source::Directory { .. } | Source::Link { .. })) => {
                if let Some(fingerprint) = pkg.manifest_fingerprint.as_deref()
                    && !valid_sha256_prefixed_hex(fingerprint)
                {
                    return Err(LockfileError::Deserialize(format!(
                        "package {:?} has an invalid local manifest fingerprint",
                        pkg.name
                    )));
                }
            }
            Some(Ok(_)) | None => {}
        }
        if pkg.manifest_fingerprint.is_some()
            && !matches!(
                pkg.source_kind(),
                Some(Ok(Source::Directory { .. } | Source::Link { .. }))
            )
        {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} has a local manifest fingerprint on a non-local source",
                pkg.name
            )));
        }
        if let Some(source) = pkg.lpm_scope_origin_mismatch() {
            return Err(LockfileError::InvalidScopeOrigin {
                package: pkg.name.clone(),
                source_identity: source,
            });
        }
        if let Some(reason) = pkg.git_metadata_error() {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} has invalid git metadata: {reason}",
                pkg.name
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_package_schema(
        pkg: &LockedPackage,
        lockfile_version: u32,
    ) -> Result<(), LockfileError> {
        let local_source = matches!(
            pkg.source_kind(),
            Some(Ok(Source::Directory { .. } | Source::Link { .. }))
        );
        if lockfile_version >= LOCKFILE_VERSION_WITH_LOCAL_MANIFEST_FINGERPRINTS
            && local_source
            && pkg.manifest_fingerprint.is_none()
        {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} is a mutable local source without a manifest fingerprint",
                pkg.name
            )));
        }
        if lockfile_version < LOCKFILE_VERSION_WITH_LOCAL_MANIFEST_FINGERPRINTS
            && pkg.manifest_fingerprint.is_some()
        {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} uses local manifest fingerprint metadata before lockfile version {}",
                pkg.name, LOCKFILE_VERSION_WITH_LOCAL_MANIFEST_FINGERPRINTS
            )));
        }
        if lockfile_version >= LOCKFILE_VERSION_WITH_STRUCTURED_PEERS && !pkg.peers.is_empty() {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} uses legacy peer metadata in lockfile version {}",
                pkg.name, LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
            )));
        }
        if lockfile_version < LOCKFILE_VERSION_WITH_STRUCTURED_PEERS && !pkg.peer_edges.is_empty() {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} uses structured peer metadata before lockfile version {}",
                pkg.name, LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
            )));
        }
        let exact_instance_schema = lockfile_version >= LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES;
        if exact_instance_schema && pkg.instance_id.is_none() {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} is missing instance-id in lockfile version {}",
                pkg.name, LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
            )));
        }
        if !exact_instance_schema
            && (pkg.instance_id.is_some()
                || !pkg.dependency_targets.is_empty()
                || !pkg.peer_targets.is_empty())
        {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} uses exact instance metadata before lockfile version {}",
                pkg.name, LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
            )));
        }
        let mut dependency_slots = HashSet::with_capacity(pkg.dependencies.len());
        for dependency in &pkg.dependencies {
            let Some(at) = dependency.rfind('@') else {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} has malformed dependency edge {:?}: missing exact version separator",
                    pkg.name, dependency
                )));
            };
            let (local_name, version_with_separator) = dependency.split_at(at);
            let version = &version_with_separator[1..];
            if local_name.is_empty() || version.is_empty() {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} has malformed dependency edge {:?}: local name and exact version are required",
                    pkg.name, dependency
                )));
            }
            validate_package_name(local_name).map_err(|reason| {
                LockfileError::Deserialize(format!(
                    "package {:?} has invalid dependency local name {:?}: {reason}",
                    pkg.name, local_name
                ))
            })?;
            if let Err(error) = node_semver::Version::parse(version)
                && !(exact_instance_schema && is_source_dependency_id(version))
            {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} has invalid dependency exact version or source identity {:?}: {error}",
                    pkg.name, version
                )));
            }
            if !dependency_slots.insert(local_name) {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} contains duplicate dependency slot {:?}",
                    pkg.name, local_name
                )));
            }
        }
        if exact_instance_schema
            && pkg
                .dependency_targets
                .keys()
                .map(String::as_str)
                .collect::<HashSet<_>>()
                != dependency_slots
        {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} dependency-target slots do not match dependency slots",
                pkg.name
            )));
        }
        let mut alias_slots = HashSet::with_capacity(pkg.alias_dependencies.len());
        for [local_name, target_name] in &pkg.alias_dependencies {
            validate_package_name(local_name).map_err(|reason| {
                LockfileError::Deserialize(format!(
                    "package {:?} has invalid alias local name {:?}: {reason}",
                    pkg.name, local_name
                ))
            })?;
            validate_package_name(target_name).map_err(|reason| {
                LockfileError::Deserialize(format!(
                    "package {:?} has invalid alias target name {:?}: {reason}",
                    pkg.name, target_name
                ))
            })?;
            if !alias_slots.insert(local_name.as_str()) {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} contains duplicate alias slot {:?}",
                    pkg.name, local_name
                )));
            }
            if !dependency_slots.contains(local_name.as_str()) {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} alias slot {:?} has no matching dependency edge",
                    pkg.name, local_name
                )));
            }
        }
        let mut peer_slots = HashSet::with_capacity(pkg.peer_edges.len());
        for peer in &pkg.peer_edges {
            if peer.local_name.is_empty()
                || peer.target_name.is_empty()
                || peer.target_version.is_empty()
            {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} has a structured peer edge with an empty identity field",
                    pkg.name
                )));
            }
            validate_package_name(&peer.local_name).map_err(|reason| {
                LockfileError::Deserialize(format!(
                    "package {:?} has invalid peer local name {:?}: {reason}",
                    pkg.name, peer.local_name
                ))
            })?;
            Self::validate_package_name_and_version(&peer.target_name, &peer.target_version)?;
            if !peer_slots.insert(peer.local_name.as_str()) {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} contains duplicate peer slot {:?}",
                    pkg.name, peer.local_name
                )));
            }
            if dependency_slots.contains(peer.local_name.as_str()) {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} uses local slot {:?} as both dependency and peer",
                    pkg.name, peer.local_name
                )));
            }
        }
        if exact_instance_schema
            && pkg
                .peer_targets
                .keys()
                .map(String::as_str)
                .collect::<HashSet<_>>()
                != peer_slots
        {
            return Err(LockfileError::Deserialize(format!(
                "package {:?} peer-target slots do not match peer slots",
                pkg.name
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_root_resolution_schema(
        root_resolutions: &RootResolutions,
        lockfile_version: u32,
    ) -> Result<(), LockfileError> {
        if lockfile_version < LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
            && let Some(local_name) = root_resolutions
                .iter()
                .find_map(|(local_name, root)| root.instance_id.map(|_| local_name))
        {
            return Err(LockfileError::Deserialize(format!(
                "root resolution {local_name:?} uses instance-id metadata before lockfile version {}",
                LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES
            )));
        }
        Ok(())
    }

    pub fn validate_package_name_and_version(
        name: &str,
        version: &str,
    ) -> Result<(), LockfileError> {
        validate_package_name(name).map_err(|reason| LockfileError::InvalidPackageField {
            package: name.to_string(),
            field: "name",
            reason,
        })?;
        node_semver::Version::parse(version).map_err(|error| {
            LockfileError::InvalidPackageField {
                package: name.to_string(),
                field: "version",
                reason: error.to_string(),
            }
        })?;
        Ok(())
    }

    pub(crate) fn validate_package_identity(pkg: &LockedPackage) -> Result<(), LockfileError> {
        Self::validate_package_name_and_version(&pkg.name, &pkg.version)?;
        if let Some(integrity) = pkg.integrity.as_deref() {
            if integrity.is_empty() {
                return Err(LockfileError::InvalidPackageField {
                    package: pkg.name.clone(),
                    field: "integrity",
                    reason: "empty 'integrity' is invalid".to_string(),
                });
            }
            lpm_common::Integrity::parse(integrity).map_err(|error| {
                LockfileError::InvalidPackageField {
                    package: pkg.name.clone(),
                    field: "integrity",
                    reason: error.to_string(),
                }
            })?;
        }
        Ok(())
    }

    pub fn validate_loaded_packages(packages: &[LockedPackage]) -> Result<(), LockfileError> {
        for pkg in packages {
            Self::validate_loaded_package(pkg)?;
        }
        Self::validate_standalone_package_order(packages)?;
        Ok(())
    }

    pub(crate) fn validate_standalone_package_order(
        packages: &[LockedPackage],
    ) -> Result<(), LockfileError> {
        let mut previous: Option<(PackageKey, Option<lpm_common::PackageInstanceId>)> = None;
        for package in packages {
            let key = package.package_key();
            let identity = (key, package.instance_id);
            if let Some((previous_key, previous_instance_id)) = previous.as_ref() {
                let ordering = previous_key
                    .name
                    .cmp(&identity.0.name)
                    .then_with(|| previous_key.version.cmp(&identity.0.version))
                    .then_with(|| previous_key.source_id.cmp(&identity.0.source_id))
                    .then_with(|| previous_instance_id.cmp(&identity.1));
                if ordering.is_eq() {
                    return Err(LockfileError::Deserialize(format!(
                        "duplicate package identity {:?}",
                        identity.0.lockfile_id()
                    )));
                }
                if ordering.is_gt() {
                    return Err(LockfileError::Deserialize(
                        "standalone packages are not in package identity order".to_string(),
                    ));
                }
            }
            previous = Some(identity);
        }
        Ok(())
    }

    pub(crate) fn validate_instance_graph(&self) -> Result<(), LockfileError> {
        if self.metadata.lockfile_version < LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
            return Ok(());
        }
        Self::validate_instance_graph_in_packages(
            None,
            self.packages.iter(),
            &self.root_resolutions,
            &self.ambient_peer_installs,
            self.importers.get("."),
        )
    }

    fn validate_instance_graph_in_packages<'a>(
        importer: Option<&str>,
        mut packages: impl Iterator<Item = &'a LockedPackage> + Clone,
        root_resolutions: &RootResolutions,
        ambient_peer_installs: &[String],
        importer_snapshot: Option<&ImporterSnapshot>,
    ) -> Result<(), LockfileError> {
        let importer_context = importer
            .map(|importer| format!(" in workspace importer {importer:?}"))
            .unwrap_or_default();
        let mut by_instance = HashMap::new();
        for package in packages.clone() {
            Self::validate_package_schema(package, LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES)?;
            let instance_id = package.instance_id.ok_or_else(|| {
                LockfileError::Deserialize(format!(
                    "package {:?}{importer_context} is missing instance-id",
                    package.name
                ))
            })?;
            if by_instance.insert(instance_id, package).is_some() {
                return Err(LockfileError::Deserialize(format!(
                    "duplicate package instance-id {instance_id}{importer_context}"
                )));
            }
        }
        for package in packages.clone() {
            let aliases = package
                .alias_dependencies
                .iter()
                .map(|pair| (pair[0].as_str(), pair[1].as_str()))
                .collect::<HashMap<_, _>>();
            let dependency_versions = package
                .dependencies
                .iter()
                .filter_map(|dependency| {
                    dependency
                        .rfind('@')
                        .map(|at| (&dependency[..at], &dependency[at + 1..]))
                })
                .collect::<HashMap<_, _>>();
            for (local_name, target_id) in &package.dependency_targets {
                let target = by_instance.get(target_id).ok_or_else(|| {
                    LockfileError::Deserialize(format!(
                        "package {:?}{importer_context} dependency slot {:?} references missing instance {target_id}",
                        package.name, local_name
                    ))
                })?;
                let expected_name = aliases
                    .get(local_name.as_str())
                    .copied()
                    .unwrap_or(local_name.as_str());
                let expected_version = dependency_versions.get(local_name.as_str()).ok_or_else(|| {
                    LockfileError::Deserialize(format!(
                        "package {:?}{importer_context} dependency target {:?} has no matching dependency edge",
                        package.name, local_name
                    ))
                })?;
                let expected_target_value = match target.source_kind() {
                    Some(Ok(Source::Registry { .. })) | None => target.version.clone(),
                    Some(Ok(source)) => source.source_id(),
                    Some(Err(_)) => continue,
                };
                if target.name != expected_name || expected_target_value != **expected_version {
                    return Err(LockfileError::Deserialize(format!(
                        "package {:?}{importer_context} dependency slot {:?} metadata disagrees with target instance {target_id}",
                        package.name, local_name
                    )));
                }
            }
            for peer in &package.peer_edges {
                let target_id = package.peer_targets.get(&peer.local_name).ok_or_else(|| {
                    LockfileError::Deserialize(format!(
                        "package {:?}{importer_context} peer slot {:?} has no exact target",
                        package.name, peer.local_name
                    ))
                })?;
                let target = by_instance.get(target_id).ok_or_else(|| {
                    LockfileError::Deserialize(format!(
                        "package {:?}{importer_context} peer slot {:?} references missing instance {target_id}",
                        package.name, peer.local_name
                    ))
                })?;
                let wrapper_id = match target.source_kind() {
                    Some(Ok(Source::Registry { .. })) | None => None,
                    Some(Ok(source)) => Some(source.source_id()),
                    Some(Err(_)) => continue,
                };
                if target.name != peer.target_name
                    || target.version != peer.target_version
                    || wrapper_id != peer.target_wrapper_id
                {
                    return Err(LockfileError::Deserialize(format!(
                        "package {:?}{importer_context} peer slot {:?} metadata disagrees with target instance {target_id}",
                        package.name, peer.local_name
                    )));
                }
            }
        }
        let declared_roots = importer_snapshot.map(|snapshot| {
            snapshot
                .dependencies
                .keys()
                .chain(snapshot.dev_dependencies.keys())
                .chain(snapshot.optional_dependencies.keys())
                .map(String::as_str)
                .collect::<HashSet<_>>()
        });
        if !ambient_peer_installs.is_empty() && declared_roots.is_none() {
            return Err(LockfileError::Deserialize(format!(
                "ambient peer roots{importer_context} require an importer snapshot"
            )));
        }

        let mut pending = Vec::with_capacity(root_resolutions.len());
        for (local_name, root) in root_resolutions {
            let target_id = root.instance_id.ok_or_else(|| {
                LockfileError::Deserialize(format!(
                    "root resolution {local_name:?}{importer_context} is missing instance-id"
                ))
            })?;
            let target = by_instance.get(&target_id).ok_or_else(|| {
                LockfileError::Deserialize(format!(
                    "root resolution {local_name:?}{importer_context} references missing instance {target_id}"
                ))
            })?;
            if target.name != root.package
                || target.version != root.version
                || target.source != root.source
            {
                return Err(LockfileError::Deserialize(format!(
                    "root resolution {local_name:?}{importer_context} metadata disagrees with target instance {target_id}"
                )));
            }
            if declared_roots
                .as_ref()
                .is_none_or(|declared| declared.contains(local_name.as_str()))
            {
                pending.push(target_id);
            }
        }
        let mut reachable = HashSet::with_capacity(by_instance.len());
        while let Some(instance_id) = pending.pop() {
            if !reachable.insert(instance_id) {
                continue;
            }
            let package = by_instance[&instance_id];
            pending.extend(package.dependency_targets.values().copied());
            pending.extend(package.peer_targets.values().copied());
        }
        let mut ambient_names = HashSet::with_capacity(ambient_peer_installs.len());
        for local_name in ambient_peer_installs {
            if !ambient_names.insert(local_name.as_str()) {
                return Err(LockfileError::Deserialize(format!(
                    "duplicate ambient peer root {local_name:?}{importer_context}"
                )));
            }
            if declared_roots
                .as_ref()
                .is_some_and(|declared| declared.contains(local_name.as_str()))
            {
                return Err(LockfileError::Deserialize(format!(
                    "ambient peer root {local_name:?}{importer_context} is already manifest-declared"
                )));
            }
            let target_id = root_resolutions
                .get(local_name)
                .and_then(|root| root.instance_id)
                .ok_or_else(|| {
                    LockfileError::Deserialize(format!(
                        "ambient peer root {local_name:?}{importer_context} has no exact root resolution"
                    ))
                })?;
            if !reachable.contains(&target_id) {
                return Err(LockfileError::Deserialize(format!(
                    "ambient peer root {local_name:?}{importer_context} is unreachable from manifest-declared dependencies"
                )));
            }
        }
        if let Some(package) = packages.find(|package| {
            package
                .instance_id
                .is_some_and(|instance_id| !reachable.contains(&instance_id))
        }) {
            return Err(LockfileError::Deserialize(format!(
                "package {:?}{importer_context} is unreachable from every exact root",
                package.name
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_peer_edge_targets(&self) -> Result<(), LockfileError> {
        Self::validate_peer_edge_targets_in_packages(None, self.packages.iter())
    }

    fn validate_peer_edge_targets_in_packages<'a>(
        importer: Option<&str>,
        packages: impl Iterator<Item = &'a LockedPackage> + Clone,
    ) -> Result<(), LockfileError> {
        let mut targets: HashSet<(&str, &str, Option<Cow<'_, str>>)> = HashSet::new();
        for package in packages.clone() {
            let wrapper_id = match package.source_kind() {
                Some(Ok(Source::Registry { .. })) | None => None,
                Some(Ok(source)) => Some(Cow::Owned(source.source_id())),
                Some(Err(_)) => continue,
            };
            targets.insert((package.name.as_str(), package.version.as_str(), wrapper_id));
        }
        for package in packages {
            for peer in &package.peer_edges {
                let identity = (
                    peer.target_name.as_str(),
                    peer.target_version.as_str(),
                    peer.target_wrapper_id.as_deref().map(Cow::Borrowed),
                );
                if !targets.contains(&identity) {
                    let importer_context = importer
                        .map(|importer| format!(" in workspace importer {importer:?}"))
                        .unwrap_or_default();
                    return Err(LockfileError::Deserialize(format!(
                        "package {:?}{importer_context} peer slot {:?} references missing or source-mismatched target {}@{} wrapper_id={:?}",
                        package.name,
                        peer.local_name,
                        peer.target_name,
                        peer.target_version,
                        peer.target_wrapper_id,
                    )));
                }
            }
        }
        Ok(())
    }

    /// Look up a locked package by name. **Name-only — does NOT
    /// disambiguate cross-source collisions.** Returns the first
    /// match in sort order; under a `(name, version, source_id)`
    /// triple sort that's the lowest-source_id entry for the
    /// lowest-version with this name.
    ///
    /// Prefer [`Self::find_package_by_key`] for new code. This
    /// name-only method is retained for back-compat with callers
    /// (alias resolution etc.) where the name uniquely identifies a
    /// package; non-Registry source kinds landing in the same lockfile
    /// may shadow such lookups.
    pub fn find_package(&self, name: &str) -> Option<&LockedPackage> {
        self.packages
            .binary_search_by(|p| p.name.as_str().cmp(name))
            .ok()
            .map(|idx| &self.packages[idx])
    }

    /// Source-aware lookup keyed by the full `(name, version,
    /// source_id)` triple.
    /// Returns `Some(&LockedPackage)` only when the exact key
    /// matches; under cross-source collision (registry +
    /// tarball-URL with same `name@version`), returns the
    /// requested side, never an ambiguous shadow.
    pub fn find_package_by_key(&self, key: &PackageKey) -> Option<&LockedPackage> {
        self.packages
            .binary_search_by(|p| {
                let pk = p.package_key();
                pk.name
                    .cmp(&key.name)
                    .then_with(|| pk.version.cmp(&key.version))
                    .then_with(|| pk.source_id.cmp(&key.source_id))
            })
            .ok()
            .map(|idx| &self.packages[idx])
    }

    pub fn set_verified_provenance(
        &mut self,
        key: &PackageKey,
        evidence: LockedProvenance,
    ) -> Option<LockedProvenance> {
        self.provenance.insert(key.lockfile_id(), evidence)
    }

    pub fn verified_provenance(&self, key: &PackageKey) -> Option<&LockedProvenance> {
        self.provenance.get(&key.lockfile_id())
    }

    pub(crate) fn validate_provenance(&self) -> Result<(), String> {
        if self.provenance.is_empty() {
            return Ok(());
        }
        let mut packages_by_lockfile_id = HashMap::with_capacity(self.packages.len());
        for package in &self.packages {
            packages_by_lockfile_id.insert(package.package_key().lockfile_id(), package);
        }

        for (lockfile_id, evidence) in &self.provenance {
            let Some(package) = packages_by_lockfile_id.get(lockfile_id) else {
                return Err(format!(
                    "provenance entry {lockfile_id:?} does not match any locked package"
                ));
            };
            if !evidence.snapshot.present {
                return Err(format!(
                    "provenance entry {lockfile_id:?} is marked absent; only verified evidence may be locked"
                ));
            }
            for (field, value) in [
                ("subject-name", evidence.subject_name.as_str()),
                ("subject-sha512", evidence.subject_sha512.as_str()),
                ("log-id", evidence.log_id.as_str()),
                ("bundle-sha256", evidence.bundle_sha256.as_str()),
            ] {
                if value.is_empty() {
                    return Err(format!(
                        "provenance entry {lockfile_id:?} has an empty required {field} field"
                    ));
                }
            }
            for (field, value) in [
                ("publisher", evidence.snapshot.publisher.as_deref()),
                ("workflow-path", evidence.snapshot.workflow_path.as_deref()),
                ("workflow-ref", evidence.snapshot.workflow_ref.as_deref()),
                (
                    "attestation-cert-sha256",
                    evidence.snapshot.attestation_cert_sha256.as_deref(),
                ),
            ] {
                if value == Some("") {
                    return Err(format!(
                        "provenance entry {lockfile_id:?} has an empty optional {field} field"
                    ));
                }
            }
            if evidence.subject_sha512.len() != 128
                || !evidence
                    .subject_sha512
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(format!(
                    "provenance entry {lockfile_id:?} has an invalid subject-sha512 digest"
                ));
            }
            if evidence.log_index < 0 {
                return Err(format!(
                    "provenance entry {lockfile_id:?} has an invalid log-index"
                ));
            }
            let Some(bundle_digest) = evidence.bundle_sha256.strip_prefix("sha256-") else {
                return Err(format!(
                    "provenance entry {lockfile_id:?} has an invalid bundle-sha256 digest"
                ));
            };
            if bundle_digest.len() != 64
                || !bundle_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(format!(
                    "provenance entry {lockfile_id:?} has an invalid bundle-sha256 digest"
                ));
            }
            let expected_subject = lpm_common::npm_package_purl(&package.name, &package.version);
            if evidence.subject_name != expected_subject {
                return Err(format!(
                    "provenance entry {lockfile_id:?} is bound to subject {:?}, expected {expected_subject:?}",
                    evidence.subject_name
                ));
            }
            let integrity = package.integrity.as_deref().ok_or_else(|| {
                format!(
                    "provenance entry {lockfile_id:?} cannot be bound because the package has no integrity"
                )
            })?;
            let parsed_integrity = lpm_common::Integrity::parse(integrity).map_err(|error| {
                format!(
                    "provenance entry {lockfile_id:?} cannot be bound to invalid package integrity: {error}"
                )
            })?;
            if parsed_integrity.algorithm != lpm_common::integrity::HashAlgorithm::Sha512 {
                return Err(format!(
                    "provenance entry {lockfile_id:?} requires sha512 package integrity"
                ));
            }
            if evidence.subject_sha512 != hex::encode(parsed_integrity.hash) {
                return Err(format!(
                    "provenance entry {lockfile_id:?} subject-sha512 does not match the locked package integrity"
                ));
            }
        }
        Ok(())
    }
}

impl ValidatedLockfile {
    /// Create an empty validated lockfile with the default resolver marker.
    pub fn new() -> Self {
        Self(Lockfile::new())
    }

    /// Create an empty validated lockfile with an explicit resolver marker.
    pub fn new_with_resolver(resolver: &str) -> Self {
        Self(Lockfile::new_with_resolver(resolver))
    }

    /// Borrow the validated lockfile without permitting mutation.
    pub fn as_lockfile(&self) -> &Lockfile {
        &self.0
    }

    /// Add a validated standalone importer while preserving union invariants.
    pub fn absorb_importer(
        &mut self,
        importer: &str,
        standalone: Self,
    ) -> Result<(), LockfileError> {
        self.0.absorb_importer(importer, standalone.0)
    }

    /// Materialize an importer after reusing validation performed at load time.
    pub fn project_importer(&self, importer: &str) -> Result<Lockfile, LockfileError> {
        self.0.project_validated_importer(importer)
    }

    /// Materialize importer metadata without cloning its package rows.
    pub fn project_importer_metadata(&self, importer: &str) -> Result<Lockfile, LockfileError> {
        self.0.project_validated_importer_metadata(importer)
    }

    /// Borrow validated package rows in standalone package identity order.
    pub fn importer_packages(&self, importer: &str) -> Result<Vec<&LockedPackage>, LockfileError> {
        self.0.validated_importer_packages(importer)
    }

    /// Reuse validated union rows while pruning removed importers and replacing changed ones.
    pub fn update_workspace_importers(
        &self,
        retained_importers: &BTreeSet<String>,
        replacements: BTreeMap<String, Lockfile>,
    ) -> Result<Lockfile, LockfileError> {
        let mut updated = self.0.clone();
        updated.retain_workspace_importers(retained_importers);
        for (importer, replacement) in replacements {
            updated.replace_workspace_importer_in_place(&importer, replacement)?;
        }
        Ok(updated)
    }
}

impl Default for ValidatedLockfile {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

fn is_source_dependency_id(value: &str) -> bool {
    matches!(value.as_bytes(), [b'f' | b'l' | b't' | b'g', b'-', hex @ ..]
        if hex.len() == 16
            && hex.iter().all(u8::is_ascii_hexdigit)
            && hex.iter().all(|byte| !byte.is_ascii_uppercase()))
}

/// Validate that a package source URL in the lockfile is safe.
///
/// Accepts HTTPS registries, localhost registries used for development,
/// and public GitHub repositories pinned to an exact lowercase commit.
/// Returns `false` for insecure or credential-bearing network sources.
pub fn is_safe_source(source: &str) -> bool {
    if let Some(raw_url) = source.strip_prefix("registry+") {
        let Ok(url) = url::Url::parse(raw_url) else {
            return false;
        };
        let Some(host) = url.host_str() else {
            return false;
        };
        if !url.username().is_empty() || url.password().is_some() {
            return false;
        }
        return url.scheme() == "https"
            || url.scheme() == "http" && lpm_common::is_loopback_host(host);
    }
    is_safe_github_source(source)
}

fn is_safe_github_source(source: &str) -> bool {
    let Some(raw_url) = source.strip_prefix("git+") else {
        return false;
    };
    let Ok(url) = url::Url::parse(raw_url) else {
        return false;
    };
    let Some(commit) = url.fragment() else {
        return false;
    };
    if commit.len() != 40
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        || commit.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    let mut segments = match url.path_segments() {
        Some(segments) => segments,
        None => return false,
    };
    let owner = segments.next();
    let repository = segments.next();
    url.scheme() == "https"
        && url.host_str() == Some("github.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && owner.is_some_and(is_safe_github_component)
        && repository.is_some_and(|name| {
            name.strip_suffix(".git")
                .is_some_and(is_safe_github_component)
        })
        && segments.next().is_none()
}

fn is_safe_github_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
