use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

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
///
/// **Why this matters:** install.rs's lockfile fast path uses the
/// version to decide whether the absence of `ambient-peer-installs`
/// is meaningful. On v1 + `auto_install_peers = true`, the absence
/// could be a buggy-writer artifact, so the fast path is invalidated
/// and a fresh resolve runs (which writes a current lockfile, restoring
/// fast-path eligibility on subsequent installs).
pub const LOCKFILE_VERSION_WITH_DEPENDENCY_ENGINES: u32 = 6;
pub const LOCKFILE_VERSION_WITH_PROVENANCE: u32 = 7;
pub const LOCKFILE_VERSION: u32 = LOCKFILE_VERSION_WITH_PROVENANCE;

/// Default lockfile filename.
pub const LOCKFILE_NAME: &str = "lpm.lock";

/// Catalog resolutions used by this install, grouped by catalog name and package name.
pub type CatalogSnapshots = BTreeMap<String, BTreeMap<String, CatalogSnapshotEntry>>;

/// Importer snapshots keyed by importer path relative to the lockfile root.
pub type ImporterSnapshots = BTreeMap<String, ImporterSnapshot>;

/// Lockfile-recorded patch evidence keyed by `<package-name>@<version>`.
pub type LockfilePatches = BTreeMap<String, LockfilePatch>;

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

    /// Returns `Some(url)` if this is a `@lpm.dev/*` package pointing
    /// at a non-lpm.dev origin. Scoped names must always resolve
    /// through the LPM origin (or `http://localhost` for dev),
    /// regardless of what other registries the client is configured to
    /// talk to.
    pub fn lpm_scope_origin_mismatch(&self) -> Option<String> {
        if !self.name.starts_with("@lpm.dev/") {
            return None;
        }
        let Some(Ok(Source::Registry { url })) = self.source_kind() else {
            return None;
        };
        if is_lpm_origin(&url) { None } else { Some(url) }
    }
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
            root_aliases: BTreeMap::new(),
            // Populated by `install.rs` from
            // `ResolveResult.ambient_peer_installs` on cold-resolve
            // lockfile writes; empty on warm/lockfile-fast-path
            // returns from `Lockfile::read_fast` until the writer
            // updates an existing lockfile.
            ambient_peer_installs: Vec::new(),
        }
    }

    /// Add a resolved package. Maintains sorted order by
    /// `(name, version, source_id)` triple. Two packages with the
    /// same name but different `(version, source_id)` no longer race
    /// for the same slot, preventing cross-source collision.
    pub fn add_package(&mut self, pkg: LockedPackage) {
        let key = pkg.package_key();
        let pos = self
            .packages
            .binary_search_by(|p| {
                let other = p.package_key();
                other
                    .name
                    .cmp(&key.name)
                    .then_with(|| other.version.cmp(&key.version))
                    .then_with(|| other.source_id.cmp(&key.source_id))
            })
            .unwrap_or_else(|pos| pos);
        self.packages.insert(pos, pkg);
    }

    /// Package-shape invariants that hold for both the TOML and
    /// binary read sides. Currently: `@lpm.dev/*` scope-pinning.
    pub fn validate_loaded_packages(packages: &[LockedPackage]) -> Result<(), LockfileError> {
        for pkg in packages {
            if let Some(url) = pkg.lpm_scope_origin_mismatch() {
                return Err(LockfileError::InvalidScopeOrigin {
                    package: pkg.name.clone(),
                    url,
                });
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

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a package source URL in the lockfile is safe.
///
/// Only HTTPS registries and localhost (for development) are accepted.
/// Returns `false` for HTTP (non-localhost), file://, ftp://, or other schemes
/// that could indicate a tampered lockfile redirecting downloads to a malicious server.
pub fn is_safe_source(source: &str) -> bool {
    // Allow HTTPS registries (any host)
    if source.starts_with("registry+https://") {
        return true;
    }
    // Allow localhost/loopback for development
    if source.starts_with("registry+http://localhost")
        || source.starts_with("registry+http://127.0.0.1")
    {
        return true;
    }
    false
}
