//! v2 store graph-key derivation.
//!
//! A [`GraphKey`] identifies a unique materialization context for a
//! `(name, version)` pair. Two installations whose [`GraphKeyInputs`]
//! match are interchangeable — they can share the same on-disk wrapper
//! at `~/.lpm/store/v2/links/<graph-key>/`.
//!
//! See the Phase 66 preplan §2.2 for the design rationale and the
//! audit history that locked which fields are identity-bearing.
//!
//! # Inputs hashed (stable order)
//!
//! 1. Schema version tag (`v=2`)
//! 2. `name`
//! 3. `version`
//! 4. Platform tuple `(os, cpu, libc)` — libc empty on non-Linux
//! 5. Linker mode tag (`isolated` | `hoisted`)
//! 6. Sorted peer-context: `peer_name@peer_version` joined by `,`
//!    (always empty in hoisted mode — preplan §2.2)
//! 7. Sorted dep edges: `local => target_name@target_version`
//!    joined by `,`
//! 8. Sorted aliases: `local => canonical_target_name`
//!    joined by `,`
//! 9. Sorted root-link names joined by `,`
//! 10. Source-identity disambiguator (`wrapper_id`)
//! 11. Patch fingerprint (Phase 66 confidence-followup F1) — `Some("p-…")`
//!     for any package that carries a `lpm.patchedDependencies` entry,
//!     `None` otherwise. Folded in so a project applying a patch gets a
//!     distinct link entry from any other project's unpatched (or
//!     differently-patched) install of the same coords. Without this,
//!     v2's cross-project sharing of `<store>/v2/links/<key>/...`
//!     dirs would let project A's patched bytes leak into project B
//!     via shared materialization (the `links/` dir is the on-disk
//!     destination, not a project-private wrapper).
//!
//! Each component is preceded by a labeled NUL-delimited prefix
//! (e.g. `name=\0...\0`) so cross-component byte boundaries are
//! unambiguous and adding a new component later doesn't collide with
//! existing inputs.
//!
//! # Output shape
//!
//! `<safe_name>@<version>+<short_hash>` where `<short_hash>` is the
//! first 16 hex chars of the BLAKE3 digest. Human-readable so directory
//! listings under `links/` are debuggable; collision-resistant because
//! the full 256-bit digest still uniquely identifies the inputs in the
//! sidecar metadata (see [`crate::v2::link_meta::LinkMeta::graph_key_digest_hex`]).

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

use crate::v2::platform::PlatformTuple;

/// Linker mode tag stamped into the graph key.
///
/// Two installations of `react@18.3.0` under different linker modes
/// must produce different keys — even if every other input matches —
/// because the wrapper layouts (sibling symlinks vs flat-hoisted) are
/// not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkerModeTag {
    /// pnpm-style isolated, sibling symlinks under `node_modules/`.
    Isolated,
    /// npm-style hoisted, flat layout. Peer-context collapses to empty
    /// (one canonical version per name) but dep edges still distinguish.
    Hoisted,
}

impl LinkerModeTag {
    fn as_str(self) -> &'static str {
        match self {
            LinkerModeTag::Isolated => "isolated",
            LinkerModeTag::Hoisted => "hoisted",
        }
    }
}

/// Single peer-context entry: a peer that resolved to a specific version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerEntry {
    /// Canonical registry name of the peer (e.g. `react`).
    pub name: String,
    /// Exact resolved version (e.g. `18.3.0`).
    pub version: String,
}

/// Single dep edge: local name in the consumer → target package coords.
///
/// `local` matches the consumer's `package.json > dependencies` key
/// (which differs from the canonical name only for npm-aliased deps —
/// `"strip-ansi-cjs": "npm:strip-ansi@^6"` yields `local =
/// "strip-ansi-cjs"`, `target_name = "strip-ansi"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepEdge {
    /// Key from the consumer package's `dependencies` map.
    pub local: String,
    /// Canonical registry name of the target package.
    pub target_name: String,
    /// Exact resolved target version.
    pub target_version: String,
}

/// Identity inputs for one materialization of `(name, version)`.
///
/// Construct via [`GraphKeyInputs::new`], then optionally enrich with
/// `with_peers` / `with_deps` / `with_aliases` / `with_root_link_names`.
/// Hash with [`GraphKey::derive`].
#[derive(Debug, Clone)]
pub struct GraphKeyInputs {
    /// Canonical registry name of the package being materialized.
    pub name: String,
    /// Exact resolved version of the package being materialized.
    pub version: String,
    /// Host platform tuple. See [`PlatformTuple`].
    pub platform: PlatformTuple,
    /// Linker mode under which this wrapper would materialize.
    pub linker_mode: LinkerModeTag,
    /// Peer-context. Empty in hoisted mode (preplan §2.2 lock-in).
    pub peers: Vec<PeerEntry>,
    /// Dep edges declared in this package's manifest.
    pub deps: Vec<DepEdge>,
    /// npm-alias edges: `local_name → canonical_target_name`.
    /// Subset of [`Self::deps`]; an entry appears iff the dep is aliased
    /// (i.e., consumer's `local` differs from the dep's canonical
    /// registry name). Carried as a separate field rather than derived
    /// from `deps` so the linker contract — which today treats
    /// `LinkTarget.aliases` as identity-bearing alongside
    /// `LinkTarget.dependencies` — stays explicit in the key.
    pub aliases: BTreeMap<String, String>,
    /// Root-link names this materialization would expose at the project
    /// root (corresponds to [`LinkTarget::root_link_names`]). `None`
    /// means "no override; inherit the linker's default behavior" —
    /// distinguishable from `Some(vec![])` which means "explicitly no
    /// root symlinks." Both are identity-bearing.
    ///
    /// [`LinkTarget::root_link_names`]: ../../../lpm-linker/src/lib.rs
    pub root_link_names: Option<Vec<String>>,
    /// **Phase 66 §2.2 / preplan day-7 audit response** — source-identity
    /// disambiguator. Mirrors `LinkTarget.wrapper_id`:
    /// - `None` for `Source::Registry` (registry is the only source
    ///   that doesn't share `(name, version)` namespace with other
    ///   source kinds, so no disambiguation needed).
    /// - `Some(<source-id>)` for non-Registry sources (Tarball
    ///   remote/local, Directory, Link, Git).
    ///
    /// Folded into the GraphKey so `Source::Registry { foo@1.0.0 }`
    /// and `Source::Tarball { foo@1.0.0 from a custom URL }` produce
    /// distinct keys — the link entries materialize independently and
    /// the `links/<key>/` namespace stays collision-free under
    /// multi-source installs. Empty / `None` means "no source-identity
    /// constraint", matching the legacy registry-only shape so a
    /// pre-Phase-66 GraphKey for a registry package doesn't suddenly
    /// invalidate.
    pub wrapper_id: Option<String>,
    /// **Phase 66 confidence-followup F1 (2026-05-09)** — patch identity.
    /// When the install pipeline detects a `lpm.patchedDependencies`
    /// entry for `(name, version)`, the caller computes
    /// `sha256(patch_bytes || originalIntegrity)` (truncated to 16 hex
    /// chars, prefixed `p-`) and threads it here. Folded into the
    /// GraphKey so a patched install lands in its own
    /// `<store>/v2/links/<key>+<short-hash>/` directory and never
    /// shares bytes with an unpatched install of the same coords in
    /// another project. `None` for unpatched packages — preserves the
    /// pre-F1 hash so existing v2 link entries don't get invalidated.
    pub patch_fingerprint: Option<String>,
}

impl GraphKeyInputs {
    /// Minimal inputs: name + version + platform + linker mode. Use
    /// the `with_*` methods to fold in optional dimensions.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        platform: PlatformTuple,
        linker_mode: LinkerModeTag,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            platform,
            linker_mode,
            peers: Vec::new(),
            deps: Vec::new(),
            aliases: BTreeMap::new(),
            root_link_names: None,
            wrapper_id: None,
            patch_fingerprint: None,
        }
    }

    /// Replace the source-identity disambiguator. `None` is the
    /// pre-Phase-66 shape (registry-only); `Some(...)` is the
    /// non-Registry-source case.
    pub fn with_wrapper_id(mut self, wrapper_id: Option<String>) -> Self {
        self.wrapper_id = wrapper_id;
        self
    }

    /// Replace the patch fingerprint. `None` is the unpatched shape
    /// (preserves the pre-F1 hash); `Some("p-…")` indicates a
    /// `lpm.patchedDependencies` entry covers this `(name, version)`.
    pub fn with_patch_fingerprint(mut self, patch_fingerprint: Option<String>) -> Self {
        self.patch_fingerprint = patch_fingerprint;
        self
    }

    /// Replace the peer-context. Order doesn't matter (hashing sorts).
    pub fn with_peers(mut self, peers: impl IntoIterator<Item = PeerEntry>) -> Self {
        self.peers = peers.into_iter().collect();
        self
    }

    /// Replace the dep edges. Order doesn't matter (hashing sorts).
    pub fn with_deps(mut self, deps: impl IntoIterator<Item = DepEdge>) -> Self {
        self.deps = deps.into_iter().collect();
        self
    }

    /// Replace the alias map.
    pub fn with_aliases<I, K, V>(mut self, aliases: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.aliases = aliases
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    /// Set the root-link-name override. Pass `None` to clear it.
    pub fn with_root_link_names(mut self, names: Option<Vec<String>>) -> Self {
        self.root_link_names = names;
        self
    }
}

/// Stable identity for one materialization context, derived from
/// [`GraphKeyInputs`] via BLAKE3.
///
/// The struct holds both the human-readable directory-name form
/// (`<safe>@<ver>+<short_hex>`) and the full 256-bit digest. Disk
/// layout uses [`Self::dir_name`]; the sidecar [`crate::v2::link_meta::LinkMeta`]
/// records [`Self::digest_hex`] so `lpm cache prune` can reconstruct
/// identity without re-hashing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GraphKey {
    name: String,
    version: String,
    digest: [u8; 32],
}

impl GraphKey {
    /// Schema version tag. Bump if the input layout changes — older
    /// wrappers will produce different keys and naturally GC.
    const SCHEMA: &'static [u8] = b"v=2";

    /// Length of the directory-name suffix in hex chars (16 = 64 bits
    /// of the BLAKE3 digest, ~10⁻¹⁹ collision probability for 10⁹ keys).
    const SHORT_HEX_LEN: usize = 16;

    /// Compute the graph key from a complete [`GraphKeyInputs`] struct.
    ///
    /// **Hoisted peer-collapse is enforced here, not at the caller.**
    /// Preplan §2.2 locks "peers are empty in hoisted mode" as the
    /// invariant that lets cross-project hoisted wrappers share. If
    /// the primitive trusted callers to normalize, a single missed
    /// site in Phase 4b would silently fragment the cache (one wrapper
    /// per peer-context instead of one per name+edge-set), throwing
    /// away the hoisted-side win this whole rewrite is supposed to
    /// unlock. We collapse `inputs.peers` to empty when
    /// `linker_mode == Hoisted` and `debug_assert!` to surface the
    /// caller's mistake during dev/test builds.
    pub fn derive(inputs: &GraphKeyInputs) -> Self {
        debug_assert!(
            !matches!(inputs.linker_mode, LinkerModeTag::Hoisted) || inputs.peers.is_empty(),
            "GraphKey::derive: hoisted graph keys must not carry peers \
             (collapsing silently in release; caller should pass an \
             empty Vec). Got {} peers for {}@{}.",
            inputs.peers.len(),
            inputs.name,
            inputs.version,
        );

        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::SCHEMA);
        hasher.update(b"\0");

        write_field(&mut hasher, b"name", inputs.name.as_bytes());
        write_field(&mut hasher, b"version", inputs.version.as_bytes());

        let platform_str = format_platform(&inputs.platform);
        write_field(&mut hasher, b"platform", platform_str.as_bytes());

        write_field(
            &mut hasher,
            b"linker",
            inputs.linker_mode.as_str().as_bytes(),
        );

        // Defense-in-depth: even if a caller slips a non-empty peer
        // list past the debug_assert (release build), peers do NOT
        // contribute to the hoisted graph key.
        let effective_peers: &[PeerEntry] = match inputs.linker_mode {
            LinkerModeTag::Isolated => &inputs.peers,
            LinkerModeTag::Hoisted => &[],
        };
        let peers_str = format_peers(effective_peers);
        write_field(&mut hasher, b"peers", peers_str.as_bytes());

        let edges_str = format_deps(&inputs.deps);
        write_field(&mut hasher, b"edges", edges_str.as_bytes());

        let aliases_str = format_aliases(&inputs.aliases);
        write_field(&mut hasher, b"aliases", aliases_str.as_bytes());

        let root_names_str = format_root_link_names(inputs.root_link_names.as_deref());
        write_field(&mut hasher, b"root_link_names", root_names_str.as_bytes());

        // Phase 66 §2.2 — source-identity disambiguation. Empty when
        // wrapper_id is None (registry default), preserving the
        // pre-Phase-66 hash for registry packages so existing v2
        // store entries don't get invalidated by this addition.
        let wrapper_str = inputs.wrapper_id.as_deref().unwrap_or("");
        write_field(&mut hasher, b"wrapper_id", wrapper_str.as_bytes());

        // Phase 66 confidence-followup F1 — patch identity. Empty when
        // unpatched, preserving the pre-F1 hash so unpatched v2 link
        // entries don't get invalidated by this addition. Non-empty
        // for any `(name, version)` covered by a
        // `lpm.patchedDependencies` entry; the caller derives the
        // value from `sha256(patch_bytes || originalIntegrity)` so two
        // semantically identical patches collide on the same hash and
        // share a link entry, while edits to the patch (or to the
        // pinned baseline integrity) split into a fresh entry.
        let patch_str = inputs.patch_fingerprint.as_deref().unwrap_or("");
        write_field(&mut hasher, b"patch_fingerprint", patch_str.as_bytes());

        let digest = hasher.finalize();
        Self {
            name: inputs.name.clone(),
            version: inputs.version.clone(),
            digest: *digest.as_bytes(),
        }
    }

    /// Same semantics as [`Self::derive`] but takes raw component types
    /// directly — bypassing the [`GraphKeyInputs`] / [`DepEdge`] /
    /// [`PeerEntry`] intermediate structs and their string-clone overhead.
    ///
    /// Produces a byte-identical BLAKE3 digest to [`Self::derive`] for
    /// the same logical inputs (invariant enforced by the
    /// `derive_raw_matches_derive` unit test). Prefer this over
    /// `derive` in hot paths that already hold `&LinkTarget` data.
    ///
    /// `raw_deps` — `(local, resolved_version)` pairs from
    ///   `LinkTarget::dependencies`. `aliases` maps each `local` to
    ///   its canonical target name (identity if absent — no alias).
    /// `peers`    — `(canonical_name, resolved_version)` pairs from
    ///   `LinkTarget::peers`.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_raw(
        name: &str,
        version: &str,
        platform: &PlatformTuple,
        linker_tag: LinkerModeTag,
        raw_deps: &[(String, String)],
        aliases: &HashMap<String, String>,
        peers: &[(String, String)],
        root_link_names: Option<&[String]>,
        wrapper_id: Option<&str>,
        patch_fingerprint: Option<&str>,
    ) -> Self {
        debug_assert!(
            !matches!(linker_tag, LinkerModeTag::Hoisted) || peers.is_empty(),
            "GraphKey::derive_raw: hoisted graph keys must not carry peers \
             (collapsing silently in release). Got {} peers for {name}@{version}.",
            peers.len(),
        );

        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::SCHEMA);
        hasher.update(b"\0");

        write_field(&mut hasher, b"name", name.as_bytes());
        write_field(&mut hasher, b"version", version.as_bytes());

        write_platform_direct(&mut hasher, platform);
        write_field(&mut hasher, b"linker", linker_tag.as_str().as_bytes());

        let effective_peers: &[(String, String)] = match linker_tag {
            LinkerModeTag::Isolated => peers,
            LinkerModeTag::Hoisted => &[],
        };
        write_peers_raw_direct(&mut hasher, effective_peers);
        write_deps_raw_direct(&mut hasher, raw_deps, aliases);
        write_aliases_raw_direct(&mut hasher, aliases);

        let root_names_str = format_root_link_names(root_link_names);
        write_field(&mut hasher, b"root_link_names", root_names_str.as_bytes());

        let wrapper_str = wrapper_id.unwrap_or("");
        write_field(&mut hasher, b"wrapper_id", wrapper_str.as_bytes());

        let patch_str = patch_fingerprint.unwrap_or("");
        write_field(&mut hasher, b"patch_fingerprint", patch_str.as_bytes());

        let digest = hasher.finalize();
        Self {
            name: name.to_owned(),
            version: version.to_owned(),
            digest: *digest.as_bytes(),
        }
    }

    /// Reconstruct a `GraphKey` from a previously-recorded digest. Used
    /// when reading a sidecar [`crate::v2::link_meta::LinkMeta`] back
    /// off disk: callers don't always have the original inputs but
    /// still need a `GraphKey` for path computations.
    pub fn from_recorded(
        name: impl Into<String>,
        version: impl Into<String>,
        digest: [u8; 32],
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            digest,
        }
    }

    /// Canonical name component (matches the registry-canonical name).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Exact version component.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Full BLAKE3 digest (256 bits / 32 bytes).
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Lowercase-hex of the full digest. Used by the sidecar so prune
    /// can re-key without re-running [`Self::derive`].
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// First 16 hex chars of the digest — short enough for a directory
    /// suffix while keeping ~64 bits of collision resistance.
    pub fn short_hex(&self) -> String {
        let full = hex::encode(self.digest);
        full[..Self::SHORT_HEX_LEN].to_string()
    }

    /// Filesystem-safe directory name under
    /// `~/.lpm/store/v2/links/<dir>/`. Format: `<safe_name>@<version>+<short_hex>`.
    /// `safe_name` replaces `/` and `\` with `+` so scoped packages
    /// (`@scope/pkg`) become a flat directory name (`@scope+pkg@1.2.3+...`).
    pub fn dir_name(&self) -> String {
        let safe_name = self.name.replace(['/', '\\'], "+");
        format!("{}@{}+{}", safe_name, self.version, self.short_hex())
    }
}

fn write_field(hasher: &mut blake3::Hasher, label: &[u8], value: &[u8]) {
    hasher.update(label);
    hasher.update(b"=");
    hasher.update(value);
    hasher.update(b"\0");
}

fn format_platform(p: &PlatformTuple) -> String {
    match &p.libc {
        Some(libc) => format!("{}/{}/{}", p.os, p.cpu, libc),
        None => format!("{}/{}/", p.os, p.cpu),
    }
}

fn format_peers(peers: &[PeerEntry]) -> String {
    if peers.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<String> = peers
        .iter()
        .map(|p| format!("{}@{}", p.name, p.version))
        .collect();
    sorted.sort();
    sorted.join(",")
}

fn format_deps(deps: &[DepEdge]) -> String {
    if deps.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<String> = deps
        .iter()
        .map(|d| format!("{}=>{}@{}", d.local, d.target_name, d.target_version))
        .collect();
    sorted.sort();
    sorted.join(",")
}

fn format_aliases(aliases: &BTreeMap<String, String>) -> String {
    if aliases.is_empty() {
        return String::new();
    }
    aliases
        .iter()
        .map(|(local, canonical)| format!("{local}=>{canonical}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_root_link_names(names: Option<&[String]>) -> Cow<'static, str> {
    match names {
        // Distinguishable encoding: `None` (use linker default) vs
        // `Some(vec![])` (explicit empty) vs `Some(vec!["a","b"])`.
        // `None` hashes as the empty marker; `Some([])` hashes with
        // a sentinel prefix so the two states yield different keys.
        //
        // `Cow::Borrowed` for the constant cases avoids a heap allocation
        // per package (~40-50 packages in a typical install have None here).
        None => Cow::Borrowed(""),
        Some([]) => Cow::Borrowed("<explicit-empty>"),
        Some(list) => {
            let mut sorted: Vec<&str> = list.iter().map(String::as_str).collect();
            sorted.sort_unstable();
            Cow::Owned(sorted.join(","))
        }
    }
}

// ── Direct-write helpers for derive_raw ─────────────────────────────────────
// Stream bytes directly into the BLAKE3 hasher, eliminating the intermediate
// String allocations of the old format_*_raw → write_field pattern.
// Each function writes the full field (label + "=" + value + "\0").
// Sort order is byte-identical to sorted-string approach — verified by the
// derive_raw_matches_derive* parity tests.

fn write_platform_direct(hasher: &mut blake3::Hasher, p: &PlatformTuple) {
    hasher.update(b"platform=");
    hasher.update(p.os.as_bytes());
    hasher.update(b"/");
    hasher.update(p.cpu.as_bytes());
    hasher.update(b"/");
    if let Some(libc) = &p.libc {
        hasher.update(libc.as_bytes());
    }
    hasher.update(b"\0");
}

fn write_peers_raw_direct(hasher: &mut blake3::Hasher, peers: &[(String, String)]) {
    hasher.update(b"peers=");
    if !peers.is_empty() {
        let mut sorted: Vec<(&str, &str)> =
            peers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        // Must sort by the byte sequence "name@ver", not by (name, ver) tuple.
        // Tuple sort puts "react" before "react-dom" (prefix is shorter);
        // string sort of "react@v" vs "react-dom@v" puts "react-dom" first
        // because '-' (0x2D) < '@' (0x40) at position 5. The comparator below
        // simulates string sort without allocating the formatted strings.
        sorted.sort_unstable_by(|(a_name, a_ver), (b_name, b_ver)| {
            a_name
                .bytes()
                .chain(std::iter::once(b'@'))
                .chain(a_ver.bytes())
                .cmp(
                    b_name
                        .bytes()
                        .chain(std::iter::once(b'@'))
                        .chain(b_ver.bytes()),
                )
        });
        for (i, (name, ver)) in sorted.iter().enumerate() {
            if i > 0 {
                hasher.update(b",");
            }
            hasher.update(name.as_bytes());
            hasher.update(b"@");
            hasher.update(ver.as_bytes());
        }
    }
    hasher.update(b"\0");
}

fn write_deps_raw_direct(
    hasher: &mut blake3::Hasher,
    deps: &[(String, String)],
    aliases: &HashMap<String, String>,
) {
    hasher.update(b"edges=");
    if !deps.is_empty() {
        let mut sorted: Vec<(&str, &str, &str)> = deps
            .iter()
            .map(|(local, ver)| {
                let canonical = aliases
                    .get(local)
                    .map(|s| s.as_str())
                    .unwrap_or(local.as_str());
                (local.as_str(), canonical, ver.as_str())
            })
            .collect();
        // Sort by "local=>canonical@ver" byte sequence to match the old string sort.
        sorted.sort_unstable_by(|(a_local, a_can, a_ver), (b_local, b_can, b_ver)| {
            a_local
                .bytes()
                .chain(b"=>".iter().copied())
                .chain(a_can.bytes())
                .chain(std::iter::once(b'@'))
                .chain(a_ver.bytes())
                .cmp(
                    b_local
                        .bytes()
                        .chain(b"=>".iter().copied())
                        .chain(b_can.bytes())
                        .chain(std::iter::once(b'@'))
                        .chain(b_ver.bytes()),
                )
        });
        for (i, (local, canonical, ver)) in sorted.iter().enumerate() {
            if i > 0 {
                hasher.update(b",");
            }
            hasher.update(local.as_bytes());
            hasher.update(b"=>");
            hasher.update(canonical.as_bytes());
            hasher.update(b"@");
            hasher.update(ver.as_bytes());
        }
    }
    hasher.update(b"\0");
}

fn write_aliases_raw_direct(hasher: &mut blake3::Hasher, aliases: &HashMap<String, String>) {
    hasher.update(b"aliases=");
    if !aliases.is_empty() {
        let mut sorted: Vec<(&str, &str)> = aliases
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        sorted.sort_unstable_by_key(|(k, _)| *k);
        for (i, (local, canonical)) in sorted.iter().enumerate() {
            if i > 0 {
                hasher.update(b",");
            }
            hasher.update(local.as_bytes());
            hasher.update(b"=>");
            hasher.update(canonical.as_bytes());
        }
    }
    hasher.update(b"\0");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macos_arm64() -> PlatformTuple {
        PlatformTuple::new("darwin", "arm64", None)
    }

    fn linux_x64_glibc() -> PlatformTuple {
        PlatformTuple::new("linux", "x64", Some("glibc".into()))
    }

    fn linux_x64_musl() -> PlatformTuple {
        PlatformTuple::new("linux", "x64", Some("musl".into()))
    }

    fn base_inputs() -> GraphKeyInputs {
        GraphKeyInputs::new("react", "18.3.0", macos_arm64(), LinkerModeTag::Isolated)
    }

    #[test]
    fn determinism_same_inputs_same_key() {
        let a = GraphKey::derive(&base_inputs());
        let b = GraphKey::derive(&base_inputs());
        assert_eq!(a, b);
        assert_eq!(a.dir_name(), b.dir_name());
    }

    #[test]
    fn input_order_does_not_affect_key() {
        // Peer order shouldn't matter — same set of peers in different
        // order produces the same key.
        let p1 = PeerEntry {
            name: "react".into(),
            version: "18.3.0".into(),
        };
        let p2 = PeerEntry {
            name: "react-dom".into(),
            version: "18.3.0".into(),
        };
        let ordered = base_inputs().with_peers([p1.clone(), p2.clone()]);
        let reversed = base_inputs().with_peers([p2.clone(), p1.clone()]);
        assert_eq!(GraphKey::derive(&ordered), GraphKey::derive(&reversed));
    }

    #[test]
    fn dep_edge_order_does_not_affect_key() {
        let d1 = DepEdge {
            local: "scheduler".into(),
            target_name: "scheduler".into(),
            target_version: "0.23.0".into(),
        };
        let d2 = DepEdge {
            local: "loose-envify".into(),
            target_name: "loose-envify".into(),
            target_version: "1.4.0".into(),
        };
        let a = base_inputs().with_deps([d1.clone(), d2.clone()]);
        let b = base_inputs().with_deps([d2.clone(), d1.clone()]);
        assert_eq!(GraphKey::derive(&a), GraphKey::derive(&b));
    }

    #[test]
    fn different_libc_yields_different_key() {
        let glibc = GraphKeyInputs::new(
            "esbuild",
            "0.21.0",
            linux_x64_glibc(),
            LinkerModeTag::Isolated,
        );
        let musl = GraphKeyInputs::new(
            "esbuild",
            "0.21.0",
            linux_x64_musl(),
            LinkerModeTag::Isolated,
        );
        assert_ne!(GraphKey::derive(&glibc), GraphKey::derive(&musl));
    }

    #[test]
    fn different_linker_mode_yields_different_key() {
        let isolated = GraphKey::derive(&base_inputs());
        let hoisted = {
            let mut i = base_inputs();
            i.linker_mode = LinkerModeTag::Hoisted;
            GraphKey::derive(&i)
        };
        assert_ne!(isolated, hoisted);
    }

    #[test]
    fn alias_change_yields_different_key() {
        // Preplan §2.2 lock-in: aliases are identity-bearing even when
        // the dep edges are otherwise identical. A consumer that
        // declares `"strip-ansi-cjs": "npm:strip-ansi@^6"` materializes
        // a different wrapper than one that just declares `strip-ansi`.
        let no_alias = base_inputs();
        let with_alias = base_inputs().with_aliases([("strip-ansi-cjs", "strip-ansi")]);
        assert_ne!(GraphKey::derive(&no_alias), GraphKey::derive(&with_alias));
    }

    #[test]
    fn root_link_names_distinguishes_none_vs_empty_vs_set() {
        let none_inputs = base_inputs();
        let mut explicit_empty = base_inputs();
        explicit_empty.root_link_names = Some(vec![]);
        let mut named = base_inputs();
        named.root_link_names = Some(vec!["react".into()]);

        let k_none = GraphKey::derive(&none_inputs);
        let k_empty = GraphKey::derive(&explicit_empty);
        let k_named = GraphKey::derive(&named);

        assert_ne!(k_none, k_empty);
        assert_ne!(k_none, k_named);
        assert_ne!(k_empty, k_named);
    }

    #[test]
    fn name_or_version_change_yields_different_key() {
        let a = GraphKey::derive(&base_inputs());
        let mut other_name = base_inputs();
        other_name.name = "preact".into();
        let mut other_ver = base_inputs();
        other_ver.version = "18.3.1".into();
        assert_ne!(a, GraphKey::derive(&other_name));
        assert_ne!(a, GraphKey::derive(&other_ver));
    }

    #[test]
    fn dir_name_format_is_safe_for_scoped_packages() {
        let inputs = GraphKeyInputs::new(
            "@types/node",
            "20.10.0",
            macos_arm64(),
            LinkerModeTag::Isolated,
        );
        let key = GraphKey::derive(&inputs);
        let dir = key.dir_name();
        assert!(dir.starts_with("@types+node@20.10.0+"));
        assert!(!dir.contains('/'));
        assert!(!dir.contains('\\'));
    }

    #[test]
    fn short_hex_is_prefix_of_digest_hex() {
        let key = GraphKey::derive(&base_inputs());
        let full = key.digest_hex();
        let short = key.short_hex();
        assert_eq!(short.len(), GraphKey::SHORT_HEX_LEN);
        assert!(full.starts_with(&short));
    }

    #[test]
    fn from_recorded_round_trips_digest() {
        let key = GraphKey::derive(&base_inputs());
        let recreated = GraphKey::from_recorded(key.name(), key.version(), *key.digest());
        assert_eq!(key, recreated);
        assert_eq!(key.dir_name(), recreated.dir_name());
    }

    #[test]
    fn alias_with_same_logical_set_produces_same_key() {
        // BTreeMap construction order shouldn't matter — both inputs
        // describe the same alias set.
        let a = base_inputs().with_aliases([("foo", "bar"), ("baz", "qux")]);
        let b = base_inputs().with_aliases([("baz", "qux"), ("foo", "bar")]);
        assert_eq!(GraphKey::derive(&a), GraphKey::derive(&b));
    }

    // ── R2.3 — peer-divergent installs MUST produce distinct keys ──
    //
    // **Load-bearing for R2.2.** If two projects (or the same project
    // across reinstalls) have identical dep edges + linker mode +
    // platform but differ in WHICH version of a peer they pinned,
    // they are semantically different materializations: each
    // consumer's runtime sees a different peer instance. The v2
    // store's per-graph-key link entries MUST be distinct so the
    // copies of the consumer's bytes don't share state across
    // peer-divergent installs.
    //
    // Pre-R2.2 the resolver didn't auto-install peers, so the
    // distinction rarely surfaced — most peer-declared packages
    // either errored out or relied on the user to install a peer
    // version manually, and the consumer's GraphKey-input `peers` was
    // empty in either case. R2.2 makes auto-install the default, so
    // the same consumer (e.g., react-redux) can land with react@18 in
    // project A and react@19 in project B from the same lockfile-fast-
    // path entry. The link-entry isolation has to work.

    #[test]
    fn r23_different_peer_versions_yield_different_keys() {
        // Same consumer, same dep edges, same linker mode, same
        // platform. Only the peer pin differs. Keys must diverge so
        // the link entries can't share bytes across peer-divergent
        // installs.
        let consumer_with_react_18 = base_inputs().with_peers([PeerEntry {
            name: "react".into(),
            version: "18.3.1".into(),
        }]);
        let consumer_with_react_19 = base_inputs().with_peers([PeerEntry {
            name: "react".into(),
            version: "19.0.0".into(),
        }]);
        assert_ne!(
            GraphKey::derive(&consumer_with_react_18),
            GraphKey::derive(&consumer_with_react_19),
            "peer-version divergence MUST split link entries — without this, \
             two projects pinning different react majors would share a \
             single materialization of the consumer's bytes and the v2 \
             store would silently corrupt cross-project peer isolation"
        );
    }

    #[test]
    fn r23_different_peer_names_yield_different_keys() {
        // Two consumers with same dep edges but different peer SETS
        // (not just versions). E.g., one peers `react` only; the
        // other peers both `react` and `react-dom`. The keys must
        // distinguish these — the consumer's runtime context differs
        // by which peers are in scope.
        let only_react = base_inputs().with_peers([PeerEntry {
            name: "react".into(),
            version: "18.3.1".into(),
        }]);
        let react_and_dom = base_inputs().with_peers([
            PeerEntry {
                name: "react".into(),
                version: "18.3.1".into(),
            },
            PeerEntry {
                name: "react-dom".into(),
                version: "18.3.1".into(),
            },
        ]);
        assert_ne!(
            GraphKey::derive(&only_react),
            GraphKey::derive(&react_and_dom),
            "different peer sets must split link entries"
        );
    }

    // ── F1 — patch_fingerprint identity ─────────────────────────────
    //
    // **Load-bearing for cross-project patch isolation.** Two projects
    // with identical dep edges + linker mode + platform + peers
    // resolve to the same v2 link entry by design (preplan §2.2 — the
    // sharing invariant unlocks the v2 install hot path). That sharing
    // means project A's mutation of `<store>/v2/links/<key>/...`
    // would propagate to project B via shared materialization. The
    // F1 fix folds patch identity into the key so a patched install
    // gets its own link entry and never collides with an unpatched
    // install (or a different-patch install) of the same coords.

    #[test]
    fn f1_patched_vs_unpatched_yields_different_keys() {
        let unpatched = base_inputs();
        let patched = base_inputs().with_patch_fingerprint(Some("p-deadbeefdeadbeef".into()));
        assert_ne!(
            GraphKey::derive(&unpatched),
            GraphKey::derive(&patched),
            "an installed-with-patch wrapper MUST be distinct from an \
             unpatched wrapper of the same coords — without this, \
             project A's patched bytes leak into project B via shared \
             v2 link materialization"
        );
    }

    #[test]
    fn f1_different_patch_fingerprints_yield_different_keys() {
        let patch_a = base_inputs().with_patch_fingerprint(Some("p-aaaaaaaaaaaaaaaa".into()));
        let patch_b = base_inputs().with_patch_fingerprint(Some("p-bbbbbbbbbbbbbbbb".into()));
        assert_ne!(
            GraphKey::derive(&patch_a),
            GraphKey::derive(&patch_b),
            "different patch contents (or different originalIntegrity \
             baselines) MUST split link entries"
        );
    }

    #[test]
    fn f1_same_patch_fingerprint_collides_for_sharing() {
        // Two projects applying the SAME patch with the SAME baseline
        // SHOULD share a single link entry — that's the whole point
        // of content-derived fingerprinting. Re-applying byte-identical
        // patches across projects is safe and expensive to duplicate.
        let p1 = base_inputs().with_patch_fingerprint(Some("p-1234567890abcdef".into()));
        let p2 = base_inputs().with_patch_fingerprint(Some("p-1234567890abcdef".into()));
        assert_eq!(GraphKey::derive(&p1), GraphKey::derive(&p2));
    }

    #[test]
    fn f1_unpatched_key_unchanged_by_field_addition() {
        // Defense-in-depth check: the empty-fingerprint default
        // hashes the same way the explicit `with_patch_fingerprint(None)`
        // call does. Together with the empty-string-on-None encoding
        // in `derive`, this preserves the pre-F1 hash for unpatched
        // registry packages so existing on-disk link entries stay
        // valid after the upgrade.
        let default = base_inputs();
        let explicit_none = base_inputs().with_patch_fingerprint(None);
        assert_eq!(GraphKey::derive(&default), GraphKey::derive(&explicit_none));
    }

    #[test]
    fn r23_no_peers_vs_one_peer_yields_different_keys() {
        // Empty peer set vs single-peer set must differ. Important
        // because a consumer with no peer requirements at all
        // (post-R5 optional-peer skip → empty peers field) must NOT
        // collide with a consumer that has the same dep tree plus a
        // single resolved peer.
        let no_peers = base_inputs();
        let one_peer = base_inputs().with_peers([PeerEntry {
            name: "react".into(),
            version: "18.3.1".into(),
        }]);
        assert_ne!(
            GraphKey::derive(&no_peers),
            GraphKey::derive(&one_peer),
            "empty-peer-set must differ from non-empty-peer-set"
        );
    }

    // ── Parity: derive_raw must produce byte-identical keys to derive ─────────

    #[test]
    fn derive_raw_matches_derive_no_extras() {
        // Minimal inputs (no deps, no peers, no aliases).
        let inputs = base_inputs();
        let via_struct = GraphKey::derive(&inputs);
        let via_raw = GraphKey::derive_raw(
            "react",
            "18.3.0",
            &macos_arm64(),
            LinkerModeTag::Isolated,
            &[],
            &HashMap::new(),
            &[],
            None,
            None,
            None,
        );
        assert_eq!(
            via_struct, via_raw,
            "derive_raw must match derive for zero-extra inputs"
        );
    }

    #[test]
    fn derive_raw_matches_derive_with_deps_and_peers() {
        // Full inputs: deps (including aliased), peers, root_link_names,
        // wrapper_id, patch_fingerprint.
        let aliases: HashMap<String, String> =
            [("strip-ansi-cjs".to_owned(), "strip-ansi".to_owned())]
                .into_iter()
                .collect();
        let platform = macos_arm64();

        // Build via GraphKeyInputs (existing API).
        let inputs = GraphKeyInputs::new("foo", "2.0.0", platform.clone(), LinkerModeTag::Isolated)
            .with_deps([
                DepEdge {
                    local: "debug".into(),
                    target_name: "debug".into(),
                    target_version: "4.3.4".into(),
                },
                DepEdge {
                    local: "strip-ansi-cjs".into(),
                    target_name: "strip-ansi".into(),
                    target_version: "6.0.1".into(),
                },
            ])
            .with_aliases([("strip-ansi-cjs".to_owned(), "strip-ansi".to_owned())])
            .with_peers([PeerEntry {
                name: "react".into(),
                version: "18.3.0".into(),
            }])
            .with_root_link_names(Some(vec!["foo".into()]))
            .with_wrapper_id(Some("tarball+https://example.com/foo.tgz".into()))
            .with_patch_fingerprint(Some("p-abc123".into()));
        let via_struct = GraphKey::derive(&inputs);

        // Build via derive_raw (optimised path).
        let raw_deps = vec![
            ("debug".to_owned(), "4.3.4".to_owned()),
            ("strip-ansi-cjs".to_owned(), "6.0.1".to_owned()),
        ];
        let peers = vec![("react".to_owned(), "18.3.0".to_owned())];
        let root_names = vec!["foo".to_owned()];
        let via_raw = GraphKey::derive_raw(
            "foo",
            "2.0.0",
            &platform,
            LinkerModeTag::Isolated,
            &raw_deps,
            &aliases,
            &peers,
            Some(&root_names),
            Some("tarball+https://example.com/foo.tgz"),
            Some("p-abc123"),
        );
        assert_eq!(
            via_struct, via_raw,
            "derive_raw must produce identical key to derive for full inputs"
        );
    }

    #[test]
    fn derive_raw_peer_sort_prefix_name_matches_string_sort() {
        // "react-dom@v" sorts BEFORE "react@v" as a string ('-' 0x2D < '@' 0x40),
        // but a naive tuple sort ("react","v") vs ("react-dom","v") puts "react"
        // first because it's a shorter prefix.  write_peers_raw_direct MUST use
        // string sort (the custom byte-streaming comparator) so it stays
        // byte-identical to the format_peers / derive path.
        let platform = macos_arm64();
        let via_struct = GraphKey::derive(
            &GraphKeyInputs::new("pkg", "1.0.0", platform.clone(), LinkerModeTag::Isolated)
                .with_peers([
                    PeerEntry {
                        name: "react".into(),
                        version: "18.3.0".into(),
                    },
                    PeerEntry {
                        name: "react-dom".into(),
                        version: "18.3.0".into(),
                    },
                ]),
        );
        let raw_forward = GraphKey::derive_raw(
            "pkg",
            "1.0.0",
            &platform,
            LinkerModeTag::Isolated,
            &[],
            &HashMap::new(),
            &[
                ("react".to_owned(), "18.3.0".to_owned()),
                ("react-dom".to_owned(), "18.3.0".to_owned()),
            ],
            None,
            None,
            None,
        );
        let raw_reverse = GraphKey::derive_raw(
            "pkg",
            "1.0.0",
            &platform,
            LinkerModeTag::Isolated,
            &[],
            &HashMap::new(),
            &[
                ("react-dom".to_owned(), "18.3.0".to_owned()),
                ("react".to_owned(), "18.3.0".to_owned()),
            ],
            None,
            None,
            None,
        );
        assert_eq!(
            via_struct, raw_forward,
            "derive and derive_raw (forward) must match for prefix-named peers"
        );
        assert_eq!(
            raw_forward, raw_reverse,
            "derive_raw must be order-independent for prefix-named peers (react vs react-dom)"
        );
    }
}
