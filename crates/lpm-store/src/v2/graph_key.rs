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

use std::collections::BTreeMap;

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
        }
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

        let digest = hasher.finalize();
        Self {
            name: inputs.name.clone(),
            version: inputs.version.clone(),
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

fn format_root_link_names(names: Option<&[String]>) -> String {
    match names {
        // Distinguishable encoding: `None` (use linker default) vs
        // `Some(vec![])` (explicit empty) vs `Some(vec!["a","b"])`.
        // `None` hashes as the empty marker; `Some([])` hashes with
        // a sentinel prefix so the two states yield different keys.
        None => String::new(),
        Some([]) => "<explicit-empty>".to_string(),
        Some(list) => {
            let mut sorted: Vec<&String> = list.iter().collect();
            sorted.sort();
            sorted.into_iter().cloned().collect::<Vec<_>>().join(",")
        }
    }
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
}
