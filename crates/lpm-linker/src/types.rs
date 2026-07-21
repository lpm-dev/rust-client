use crate::layout::LayoutPaths;
use std::collections::HashMap;
use std::path::PathBuf;

/// Per-package link outcome — exposes Stage 1 action + Stage 2
/// symlink count to the event-driven caller so totals match the
/// single-shot [`link_packages`] path.
#[derive(Debug, Default, Clone, Copy)]
pub struct OnePackageResult {
    /// `true` if Stage 1 freshly linked the package; `false` if the
    /// incremental `.linked` marker caused a skip.
    pub linked: bool,
    /// Stage 2 internal-symlink count for this package (one per entry in
    /// the package's `dependencies` that wasn't already symlinked).
    pub symlinks_created: usize,
}

/// Final-stage result — Stage 3 root symlinks + Stage 3.5
/// self-reference + Stage 4 `.bin` creation, aggregated into the tail
/// end of the `LinkResult` that [`link_packages`] returns.
#[derive(Debug, Default)]
pub struct FinalizeResult {
    /// Stage 3 + 3.5 symlink count (direct-dep root symlinks + optional
    /// self-reference).
    pub symlinks_created: usize,
    /// Stage 4 `.bin` entries created.
    pub bin_count: usize,
    /// `true` iff the self-reference symlink at `node_modules/<self>`
    /// was created on this call.
    pub self_referenced: bool,
}
/// Linking strategy for node_modules.
///
/// The default is [`Hoisted`]. With the v2 store, both modes symlink
/// project `node_modules/<dep>` entries into shared
/// `~/.lpm/store/v2/links/<graph-key>/` materializations, so warm
/// installs are equivalent while hoisted keeps npm-compatible root
/// links for declared dependencies.
///
/// `Hoisted` gives users:
///
/// - Faster cold installs on large fixtures.
/// - Same warm-install shape as isolated with v2 store links.
/// - npm-compatible root links for declared dependencies while keeping
///   v2 transitives inside their shared link entries instead of
///   flattening every transitive to the project root.
///
/// [`Isolated`] remains a valid opt-in via `LPM_LINKER=isolated`,
/// `package.json > lpm > linker`, `~/.lpm/config.toml > linker`,
/// or `--linker isolated`. Use it when you want strict
/// no-phantom-deps semantics — the layout that catches "I forgot
/// to declare this dep" bugs early.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum LinkerMode {
    /// pnpm-style isolated layout. Strict, no phantom deps.
    /// Available via explicit `--linker isolated` /
    /// `LPM_LINKER=isolated` / `package.json > lpm > linker`.
    Isolated,
    /// v2 hoisted virtual-store layout. Root dependencies are linked at
    /// project `node_modules`, while transitives are hoisted within shared
    /// link entries rather than flattened to the project root. Default.
    #[default]
    Hoisted,
}

impl LinkerMode {
    /// Accepted string values across every config surface: the `--linker`
    /// CLI flag (clamped at parse time by clap), `package.json > lpm > linker`,
    /// `~/.lpm/config.toml > linker`, and the `LPM_LINKER` env var.
    pub const ACCEPTED_VALUES: &'static [&'static str] = &["isolated", "hoisted"];

    /// Parse a linker mode string from any non-CLI config surface
    /// (`package.json`, `config.toml`, env). Unknown values produce a
    /// human-readable error so the install entry point can surface them
    /// loudly before any work begins. The CLI surface is parsed by clap
    /// directly via the `LinkerCli` value-enum and never reaches this
    /// function as a free string.
    pub fn parse_str(s: &str) -> Result<Self, String> {
        match s {
            "isolated" => Ok(Self::Isolated),
            "hoisted" => Ok(Self::Hoisted),
            other => Err(format!(
                "unknown linker mode {other:?}. Accepted values: {accepted}.",
                accepted = Self::ACCEPTED_VALUES
                    .iter()
                    .map(|v| format!("{v:?}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
        }
    }

    /// Stable string representation that round-trips through `parse_str`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Hoisted => "hoisted",
        }
    }
}

#[cfg(test)]
mod linker_mode_tests {
    use super::LinkerMode;

    #[test]
    fn parse_str_accepts_canonical_values() {
        assert_eq!(
            LinkerMode::parse_str("isolated").unwrap(),
            LinkerMode::Isolated
        );
        assert_eq!(
            LinkerMode::parse_str("hoisted").unwrap(),
            LinkerMode::Hoisted
        );
    }

    #[test]
    fn parse_str_rejects_legacy_symlink_alias() {
        // "symlink" was documented as a legacy alias on the package.json
        // schema but never recognized by the install dispatch — typing it
        // silently fell back to Isolated. The new contract is fail-loud.
        let err = LinkerMode::parse_str("symlink").unwrap_err();
        assert!(err.contains("unknown linker mode"));
        assert!(err.contains("\"isolated\""));
        assert!(err.contains("\"hoisted\""));
    }

    #[test]
    fn parse_str_rejects_typos_loudly() {
        for bad in ["hosited", "Isolated", "HOISTED", "", " hoisted ", "default"] {
            let err = LinkerMode::parse_str(bad).unwrap_err();
            assert!(
                err.contains("unknown linker mode"),
                "value {bad:?} should reject"
            );
        }
    }

    #[test]
    fn as_str_round_trips() {
        for mode in [LinkerMode::Isolated, LinkerMode::Hoisted] {
            assert_eq!(LinkerMode::parse_str(mode.as_str()).unwrap(), mode);
        }
    }
}
/// Drives the materialization branch in [`link_one_package`].
///
/// Decoupled from [`LinkTarget::wrapper_id`] so tarball sources can
/// carry a wrapper_id (for collision-free `.lpm/<safe>+<wrapper_id>/`
/// segments) WITHOUT inheriting the directory-source per-file-symlink
/// materialization. Using `wrapper_id.is_some()` as the proxy stopped
/// working once Tarball started using it for cross-source collision
/// avoidance — these two concerns need separate fields.
///
/// The default ([`Materialization::CasBacked`]) matches the legacy
/// behavior for every CAS-backed source (Registry, Tarball remote,
/// Tarball local, Git): clonefile / hardlink / copy from
/// [`LinkTarget::store_path`] (which lives inside the global CAS
/// store).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Materialization {
    /// CAS-backed: [`link_dir_recursive`] copies the package tree
    /// from the global store into the wrapper. Used for Registry,
    /// Tarball (remote + local), and Git sources.
    #[default]
    CasBacked,
    /// Local-source directory: [`materialize_directory_source`]
    /// builds the wrapper as per-file absolute symlinks pointing at
    /// `store_path` (the source's realpath, OUTSIDE the global
    /// store). Used for `Source::Directory` (`file:`) and
    /// `Source::Link` (`link:`). Edits to the source are visible
    /// through the wrapper without re-running `lpm install`.
    DirectorySource,
}

/// One dependency edge inside a linked package.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkDependency {
    /// Name used by the consumer package in `require()` / `import`.
    pub local: String,
    /// Canonical package name of the target package.
    pub target_name: String,
    /// Exact version of the target package.
    pub target_version: String,
    /// Source wrapper identity for non-registry targets. `None`
    /// means the edge targets the registry/CAS-backed
    /// `<target_name>@<target_version>` instance.
    pub target_wrapper_id: Option<String>,
}

impl LinkDependency {
    pub fn new(
        local: impl Into<String>,
        target_name: impl Into<String>,
        target_version: impl Into<String>,
        target_wrapper_id: Option<String>,
    ) -> Self {
        Self {
            local: local.into(),
            target_name: target_name.into(),
            target_version: target_version.into(),
            target_wrapper_id,
        }
    }

    pub fn registry(local: impl Into<String>, target_version: impl Into<String>) -> Self {
        let local = local.into();
        Self {
            target_name: local.clone(),
            local,
            target_version: target_version.into(),
            target_wrapper_id: None,
        }
    }

    #[inline]
    pub(crate) fn graph_key_value(&self) -> &str {
        self.target_wrapper_id
            .as_deref()
            .unwrap_or(&self.target_version)
    }

    #[inline]
    pub(crate) fn wrapper_segment(&self) -> String {
        let safe_target = self.target_name.replace('/', "+");
        match self.target_wrapper_id.as_deref() {
            Some(wrapper_id) => format!("{safe_target}+{wrapper_id}"),
            None => format!("{safe_target}@{}", self.target_version),
        }
    }
}

/// A package to be linked into node_modules.
#[derive(Debug, Clone)]
pub struct LinkTarget {
    /// Canonical registry package name (e.g., "express", "@types/node").
    /// Used as the `.lpm/<name>@<version>/node_modules/<name>/` key and
    /// the default root-symlink filename for non-aliased direct deps.
    pub name: String,
    /// Exact version string.
    pub version: String,
    /// Path to the package in the global store.
    pub store_path: PathBuf,
    /// Dependencies of this package.
    ///
    /// Each edge records the local import name plus the target's
    /// package identity. Registry/CAS-backed edges target
    /// `<target_name>@<target_version>`; source-backed edges also
    /// carry `target_wrapper_id` so same-name same-version packages
    /// from different sources remain distinct.
    pub dependencies: Vec<LinkDependency>,
    /// npm-alias edges: `local_name → target_canonical_name`.
    /// Populated only for local names that refer to a different
    /// registry-canonical target than themselves (the common case is
    /// empty). Kept in the graph-key input so alias-shaped installs
    /// do not share link entries with canonical-name installs.
    pub aliases: HashMap<String, String>,
    /// Whether this is a direct dependency of the root project.
    ///
    /// Used for lifecycle-script filtering and display purposes. For
    /// Stage 3 root-symlink creation, the linker consults
    /// [`Self::root_link_names`] instead — that field expresses the
    /// alias-aware "what filenames do I get at the project root"
    /// contract, including the (rare) case of a single package
    /// referenced by its canonical name AND by one or more aliases at
    /// the same version.
    pub is_direct: bool,
    /// Explicit list of `node_modules/<entry>/`
    /// symlinks to create at the project root for this package.
    ///
    /// Callers may leave this `None` to get the legacy-compatible
    /// default: Stage 3 creates a single `node_modules/<name>/`
    /// symlink when `is_direct` is true, nothing otherwise. Callers
    /// that have alias info from the resolver set this to
    /// `Some(vec![...])`:
    ///
    /// - `Some([pkg.name])`: regular direct dep (equivalent to the
    ///   default, but explicit).
    /// - `Some([local])` where `local != pkg.name`: aliased root dep —
    ///   the consumer declared `"local": "npm:<pkg.name>@<range>"`.
    ///   Stage 3 creates `node_modules/<local>/` with the target set to
    ///   `.lpm/<pkg.name>@<version>/node_modules/<pkg.name>/`.
    /// - `Some([name, alias1, ...])`: the same resolved `(name,
    ///   version)` is referenced from the root under multiple names
    ///   (canonical plus one or more aliases). One symlink per entry.
    /// - `Some([])`: never a root dep, no root symlink. Distinguishes
    ///   "explicitly zero" from "use the default."
    ///
    /// When `Some`, the `is_direct` flag is ignored for Stage 3
    /// purposes; `is_direct` is still consulted elsewhere (lifecycle
    /// filtering, display). When `None`, Stage 3 falls back to the
    /// `is_direct ? [name] : []` default.
    pub root_link_names: Option<Vec<String>>,
    /// When `Some`, the `.lpm/` wrapper segment is
    /// `<safe_name>+<wrapper_id>` instead of `<safe_name>@<version>`.
    /// Used for any source whose `(name, version)` could collide
    /// with another source kind — every NON-Registry source.
    /// Required so `Source::Registry { foo@1.0.0 }` and
    /// `Source::Tarball { foo@1.0.0 from custom URL }` stay distinct
    /// in the wrapper tree.
    ///
    /// Materialization strategy is controlled by the orthogonal
    /// [`LinkTarget::materialization`] field, NOT
    /// `wrapper_id.is_some()`.
    ///
    /// The `+` separator visually distinguishes wrapped sources from
    /// unwrapped (Registry-only) deps in the `.lpm/` tree. Node
    /// module resolution from inside the wrapped package walks
    /// ancestors that stay inside the consumer's `node_modules/`
    /// tree, so transitive deps resolve correctly (which a direct
    /// `node_modules/<name>` symlink at the source realpath would
    /// NOT achieve).
    ///
    /// `None` for `Source::Registry` only — registry deps are
    /// keyed by `(name, version)` alone (no cross-source collision
    /// risk because no other source kind shares the registry
    /// namespace).
    ///
    /// `wrapper_id` is opaque to the linker — typically the source's
    /// `lpm_lockfile::Source::source_id()` output (e.g., `"f-{16hex}"`
    /// for Directory, `"l-{16hex}"` for Link, `"t-{16hex}"` for
    /// Tarball). The linker accepts whatever the caller supplies;
    /// correctness depends on the caller producing a stable,
    /// collision-free identifier per `(name, version)` group.
    pub wrapper_id: Option<String>,
    /// Drives the materialization branch in [`link_one_package`].
    /// See [`Materialization`] for the full contract.
    ///
    /// Defaults to [`Materialization::CasBacked`] — every source kind
    /// EXCEPT `Source::Directory` and `Source::Link` materializes
    /// from the global CAS store via [`link_dir_recursive`].
    pub materialization: Materialization,
    /// Resolved peers in scope for this package's instance in the
    /// install graph.
    ///
    /// Each binding is an exact registry version or a non-registry source
    /// wrapper ID. Entries are sorted by peer name.
    /// Empty under any of:
    /// - The package declares no peers in its `package.json`.
    /// - All declared peers are absent from the install set
    ///   (`check_unmet_peers` surfaces those upstream).
    /// - The lockfile fast-path constructed this LinkTarget (peers
    ///   not persisted in the lockfile today; v2 linker re-derives
    ///   from the extracted `package.json` when needed).
    ///
    /// **Used by the v2 isolated linker** to:
    /// 1. Synthesize peer-edge sibling symlinks inside each link
    ///    entry (peer must be a sibling of the consumer's package
    ///    dir for Node's symlink-walk-up resolution).
    /// 2. Fold into [`lpm_store::v2::GraphKeyInputs::with_peers`] so
    ///    two projects with the same edge graph but different peer
    ///    pinning produce distinct graph keys (the cross-project
    ///    cross-project sharing invariant).
    ///
    /// **Ignored under v1** — v1's relative-symlink wrappers walk
    /// up to the project root for peers, so threading is
    /// informational. The field is populated regardless so a future
    /// hoisted-mode v1 wanting to share wrappers across projects
    /// can fold it in.
    pub peers: Vec<(String, String)>,
    /// Patch identity, plumbed through to v2's
    /// [`GraphKeyInputs::patch_fingerprint`].
    ///
    /// `Some("p-<16hex>")` when the install pipeline detected a
    /// `lpm.patchedDependencies` entry covering this `(name, version)`,
    /// `None` otherwise. The 16-hex suffix is the first 16 chars of
    /// `sha256(patch_bytes || originalIntegrity)` — content-derived so
    /// (a) two projects applying byte-identical patches share a single
    /// link entry, and (b) any edit to the patch text or to the pinned
    /// baseline integrity splits into a fresh entry.
    ///
    /// **Ignored under v1.** v1 wrappers live at `<project>/.lpm/<seg>/`,
    /// already project-private, so cross-project mutation isn't a
    /// concern there. The field is populated regardless so a future
    /// shared-v1-wrapper variant can fold it in without revisiting the
    /// install pipeline plumbing.
    pub patch_fingerprint: Option<String>,
}

impl LinkTarget {
    /// The `.lpm/<segment>/` directory name
    /// for this target.
    ///
    /// - `<safe_name>+<wrapper_id>` for non-Registry deps. Visually
    ///   distinct from the CAS shape so `lpm doctor`
    ///   / `lpm why` output is parseable at a glance.
    /// - `<safe_name>@<version>` for CAS-backed deps (the legacy
    ///   shape — Registry + Tarball remote + Tarball local all use
    ///   this).
    ///
    /// Used by [`link_one_package`], [`link_finalize`], and
    /// [`cleanup_stale_entries`] so the wrapper-segment shape is
    /// computed in one place.
    ///
    /// Delegates to [`LayoutPaths::wrapper_segment`] (the cross-crate
    /// source of truth) so non-linker consumers (`lpm rebuild`,
    /// `lpm doctor`, etc.) cannot accidentally compute a different
    /// shape from the same `(name, version, wrapper_id)` inputs.
    pub fn wrapper_segment(&self) -> String {
        LayoutPaths::wrapper_segment(&self.name, &self.version, self.wrapper_id.as_deref())
    }
}

/// Create the pnpm-style node_modules layout.
///
/// Result of the linking operation.
#[derive(Debug)]
pub struct LinkResult {
    /// Number of packages copied from store.
    pub linked: usize,
    /// Number of symlinks created.
    pub symlinked: usize,
    /// Number of bin links created.
    pub bin_linked: usize,
    /// Number of packages skipped (already linked, marker present).
    pub skipped: usize,
    /// Whether a self-referencing symlink was created for the project package.
    pub self_referenced: bool,
    /// **`lpm patch`.** Every physical destination
    /// where a package was materialized in this run. The patch-apply
    /// pass consumes this slice directly so it never has to
    /// reverse-engineer the linker's destination shapes from
    /// `(name, version)` — which would silently miss the
    /// `<project>/.lpm/hoisted/nested/<name>/` shape used in hoisted
    /// mode when a nested loser's parent is itself nested
    /// (`link_packages_hoisted` else branch).
    ///
    /// **Population:**
    /// - Isolated mode: one entry per `(name, version)` pointing at
    ///   `<project>/.lpm/wrappers/<safe_name>@<version>/node_modules/<name>/`.
    /// - Hoisted mode (full re-link path): one entry per hoisted
    ///   package + one per nested package (under hoisted parent OR
    ///   under `<project>/.lpm/hoisted/nested/`).
    /// - Hoisted mode (incremental skip): re-derived from the saved
    ///   `desired_hoisted` / `desired_nested` maps so the patch pass
    ///   still gets a complete location list when the linker took the
    ///   metadata fast path.
    pub materialized: Vec<MaterializedPackage>,
}

/// One physical destination of a linked package. .
///
/// Returned in [`LinkResult::materialized`] so the patch-apply pass
/// always operates on the linker's authoritative location list and
/// stays correct across linker layout changes.
#[derive(Debug, Clone)]
pub struct MaterializedPackage {
    /// Package name (e.g., `"lodash"`, `"@types/node"`).
    pub name: String,
    /// Exact version string (e.g., `"4.17.21"`).
    pub version: String,
    /// Absolute path to the package directory in `node_modules`. The
    /// directory directly contains the package's `package.json` (and
    /// the LPM-internal sentinels `.integrity` /
    /// `.lpm-security.json`, which the patch engine filters out).
    pub destination: PathBuf,
}
