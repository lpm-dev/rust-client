use super::*;

/// Source-string compound key for fetch-phase bookkeeping maps
/// (`FetchCoordinator`, `v2_target_by_key`, `integrity_map`, `fresh_urls`).
///
/// Encodes `"name\x00version\x00source"` — unique across all source kinds
/// without the SHA-256 computation that [`lpm_lockfile::PackageKey`] requires.
/// `name`, `version`, and `source` strings cannot contain `\x00`.
#[inline]
pub(super) fn install_pkg_key(p: &InstallPackage) -> String {
    let mut k = String::with_capacity(p.name.len() + 1 + p.version.len() + 1 + p.source.len());
    k.push_str(&p.name);
    k.push('\x00');
    k.push_str(&p.version);
    k.push('\x00');
    k.push_str(&p.source);
    k
}

fn append_unique_strings(dst: &mut Vec<String>, src: impl IntoIterator<Item = String>) {
    let mut seen: HashSet<String> = dst.iter().cloned().collect();
    for value in src {
        if seen.insert(value.clone()) {
            dst.push(value);
        }
    }
}

fn append_unique_pairs_by_left(dst: &mut Vec<(String, String)>, src: Vec<(String, String)>) {
    let mut seen: HashSet<String> = dst.iter().map(|(left, _)| left.clone()).collect();
    for (left, right) in src {
        if seen.insert(left.clone()) {
            dst.push((left, right));
        }
    }
}

fn normalize_implicit_root_links(pkg: &mut InstallPackage) {
    if pkg.root_link_names.is_none() && pkg.is_direct {
        pkg.root_link_names = Some(vec![pkg.name.clone()]);
    }
}

fn merge_install_package(dst: &mut InstallPackage, mut src: InstallPackage) {
    normalize_implicit_root_links(dst);
    normalize_implicit_root_links(&mut src);

    match (&mut dst.root_link_names, src.root_link_names) {
        (Some(dst_names), Some(src_names)) => append_unique_strings(dst_names, src_names),
        (None, Some(src_names)) => dst.root_link_names = Some(src_names),
        (Some(_), None) | (None, None) => {}
    }

    append_unique_pairs_by_left(&mut dst.dependencies, src.dependencies);
    for (alias, target) in src.aliases {
        dst.aliases.entry(alias).or_insert(target);
    }
    append_unique_pairs_by_left(&mut dst.peers, src.peers);

    dst.is_direct |= src.is_direct;
    dst.is_lpm |= src.is_lpm;
    dst.optional &= src.optional;
    if dst.integrity.is_none() {
        dst.integrity = src.integrity;
    }
    if dst.registry_signatures.is_empty() {
        dst.registry_signatures = src.registry_signatures;
    }
    if dst.registry_published_at.is_none() {
        dst.registry_published_at = src.registry_published_at;
    }
    if dst.platform.is_none() {
        dst.platform = src.platform;
    }
    if dst.node_engine.is_none() {
        dst.node_engine = src.node_engine;
    }
    if dst.tarball_url.is_none() {
        dst.tarball_url = src.tarball_url;
    }
    dst.metadata_checked_for_tarball |= src.metadata_checked_for_tarball;
}

pub(super) fn dedupe_install_packages_by_identity(packages: &mut Vec<InstallPackage>) {
    if packages.len() < 2 {
        return;
    }

    let mut index_by_key: HashMap<String, usize> = HashMap::with_capacity(packages.len());
    let mut deduped = Vec::with_capacity(packages.len());
    for package in packages.drain(..) {
        let key = install_pkg_key(&package);
        if let Some(existing_index) = index_by_key.get(&key).copied() {
            merge_install_package(&mut deduped[existing_index], package);
        } else {
            index_by_key.insert(key, deduped.len());
            deduped.push(package);
        }
    }
    *packages = deduped;
}

/// Lightweight representation of a resolved package for the install pipeline.
/// Used both for fresh resolution results and lockfile-restored packages.
#[derive(Debug, Clone)]
pub(super) struct InstallPackage {
    pub(super) name: String,
    pub(super) version: String,
    /// Source registry for lockfile
    pub(super) source: String,
    /// Dependencies: (dep_name_in_parent, dep_version). The name is the
    /// LOCAL label THIS package uses for the dep in its own `package.json`
    pub(super) dependencies: Vec<(String, String)>,
    /// npm alias edges declared by this package: local dep name -> canonical target name.
    pub(super) aliases: HashMap<String, String>,
    pub(super) root_link_names: Option<Vec<String>>,
    /// Whether this is a direct dependency of the root project
    pub(super) is_direct: bool,
    /// Whether this is an LPM package (for tarball fetching)
    pub(super) is_lpm: bool,
    /// resolved peers in scope for THIS package's
    /// instance in this install graph: `(peer_name, resolved_version)`.
    /// Sorted by peer_name for deterministic GraphKey hashing.
    ///
    /// Carried verbatim from the resolver's
    /// [`lpm_resolver::ResolvedPackage::peers`] field. The v2 linker
    /// uses this to (a) synthesize peer-edge siblings inside each
    /// link entry without re-reading package.json, and (b) fold the
    /// peer-context into [`lpm_store::v2::GraphKey`] so two projects
    /// with the same edge graph but different peer pinning produce
    /// distinct keys (design cross-project sharing
    /// invariant). v1 ignores this field — its relative-symlink
    /// wrappers walk up to the project root for peers, so threading
    /// is informational under v1.
    pub(super) peers: Vec<(String, String)>,
    /// SRI integrity hash for verification (e.g. "sha512-...")
    pub(super) integrity: Option<String>,
    /// Registry package-signature payload from `dist.signatures`.
    pub(super) registry_signatures: Vec<lpm_registry::RegistrySignature>,
    /// Registry publish timestamp for the selected version, used when
    /// checking signature key expiry.
    pub(super) registry_published_at: Option<String>,
    /// Platform restrictions declared by the selected package version.
    pub(super) platform: Option<lpm_resolver::PlatformMeta>,
    /// `engines.node` constraint declared by this package version.
    pub(super) node_engine: Option<String>,
    /// True when this package is reachable only through optional dependency
    /// edges.
    pub(super) optional: bool,
    /// Tarball URL from resolution — avoids re-fetching metadata during download.
    pub(super) tarball_url: Option<String>,
    /// Whether current metadata was already consulted for tarball lookup.
    /// Distinguishes a fresh-resolution `dist.tarball` miss from an older
    /// lockfile entry that simply has no cached tarball URL yet.
    pub(super) metadata_checked_for_tarball: bool,
}

impl InstallPackage {
    /// parse the
    /// `source` string into a typed [`lpm_lockfile::Source`]. Used
    /// by the fetch-dispatch site to route non-Registry sources
    /// (`Source::Tarball` etc.) through their dedicated install
    /// path instead of the registry-routed fetch.
    ///
    /// Mirrors [`lpm_lockfile::LockedPackage::source_kind`] —
    /// returns `Some(Err(_))` for malformed source strings (the
    /// caller treats this as a programmer error since the
    /// lockfile's reader gate would have rejected such input).
    pub(super) fn source_kind(
        &self,
    ) -> Result<lpm_lockfile::Source, lpm_lockfile::SourceParseError> {
        lpm_lockfile::Source::parse(&self.source)
    }

    /// source-
    /// aware existence check. For `Source::Tarball` packages,
    /// checks the integrity-keyed CAS layout
    /// ([`PackageStore::has_tarball`]); everything else falls back
    /// to the legacy `(name, version)`-keyed
    /// [`PackageStore::has_package`].
    ///
    /// Trust-on-first-use `Source::Tarball` (integrity = None)
    /// returns `false` even when a coincidentally-named registry
    /// package exists in the store. The fetch must run to compute the
    /// integrity rather than silently substituting registry content.
    pub(super) fn store_has_source_aware(&self, store: &PackageStore, project_dir: &Path) -> bool {
        match self.source_kind() {
            Ok(lpm_lockfile::Source::Tarball { ref url }) if url.starts_with("file:") => {
                self.integrity.as_deref().is_some_and(|sri| {
                    sri_to_sha256_hex(sri).is_some_and(|hex| store.has_local_tarball(&hex))
                })
            }
            Ok(lpm_lockfile::Source::Tarball { .. }) => self
                .integrity
                .as_deref()
                .is_some_and(|sri| store.has_tarball(sri)),
            Ok(lpm_lockfile::Source::Directory { path })
            | Ok(lpm_lockfile::Source::Link { path }) => {
                // () — directory and link deps live
                // OUTSIDE the global store. "Has it" means: the source
                // path resolves to a directory containing a
                // `package.json` at install time. If the source dir was
                // moved or deleted between resolve and link, this
                // returns false so the install pipeline surfaces a
                // clear error rather than linking against a dangling
                // path.
                let abs = project_dir.join(&path);
                abs.is_dir() && abs.join("package.json").is_file()
            }
            _ => store.has_package(&self.name, &self.version),
        }
    }

    pub(super) fn store_has_for_install_layout(
        &self,
        store: &PackageStore,
        store_v2: Option<&lpm_store::v2::Store>,
        project_dir: &Path,
    ) -> bool {
        if let Some(v2_store) = store_v2 {
            match self.source_kind() {
                Ok(lpm_lockfile::Source::Directory { .. })
                | Ok(lpm_lockfile::Source::Link { .. }) => {
                    return self.store_has_source_aware(store, project_dir);
                }
                _ => {
                    return self.integrity.as_deref().is_some_and(|sri| {
                        v2_store
                            .reusable_object_dir(sri)
                            .is_ok_and(|object_dir| object_dir.is_some())
                    });
                }
            }
        }

        self.store_has_source_aware(store, project_dir)
    }

    /// Source-aware store path.
    ///
    /// Three CAS subtrees today, one path-resolution function:
    /// - `Source::Registry` → `package_dir(name, version)` (the
    ///   legacy `v1/{name}@{version}/` subtree).
    /// - `Source::Tarball { url: "https://..." }` → integrity-keyed
    ///   `v1/tarball/{algo}-{hex}/`.
    /// - `Source::Tarball { url: "file:..." }` → content-hash-keyed
    ///   `v1/tarball-local/sha256-{hex}/`. The hex
    ///   is derived from the SAME SRI; only the subtree differs.
    ///
    /// URL-scheme dispatch (vs a separate `Source` variant for
    /// local tarballs) is intentional: the wire format
    /// `tarball+<url-or-path>` covers both kinds, so the install
    /// pipeline reads the URL prefix at every routing site rather
    /// than carving a fifth `Source` variant. If routing-site count
    /// grows past a few call sites, revisit by introducing
    /// `Source::TarballLocal`.
    ///
    /// The optional `sri_override` lets post-fetch contexts pass
    /// the just-computed SRI before it's been written to
    /// `self.integrity`. Applies symmetrically to both tarball arms.
    ///
    /// Returns `None` for `Source::Tarball` with NO integrity
    /// available (neither override nor recorded). Callers must
    /// treat this as a programmer error — at every call site, an
    /// SRI should be available by construction (post-fetch from
    /// the download, post-resolve from the lockfile, or post-wake
    /// from the sibling task that just stored it). A `package_dir`
    /// fallback would silently substitute a registry-keyed path.
    ///
    /// Most callers should prefer [`Self::store_path_or_err`],
    /// which returns a typed error with full context instead of an
    /// `Option`. This `Option`-returning variant is kept for the
    /// offline-gate path where `None` is a *meaningful* signal
    /// ("not yet fetched") rather than a programmer error.
    pub(super) fn store_path_source_aware(
        &self,
        store: &PackageStore,
        project_dir: &Path,
        sri_override: Option<&str>,
    ) -> Option<PathBuf> {
        match self.source_kind() {
            Ok(lpm_lockfile::Source::Tarball { ref url }) if url.starts_with("file:") => {
                // Local-file tarball — content-keyed CAS subtree.
                // The SRI's raw hash bytes hex-encode to the CAS key.
                let sri = sri_override.or(self.integrity.as_deref())?;
                let hex = sri_to_sha256_hex(sri)?;
                store.tarball_local_store_path(&hex).ok()
            }
            Ok(lpm_lockfile::Source::Tarball { .. }) => sri_override
                .or(self.integrity.as_deref())
                .and_then(|sri| store.tarball_store_path(sri).ok()),
            Ok(lpm_lockfile::Source::Directory { path })
            | Ok(lpm_lockfile::Source::Link { path }) => {
                // () — directory + link deps live
                // OUTSIDE the global store. The "store path" is the
                // canonicalized source directory; the linker
                // materializes per-file symlinks pointing at it.
                //
                // Canonicalize to make the path stable across symlink
                // chains in the source tree (e.g., a workspace symlink
                // pointing into a sibling project). Returns None on a
                // missing/unreadable path — same posture as the
                // tarball arm with no SRI: the typed-error variant
                // `store_path_or_err` surfaces a clear message, the
                // `Option`-returning variant signals "not yet
                // available" to the offline gate.
                let abs = project_dir.join(&path);
                let canonical = abs.canonicalize().ok()?;
                // Warn when the canonical resolution escapes the
                // project tree. A `link:./packages/foo` whose target
                // is a symlink pointing at `/etc/secret-pkg` is
                // technically valid (the lockfile allows it) but the
                // pattern is surprising enough — and load-bearing for
                // any "the workspace only references content within
                // the project tree" assumption — that it deserves a
                // visible warning. Best-effort: only emit when
                // `project_dir.canonicalize()` succeeds (it usually
                // does; failures fall through silently).
                if let Ok(project_canonical) = project_dir.canonicalize()
                    && !canonical.starts_with(&project_canonical)
                    && !is_declared_workspace_package_source(
                        project_dir,
                        &canonical,
                        &self.name,
                        &self.version,
                    )
                {
                    tracing::warn!(
                        name = %self.name,
                        version = %self.version,
                        link_path = %path,
                        canonical = %canonical.display(),
                        project_root = %project_canonical.display(),
                        "link/directory dep resolves to a path outside the project tree \
                         (likely via a symlink) — confirm this is intentional",
                    );
                }
                Some(canonical)
            }
            _ => Some(store.package_dir(&self.name, &self.version)),
        }
    }

    /// typed-error variant of
    /// [`Self::store_path_source_aware`]. Returns a clear
    /// `LpmError::Registry` when a `Source::Tarball` package
    /// reaches a call site without an SRI in either the override
    /// or the recorded `integrity` field. Never fall back to a
    /// registry-keyed path for a tarball source.
    ///
    /// Use this at every site that knows it has an SRI by
    /// construction (post-fetch with computed_sri, post-store-hit
    /// where `store_has_source_aware()` already returned true,
    /// post-resolve with `p.integrity` populated from the
    /// lockfile). The only legitimate `None` case is the
    /// pre-fetch offline gate, where [`Self::store_path_source_aware`]
    /// is the right fit.
    pub(super) fn store_path_or_err(
        &self,
        store: &PackageStore,
        project_dir: &Path,
        sri_override: Option<&str>,
    ) -> Result<PathBuf, LpmError> {
        self.store_path_source_aware(store, project_dir, sri_override)
            .ok_or_else(|| {
                // : error message disambiguates the
                // tarball-source SRI case from the directory-source
                // missing-path case so users get an actionable hint.
                let kind_note = match self.source_kind() {
                    Ok(lpm_lockfile::Source::Directory { path })
                    | Ok(lpm_lockfile::Source::Link { path }) => format!(
                        "directory/link source path {path:?} (resolved against {}) \
                         could not be canonicalized — missing or unreadable",
                        project_dir.display(),
                    ),
                    _ => format!(
                        "tarball-source package {}@{} reached \
                         a path-resolution site without an SRI (override + \
                         recorded integrity both absent). This is a programmer \
                         error in the install pipeline — please report.",
                        self.name, self.version,
                    ),
                };
                LpmError::Registry(format!("install-source invariant: {kind_note}"))
            })
    }

    /// —
    /// wrapper identifier for the linker.
    ///
    /// Returns `Some` for every NON-Registry source — Directory,
    /// Link, and Tarball (remote + local). These all live in
    /// `node_modules/.lpm/<safe_name>+<wrapper_id>/` rather than
    /// the legacy `<safe_name>@<version>/` shape. The wrapper id
    /// is the source's [`lpm_lockfile::Source::source_id`]:
    ///
    /// - `Source::Directory` → `f-{16hex(rel-path)}`
    /// - `Source::Link` → `l-{16hex(rel-path)}`
    /// - `Source::Tarball` → `t-{16hex(url)}` (URL distinguishes
    ///   remote `https://…` from local `file:./…`)
    ///
    /// Returns `None` only for `Source::Registry` — the registry
    /// namespace doesn't share `(name, version)` keys with any other
    /// source kind, so the legacy `<name>@<version>` wrapper segment
    /// stays collision-free for registry deps.
    ///
    /// This must return a source-specific wrapper id for every
    /// non-registry source. Otherwise registry `foo@1.0.0` and
    /// tarball `foo@1.0.0` can collapse to the same wrapper segment
    /// `foo@1.0.0` and silently overwrite each other in
    /// `node_modules/.lpm/`. The invariant extends the helper
    /// to Tarball (which correlates with [`Self::materialization_for_source`]
    /// staying [`lpm_linker::Materialization::CasBacked`] for
    /// tarballs — the wrapper-segment fix is decoupled from the
    /// CAS-copy materialization).
    pub(super) fn wrapper_id_for_source(&self) -> Option<String> {
        match self.source_kind() {
            Ok(s @ lpm_lockfile::Source::Directory { .. })
            | Ok(s @ lpm_lockfile::Source::Link { .. })
            | Ok(s @ lpm_lockfile::Source::Tarball { .. }) => Some(s.source_id()),
            _ => None,
        }
    }

    /// materialization
    /// strategy for the linker.
    ///
    /// Returns [`lpm_linker::Materialization::DirectorySource`] for
    /// `Source::Directory` (`file:` dir) and `Source::Link` (`link:`)
    /// — the linker walks the source realpath and creates per-file
    /// absolute symlinks under the wrapper, so edits to the source
    /// are visible without re-running `lpm install`.
    ///
    /// Returns [`lpm_linker::Materialization::CasBacked`] (the
    /// default) for every CAS-backed source — Registry, Tarball
    /// (remote + local), and Git. The linker uses
    /// `link_dir_recursive` (clonefile / hardlink / copy) from
    /// `LinkTarget::store_path` (which lives inside the global CAS
    /// store).
    ///
    /// Decoupled from [`Self::wrapper_id_for_source`] so tarball
    /// LinkTargets get a distinct `+`-shape wrapper segment (no
    /// collision with the registry namespace) WITHOUT inheriting
    /// the directory-source per-file-symlink fanout.
    pub(super) fn materialization_for_source(&self) -> lpm_linker::Materialization {
        match self.source_kind() {
            Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. }) => {
                lpm_linker::Materialization::DirectorySource
            }
            _ => lpm_linker::Materialization::CasBacked,
        }
    }
}
