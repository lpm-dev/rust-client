use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use lpm_common::LpmError;

use crate::{PackageStore, read_stored_integrity};

/// Resolved location of a package's source bytes along with the
/// integrity SRI recorded for that copy. Returned by
/// [`find_installed_package_baseline`].
#[derive(Debug, Clone)]
pub struct InstalledPackageBaseline {
    /// Absolute path to the package directory whose contents match the
    /// extracted tarball. Under v1 this is `<store>/v1/<safe>@<ver>/`;
    /// under v2 this is `<store>/v2/links/<graph-key>/node_modules/<name>/`
    /// (the link's clonefile-materialized copy of the object-addressed
    /// bytes).
    pub package_dir: PathBuf,
    /// Absolute path to a directory holding the **pristine,
    /// never-mutated** copy of the published bytes for
    /// `(name, version)`.
    ///
    /// - Under v1, equals [`Self::package_dir`] — the v1 store dir is
    ///   pristine because patches mutate the project-private wrapper
    ///   at `<project>/.lpm/<seg>/node_modules/<name>/`, not the
    ///   store itself.
    /// - Under v2, points at `<store>/v2/objects/<sri-segment>/`. The
    ///   v2 link entry at `package_dir` is the patch destination —
    ///   reading baselines from `package_dir` under v2 would re-feed
    ///   already-patched bytes to a second `apply_patch` and break
    ///   re-install idempotency.
    ///
    /// Read-only baseline consumers (patch engine pre-image reads,
    /// ADD/DELETE-hunk existence checks) MUST consult this field
    /// rather than `package_dir` to stay correct under both layouts.
    pub pristine_dir: PathBuf,
    /// SRI string of the source tarball — `meta.source_sri` under v2,
    /// `<package_dir>/.integrity` under v1.
    pub integrity: String,
    /// Which store the lookup hit. Callers that need to read sentinel
    /// files (e.g. `<v1_dir>/.integrity`) only when on v1 can branch on
    /// this.
    pub layout: PackageBaselineLayout,
}

/// Discriminator for [`InstalledPackageBaseline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageBaselineLayout {
    /// Package found at `<store>/v1/<safe>@<ver>/`.
    V1,
    /// Package found at `<store>/v2/links/<graph-key>/node_modules/<name>/`.
    V2,
}

/// Invocation-local index over the v2 store's link entries, keyed by
/// `(name, version)`.
///
/// Built once per `lpm rebuild` / `lpm approve-scripts` /
/// `all_scripted_packages_trusted` / `scriptable_package_rows` from a
/// single ordered walk of [`crate::v2::Store::iter_link_entries`].
/// Subsequent per-package lookups become O(1) hashmap reads instead
/// of re-scanning every link entry + parsing every sidecar JSON.
///
/// **Why this matters.** [`find_installed_package_baseline`] is O(N) with
/// a sidecar parse per call. The rebuild pipeline calls it inside per-package
/// loops over the lockfile — on a 1000-package lockfile against a 5000-link
/// global store that's 5M sidecar reads per invocation, pure waste since the
/// link-entry layout doesn't change mid-command.
///
/// **First-match semantics preserved.** When the same
/// `(name, version)` appears under multiple graph keys (multi-source-
/// same-coords or peer-divergent installs sharing coords), the first
/// entry seen in `iter_link_entries()` directory order wins —
/// matching the legacy linear scan's tie-breaking.
///
/// Construction is best-effort: malformed sidecars are silently
/// skipped. An empty index is cheap and safe — callers on stores
/// with no v2 entries get an empty map and pay only the v1 fallback.
#[derive(Debug, Clone, Default)]
pub struct V2BaselineIndex {
    by_coords: HashMap<(String, String), InstalledPackageBaseline>,
    by_integrity: HashMap<String, InstalledPackageBaseline>,
}

impl V2BaselineIndex {
    /// Build a project-scoped index by walking only the link entries
    /// the project's `<project>/node_modules/` tree actually points
    /// at, BFS'd through each entry's `LinkMeta.deps` to cover
    /// transitives.
    ///
    /// **Why this exists.** [`Self::build`] (the global walker) keys
    /// on `(name, version)` and keeps the first match in directory
    /// iteration order. Once patched and unpatched installs of the
    /// same coords can legitimately coexist on disk (the patch
    /// fingerprint splits them into distinct link entries),
    /// "first global match" is no longer safe — the rebuild pipeline
    /// could read scripts / trust / build-marker state from the wrong
    /// link entry, and write its build marker into a sibling
    /// project's store dir.
    ///
    /// **The walk.** Every entry under `<project>/node_modules/`
    /// that resolves to `<lpm_root>/store/v2/links/<key>/...` is a
    /// seed. From each seed link entry's [`LinkMeta::deps`], the
    /// dep's link-entry directory name is reconstructed
    /// (`{safe_name}@{version}+{first16hex}`) and visited too.
    /// Repeated until a fixed point is reached.
    ///
    /// **Safety.** Any sidecar that fails to parse, any symlink that
    /// points outside the v2 store, any non-symlink entry, and any
    /// reachable link entry whose `node_modules/<pkg>/` is missing
    /// is silently skipped. Each skip is logged at `tracing::debug!`
    /// so a malformed install surfaces under `RUST_LOG=debug`
    /// without blocking the operation.
    ///
    /// **Fallback contract.** When the project has no `node_modules/`
    /// (fresh checkout, never installed), or every symlink resolves
    /// outside the v2 store (pure-v1 install), this returns an empty
    /// index. Callers route through
    /// [`find_installed_package_baseline_indexed`] which falls
    /// through to the v1 lookup on miss — same behavior as a
    /// freshly-built [`Self::build`] empty index.
    pub fn for_project(
        project_dir: &Path,
        lpm_root: &lpm_common::LpmRoot,
    ) -> Result<Self, LpmError> {
        use {HashSet, VecDeque};

        let store_v2 = crate::v2::Store::from_lpm_root(lpm_root);
        let links_root = store_v2.paths().links_root();
        let mut by_coords: HashMap<(String, String), InstalledPackageBaseline> = HashMap::new();
        let mut by_integrity: HashMap<String, InstalledPackageBaseline> = HashMap::new();

        // Seeds: every direct symlink under `<project>/node_modules/`
        // whose target lives inside `<links_root>/<key>/`. Direct-bin
        // compatibility roots point at project-local copies instead;
        // those copies use the same `<key>` directory name, so they
        // map back to the owning link entry before the sidecar walk.
        let mut to_visit: VecDeque<PathBuf> = VecDeque::new();
        let mut visited: HashSet<PathBuf> = HashSet::new();
        let nm_root = project_dir.join("node_modules");
        let compatibility_root = nm_root.join(".lpm").join("compat");
        if let Ok(read_dir) = std::fs::read_dir(&nm_root) {
            for entry in read_dir.flatten() {
                let symlink_path = entry.path();
                seed_project_link_dir(
                    &symlink_path,
                    &links_root,
                    &compatibility_root,
                    &mut visited,
                    &mut to_visit,
                );

                // Scoped direct deps live at `node_modules/@scope/pkg`,
                // so the project root contains a REAL `@scope/` dir and
                // the symlink is one level deeper. Without this extra
                // walk, `for_project` misses every scoped direct dep.
                let file_type = match entry.file_type() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let is_scope_dir = file_type.is_dir()
                    && entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with('@'));
                if !is_scope_dir {
                    continue;
                }

                if let Ok(scope_entries) = std::fs::read_dir(&symlink_path) {
                    for scope_entry in scope_entries.flatten() {
                        seed_project_link_dir(
                            &scope_entry.path(),
                            &links_root,
                            &compatibility_root,
                            &mut visited,
                            &mut to_visit,
                        );
                    }
                }
            }
        }

        // BFS through each link entry's `LinkMeta.deps`. Sibling
        // entries are reached by reconstructing their directory name
        // from the dep's `target_graph_key` digest + name + version.
        while let Some(link_dir) = to_visit.pop_front() {
            let meta = match crate::v2::link_meta::LinkMeta::read_from(&link_dir) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(
                        "v2 project-scoped index: skipping {}: sidecar unreadable ({e})",
                        link_dir.display()
                    );
                    continue;
                }
            };
            // Destructure meta to move name/version/source_sri
            // directly into the HashMap key + baseline without cloning.
            let crate::v2::link_meta::LinkMeta {
                name: meta_name,
                version: meta_version,
                source_sri: meta_sri,
                deps: meta_deps,
                ..
            } = meta;

            let package_dir = link_dir.join("node_modules").join(&meta_name);
            if !package_dir.exists() {
                tracing::debug!(
                    "v2 project-scoped index: skipping {}: package dir missing",
                    link_dir.display()
                );
                continue;
            }
            let pristine_dir = match store_v2.paths().object_dir(&meta_sri) {
                Ok(p) if p.exists() => p,
                _ => package_dir.clone(),
            };
            // Project-scoped: in a single project a (name, version) is
            // resolved by exactly one link entry, except the
            // multi-source-same-coords corner case (two distinct
            // sources sharing coords and BOTH symlinked from the
            // project — rare). Keep first-write-wins: the seed-symlink
            // walk inserts before the BFS, and BFS itself is FIFO, so
            // the chosen entry is whichever is closer to the project
            // root in the symlink graph.
            let baseline = InstalledPackageBaseline {
                package_dir,
                pristine_dir,
                integrity: meta_sri.clone(),
                layout: PackageBaselineLayout::V2,
            };
            by_integrity
                .entry(meta_sri)
                .or_insert_with(|| baseline.clone());
            by_coords
                .entry((meta_name, meta_version))
                .or_insert(baseline);
            for dep in &meta_deps {
                // `LinkMeta.deps` carries the full 64-hex digest; the
                // on-disk dir name uses the first 16 chars. See
                // `crate::v2::GraphKey::dir_name` for the format.
                if dep.target_graph_key.len() < 16 {
                    continue; // malformed sidecar
                }
                let short_hex = &dep.target_graph_key[..16];
                // Avoid allocating an intermediate `safe_name` for
                // unscoped packages (the majority) by using `Cow<str>`
                // — borrows as-is when no replacement is needed.
                let safe_name: std::borrow::Cow<str> = if dep.target_name.contains(['/', '\\']) {
                    std::borrow::Cow::Owned(dep.target_name.replace(['/', '\\'], "+"))
                } else {
                    std::borrow::Cow::Borrowed(dep.target_name.as_str())
                };
                let mut dep_dir_name =
                    String::with_capacity(safe_name.len() + 1 + dep.target_version.len() + 17);
                dep_dir_name.push_str(&safe_name);
                dep_dir_name.push('@');
                dep_dir_name.push_str(&dep.target_version);
                dep_dir_name.push('+');
                dep_dir_name.push_str(short_hex);
                let dep_link_dir = links_root.join(&dep_dir_name);
                if visited.insert(dep_link_dir.clone()) {
                    to_visit.push_back(dep_link_dir);
                }
            }
        }

        Ok(Self {
            by_coords,
            by_integrity,
        })
    }

    /// Walk every v2 link entry under `lpm_root` once and produce an
    /// invocation-local lookup index.
    ///
    /// Returns `Ok(empty)` when v2 is empty or absent — callers should
    /// always succeed-then-fall-back via [`Self::lookup`], not gate on
    /// emptiness.
    ///
    /// **Use [`Self::for_project`] when the caller has a project
    /// directory in scope.** The global walk's first-match-wins
    /// tie-breaking is incorrect under multi-link-per-coords
    /// states. `for_project` is the supported lookup path for
    /// `lpm rebuild` / `lpm approve-scripts` and any other read of
    /// project-side script state.
    pub fn build(lpm_root: &lpm_common::LpmRoot) -> Result<Self, LpmError> {
        let store_v2 = crate::v2::Store::from_lpm_root(lpm_root);
        let mut by_coords: HashMap<(String, String), InstalledPackageBaseline> = HashMap::new();
        let mut by_integrity: HashMap<String, InstalledPackageBaseline> = HashMap::new();
        for (link_dir, meta) in store_v2.iter_link_entries()? {
            let key = (meta.name.clone(), meta.version.clone());
            let package_dir = link_dir.join("node_modules").join(&meta.name);
            if !package_dir.exists() {
                // Sidecar present but link entry missing the package
                // dir — corrupt entry. Skip and let any later valid
                // entry for the same coords win, mirroring
                // `find_installed_package_baseline`.
                continue;
            }
            let pristine_dir = match store_v2.paths().object_dir(&meta.source_sri) {
                Ok(p) if p.exists() => p,
                _ => package_dir.clone(),
            };
            let baseline = InstalledPackageBaseline {
                package_dir,
                pristine_dir,
                integrity: meta.source_sri.clone(),
                layout: PackageBaselineLayout::V2,
            };
            by_integrity
                .entry(meta.source_sri)
                .or_insert_with(|| baseline.clone());
            // Coordinate lookup retains its legacy first-match semantics,
            // while the integrity index keeps distinct source bytes.
            by_coords.entry(key).or_insert(baseline);
        }
        Ok(Self {
            by_coords,
            by_integrity,
        })
    }

    /// O(1) lookup. `None` means no v2 link entry covers the
    /// `(name, version)` pair — caller should fall back to v1.
    pub fn lookup(&self, name: &str, version: &str) -> Option<&InstalledPackageBaseline> {
        self.by_coords.get(&(name.to_string(), version.to_string()))
    }

    /// O(1) lookup by the package tarball's SRI identity.
    ///
    /// Unlike [`Self::lookup`], this remains unambiguous when different
    /// registries provide different bytes for the same package coordinates.
    pub fn lookup_by_integrity(&self, integrity: &str) -> Option<&InstalledPackageBaseline> {
        self.by_integrity.get(integrity)
    }
}

fn seed_project_link_dir(
    symlink_path: &Path,
    links_root: &Path,
    compatibility_root: &Path,
    visited: &mut HashSet<PathBuf>,
    to_visit: &mut VecDeque<PathBuf>,
) {
    // `read_link` reads the symlink target without following further
    // symlinks. v2 plants ABSOLUTE symlinks at the project root today,
    // but nested scoped entries should still resolve relative to their
    // own parent dir if that ever changes.
    let target = match std::fs::read_link(symlink_path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let target = if target.is_absolute() {
        target
    } else {
        symlink_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(target)
    };
    let link_dir = link_dir_from_target(&target, links_root)
        .or_else(|| link_dir_from_compatibility_target(&target, compatibility_root, links_root));
    if let Some(link_dir) = link_dir
        && visited.insert(link_dir.clone())
    {
        to_visit.push_back(link_dir);
    }
}

/// Given a path that a project-side symlink resolves to, reconstruct
/// the v2 link entry directory that owns it.
///
/// v2 plants the project's `<project>/node_modules/<dep>` symlink to
/// point at `<links_root>/<key_dir>/node_modules/<dep>/`. Scoped deps
/// add one more segment (`node_modules/@scope/<pkg>/`). Rather than
/// trying to strip a fixed suffix width, walk ancestors until the
/// first path whose parent is exactly `<links_root>` — that ancestor
/// is the owning `<key_dir>` for both unscoped and scoped targets.
/// Returns `None` when the target lives outside `links_root` (e.g. a
/// project-local file:/link: dep, a v1-installed package with a
/// custom symlink shape, or a legitimately-broken symlink).
///
/// Uses ancestor walking + path-prefix matching rather than canonical-
/// izing both paths, so a non-canonical `links_root` (test fixture
/// with `/private/var/.../links/...` vs `/var/.../links/...` on macOS)
/// still matches when the input target is canonical.
fn link_dir_from_target(target: &Path, links_root: &Path) -> Option<PathBuf> {
    for ancestor in target.ancestors() {
        if ancestor.parent() == Some(links_root) {
            return Some(ancestor.to_path_buf());
        }
    }
    // macOS canonicalization mismatch fallback: if direct parent
    // comparison missed, check via `starts_with` against the
    // canonicalized links_root. Symmetric with `iter_link_entries`'
    // tolerance for paths.
    let canonical_links_root = match links_root.canonicalize() {
        Ok(p) => p,
        Err(_) => return None,
    };
    let canonical_target = match target.canonicalize() {
        Ok(p) => p,
        Err(_) => return None,
    };
    for ancestor in canonical_target.ancestors() {
        if ancestor.parent() == Some(canonical_links_root.as_path()) {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn link_dir_from_compatibility_target(
    target: &Path,
    compatibility_root: &Path,
    links_root: &Path,
) -> Option<PathBuf> {
    for ancestor in target.ancestors() {
        if ancestor.parent() == Some(compatibility_root) {
            return ancestor
                .file_name()
                .map(|entry_name| links_root.join(entry_name));
        }
    }

    let canonical_compatibility_root = match compatibility_root.canonicalize() {
        Ok(p) => p,
        Err(_) => return None,
    };
    let canonical_target = match target.canonicalize() {
        Ok(p) => p,
        Err(_) => return None,
    };
    for ancestor in canonical_target.ancestors() {
        if ancestor.parent() == Some(canonical_compatibility_root.as_path()) {
            return ancestor
                .file_name()
                .map(|entry_name| links_root.join(entry_name));
        }
    }
    None
}

/// Index-aware variant of [`find_installed_package_baseline`]. Hits
/// the pre-built [`V2BaselineIndex`] for v2 in O(1); falls back to
/// the same v1 lookup as the legacy helper on a v2 miss. Returns
/// `None` when neither store has the package — same shape as the
/// `Result<Option<…>, _>` of the legacy call, except construction
/// errors are absorbed at index-build time so per-package callers
/// don't have to thread a `Result` through hot loops.
pub fn find_installed_package_baseline_indexed(
    index: &V2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
) -> Option<InstalledPackageBaseline> {
    if let Some(b) = index.lookup(name, version) {
        return Some(b.clone());
    }
    let store_v1 = PackageStore::from_root(lpm_root);
    let pkg_dir = store_v1.package_dir(name, version);
    if pkg_dir.exists()
        && let Some(integrity) = read_stored_integrity(&pkg_dir)
    {
        return Some(InstalledPackageBaseline {
            package_dir: pkg_dir.clone(),
            pristine_dir: pkg_dir,
            integrity,
            layout: PackageBaselineLayout::V1,
        });
    }
    None
}

/// Resolve an indexed baseline using the source integrity when available.
///
/// An integrity-qualified v2 miss does not fall back to a coordinate-only v2
/// match because that could select different bytes from another registry.
/// The v1 fallback is accepted only when its recorded integrity matches.
pub fn find_installed_package_baseline_by_identity_indexed(
    index: &V2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
    integrity: Option<&str>,
) -> Option<InstalledPackageBaseline> {
    let Some(expected_integrity) = integrity else {
        return find_installed_package_baseline_indexed(index, lpm_root, name, version);
    };

    if let Some(baseline) = index.lookup_by_integrity(expected_integrity) {
        return Some(baseline.clone());
    }

    let store_v1 = PackageStore::from_root(lpm_root);
    let package_dir = store_v1.package_dir(name, version);
    let recorded_integrity = read_stored_integrity(&package_dir)?;
    if recorded_integrity != expected_integrity {
        return None;
    }

    Some(InstalledPackageBaseline {
        package_dir: package_dir.clone(),
        pristine_dir: package_dir,
        integrity: recorded_integrity,
        layout: PackageBaselineLayout::V1,
    })
}

/// Resolve a package's installed source bytes + integrity in a
/// store-version-agnostic way. **Prefers v2** (the active default);
/// falls back to v1 if no v2 link entry matches.
///
/// Designed for downstream commands that read package metadata or
/// source files post-install — `lpm patch`, `lpm patch-commit`,
/// `lpm rebuild`, `lpm approve-scripts --show-scripts` — which must
/// not blindly call [`PackageStore::package_dir`] (v1-only) under v2
/// installs.
///
/// **Multi-source-same-coords:** when two distinct sources share
/// `(name, version)` and produce different graph keys, this helper
/// picks the lexicographically smallest matching v2 link entry.
///
/// The lex sort buys **reproducibility, not plant-attack defense.**
/// Across runs, across filesystems (read_dir is inode-order on
/// ext4/APFS and undefined elsewhere), and across the indexed +
/// non-indexed variants of this lookup, the same input store now
/// yields the same hit — patches/rebuilds become deterministic
/// instead of inode-order-dependent. A same-UID local attacker
/// who can plant `<links_root>/A@1.0.0+0000000000000000/` with
/// a crafted sidecar will still win first-match deterministically
/// (a `0000…`-prefixed graph-key suffix sorts before legitimate
/// sha256-derived hex), and arguably more reliably than under
/// inode-order luck — the lex sort does NOT close that attack.
/// The actual defense against same-UID plants is the
/// `(name, version, wrapper_id)` lookup tracked separately, which
/// will require `wrapper_id` to flow through the lockfile;
/// canonical ordering is the reproducibility pin in the meantime.
pub fn find_installed_package_baseline(
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
) -> Result<Option<InstalledPackageBaseline>, LpmError> {
    // v2 first — the active default. Iterating link entries reads
    // each sidecar `.lpm-link-meta.json`; the iterator gracefully
    // skips malformed entries so a corrupt sibling never blocks a
    // valid match.
    //
    // Collect-and-sort by link_dir path so the first match is
    // deterministic across runs and across filesystems (read_dir
    // order is inode-order on ext4/APFS and undefined elsewhere).
    let store_v2 = crate::v2::Store::from_lpm_root(lpm_root);
    let mut entries: Vec<(PathBuf, _)> = store_v2.iter_link_entries()?.collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (link_dir, meta) in entries {
        if meta.name == name && meta.version == version {
            let package_dir = link_dir.join("node_modules").join(name);
            if package_dir.exists() {
                // Derive the pristine object dir from the source SRI.
                // v2 populates link entries via clonefile from
                // `objects/<sri>/`, so for a well-formed install the
                // object dir is always derivable AND present on disk.
                //
                // **Defensive aliasing.** If `sri_to_segment` can't
                // parse the SRI (synthetic test fixtures) or the
                // resolved path is missing (manual pruning, partial
                // migration), fall back to aliasing `package_dir`.
                // Patch consumers then re-read the link entry
                // directly — same shape as v1, where
                // `pristine_dir == package_dir` by construction. A
                // genuinely-corrupt v2 install fails later with a
                // patch-engine drift error, keeping the user-facing
                // failure mode close to the cause.
                let pristine_dir = match store_v2.paths().object_dir(&meta.source_sri) {
                    Ok(p) if p.exists() => p,
                    _ => package_dir.clone(),
                };
                return Ok(Some(InstalledPackageBaseline {
                    package_dir,
                    pristine_dir,
                    integrity: meta.source_sri,
                    layout: PackageBaselineLayout::V2,
                }));
            }
            // The sidecar pointed at us, but the materialized package
            // dir is missing — corrupt link entry. Continue scanning
            // for another link that might satisfy the request.
        }
    }
    // v1 fallback — older installs, the migration grace window, or
    // ad-hoc test fixtures that populate v1 directly.
    let store_v1 = PackageStore::from_root(lpm_root);
    let pkg_dir = store_v1.package_dir(name, version);
    if pkg_dir.exists()
        && let Some(integrity) = read_stored_integrity(&pkg_dir)
    {
        return Ok(Some(InstalledPackageBaseline {
            package_dir: pkg_dir.clone(),
            // Under v1 the store dir is pristine — patches mutate
            // project-private wrappers, never the v1 store. Aliasing
            // the same path here keeps the patch engine layout-agnostic
            // (read pristine bytes from `pristine_dir`, write
            // destinations via `MaterializedPackage.destination`).
            pristine_dir: pkg_dir,
            integrity,
            layout: PackageBaselineLayout::V1,
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{LinkEntryRequest, LinkMetaPlatform, Store as V2Store};

    fn sample_meta_platform() -> LinkMetaPlatform {
        LinkMetaPlatform {
            os: "darwin".into(),
            cpu: "arm64".into(),
            libc: None,
        }
    }

    fn synthetic_sri(seed: &[u8]) -> String {
        crate::compute_sri_hash(seed)
    }

    fn write_object(store: &V2Store, sri: &str, files: &[(&str, &[u8])]) -> PathBuf {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("package/{path}"), &content[..])
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tarball = encoder.finish().unwrap();
        store.extract_object(sri, &tarball).unwrap()
    }

    fn sample_key(name: &str, version: &str) -> crate::v2::GraphKey {
        use crate::v2::{GraphKeyInputs, LinkerModeTag, PlatformTuple};
        let inputs = GraphKeyInputs::new(
            name,
            version,
            PlatformTuple::new("darwin", "arm64", None),
            LinkerModeTag::Isolated,
        );
        crate::v2::GraphKey::derive(&inputs)
    }
    /// Construction against an empty `~/.lpm/` directory yields an
    /// empty index. Lookup against any coords returns `None` so the
    /// index-aware helper falls through to v1 cleanly. This is the
    /// "no v2 store at all" case (pure-v1 test fixtures, fresh
    /// install populated v1 only).
    #[test]
    fn v2_baseline_index_empty_when_no_v2_links() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        assert!(index.lookup("nonexistent", "1.0.0").is_none());
    }

    /// A populated v2 store yields a hit through the indexed lookup.
    /// This is the hot path for `lpm rebuild` on a v2-default install.
    #[test]
    fn v2_baseline_index_hits_populated_link_entry() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let store = V2Store::from_lpm_root(&lpm_root);

        let sri = synthetic_sri(b"baseline_index/lodash");
        write_object(
            &store,
            &sri,
            &[(
                "package.json",
                b"{\"name\":\"lodash\",\"version\":\"4.17.21\"}",
            )],
        );
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: std::sync::Arc::new(sample_key("lodash", "4.17.21")),
                source_sri: sri.clone(),
                object_dir: store.paths().object_dir(&sri).unwrap(),
                deps: vec![],
                platform: std::sync::Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        let hit = index
            .lookup("lodash", "4.17.21")
            .expect("populated link entry must be indexed");
        assert_eq!(hit.layout, PackageBaselineLayout::V2);
        assert_eq!(hit.integrity, sri);
        assert!(
            hit.package_dir.exists(),
            "indexed package_dir must point at a real materialization"
        );
        assert!(
            hit.pristine_dir.exists(),
            "indexed pristine_dir must point at the populated objects/<sri>/"
        );
        // Different by design under v2 — pristine_dir is the immutable
        // object dir; package_dir is the link entry's clonefile copy.
        assert_ne!(
            hit.package_dir, hit.pristine_dir,
            "v2 entries must surface a distinct pristine_dir"
        );
    }

    /// `find_installed_package_baseline_indexed` falls through to v1
    /// when the index has no entry. Mirror of the legacy helper's
    /// fall-through path, but reachable via the per-loop O(1) form.
    #[test]
    fn indexed_helper_falls_through_to_v1_on_index_miss() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        // Seed v1 only (no v2 link entries) — index is empty, but the
        // legacy v1 fallback should still resolve the package.
        let store_v1 = PackageStore::from_root(&lpm_root);
        let pkg_dir = store_v1.package_dir("legacy", "1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join(".integrity"), "sha512-stub").unwrap();
        std::fs::write(pkg_dir.join("package.json"), r#"{"name":"legacy"}"#).unwrap();

        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        let resolved =
            find_installed_package_baseline_indexed(&index, &lpm_root, "legacy", "1.0.0")
                .expect("v1 fallback must populate the result");
        assert_eq!(resolved.layout, PackageBaselineLayout::V1);
        assert_eq!(
            resolved.package_dir, resolved.pristine_dir,
            "v1 entries alias pristine_dir to package_dir (the v1 store \
             dir is never mutated by patches)"
        );
    }

    /// When two link entries legitimately share the same
    /// `(name, version)` (the patched-vs-unpatched cross-project
    /// case, or multi-source-same-coords), `V2BaselineIndex::for_project`
    /// MUST resolve to the link entry the CURRENT project's tree
    /// points at — not the first match in global directory order.
    ///
    /// Seeds two link entries for `lodash@1.0.0`, points project A's
    /// `node_modules/lodash` symlink at the SECOND one, and asserts
    /// the project-scoped index returns that one. The global walker
    /// would return whichever entry comes first in directory order
    /// — wrong half the time for project A.
    ///
    /// Without project-scoping, `lpm rebuild` in project A could
    /// read scripts / trust state from the WRONG link entry and
    /// stamp the build marker into a sibling project's store dir.
    #[cfg(unix)]
    #[test]
    fn for_project_resolves_to_the_link_entry_this_project_uses() {
        use crate::v2::link_meta::{LinkMeta, LinkMetaPlatform};
        use chrono::Utc;

        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        // Seed two link entries for the same coords. Both have
        // realistic (different) graph-key dir names; both have a
        // populated package dir + sidecar. The two coexist legitimately
        // after multi-link-per-coords support (e.g. one carries `patch_fingerprint`, the other
        // doesn't).
        let v2_links_root = dir.path().join("store").join("v2").join("links");
        let entry_unpatched = v2_links_root.join("lodash@1.0.0+aaaaaaaaaaaaaaaa");
        let entry_patched = v2_links_root.join("lodash@1.0.0+bbbbbbbbbbbbbbbb");
        for (link_dir, suffix) in [
            (&entry_unpatched, "aaaaaaaaaaaaaaaa"),
            (&entry_patched, "bbbbbbbbbbbbbbbb"),
        ] {
            let pkg_dir = link_dir.join("node_modules").join("lodash");
            std::fs::create_dir_all(&pkg_dir).unwrap();
            std::fs::write(
                pkg_dir.join("package.json"),
                r#"{"name":"lodash","version":"1.0.0"}"#,
            )
            .unwrap();
            let meta = LinkMeta {
                schema: 1,
                graph_key: format!("lodash@1.0.0+{suffix}"),
                graph_key_digest_hex: format!("{suffix}{suffix}{suffix}{suffix}"),
                name: "lodash".into(),
                version: "1.0.0".into(),
                source_sri: format!("sha512-stub-{suffix}"),
                object_path: format!("objects/sha512-stub-{suffix}"),
                deps: vec![],
                platform: std::sync::Arc::new(LinkMetaPlatform {
                    os: "darwin".into(),
                    cpu: "arm64".into(),
                    libc: None,
                }),
                created_at: Utc::now(),
                last_referenced_at: Utc::now(),
            };
            meta.write_to(link_dir).unwrap();
        }

        // Build project A: its `node_modules/lodash` symlinks INTO
        // the patched entry. This is the load-bearing fixture: the
        // project-scoped lookup must follow this symlink and return
        // the patched entry, never the unpatched one.
        let project = dir.path().join("project-a");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            entry_patched.join("node_modules").join("lodash"),
            project.join("node_modules").join("lodash"),
        )
        .unwrap();

        // Sanity: the global index could return either entry — that's
        // exactly the ambiguity the project-scoped lookup is meant to
        // eliminate.
        let global = V2BaselineIndex::build(&lpm_root).unwrap();
        let global_hit = global.lookup("lodash", "1.0.0").unwrap();
        let global_resolves_correctly = global_hit
            .package_dir
            .starts_with(entry_patched.join("node_modules"));
        // We don't assert which one global returns — just that the
        // project-scoped variant below is unambiguous about the right
        // answer.
        let _ = global_resolves_correctly;

        // The project-scoped index MUST land on the patched entry
        // because that's where project A's symlink resolves to. This
        let project_index = V2BaselineIndex::for_project(&project, &lpm_root).unwrap();
        let project_hit = project_index
            .lookup("lodash", "1.0.0")
            .expect("project-scoped index must resolve the package");
        assert!(
            project_hit
                .package_dir
                .starts_with(entry_patched.join("node_modules")),
            "project-scoped lookup MUST return the link entry the project's \
             symlinks resolve to (patched entry), not the first global match. \
             Got: {:?}, expected under: {:?}",
            project_hit.package_dir,
            entry_patched
        );
    }

    /// Direct-bin compatibility rewires `node_modules/<pkg>` to a
    /// project-local copy under `node_modules/.lpm/compat/<key>/`.
    /// Rebuild still needs to discover and mutate the owning v2 link
    /// entry, not the project-local copy.
    #[cfg(unix)]
    #[test]
    fn for_project_maps_compatibility_root_symlink_to_owning_link_entry() {
        use crate::v2::link_meta::{LinkMeta, LinkMetaPlatform};
        use chrono::Utc;

        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        let v2_links_root = dir.path().join("store").join("v2").join("links");
        let key_dir_name = "cli-tool@1.0.0+dddddddddddddddd";
        let entry = v2_links_root.join(key_dir_name);
        let link_pkg = entry.join("node_modules").join("cli-tool");
        std::fs::create_dir_all(&link_pkg).unwrap();
        std::fs::write(
            link_pkg.join("package.json"),
            r#"{"name":"cli-tool","version":"1.0.0","bin":{"cli-tool":"bin/cli.js"}}"#,
        )
        .unwrap();
        let meta = LinkMeta {
            schema: 1,
            graph_key: key_dir_name.into(),
            graph_key_digest_hex:
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
            name: "cli-tool".into(),
            version: "1.0.0".into(),
            source_sri: "sha512-stub-cli-tool".into(),
            object_path: "objects/sha512-stub-cli-tool".into(),
            deps: vec![],
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        };
        meta.write_to(&entry).unwrap();

        let project = dir.path().join("project");
        let nm = project.join("node_modules");
        let compat_pkg = nm
            .join(".lpm")
            .join("compat")
            .join(key_dir_name)
            .join("node_modules")
            .join("cli-tool");
        std::fs::create_dir_all(&compat_pkg).unwrap();
        std::fs::write(
            compat_pkg.join("package.json"),
            r#"{"name":"cli-tool","version":"1.0.0"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&compat_pkg, nm.join("cli-tool")).unwrap();

        let index = V2BaselineIndex::for_project(&project, &lpm_root).unwrap();
        let hit = index
            .lookup("cli-tool", "1.0.0")
            .expect("compatibility root symlink must seed the owning link entry");
        assert!(
            hit.package_dir.starts_with(entry.join("node_modules")),
            "compatibility root must map back to the v2 link entry; got {:?}",
            hit.package_dir
        );
    }

    /// `for_project` reaches transitive dependencies via the BFS over
    /// `LinkMeta.deps`. The seed is the project's direct symlink; the
    /// transitive's link entry is reconstructed from the seed
    /// sidecar's `target_graph_key` digest (16-hex prefix) + name +
    /// version.
    ///
    /// Without this, `live_package_dir_with_v2`'s transitive fallback
    /// (which today routes through `Store::find_link_package_dir`'s
    /// global first-match) would still be ambiguous after multi-link-per-coords support.
    #[cfg(unix)]
    #[test]
    fn for_project_reaches_transitive_via_link_meta_deps() {
        use crate::v2::link_meta::{LinkMeta, LinkMetaDep, LinkMetaPlatform};
        use chrono::Utc;

        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        let v2_links_root = dir.path().join("store").join("v2").join("links");

        // Transitive: `tslib@2.0.0` lives in its own link entry, never
        // symlinked at the project root.
        let tslib_short = "1111111111111111";
        let tslib_full = format!("{tslib_short}{tslib_short}{tslib_short}{tslib_short}");
        let tslib_entry = v2_links_root.join(format!("tslib@2.0.0+{tslib_short}"));
        let tslib_pkg = tslib_entry.join("node_modules").join("tslib");
        std::fs::create_dir_all(&tslib_pkg).unwrap();
        std::fs::write(
            tslib_pkg.join("package.json"),
            r#"{"name":"tslib","version":"2.0.0"}"#,
        )
        .unwrap();
        let tslib_meta = LinkMeta {
            schema: 1,
            graph_key: format!("tslib@2.0.0+{tslib_short}"),
            graph_key_digest_hex: tslib_full.clone(),
            name: "tslib".into(),
            version: "2.0.0".into(),
            source_sri: "sha512-stub-tslib".into(),
            object_path: "objects/sha512-stub-tslib".into(),
            deps: vec![],
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        };
        tslib_meta.write_to(&tslib_entry).unwrap();

        // Direct: `consumer@1.0.0` is a project root dep that depends
        // on tslib. Its `LinkMeta.deps` carries tslib's full digest.
        let consumer_short = "2222222222222222";
        let consumer_entry = v2_links_root.join(format!("consumer@1.0.0+{consumer_short}"));
        let consumer_pkg = consumer_entry.join("node_modules").join("consumer");
        std::fs::create_dir_all(&consumer_pkg).unwrap();
        std::fs::write(
            consumer_pkg.join("package.json"),
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"tslib":"2.0.0"}}"#,
        )
        .unwrap();
        let consumer_meta = LinkMeta {
            schema: 1,
            graph_key: format!("consumer@1.0.0+{consumer_short}"),
            graph_key_digest_hex: format!(
                "{consumer_short}{consumer_short}{consumer_short}{consumer_short}"
            ),
            name: "consumer".into(),
            version: "1.0.0".into(),
            source_sri: "sha512-stub-consumer".into(),
            object_path: "objects/sha512-stub-consumer".into(),
            deps: vec![LinkMetaDep {
                local: "tslib".into(),
                target_graph_key: tslib_full,
                target_name: "tslib".into(),
                target_version: "2.0.0".into(),
            }],
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        };
        consumer_meta.write_to(&consumer_entry).unwrap();

        // Project: only the consumer is symlinked at the root; tslib
        // is reachable ONLY via `consumer`'s sidecar deps.
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            consumer_entry.join("node_modules").join("consumer"),
            project.join("node_modules").join("consumer"),
        )
        .unwrap();

        let index = V2BaselineIndex::for_project(&project, &lpm_root).unwrap();
        let consumer_hit = index.lookup("consumer", "1.0.0").unwrap();
        assert!(
            consumer_hit
                .package_dir
                .starts_with(consumer_entry.join("node_modules"))
        );
        let tslib_hit = index
            .lookup("tslib", "2.0.0")
            .expect("BFS through LinkMeta.deps must reach the transitive");
        assert!(
            tslib_hit
                .package_dir
                .starts_with(tslib_entry.join("node_modules")),
            "transitive lookup MUST land on tslib's link entry, not anywhere \
             else (got: {:?}, expected under {:?})",
            tslib_hit.package_dir,
            tslib_entry,
        );
    }

    /// Scoped direct deps live under `node_modules/@scope/pkg`, so the
    /// project root contains a real `@scope/` directory and the actual
    /// package symlink is nested one level deeper. `for_project` must
    /// seed from that nested symlink too, otherwise rebuild / install-
    /// hint silently skip the entire scoped direct-dependency surface.
    #[cfg(unix)]
    #[test]
    fn for_project_includes_scoped_direct_dependencies() {
        use crate::v2::link_meta::{LinkMeta, LinkMetaPlatform};
        use chrono::Utc;

        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        let v2_links_root = dir.path().join("store").join("v2").join("links");
        let entry = v2_links_root.join("@scope+pkg@1.0.0+cccccccccccccccc");
        let pkg_dir = entry.join("node_modules").join("@scope/pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"@scope/pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let meta = LinkMeta {
            schema: 1,
            graph_key: "@scope+pkg@1.0.0+cccccccccccccccc".into(),
            graph_key_digest_hex:
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            name: "@scope/pkg".into(),
            version: "1.0.0".into(),
            source_sri: "sha512-stub-scoped".into(),
            object_path: "objects/sha512-stub-scoped".into(),
            deps: vec![],
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        };
        meta.write_to(&entry).unwrap();

        let project = dir.path().join("project");
        let project_scope_dir = project.join("node_modules").join("@scope");
        std::fs::create_dir_all(&project_scope_dir).unwrap();
        std::os::unix::fs::symlink(
            entry.join("node_modules").join("@scope/pkg"),
            project_scope_dir.join("pkg"),
        )
        .unwrap();

        let index = V2BaselineIndex::for_project(&project, &lpm_root).unwrap();
        let hit = index
            .lookup("@scope/pkg", "1.0.0")
            .expect("scoped direct dependency must seed the project-scoped index");
        assert!(
            hit.package_dir.starts_with(entry.join("node_modules")),
            "scoped direct dep must resolve to its link entry; got {:?}",
            hit.package_dir
        );
    }

    /// Multi-coords collision: when two link entries share the same
    /// `(name, version)` (multi-source-same-coords or peer-divergent),
    /// the index keeps the FIRST entry seen — exactly matching the
    /// legacy linear scan's tie-breaking. Without this, a re-index
    /// could expose a different first-match across runs.
    #[test]
    fn v2_baseline_index_first_match_wins_for_duplicate_coords() {
        // The legacy `find_installed_package_baseline` scanned in
        // `iter_link_entries()` directory order and returned the
        // first match. The index must preserve that contract — a
        // duplicate insert must NOT overwrite the first hit.
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let store = V2Store::from_lpm_root(&lpm_root);

        // Two link entries for the same `(react, 18.0.0)` under
        // distinct graph keys (peer-divergent inputs differ in
        // `with_root_link_names` to fork the digest).
        use crate::v2::{GraphKeyInputs, LinkerModeTag, PlatformTuple};
        let key_a = crate::v2::GraphKey::derive(
            &GraphKeyInputs::new(
                "react",
                "18.0.0",
                PlatformTuple::new("darwin", "arm64", None),
                LinkerModeTag::Isolated,
            )
            .with_root_link_names(Some(vec!["react".into()])),
        );
        let key_b = crate::v2::GraphKey::derive(
            &GraphKeyInputs::new(
                "react",
                "18.0.0",
                PlatformTuple::new("darwin", "arm64", None),
                LinkerModeTag::Isolated,
            )
            .with_root_link_names(Some(vec!["react".into(), "alias".into()])),
        );
        assert_ne!(key_a, key_b, "fixture must produce divergent keys");

        let sri = synthetic_sri(b"baseline_index/react");
        write_object(
            &store,
            &sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"18.0.0\"}",
            )],
        );
        for key in [std::sync::Arc::new(key_a), std::sync::Arc::new(key_b)] {
            store
                .populate_link_entry(LinkEntryRequest {
                    graph_key: key,
                    source_sri: sri.clone(),
                    object_dir: store.paths().object_dir(&sri).unwrap(),
                    deps: vec![],
                    platform: std::sync::Arc::new(sample_meta_platform()),
                })
                .unwrap();
        }

        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        let hit = index
            .lookup("react", "18.0.0")
            .expect("either entry should satisfy the lookup");
        // Re-build and confirm the same entry wins. Stable
        // first-match-wins in the face of multi-entry coords.
        let index2 = V2BaselineIndex::build(&lpm_root).unwrap();
        let hit2 = index2.lookup("react", "18.0.0").unwrap();
        assert_eq!(
            hit.package_dir, hit2.package_dir,
            "rebuilding the index against the same disk state must \
             preserve first-match identity"
        );
    }

    /// `find_installed_package_baseline` must return a result
    /// keyed by lexicographic ordering of link-dir paths, not
    /// `read_dir`'s filesystem-order accident. A same-UID attacker
    /// who plants a link entry whose path sorts before the
    /// legitimate one must not be able to win the first-match race
    /// merely by getting their inode allocated earlier.
    #[test]
    fn find_installed_package_baseline_returns_lex_smallest_match_on_coord_collision() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let store = V2Store::from_lpm_root(&lpm_root);

        use crate::v2::{GraphKeyInputs, LinkerModeTag, PlatformTuple};
        let key_a = crate::v2::GraphKey::derive(
            &GraphKeyInputs::new(
                "react",
                "18.0.0",
                PlatformTuple::new("darwin", "arm64", None),
                LinkerModeTag::Isolated,
            )
            .with_root_link_names(Some(vec!["react".into()])),
        );
        let key_b = crate::v2::GraphKey::derive(
            &GraphKeyInputs::new(
                "react",
                "18.0.0",
                PlatformTuple::new("darwin", "arm64", None),
                LinkerModeTag::Isolated,
            )
            .with_root_link_names(Some(vec!["react".into(), "alias".into()])),
        );
        assert_ne!(key_a, key_b);

        let sri = synthetic_sri(b"deterministic_baseline/react");
        write_object(
            &store,
            &sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"18.0.0\"}",
            )],
        );
        for key in [std::sync::Arc::new(key_a), std::sync::Arc::new(key_b)] {
            store
                .populate_link_entry(LinkEntryRequest {
                    graph_key: key,
                    source_sri: sri.clone(),
                    object_dir: store.paths().object_dir(&sri).unwrap(),
                    deps: vec![],
                    platform: std::sync::Arc::new(sample_meta_platform()),
                })
                .unwrap();
        }

        // Discover what the canonical winner SHOULD be — the
        // lex-smallest link_dir among the two-coord matches.
        let entries: Vec<_> = store.iter_link_entries().unwrap().collect();
        let matching: Vec<_> = entries
            .iter()
            .filter(|(_, m)| m.name == "react" && m.version == "18.0.0")
            .map(|(d, _)| d.clone())
            .collect();
        assert_eq!(
            matching.len(),
            2,
            "fixture must yield two link entries for the colliding coords"
        );
        let expected = matching.iter().min().unwrap().clone();

        let hit = find_installed_package_baseline(&lpm_root, "react", "18.0.0")
            .unwrap()
            .expect("must match one of the link entries");
        let hit_link_dir = hit
            .package_dir
            .ancestors()
            .nth(2)
            .expect("link_dir is grandparent of package_dir")
            .to_path_buf();
        assert_eq!(
            hit_link_dir, expected,
            "find_installed_package_baseline must return the lex-smallest \
             link entry on coord collision, not read_dir order"
        );
    }
}
