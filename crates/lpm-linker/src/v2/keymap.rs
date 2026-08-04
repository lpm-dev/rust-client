use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

use lpm_common::LpmError;
use lpm_store::v2::{GraphKey, LinkerModeTag, PlatformTuple};

use super::V2Target;
use crate::{LinkDependency, LinkTarget};

/// Per-install lookup table from `(name, version, wrapper_id)` to the
/// derived `GraphKey`.
///
/// Built once during [`link_v2_prepare`], stored on [`LinkPlanV2`],
/// consulted by every [`link_v2_one`] / [`link_v2_finalize`] call.
/// Public so callers can hold a reference across spawn boundaries
/// without reaching into linker private API.
///
/// Two lookup indexes plus one duplicate guard:
/// - `by_triple` — full `(name, version, wrapper_id)` identity. Used
///   by `populate_one` to fetch this target's own key and to resolve
///   source-aware dependency edges.
/// - `by_coords` — `(name, version)` only. Used only when the install
///   graph has a single unambiguous package at those coordinates.
/// - `source_identities` — `(name, wrapper_id)` guard so one source
///   identity cannot appear twice with diverging versions.
///
/// Keys are stored as a single `String` using a `\x00`-separated
/// compound key: `"name\x00version"` for `by_coords` and
/// `"name\x00version\x00wrapper_id"` for `by_triple`. Package names
/// and versions never contain null bytes, so there is no collision risk.
/// This lets lookups form the key with a single `format!` call (1 alloc)
/// instead of cloning each field separately (2–3 allocs per lookup).
pub struct KeyMap {
    by_triple: HashMap<String, Arc<GraphKey>>,
    by_coords: HashMap<String, CoordEntry>,
}

enum CoordEntry {
    Single(Arc<GraphKey>),
    Ambiguous,
}

#[derive(Eq, PartialEq)]
struct GraphKeyCacheInput {
    name: String,
    version: String,
    platform: PlatformTuple,
    linker_tag: LinkerModeTag,
    dependencies: Vec<LinkDependency>,
    aliases: HashMap<String, String>,
    peers: Vec<(String, String)>,
    root_link_names: Option<Vec<String>>,
    wrapper_id: Option<String>,
    patch_fingerprint: Option<String>,
}

impl GraphKeyCacheInput {
    fn from_target(
        target: &LinkTarget,
        platform: &PlatformTuple,
        linker_tag: LinkerModeTag,
    ) -> Self {
        Self {
            name: target.name.clone(),
            version: target.version.clone(),
            platform: platform.clone(),
            linker_tag,
            dependencies: target.dependencies.clone(),
            aliases: target.aliases.clone(),
            peers: target.peers.clone(),
            root_link_names: target.root_link_names.clone(),
            wrapper_id: target.wrapper_id.clone(),
            patch_fingerprint: target.patch_fingerprint.clone(),
        }
    }

    fn matches(
        &self,
        target: &LinkTarget,
        platform: &PlatformTuple,
        linker_tag: LinkerModeTag,
    ) -> bool {
        self.name == target.name
            && self.version == target.version
            && &self.platform == platform
            && self.linker_tag == linker_tag
            && self.dependencies == target.dependencies
            && self.aliases == target.aliases
            && self.peers == target.peers
            && self.root_link_names == target.root_link_names
            && self.wrapper_id == target.wrapper_id
            && self.patch_fingerprint == target.patch_fingerprint
    }
}

struct CachedGraphKey {
    input: GraphKeyCacheInput,
    graph_key: Arc<GraphKey>,
}

#[derive(Default)]
pub struct GraphKeyCache {
    entries: Mutex<HashMap<u64, Vec<CachedGraphKey>>>,
}

impl GraphKeyCache {
    fn derive_many(
        &self,
        targets: &[Arc<V2Target>],
        platform: &PlatformTuple,
        linker_tag: LinkerModeTag,
    ) -> Vec<Arc<GraphKey>> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut graph_keys = Vec::with_capacity(targets.len());
        for target in targets {
            let target = &target.target;
            let fingerprint = graph_key_input_fingerprint(target, platform, linker_tag);
            let bucket = entries.entry(fingerprint).or_default();
            if let Some(cached) = bucket
                .iter()
                .find(|cached| cached.input.matches(target, platform, linker_tag))
            {
                graph_keys.push(Arc::clone(&cached.graph_key));
                continue;
            }
            let graph_key = derive_graph_key(target, platform, linker_tag);
            bucket.push(CachedGraphKey {
                input: GraphKeyCacheInput::from_target(target, platform, linker_tag),
                graph_key: Arc::clone(&graph_key),
            });
            graph_keys.push(graph_key);
        }
        graph_keys
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(Vec::len)
            .sum()
    }
}

fn fingerprint_bytes(fingerprint: &mut u64, bytes: &[u8]) {
    *fingerprint ^= bytes.len() as u64;
    *fingerprint = fingerprint.wrapping_mul(0x100000001b3);
    for byte in bytes {
        *fingerprint ^= u64::from(*byte);
        *fingerprint = fingerprint.wrapping_mul(0x100000001b3);
    }
}

fn fingerprint_optional(fingerprint: &mut u64, value: Option<&str>) {
    match value {
        Some(value) => {
            fingerprint_bytes(fingerprint, b"1");
            fingerprint_bytes(fingerprint, value.as_bytes());
        }
        None => fingerprint_bytes(fingerprint, b"0"),
    }
}

fn graph_key_input_fingerprint(
    target: &LinkTarget,
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> u64 {
    let mut fingerprint = 0xcbf29ce484222325u64;
    for value in [
        target.name.as_str(),
        target.version.as_str(),
        platform.os.as_str(),
        platform.cpu.as_str(),
    ] {
        fingerprint_bytes(&mut fingerprint, value.as_bytes());
    }
    fingerprint_optional(&mut fingerprint, platform.libc.as_deref());
    fingerprint_bytes(
        &mut fingerprint,
        match linker_tag {
            LinkerModeTag::Isolated => b"isolated",
            LinkerModeTag::Hoisted => b"hoisted",
        },
    );
    for dependency in &target.dependencies {
        for value in [
            dependency.local.as_str(),
            dependency.target_name.as_str(),
            dependency.target_version.as_str(),
        ] {
            fingerprint_bytes(&mut fingerprint, value.as_bytes());
        }
        fingerprint_optional(&mut fingerprint, dependency.target_wrapper_id.as_deref());
    }
    let mut aliases_fingerprint = 0u64;
    for (local, canonical) in &target.aliases {
        let mut entry_fingerprint = 0xcbf29ce484222325u64;
        fingerprint_bytes(&mut entry_fingerprint, local.as_bytes());
        fingerprint_bytes(&mut entry_fingerprint, canonical.as_bytes());
        aliases_fingerprint ^= entry_fingerprint;
    }
    fingerprint_bytes(&mut fingerprint, &aliases_fingerprint.to_le_bytes());
    for (name, version) in &target.peers {
        fingerprint_bytes(&mut fingerprint, name.as_bytes());
        fingerprint_bytes(&mut fingerprint, version.as_bytes());
    }
    match target.root_link_names.as_deref() {
        None => fingerprint_bytes(&mut fingerprint, b"none"),
        Some(names) => {
            fingerprint_bytes(&mut fingerprint, b"some");
            for name in names {
                fingerprint_bytes(&mut fingerprint, name.as_bytes());
            }
        }
    }
    fingerprint_optional(&mut fingerprint, target.wrapper_id.as_deref());
    fingerprint_optional(&mut fingerprint, target.patch_fingerprint.as_deref());
    fingerprint
}

fn derive_graph_key(
    target: &LinkTarget,
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> Arc<GraphKey> {
    let mut graph_key_deps: Vec<(String, String)> = Vec::with_capacity(target.dependencies.len());
    graph_key_deps.extend(
        target
            .dependencies
            .iter()
            .map(|dep| (dep.local.clone(), dep.graph_key_value().to_string())),
    );
    Arc::new(GraphKey::derive_raw(
        &target.name,
        &target.version,
        platform,
        linker_tag,
        &graph_key_deps,
        &target.aliases,
        &target.peers,
        target.root_link_names.as_deref(),
        target.wrapper_id.as_deref(),
        target.patch_fingerprint.as_deref(),
    ))
}

/// Form the `by_coords` key: `"name\x00version"`.
#[inline]
fn coords_key(name: &str, version: &str) -> String {
    let mut key = String::with_capacity(name.len() + 1 + version.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(version);
    key
}

/// Form the `by_triple` key: `"name\x00version\x00wrapper_id"`.
#[inline]
fn triple_key(name: &str, version: &str, wrapper_id: Option<&str>) -> String {
    let wid = wrapper_id.unwrap_or("");
    let mut key = String::with_capacity(name.len() + 1 + version.len() + 1 + wid.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(version);
    key.push('\x00');
    key.push_str(wid);
    key
}

#[inline]
fn name_wrapper_key(name: &str, wrapper_id: &str) -> String {
    let mut key = String::with_capacity(name.len() + 1 + wrapper_id.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(wrapper_id);
    key
}

impl KeyMap {
    pub(super) fn get_for(&self, target: &LinkTarget) -> Option<&Arc<GraphKey>> {
        self.by_triple.get(&triple_key(
            &target.name,
            &target.version,
            target.wrapper_id.as_deref(),
        ))
    }

    pub(super) fn get_for_dependency(&self, dep: &LinkDependency) -> Option<&Arc<GraphKey>> {
        self.by_triple
            .get(&triple_key(
                &dep.target_name,
                &dep.target_version,
                dep.target_wrapper_id.as_deref(),
            ))
            .or_else(|| {
                if dep.target_wrapper_id.is_none() {
                    self.get_by_coords_unambiguous(&dep.target_name, &dep.target_version)
                } else {
                    None
                }
            })
    }

    pub(super) fn get_peer(&self, name: &str, version: &str) -> Option<&Arc<GraphKey>> {
        self.by_triple
            .get(&triple_key(name, version, None))
            .or_else(|| self.get_by_coords_unambiguous(name, version))
    }

    fn get_by_coords_unambiguous(&self, name: &str, version: &str) -> Option<&Arc<GraphKey>> {
        match self.by_coords.get(&coords_key(name, version)) {
            Some(CoordEntry::Single(gk)) => Some(gk),
            Some(CoordEntry::Ambiguous) | None => None,
        }
    }
}

pub(super) fn derive_graph_keys(
    targets: &[Arc<V2Target>],
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
    cache: Option<&GraphKeyCache>,
) -> Result<KeyMap, LpmError> {
    let mut by_triple: HashMap<String, Arc<GraphKey>> = HashMap::with_capacity(targets.len());
    let mut source_identities: HashSet<String> = HashSet::with_capacity(targets.len());
    let mut by_coords: HashMap<String, CoordEntry> = HashMap::with_capacity(targets.len());

    let graph_keys = cache.map_or_else(
        || {
            targets
                .iter()
                .map(|target| derive_graph_key(&target.target, platform, linker_tag))
                .collect()
        },
        |cache| cache.derive_many(targets, platform, linker_tag),
    );

    for (v2t, key) in targets.iter().zip(graph_keys) {
        let tkey = triple_key(
            &v2t.target.name,
            &v2t.target.version,
            v2t.target.wrapper_id.as_deref(),
        );
        if by_triple.insert(tkey, key.clone()).is_some() {
            return Err(LpmError::Store(format!(
                "virtual-store linker: duplicate LinkTarget for {}@{} wrapper_id={:?}",
                v2t.target.name, v2t.target.version, v2t.target.wrapper_id
            )));
        }
        if let Some(wrapper_id) = v2t.target.wrapper_id.as_deref() {
            let wkey = name_wrapper_key(&v2t.target.name, wrapper_id);
            if !source_identities.insert(wkey) {
                return Err(LpmError::Store(format!(
                    "virtual-store linker: duplicate source identity for {} wrapper_id={wrapper_id:?}",
                    v2t.target.name
                )));
            }
        }

        let ckey = coords_key(&v2t.target.name, &v2t.target.version);
        match by_coords.entry(ckey) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(CoordEntry::Single(key));
            }
            std::collections::hash_map::Entry::Occupied(mut existing) => {
                existing.insert(CoordEntry::Ambiguous);
            }
        }
    }
    Ok(KeyMap {
        by_triple,
        by_coords,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::Materialization;

    fn target() -> V2Target {
        V2Target {
            target: Arc::new(LinkTarget {
                name: "shared".to_string(),
                version: "1.0.0".to_string(),
                store_path: PathBuf::new(),
                dependencies: vec![LinkDependency::registry("child", "2.0.0")],
                aliases: HashMap::new(),
                is_direct: false,
                root_link_names: Some(Vec::new()),
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: vec![("peer".to_string(), "3.0.0".to_string())],
                patch_fingerprint: None,
            }),
            source_sri: "sha512-shared".to_string(),
            verified_object_integrity: None,
            fresh_object: None,
        }
    }

    #[test]
    fn graph_key_cache_reuses_identical_derivation_inputs() {
        let cache = GraphKeyCache::default();
        let platform = PlatformTuple::new("darwin", "arm64", None);
        let target = target();

        cache.derive_many(
            &[Arc::new(target.clone())],
            &platform,
            LinkerModeTag::Isolated,
        );
        cache.derive_many(&[Arc::new(target)], &platform, LinkerModeTag::Isolated);

        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn graph_key_cache_keeps_all_derivation_contexts_distinct() {
        let cache = GraphKeyCache::default();
        let platform = PlatformTuple::new("darwin", "arm64", None);
        let base = target();
        let mut dependency = base.clone();
        Arc::make_mut(&mut dependency.target).dependencies =
            vec![LinkDependency::registry("other-child", "2.0.0")];
        let mut alias = base.clone();
        Arc::make_mut(&mut alias.target)
            .aliases
            .insert("child".to_string(), "canonical-child".to_string());
        let mut peer = base.clone();
        Arc::make_mut(&mut peer.target).peers =
            vec![("other-peer".to_string(), "3.0.0".to_string())];
        let mut direct = base.clone();
        Arc::make_mut(&mut direct.target).root_link_names = Some(vec!["shared".to_string()]);
        let mut wrapped = base.clone();
        Arc::make_mut(&mut wrapped.target).wrapper_id = Some("t-source".to_string());
        let mut patched = base.clone();
        Arc::make_mut(&mut patched.target).patch_fingerprint = Some("p-content".to_string());

        cache.derive_many(
            &[Arc::new(base.clone())],
            &platform,
            LinkerModeTag::Isolated,
        );
        cache.derive_many(&[Arc::new(dependency)], &platform, LinkerModeTag::Isolated);
        cache.derive_many(&[Arc::new(alias)], &platform, LinkerModeTag::Isolated);
        cache.derive_many(&[Arc::new(peer)], &platform, LinkerModeTag::Isolated);
        cache.derive_many(&[Arc::new(direct)], &platform, LinkerModeTag::Isolated);
        cache.derive_many(&[Arc::new(wrapped)], &platform, LinkerModeTag::Isolated);
        cache.derive_many(&[Arc::new(patched)], &platform, LinkerModeTag::Isolated);
        cache.derive_many(&[Arc::new(base)], &platform, LinkerModeTag::Hoisted);
        cache.derive_many(
            &[Arc::new(target())],
            &PlatformTuple::new("linux", "arm64", Some("musl".to_string())),
            LinkerModeTag::Isolated,
        );

        assert_eq!(cache.len(), 9);
    }
}
