use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use lpm_common::{LpmError, PackageInstanceId};
use lpm_store::v2::{GraphKey, LinkerModeTag, PlatformTuple};

use super::V2Target;
use crate::LinkDependency;
#[cfg(test)]
use crate::LinkTarget;

/// Per-install lookup table from exact package-instance identity to the
/// derived `GraphKey`.
///
/// Built once during [`link_v2_prepare`], stored on [`LinkPlanV2`],
/// consulted by every [`link_v2_one`] / [`link_v2_finalize`] call.
/// Public so callers can hold a reference across spawn boundaries
/// without reaching into linker private API.
pub struct KeyMap {
    by_instance: HashMap<PackageInstanceId, Arc<GraphKey>>,
}

struct GraphKeyCacheInput {
    target: Arc<V2Target>,
    platform: PlatformTuple,
    linker_tag: LinkerModeTag,
}

impl GraphKeyCacheInput {
    fn from_target(
        target: &Arc<V2Target>,
        platform: &PlatformTuple,
        linker_tag: LinkerModeTag,
    ) -> Self {
        Self {
            target: Arc::clone(target),
            platform: platform.clone(),
            linker_tag,
        }
    }

    fn matches(
        &self,
        target: &V2Target,
        platform: &PlatformTuple,
        linker_tag: LinkerModeTag,
    ) -> bool {
        let cached_target = &self.target;
        let cached_link_target = &cached_target.target;
        let link_target = &target.target;
        cached_link_target.name == link_target.name
            && cached_link_target.version == link_target.version
            && &self.platform == platform
            && self.linker_tag == linker_tag
            && cached_link_target.dependencies == link_target.dependencies
            && cached_target.dependency_targets == target.dependency_targets
            && cached_link_target.aliases == link_target.aliases
            && cached_link_target.peers == link_target.peers
            && cached_target.peer_targets == target.peer_targets
            && cached_link_target.root_link_names == link_target.root_link_names
            && cached_link_target.wrapper_id == link_target.wrapper_id
            && cached_link_target.patch_fingerprint == link_target.patch_fingerprint
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
    target: &V2Target,
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> u64 {
    let link_target = &target.target;
    let mut fingerprint = 0xcbf29ce484222325u64;
    for value in [
        link_target.name.as_str(),
        link_target.version.as_str(),
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
    for dependency in &link_target.dependencies {
        for value in [
            dependency.local.as_str(),
            dependency.target_name.as_str(),
            dependency.target_version.as_str(),
        ] {
            fingerprint_bytes(&mut fingerprint, value.as_bytes());
        }
        fingerprint_optional(&mut fingerprint, dependency.target_wrapper_id.as_deref());
        if let Some(instance_id) = target.dependency_targets.get(&dependency.local) {
            fingerprint_bytes(&mut fingerprint, instance_id.as_bytes());
        }
    }
    let mut aliases_fingerprint = 0u64;
    for (local, canonical) in &link_target.aliases {
        let mut entry_fingerprint = 0xcbf29ce484222325u64;
        fingerprint_bytes(&mut entry_fingerprint, local.as_bytes());
        fingerprint_bytes(&mut entry_fingerprint, canonical.as_bytes());
        aliases_fingerprint ^= entry_fingerprint;
    }
    fingerprint_bytes(&mut fingerprint, &aliases_fingerprint.to_le_bytes());
    for peer in &link_target.peers {
        fingerprint_bytes(&mut fingerprint, peer.local_name.as_bytes());
        fingerprint_bytes(&mut fingerprint, peer.target_name.as_bytes());
        fingerprint_bytes(&mut fingerprint, peer.target_version.as_bytes());
        fingerprint_optional(&mut fingerprint, peer.target_wrapper_id.as_deref());
        if let Some(instance_id) = target.peer_targets.get(&peer.local_name) {
            fingerprint_bytes(&mut fingerprint, instance_id.as_bytes());
        }
    }
    match link_target.root_link_names.as_deref() {
        None => fingerprint_bytes(&mut fingerprint, b"none"),
        Some(names) => {
            fingerprint_bytes(&mut fingerprint, b"some");
            for name in names {
                fingerprint_bytes(&mut fingerprint, name.as_bytes());
            }
        }
    }
    fingerprint_optional(&mut fingerprint, link_target.wrapper_id.as_deref());
    fingerprint_optional(&mut fingerprint, link_target.patch_fingerprint.as_deref());
    fingerprint
}

fn derive_graph_key(
    target: &V2Target,
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> Arc<GraphKey> {
    let link_target = &target.target;
    let mut graph_key_deps: Vec<(String, String)> =
        Vec::with_capacity(link_target.dependencies.len());
    graph_key_deps.extend(
        link_target
            .dependencies
            .iter()
            .map(|dep| (dep.local.clone(), dep.graph_key_value().to_string())),
    );
    Arc::new(GraphKey::derive_raw_exact_peer_edges(
        &link_target.name,
        &link_target.version,
        platform,
        linker_tag,
        &graph_key_deps,
        &target.dependency_targets,
        &link_target.aliases,
        &link_target.peers,
        &target.peer_targets,
        link_target.root_link_names.as_deref(),
        link_target.wrapper_id.as_deref(),
        link_target.patch_fingerprint.as_deref(),
    ))
}

impl KeyMap {
    pub(super) fn get_for(&self, target: &V2Target) -> Option<&Arc<GraphKey>> {
        self.by_instance.get(&target.instance_id)
    }

    pub(super) fn get_for_dependency(
        &self,
        target: &V2Target,
        dep: &LinkDependency,
    ) -> Option<&Arc<GraphKey>> {
        target
            .dependency_targets
            .get(&dep.local)
            .and_then(|instance_id| self.by_instance.get(instance_id))
    }

    pub(super) fn get_peer(
        &self,
        target: &V2Target,
        peer: &lpm_common::PeerEdge,
    ) -> Option<&Arc<GraphKey>> {
        target
            .peer_targets
            .get(&peer.local_name)
            .and_then(|instance_id| self.by_instance.get(instance_id))
    }
}

pub(super) fn derive_graph_keys(
    targets: &[Arc<V2Target>],
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
    cache: Option<&GraphKeyCache>,
) -> Result<KeyMap, LpmError> {
    let mut by_instance: HashMap<PackageInstanceId, Arc<GraphKey>> =
        HashMap::with_capacity(targets.len());

    let graph_keys = cache.map_or_else(
        || {
            targets
                .iter()
                .map(|target| derive_graph_key(target, platform, linker_tag))
                .collect()
        },
        |cache| cache.derive_many(targets, platform, linker_tag),
    );

    for (v2t, key) in targets.iter().zip(graph_keys) {
        if by_instance.insert(v2t.instance_id, key).is_some() {
            return Err(LpmError::Store(format!(
                "virtual-store linker: duplicate package instance {} for {}@{}",
                v2t.instance_id, v2t.target.name, v2t.target.version
            )));
        }
    }
    Ok(KeyMap { by_instance })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::Materialization;

    fn target() -> V2Target {
        let child_id = PackageInstanceId::derive("child", "2.0.0", "registry+npm", "child");
        let peer_id = PackageInstanceId::derive("peer", "3.0.0", "registry+npm", "peer");
        V2Target {
            instance_id: PackageInstanceId::derive("shared", "1.0.0", "registry+npm", "shared"),
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
                peers: vec![lpm_common::PeerEdge::registry("peer", "peer", "3.0.0")],
                patch_fingerprint: None,
            }),
            dependency_targets: HashMap::from([("child".to_string(), child_id)]),
            peer_targets: HashMap::from([("peer".to_string(), peer_id)]),
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
        Arc::make_mut(&mut peer.target).peers = vec![lpm_common::PeerEdge::registry(
            "other-peer",
            "other-peer",
            "3.0.0",
        )];
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

    #[test]
    fn same_coordinate_contextual_targets_get_distinct_key_map_entries() {
        let platform = PlatformTuple::new("darwin", "arm64", None);
        let first = target();
        let mut second = target();
        second.instance_id =
            PackageInstanceId::derive("shared", "1.0.0", "registry+npm", "second-context");
        second.source_sri = "sha512-other-context".to_string();
        Arc::make_mut(&mut second.target).dependencies =
            vec![LinkDependency::registry("other-child", "2.0.0")];

        let result = derive_graph_keys(
            &[Arc::new(first), Arc::new(second)],
            &platform,
            LinkerModeTag::Isolated,
            None,
        );

        assert!(
            result.is_ok(),
            "same-coordinate package instances with different materialization contexts must not collapse"
        );
    }

    #[test]
    fn consumer_instance_id_does_not_split_identical_materialization() {
        let platform = PlatformTuple::new("darwin", "arm64", None);
        let first = target();
        let mut second = first.clone();
        second.instance_id =
            PackageInstanceId::derive("shared", "1.0.0", "registry+npm", "second-consumer");
        let targets = [Arc::new(first), Arc::new(second)];

        let key_map = derive_graph_keys(&targets, &platform, LinkerModeTag::Isolated, None)
            .expect("distinct row IDs with identical context must remain addressable");

        assert_eq!(key_map.get_for(&targets[0]), key_map.get_for(&targets[1]));
    }
}
