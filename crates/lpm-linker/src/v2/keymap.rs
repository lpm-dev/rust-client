use std::collections::HashMap;
use std::sync::Arc;

use lpm_common::LpmError;
use lpm_store::v2::{GraphKey, LinkerModeTag, PlatformTuple};

use super::V2Target;
use crate::LinkDependency;

/// Per-install lookup table from exact package source identity to GraphKey.
/// Coordinate and wrapper indexes exist only to resolve legacy edge bindings;
/// ambiguous bindings fail instead of selecting an arbitrary source.
pub struct KeyMap {
    by_identity: HashMap<String, Arc<GraphKey>>,
    by_triple: HashMap<String, KeyEntry>,
    by_coords: HashMap<String, KeyEntry>,
    by_source: HashMap<String, KeyEntry>,
}

enum KeyEntry {
    Single(Arc<GraphKey>),
    Ambiguous,
}

enum IdentityEntry {
    Single(String),
    Ambiguous,
}

struct TargetIdentityIndex {
    by_triple: HashMap<String, IdentityEntry>,
    by_coords: HashMap<String, IdentityEntry>,
    by_source: HashMap<String, IdentityEntry>,
}

#[inline]
fn coords_key(name: &str, version: &str) -> String {
    let mut key = String::with_capacity(name.len() + 1 + version.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(version);
    key
}

#[inline]
fn triple_key(name: &str, version: &str, wrapper_id: Option<&str>) -> String {
    let wrapper_id = wrapper_id.unwrap_or("");
    let mut key = String::with_capacity(name.len() + 1 + version.len() + 1 + wrapper_id.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(version);
    key.push('\x00');
    key.push_str(wrapper_id);
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

#[inline]
fn identity_key(name: &str, version: &str, source_identity: &str) -> String {
    let mut key = String::with_capacity(name.len() + 1 + version.len() + 1 + source_identity.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(version);
    key.push('\x00');
    key.push_str(source_identity);
    key
}

fn insert_identity(index: &mut HashMap<String, IdentityEntry>, key: String, identity: &str) {
    match index.entry(key) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(IdentityEntry::Single(identity.to_string()));
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            if !matches!(entry.get(), IdentityEntry::Single(existing) if existing == identity) {
                entry.insert(IdentityEntry::Ambiguous);
            }
        }
    }
}

fn insert_key(index: &mut HashMap<String, KeyEntry>, key: String, graph_key: &Arc<GraphKey>) {
    match index.entry(key) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(KeyEntry::Single(Arc::clone(graph_key)));
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            if !matches!(entry.get(), KeyEntry::Single(existing) if existing == graph_key) {
                entry.insert(KeyEntry::Ambiguous);
            }
        }
    }
}

fn single_identity(entry: Option<&IdentityEntry>) -> Option<&str> {
    match entry {
        Some(IdentityEntry::Single(identity)) => Some(identity),
        Some(IdentityEntry::Ambiguous) | None => None,
    }
}

fn single_key(entry: Option<&KeyEntry>) -> Option<&Arc<GraphKey>> {
    match entry {
        Some(KeyEntry::Single(key)) => Some(key),
        Some(KeyEntry::Ambiguous) | None => None,
    }
}

impl TargetIdentityIndex {
    fn new(targets: &[V2Target]) -> Result<Self, LpmError> {
        let mut by_triple = HashMap::with_capacity(targets.len());
        let mut by_coords = HashMap::with_capacity(targets.len());
        let mut by_source = HashMap::with_capacity(targets.len());
        let mut exact = HashMap::with_capacity(targets.len());

        for v2t in targets {
            let exact_key =
                identity_key(&v2t.target.name, &v2t.target.version, &v2t.source_identity);
            if exact.insert(exact_key, ()).is_some() {
                return Err(LpmError::Store(format!(
                    "v2 linker: duplicate exact source identity for {}@{}",
                    v2t.target.name, v2t.target.version
                )));
            }
            insert_identity(
                &mut by_triple,
                triple_key(
                    &v2t.target.name,
                    &v2t.target.version,
                    v2t.target.wrapper_id.as_deref(),
                ),
                &v2t.source_identity,
            );
            insert_identity(
                &mut by_coords,
                coords_key(&v2t.target.name, &v2t.target.version),
                &v2t.source_identity,
            );
            if let Some(wrapper_id) = v2t.target.wrapper_id.as_deref() {
                insert_identity(
                    &mut by_source,
                    name_wrapper_key(&v2t.target.name, wrapper_id),
                    &v2t.source_identity,
                );
            }
        }

        Ok(Self {
            by_triple,
            by_coords,
            by_source,
        })
    }

    fn dependency(&self, dependency: &LinkDependency) -> Option<&str> {
        single_identity(self.by_triple.get(&triple_key(
            &dependency.target_name,
            &dependency.target_version,
            dependency.target_wrapper_id.as_deref(),
        )))
        .or_else(|| {
            dependency
                .target_wrapper_id
                .as_deref()
                .and_then(|wrapper_id| {
                    single_identity(
                        self.by_source
                            .get(&name_wrapper_key(&dependency.target_name, wrapper_id)),
                    )
                })
        })
        .or_else(|| {
            dependency.target_wrapper_id.is_none().then(|| {
                single_identity(self.by_coords.get(&coords_key(
                    &dependency.target_name,
                    &dependency.target_version,
                )))
            })?
        })
    }

    fn peer(&self, name: &str, binding: &str) -> Option<&str> {
        single_identity(self.by_triple.get(&triple_key(name, binding, None)))
            .or_else(|| single_identity(self.by_coords.get(&coords_key(name, binding))))
            .or_else(|| single_identity(self.by_source.get(&name_wrapper_key(name, binding))))
    }
}

impl KeyMap {
    pub(super) fn get_for(&self, target: &V2Target) -> Option<&Arc<GraphKey>> {
        self.by_identity.get(&identity_key(
            &target.target.name,
            &target.target.version,
            &target.source_identity,
        ))
    }

    pub(super) fn get_for_dependency(&self, dep: &LinkDependency) -> Option<&Arc<GraphKey>> {
        single_key(self.by_triple.get(&triple_key(
            &dep.target_name,
            &dep.target_version,
            dep.target_wrapper_id.as_deref(),
        )))
        .or_else(|| {
            dep.target_wrapper_id.as_deref().and_then(|wrapper_id| {
                single_key(
                    self.by_source
                        .get(&name_wrapper_key(&dep.target_name, wrapper_id)),
                )
            })
        })
        .or_else(|| {
            dep.target_wrapper_id.is_none().then(|| {
                single_key(
                    self.by_coords
                        .get(&coords_key(&dep.target_name, &dep.target_version)),
                )
            })?
        })
    }

    pub(super) fn get_peer(&self, name: &str, binding: &str) -> Option<&Arc<GraphKey>> {
        single_key(self.by_triple.get(&triple_key(name, binding, None)))
            .or_else(|| single_key(self.by_coords.get(&coords_key(name, binding))))
            .or_else(|| single_key(self.by_source.get(&name_wrapper_key(name, binding))))
    }
}

pub(super) fn derive_graph_keys(
    targets: &[V2Target],
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> Result<KeyMap, LpmError> {
    let identities = TargetIdentityIndex::new(targets)?;
    let mut derived = Vec::with_capacity(targets.len());

    for v2t in targets {
        let mut graph_key_deps = Vec::with_capacity(v2t.target.dependencies.len());
        for dep in &v2t.target.dependencies {
            let source_identity = identities.dependency(dep).ok_or_else(|| {
                LpmError::Store(format!(
                    "v2 linker: dependency {}=>{}@{} of {}@{} has an unresolved or ambiguous source identity",
                    dep.local,
                    dep.target_name,
                    dep.graph_key_value(),
                    v2t.target.name,
                    v2t.target.version
                ))
            })?;
            graph_key_deps.push((dep.local.clone(), source_identity.to_string()));
        }

        let mut graph_key_peers = Vec::with_capacity(v2t.target.peers.len());
        for (peer_name, binding) in &v2t.target.peers {
            let target_name = v2t
                .target
                .aliases
                .get(peer_name)
                .map_or(peer_name.as_str(), String::as_str);
            let source_identity = identities.peer(target_name, binding).ok_or_else(|| {
                LpmError::Store(format!(
                    "v2 linker: peer {peer_name}=>{target_name}@{binding} of {}@{} has an unresolved or ambiguous source identity",
                    v2t.target.name, v2t.target.version
                ))
            })?;
            graph_key_peers.push((peer_name.clone(), source_identity.to_string()));
        }

        let graph_key = Arc::new(GraphKey::derive_raw(
            &v2t.target.name,
            &v2t.target.version,
            platform,
            linker_tag,
            &graph_key_deps,
            &v2t.target.aliases,
            &graph_key_peers,
            v2t.target.root_link_names.as_deref(),
            Some(&v2t.source_identity),
            v2t.target.patch_fingerprint.as_deref(),
        ));
        derived.push((v2t, graph_key));
    }

    let mut by_identity = HashMap::with_capacity(targets.len());
    let mut by_triple = HashMap::with_capacity(targets.len());
    let mut by_coords = HashMap::with_capacity(targets.len());
    let mut by_source = HashMap::with_capacity(targets.len());
    for (v2t, graph_key) in derived {
        by_identity.insert(
            identity_key(&v2t.target.name, &v2t.target.version, &v2t.source_identity),
            Arc::clone(&graph_key),
        );
        insert_key(
            &mut by_triple,
            triple_key(
                &v2t.target.name,
                &v2t.target.version,
                v2t.target.wrapper_id.as_deref(),
            ),
            &graph_key,
        );
        insert_key(
            &mut by_coords,
            coords_key(&v2t.target.name, &v2t.target.version),
            &graph_key,
        );
        if let Some(wrapper_id) = v2t.target.wrapper_id.as_deref() {
            insert_key(
                &mut by_source,
                name_wrapper_key(&v2t.target.name, wrapper_id),
                &graph_key,
            );
        }
    }

    Ok(KeyMap {
        by_identity,
        by_triple,
        by_coords,
        by_source,
    })
}
