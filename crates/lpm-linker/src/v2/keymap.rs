use std::collections::HashMap;
use std::sync::Arc;

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
/// Three lookup indexes:
/// - `by_triple` — full `(name, version, wrapper_id)` identity. Used
///   by `populate_one` to fetch this target's own key and to resolve
///   source-aware dependency edges.
/// - `by_coords` — `(name, version)` only. Used only when the install
///   graph has a single unambiguous package at those coordinates.
/// - `by_source` — `(name, wrapper_id)`. Resolves source-bound peer edges
///   and rejects duplicate source identities.
///
/// Keys are stored as a single `String` using a `\x00`-separated
/// compound key: `"name\x00version"` for `by_coords` and
/// `"name\x00version\x00wrapper_id"` for `by_triple`. Package names
/// and versions never contain null bytes, so there is no collision risk.
pub struct KeyMap {
    by_triple: HashMap<String, Arc<GraphKey>>,
    by_coords: HashMap<String, CoordEntry>,
    by_source: HashMap<String, Arc<GraphKey>>,
}

enum CoordEntry {
    Single(Arc<GraphKey>),
    Ambiguous,
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

    pub(super) fn get_peer(&self, name: &str, binding: &str) -> Option<&Arc<GraphKey>> {
        self.by_triple
            .get(&triple_key(name, binding, None))
            .or_else(|| self.get_by_coords_unambiguous(name, binding))
            .or_else(|| self.by_source.get(&name_wrapper_key(name, binding)))
    }

    fn get_by_coords_unambiguous(&self, name: &str, version: &str) -> Option<&Arc<GraphKey>> {
        match self.by_coords.get(&coords_key(name, version)) {
            Some(CoordEntry::Single(gk)) => Some(gk),
            Some(CoordEntry::Ambiguous) | None => None,
        }
    }
}

pub(super) fn derive_graph_keys(
    targets: &[V2Target],
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> Result<KeyMap, LpmError> {
    let mut by_triple: HashMap<String, Arc<GraphKey>> = HashMap::with_capacity(targets.len());
    let mut by_source: HashMap<String, Arc<GraphKey>> = HashMap::with_capacity(targets.len());
    let mut by_coords: HashMap<String, CoordEntry> = HashMap::with_capacity(targets.len());

    for v2t in targets {
        let graph_key_peers: &[(String, String)] = &v2t.target.peers;
        let mut graph_key_deps: Vec<(String, String)> =
            Vec::with_capacity(v2t.target.dependencies.len());
        graph_key_deps.extend(
            v2t.target
                .dependencies
                .iter()
                .map(|dep| (dep.local.clone(), dep.graph_key_value().to_string())),
        );

        let key = Arc::new(GraphKey::derive_raw(
            &v2t.target.name,
            &v2t.target.version,
            platform,
            linker_tag,
            &graph_key_deps,
            &v2t.target.aliases,
            graph_key_peers,
            v2t.target.root_link_names.as_deref(),
            v2t.target.wrapper_id.as_deref(),
            v2t.target.patch_fingerprint.as_deref(),
        ));

        let tkey = triple_key(
            &v2t.target.name,
            &v2t.target.version,
            v2t.target.wrapper_id.as_deref(),
        );
        if by_triple.insert(tkey, key.clone()).is_some() {
            return Err(LpmError::Store(format!(
                "v2 linker: duplicate LinkTarget for {}@{} wrapper_id={:?}",
                v2t.target.name, v2t.target.version, v2t.target.wrapper_id
            )));
        }
        if let Some(wrapper_id) = v2t.target.wrapper_id.as_deref() {
            let wkey = name_wrapper_key(&v2t.target.name, wrapper_id);
            if by_source.insert(wkey, key.clone()).is_some() {
                return Err(LpmError::Store(format!(
                    "v2 linker: duplicate source identity for {} wrapper_id={wrapper_id:?}",
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
        by_source,
    })
}
