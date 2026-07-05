use std::collections::{BTreeMap, BTreeSet, HashMap};

pub(super) struct MapDiff {
    pub(super) kind: &'static str,
    pub(super) name: String,
    pub(super) manifest: String,
    pub(super) lockfile: String,
}

pub(super) fn btree_from_hash_map(map: &HashMap<String, String>) -> BTreeMap<String, String> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub(super) fn nested_btree_from_hash_map(
    map: &HashMap<String, HashMap<String, String>>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    map.iter()
        .map(|(key, value)| (key.clone(), btree_from_hash_map(value)))
        .collect()
}

pub(super) fn compare_string_maps(
    kind: &'static str,
    current: &BTreeMap<String, String>,
    locked: &BTreeMap<String, String>,
) -> Option<MapDiff> {
    let keys: BTreeSet<&String> = current.keys().chain(locked.keys()).collect();
    for key in keys {
        if current.get(key) != locked.get(key) {
            return Some(MapDiff {
                kind,
                name: key.clone(),
                manifest: current
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| "<absent>".to_string()),
                lockfile: locked
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| "<absent>".to_string()),
            });
        }
    }
    None
}

pub(super) fn compare_nested_string_maps(
    kind: &'static str,
    current: &BTreeMap<String, BTreeMap<String, String>>,
    locked: &BTreeMap<String, BTreeMap<String, String>>,
) -> Option<MapDiff> {
    let outer_keys: BTreeSet<&String> = current.keys().chain(locked.keys()).collect();
    for outer in outer_keys {
        let empty = BTreeMap::new();
        if let Some(diff) = compare_string_maps(
            kind,
            current.get(outer).unwrap_or(&empty),
            locked.get(outer).unwrap_or(&empty),
        ) {
            return Some(MapDiff {
                name: format!("{outer}.{}", diff.name),
                ..diff
            });
        }
    }
    None
}

pub(super) fn compare_option(
    name: &'static str,
    current: &Option<String>,
    locked: &Option<String>,
) -> Option<MapDiff> {
    (current != locked).then(|| MapDiff {
        kind: "setting",
        name: name.to_string(),
        manifest: current.clone().unwrap_or_else(|| "<absent>".to_string()),
        lockfile: locked.clone().unwrap_or_else(|| "<absent>".to_string()),
    })
}
