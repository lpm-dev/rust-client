use crate::{
    MAX_DEPTH, MAX_EDGES, MAX_MERGE_VISITS, MAX_NODES, MAX_SCHEMA_BYTES, MAX_SOURCE_BYTES,
    RESOLVER_VERSION, ResolutionStats, ResolvedSchema, SchemaDependency, SchemaSnapshot,
    SourceError, SourceLocation, declaration_code, digest, json_size, read,
};
use lpm_env::{EnvSchema, EnvSchemaDefinition, EnvVarRule, VarGroup, env_schema_preset};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

struct Declaration<T> {
    value: Arc<T>,
    origin: Arc<SourceLocation>,
    declaring_origin: Arc<SourceLocation>,
}

impl<T: serde::Serialize> serde::Serialize for Declaration<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

impl<T> Clone for Declaration<T> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            origin: Arc::clone(&self.origin),
            declaring_origin: Arc::clone(&self.declaring_origin),
        }
    }
}

#[derive(Default)]
struct Node {
    height: usize,
    vars: HashMap<String, Declaration<EnvVarRule>>,
    groups: HashMap<String, Declaration<VarGroup>>,
    prefixes: BTreeSet<String>,
}

struct Graph {
    root: Arc<cap_std::fs::Dir>,
    memo: HashMap<String, Arc<Node>>,
    active: HashSet<String>,
    identities: HashMap<same_file::Handle, String>,
    requested: BTreeSet<String>,
    dependencies: BTreeMap<String, SchemaDependency>,
    edges: Vec<(String, String)>,
    stats: ResolutionStats,
    root_identity: Option<same_file::Handle>,
    named_root: Option<std::path::PathBuf>,
}

pub(crate) fn resolve(
    root: Arc<cap_std::fs::Dir>,
    root_content: &[u8],
    definition: Cow<'_, EnvSchemaDefinition>,
    named_root: Option<std::path::PathBuf>,
) -> Result<ResolvedSchema, SourceError> {
    if root_content.len() > 16 * 1024 * 1024 {
        return Err(SourceError::new(
            "env.source_budget",
            "resolve",
            "lpm.json",
            "/envSchema",
        ));
    }
    let root_identity = same_file::Handle::from_file(
        root.try_clone()
            .map_err(|_| {
                SourceError::new(
                    "env.project_unavailable",
                    "resolve",
                    "lpm.json",
                    "/envSchema",
                )
            })?
            .into_std_file(),
    )
    .map_err(|_| {
        SourceError::new(
            "env.project_unavailable",
            "resolve",
            "lpm.json",
            "/envSchema",
        )
    })?;
    let mut graph = Graph {
        root,
        root_identity: Some(root_identity),
        named_root,
        memo: HashMap::with_capacity(MAX_NODES),
        active: HashSet::with_capacity(MAX_DEPTH),
        identities: HashMap::with_capacity(MAX_NODES),
        requested: BTreeSet::new(),
        dependencies: BTreeMap::new(),
        edges: Vec::with_capacity(MAX_EDGES),
        stats: ResolutionStats {
            source_bytes: json_size(definition.as_ref(), MAX_SCHEMA_BYTES)?,
            ..Default::default()
        },
    };
    let result = graph
        .visit("lpm.json", Some(definition.into_owned()), 0)
        .and_then(|node| graph.finish(root_content, node));
    result.map_err(|mut error| {
        error.requested_paths = graph.requested.into_iter().collect();
        error
    })
}

impl Graph {
    fn visit(
        &mut self,
        source: &str,
        definition: Option<EnvSchemaDefinition>,
        depth: usize,
    ) -> Result<Arc<Node>, SourceError> {
        if depth > MAX_DEPTH {
            return Err(SourceError::new(
                "env.graph_depth",
                "resolve",
                source,
                "/extends",
            ));
        }
        if self.active.contains(source) {
            return Err(SourceError::new(
                "env.import_cycle",
                "resolve",
                source,
                "/extends",
            ));
        }
        if let Some(node) = self.memo.get(source) {
            if depth + node.height > MAX_DEPTH {
                return Err(SourceError::new(
                    "env.graph_depth",
                    "resolve",
                    source,
                    "/extends",
                ));
            }
            return Ok(Arc::clone(node));
        }
        if self.stats.nodes == MAX_NODES {
            return Err(SourceError::new(
                "env.graph_nodes",
                "resolve",
                source,
                "/extends",
            ));
        }
        self.stats.nodes += 1;
        self.active.insert(source.into());
        let definition = match definition {
            Some(definition) => definition,
            None if source.starts_with("preset:") => env_schema_preset(&source[7..])
                .ok_or_else(|| SourceError::new("env.unknown_preset", "resolve", source, ""))?,
            None => {
                self.requested.insert(source.into());
                let file = read::read_fragment(&self.root, source)?;
                if let Some(existing) = self.identities.get(&file.identity) {
                    let code = if self.active.contains(existing) {
                        "env.import_cycle"
                    } else {
                        "env.source_alias"
                    };
                    return Err(SourceError::new(code, "resolve", source, ""));
                }
                self.identities.insert(file.identity, source.into());
                if file.content.len() > MAX_SOURCE_BYTES.saturating_sub(self.stats.source_bytes) {
                    return Err(SourceError::new("env.source_budget", "read", source, ""));
                }
                self.stats.source_bytes += file.content.len();
                self.dependencies.insert(
                    source.into(),
                    SchemaDependency {
                        path: source.into(),
                        digest: digest(&file.content),
                        bytes: file.content.len(),
                    },
                );
                decode_definition(strip_bom(&file.content), source)?
            }
        };
        let mut prefix_names = HashSet::with_capacity(definition.client_prefixes.len());
        if definition
            .client_prefixes
            .iter()
            .any(|name| !prefix_names.insert(name))
        {
            return Err(SourceError::new(
                "env.invalid_prefixes",
                "definition",
                source,
                "/clientPrefixes",
            ));
        }
        let mut node = Node::default();
        let mut var_conflicts = BTreeMap::new();
        let mut group_conflicts = BTreeMap::new();
        for import in definition.extends {
            if self.stats.edges == MAX_EDGES {
                return Err(SourceError::new(
                    "env.graph_edges",
                    "resolve",
                    source,
                    "/extends",
                ));
            }
            self.stats.edges += 1;
            let target = if import.starts_with("preset:") {
                import
            } else {
                read::import_path(source, &import)?
            };
            self.edges.push((source.into(), target.clone()));
            let inherited = self.visit(&target, None, depth + 1)?;
            node.height = node.height.max(inherited.height + 1);
            self.visit_cost(
                inherited.vars.len() + inherited.groups.len() + inherited.prefixes.len(),
                source,
            )?;
            merge(&mut node.vars, &inherited.vars, &mut var_conflicts);
            merge(&mut node.groups, &inherited.groups, &mut group_conflicts);
            node.prefixes.extend(inherited.prefixes.iter().cloned());
            check_counts(&node, source)?;
        }
        self.visit_cost(
            definition.vars.len()
                + definition.groups.len()
                + definition.overrides.len()
                + definition.group_overrides.len()
                + definition.client_prefixes.len(),
            source,
        )?;
        apply(
            &mut node.vars,
            definition.vars,
            definition.overrides,
            &mut var_conflicts,
            source,
            "vars",
            "overrides",
        )?;
        apply(
            &mut node.groups,
            definition.groups,
            definition.group_overrides,
            &mut group_conflicts,
            source,
            "groups",
            "groupOverrides",
        )?;
        node.prefixes.extend(definition.client_prefixes);
        check_counts(&node, source)?;
        if node
            .groups
            .values()
            .map(|g| g.value.vars.len())
            .sum::<usize>()
            > 4096
        {
            return Err(SourceError::new(
                "env.aggregate_budget",
                "resolve",
                source,
                "/groups",
            ));
        }
        self.active.remove(source);
        let node = Arc::new(node);
        self.memo.insert(source.into(), Arc::clone(&node));
        Ok(node)
    }

    fn visit_cost(&mut self, count: usize, source: &str) -> Result<(), SourceError> {
        if count > MAX_MERGE_VISITS.saturating_sub(self.stats.merge_visits) {
            return Err(SourceError::new("env.merge_budget", "resolve", source, ""));
        }
        self.stats.merge_visits += count;
        Ok(())
    }

    fn finish(
        &mut self,
        root_content: &[u8],
        node: Arc<Node>,
    ) -> Result<ResolvedSchema, SourceError> {
        #[derive(serde::Serialize)]
        struct SharedSchema<'a> {
            vars: &'a HashMap<String, Declaration<EnvVarRule>>,
            #[serde(skip_serializing_if = "HashMap::is_empty")]
            groups: &'a HashMap<String, Declaration<VarGroup>>,
            #[serde(rename = "clientPrefixes", skip_serializing_if = "BTreeSet::is_empty")]
            prefixes: &'a BTreeSet<String>,
        }
        json_size(
            &SharedSchema {
                vars: &node.vars,
                groups: &node.groups,
                prefixes: &node.prefixes,
            },
            MAX_SCHEMA_BYTES,
        )?;
        let origins: BTreeMap<_, _> = node
            .vars
            .iter()
            .map(|(key, declaration)| (key.clone(), (*declaration.origin).clone()))
            .collect();
        let declaring_origins: BTreeMap<_, _> = node
            .vars
            .iter()
            .filter(|(_, declaration)| {
                !Arc::ptr_eq(&declaration.origin, &declaration.declaring_origin)
            })
            .map(|(key, declaration)| (key.clone(), (*declaration.declaring_origin).clone()))
            .collect();
        let group_origins: BTreeMap<_, _> = node
            .groups
            .iter()
            .map(|(key, declaration)| (key.clone(), (*declaration.origin).clone()))
            .collect();
        self.memo.clear();
        let node = Arc::try_unwrap(node).map_err(|_| {
            SourceError::new("env.engine_internal", "resolve", "lpm.json", "/envSchema")
        })?;
        let schema = EnvSchema {
            vars: node
                .vars
                .into_iter()
                .map(|(key, rule)| {
                    (
                        key,
                        Arc::try_unwrap(rule.value).unwrap_or_else(|value| (*value).clone()),
                    )
                })
                .collect(),
            groups: node
                .groups
                .into_iter()
                .map(|(key, group)| {
                    (
                        key,
                        Arc::try_unwrap(group.value).unwrap_or_else(|value| (*value).clone()),
                    )
                })
                .collect(),
            client_prefixes: node.prefixes.into_iter().collect(),
        };

        if let Some(error) = lpm_env::validate_schema(&schema).into_iter().next() {
            let origin = origins.get(&error.key).or_else(|| {
                error
                    .key
                    .strip_prefix("envSchema.groups.")
                    .and_then(|name| group_origins.get(name))
            });
            let mut failure = SourceError::new(
                declaration_code(&error.kind),
                "definition",
                origin.map_or("lpm.json", |o| o.source.as_str()),
                origin.map_or("/envSchema", |o| o.pointer.as_str()),
            );
            if let lpm_env::ValidationErrorKind::InvalidRule { message } = error.kind {
                failure.diagnostic.message = Some(message);
            }
            failure.diagnostic.key = crate::diagnostic_key(&error.key);
            return Err(failure);
        }
        let dependencies: Vec<_> = self.dependencies.values().cloned().collect();
        let mut hash = Sha256::new();
        hash_record(&mut hash, RESOLVER_VERSION.as_bytes());
        let root_digest = digest(root_content);
        hash_record(&mut hash, &root_digest);
        for dependency in &dependencies {
            hash_record(&mut hash, dependency.path.as_bytes());
            hash_record(&mut hash, &dependency.digest);
        }
        for (source, target) in &self.edges {
            hash_record(&mut hash, source.as_bytes());
            hash_record(&mut hash, target.as_bytes());
        }
        Ok(ResolvedSchema {
            schema,
            snapshot: Arc::new(SchemaSnapshot {
                origins,
                group_origins,
                declaring_origins,
                dependencies,
                fingerprint: hash.finalize().into(),
                root_digest,
                stats: self.stats,
                root: Arc::clone(&self.root),
                root_identity: self.root_identity.take().ok_or_else(|| {
                    SourceError::new(
                        "env.project_unavailable",
                        "resolve",
                        "lpm.json",
                        "/envSchema",
                    )
                })?,
                named_root: self.named_root.take(),
            }),
        })
    }
}

/// Decode one schema document, locating a failure by its source and JSON
/// pointer. The diagnostic never contains literals from the document.
pub fn decode_definition(bytes: &[u8], source: &str) -> Result<EnvSchemaDefinition, SourceError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let definition = serde_path_to_error::deserialize(&mut deserializer).map_err(|failure| {
        let mut pointer = String::with_capacity(64);
        if source == "lpm.json" {
            pointer.push_str("/envSchema");
        }
        for segment in failure.path().iter() {
            pointer.push('/');
            match segment {
                serde_path_to_error::Segment::Map { key }
                | serde_path_to_error::Segment::Enum { variant: key } => {
                    push_pointer_segment(&mut pointer, key);
                }
                serde_path_to_error::Segment::Seq { index } => {
                    use std::fmt::Write;
                    let _ = write!(pointer, "{index}");
                }
                serde_path_to_error::Segment::Unknown => {
                    pointer.pop();
                }
            }
        }
        let mut error = SourceError::new("env.invalid_definition", "parse", source, &pointer);
        error.diagnostic.message = Some(match failure.inner().classify() {
            serde_json::error::Category::Data => {
                "Invalid schema definition. Check the field name and value type at this location."
            }
            _ => "Invalid JSON syntax. Correct this schema document.",
        });
        error
    })?;
    deserializer.end().map_err(|_| {
        let mut error = SourceError::new("env.invalid_definition", "parse", source, "");
        error.diagnostic.message = Some("Invalid JSON syntax. Correct this schema document.");
        error
    })?;
    Ok(definition)
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)
}

fn hash_record(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn check_counts(node: &Node, source: &str) -> Result<(), SourceError> {
    if node.vars.len() > 4096 || node.groups.len() > 128 || node.prefixes.len() > 32 {
        return Err(SourceError::new(
            "env.aggregate_budget",
            "resolve",
            source,
            "",
        ));
    }
    Ok(())
}

fn merge<T>(
    target: &mut HashMap<String, Declaration<T>>,
    source: &HashMap<String, Declaration<T>>,
    conflicts: &mut BTreeMap<String, [Arc<SourceLocation>; 2]>,
) {
    for (key, declaration) in source {
        if let Some(existing) = target.get(key) {
            if !Arc::ptr_eq(&existing.origin, &declaration.origin) {
                conflicts.entry(key.clone()).or_insert_with(|| {
                    [
                        Arc::clone(&existing.origin),
                        Arc::clone(&declaration.origin),
                    ]
                });
            }
        } else {
            target.insert(key.clone(), declaration.clone());
        }
    }
}

fn apply<T>(
    target: &mut HashMap<String, Declaration<T>>,
    local: HashMap<String, T>,
    overrides: HashMap<String, T>,
    conflicts: &mut BTreeMap<String, [Arc<SourceLocation>; 2]>,
    source: &str,
    field: &str,
    override_field: &str,
) -> Result<(), SourceError> {
    for key in local.keys().chain(overrides.keys()) {
        if key.len() > 256 || !lpm_env::is_valid_env_var_name(key) {
            return Err(SourceError::new(
                "env.invalid_name",
                "definition",
                source,
                &format!("/{field}"),
            ));
        }
    }
    let mut override_keys: Vec<_> = overrides.keys().collect();
    override_keys.sort_unstable();
    for key in override_keys {
        if !target.contains_key(key) {
            let mut error = SourceError::new(
                "env.override_missing",
                "resolve",
                source,
                &pointer(source, override_field, key),
            );
            error.diagnostic.key = crate::diagnostic_key(key);
            return Err(error);
        }
        if local.contains_key(key) {
            return Err(conflict_error(
                key,
                &SourceLocation {
                    source: source.into(),
                    pointer: pointer(source, field, key),
                },
                &SourceLocation {
                    source: source.into(),
                    pointer: pointer(source, override_field, key),
                },
            ));
        }
    }
    for (key, value) in local {
        let origin = Arc::new(SourceLocation {
            source: source.into(),
            pointer: pointer(source, field, &key),
        });
        if let Some(existing) = target.get(&key) {
            conflicts
                .entry(key.clone())
                .or_insert_with(|| [Arc::clone(&existing.origin), Arc::clone(&origin)]);
        }
        target.insert(
            key,
            Declaration {
                value: Arc::new(value),
                declaring_origin: Arc::clone(&origin),
                origin,
            },
        );
    }
    for (key, value) in overrides {
        let Some(existing) = target.get_mut(&key) else {
            let mut error = SourceError::new(
                "env.override_missing",
                "resolve",
                source,
                &pointer(source, override_field, &key),
            );
            error.diagnostic.key = crate::diagnostic_key(&key);
            return Err(error);
        };
        // An override is a replacement, never a partial merge of security policy.
        conflicts.remove(&key);
        let origin = Arc::new(SourceLocation {
            source: source.into(),
            pointer: pointer(source, override_field, &key),
        });
        existing.value = Arc::new(value);
        existing.origin = origin;
    }
    if let Some((key, origins)) = conflicts.first_key_value() {
        return Err(conflict_error(key, &origins[0], &origins[1]));
    }
    Ok(())
}

fn conflict_error(key: &str, first: &SourceLocation, second: &SourceLocation) -> SourceError {
    let mut error = SourceError::new(
        "env.declaration_conflict",
        "resolve",
        &second.source,
        &second.pointer,
    );
    error.diagnostic.key = crate::diagnostic_key(key);
    error.diagnostic.related_sources = vec![first.clone(), second.clone()];
    error
}

fn pointer(source: &str, field: &str, key: &str) -> String {
    let mut pointer = String::with_capacity(16 + field.len() + key.len());
    pointer.push_str(if source == "lpm.json" {
        "/envSchema/"
    } else {
        "/"
    });
    pointer.push_str(field);
    pointer.push('/');
    push_pointer_segment(&mut pointer, key);
    pointer
}

/// Appends an authored key as a JSON pointer segment that is safe to show:
/// characters that could hide or reorder the surrounding text are escaped.
fn push_pointer_segment(pointer: &mut String, segment: &str) {
    use std::fmt::Write;
    for c in segment.chars() {
        match c {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            c if !c.is_ascii() || crate::is_display_unsafe(c) => {
                let _ = write!(pointer, "{}", c.escape_unicode());
            }
            c => pointer.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_origins_merge_without_allocating_duplicate_keys() {
        let mut source = HashMap::with_capacity(4096);
        for index in 0..4096 {
            let key = format!("A{index:04}{}", "x".repeat(251));
            let origin = Arc::new(SourceLocation {
                source: "leaf.json".into(),
                pointer: "/vars".into(),
            });
            source.insert(
                key,
                Declaration {
                    value: Arc::new(EnvVarRule::default()),
                    declaring_origin: Arc::clone(&origin),
                    origin,
                },
            );
        }
        let mut target = source.clone();
        let mut conflicts = BTreeMap::new();
        let (_, allocated, maximum) =
            crate::tests::allocation_probe(|| merge(&mut target, &source, &mut conflicts));
        assert_eq!(allocated, 0);
        assert_eq!(maximum, 0);
        assert_eq!(target.len(), 4096);
        assert!(conflicts.is_empty());
    }
}
