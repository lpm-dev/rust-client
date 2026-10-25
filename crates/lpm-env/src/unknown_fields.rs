//! Finding the first field a schema document uses that this version doesn't
//! know, so a typo and a field from a newer version read as what they are
//! instead of a generic invalid definition.
//!
//! The walk follows the JSON Schema the types derive, so the field set of
//! every node comes from the same declarations as the parser. Maps of
//! variable or group names are values, never checked as fields. For an
//! untagged union, a key is unknown only if no alternative defines it; the
//! typed parser still rejects invalid combinations. A key written twice is
//! checked in each copy, since the typed parser may have stopped at either.

use std::sync::OnceLock;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// A field no node of its kind defines, at `parent`, the path segments of
/// the object holding it, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownField {
    pub parent: Vec<String>,
    pub name: String,
}

/// The first unknown field of an `envSchema` document, including imported
/// schema files, in document order.
pub fn first_unknown_definition_field(document: &[u8]) -> Option<UnknownField> {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    first_unknown_field(
        document,
        SCHEMA.get_or_init(generated::<crate::EnvSchemaDefinition>),
    )
}

/// The first unknown field of a flat env schema, as the engine's flat
/// interface parses it.
pub fn first_unknown_schema_field(document: &[u8]) -> Option<UnknownField> {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    first_unknown_field(document, SCHEMA.get_or_init(generated::<crate::EnvSchema>))
}

fn generated<T: schemars::JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap_or(Value::Null)
}

fn first_unknown_field(document: &[u8], schema: &Value) -> Option<UnknownField> {
    let node: Node = serde_json::from_slice(document).ok()?;
    let mut parent = Vec::new();
    walk(&node, schema, schema, &mut parent)
}

/// A document's shape as written: every entry of an object, a repeated key
/// in each place it appears, and no scalar values.
enum Node {
    Object(Vec<(String, Node)>),
    Array(Vec<Node>),
    Scalar,
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NodeVisitor;

        impl<'de> Visitor<'de> for NodeVisitor {
            type Value = Node;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
                let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(entry) = map.next_entry::<String, Node>()? {
                    entries.push(entry);
                }
                Ok(Node::Object(entries))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Node, A::Error> {
                let mut nodes = Vec::with_capacity(items.size_hint().unwrap_or(0));
                while let Some(node) = items.next_element()? {
                    nodes.push(node);
                }
                Ok(Node::Array(nodes))
            }

            fn visit_bool<E>(self, _: bool) -> Result<Node, E> {
                Ok(Node::Scalar)
            }

            fn visit_i64<E>(self, _: i64) -> Result<Node, E> {
                Ok(Node::Scalar)
            }

            fn visit_u64<E>(self, _: u64) -> Result<Node, E> {
                Ok(Node::Scalar)
            }

            fn visit_f64<E>(self, _: f64) -> Result<Node, E> {
                Ok(Node::Scalar)
            }

            fn visit_str<E>(self, _: &str) -> Result<Node, E> {
                Ok(Node::Scalar)
            }

            fn visit_unit<E>(self) -> Result<Node, E> {
                Ok(Node::Scalar)
            }
        }

        deserializer.deserialize_any(NodeVisitor)
    }
}

fn walk(
    value: &Node,
    schema: &Value,
    root: &Value,
    parent: &mut Vec<String>,
) -> Option<UnknownField> {
    match value {
        Node::Object(entries) => walk_object(entries, schema, root, parent),
        Node::Array(items) => {
            let item_schemas: Vec<&Value> = alternatives(schema, root)
                .into_iter()
                .filter_map(|alternative| alternative.get("items"))
                .collect();
            if item_schemas.is_empty() {
                return None;
            }
            for (index, item) in items.iter().enumerate() {
                parent.push(index.to_string());
                let found = unknown_under_all(item, &item_schemas, root, parent);
                parent.pop();
                if found.is_some() {
                    return found;
                }
            }
            None
        }
        Node::Scalar => None,
    }
}

fn walk_object(
    entries: &[(String, Node)],
    schema: &Value,
    root: &Value,
    parent: &mut Vec<String>,
) -> Option<UnknownField> {
    let objects: Vec<&Value> = alternatives(schema, root)
        .into_iter()
        .filter(|alternative| accepts_objects(alternative))
        .collect();
    if objects.is_empty() {
        return None;
    }
    for (key, child) in entries {
        let mut child_schemas = Vec::with_capacity(objects.len());
        let mut open = false;
        for object in &objects {
            match field_schema(object, key) {
                FieldSchema::Defined(child_schema) => child_schemas.push(child_schema),
                FieldSchema::Open => open = true,
                FieldSchema::Closed => {}
            }
        }
        if child_schemas.is_empty() {
            if open {
                continue;
            }
            return Some(UnknownField {
                parent: parent.clone(),
                name: key.clone(),
            });
        }
        parent.push(key.clone());
        let found = if open {
            None
        } else {
            unknown_under_all(child, &child_schemas, root, parent)
        };
        parent.pop();
        if found.is_some() {
            return found;
        }
    }
    None
}

/// An unknown field inside `value` only when every schema that could
/// describe it reports one, so a union alternative that accepts it wins.
fn unknown_under_all(
    value: &Node,
    schemas: &[&Value],
    root: &Value,
    parent: &mut Vec<String>,
) -> Option<UnknownField> {
    let mut first = None;
    for schema in schemas {
        match walk(value, schema, root, parent) {
            None => return None,
            Some(found) => {
                first.get_or_insert(found);
            }
        }
    }
    first
}

enum FieldSchema<'schema> {
    Defined(&'schema Value),
    Open,
    Closed,
}

fn field_schema<'schema>(object: &'schema Value, key: &str) -> FieldSchema<'schema> {
    if let Some(property) = object
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(key))
    {
        return FieldSchema::Defined(property);
    }
    for member in object
        .get("allOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(property) = member
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(key))
        {
            return FieldSchema::Defined(property);
        }
    }
    match object.get("additionalProperties") {
        Some(Value::Bool(false)) => FieldSchema::Closed,
        Some(schema @ Value::Object(_)) => FieldSchema::Defined(schema),
        _ => FieldSchema::Open,
    }
}

fn accepts_objects(schema: &Value) -> bool {
    match schema.get("type") {
        Some(Value::String(kind)) => kind == "object",
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind == "object"),
        _ => schema.get("properties").is_some() || schema.get("additionalProperties").is_some(),
    }
}

/// The concrete schemas `schema` may be: references resolved and `anyOf`
/// and `oneOf` flattened.
fn alternatives<'schema>(schema: &'schema Value, root: &'schema Value) -> Vec<&'schema Value> {
    let mut found = Vec::with_capacity(2);
    collect_alternatives(schema, root, &mut found, 0);
    found
}

fn collect_alternatives<'schema>(
    schema: &'schema Value,
    root: &'schema Value,
    found: &mut Vec<&'schema Value>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    if let Some(target) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(resolved) = resolve(target, root) {
            collect_alternatives(resolved, root, found, depth + 1);
        }
        return;
    }
    let mut branched = false;
    for keyword in ["anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            branched = true;
            for branch in branches {
                collect_alternatives(branch, root, found, depth + 1);
            }
        }
    }
    if !branched || schema.get("properties").is_some() {
        found.push(schema);
    }
}

fn resolve<'schema>(target: &str, root: &'schema Value) -> Option<&'schema Value> {
    let path = target.strip_prefix('#')?;
    root.pointer(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(json: &str) -> Option<(Vec<String>, String)> {
        first_unknown_definition_field(json.as_bytes()).map(|found| (found.parent, found.name))
    }

    fn path(segments: &[&str]) -> Vec<String> {
        segments
            .iter()
            .map(|segment| (*segment).to_owned())
            .collect()
    }

    #[test]
    fn a_misspelled_rule_field_is_found_with_its_parent() {
        assert_eq!(
            definition(r#"{"vars":{"API_URL":{"format":"url","rotateEvery":"30d"}}}"#),
            Some((path(&["vars", "API_URL"]), "rotateEvery".to_owned()))
        );
    }

    #[test]
    fn variable_and_group_names_are_never_fields() {
        assert_eq!(
            definition(
                r#"{"vars":{"ANYTHING_AT_ALL":{"required":true}},"groups":{"any_group":{"mode":"allOrNone","vars":["ANYTHING_AT_ALL"]}}}"#
            ),
            None
        );
    }

    #[test]
    fn a_top_level_unknown_field_is_found() {
        assert_eq!(
            definition(r#"{"vars":{},"rotationPolicy":{}}"#),
            Some((Vec::new(), "rotationPolicy".to_owned()))
        );
    }

    #[test]
    fn an_unknown_field_in_any_copy_of_a_repeated_key_is_found() {
        assert_eq!(
            definition(r#"{"vars":{"A":{"requird":true},"A":{"required":true}}}"#),
            Some((path(&["vars", "A"]), "requird".to_owned()))
        );
        assert_eq!(
            definition(r#"{"vars":{"A":{}},"vars":{"B":{"zeta":1}}}"#),
            Some((path(&["vars", "B"]), "zeta".to_owned()))
        );
    }

    #[test]
    fn the_first_unknown_field_in_document_order_wins() {
        assert_eq!(
            definition(r#"{"vars":{"B":{"zeta":1},"A":{"alpha":1}}}"#),
            Some((path(&["vars", "B"]), "zeta".to_owned()))
        );
    }

    #[test]
    fn a_union_key_is_unknown_only_when_no_alternative_defines_it() {
        assert_eq!(
            definition(r#"{"vars":{"A":{"requiredWhen":{"variable":"B","equals":"x"}},"B":{}}}"#),
            None
        );
        assert_eq!(
            definition(r#"{"vars":{"A":{"requiredWhen":{"variable":"B","present":true}},"B":{}}}"#),
            None
        );
        assert_eq!(
            definition(r#"{"vars":{"A":{"requiredWhen":{"variable":"B","matches":"x"}},"B":{}}}"#),
            Some((path(&["vars", "A", "requiredWhen"]), "matches".to_owned()))
        );
    }

    #[test]
    fn valid_documents_and_type_errors_have_no_unknown_field() {
        assert_eq!(definition(r#"{"vars":{"A":{"required":"yes"}}}"#), None);
        assert_eq!(definition("not json"), None);
    }

    #[test]
    fn the_flat_schema_reports_definition_only_fields_as_unknown() {
        let found = first_unknown_schema_field(br#"{"vars":{},"extends":["preset:node"]}"#);
        assert_eq!(found.map(|found| found.name), Some("extends".to_owned()));
    }
}
