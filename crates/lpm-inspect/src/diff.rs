//! Structural JSON diff engine.
//!
//! Compares two `serde_json::Value` trees and produces a typed diff —
//! added, removed, and changed nodes with their JSON Pointer paths.
//!
//! Unlike text-based diffing, this handles:
//! - Key ordering differences (JSON objects are unordered)
//! - Nested structure changes (deep path tracking)
//! - Type changes (string → number, object → array)
//! - Array element-by-element comparison (positional)
//!
//! The diff output is designed for frontend rendering with color-coded
//! highlights (green = added, red = removed, yellow = changed).

use serde::Serialize;
use serde_json::Value;

/// A single diff entry representing one change between two JSON values.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DiffEntry {
    /// JSON Pointer path to the changed node (e.g., "/data/object/id").
    pub path: String,
    /// The kind of change.
    pub kind: DiffKind,
    /// The old value (present for `Removed` and `Changed`).
    pub old: Option<Value>,
    /// The new value (present for `Added` and `Changed`).
    pub new: Option<Value>,
}

/// The kind of structural change.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiffKind {
    /// Key/element exists only in the new value.
    Added,
    /// Key/element exists only in the old value.
    Removed,
    /// Key/element exists in both but the value differs.
    Changed,
}

/// Compare two JSON values and return a list of structural differences.
///
/// Returns an empty vec if the values are identical.
///
/// # Path format
///
/// Uses JSON Pointer notation (RFC 6901):
/// - Root: `""`
/// - Object key: `"/key"`
/// - Nested: `"/data/object/id"`
/// - Array index: `"/items/0"`, `"/items/1"`
///
/// # Example
///
/// ```
/// use serde_json::json;
/// use lpm_inspect::diff::{diff_json, DiffKind};
///
/// let old = json!({"type": "charge.succeeded", "amount": 1000});
/// let new = json!({"type": "charge.succeeded", "amount": 2000, "currency": "usd"});
///
/// let diffs = diff_json(&old, &new);
/// assert_eq!(diffs.len(), 2); // amount changed, currency added
/// ```
pub fn diff_json(old: &Value, new: &Value) -> Vec<DiffEntry> {
    let mut entries = Vec::new();
    diff_recursive(old, new, String::new(), &mut entries);
    entries
}

fn diff_recursive(old: &Value, new: &Value, path: String, entries: &mut Vec<DiffEntry>) {
    // Same value — no diff
    if old == new {
        return;
    }

    match (old, new) {
        // Both objects — compare keys structurally
        (Value::Object(old_map), Value::Object(new_map)) => {
            // Keys removed (in old but not in new)
            for key in old_map.keys() {
                if !new_map.contains_key(key) {
                    let child_path = format!("{path}/{}", escape_json_pointer(key));
                    entries.push(DiffEntry {
                        path: child_path,
                        kind: DiffKind::Removed,
                        old: Some(old_map[key].clone()),
                        new: None,
                    });
                }
            }

            // Keys added (in new but not in old)
            for key in new_map.keys() {
                if !old_map.contains_key(key) {
                    let child_path = format!("{path}/{}", escape_json_pointer(key));
                    entries.push(DiffEntry {
                        path: child_path,
                        kind: DiffKind::Added,
                        old: None,
                        new: Some(new_map[key].clone()),
                    });
                }
            }

            // Keys in both — recurse to find nested changes
            for key in old_map.keys() {
                if let Some(new_val) = new_map.get(key) {
                    let child_path = format!("{path}/{}", escape_json_pointer(key));
                    diff_recursive(&old_map[key], new_val, child_path, entries);
                }
            }
        }

        // Both arrays — positional element comparison
        (Value::Array(old_arr), Value::Array(new_arr)) => {
            let max_len = old_arr.len().max(new_arr.len());
            for i in 0..max_len {
                let child_path = format!("{path}/{i}");
                match (old_arr.get(i), new_arr.get(i)) {
                    (Some(old_elem), Some(new_elem)) => {
                        diff_recursive(old_elem, new_elem, child_path, entries);
                    }
                    (Some(old_elem), None) => {
                        entries.push(DiffEntry {
                            path: child_path,
                            kind: DiffKind::Removed,
                            old: Some(old_elem.clone()),
                            new: None,
                        });
                    }
                    (None, Some(new_elem)) => {
                        entries.push(DiffEntry {
                            path: child_path,
                            kind: DiffKind::Added,
                            old: None,
                            new: Some(new_elem.clone()),
                        });
                    }
                    (None, None) => unreachable!(),
                }
            }
        }

        // Different types or different primitive values
        _ => {
            entries.push(DiffEntry {
                path,
                kind: DiffKind::Changed,
                old: Some(old.clone()),
                new: Some(new.clone()),
            });
        }
    }
}

/// Escape a JSON Pointer token per RFC 6901.
/// `~` → `~0`, `/` → `~1`
fn escape_json_pointer(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Compute a diff summary for display purposes.
pub fn diff_summary(entries: &[DiffEntry]) -> DiffSummary {
    let mut added = 0;
    let mut removed = 0;
    let mut changed = 0;
    for entry in entries {
        match entry.kind {
            DiffKind::Added => added += 1,
            DiffKind::Removed => removed += 1,
            DiffKind::Changed => changed += 1,
        }
    }
    DiffSummary {
        total: entries.len(),
        added,
        removed,
        changed,
    }
}

/// Summary counts of a diff result.
#[derive(Debug, Serialize)]
pub struct DiffSummary {
    pub total: usize,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identical_values_no_diff() {
        let v = json!({"type": "charge.succeeded", "amount": 1000});
        let diffs = diff_json(&v, &v);
        assert!(diffs.is_empty());
    }

    #[test]
    fn primitive_change() {
        let old = json!(42);
        let new = json!(99);
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "");
        assert_eq!(diffs[0].kind, DiffKind::Changed);
        assert_eq!(diffs[0].old, Some(json!(42)));
        assert_eq!(diffs[0].new, Some(json!(99)));
    }

    #[test]
    fn type_change() {
        let old = json!("hello");
        let new = json!(42);
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::Changed);
    }

    #[test]
    fn object_key_added() {
        let old = json!({"a": 1});
        let new = json!({"a": 1, "b": 2});
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/b");
        assert_eq!(diffs[0].kind, DiffKind::Added);
        assert_eq!(diffs[0].new, Some(json!(2)));
    }

    #[test]
    fn object_key_removed() {
        let old = json!({"a": 1, "b": 2});
        let new = json!({"a": 1});
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/b");
        assert_eq!(diffs[0].kind, DiffKind::Removed);
        assert_eq!(diffs[0].old, Some(json!(2)));
    }

    #[test]
    fn object_value_changed() {
        let old = json!({"amount": 1000});
        let new = json!({"amount": 2000});
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/amount");
        assert_eq!(diffs[0].kind, DiffKind::Changed);
        assert_eq!(diffs[0].old, Some(json!(1000)));
        assert_eq!(diffs[0].new, Some(json!(2000)));
    }

    #[test]
    fn nested_object_change() {
        let old = json!({"data": {"object": {"id": "ch_123", "amount": 1000}}});
        let new = json!({"data": {"object": {"id": "ch_123", "amount": 2000}}});
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/data/object/amount");
        assert_eq!(diffs[0].kind, DiffKind::Changed);
    }

    #[test]
    fn deep_nested_add_and_remove() {
        let old = json!({"a": {"b": {"c": 1, "d": 2}}});
        let new = json!({"a": {"b": {"c": 1, "e": 3}}});
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 2);

        let removed = diffs.iter().find(|d| d.kind == DiffKind::Removed).unwrap();
        assert_eq!(removed.path, "/a/b/d");

        let added = diffs.iter().find(|d| d.kind == DiffKind::Added).unwrap();
        assert_eq!(added.path, "/a/b/e");
    }

    #[test]
    fn array_element_changed() {
        let old = json!([1, 2, 3]);
        let new = json!([1, 99, 3]);
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/1");
        assert_eq!(diffs[0].kind, DiffKind::Changed);
    }

    #[test]
    fn array_element_added() {
        let old = json!([1, 2]);
        let new = json!([1, 2, 3]);
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/2");
        assert_eq!(diffs[0].kind, DiffKind::Added);
    }

    #[test]
    fn array_element_removed() {
        let old = json!([1, 2, 3]);
        let new = json!([1, 2]);
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/2");
        assert_eq!(diffs[0].kind, DiffKind::Removed);
    }

    #[test]
    fn array_of_objects() {
        let old = json!([{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]);
        let new = json!([{"id": 1, "name": "a"}, {"id": 2, "name": "c"}]);
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/1/name");
        assert_eq!(diffs[0].kind, DiffKind::Changed);
    }

    #[test]
    fn key_ordering_irrelevant() {
        // JSON objects are unordered — same keys in different order should produce no diff
        let old = json!({"b": 2, "a": 1});
        let new = json!({"a": 1, "b": 2});
        let diffs = diff_json(&old, &new);
        assert!(diffs.is_empty());
    }

    #[test]
    fn null_handling() {
        let old = json!({"a": null});
        let new = json!({"a": 1});
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::Changed);
        assert_eq!(diffs[0].old, Some(Value::Null));
    }

    #[test]
    fn object_to_array_type_change() {
        let old = json!({"a": {"nested": true}});
        let new = json!({"a": [1, 2, 3]});
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "/a");
        assert_eq!(diffs[0].kind, DiffKind::Changed);
    }

    #[test]
    fn json_pointer_escape() {
        assert_eq!(escape_json_pointer("simple"), "simple");
        assert_eq!(escape_json_pointer("a/b"), "a~1b");
        assert_eq!(escape_json_pointer("a~b"), "a~0b");
        assert_eq!(escape_json_pointer("~/"), "~0~1");
    }

    #[test]
    fn diff_summary_counts() {
        let old = json!({"a": 1, "b": 2, "c": 3});
        let new = json!({"a": 99, "c": 3, "d": 4});
        let diffs = diff_json(&old, &new);
        let summary = diff_summary(&diffs);
        assert_eq!(summary.changed, 1); // a: 1 → 99
        assert_eq!(summary.removed, 1); // b removed
        assert_eq!(summary.added, 1); // d added
        assert_eq!(summary.total, 3);
    }

    #[test]
    fn realistic_stripe_webhook_diff() {
        let old = json!({
            "id": "evt_1",
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {
                    "id": "in_123",
                    "amount_paid": 2000,
                    "status": "paid",
                    "lines": {
                        "data": [
                            {"id": "li_1", "amount": 2000}
                        ]
                    }
                }
            },
            "livemode": false
        });

        let new = json!({
            "id": "evt_2",
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {
                    "id": "in_456",
                    "amount_paid": 5000,
                    "status": "paid",
                    "discount": {"coupon": "SAVE20"},
                    "lines": {
                        "data": [
                            {"id": "li_2", "amount": 5000}
                        ]
                    }
                }
            },
            "livemode": true
        });

        let diffs = diff_json(&old, &new);

        // Should find: id changed, data.object.id changed, amount_paid changed,
        // discount added, lines.data[0].id changed, lines.data[0].amount changed,
        // livemode changed
        assert!(diffs.len() >= 6);

        // Verify specific paths exist
        let paths: Vec<&str> = diffs.iter().map(|d| d.path.as_str()).collect();
        assert!(paths.contains(&"/id"));
        assert!(paths.contains(&"/data/object/id"));
        assert!(paths.contains(&"/data/object/amount_paid"));
        assert!(paths.contains(&"/data/object/discount"));
        assert!(paths.contains(&"/livemode"));
    }

    #[test]
    fn empty_objects_no_diff() {
        let diffs = diff_json(&json!({}), &json!({}));
        assert!(diffs.is_empty());
    }

    #[test]
    fn empty_arrays_no_diff() {
        let diffs = diff_json(&json!([]), &json!([]));
        assert!(diffs.is_empty());
    }

    #[test]
    fn bool_change() {
        let old = json!({"livemode": false});
        let new = json!({"livemode": true});
        let diffs = diff_json(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].old, Some(json!(false)));
        assert_eq!(diffs[0].new, Some(json!(true)));
    }
}
