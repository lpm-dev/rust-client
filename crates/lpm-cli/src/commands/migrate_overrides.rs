//! Translate `package.json > pnpm.overrides` into LPM's
//! native override location at migrate time.
//!
//! The plan is computed and validated before any file mutation: parse
//! errors, unsupported value shapes, and merge conflicts are all
//! discovered up-front so the migrate flow can abort cleanly without
//! touching disk.
//!
//! ## What goes where
//!
//! - **Translatable entries** (string-valued, parsable through LPM's
//!   selector grammar, no conflict with existing `lpm.overrides`) land
//!   in `to_apply`. The migrate handler merges these into
//!   `package.json > lpm.overrides`.
//! - **Conflicts** (same raw key in both `pnpm.overrides` and
//!   `lpm.overrides` with different targets) are blocking errors. The
//!   raw key is the comparison unit.
//! - **Parse errors** (e.g. multi-segment paths, invalid version
//!   ranges) are blocking errors. We surface the offending entry with
//!   the underlying parser message so the user can port manually.
//! - **Unsupported value shapes** (object, array, null — pnpm allows
//!   some of these for niche cases) are blocking errors. We don't
//!   silently skip them.
//!
//! ## Why this lives in `lpm-cli` instead of `lpm-migrate`
//!
//! Validation needs LPM's selector parser ([`OverrideSet::parse`] from
//! the resolver crate). `lpm-cli` already depends on `lpm-resolver`;
//! `lpm-migrate` does not. Keeping the planner here avoids growing the
//! migrate crate's dep graph while putting the logic next to the CLI
//! handler that consumes it.
//!
//! ## Idempotence
//!
//! After a successful migrate, `pnpm.overrides` stays in `package.json`
//! (we don't strip it). On a second
//! `lpm migrate`, every entry already lives in `lpm.overrides` with the
//! same target — it's a no-op merge, not a conflict. The diff-aware
//! install-time warning silences automatically.

use lpm_common::LpmError;
use lpm_resolver::OverrideSet;
use lpm_workspace::PackageJson;
use std::collections::HashMap;

/// Outcome of analyzing `package.json > pnpm.overrides` against the
/// project's current LPM-side configuration.
///
/// The CLI handler reads this BEFORE the first file mutation. Any of
/// `conflicts`, `parse_errors`, or `unsupported_shapes` makes
/// [`Self::has_blocking_errors`] true and the handler must abort the
/// migration without touching disk. Otherwise [`Self::to_apply`]
/// carries the entries that should be merged into `lpm.overrides`.
#[derive(Debug, Clone, Default)]
pub struct PnpmOverridesPlan {
    /// Entries to merge into `package.json > lpm.overrides`. Keys
    /// already present in `lpm.overrides` with the same target are
    /// omitted (idempotent merge).
    pub to_apply: HashMap<String, String>,
    /// Same raw key in both `pnpm.overrides` and `lpm.overrides` with
    /// different targets. The user has divergent intent — we don't
    /// pick a winner.
    pub conflicts: Vec<OverridesConflict>,
    /// Entries that LPM's selector parser rejected.
    pub parse_errors: Vec<OverridesParseError>,
    /// Entries whose `pnpm.overrides` value isn't a string.
    pub unsupported_shapes: Vec<UnsupportedShape>,
}

/// `pnpm.overrides[key] = pnpm_target` collides with
/// `lpm.overrides[key] = lpm_target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverridesConflict {
    pub key: String,
    pub pnpm_target: String,
    pub lpm_target: String,
}

/// LPM's selector parser rejected this entry.
#[derive(Debug, Clone)]
pub struct OverridesParseError {
    pub key: String,
    pub target: String,
    /// Human-readable error from the resolver's `OverrideSet::parse`.
    pub error: String,
}

/// `pnpm.overrides[key]` had a non-string value (e.g. object, array,
/// null). LPM's grammar only accepts string targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedShape {
    pub key: String,
    pub got: &'static str,
}

impl PnpmOverridesPlan {
    /// True iff anything in this plan should fail the migration before
    /// any disk mutation.
    pub fn has_blocking_errors(&self) -> bool {
        !self.conflicts.is_empty()
            || !self.parse_errors.is_empty()
            || !self.unsupported_shapes.is_empty()
    }

    /// True iff there is anything to merge into `lpm.overrides` after
    /// validation passed.
    pub fn has_entries(&self) -> bool {
        !self.to_apply.is_empty()
    }

    /// True iff the plan has no entries and no errors at all — pnpm
    /// users without overrides, or non-pnpm projects.
    ///
    /// Currently only consumed by the in-crate tests; kept as a public
    /// affordance because callers that want to short-circuit before
    /// `has_blocking_errors` / `has_entries` checks find it more
    /// readable than an `&& !` chain.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.to_apply.is_empty()
            && self.conflicts.is_empty()
            && self.parse_errors.is_empty()
            && self.unsupported_shapes.is_empty()
    }
}

/// Build the override-translation plan from a parsed `PackageJson`.
///
/// Pure function: reads only the in-memory struct, never the
/// filesystem. Returns an `LpmError` only when the top-level
/// `pnpm.overrides` field has a fundamentally wrong shape (e.g. it's
/// an array or string instead of an object). Per-entry shape problems
/// are non-fatal at the plan-construction layer — they're surfaced as
/// blocking errors via the plan's `unsupported_shapes` / `parse_errors`
/// fields so the caller can render all problems together.
pub fn build_plan(pkg: &PackageJson) -> Result<PnpmOverridesPlan, LpmError> {
    let pnpm = match pkg.pnpm.as_ref() {
        Some(p) => p,
        None => return Ok(PnpmOverridesPlan::default()),
    };

    if pnpm.overrides.is_null() {
        return Ok(PnpmOverridesPlan::default());
    }

    let entries = pnpm.overrides.as_object().ok_or_else(|| {
        LpmError::Script(format!(
            "package.json > pnpm.overrides must be an object, got {}",
            json_kind(&pnpm.overrides)
        ))
    })?;

    let lpm_overrides: HashMap<String, String> = pkg
        .lpm
        .as_ref()
        .map(|l| l.overrides.clone())
        .unwrap_or_default();

    let mut plan = PnpmOverridesPlan::default();

    for (key, value) in entries {
        let target = match value.as_str() {
            Some(s) => s.to_string(),
            None => {
                plan.unsupported_shapes.push(UnsupportedShape {
                    key: key.clone(),
                    got: json_kind(value),
                });
                continue;
            }
        };

        // Validate the (key, target) pair through LPM's selector parser.
        // `OverrideSet::parse` accepts three sources; passing the entry
        // as the lpm-overrides source gives us the same fail-closed
        // grammar check the install path uses, isolated to this entry.
        let single = HashMap::from([(key.clone(), target.clone())]);
        let empty = HashMap::new();
        if let Err(e) = OverrideSet::parse(&single, &empty, &empty) {
            plan.parse_errors.push(OverridesParseError {
                key: key.clone(),
                target: target.clone(),
                error: e.to_string(),
            });
            continue;
        }

        // Conflict check at the raw key level.
        if let Some(existing) = lpm_overrides.get(key) {
            if existing != &target {
                plan.conflicts.push(OverridesConflict {
                    key: key.clone(),
                    pnpm_target: target,
                    lpm_target: existing.clone(),
                });
            }
            // Same key, same target: idempotent — already in lpm.overrides,
            // nothing to apply.
            continue;
        }

        plan.to_apply.insert(key.clone(), target);
    }

    Ok(plan)
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg_from(json: &str) -> PackageJson {
        serde_json::from_str(json).expect("test package.json must parse")
    }

    #[test]
    fn build_plan_empty_when_no_pnpm_block() {
        let pkg = pkg_from(r#"{"name": "x"}"#);
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn build_plan_empty_when_pnpm_overrides_absent() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": { "peerDependencyRules": {} }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn build_plan_translates_clean_entries() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "overrides": {
                        "lodash": "^4.17.21",
                        "react": "18.2.0"
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert_eq!(plan.to_apply.len(), 2);
        assert_eq!(plan.to_apply.get("lodash").unwrap(), "^4.17.21");
        assert_eq!(plan.to_apply.get("react").unwrap(), "18.2.0");
        assert!(!plan.has_blocking_errors());
        assert!(plan.has_entries());
    }

    #[test]
    fn build_plan_idempotent_when_lpm_already_has_same_entry() {
        // After a previous migrate run, lpm.overrides already mirrors
        // pnpm.overrides. The next migrate must be a no-op merge, not
        // a conflict.
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": { "overrides": { "lodash": "^4.17.21" } },
                "lpm":  { "overrides": { "lodash": "^4.17.21" } }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.is_empty(), "no-op merge should produce empty plan");
    }

    #[test]
    fn build_plan_flags_conflict_on_diff_target_for_same_key() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": { "overrides": { "lodash": "^4.17.21" } },
                "lpm":  { "overrides": { "lodash": "^4.18.0" } }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.has_blocking_errors());
        assert_eq!(plan.conflicts.len(), 1);
        let c = &plan.conflicts[0];
        assert_eq!(c.key, "lodash");
        assert_eq!(c.pnpm_target, "^4.17.21");
        assert_eq!(c.lpm_target, "^4.18.0");
        assert!(plan.to_apply.is_empty());
    }

    #[test]
    fn build_plan_raw_key_conflict_semantics() {
        // `lodash` and `lodash@>=0.0.0` are different raw keys even
        // though they refer to the same package. Different keys never
        // conflict — both end up either in to_apply or already in
        // lpm.overrides without any cross-talk.
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": { "overrides": { "lodash": "^4.17.21" } },
                "lpm":  { "overrides": { "lodash@>=0.0.0": "^4.18.0" } }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.conflicts.is_empty());
        assert_eq!(plan.to_apply.get("lodash").unwrap(), "^4.17.21");
    }

    #[test]
    fn build_plan_rejects_object_value_shape() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "overrides": {
                        "lodash": { "version": "^4.17.21" }
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert_eq!(plan.unsupported_shapes.len(), 1);
        assert_eq!(plan.unsupported_shapes[0].key, "lodash");
        assert_eq!(plan.unsupported_shapes[0].got, "object");
        assert!(plan.has_blocking_errors());
        assert!(plan.to_apply.is_empty());
    }

    #[test]
    fn build_plan_rejects_array_null_number_shapes() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "overrides": {
                        "a": [],
                        "b": null,
                        "c": 4
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        let kinds: Vec<&'static str> = plan.unsupported_shapes.iter().map(|s| s.got).collect();
        assert!(kinds.contains(&"array"));
        assert!(kinds.contains(&"null"));
        assert!(kinds.contains(&"number"));
        assert_eq!(plan.unsupported_shapes.len(), 3);
    }

    #[test]
    fn build_plan_rejects_multi_segment_path_selector() {
        // LPM's grammar caps path selectors at one `>`. Multi-segment
        // pnpm overrides fail-closed.
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "overrides": { "a>b>c": "1.0.0" }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert_eq!(plan.parse_errors.len(), 1);
        assert_eq!(plan.parse_errors[0].key, "a>b>c");
        assert!(plan.has_blocking_errors());
    }

    #[test]
    fn build_plan_top_level_pnpm_overrides_array_is_hard_error() {
        // The whole `pnpm.overrides` field has the wrong shape — this
        // is fundamental enough to be a function-level error, not a
        // per-entry one (there are no entries to enumerate).
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": { "overrides": ["nope"] }
            }"#,
        );
        let err = build_plan(&pkg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("must be an object"), "got: {msg}");
    }

    #[test]
    fn build_plan_collects_multiple_errors_in_one_pass() {
        // Mix of clean, conflict, parse error, and shape error in one
        // plan. The handler can render all of them together.
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "overrides": {
                        "ok": "1.0.0",
                        "bad-shape": { "version": "1.0.0" },
                        "a>b>c": "2.0.0",
                        "conflicting": "3.0.0"
                    }
                },
                "lpm": {
                    "overrides": { "conflicting": "9.9.9" }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert_eq!(plan.to_apply.len(), 1);
        assert_eq!(plan.to_apply.get("ok").unwrap(), "1.0.0");
        assert_eq!(plan.unsupported_shapes.len(), 1);
        assert_eq!(plan.parse_errors.len(), 1);
        assert_eq!(plan.conflicts.len(), 1);
        assert!(plan.has_blocking_errors());
    }

    #[test]
    fn build_plan_skips_pnpm_without_overrides_field() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": { "patchedDependencies": {} }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.is_empty());
    }
}
