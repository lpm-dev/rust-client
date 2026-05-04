//! Phase 64 #33 — translate `package.json > pnpm.peerDependencyRules`
//! into `package.json > lpm.peerDependencyRules`.
//!
//! Mirrors the layered shape used by [`super::migrate_overrides`] and
//! [`super::migrate_patches`]: a pure planner that returns a
//! [`PnpmPeerRulesPlan`] from an in-memory `PackageJson`, plus a
//! caller that applies the validated plan in `commands::migrate` after
//! all blocking errors have been surfaced.
//!
//! pnpm's `peerDependencyRules` has three sub-keys with distinct
//! semantics; LPM ports each verbatim:
//!
//! - **`ignoreMissing`** — list of names (or glob patterns) whose
//!   missing-peer warnings are suppressed.
//! - **`allowedVersions`** — selector → range map widening the
//!   accepted peer range. Selector grammar mirrors `lpm.overrides`:
//!   `"react"` (any consumer), `"foo>react"` (peer of foo),
//!   `"foo@^2>react"` (peer of foo whose version satisfies `^2`),
//!   and the scoped variants.
//! - **`allowAny`** — list of names (or glob patterns) whose
//!   version-mismatch warnings are suppressed when the peer is
//!   present in the tree.
//!
//! The translation is value-preserving — patterns, selectors, and
//! ranges land in `lpm.peerDependencyRules` exactly as they appeared
//! on the pnpm side. The resolver compiles them at install time via
//! [`lpm_resolver::CompiledPeerRules::compile`], which also runs
//! every selector key through the same parser used here so the same
//! grammar is enforced on both surfaces.
//!
//! ## Validation
//!
//! `allowedVersions` keys are validated up-front via
//! [`lpm_resolver::validate_allowed_versions_selector`] so malformed
//! selectors surface as blocking errors before any disk mutation.
//! Same parser the resolver uses at install time — drift between the
//! two surfaces is impossible.
//!
//! ## Conflict semantics
//!
//! - **`ignoreMissing` / `allowAny`**: list-shaped, so we union
//!   pnpm's entries with LPM's existing entries. Duplicates dedupe.
//!   No conflicts possible — these are pure "names to suppress."
//! - **`allowedVersions`**: map-shaped. Same name in both with
//!   different ranges is a hard conflict (we don't pick a winner —
//!   the user has divergent intent). Same name with the same range
//!   is an idempotent no-op merge.
//!
//! After a successful migrate, `pnpm.peerDependencyRules` stays in
//! `package.json` (we don't strip it) so a parallel `pnpm install`
//! keeps working during the transition. The diff-aware drift
//! detector in
//! [`lpm_workspace::PackageJson::manifest_compat_issues`] silences
//! once `lpm.peerDependencyRules` is a superset.

use lpm_common::LpmError;
use lpm_workspace::PackageJson;
use std::collections::{BTreeSet, HashMap};

/// Outcome of analyzing `package.json > pnpm.peerDependencyRules`
/// against the project's current LPM-side configuration.
///
/// The CLI handler reads this BEFORE any file mutation. Any of
/// `allowed_versions_conflicts`, `allowed_versions_parse_errors`, or
/// `unsupported_shapes` makes [`Self::has_blocking_errors`] true and
/// the handler must abort the migration without touching disk.
/// Otherwise [`Self::to_apply`] carries the merged
/// `lpm.peerDependencyRules` to write.
#[derive(Debug, Clone, Default)]
pub struct PnpmPeerRulesPlan {
    /// Names from `pnpm.ignoreMissing` not already present (verbatim)
    /// in `lpm.peerDependencyRules.ignoreMissing`.
    pub ignore_missing_to_apply: Vec<String>,
    /// Names from `pnpm.allowAny` not already present (verbatim) in
    /// `lpm.peerDependencyRules.allowAny`.
    pub allow_any_to_apply: Vec<String>,
    /// `(name, range)` pairs from `pnpm.allowedVersions` not already
    /// present (with the same range) in
    /// `lpm.peerDependencyRules.allowedVersions`.
    pub allowed_versions_to_apply: HashMap<String, String>,
    /// Same name in `pnpm.allowedVersions` AND
    /// `lpm.peerDependencyRules.allowedVersions` with different
    /// ranges. The user has divergent intent — we don't pick a
    /// winner.
    pub allowed_versions_conflicts: Vec<AllowedVersionsConflict>,
    /// Range strings the user pasted that don't parse as valid
    /// semver ranges. Surfaced up-front so the user can fix the
    /// typo before we mutate disk.
    pub allowed_versions_parse_errors: Vec<AllowedVersionsParseError>,
    /// Each sub-field that turned out to have the wrong shape (e.g.
    /// `ignoreMissing` is an object instead of an array).
    pub unsupported_shapes: Vec<UnsupportedShape>,
}

/// Same name in both `pnpm.allowedVersions` and
/// `lpm.peerDependencyRules.allowedVersions`, with different ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedVersionsConflict {
    pub name: String,
    pub pnpm_range: String,
    pub lpm_range: String,
}

/// `pnpm.peerDependencyRules.allowedVersions[name]` is set to a
/// string LPM's semver parser rejects.
#[derive(Debug, Clone)]
pub struct AllowedVersionsParseError {
    pub name: String,
    pub range: String,
    /// Human-readable error from the semver parser.
    pub error: String,
}

/// One of the three sub-fields had the wrong shape (e.g.
/// `pnpm.peerDependencyRules.ignoreMissing` is an object instead
/// of an array, or an `allowedVersions[name]` value is not a string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedShape {
    /// Field path: e.g. `"ignoreMissing"`,
    /// `"allowedVersions[react]"`, `"allowAny[3]"`.
    pub field: String,
    pub got: &'static str,
}

impl PnpmPeerRulesPlan {
    /// True iff anything in this plan should fail the migration
    /// before any disk mutation.
    pub fn has_blocking_errors(&self) -> bool {
        !self.allowed_versions_conflicts.is_empty()
            || !self.allowed_versions_parse_errors.is_empty()
            || !self.unsupported_shapes.is_empty()
    }

    /// True iff there is anything to merge into
    /// `lpm.peerDependencyRules` after validation passed.
    pub fn has_entries(&self) -> bool {
        !self.ignore_missing_to_apply.is_empty()
            || !self.allow_any_to_apply.is_empty()
            || !self.allowed_versions_to_apply.is_empty()
    }

    /// True iff the plan has no entries and no errors at all.
    /// Currently only consumed by tests; mirrors the affordance on
    /// [`super::migrate_overrides::PnpmOverridesPlan::is_empty`].
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        !self.has_blocking_errors() && !self.has_entries()
    }
}

/// Build the peer-rules translation plan from a parsed `PackageJson`.
///
/// Pure function — reads only the in-memory struct, never the
/// filesystem. Returns an `LpmError` only when the top-level
/// `pnpm.peerDependencyRules` field has a fundamentally wrong shape
/// (e.g. it's an array or string instead of an object). Per-sub-field
/// shape problems are non-fatal at the plan-construction layer —
/// they surface as blocking errors via the plan's `unsupported_shapes`
/// / `allowed_versions_conflicts` / `allowed_versions_parse_errors`
/// fields so the caller can render all problems together.
pub fn build_plan(pkg: &PackageJson) -> Result<PnpmPeerRulesPlan, LpmError> {
    let pnpm = match pkg.pnpm.as_ref() {
        Some(p) => p,
        None => return Ok(PnpmPeerRulesPlan::default()),
    };

    if pnpm.peer_dependency_rules.is_null() {
        return Ok(PnpmPeerRulesPlan::default());
    }

    let block = pnpm.peer_dependency_rules.as_object().ok_or_else(|| {
        LpmError::Script(format!(
            "package.json > pnpm.peerDependencyRules must be an object, got {}",
            json_kind(&pnpm.peer_dependency_rules)
        ))
    })?;

    let lpm_rules = pkg
        .lpm
        .as_ref()
        .map(|l| &l.peer_dependency_rules)
        .cloned()
        .unwrap_or_default();

    let mut plan = PnpmPeerRulesPlan::default();

    // ── ignoreMissing ─────────────────────────────────────────────
    if let Some(value) = block.get("ignoreMissing") {
        match value.as_array() {
            Some(arr) => {
                let lpm_set: BTreeSet<&String> = lpm_rules.ignore_missing.iter().collect();
                let mut seen_in_apply: BTreeSet<String> = BTreeSet::new();
                for (i, item) in arr.iter().enumerate() {
                    match item.as_str() {
                        Some(s) => {
                            let key = s.to_string();
                            if lpm_set.contains(&key) || seen_in_apply.contains(&key) {
                                continue; // idempotent + dedupe
                            }
                            seen_in_apply.insert(key.clone());
                            plan.ignore_missing_to_apply.push(key);
                        }
                        None => plan.unsupported_shapes.push(UnsupportedShape {
                            field: format!("ignoreMissing[{i}]"),
                            got: json_kind(item),
                        }),
                    }
                }
            }
            None => plan.unsupported_shapes.push(UnsupportedShape {
                field: "ignoreMissing".into(),
                got: json_kind(value),
            }),
        }
    }

    // ── allowAny ─────────────────────────────────────────────────
    if let Some(value) = block.get("allowAny") {
        match value.as_array() {
            Some(arr) => {
                let lpm_set: BTreeSet<&String> = lpm_rules.allow_any.iter().collect();
                let mut seen_in_apply: BTreeSet<String> = BTreeSet::new();
                for (i, item) in arr.iter().enumerate() {
                    match item.as_str() {
                        Some(s) => {
                            let key = s.to_string();
                            if lpm_set.contains(&key) || seen_in_apply.contains(&key) {
                                continue;
                            }
                            seen_in_apply.insert(key.clone());
                            plan.allow_any_to_apply.push(key);
                        }
                        None => plan.unsupported_shapes.push(UnsupportedShape {
                            field: format!("allowAny[{i}]"),
                            got: json_kind(item),
                        }),
                    }
                }
            }
            None => plan.unsupported_shapes.push(UnsupportedShape {
                field: "allowAny".into(),
                got: json_kind(value),
            }),
        }
    }

    // ── allowedVersions ──────────────────────────────────────────
    if let Some(value) = block.get("allowedVersions") {
        match value.as_object() {
            Some(map) => {
                for (name, range_value) in map {
                    let range = match range_value.as_str() {
                        Some(s) => s.to_string(),
                        None => {
                            plan.unsupported_shapes.push(UnsupportedShape {
                                field: format!("allowedVersions[{name}]"),
                                got: json_kind(range_value),
                            });
                            continue;
                        }
                    };

                    // Validate the selector key shape via the same
                    // parser the resolver uses at install time. Catches
                    // multi-segment paths, ambiguous `foo@2` bare keys,
                    // glob wildcards (`*`), empty halves, invalid npm
                    // names, and unparseable parent ranges — all
                    // blocking.
                    if let Err(e) = lpm_resolver::validate_allowed_versions_selector(name) {
                        plan.allowed_versions_parse_errors
                            .push(AllowedVersionsParseError {
                                name: name.clone(),
                                range: range.clone(),
                                error: e,
                            });
                        continue;
                    }

                    // Validate the widened range via the resolver's
                    // own `NpmRange::parse` — same parser the install
                    // path runs at compile time, so a range that
                    // migrates clean must also compile clean. We do
                    // NOT use `lpm_semver::VersionReq::parse` here
                    // (stricter strict-semver) because that parser is
                    // narrower than the npm-compat grammar the install
                    // path honors; a range like `>=16 <19` must
                    // migrate the same way it'll later compile.
                    if let Err(e) = lpm_resolver::validate_allowed_versions_range(&range) {
                        plan.allowed_versions_parse_errors
                            .push(AllowedVersionsParseError {
                                name: name.clone(),
                                range: range.clone(),
                                error: e,
                            });
                        continue;
                    }

                    if let Some(existing) = lpm_rules.allowed_versions.get(name) {
                        if existing != &range {
                            plan.allowed_versions_conflicts
                                .push(AllowedVersionsConflict {
                                    name: name.clone(),
                                    pnpm_range: range,
                                    lpm_range: existing.clone(),
                                });
                        }
                        // same name, same range: idempotent — skip.
                        continue;
                    }
                    plan.allowed_versions_to_apply.insert(name.clone(), range);
                }
            }
            None => plan.unsupported_shapes.push(UnsupportedShape {
                field: "allowedVersions".into(),
                got: json_kind(value),
            }),
        }
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
    fn empty_when_no_pnpm_block() {
        let pkg = pkg_from(r#"{"name": "x"}"#);
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn empty_when_pnpm_peer_dependency_rules_absent() {
        let pkg = pkg_from(r#"{"name": "x", "pnpm": { "overrides": {} }}"#);
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn translates_clean_three_sub_keys() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": ["@types/react", "fsevents"],
                        "allowedVersions": {
                            "react": "16 || 17 || 18",
                            "typescript": "5"
                        },
                        "allowAny": ["@babel/*"]
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(!plan.has_blocking_errors());
        assert!(plan.has_entries());
        assert_eq!(
            plan.ignore_missing_to_apply,
            vec!["@types/react".to_string(), "fsevents".to_string()]
        );
        assert_eq!(plan.allow_any_to_apply, vec!["@babel/*".to_string()]);
        assert_eq!(
            plan.allowed_versions_to_apply.get("react").unwrap(),
            "16 || 17 || 18"
        );
        assert_eq!(
            plan.allowed_versions_to_apply.get("typescript").unwrap(),
            "5"
        );
    }

    #[test]
    fn idempotent_when_lpm_already_has_same_entries() {
        // After a previous migrate, lpm.peerDependencyRules already
        // mirrors pnpm.peerDependencyRules. The next migrate must be
        // a no-op merge, not a conflict.
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": ["fsevents"],
                        "allowedVersions": { "react": "16 || 17" }
                    }
                },
                "lpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": ["fsevents"],
                        "allowedVersions": { "react": "16 || 17" }
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.is_empty(), "fully covered → empty plan");
    }

    #[test]
    fn allowed_versions_conflict_blocks_migration() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "allowedVersions": { "react": "17 || 18" }
                    }
                },
                "lpm": {
                    "peerDependencyRules": {
                        "allowedVersions": { "react": "16 || 17" }
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.has_blocking_errors());
        assert_eq!(plan.allowed_versions_conflicts.len(), 1);
        let c = &plan.allowed_versions_conflicts[0];
        assert_eq!(c.name, "react");
        assert_eq!(c.pnpm_range, "17 || 18");
        assert_eq!(c.lpm_range, "16 || 17");
    }

    #[test]
    fn allowed_versions_unparseable_range_blocks_migration() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "allowedVersions": { "react": "not a range~~" }
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.has_blocking_errors());
        assert_eq!(plan.allowed_versions_parse_errors.len(), 1);
        assert_eq!(plan.allowed_versions_parse_errors[0].name, "react");
    }

    #[test]
    fn ignore_missing_non_string_entry_is_unsupported_shape() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": ["react", { "name": "wat" }]
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.has_blocking_errors());
        assert_eq!(plan.unsupported_shapes.len(), 1);
        assert_eq!(plan.unsupported_shapes[0].field, "ignoreMissing[1]");
        assert_eq!(plan.unsupported_shapes[0].got, "object");
    }

    #[test]
    fn ignore_missing_wrong_shape_is_unsupported_shape() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": { "react": "yes" }
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.has_blocking_errors());
        assert_eq!(plan.unsupported_shapes.len(), 1);
        assert_eq!(plan.unsupported_shapes[0].field, "ignoreMissing");
        assert_eq!(plan.unsupported_shapes[0].got, "object");
    }

    #[test]
    fn top_level_peer_dependency_rules_array_is_hard_error() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": ["this is not how it works"]
                }
            }"#,
        );
        let err = build_plan(&pkg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("peerDependencyRules"));
        assert!(msg.contains("array"));
    }

    #[test]
    fn dedupes_within_pnpm_side_lists() {
        // pnpm allows duplicates within a list (it's just a JSON array).
        // The translator should dedupe so we don't write `["fsevents",
        // "fsevents"]` to lpm.peerDependencyRules.
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": ["fsevents", "fsevents"]
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert_eq!(plan.ignore_missing_to_apply.len(), 1);
        assert_eq!(plan.ignore_missing_to_apply[0], "fsevents");
    }

    #[test]
    fn allowed_versions_selector_grammar_translates_verbatim_for_valid_keys() {
        // Full pnpm parity: bare names, scoped names, parent>peer,
        // parent@range>peer, scoped parent — all translate verbatim.
        // Includes scoped names whose package half starts with `.`
        // or `_` (npm-spec valid: the leading-char check fires
        // against the WHOLE name, which starts with `@`).
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "allowedVersions": {
                            "react": "16 || 17",
                            "@scope/foo": "1",
                            "card>react": "17",
                            "foo@^2>react": "17",
                            "@scope/bar@^3>react": "17",
                            "@scope/_internal": "1",
                            "@scope/.config": "1",
                            "@scope/_internal@^2>react": "17"
                        }
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(
            !plan.has_blocking_errors(),
            "scoped names with leading `.`/`_` on the package half are valid \
             per npm spec — got blocking errors: {plan:?}"
        );
        assert_eq!(plan.allowed_versions_to_apply.len(), 8);
        for key in [
            "react",
            "@scope/foo",
            "card>react",
            "foo@^2>react",
            "@scope/bar@^3>react",
            "@scope/_internal",
            "@scope/.config",
            "@scope/_internal@^2>react",
        ] {
            assert!(
                plan.allowed_versions_to_apply.contains_key(key),
                "expected key {key} to be translated verbatim",
            );
        }
    }

    #[test]
    fn allowed_versions_rejects_invalid_selector_keys_at_migrate_time() {
        // Multi-segment, ambiguous bare-name-with-version, peer half
        // with version qualifier, glob wildcards in any position —
        // all caught by the same parser the resolver uses at install
        // time. No drift between surfaces.
        for bad_key in [
            // Structural rejections.
            "a>b>c",
            "foo@2",
            "foo>react@2",
            ">react",
            "foo>",
            // Glob wildcards must reject in every selector position
            // (Phase 64 #33 second-pass: `is_valid_dep_name` is too
            // permissive for the selector grammar — `*` slipped
            // through pre-fix).
            "*",
            "@scope/*",
            "*-eslint-plugin",
            "foo>*",
            "*>react",
            "@*/foo>react",
            // Phase 64 #33 third-pass: malformed non-wildcard names
            // (spaces, uppercase, leading `.`/`_`, special chars)
            // also slipped through `is_valid_dep_name` and silently
            // no-op'd at runtime. The new strict npm-name predicate
            // rejects them on both surfaces.
            "foo bar",
            "FooBar",
            ".hidden",
            "_private",
            "foo!bar",
            "foo>React",
            "FooBar>react",
        ] {
            let pkg: PackageJson = serde_json::from_str(&format!(
                r#"{{
                    "name": "x",
                    "pnpm": {{
                        "peerDependencyRules": {{
                            "allowedVersions": {{ {bad:?}: "1" }}
                        }}
                    }}
                }}"#,
                bad = bad_key
            ))
            .expect("test package.json must parse");
            let plan = build_plan(&pkg).unwrap();
            assert!(
                plan.has_blocking_errors(),
                "expected {bad_key:?} to be a blocking error, got: {plan:?}",
            );
            assert!(
                plan.allowed_versions_parse_errors
                    .iter()
                    .any(|e| e.name == bad_key),
                "expected parse_errors to name {bad_key}",
            );
        }
    }

    /// Migrate uses the resolver's own `NpmRange::parse` for widened-
    /// range validation (via `validate_allowed_versions_range`), not
    /// the stricter `lpm_semver::VersionReq::parse`. A range that
    /// migrates clean must compile clean — single parser on both
    /// surfaces. This test pins the parity by exercising npm-compat
    /// shapes that the broader grammar accepts.
    #[test]
    fn allowed_versions_range_validation_uses_npm_range_grammar() {
        for ok_range in ["16 || 17 || 18", ">=16 <19", "^4.17.21", "1.x"] {
            let pkg: PackageJson = serde_json::from_str(&format!(
                r#"{{
                    "name": "x",
                    "pnpm": {{
                        "peerDependencyRules": {{
                            "allowedVersions": {{ "react": {range:?} }}
                        }}
                    }}
                }}"#,
                range = ok_range
            ))
            .expect("test package.json must parse");
            let plan = build_plan(&pkg).unwrap();
            assert!(
                !plan.has_blocking_errors(),
                "expected {ok_range:?} to validate as a widened range, got: {plan:?}"
            );
        }
        for bad_range in ["~~not-a-range", "not-a-version"] {
            let pkg: PackageJson = serde_json::from_str(&format!(
                r#"{{
                    "name": "x",
                    "pnpm": {{
                        "peerDependencyRules": {{
                            "allowedVersions": {{ "react": {range:?} }}
                        }}
                    }}
                }}"#,
                range = bad_range
            ))
            .expect("test package.json must parse");
            let plan = build_plan(&pkg).unwrap();
            assert!(
                plan.has_blocking_errors(),
                "expected {bad_range:?} to fail validation, got: {plan:?}"
            );
        }
    }

    #[test]
    fn empty_sub_keys_produce_no_apply_entries() {
        let pkg = pkg_from(
            r#"{
                "name": "x",
                "pnpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": [],
                        "allowedVersions": {},
                        "allowAny": []
                    }
                }
            }"#,
        );
        let plan = build_plan(&pkg).unwrap();
        assert!(plan.is_empty());
    }
}
