use super::*;

// ── parse_package_spec ──────────────────────────────────────────
//
// The legacy `parse_package_spec` function and its tests were removed
//. The replacement parser is `save_spec::parse_user_save_intent`,
// which returns a strongly typed `UserSaveIntent` enum and is exhaustively
// tested in `save_spec::tests::parse_*` (15 cases covering scoped,
// unscoped, exact, range, dist-tag, wildcard, and workspace inputs).
// Re-asserting parser behavior here would just duplicate that coverage.

// ── resolve_version_from_spec ───────────────────────────────────

#[test]
fn resolve_wildcard_returns_latest() {
    let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");
    let result = resolve_version_from_spec("*", &meta, "3.0.0").unwrap();
    assert_eq!(result, "3.0.0");
}

#[test]
fn resolve_exact_version_returns_that_version() {
    let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");
    let result = resolve_version_from_spec("1.0.0", &meta, "3.0.0").unwrap();
    assert_eq!(result, "1.0.0");
}

#[test]
fn resolve_caret_range_returns_best_match() {
    let meta = make_metadata(&["1.0.0", "1.5.0", "2.0.0", "2.1.0"], "2.1.0");
    let result = resolve_version_from_spec("^1.0.0", &meta, "2.1.0").unwrap();
    assert_eq!(result, "1.5.0");
}

#[test]
fn resolve_tilde_range_returns_best_match() {
    let meta = make_metadata(&["1.0.0", "1.0.5", "1.1.0", "2.0.0"], "2.0.0");
    let result = resolve_version_from_spec("~1.0.0", &meta, "2.0.0").unwrap();
    assert_eq!(result, "1.0.5");
}

#[test]
fn resolve_dist_tag_returns_tagged_version() {
    let mut meta = make_metadata(&["1.9.0", "2.0.0-beta.2"], "1.9.0");
    meta.dist_tags
        .insert("beta".to_string(), "2.0.0-beta.2".to_string());

    let result = resolve_version_from_spec("beta", &meta, "1.9.0").unwrap();
    assert_eq!(result, "2.0.0-beta.2");
}

#[test]
fn resolve_no_match_returns_error() {
    let meta = make_metadata(&["1.0.0", "1.5.0"], "1.5.0");
    let result = resolve_version_from_spec("^3.0.0", &meta, "1.5.0");
    assert!(result.is_err());
}

/// This is the exact bug scenario: user specifies `@1.0.0` but the code
/// previously ignored it and used `latest_ver` (3.0.0) instead.
#[test]
fn bug_version_spec_not_ignored_for_swift_packages() {
    let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");

    // User asked for @1.0.0 — must get 1.0.0, NOT 3.0.0
    let result = resolve_version_from_spec("1.0.0", &meta, "3.0.0").unwrap();
    assert_eq!(
        result, "1.0.0",
        "user-specified version @1.0.0 should be respected, not silently replaced with latest"
    );

    // User asked for @^2.0.0 — must get 2.0.0, NOT 3.0.0
    let result = resolve_version_from_spec("^2.0.0", &meta, "3.0.0").unwrap();
    assert_eq!(
        result, "2.0.0",
        "user-specified range @^2.0.0 should resolve to 2.0.0, not latest"
    );
}
