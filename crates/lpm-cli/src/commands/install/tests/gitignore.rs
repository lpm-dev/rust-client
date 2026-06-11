use super::*;

#[test]
fn ensure_skills_gitignore_appends_entry() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

    ensure_skills_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(content.contains(".lpm/skills/"), "entry should be added");
    assert!(
        content.contains("node_modules/"),
        "existing content preserved"
    );
}

#[test]
fn ensure_skills_gitignore_no_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

    ensure_skills_gitignore(dir.path());
    ensure_skills_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    let count = content.matches(".lpm/skills/").count();
    assert_eq!(count, 1, "should not duplicate entry");
}

// ── — ensure_lpm_wrappers_gitignore ───────────────────

#[test]
fn ensure_lpm_wrappers_gitignore_appends_entry() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

    ensure_lpm_wrappers_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(content.contains(".lpm/wrappers/"), "entry should be added");
    assert!(
        content.contains("node_modules/"),
        "existing content preserved"
    );
}

#[test]
fn ensure_lpm_wrappers_gitignore_no_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

    ensure_lpm_wrappers_gitignore(dir.path());
    ensure_lpm_wrappers_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    let count = content.matches(".lpm/wrappers/").count();
    assert_eq!(count, 1, "should not duplicate entry");
}

#[test]
fn ensure_lpm_wrappers_gitignore_creates_when_no_gitignore() {
    let dir = tempfile::tempdir().unwrap();
    // No pre-existing .gitignore — helper must create one.
    ensure_lpm_wrappers_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(content.contains(".lpm/wrappers/"));
}

// ── Hoisted-symmetry — ensure_lpm_hoisted_gitignore ──────────────

#[test]
fn ensure_lpm_hoisted_gitignore_appends_entry() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

    ensure_lpm_hoisted_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(content.contains(".lpm/hoisted/"), "entry should be added");
    assert!(
        content.contains("node_modules/"),
        "existing content preserved"
    );
}

#[test]
fn ensure_lpm_hoisted_gitignore_no_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

    ensure_lpm_hoisted_gitignore(dir.path());
    ensure_lpm_hoisted_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    let count = content.matches(".lpm/hoisted/").count();
    assert_eq!(count, 1, "should not duplicate entry");
}

#[test]
fn ensure_lpm_hoisted_gitignore_creates_when_no_gitignore() {
    let dir = tempfile::tempdir().unwrap();
    ensure_lpm_hoisted_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(content.contains(".lpm/hoisted/"));
}

#[test]
fn ensure_lpm_hoisted_and_wrappers_coexist_in_gitignore() {
    // The install entry point calls both helpers unconditionally;
    // both markers must end up in `.gitignore` regardless of
    // call order, with no duplicates and no interference.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

    ensure_lpm_wrappers_gitignore(dir.path());
    ensure_lpm_hoisted_gitignore(dir.path());

    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(content.contains(".lpm/wrappers/"));
    assert!(content.contains(".lpm/hoisted/"));
    assert_eq!(content.matches(".lpm/wrappers/").count(), 1);
    assert_eq!(content.matches(".lpm/hoisted/").count(), 1);

    // Re-running both is a no-op (idempotent).
    ensure_lpm_wrappers_gitignore(dir.path());
    ensure_lpm_hoisted_gitignore(dir.path());
    let content2 = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert_eq!(content2.matches(".lpm/wrappers/").count(), 1);
    assert_eq!(content2.matches(".lpm/hoisted/").count(), 1);
}

// ── — wrapper-layout migration ────────────────────────

#[test]
fn migrate_legacy_wrapper_layout_wipes_legacy_state() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let layout = lpm_linker::LayoutPaths::for_project(p);
    // Populate legacy wrapper dir as if from a pre-existing install.
    let legacy = layout.isolated_legacy_wrapper_root().join("express@4.22.1");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("marker"), b"x").unwrap();
    // New wrapper root is empty → migration is owed.
    assert!(layout.needs_layout_migration());

    migrate_legacy_wrapper_layout(p, true);

    assert!(
        !legacy.exists(),
        "legacy wrapper subtree should be removed by migration"
    );
    // Subsequent migration call is a no-op (idempotent).
    migrate_legacy_wrapper_layout(p, true);
}

#[test]
fn migrate_legacy_wrapper_layout_noop_when_not_owed() {
    // No legacy state → migration is a no-op; the helper must
    // not create directories or otherwise touch the project.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    migrate_legacy_wrapper_layout(p, true);
    assert!(
        !p.join("node_modules").exists(),
        "no-migration path must not synthesize node_modules/"
    );
    assert!(
        !p.join(".lpm").exists(),
        "no-migration path must not synthesize .lpm/"
    );
}

#[test]
fn migrate_legacy_wrapper_layout_noop_when_both_populated() {
    // Mid-migration mixed state — the gate is "legacy populated
    // AND new empty"; with both populated, the predicate returns
    // false and the helper takes the no-op path. Real
    // convergence of this state happens via a normal `lpm install`
    // re-run.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let layout = lpm_linker::LayoutPaths::for_project(p);
    let legacy = layout.isolated_legacy_wrapper_root().join("express@4.22.1");
    let new = layout.isolated_wrapper_root().join("express@4.22.1");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::create_dir_all(&new).unwrap();

    migrate_legacy_wrapper_layout(p, true);

    // Both states intact — helper didn't fire.
    assert!(legacy.exists());
    assert!(new.exists());
}

// ── Hoisted-symmetry — legacy hoisted-state migration ────────────

#[test]
fn migrate_legacy_wrapper_layout_wipes_legacy_hoisted_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let layout = lpm_linker::LayoutPaths::for_project(p);
    let nm = p.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();
    // Legacy hoisted state: metadata sidecar in node_modules/.
    let legacy_metadata = layout.hoisted_legacy_metadata_path();
    std::fs::write(&legacy_metadata, b"{}").unwrap();
    // Migration is owed (legacy present, new absent).
    assert!(layout.needs_layout_migration());

    migrate_legacy_wrapper_layout(p, true);

    assert!(
        !legacy_metadata.exists(),
        "legacy metadata sidecar should be removed"
    );
}

#[test]
fn migrate_legacy_wrapper_layout_wipes_legacy_hoisted_nested_root() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let layout = lpm_linker::LayoutPaths::for_project(p);
    let nm = p.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();
    // Legacy hoisted state: BOTH metadata AND nested fallback
    // populated (the harder migration case).
    std::fs::write(layout.hoisted_legacy_metadata_path(), b"{}").unwrap();
    let legacy_nested = layout.hoisted_legacy_nested_root().join("debug");
    std::fs::create_dir_all(&legacy_nested).unwrap();
    std::fs::write(legacy_nested.join("package.json"), b"{}").unwrap();

    migrate_legacy_wrapper_layout(p, true);

    assert!(
        !layout.hoisted_legacy_metadata_path().exists(),
        "legacy metadata sidecar should be removed"
    );
    assert!(
        !layout.hoisted_legacy_nested_root().exists(),
        "legacy nested root should be removed"
    );
}

#[test]
fn migrate_legacy_wrapper_layout_handles_both_legacy_layouts_simultaneously() {
    // The catastrophic mixed-legacy case: a project that somehow
    // ended up with BOTH legacy isolated wrapper state AND
    // legacy hoisted state. Both must be wiped.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let layout = lpm_linker::LayoutPaths::for_project(p);
    std::fs::create_dir_all(p.join("node_modules")).unwrap();

    let legacy_iso = layout.isolated_legacy_wrapper_root().join("express@4.22.1");
    std::fs::create_dir_all(&legacy_iso).unwrap();
    std::fs::write(layout.hoisted_legacy_metadata_path(), b"{}").unwrap();

    migrate_legacy_wrapper_layout(p, true);

    assert!(!legacy_iso.exists(), "legacy isolated wrapper wiped");
    assert!(
        !layout.hoisted_legacy_metadata_path().exists(),
        "legacy hoisted metadata wiped",
    );
}

#[test]
fn migrate_legacy_wrapper_layout_hoisted_only_with_nested_does_not_emit_isolated_notice() {
    // invariant: a hoisted-only legacy project with at least
    // one transitive conflict has `node_modules/.lpm/nested/<pkg>/`
    // populated. Previously, the migration helper keyed off
    // `legacy_isolated_root.exists()`, which returned true (the
    // `.lpm/` parent exists) and emitted a spurious "migrating
    // wrapper layout" notice for hoisted-only users.
    //
    // Post-fix, the isolated branch gates on
    // `legacy_isolated_root_has_wrapper_segments()` so the
    // hoisted-only state takes the hoisted branch path
    // exclusively. This test pins the predicate behavior — we
    // can't easily capture stdout in unit tests, but we CAN
    // assert the predicate that drives the notice.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let layout = lpm_linker::LayoutPaths::for_project(p);
    std::fs::create_dir_all(p.join("node_modules")).unwrap();
    // Legacy hoisted state — metadata sidecar + nested fallback dir.
    std::fs::write(layout.hoisted_legacy_metadata_path(), b"{}").unwrap();
    let nested = layout.hoisted_legacy_nested_root().join("debug");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("package.json"), b"{}").unwrap();

    // Public union predicate fires (legacy hoisted is owed migration).
    assert!(layout.needs_layout_migration());
    // BUT the isolated-branch predicate must NOT fire — the only
    // entries under `node_modules/.lpm/` are `nested/`, which is
    // hoisted state.
    assert!(
        !layout.legacy_isolated_root_has_wrapper_segments(),
        "hoisted-only legacy project must not register as isolated"
    );

    migrate_legacy_wrapper_layout(p, true);

    // Hoisted half wiped (metadata + nested gone).
    assert!(!layout.hoisted_legacy_metadata_path().exists());
    assert!(!layout.hoisted_legacy_nested_root().exists());
}

#[test]
fn migrate_legacy_wrapper_layout_noop_when_only_new_hoisted_present() {
    // Already-migrated hoisted user — must not re-fire migration.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let layout = lpm_linker::LayoutPaths::for_project(p);
    std::fs::create_dir_all(layout.hoisted_root()).unwrap();
    std::fs::write(layout.hoisted_metadata_path(), b"{}").unwrap();
    assert!(!layout.needs_layout_migration());

    migrate_legacy_wrapper_layout(p, true);

    // New metadata still present, no legacy paths created.
    assert!(layout.hoisted_metadata_path().exists());
    assert!(!layout.hoisted_legacy_metadata_path().exists());
}
