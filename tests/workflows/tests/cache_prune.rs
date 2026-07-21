//! `lpm cache prune` workflow tests — exercises the CLI surface end-to-end
//! through `lpm-rs`, covering:
//!
//! - `--apply` runs under the store reader/writer lock without panicking
//!   or deadlocking against itself (smoke).
//! - The registry-missing degraded path: `--apply` without a populated
//!   `~/.lpm/known-projects.json` AND without `--project` succeeds, skips
//!   orphan removal (no roots → unsafe), and reports
//!   `registry_missing: true` in JSON.
//! - The orphan walk + apply path with an explicit `--project` argument.
//! - Dry-run reports without mutating anything.

mod support;

use serde_json::Value;
use support::{TempProject, lpm};

/// Cache prune operates on the v2 store; the workflow harness exercises the
/// shipped default and removes inherited store-version overrides.
fn lpm_v2(project: &TempProject) -> assert_cmd::Command {
    lpm(project)
}

fn parse_json(stdout: &[u8]) -> Value {
    let s = String::from_utf8(stdout.to_vec()).expect("stdout is not utf-8");
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\n---\n{s}"))
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Build a registry seed JSON with proper escaping for the path. Uses
/// `serde_json::json!` so Windows backslashes (`C:\Users\…`) and other
/// platform-specific quirks are escaped correctly. Returns the bytes
/// that get written to disk so callers can compare byte-identity post-
/// invocation.
fn seed_registry(registry_path: &std::path::Path, project_path: &std::path::Path) -> String {
    let canonical = std::fs::canonicalize(project_path).expect("project must canonicalize");
    let stale = if cfg!(windows) {
        std::path::PathBuf::from(r"C:\nonexistent\stale-project")
    } else {
        std::path::PathBuf::from("/nonexistent/stale-project")
    };
    let payload = serde_json::json!({
        "version": 1,
        "projects": [
            { "path": canonical, "last_seen": "2026-05-01T00:00:00Z" },
            { "path": stale, "last_seen": "2026-04-01T00:00:00Z" },
        ],
    });
    let serialized = serde_json::to_string(&payload).expect("registry seed must serialize");
    std::fs::write(registry_path, &serialized).expect("failed to seed registry");
    serialized
}

#[test]
fn prune_dry_run_with_no_registry_succeeds_without_mutation() {
    // Bare `lpm cache prune` (dry-run) on a fresh HOME with no project
    // registry must succeed — dry-run never mutates, so it has no
    // safety reason to fail.
    let project = TempProject::empty(r#"{"name":"prune-dry-run","version":"1.0.0"}"#);

    let output = lpm_v2(&project)
        .args(["cache", "prune", "--json"])
        .output()
        .expect("failed to run lpm cache prune");

    assert!(
        output.status.success(),
        "dry-run prune failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json(&output.stdout);
    insta::assert_json_snapshot!("cache_prune_dry_run_json_envelope_missing_registry", json);
    assert_eq!(json["applied"], false, "dry-run must not report applied");
    assert_eq!(
        json["registry_missing"], true,
        "fresh HOME has no known-projects.json; expected registry_missing=true"
    );
    assert_eq!(
        json["link_entries_orphaned"].as_array().map_or(0, Vec::len),
        0,
        "no roots means no orphan walk; orphan list must be empty"
    );
    assert!(
        !project
            .home()
            .join(".lpm")
            .join("store")
            .join("v2")
            .exists()
            || project
                .home()
                .join(".lpm")
                .join("store")
                .join("v2")
                .read_dir()
                .map_or(true, |mut d| d.next().is_none()),
        "dry-run must not create or populate the store"
    );
}

#[test]
fn prune_human_output_uses_slim_status_lines() {
    let project = TempProject::empty(r#"{"name":"prune-human","version":"1.0.0"}"#);

    let output = lpm_v2(&project)
        .args(["cache", "prune"])
        .output()
        .expect("failed to run lpm cache prune");

    assert!(
        output.status.success(),
        "dry-run prune failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(
        combined.contains("! No project registry at ~/.lpm/known-projects.json"),
        "missing-registry path should use a slim warning, got:\n{combined}"
    );
    assert!(
        combined.contains("✓ Done · checked cache in "),
        "cache prune dry-run should finish with elapsed done line, got:\n{combined}"
    );
    assert!(
        !combined.contains('│') && !combined.contains('◇'),
        "cache prune output should not use bordered/cliclack glyphs, got:\n{combined}"
    );
}

#[test]
fn prune_apply_with_no_registry_degrades_to_tombstone_only() {
    // `--apply` with no registry and no `--project` must NOT abort.
    // It must succeed, skip orphan removal
    // (we have no roots — every link entry would look unreachable),
    // and still run the tombstone sweep so `lpm uninstall -g`'s
    // deferred cleanup retry remains reachable without a populated
    // project registry.
    let project = TempProject::empty(r#"{"name":"prune-apply-degrade","version":"1.0.0"}"#);

    let output = lpm_v2(&project)
        .args(["cache", "prune", "--apply", "--json"])
        .output()
        .expect("failed to run lpm cache prune --apply");

    assert!(
        output.status.success(),
        "--apply must NOT error when registry is missing; this is the degraded tombstone-only path:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json(&output.stdout);
    assert_eq!(json["applied"], true);
    assert_eq!(
        json["registry_missing"], true,
        "no project registry → registry_missing must be true"
    );
    assert_eq!(
        json["link_entries_orphaned"].as_array().map_or(0, Vec::len),
        0,
        "registry-missing apply must not delete link entries"
    );
    assert_eq!(
        json["object_entries_orphaned"]
            .as_array()
            .map_or(0, Vec::len),
        0,
        "registry-missing apply must not delete objects"
    );
    // Tombstone sweep ran — no tombstones to sweep on this fresh HOME,
    // but the field is populated (zero), proving the sweep code path
    // executed under apply.
    assert_eq!(json["tombstones_swept"], 0);
}

#[test]
fn prune_apply_with_explicit_project_succeeds_with_no_v2_store() {
    // `--project` bypasses the registry. With no v2 store populated,
    // the walk produces zero orphans and apply is a clean noop.
    // Verifies the lock-wrapped happy path.
    let project = TempProject::empty(r#"{"name":"prune-apply-project","version":"1.0.0"}"#);

    let output = lpm_v2(&project)
        .args([
            "cache",
            "prune",
            "--apply",
            "--project",
            project.path().to_str().expect("project path utf-8"),
            "--json",
        ])
        .output()
        .expect("failed to run lpm cache prune --apply --project");

    assert!(
        output.status.success(),
        "--apply --project on empty store must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json(&output.stdout);
    assert_eq!(json["applied"], true);
    assert_eq!(
        json["registry_missing"], false,
        "--project bypasses registry; registry_missing must be false"
    );
    assert_eq!(json["link_entries_total"], 0);
    assert_eq!(json["object_entries_total"], 0);
}

#[test]
fn prune_apply_human_output_uses_done_line_with_elapsed() {
    let project = TempProject::empty(r#"{"name":"prune-apply-human","version":"1.0.0"}"#);

    let output = lpm_v2(&project)
        .args([
            "cache",
            "prune",
            "--apply",
            "--project",
            project.path().to_str().expect("project path utf-8"),
        ])
        .output()
        .expect("failed to run lpm cache prune --apply --project");

    assert!(
        output.status.success(),
        "--apply --project on empty store must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(
        combined.contains("✓ Done · pruned 0 link entries + 0 objects (0 B) in "),
        "cache prune apply should finish with elapsed done line, got:\n{combined}"
    );
}

#[test]
fn prune_dry_run_does_not_mutate_the_project_registry() {
    // Regression test for the registry-write race: dry-run holds only
    // the SHARED store lock, so concurrent installs (which also hold
    // shared) can run in parallel. If dry-run rewrote
    // `known-projects.json` to drop missing entries, it could clobber
    // a freshly registered project written between dry-run's
    // `load()` and `write()`. The fix: dry-run is read-only on the
    // registry; only `--apply` (under the EXCLUSIVE lock, which
    // blocks installs) rewrites the file.
    //
    // This test seeds a registry with one valid entry + one stale
    // entry, runs dry-run, and asserts the file content is byte-
    // identical afterward — even though the JSON output reports the
    // stale entry would be dropped.
    let project = TempProject::empty(r#"{"name":"prune-dry-no-mut","version":"1.0.0"}"#);

    let lpm_root = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_root).expect("failed to create .lpm dir");
    let registry_path = lpm_root.join("known-projects.json");

    // Seed: one entry pointing at the project (lives), one stale.
    let registry_seed = seed_registry(&registry_path, project.path());

    let output = lpm_v2(&project)
        .args(["cache", "prune", "--json"])
        .output()
        .expect("failed to run lpm cache prune");

    assert!(
        output.status.success(),
        "dry-run with seeded registry must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json(&output.stdout);
    assert_eq!(json["applied"], false, "dry-run must report applied=false");
    assert_eq!(
        json["registry_missing"], false,
        "registry exists; registry_missing must be false"
    );
    assert_eq!(
        json["registry_entries_dropped"], 1,
        "dry-run must report 1 stale entry would be dropped"
    );

    // The file content must be byte-identical. This is the load-
    // bearing assertion: dry-run did NOT rewrite the registry under
    // the shared store lock.
    let post = std::fs::read_to_string(&registry_path).expect("registry must still exist");
    assert_eq!(
        post, registry_seed,
        "dry-run must not rewrite known-projects.json"
    );
}

#[test]
fn prune_apply_drops_stale_registry_entries_under_exclusive_lock() {
    // Counterpart to the dry-run-no-mutation test: `--apply` IS
    // expected to rewrite the registry. The exclusive store lock
    // guarantees no concurrent install holds the shared half, so the
    // read-modify-write window is safe.
    let project = TempProject::empty(r#"{"name":"prune-apply-drops","version":"1.0.0"}"#);

    let lpm_root = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_root).expect("failed to create .lpm dir");
    let registry_path = lpm_root.join("known-projects.json");

    let _registry_seed = seed_registry(&registry_path, project.path());
    let canonical_project = std::fs::canonicalize(project.path())
        .expect("project must canonicalize")
        .display()
        .to_string();

    let output = lpm_v2(&project)
        .args(["cache", "prune", "--apply", "--json"])
        .output()
        .expect("failed to run lpm cache prune --apply");

    assert!(
        output.status.success(),
        "--apply with seeded registry must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json(&output.stdout);
    assert_eq!(json["applied"], true);
    assert_eq!(json["registry_entries_dropped"], 1);

    // After apply, the stale entry must be gone and the live entry
    // preserved. Parse the JSON instead of substring-matching so the
    // assertion handles platform-specific path escaping (backslashes
    // on Windows JSON-encode as `\\`, which would break a raw
    // `contains()` against the un-escaped `display()` form).
    let post = std::fs::read_to_string(&registry_path).expect("registry must still exist");
    let parsed: Value = serde_json::from_str(&post)
        .unwrap_or_else(|e| panic!("registry JSON must parse after apply: {e}\n---\n{post}"));
    let project_paths: Vec<String> = parsed["projects"]
        .as_array()
        .expect("registry must have a projects array")
        .iter()
        .filter_map(|p| p["path"].as_str().map(String::from))
        .collect();
    assert!(
        !project_paths.iter().any(|p| p.contains("stale-project")),
        "--apply must drop the stale entry; registry projects now: {project_paths:?}"
    );
    assert!(
        project_paths.iter().any(|p| p == &canonical_project),
        "--apply must preserve the live entry; registry projects now: {project_paths:?}, \
         expected to contain: {canonical_project}"
    );
}

#[test]
fn prune_apply_with_corrupt_registry_does_not_wipe_the_store() {
    // Critical safety regression: `known_projects::load()` lossy-collapses
    // malformed JSON, schema mismatches, and I/O errors all to an empty
    // `Registry`. If `compute_prune_plan` only checked file-existence
    // (the prior behavior), a corrupt registry would yield zero roots
    // → every link entry would look orphaned → `--apply` would wipe
    // the live store.
    //
    // The fix uses `try_load` to distinguish missing from corrupt;
    // both states skip the orphan walk and `--apply` degrades to
    // tombstone-only mode. This test seeds a corrupt registry plus
    // synthetic link + object dirs, runs `--apply`, and asserts the
    // dirs still exist + the response surfaces `registry_corrupt`.
    let project = TempProject::empty(r#"{"name":"prune-corrupt","version":"1.0.0"}"#);

    let lpm_root = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_root).expect("failed to create .lpm dir");
    let registry_path = lpm_root.join("known-projects.json");

    // Corrupt registry: text that can't possibly parse as JSON.
    std::fs::write(&registry_path, b"not even close to json{[")
        .expect("failed to seed corrupt registry");

    // Plant synthetic v2 store entries so we can prove apply didn't
    // delete them. These aren't valid link entries (no sidecar, no
    // real bytes), but they live where the orphan walker would find
    // them — `compute_prune_plan` is supposed to skip the walk in
    // the corrupt-registry path, so the dirs survive untouched.
    let store_v2 = lpm_root.join("store").join("v2");
    let synth_link = store_v2.join("links").join("synth-key");
    let synth_object = store_v2.join("objects").join("synth-sri");
    std::fs::create_dir_all(&synth_link).expect("failed to seed synthetic link entry");
    std::fs::create_dir_all(&synth_object).expect("failed to seed synthetic object");
    std::fs::write(synth_link.join("marker.txt"), b"survive me").expect("failed to seed marker");

    let output = lpm_v2(&project)
        .args(["cache", "prune", "--apply", "--json"])
        .output()
        .expect("failed to run lpm cache prune --apply with corrupt registry");

    assert!(
        output.status.success(),
        "--apply with corrupt registry must succeed (degrade safely):\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json(&output.stdout);
    assert_eq!(json["applied"], true, "applied must be true");
    assert_eq!(
        json["registry_corrupt"], true,
        "corrupt registry must set registry_corrupt=true"
    );
    assert_eq!(
        json["registry_missing"], false,
        "the file exists, just not parseable; registry_missing must stay false"
    );
    assert!(
        json["registry_corrupt_reason"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "registry_corrupt_reason must be a non-empty explanation"
    );
    assert_eq!(
        json["link_entries_orphaned"].as_array().map_or(0, Vec::len),
        0,
        "corrupt-registry apply must NOT report link orphans"
    );
    assert_eq!(
        json["object_entries_orphaned"]
            .as_array()
            .map_or(0, Vec::len),
        0,
        "corrupt-registry apply must NOT report object orphans"
    );

    // The load-bearing safety assertion: the synthetic store entries
    // still exist on disk. If the orphan walk had run against the
    // empty root set, both would have been deleted.
    assert!(
        synth_link.exists() && synth_link.join("marker.txt").exists(),
        "corrupt-registry --apply must NOT delete link entries: {} survived?",
        synth_link.display()
    );
    assert!(
        synth_object.exists(),
        "corrupt-registry --apply must NOT delete object entries: {} survived?",
        synth_object.display()
    );
}

#[test]
fn prune_back_to_back_apply_invocations_release_the_store_lock() {
    // Smoke test: two sequential `--apply` invocations must each
    // acquire-and-release the exclusive store lock cleanly. A leaked
    // lock would manifest as the second invocation hanging on the
    // contention probe (or, with the default 1-second poll, emitting
    // the "Waiting for another lpm store operation to finish..."
    // hint and eventually succeeding). Both succeeding back-to-back
    // is the simplest end-to-end proof that the lock guard is paired
    // with a release.
    let project = TempProject::empty(r#"{"name":"prune-lock-release","version":"1.0.0"}"#);

    for round in 0..2 {
        let output = lpm_v2(&project)
            .args(["cache", "prune", "--apply", "--json"])
            .output()
            .unwrap_or_else(|e| {
                panic!("round {round}: failed to run lpm cache prune --apply: {e}")
            });

        assert!(
            output.status.success(),
            "round {round}: --apply must succeed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
