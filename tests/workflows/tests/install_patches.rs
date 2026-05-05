//! Workflow tests for `lpm install` + the patch-apply pipeline.
//!
//! Phase 32 Phase 6 acceptance criteria + 2026-04-12 audit fixes:
//! - Patches apply after the linker pass (canonical isolated location).
//! - Idempotent reruns are no-ops (no double-apply, no zero-op summary
//!   in JSON or human output).
//! - Drift / missing patch / fuzzy hunk are HARD install errors.
//! - `--offline` enforces patch-fingerprint integrity (mirror of the
//!   Phase 5 overrides offline contract).
//! - State-file lifecycle: created on apply, deleted when patches
//!   removed.
//! - `--json` envelope's `applied_patches[]` reflects per-run work,
//!   not the persisted state.
//!
//! Companion: patch authoring (`patch` + `patch-commit`) lives in
//! `patch.rs`; graph `--why` + patch decoration lives in `graph.rs`.

mod support;

use std::path::PathBuf;
use support::{TempProject, lpm_with_registry};

// ─── Helpers ────────────────────────────────────────────────────────────

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

/// Seed `<store>/v1/<safe>@<v>/` with package.json, the supplied source
/// files, and the `.integrity` sentinel. Returns the integrity string
/// the engine reads back from disk.
fn seed_store_package(
    project: &TempProject,
    name: &str,
    version: &str,
    files: &[(&str, &str)],
) -> String {
    let safe = name.replace(['/', '\\'], "+");
    let dir = project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{version}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
    for (rel, content) in files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
    }
    let integrity = format!("sha512-fixture-{name}-{version}");
    std::fs::write(dir.join(".integrity"), &integrity).unwrap();
    integrity
}

/// Write a synthetic `lpm.lock`.
fn write_lockfile(project: &TempProject, entries: &[(&str, &str, &[&str])]) {
    let pkgs: Vec<String> = entries
        .iter()
        .map(|(name, version, deps)| {
            let deps_block = if deps.is_empty() {
                String::new()
            } else {
                let inner = deps
                    .iter()
                    .map(|d| format!("\"{d}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("\ndependencies = [{inner}]")
            };
            format!("[[packages]]\nname = \"{name}\"\nversion = \"{version}\"{deps_block}\n")
        })
        .collect();
    let toml = format!(
        "[metadata]\nlockfile-version = 1\nresolved-with = \"pubgrub\"\n\n{}\n",
        pkgs.join("\n")
    );
    project.write_file("lpm.lock", &toml);
}

/// Mirror of `patch_state::compute_fingerprint`. **MUST stay in sync**
/// with the resolver — divergence makes the matching-fingerprint tests
/// fail loudly.
fn phase6_fingerprint(entries: &[(&str, &str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut keys: Vec<&(&str, &str, &str)> = entries.iter().collect();
    keys.sort_by(|a, b| a.0.cmp(b.0));
    let mut h = Sha256::new();
    for (k, p, integrity) in keys {
        h.update(k.as_bytes());
        h.update(b"\x00");
        h.update(p.as_bytes());
        h.update(b"\x00");
        h.update(integrity.as_bytes());
        h.update(b"\x01");
    }
    format!("sha256-{:x}", h.finalize())
}

type AppliedTuple<'a> = (
    &'a str,       // name
    &'a str,       // version
    &'a str,       // patch_path
    &'a [&'a str], // locations
    usize,         // modified
    usize,         // added
    usize,         // deleted
);

/// Write `.lpm/patch-state.json` capturing parsed + applied entries.
/// Used both as drift-gate fixture and as graph-decoration fixture.
fn write_patch_state(
    project: &TempProject,
    fingerprint: &str,
    parsed: &[(&str, &str, &str, &str)],
    applied: &[AppliedTuple<'_>],
) {
    let parsed_json: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(raw_key, name, version, path)| {
            serde_json::json!({
                "raw_key": raw_key,
                "name": name,
                "version": version,
                "path": path,
                "original_integrity": "sha512-fixture",
            })
        })
        .collect();
    let applied_json: Vec<serde_json::Value> = applied
        .iter()
        .map(
            |(name, version, patch_path, locations, modified, added, deleted)| {
                serde_json::json!({
                    "raw_key": format!("{name}@{version}"),
                    "name": name,
                    "version": version,
                    "patch_path": patch_path,
                    "locations": locations.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    "files_modified": modified,
                    "files_added": added,
                    "files_deleted": deleted,
                })
            },
        )
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": fingerprint,
        "captured_at": "2026-04-12T00:00:00Z",
        "parsed": parsed_json,
        "applied": applied_json,
    });
    project.write_file(
        ".lpm/patch-state.json",
        &serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// Build a fixture with the seeded store entry, a patch file at
/// `patches/<key>.patch`, a manifest declaring
/// `lpm.patchedDependencies`, a lockfile, and a matching
/// `.lpm/patch-state.json`. Returns the integrity the engine will read
/// back. The pre-staged state is required so the offline drift gate
/// accepts the apply pass.
fn build_patch_install_fixture(
    project: &TempProject,
    project_name: &str,
    pkg_name: &str,
    pkg_version: &str,
    store_files: &[(&str, &str)],
    patch_text: &str,
) -> String {
    let integrity = seed_store_package(project, pkg_name, pkg_version, store_files);

    let patch_rel = format!("patches/{pkg_name}@{pkg_version}.patch");
    project.write_file(&patch_rel, patch_text);

    project.write_file(
        "package.json",
        &format!(
            r#"{{
  "name": "{project_name}",
  "version": "0.0.0",
  "dependencies": {{ "{pkg_name}": "^{pkg_version}" }},
  "lpm": {{
    "patchedDependencies": {{
      "{pkg_name}@{pkg_version}": {{
        "path": "{patch_rel}",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(project, &[(pkg_name, pkg_version, &[])]);

    let key = format!("{pkg_name}@{pkg_version}");
    let fp = phase6_fingerprint(&[(&key, &patch_rel, &integrity)]);
    write_patch_state(
        project,
        &fp,
        &[(&key, pkg_name, pkg_version, &patch_rel)],
        &[],
    );
    integrity
}

// ─── Online apply (run via `--offline` against a seeded store) ──────────

/// Patch is applied to the canonical isolated linker location after the
/// linker pass. `.lpm/wrappers/<name>@<version>/node_modules/<name>/<file>`
/// must contain the patched bytes.
#[test]
fn install_patches_applied_after_link_in_isolated_layout() {
    let project = TempProject::empty("");
    let original = "module.exports = 'orig'\n";
    let patched = "module.exports = 'PATCHED'\n";
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-module.exports = 'orig'\n+module.exports = 'PATCHED'\n";
    build_patch_install_fixture(
        &project,
        "install-applies-patch",
        "lodash",
        "4.17.21",
        &[("index.js", original)],
        patch_text,
    );

    lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .assert()
        .success();

    let nm_file = project
        .path()
        .join(".lpm/wrappers/lodash@4.17.21/node_modules/lodash/index.js");
    assert!(nm_file.exists(), "linked file must exist");
    assert_eq!(
        std::fs::read_to_string(&nm_file).unwrap(),
        patched,
        "patch must be applied to the linked tree"
    );
}

/// Two installs back-to-back leave the patched bytes intact (no
/// double-apply, no revert). Idempotency contract.
#[test]
fn install_patches_idempotent_across_repeated_installs() {
    let project = TempProject::empty("");
    let original = "a\nb\nc\n";
    let patched = "a\nB\nc\n";
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n";
    build_patch_install_fixture(
        &project,
        "install-idempotent",
        "lodash",
        "4.17.21",
        &[("index.js", original)],
        patch_text,
    );

    lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .assert()
        .success();
    lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .assert()
        .success();

    let nm_file = project
        .path()
        .join(".lpm/wrappers/lodash@4.17.21/node_modules/lodash/index.js");
    assert_eq!(std::fs::read_to_string(&nm_file).unwrap(), patched);
}

/// Drift in the store's `.integrity` between apply-time and recorded
/// `originalIntegrity` is a HARD install error. Catches a tampered
/// store after a patch was authored against a different baseline.
#[test]
fn install_patches_hard_errors_on_integrity_drift() {
    let project = TempProject::empty("");
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-orig\n+patched\n";
    build_patch_install_fixture(
        &project,
        "install-drift",
        "lodash",
        "4.17.21",
        &[("index.js", "orig\n")],
        patch_text,
    );

    // Mutate `.integrity` after the fixture was built so the live store
    // reports a different value than the one bound in the manifest.
    let store_integrity = project.store_dir().join("v1/lodash@4.17.21/.integrity");
    std::fs::write(&store_integrity, "sha512-different-from-recorded").unwrap();

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "drift must hard-error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("drift"),
        "error must mention 'drift'; got:\n{combined}"
    );
    assert!(
        combined.contains("lodash"),
        "error must name the package; got:\n{combined}"
    );
}

/// Manifest references `patches/missing.patch` but the file is absent.
/// Apply pass must fail with a diagnostic naming the missing path.
#[test]
fn install_patches_hard_errors_on_missing_patch_file() {
    let project = TempProject::empty("");
    let integrity = seed_store_package(&project, "lodash", "4.17.21", &[("index.js", "x\n")]);
    let patch_rel = "patches/missing.patch";
    project.write_file(
        "package.json",
        &format!(
            r#"{{
  "name": "install-missing-patch",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "{patch_rel}",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    // Pre-stage matching state so the offline drift gate passes; the
    // missing-file check fires inside the apply pass.
    let fp = phase6_fingerprint(&[("lodash@4.17.21", patch_rel, &integrity)]);
    write_patch_state(
        &project,
        &fp,
        &[("lodash@4.17.21", "lodash", "4.17.21", patch_rel)],
        &[],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "missing patch file must hard-error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("does not exist") || combined.contains("missing.patch"),
        "error must name the missing path; got:\n{combined}"
    );
}

/// Patch was authored against different content than the store
/// baseline; strict apply must reject ("hunk failed" / regenerate
/// guidance).
#[test]
fn install_patches_hard_errors_on_fuzzy_hunk() {
    let project = TempProject::empty("");
    let patch_text =
        "--- a/index.js\n+++ b/index.js\n@@ -1,3 +1,3 @@\n apple\n-banana\n+BANANA\n cherry\n";
    build_patch_install_fixture(
        &project,
        "install-fuzzy",
        "lodash",
        "4.17.21",
        &[("index.js", "alpha\nbravo\ncharlie\n")],
        patch_text,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "fuzzy hunk must hard-error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("hunk failed") || combined.contains("regenerate"),
        "error must mention failed hunk / regenerate; got:\n{combined}"
    );
}

// ─── Offline drift gate ─────────────────────────────────────────────────

/// Patches map fingerprint changes between two installs (different
/// patch path) — second offline install must hard-error with a recovery
/// hint pointing at online re-resolve.
#[test]
fn install_patches_offline_hard_errors_when_patches_change_between_runs() {
    let project = TempProject::empty("");
    let integrity = seed_store_package(&project, "lodash", "4.17.21", &[("index.js", "x\n")]);
    project.write_file(
        "patches/v1.patch",
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n",
    );
    project.write_file(
        "patches/v2.patch",
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+Y\n",
    );

    let manifest_v1 = format!(
        r#"{{
  "name": "patches-changed",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "patches/v1.patch",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
    );
    project.write_file("package.json", &manifest_v1);
    write_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    let fp_v1 = phase6_fingerprint(&[("lodash@4.17.21", "patches/v1.patch", &integrity)]);
    write_patch_state(
        &project,
        &fp_v1,
        &[("lodash@4.17.21", "lodash", "4.17.21", "patches/v1.patch")],
        &[],
    );

    // First install — succeeds with v1 applied.
    lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .assert()
        .success();

    // Edit the manifest to point at v2 — fingerprint drift.
    let manifest_v2 = manifest_v1.replace("patches/v1.patch", "patches/v2.patch");
    project.write_file("package.json", &manifest_v2);

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "drift must hard-error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("patch") || combined.contains("fingerprint"),
        "error must mention patches/fingerprint; got:\n{combined}"
    );
    assert!(
        combined.contains("online") || combined.contains("re-resolve"),
        "error must point at online recovery; got:\n{combined}"
    );
}

/// Persisted fingerprint diverges from the current `lpm.patchedDependencies`
/// fingerprint → offline install hard-errors.
#[test]
fn install_patches_offline_hard_errors_on_patch_fingerprint_mismatch() {
    let project = TempProject::empty("");
    let integrity = seed_store_package(&project, "lodash", "4.17.21", &[("index.js", "x\n")]);
    project.write_file(
        "patches/lodash@4.17.21.patch",
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n",
    );
    project.write_file(
        "package.json",
        &format!(
            r#"{{
  "name": "offline-patch-mismatch",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    write_patch_state(
        &project,
        "sha256-completely-different-from-current",
        &[(
            "lodash@4.17.21",
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
        )],
        &[],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "fingerprint mismatch must hard-error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("patch") || combined.contains("fingerprint"),
        "error must mention patches/fingerprint; got:\n{combined}"
    );
    assert!(
        combined.contains("online") || combined.contains("re-resolve"),
        "error must point at online recovery; got:\n{combined}"
    );
}

/// `package.json` declares patches but `.lpm/patch-state.json` is
/// absent — offline cannot prove the lockfile is safe, must refuse.
#[test]
fn install_patches_offline_hard_errors_when_patches_exist_but_no_state_file() {
    let project = TempProject::empty("");
    let integrity = seed_store_package(&project, "lodash", "4.17.21", &[("index.js", "x\n")]);
    project.write_file(
        "patches/lodash@4.17.21.patch",
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n",
    );
    project.write_file(
        "package.json",
        &format!(
            r#"{{
  "name": "offline-patch-no-state",
  "version": "0.0.0",
  "dependencies": {{ "lodash": "^4.17.0" }},
  "lpm": {{
    "patchedDependencies": {{
      "lodash@4.17.21": {{
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "{integrity}"
      }}
    }}
  }}
}}"#
        ),
    );
    write_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    // Intentionally no patch-state.json.

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "no-state-file must hard-error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("patch") || combined.contains("fingerprint"),
        "error must mention patches/fingerprint; got:\n{combined}"
    );
}

/// Prior state declares patches; current manifest declares NONE →
/// offline must hard-error rather than silently linking against the
/// (now-stale) patched lockfile.
#[test]
fn install_patches_offline_hard_errors_when_patches_removed_with_prior_state() {
    let project = TempProject::empty("");
    seed_store_package(&project, "lodash", "4.17.21", &[("index.js", "x\n")]);
    project.write_file(
        "package.json",
        r#"{
  "name": "offline-patches-removed",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    write_patch_state(
        &project,
        "sha256-prior-fingerprint",
        &[(
            "lodash@4.17.21",
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
        )],
        &[(
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
            &[".lpm/wrappers/lodash@4.17.21/node_modules/lodash"],
            1,
            0,
            0,
        )],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "patches-removed must hard-error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("patch") || combined.contains("fingerprint"),
        "error must mention patches/fingerprint; got:\n{combined}"
    );
}

/// State-file lifecycle: after a successful install with no current
/// patches AND a state file matching the empty fingerprint, the state
/// file is deleted (no stale provenance).
#[test]
fn install_patches_deletes_patch_state_file_when_patches_removed() {
    let project = TempProject::empty("");
    seed_store_package(&project, "lodash", "4.17.21", &[("index.js", "x\n")]);
    project.write_file(
        "package.json",
        r#"{
  "name": "delete-patch-state",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    let empty_fp = phase6_fingerprint(&[]);
    write_patch_state(&project, &empty_fp, &[], &[]);

    lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .assert()
        .success();

    assert!(
        !project.path().join(".lpm/patch-state.json").exists(),
        "state file should be deleted when current patches set is empty"
    );
}

// ─── --json envelope contract ───────────────────────────────────────────

/// `lpm install --json` envelope's `applied_patches[]` lists the
/// per-run apply work with `name`, `version`, `files_modified`.
#[test]
fn install_json_envelope_includes_applied_patches_field() {
    let project = TempProject::empty("");
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n";
    build_patch_install_fixture(
        &project,
        "install-json-applied",
        "lodash",
        "4.17.21",
        &[("index.js", "x\n")],
        patch_text,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "install", "--offline"])
        .output()
        .expect("spawn lpm install --json");
    assert!(
        out.status.success(),
        "install --json must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out.stdout)))
            .unwrap_or_else(|e| panic!("install --json invalid: {e}"));
    let arr = parsed["applied_patches"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "applied_patches must contain one entry");
    assert_eq!(arr[0]["name"].as_str(), Some("lodash"));
    assert_eq!(arr[0]["version"].as_str(), Some("4.17.21"));
    assert_eq!(arr[0]["files_modified"].as_u64(), Some(1));
}

/// Audit fix (2026-04-12, Medium): a no-op idempotent rerun must NOT
/// claim work it didn't do. JSON `applied_patches` empty on the rerun;
/// human mode must NOT print "Applied N patches"; state file MUST
/// persist (so `lpm graph --why` keeps its provenance).
#[test]
fn install_patches_idempotent_rerun_reports_no_applied_patches_per_run() {
    let project = TempProject::empty("");
    let original = "x\n";
    let patched = "X\n";
    let patch_text = "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+X\n";
    build_patch_install_fixture(
        &project,
        "install-idempotent-zero-op-report",
        "lodash",
        "4.17.21",
        &[("index.js", original)],
        patch_text,
    );

    // First install: actually applies.
    let out1 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "install", "--offline"])
        .output()
        .expect("spawn lpm install --json (first)");
    assert!(
        out1.status.success(),
        "first install must succeed; stderr:\n{}",
        String::from_utf8_lossy(&out1.stderr)
    );
    let p1: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out1.stdout)))
            .unwrap_or_else(|e| panic!("first install --json invalid: {e}"));
    let arr1 = p1["applied_patches"].as_array().unwrap();
    assert_eq!(
        arr1.len(),
        1,
        "first install should report one applied patch"
    );
    assert_eq!(arr1[0]["files_modified"].as_u64(), Some(1));

    let nm_file = project
        .path()
        .join(".lpm/wrappers/lodash@4.17.21/node_modules/lodash/index.js");
    assert_eq!(std::fs::read_to_string(&nm_file).unwrap(), patched);

    // Second install: nothing to do. JSON applied_patches MUST be empty.
    let out2 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["--json", "install", "--offline"])
        .output()
        .expect("spawn lpm install --json (second)");
    assert!(
        out2.status.success(),
        "second install must succeed; stderr:\n{}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let p2: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out2.stdout)))
            .unwrap_or_else(|e| panic!("second install --json invalid: {e}"));
    let arr2 = p2["applied_patches"].as_array().unwrap();
    assert!(
        arr2.is_empty(),
        "no-op rerun must report empty applied_patches; got {arr2:?}"
    );

    // Bytes still patched.
    assert_eq!(std::fs::read_to_string(&nm_file).unwrap(), patched);

    // Third install in human mode: must NOT print "Applied N patches".
    let out3 = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install (third)");
    assert!(out3.status.success());
    let stdout3 = strip_ansi(&String::from_utf8_lossy(&out3.stdout));
    assert!(
        !stdout3.contains("Applied 1 patch") && !stdout3.contains("Applied 1 patches"),
        "no-op rerun human mode must NOT print 'Applied N patches'; got:\n{stdout3}"
    );

    // State file persists across no-op reruns.
    let state_path = project.path().join(".lpm/patch-state.json");
    assert!(
        state_path.exists(),
        "state file must persist across no-op reruns"
    );
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    let state_applied = state["applied"].as_array().unwrap();
    assert_eq!(
        state_applied.len(),
        1,
        "state file must preserve apply trace across no-op reruns; got: {state_applied:?}"
    );
    assert_eq!(state_applied[0]["files_modified"].as_u64(), Some(1));
    let _: PathBuf = state_path; // keep `PathBuf` import used
}
