//! 
//!
//! Two-step workflow:
//!
//! 1. `lpm patch <name>@<version>` extracts a clean copy of the store
//!    package to a unique staging dir under the OS temp root, prints
//!    the path, and writes a breadcrumb file (`.lpm-patch.json`) so
//!    the second step can recover `(name, version, store_path)`.
//!
//! 2. The user edits files in the staging package directory.
//!
//! 3. `lpm patch-commit <staging_dir>` reads the breadcrumb, generates
//!    a unified diff against the store baseline, writes
//!    `<project>/patches/<key>.patch`, updates `package.json` with the
//!    new `lpm.patchedDependencies` entry, and cleans up the staging
//!    directory.
//!
//! Patches travel with the repo. The next `lpm install` automatically
//! re-applies them after linking.

use crate::output;
use crate::patch_engine::{
    GeneratedPatch, PatchSelector, STAGING_BREADCRUMB_FILE, copy_store_to_staging, generate_patch,
    parse_patch_selector, resolve_patch_selector,
};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_lockfile::Lockfile;
use lpm_store::find_installed_package_baseline;
use serde_json::json;
use std::path::Path;

// ── lpm patch ────────────────────────────────────────────────────────

/// `lpm patch <selector>` — extract a store copy to a staging dir.
///
/// `<selector>` accepts a bare name (`lodash`), an exact pin
/// (`lodash@4.17.21`), or a semver range (`lodash@^4.0.0`). Bare names
/// and ranges resolve to an exact pin against the project lockfile
/// BEFORE entering the store lock scope; the persisted-key path that
/// runs under the lock always sees an exact `(name, version)`.
///
/// **Why selector resolution runs outside the lock:** the lockfile
/// read is project-scoped and unrelated to the global store. Holding
/// the store lock during a "your selector matches three packages"
/// error print would block other `lpm patch` / `lpm install`
/// invocations for no reason. The structural seam — parse and
/// resolve happen in this function, lock and staging happen in
/// `run_patch_inner` — is the contract the unit tests exercise.
pub async fn run_patch(project_dir: &Path, input: &str, json_output: bool) -> Result<(), LpmError> {
    let selector = parse_patch_selector(input)?;
    let (name, version) = match selector {
        PatchSelector::Exact { name, version } => (name, version),
        PatchSelector::BareName(_) | PatchSelector::Range { .. } => {
            let lockfile = read_lockfile_for_patch_selector(project_dir)?;
            resolve_patch_selector(&lockfile, &selector)?
        }
    };
    let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
    lpm_common::with_shared_lock_async(lock_path, run_patch_inner(name, version, json_output)).await
}

/// Read the project lockfile, or surface an actionable error if the
/// project hasn't been installed yet. Bare-name / range selectors
/// REQUIRE a lockfile — exact pins do not (the legacy workflow tests
/// exercise `lpm patch <name>@<exact>` on projects with no lockfile,
/// and that capability must be preserved).
fn read_lockfile_for_patch_selector(project_dir: &Path) -> Result<Lockfile, LpmError> {
    let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if !Lockfile::exists(&lock_path) {
        return Err(LpmError::Script(
            "bare-name and semver-range selectors require a project lockfile. \
             Run `lpm install` first, or pass an exact pin like \
             `lpm patch <name>@<version>`."
                .into(),
        ));
    }
    Lockfile::read_from_file(&lock_path).map_err(|e| {
        LpmError::Script(format!(
            "failed to read project lockfile at {lock_path:?}: {e}"
        ))
    })
}

async fn run_patch_inner(name: String, version: String, json_output: bool) -> Result<(), LpmError> {
    // Lookup goes
    // through `find_installed_package_baseline`, which prefers the
    // v2 virtual store (defaultb) and falls back to v1.
    // Pre-fix this called `store.has_package(...)` (v1-only), which
    // always returned false under v2 → "not in the global store".
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let baseline =
        find_installed_package_baseline(&lpm_root, &name, &version)?.ok_or_else(|| {
            LpmError::Script(format!(
                "{name}@{version} is not in the global store. \
                 Run `lpm install {name}@{version}` first."
            ))
        })?;
    // Seed the staging copy from
    // the PRISTINE bytes — `objects/<sri>/` under v2, or the v1 store
    // dir (which v1 patches never mutate). Reading `package_dir` on
    // an already-patched v2 link entry would seed the staging dir
    // with previously-applied edits, defeating the workflow.
    let store_path = baseline.pristine_dir;

    // Build a unique staging directory under the OS temp root. We
    // explicitly do NOT use `TempDir` (which would auto-delete on
    // Drop) — the staging dir must outlive this process so the user
    // can edit files in it before running `lpm patch-commit`.
    let staging_root = tempfile::Builder::new()
        .prefix("lpm-patch-")
        .tempdir_in(std::env::temp_dir())
        .map_err(LpmError::Io)?;
    let staging_path = staging_root.keep();

    let dest = staging_path.join("node_modules").join(&name);
    copy_store_to_staging(&store_path, &dest)?;

    // Write the breadcrumb. patch-commit reads this to recover the
    // identity without re-parsing the staging path. **The `key` field
    // is always the resolved exact pin**, never the raw user input —
    // so a user who typed `lpm patch lodash@^4.0.0` still produces a
    // breadcrumb with `key: "lodash@4.17.21"` and `lpm patch-commit`
    // writes `patches/lodash@4.17.21.patch`.
    let resolved_key = format!("{name}@{version}");
    let breadcrumb = json!({
        "name": name,
        "version": version,
        "key": resolved_key,
        "store_path": store_path.display().to_string(),
    });
    std::fs::write(
        staging_path.join(STAGING_BREADCRUMB_FILE),
        serde_json::to_string_pretty(&breadcrumb).unwrap(),
    )
    .map_err(LpmError::Io)?;

    if json_output {
        let payload = json!({
            "success": true,
            "name": name,
            "version": version,
            "key": resolved_key,
            "staging_dir": staging_path.display().to_string(),
            "package_dir": dest.display().to_string(),
            "next_steps": [
                "Edit files in the package_dir",
                format!("Run: lpm patch-commit {}", staging_path.display()),
            ],
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
    } else {
        output::success(&format!("Extracted to {}", dest.display()));
        output::info("Edit the files, then run:");
        output::info(&format!(
            "  {} {}",
            "lpm patch-commit".bold(),
            staging_path.display()
        ));
    }
    Ok(())
}

// ── lpm patch-commit ─────────────────────────────────────────────────

/// `lpm patch-commit <staging_dir>` — finalize a patch into the project.
pub async fn run_patch_commit(
    project_dir: &Path,
    staging_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
    lpm_common::with_shared_lock_async(
        lock_path,
        run_patch_commit_inner(project_dir, staging_dir, json_output),
    )
    .await
}

async fn run_patch_commit_inner(
    project_dir: &Path,
    staging_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if !staging_dir.exists() {
        return Err(LpmError::Script(format!(
            "staging directory {staging_dir:?} does not exist"
        )));
    }

    // 1. Read the breadcrumb left by `lpm patch`.
    let breadcrumb_path = staging_dir.join(STAGING_BREADCRUMB_FILE);
    let breadcrumb_text = std::fs::read_to_string(&breadcrumb_path).map_err(|e| {
        LpmError::Script(format!(
            "{staging_dir:?} is not an lpm-patch staging dir (no \
             .lpm-patch.json): {e}"
        ))
    })?;
    let breadcrumb: serde_json::Value = serde_json::from_str(&breadcrumb_text).map_err(|e| {
        LpmError::Script(format!(
            "staging breadcrumb at {breadcrumb_path:?} is malformed: {e}"
        ))
    })?;
    let name = breadcrumb["name"]
        .as_str()
        .ok_or_else(|| LpmError::Script("breadcrumb missing `name`".into()))?;
    let version = breadcrumb["version"]
        .as_str()
        .ok_or_else(|| LpmError::Script("breadcrumb missing `version`".into()))?;
    let key = breadcrumb["key"]
        .as_str()
        .ok_or_else(|| LpmError::Script("breadcrumb missing `key`".into()))?;

    // 2. Locate the store baseline. We re-read it from the live store
    // (not the breadcrumb's recorded path) so that store relocations
    // between `patch` and `patch-commit` don't break commit.
    // v2-aware via
    // `find_installed_package_baseline` — same shape as
    // `run_patch_inner` above; the integrity comes back in the same
    // call so we no longer need a separate `read_stored_integrity`
    // probe at step 4.
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let baseline = find_installed_package_baseline(&lpm_root, name, version)?.ok_or_else(|| {
        LpmError::Script(format!(
            "{name}@{version} is no longer in the global store; \
                 cannot generate patch baseline"
        ))
    })?;
    // Diff against the PRISTINE
    // bytes (`objects/<sri>/` under v2, the v1 store dir under v1) so
    // a re-run of `lpm patch` + edit + `lpm patch-commit` against an
    // already-patched install produces the correct delta-from-upstream
    // patch — not a delta-from-previously-patched-state patch.
    let store_path = baseline.pristine_dir.clone();

    let edited_dir = staging_dir.join("node_modules").join(name);
    if !edited_dir.exists() {
        return Err(LpmError::Script(format!(
            "expected edited package at {edited_dir:?} but the directory \
             does not exist; did you delete the staging tree?"
        )));
    }

    // 3. Generate the unified diff.
    let generated: GeneratedPatch = generate_patch(&store_path, &edited_dir)?;
    // Check binary files BEFORE the empty check — a staging dir whose
    // ONLY change is a binary edit produces an empty `diff` text but
    // a non-empty `binary_files_differ` list. Reporting "no changes"
    // would be misleading; the user did make a change, just one we
    // don't accept.
    if !generated.binary_files_differ.is_empty() {
        return Err(LpmError::Script(format!(
            "binary files differ ({:?}); patches must be text-only — \
             remove the binary edits before committing",
            generated.binary_files_differ
        )));
    }
    if generated.diff.is_empty() {
        return Err(LpmError::Script(format!(
            "no changes detected in {edited_dir:?} — patch-commit aborted"
        )));
    }

    // 4. Original integrity comes from the v2 link sidecar
    // (`meta.source_sri`) or v1's `.integrity` sentinel — both
    // resolved in step 2's lookup, so no second probe needed.
    let integrity = baseline.integrity;

    // 5. Write patches/<safe_key>.patch. Scoped names get `/` → `__`
    //    so the file is portable across platforms (mirrors pnpm).
    let safe_key = key.replace('/', "__");
    let patches_dir = project_dir.join("patches");
    std::fs::create_dir_all(&patches_dir).map_err(LpmError::Io)?;
    let patch_file_rel = format!("patches/{safe_key}.patch");
    let patch_file_abs = project_dir.join(&patch_file_rel);

    // Write atomically so a crash mid-write doesn't leave a partial
    // patch file.
    let tmp_patch = project_dir.join(format!("{patch_file_rel}.tmp"));
    std::fs::write(&tmp_patch, generated.diff.as_bytes()).map_err(LpmError::Io)?;
    if let Err(e) = std::fs::rename(&tmp_patch, &patch_file_abs) {
        let _ = std::fs::remove_file(&tmp_patch);
        return Err(LpmError::Io(e));
    }

    // 6. Update package.json — JSON Value mutation pattern, mirror of
    //    add.rs. Roll back the patch file write if package.json fails.
    if let Err(e) = update_package_json_patches(project_dir, key, &patch_file_rel, &integrity) {
        let _ = std::fs::remove_file(&patch_file_abs);
        return Err(e);
    }

    // 7. Clean up the staging dir on success. Best-effort — we don't
    //    fail the command if cleanup hiccups.
    let _ = std::fs::remove_dir_all(staging_dir);

    if json_output {
        let payload = json!({
            "success": true,
            "name": name,
            "version": version,
            "key": key,
            "patch_file": patch_file_rel,
            "files_changed": generated.files_changed,
            "insertions": generated.insertions,
            "deletions": generated.deletions,
            "original_integrity": integrity,
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
    } else {
        let plural = if generated.files_changed == 1 {
            ""
        } else {
            "s"
        };
        output::success(&format!(
            "Wrote {} ({} file{plural} changed, {} insertions(+), {} deletions(-))",
            patch_file_rel.bold(),
            generated.files_changed,
            generated.insertions,
            generated.deletions,
        ));
        output::success("Updated package.json (lpm.patchedDependencies)");
    }

    Ok(())
}

/// Inject `lpm.patchedDependencies.<key>` into `package.json` using the
/// JSON Value mutation pattern. Same approach as `add.rs` — `serde_json`
/// has `preserve_order` enabled at the workspace level, so existing key
/// order is preserved. Atomic write via `.tmp` rename.
fn update_package_json_patches(
    project_dir: &Path,
    key: &str,
    patch_file_rel: &str,
    integrity: &str,
) -> Result<(), LpmError> {
    let pkg_path = project_dir.join("package.json");
    let raw = std::fs::read_to_string(&pkg_path)
        .map_err(|e| LpmError::Script(format!("package.json at {pkg_path:?} unreadable: {e}")))?;
    let mut value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| LpmError::Script(format!("package.json malformed: {e}")))?;

    // Ensure `lpm` is an object.
    let lpm = value
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json root is not an object".into()))?
        .entry("lpm".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    let lpm_obj = lpm
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json `lpm` is not an object".into()))?;

    // Ensure `patchedDependencies` is an object.
    let patches = lpm_obj
        .entry("patchedDependencies".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let patches_obj = patches.as_object_mut().ok_or_else(|| {
        LpmError::Script("package.json `lpm.patchedDependencies` is not an object".into())
    })?;

    // Insert the new entry. We mirror the on-disk shape of
    // PatchedDependencyEntry exactly so a re-parse roundtrips.
    patches_obj.insert(
        key.to_string(),
        json!({
            "path": patch_file_rel,
            "originalIntegrity": integrity,
        }),
    );

    let mut output = serde_json::to_string_pretty(&value)
        .map_err(|e| LpmError::Script(format!("failed to re-serialize package.json: {e}")))?;
    if !output.ends_with('\n') {
        output.push('\n');
    }

    let tmp = project_dir.join("package.json.tmp");
    std::fs::write(&tmp, output.as_bytes()).map_err(LpmError::Io)?;
    if let Err(e) = std::fs::rename(&tmp, &pkg_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LpmError::Io(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_pkg(dir: &Path, content: &str) -> PathBuf {
        let p = dir.join("package.json");
        std::fs::write(&p, content).unwrap();
        p
    }

    fn read_pkg(dir: &Path) -> serde_json::Value {
        let raw = std::fs::read_to_string(dir.join("package.json")).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn update_package_json_creates_lpm_section_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "myproject",
  "version": "1.0.0"
}"#,
        );

        update_package_json_patches(
            dir.path(),
            "lodash@4.17.21",
            "patches/lodash@4.17.21.patch",
            "sha512-aaa",
        )
        .unwrap();

        let v = read_pkg(dir.path());
        assert_eq!(
            v["lpm"]["patchedDependencies"]["lodash@4.17.21"]["path"],
            "patches/lodash@4.17.21.patch"
        );
        assert_eq!(
            v["lpm"]["patchedDependencies"]["lodash@4.17.21"]["originalIntegrity"],
            "sha512-aaa"
        );
        // Existing fields preserved
        assert_eq!(v["name"], "myproject");
        assert_eq!(v["version"], "1.0.0");
    }

    #[test]
    fn update_package_json_extends_existing_lpm_section() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "myproject",
  "lpm": {
    "trustedDependencies": ["esbuild"]
  }
}"#,
        );

        update_package_json_patches(
            dir.path(),
            "foo@1.0.0",
            "patches/foo@1.0.0.patch",
            "sha512-foo",
        )
        .unwrap();

        let v = read_pkg(dir.path());
        // Existing trustedDependencies preserved
        assert_eq!(v["lpm"]["trustedDependencies"][0], "esbuild");
        // New patch entry present
        assert_eq!(
            v["lpm"]["patchedDependencies"]["foo@1.0.0"]["path"],
            "patches/foo@1.0.0.patch"
        );
    }

    #[test]
    fn update_package_json_replaces_existing_patch_entry() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "x",
  "lpm": {
    "patchedDependencies": {
      "lodash@4.17.21": {
        "path": "patches/old.patch",
        "originalIntegrity": "sha512-old"
      }
    }
  }
}"#,
        );

        update_package_json_patches(
            dir.path(),
            "lodash@4.17.21",
            "patches/lodash@4.17.21.patch",
            "sha512-new",
        )
        .unwrap();

        let v = read_pkg(dir.path());
        assert_eq!(
            v["lpm"]["patchedDependencies"]["lodash@4.17.21"]["path"],
            "patches/lodash@4.17.21.patch"
        );
        assert_eq!(
            v["lpm"]["patchedDependencies"]["lodash@4.17.21"]["originalIntegrity"],
            "sha512-new"
        );
    }

    #[test]
    fn update_package_json_preserves_top_level_key_order() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "x",
  "version": "1.0.0",
  "scripts": { "build": "tsc" },
  "dependencies": { "lodash": "^4.17.21" }
}"#,
        );

        update_package_json_patches(
            dir.path(),
            "lodash@4.17.21",
            "patches/lodash@4.17.21.patch",
            "sha512-aa",
        )
        .unwrap();

        // Read raw bytes — the preserve_order feature on serde_json
        // means the original key order is retained.
        let raw = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
        let pos_name = raw.find("\"name\"").unwrap();
        let pos_version = raw.find("\"version\"").unwrap();
        let pos_scripts = raw.find("\"scripts\"").unwrap();
        let pos_deps = raw.find("\"dependencies\"").unwrap();
        assert!(pos_name < pos_version);
        assert!(pos_version < pos_scripts);
        assert!(pos_scripts < pos_deps);
    }

    #[test]
    fn update_package_json_fails_on_malformed_input() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(dir.path(), "{ this is not json");
        let err = update_package_json_patches(
            dir.path(),
            "lodash@4.17.21",
            "patches/lodash@4.17.21.patch",
            "sha512-aa",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("malformed"));
    }

    /// **Slice A structural contract.** `read_lockfile_for_patch_selector`
    /// is the pre-lock branch point for bare-name / range selectors:
    /// it MUST error out before `run_patch` reaches
    /// `with_shared_lock_async`. The test verifies that a project
    /// without an `lpm.lock` produces an actionable error here — which,
    /// because of Rust's `?` control flow, propagates back through
    /// `run_patch` BEFORE the store lock is even acquired.
    ///
    /// This is the structural proof for the "no global store lock held
    /// during selector failure" guarantee. We do NOT spin up a second
    /// process to time-race a second `lpm patch` (flaky on slow CI
    /// runners); the lock-scope contract is enforced by the code's
    /// branch order, which this test exercises directly.
    #[test]
    fn read_lockfile_for_patch_selector_errors_with_actionable_hint_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_lockfile_for_patch_selector(dir.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("lockfile"), "got: {msg}");
        assert!(msg.contains("lpm install"), "got: {msg}");
        assert!(msg.contains("exact pin"), "got: {msg}");
    }

    /// Companion to the above: a well-formed `lpm.lock` is read cleanly.
    #[test]
    fn read_lockfile_for_patch_selector_loads_valid_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.lock"),
            "[metadata]\nlockfile-version = 2\nresolved-with = \"test\"\n\n\
             [[packages]]\nname = \"lodash\"\nversion = \"4.17.21\"\n\
             source = \"registry+https://registry.npmjs.org\"\n",
        )
        .unwrap();
        let lf = read_lockfile_for_patch_selector(dir.path()).unwrap();
        assert_eq!(lf.packages.len(), 1);
        assert_eq!(lf.packages[0].name, "lodash");
        assert_eq!(lf.packages[0].version, "4.17.21");
    }
}
