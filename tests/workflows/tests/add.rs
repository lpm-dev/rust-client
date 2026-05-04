//! Composed workflow tests for `lpm add` (Phase 64 #9.x chain).
//!
//! The unit tests in `crates/lpm-cli/src/commands/add.rs` cover the
//! helper-level contracts (collector dedup, save-spec decision logic,
//! preflight gate, canonical-pinning). These workflow tests exercise the
//! real `lpm-rs` binary end-to-end against a mock registry — the gap
//! GPT's audits flagged across the #9 / #9.1 / #9.2 / #9.3 / #9.4
//! retrospective.
//!
//! Three properties get composed coverage:
//!
//! 1. **Happy path** (#9 + #9.1): a config-driven source package
//!    declaring a mix of bare names and `name@^range` specs ends with
//!    each entry written to `package.json` per the Phase 33 save
//!    policy — bare → `^resolvedLatest`, explicit range preserved
//!    verbatim — and the source files copied into the project.
//!
//! 2. **Preflight** (#9.4): a deps-declaring source package against a
//!    project with no `package.json` exits non-zero with a remediation
//!    hint pointing at `lpm init` / `npm init -y`, and crucially does
//!    NOT copy any source files (no Step 8 side effects on the
//!    failure path).
//!
//! 3. **Rollback** (#9.2 + #9.3): a deps-declaring source package
//!    where the trailing install fails leaves `package.json` byte-
//!    identical to its pre-`lpm add` state and the source-file dest
//!    paths absent (or restored, for overwrites).

mod support;

use serde_json::json;
use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

/// Assemble a source-package tarball: `lpm.config.json` at the root
/// (which makes `lpm add` treat the package as a source delivery) plus
/// any extra source files. The shape mirrors what `make_tarball_from_pkg_json`
/// expects — package.json gets a minimal stub, and `extra_files` carries
/// the lpm.config.json + source files at `package/{path}` inside the
/// tarball.
fn make_source_pkg_tarball(
    name: &str,
    version: &str,
    lpm_config: serde_json::Value,
    source_files: &[(&str, &[u8])],
) -> Vec<u8> {
    let pkg_json = json!({
        "name": name,
        "version": version,
        "main": "index.js",
    });
    let lpm_config_bytes = serde_json::to_vec_pretty(&lpm_config).unwrap();

    // Carry the lpm.config.json AND every source file into `extra_files`.
    // Owned strings keep the borrow happy across the call.
    let mut extras: Vec<(String, Vec<u8>)> = Vec::new();
    extras.push(("lpm.config.json".to_string(), lpm_config_bytes));
    for (rel, bytes) in source_files {
        extras.push(((*rel).to_string(), bytes.to_vec()));
    }
    let extras_borrowed: Vec<(&str, &[u8])> = extras
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();

    make_tarball_from_pkg_json(pkg_json, &extras_borrowed)
}

// ─── Test 1: happy path ─────────────────────────────────────────────

#[tokio::test]
async fn lpm_add_with_mixed_registry_deps_installs_and_writes_resolved_specs() {
    // Source package declares one bare name (resolves to `^latest` via
    // the registry) and one explicitly-pinned range (preserved
    // verbatim). The trailing `lpm install` actually runs against the
    // mock and links node_modules — proves the wiring all the way
    // through, not just the dep-collection layer.
    let mock = MockRegistry::start().await;

    // Source package: ships an lpm.config.json declaring deps under a
    // boolean conditional, plus a single source file. The consumer
    // pre-answers the conditional via the `?withTests=true` inline
    // spec so the dep map fires deterministically (no reliance on
    // schema-default coercion under `--yes`).
    let lpm_config = json!({
        "ecosystem": "js",
        "configSchema": {
            "withTests": { "type": "boolean" }
        },
        "dependencies": {
            "withTests": {
                "true": [
                    "lucide-react",                  // bare → caret-resolved
                    "lodash@4.17.21"                 // explicit Exact, preserved
                ]
            }
        },
        "files": [
            { "src": "Foo.tsx" }
        ]
    });
    let foo_tsx_bytes = b"export const Foo = () => null;\n";
    let source_tarball = make_source_pkg_tarball(
        "source-pkg",
        "1.0.0",
        lpm_config,
        &[("Foo.tsx", foo_tsx_bytes)],
    );
    mock.with_package("source-pkg", "1.0.0", &source_tarball)
        .await;

    // Dep packages — lucide-react gets caret-resolved, lodash is pinned.
    // Both need real tarballs so the install step can materialize
    // node_modules.
    let lucide_tarball =
        make_tarball_from_pkg_json(json!({ "name": "lucide-react", "version": "0.400.0" }), &[]);
    mock.with_package("lucide-react", "0.400.0", &lucide_tarball)
        .await;

    let lodash_tarball =
        make_tarball_from_pkg_json(json!({ "name": "lodash", "version": "4.17.21" }), &[]);
    mock.with_package("lodash", "4.17.21", &lodash_tarball)
        .await;

    // Batch-metadata for the install pipeline. Includes both deps so
    // the resolver gets everything in one round-trip.
    let batch_meta = vec![
        json!({
            "name": "lucide-react",
            "dist-tags": { "latest": "0.400.0" },
            "versions": {
                "0.400.0": {
                    "name": "lucide-react",
                    "version": "0.400.0",
                    "dist": {
                        "tarball": format!("{}/tarballs/lucide-react-0.400.0.tgz", mock.url()),
                        "integrity": "sha512-placeholder",
                    },
                    "dependencies": {}
                }
            },
            "time": { "0.400.0": "2025-01-01T00:00:00.000Z" }
        }),
        json!({
            "name": "lodash",
            "dist-tags": { "latest": "4.17.21" },
            "versions": {
                "4.17.21": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "dist": {
                        "tarball": format!("{}/tarballs/lodash-4.17.21.tgz", mock.url()),
                        "integrity": "sha512-placeholder",
                    },
                    "dependencies": {}
                }
            },
            "time": { "4.17.21": "2025-01-01T00:00:00.000Z" }
        }),
    ];
    mock.with_batch_metadata(batch_meta).await;

    let project =
        TempProject::empty(r#"{"name":"add-happy-path","version":"1.0.0","dependencies":{}}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "source-pkg?withTests=true",
            "--yes",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "lpm add failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Source file copied to the default install dir. `lpm add` picks
    // `components/` as the default install dir for a JS project with
    // no framework hints; the source's `files[0].src = "components/Foo.tsx"`
    // gets stripped of the leading `components/` (the install dir
    // already IS `components/`) and lands at `components/Foo.tsx`.
    assert!(
        project.file_exists("components/Foo.tsx"),
        "source file must be copied; stderr: {stderr}"
    );

    // package.json now has resolved specs. `lucide-react` got the
    // caret-resolved range, `lodash` preserved its explicit Exact.
    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    let deps = pkg_json
        .get("dependencies")
        .and_then(|v| v.as_object())
        .expect("dependencies object should exist");
    assert_eq!(
        deps.get("lucide-react").and_then(|v| v.as_str()),
        Some("^0.400.0"),
        "bare names must caret-resolve via the registry; got {deps:?}"
    );
    assert_eq!(
        deps.get("lodash").and_then(|v| v.as_str()),
        Some("4.17.21"),
        "explicit Exact specs must be preserved verbatim; got {deps:?}"
    );
}

// ─── Test 2: #9.4 preflight ─────────────────────────────────────────

#[tokio::test]
async fn lpm_add_preflight_blocks_deps_source_with_no_consumer_manifest() {
    let mock = MockRegistry::start().await;

    let lpm_config = json!({
        "ecosystem": "js",
        "configSchema": {
            "withTests": { "type": "boolean" }
        },
        "dependencies": {
            "withTests": { "true": ["lucide-react"] }
        },
        "files": [
            { "src": "Bar.tsx" }
        ]
    });
    let bar_tsx_bytes = b"export const Bar = () => null;\n";
    let source_tarball = make_source_pkg_tarball(
        "needs-deps",
        "1.0.0",
        lpm_config,
        &[("Bar.tsx", bar_tsx_bytes)],
    );
    mock.with_package("needs-deps", "1.0.0", &source_tarball)
        .await;

    // Project with NO package.json — empty TempDir.
    let project = TempProject::empty("");
    std::fs::remove_file(project.path().join("package.json")).ok();
    assert!(
        !project.file_exists("package.json"),
        "test sentinel: project must start with no manifest"
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "needs-deps?withTests=true",
            "--yes",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "preflight must hard-error; stdout: {stdout}\nstderr: {stderr}"
    );

    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("lpm init") || combined.contains("npm init"),
        "error must point at `lpm init` / `npm init -y`; got: {combined}"
    );
    assert!(
        combined.contains("--no-install-deps"),
        "error must surface the --no-install-deps escape hatch; got: {combined}"
    );

    // Critical: NO source-file copy happened. The preflight runs
    // before Step 8, so a failed run leaves the project pristine.
    assert!(
        !project.file_exists("components/Bar.tsx"),
        "preflight must run BEFORE source-file copy; the failure path \
         must not copy anything"
    );
    // No package.json materialized either (we don't auto-init, per the
    // option-(a) call-out in the #9.4 narrative).
    assert!(
        !project.file_exists("package.json"),
        "preflight failure must not auto-create a manifest"
    );
}

// ─── Test 3: #9.2 + #9.3 rollback ───────────────────────────────────

#[tokio::test]
async fn lpm_add_rollback_restores_manifest_and_source_files_on_install_failure() {
    // Setup: source pkg declares an Exact-pinned dep whose tarball
    // path is NOT mounted on the mock. The Exact intent skips
    // `lpm add`'s pre-resolve at #9.1 (verbatim preservation), so
    // resolution succeeds at the metadata layer; the trailing install
    // then 404s on the tarball download, fails, and the
    // ManifestTransaction Drops uncommitted — rolling back the
    // package.json mutation AND the source-file copies from Step 8.
    let mock = MockRegistry::start().await;

    let lpm_config = json!({
        "ecosystem": "js",
        "configSchema": {
            "withTests": { "type": "boolean" }
        },
        "dependencies": {
            "withTests": { "true": ["unfetchable@1.0.0"] }
        },
        "files": [
            { "src": "Baz.tsx" }
        ]
    });
    let baz_tsx_bytes = b"export const Baz = () => null;\n";
    let source_tarball = make_source_pkg_tarball(
        "rollback-pkg",
        "1.0.0",
        lpm_config,
        &[("Baz.tsx", baz_tsx_bytes)],
    );
    mock.with_package("rollback-pkg", "1.0.0", &source_tarball)
        .await;

    // Mount METADATA for `unfetchable@1.0.0` but NOT a tarball at
    // the path the metadata advertises. The install pipeline will
    // 404 on download → error → rollback.
    let unfetchable_meta = json!({
        "name": "unfetchable",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "unfetchable",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/tarballs/unfetchable-1.0.0.tgz", mock.url()),
                    "integrity": "sha512-placeholder",
                },
                "dependencies": {}
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    mock.with_batch_metadata(vec![unfetchable_meta]).await;
    // Intentionally NO `mock.with_package("unfetchable", ...)` call —
    // that'd mount the tarball.

    let original_manifest =
        r#"{"name":"add-rollback","version":"1.0.0","dependencies":{}}"#.to_string();
    let project = TempProject::empty(&original_manifest);
    let original_manifest_bytes = std::fs::read(project.path().join("package.json")).unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "rollback-pkg?withTests=true",
            "--yes",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "trailing install must fail (mocked-tarball-404) and propagate \
         up so the tx drops; stdout: {stdout}\nstderr: {stderr}"
    );

    // **Manifest rolled back.** Bytes match what was on disk before.
    let post_manifest_bytes = std::fs::read(project.path().join("package.json")).unwrap();
    assert_eq!(
        post_manifest_bytes,
        original_manifest_bytes,
        "package.json must be byte-identical to its pre-`lpm add` state \
         after the rollback; got: {}",
        String::from_utf8_lossy(&post_manifest_bytes)
    );

    // **Source files rolled back.** Baz.tsx was a NEW file (didn't
    // exist before); the rollback should have deleted it. This is the
    // #9.3 property — ManifestTransaction extends to source-file
    // copies, not just manifests + lockfiles.
    assert!(
        !project.file_exists("components/Baz.tsx"),
        "source file copied during the failed run must be deleted on \
         rollback (#9.3 contract)"
    );
}
