//! Composed workflow tests for `lpm add`.
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
//!    each entry written to `package.json` per the save
//!    policy — bare → `^resolvedLatest`, explicit range preserved
//!    verbatim — and the source files copied into the project.
//!
//! 2. **Preflight** (#9.4): a deps-declaring source package against a
//!    project with no `package.json` exits non-zero with a remediation
//!    hint pointing at `lpm init` / `npm init -y`, and crucially does
//!    NOT copy any source files (no source-file copy side effects on the
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
                        "tarball": format!("{}/tarballs/lucide-react/-/lucide-react-0.400.0.tgz", mock.url()),
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
                        "tarball": format!("{}/tarballs/lodash/-/lodash-4.17.21.tgz", mock.url()),
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

#[tokio::test]
async fn lpm_add_config_aware_pkg_ignores_declaration_file_imports_in_phantom_scan() {
    let mock = MockRegistry::start().await;

    let lpm_config = json!({
        "ecosystem": "js",
        "configSchema": {
            "styling": {
                "type": "select",
                "required": true,
                "options": ["panda"]
            }
        },
        "defaultConfig": {
            "styling": "panda"
        },
        "dependencies": {
            "styling": {
                "panda": ["kleur"]
            }
        },
        "files": [
            { "src": "components/dialog/Dialog.jsx", "dest": "dialog/Dialog.jsx" },
            { "src": "components/dialog/Dialog.d.ts", "dest": "dialog/Dialog.d.ts" },
            { "src": "components/dialog/index.js", "dest": "dialog/index.js" }
        ]
    });
    let dialog_jsx =
        b"export default function Dialog({ children }) {\n  return children ?? null;\n}\n";
    let dialog_dts = b"import { ReactNode } from \"react\";\nexport interface DialogProps {\n  children?: ReactNode;\n}\nexport default function Dialog(props: DialogProps): JSX.Element;\n";
    let index_js = b"export { default } from \"./Dialog\";\n";
    let source_tarball = make_source_pkg_tarball(
        "typed-config-pkg",
        "1.0.0",
        lpm_config,
        &[
            ("components/dialog/Dialog.jsx", dialog_jsx),
            ("components/dialog/Dialog.d.ts", dialog_dts),
            ("components/dialog/index.js", index_js),
        ],
    );
    mock.with_package("typed-config-pkg", "1.0.0", &source_tarball)
        .await;

    let kleur_tarball =
        make_tarball_from_pkg_json(json!({ "name": "kleur", "version": "4.1.5" }), &[]);
    mock.with_package("kleur", "4.1.5", &kleur_tarball).await;
    mock.with_batch_metadata(vec![json!({
        "name": "kleur",
        "dist-tags": { "latest": "4.1.5" },
        "versions": {
            "4.1.5": {
                "name": "kleur",
                "version": "4.1.5",
                "dist": {
                    "tarball": format!("{}/tarballs/kleur/-/kleur-4.1.5.tgz", mock.url()),
                    "integrity": "sha512-placeholder"
                },
                "dependencies": {}
            }
        },
        "time": { "4.1.5": "2025-01-01T00:00:00.000Z" }
    })])
    .await;

    let project =
        TempProject::empty(r#"{"name":"typed-config-host","version":"1.0.0","dependencies":{}}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "typed-config-pkg?styling=panda",
            "--yes",
            "--path",
            "components",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run config-aware lpm add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "config-aware lpm add failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        project.file_exists("components/dialog/Dialog.d.ts"),
        "typed declaration file must be copied; stderr: {stderr}"
    );
    assert!(
        !combined.contains("phantom dependency import"),
        "declaration-only imports must not trigger phantom warnings; output:\n{combined}"
    );

    let pkg_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    let deps = pkg_json
        .get("dependencies")
        .and_then(|v| v.as_object())
        .expect("dependencies object should exist");
    assert_eq!(
        deps.get("kleur").and_then(|v| v.as_str()),
        Some("^4.1.5"),
        "config-aware dependencies should still install normally; got {deps:?}"
    );
}

// ─── JSON envelope contract ────────────────────────

/// `lpm add --json` envelope shape locked via insta. Source-package add
/// with no declared deps so the envelope stays minimal — sub-fields
/// that vary across platforms (e.g. config-driven extras) are not in
/// scope for the no-config-no-deps base case.
#[tokio::test]
async fn lpm_add_json_envelope_with_simple_source_pkg_matches_snapshot() {
    let mock = MockRegistry::start().await;

    // Source pkg ships an lpm.config.json declaring zero deps + one file.
    // The envelope's `dependencies_installed` must be 0 and
    // `external_imports` must be [] — clean snapshot baseline.
    let lpm_config = serde_json::json!({
        "ecosystem": "js",
        "files": [{ "src": "Snap.tsx" }]
    });
    let snap_bytes = b"export const Snap = () => null;\n";
    let tarball = make_source_pkg_tarball(
        "snap-add-pkg",
        "1.0.0",
        lpm_config,
        &[("Snap.tsx", snap_bytes)],
    );
    mock.with_package("snap-add-pkg", "1.0.0", &tarball).await;

    let project = TempProject::empty(r#"{"name":"add-snap","version":"1.0.0","dependencies":{}}"#);

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "snap-add-pkg",
            "--json",
            "--yes",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("spawn lpm add --json");
    assert!(
        out.status.success(),
        "lpm add --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("add --json must be valid JSON: {e}"));

    insta::with_settings!({
        filters => vec![
            // Mock registry URL (dynamic port) → [REGISTRY]
            (r"http://127\.0\.0\.1:\d+", "[REGISTRY]"),
        ],
    }, {
        insta::assert_json_snapshot!("add_json_envelope_simple_source_pkg", envelope);
    });
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
    // before source-file copies, so a failed run leaves the project pristine.
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
    // package.json mutation AND the source-file copies.
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
                    "tarball": format!("{}/tarballs/unfetchable/-/unfetchable-1.0.0.tgz", mock.url()),
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

// ─── security + non-interactive + npm-simple paths ───
//
// Three behavior clusters migrated from cli/tests/:
// 1. Path-traversal containment (`--path ..`, `--path /abs`)
// 2. Non-interactive `--path` requirement (`--yes`, `--json`, no-TTY)
// 3. NPM simple-path source delivery (no `lpm.config.json`, bare imports)

use std::io::Write as _;

/// Build an npm tarball with a malicious `lpm.config.json` that asks
/// `lpm add` to write `src/evil.txt` to the supplied dest. The dest can
/// be a `..`-prefixed relative path or an absolute path — both must be
/// rejected by the destination-side containment check.
fn make_traversal_tarball(name: &str, version: &str, evil_dest: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let pkg_json = serde_json::json!({ "name": name, "version": version });
    let pkg_bytes = serde_json::to_vec_pretty(&pkg_json).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_path("package/package.json").unwrap();
    h.set_size(pkg_bytes.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &pkg_bytes[..]).unwrap();

    let lpm_config = serde_json::json!({
        "files": [{ "src": "src/evil.txt", "dest": evil_dest }]
    });
    let lpm_bytes = serde_json::to_vec_pretty(&lpm_config).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_path("package/lpm.config.json").unwrap();
    h.set_size(lpm_bytes.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &lpm_bytes[..]).unwrap();

    let evil_content = b"benign content but malicious dest\n";
    let mut h = tar::Header::new_gnu();
    h.set_path("package/src/evil.txt").unwrap();
    h.set_size(evil_content.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &evil_content[..]).unwrap();

    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

/// Build a minimal npm tarball with NO `lpm.config.json` — forces the
/// simple path inside `lpm add`.
fn make_simple_npm_tarball(name: &str, version: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let pkg = serde_json::json!({ "name": name, "version": version });
    let pkg_bytes = serde_json::to_vec_pretty(&pkg).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_path("package/package.json").unwrap();
    h.set_size(pkg_bytes.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &pkg_bytes[..]).unwrap();

    let index_js = b"export const x = 42;\n";
    let mut h = tar::Header::new_gnu();
    h.set_path("package/index.js").unwrap();
    h.set_size(index_js.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &index_js[..]).unwrap();

    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

/// Build an npm tarball with bare imports + a relative import for the
/// external-imports notice tests. No `lpm.config.json` (simple path).
fn make_npm_tarball_with_bare_imports(name: &str, version: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let pkg_json = serde_json::json!({
        "name": name,
        "version": version,
        "main": "index.js",
        // Tarball declares deps but the simple-path dep gate must NOT
        // auto-install them.
        "dependencies": { "react": "^18.0.0" }
    });
    let pkg_bytes = serde_json::to_vec_pretty(&pkg_json).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_path("package/package.json").unwrap();
    h.set_size(pkg_bytes.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &pkg_bytes[..]).unwrap();

    let index_js = br#"import { useState } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cn } from "./utils";
export const Foo = () => useState();
"#;
    let mut h = tar::Header::new_gnu();
    h.set_path("package/index.js").unwrap();
    h.set_size(index_js.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &index_js[..]).unwrap();

    let utils_js = b"export const cn = (...s) => s.join(' ');\n";
    let mut h = tar::Header::new_gnu();
    h.set_path("package/utils.js").unwrap();
    h.set_size(utils_js.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &utils_js[..]).unwrap();

    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

/// Top-level entries of `path` as a sorted set. Used by path-traversal
/// tests to detect side-effect directories the failed add might have
/// left behind.
fn snapshot_dir_entries(path: &std::path::Path) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(path)
        .map(|it| {
            it.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Assert the install output carries the non-interactive `--path`
/// requirement guard. miette wraps long error lines, so substring
/// fragments must be checked individually rather than against the
/// joined string.
fn assert_add_path_guard_error(out: &std::process::Output, scenario: &str) {
    assert!(
        !out.status.success(),
        "[{scenario}] expected non-zero exit; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("non-interactive mode") && combined.contains("lpm.config.json"),
        "[{scenario}] expected guard message; got:\n{combined}"
    );
}

// ─── Path-traversal containment ─────────────────────────────────────────

/// Tarball's `lpm.config.json` asks to write a file at `../../escaped/evil.txt`.
/// The destination-side containment check must reject up-front and leave
/// no escape directory on disk.
#[tokio::test]
async fn add_rejects_relative_dotdot_dest_and_creates_no_external_directory() {
    let pkg = "add-traversal-fixture-rel";
    let mock = MockRegistry::start().await;
    let tarball = make_traversal_tarball(pkg, "1.0.0", "../../escaped/evil.txt");
    mock.with_package(pkg, "1.0.0", &tarball).await;

    let project =
        TempProject::empty(r#"{"name":"add-traversal-rel","version":"1.0.0","dependencies":{}}"#);
    let entries_before = snapshot_dir_entries(project.path());

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            pkg,
            "--yes",
            "--path",
            "src/copied",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .expect("spawn lpm add");
    assert!(
        !out.status.success(),
        "expected non-zero exit on traversal; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("'..'") || combined.contains("parent-directory"),
        "expected lexical `..` reject; got:\n{combined}"
    );

    // No file at the would-be escape path AND no escape directory.
    assert!(
        !project.path().join("escaped").join("evil.txt").exists(),
        "containment failure: escaped file written"
    );
    assert!(
        !project.path().join("escaped").exists(),
        "containment failure: escape directory was created as a side-effect"
    );

    // Top-level entries unchanged modulo the legitimate `src/` from
    // `--path src/copied`.
    let entries_after = snapshot_dir_entries(project.path());
    let unexpected: Vec<_> = entries_after
        .difference(&entries_before)
        .filter(|n| n.as_str() != "src")
        .collect();
    assert!(
        unexpected.is_empty(),
        "unexpected new top-level entries during failed add: {unexpected:?}"
    );
}

/// Tarball's `lpm.config.json` asks to write at an absolute path
/// outside the project. `Path::join(absolute)` returns the absolute
/// path verbatim — must be rejected before any `mkdir`.
#[tokio::test]
async fn add_rejects_absolute_dest_and_creates_no_external_directory() {
    let pkg = "add-traversal-fixture-abs";
    let elsewhere = std::env::temp_dir().join(format!("lpm-add-abs-escape-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&elsewhere);
    let evil_dest_str = elsewhere.join("evil.txt").to_string_lossy().into_owned();

    let mock = MockRegistry::start().await;
    let tarball = make_traversal_tarball(pkg, "1.0.0", &evil_dest_str);
    mock.with_package(pkg, "1.0.0", &tarball).await;

    let project =
        TempProject::empty(r#"{"name":"add-traversal-abs","version":"1.0.0","dependencies":{}}"#);

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            pkg,
            "--yes",
            "--path",
            "src/copied",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .expect("spawn lpm add");
    assert!(
        !out.status.success(),
        "expected non-zero exit on absolute-dest traversal; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("absolute"),
        "expected lexical absolute-path reject; got:\n{combined}"
    );

    // External dir MUST NOT have been created.
    assert!(
        !elsewhere.exists(),
        "containment failure: absolute-dest mkdir leaked outside target — {} created",
        elsewhere.display()
    );
    let _ = std::fs::remove_dir_all(&elsewhere); // paranoia cleanup
}

// ─── Non-interactive `--path` guard ─────────────────────────────────────

/// `--yes` without `--path` against a no-`lpm.config.json` package must
/// hard-error. The interactive prompt path can't fire under `--yes`, so
/// the guard catches the dest ambiguity up-front. Manifest must be
/// untouched (guard fires before any mutation).
#[tokio::test]
async fn add_simple_yes_without_path_errors_and_does_not_mutate_manifest() {
    let pkg = "add-simple-no-path-yes";
    let mock = MockRegistry::start().await;
    mock.with_package(pkg, "1.0.0", &make_simple_npm_tarball(pkg, "1.0.0"))
        .await;

    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    let out = lpm_with_registry(&project, &mock.url())
        .args(["add", pkg, "--yes"])
        .output()
        .expect("spawn lpm add");
    assert_add_path_guard_error(&out, "--yes without --path");

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    let dep_count = manifest["dependencies"].as_object().map_or(0, |o| o.len());
    assert_eq!(
        dep_count, 0,
        "guard must fire BEFORE any package.json mutation; got {dep_count} deps"
    );
}

/// `--json` without `--path` against a no-`lpm.config.json` package
/// must hard-error too. JSON mode is non-interactive by definition, so
/// the same guard applies.
#[tokio::test]
async fn add_simple_json_without_path_errors_and_does_not_mutate_manifest() {
    let pkg = "add-simple-no-path-json";
    let mock = MockRegistry::start().await;
    mock.with_package(pkg, "1.0.0", &make_simple_npm_tarball(pkg, "1.0.0"))
        .await;

    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    let out = lpm_with_registry(&project, &mock.url())
        .args(["add", pkg, "--json"])
        .output()
        .expect("spawn lpm add");
    assert_add_path_guard_error(&out, "--json without --path");

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    let dep_count = manifest["dependencies"].as_object().map_or(0, |o| o.len());
    assert_eq!(dep_count, 0);
}

/// Bare invocation with closed stdin (non-TTY) without `--path` must
/// fail the same guard. Closes stdin via `Stdio::null()` so
/// `is_terminal()` returns false even when the runner inherits a TTY.
#[tokio::test]
async fn add_simple_no_tty_without_path_errors_and_does_not_mutate_manifest() {
    let pkg = "add-simple-no-path-notty";
    let mock = MockRegistry::start().await;
    mock.with_package(pkg, "1.0.0", &make_simple_npm_tarball(pkg, "1.0.0"))
        .await;

    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    let mut cmd = lpm_with_registry(&project, &mock.url());
    cmd.args(["add", pkg]);
    // Force non-TTY stdin so `is_terminal()` returns false in the child.
    let out = cmd.output().expect("spawn lpm add");
    assert_add_path_guard_error(&out, "non-TTY without --path");

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    let dep_count = manifest["dependencies"].as_object().map_or(0, |o| o.len());
    assert_eq!(dep_count, 0);
}

/// Sanity check: `--yes --path` does NOT trip the guard. Source files
/// land directly under the supplied path, with no auto-nest under a
/// package-name subdirectory (simple-path contract).
#[tokio::test]
async fn add_simple_yes_with_path_succeeds_and_copies_files_directly() {
    let pkg = "add-simple-with-path";
    let mock = MockRegistry::start().await;
    mock.with_package(pkg, "1.0.0", &make_simple_npm_tarball(pkg, "1.0.0"))
        .await;

    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            pkg,
            "--yes",
            "--path",
            "src/copied",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .success();

    assert!(
        project.file_exists("src/copied/index.js"),
        "expected src/copied/index.js"
    );
    assert!(
        !project.path().join("src/copied").join(pkg).exists(),
        "simple path must NOT auto-nest under package-name subdirectory"
    );
}

// ─── NPM simple-path source delivery (full pipeline) ────────────────────

/// Full simple-path pipeline against an npm package with bare imports:
/// files copied verbatim, bare-imports notice surfaces, manifest
/// untouched, no `.lpm/skills/` for non-`@lpm.dev/*` packages.
#[tokio::test]
async fn add_simple_npm_pkg_copies_files_and_surfaces_bare_imports() {
    let pkg = "add-npm-simple-e2e";
    let mock = MockRegistry::start().await;
    mock.with_package(
        pkg,
        "1.0.0",
        &make_npm_tarball_with_bare_imports(pkg, "1.0.0"),
    )
    .await;

    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            pkg,
            "--yes",
            "--path",
            "src/copied",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .expect("spawn lpm add");
    assert!(
        out.status.success(),
        "expected success; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // 1. Files copied directly under target — no auto-nest.
    assert!(project.file_exists("src/copied/index.js"));
    assert!(project.file_exists("src/copied/utils.js"));
    assert!(
        !project.path().join("src/copied").join(pkg).exists(),
        "simple path must NOT auto-nest under package-name subdirectory"
    );

    // 2. Bare-imports notice surfaced on stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Source uses external imports")
            && stderr.contains("react")
            && stderr.contains("@radix-ui/react-slot"),
        "expected bare-imports notice listing react + @radix-ui/react-slot; stderr:\n{stderr}"
    );

    // 3. package.json NOT mutated — simple path doesn't auto-install
    //    the tarball's `dependencies` (60.1 dep gate).
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    let dep_count = manifest["dependencies"].as_object().map_or(0, |o| o.len());
    assert_eq!(
        dep_count, 0,
        "simple path must not auto-install deps; got {dep_count} entries"
    );

    // 4. No `.lpm/skills/` — non-@lpm.dev packages don't get skills (60.2 scope gate).
    assert!(
        !project.path().join(".lpm").join("skills").exists(),
        "skills directory must not be created for non-@lpm.dev packages"
    );
}

/// `--json` envelope on the npm simple path includes `external_imports`
/// (sorted bare specifiers, relative imports excluded), and
/// `package.name` is the verbatim npm spec — NOT the @lpm.dev/-prefixed
/// form (regression check: previously the JSON always used
/// `name.scoped()`).
#[tokio::test]
async fn add_simple_npm_pkg_json_envelope_includes_external_imports_and_npm_name() {
    let pkg = "add-npm-simple-json";
    let mock = MockRegistry::start().await;
    mock.with_package(
        pkg,
        "1.0.0",
        &make_npm_tarball_with_bare_imports(pkg, "1.0.0"),
    )
    .await;

    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    let out = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            pkg,
            "--json",
            "--path",
            "src/copied",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .expect("spawn lpm add --json");
    assert!(
        out.status.success(),
        "expected success; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("expected valid JSON on stdout: {e}\nstdout:\n{stdout}"));

    assert_eq!(parsed["success"], serde_json::json!(true));
    assert_eq!(
        parsed["package"]["name"].as_str(),
        Some(pkg),
        "json package.name should be the verbatim npm spec, not @lpm.dev/-prefixed"
    );

    let externals: Vec<&str> = parsed["external_imports"]
        .as_array()
        .expect("external_imports must be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        externals.contains(&"react"),
        "expected 'react' in external_imports; got {externals:?}"
    );
    assert!(
        externals.contains(&"@radix-ui/react-slot"),
        "expected '@radix-ui/react-slot' in external_imports; got {externals:?}"
    );
    assert!(
        !externals.contains(&"./utils"),
        "relative imports must not appear in external_imports; got {externals:?}"
    );
}
