//! Composed workflow tests for `lpm add`.
//!
//! The unit tests in `crates/lpm-cli/src/commands/add/` cover the
//! helper-level contracts (collector dedup, save-spec decision logic,
//! preflight gate, canonical-pinning). These workflow tests exercise the
//! real `lpm-rs` binary end-to-end against a mock registry.
//!
//! Three properties get composed coverage:
//!
//! 1. **Happy path**: a config-driven source package
//!    declaring a mix of bare names and `name@^range` specs ends with
//!    each entry written to `package.json` per the save
//!    policy — bare → `^resolvedLatest`, explicit range preserved
//!    verbatim — and the source files copied into the project.
//!
//! 2. **Preflight**: a deps-declaring source package against a
//!    project with no `package.json` exits non-zero with a remediation
//!    hint pointing at `lpm init` / `npm init -y`, and crucially does
//!    NOT copy any source files (no source-file copy side effects on the
//!    failure path).
//!
//! 3. **Rollback**: a deps-declaring source package
//!    where the trailing install fails leaves `package.json` byte-
//!    identical to its pre-`lpm add` state and the source-file dest
//!    paths absent (or restored, for overwrites).

mod support;

use serde_json::json;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{
    LOCK_CONTENTION_MARKER_ENV, TempProject, lpm_spawnable_with_registry, lpm_with_registry,
    wait_for_lock_contention, write_lpm_proxy_npmrc, write_npm_firewall_global_config,
};

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

fn iso8601_n_secs_ago(n_secs: i64) -> String {
    use chrono::SecondsFormat;
    let dt = chrono::Utc::now() - chrono::Duration::seconds(n_secs);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

async fn mount_release_age_source_package(
    mock: &MockRegistry,
    package_name: &str,
    dependency_spec: &str,
) {
    let source_tarball = make_source_pkg_tarball(
        package_name,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {
                "withDependency": { "type": "boolean" }
            },
            "dependencies": {
                "withDependency": {
                    "true": [dependency_spec]
                }
            },
            "files": [
                { "src": "ReleaseAge.jsx" }
            ]
        }),
        &[("ReleaseAge.jsx", b"export const ReleaseAge = () => null;\n")],
    );
    mock.with_package(package_name, "1.0.0", &source_tarball)
        .await;
}

async fn mount_release_age_source_dependency(mock: &MockRegistry) {
    let mature_tarball = make_tarball_from_pkg_json(
        json!({ "name": "release-age-source-dep", "version": "1.0.0" }),
        &[],
    );
    let fresh_tarball = make_tarball_from_pkg_json(
        json!({ "name": "release-age-source-dep", "version": "1.1.0" }),
        &[],
    );
    let metadata = json!({
        "name": "release-age-source-dep",
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.0.0": {
                "name": "release-age-source-dep",
                "version": "1.0.0",
                "dist": {
                    "tarball": mock.tarball_url("release-age-source-dep", "1.0.0"),
                    "integrity": compute_integrity(&mature_tarball),
                },
                "dependencies": {}
            },
            "1.1.0": {
                "name": "release-age-source-dep",
                "version": "1.1.0",
                "dist": {
                    "tarball": mock.tarball_url("release-age-source-dep", "1.1.0"),
                    "integrity": compute_integrity(&fresh_tarball),
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.1.0": iso8601_n_secs_ago(3_600)
        }
    });
    mock.with_package_metadata_and_tarballs(
        "release-age-source-dep",
        metadata,
        &[("1.0.0", mature_tarball), ("1.1.0", fresh_tarball)],
    )
    .await;
}

#[tokio::test]
async fn add_rewrites_imports_relative_to_the_detected_alias_mapping_base() {
    let mock = MockRegistry::start().await;
    let package = "mapped-buyer-alias-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "importAlias": "@/",
            "files": [{"src": "Button.ts"}, {"src": "util.ts"}]
        }),
        &[
            (
                "Button.ts",
                b"import { util } from '@/util';\nexport { util };\n",
            ),
            ("util.ts", b"export const util = true;\n"),
        ],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file(
        "tsconfig.json",
        r#"{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}"#,
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--path",
            "src/components",
            "--yes",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .success();

    assert!(
        project
            .read_file("src/components/Button.ts")
            .contains("from '@/components/util'")
    );
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
    assert!(
        stderr.contains("› Downloading source package source-pkg@1.0.0")
            && stderr.contains("› Detecting project structure")
            && stderr.contains("Framework:")
            && stderr.contains("Install path:")
            && stderr.contains("✓ Files copied")
            && stderr.contains("+ Foo.tsx")
            && stderr.contains("› Installing declared dependencies")
            && stderr.contains("+ lucide-react@^0.400.0")
            && stderr.contains("+ lodash@4.17.21")
            && stderr.contains("✓ Done · added 1 file and 2 dependencies in"),
        "lpm add human output should follow the slim contract; stderr:\n{stderr}"
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
async fn lpm_add_bare_source_dependency_selects_latest_mature_version() {
    let mock = MockRegistry::start().await;
    mount_release_age_source_package(&mock, "release-age-source-pkg", "release-age-source-dep")
        .await;
    mount_release_age_source_dependency(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "add-release-age-fallback",
            "version": "1.0.0",
            "dependencies": {},
            "lpm": { "minimumReleaseAge": 86400 }
        }"#,
    );
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "release-age-source-pkg?withDependency=true",
            "--yes",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run release-age-aware lpm add");

    assert!(
        output.status.success(),
        "bare source dependency should select the latest mature version; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        manifest["dependencies"]["release-age-source-dep"],
        json!("^1.0.0")
    );
    let installed: serde_json::Value = serde_json::from_str(
        &project.read_file("node_modules/release-age-source-dep/package.json"),
    )
    .unwrap();
    assert_eq!(installed["version"], json!("1.0.0"));
}

#[tokio::test]
async fn lpm_add_explicit_source_range_does_not_select_version_below_its_lower_bound() {
    let mock = MockRegistry::start().await;
    mount_release_age_source_package(
        &mock,
        "explicit-release-age-source-pkg",
        "release-age-source-dep@^1.1.0",
    )
    .await;
    mount_release_age_source_dependency(&mock).await;

    let original_manifest = r#"{
        "name": "add-explicit-release-age",
        "version": "1.0.0",
        "dependencies": {},
        "lpm": { "minimumReleaseAge": 86400 }
    }"#;
    let project = TempProject::empty(original_manifest);
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "explicit-release-age-source-pkg?withDependency=true",
            "--yes",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run explicit-range lpm add");

    assert!(
        !output.status.success(),
        "explicit ^1.1.0 must not fall back to mature 1.0.0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("release-age-source-dep@^1.1.0")
            && stderr.contains("published too recently"),
        "explicit range failure must report the unchanged range and release-age block:\n{stderr}"
    );
    assert_eq!(project.read_file("package.json"), original_manifest);
}

#[tokio::test]
async fn lpm_add_firewall_enforce_blocks_source_package_before_tarball_fetch() {
    let mock = MockRegistry::start().await;
    let source_tarball = make_tarball_from_pkg_json(
        json!({
            "name": "blocked-source",
            "version": "1.0.0",
        }),
        &[],
    );
    mock.with_package("blocked-source", "1.0.0", &source_tarball)
        .await;
    mock.with_npm_firewall_block("blocked-source", "1.0.0")
        .await;

    let project =
        TempProject::empty(r#"{"name":"add-firewall","version":"1.0.0","dependencies":{}}"#);
    write_lpm_proxy_npmrc(&project, &mock.url());
    write_npm_firewall_global_config(&project, "enforce");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "blocked-source",
            "--yes",
            "--path",
            "components",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm add with firewall enforce");

    assert!(
        !output.status.success(),
        "firewall enforce must block add source download:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined
            .contains("Downloading source package blocked-source@1.0.0 - 🔥 LPM Firewall active"),
        "firewall-active source download must show the badge; got:\n{combined}"
    );
    assert!(
        combined.contains("blocked by LPM npm firewall"),
        "error must name the firewall block; got:\n{combined}"
    );
    assert_eq!(
        mock.tarball_request_count("blocked-source", "1.0.0").await,
        0,
        "firewall block must happen before source tarball download"
    );
    assert!(
        !project.file_exists("components/package.json"),
        "blocked add must not copy source files"
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

// ─── Preflight ───────────────────────────────────────────────────────

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
    // No package.json materialized either; the command does not auto-init
    // a project from this failure path.
    assert!(
        !project.file_exists("package.json"),
        "preflight failure must not auto-create a manifest"
    );
}

// ─── Rollback ────────────────────────────────────────────────────────

#[tokio::test]
async fn lpm_add_rollback_restores_manifest_and_source_files_on_install_failure() {
    // Setup: source pkg declares an Exact-pinned dep whose tarball
    // path is NOT mounted on the mock. The Exact intent skips
    // `lpm add` preserves the exact dep spec here, so resolution succeeds
    // at the metadata layer; the trailing install then 404s on the
    // tarball download, fails, and the ManifestTransaction drops
    // uncommitted, rolling back the package.json mutation and source-file
    // copies.
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
    // exist before); the rollback should have deleted it. The transaction
    // covers source-file copies, not just manifests + lockfiles.
    assert!(
        !project.file_exists("components/Baz.tsx"),
        "source file copied during the failed run must be deleted on rollback"
    );
    assert!(
        !project.path().join("components").exists(),
        "failed add must remove directories it created"
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
/// requirement guard. The central slim error renderer owns wrapping,
/// so keep this focused on the semantic guard text.
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
        .filter(|n| !matches!(n.as_str(), "src" | ".lpm"))
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

#[tokio::test]
async fn add_rejects_source_selector_that_escapes_extraction() {
    let mock = MockRegistry::start().await;
    let tarball = make_source_pkg_tarball(
        "source-selector-escape",
        "1.0.0",
        json!({
            "ecosystem": "js",
            "files": [{"src": "../package.json", "dest": "stolen.json"}]
        }),
        &[("Safe.ts", b"export const safe = true;\n")],
    );
    mock.with_package("source-selector-escape", "1.0.0", &tarball)
        .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["add", "source-selector-escape", "--yes", "--no-skills"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!project.file_exists("components/stolen.json"));
}

#[tokio::test]
async fn add_rejects_package_without_integrity_metadata() {
    let mock = MockRegistry::start().await;
    let package = "missing-integrity-source";
    let tarball = make_simple_npm_tarball(package, "1.0.0");
    let metadata = json!({
        "name": package,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": package,
                "version": "1.0.0",
                "dist": {"tarball": mock.tarball_url(package, "1.0.0")}
            }
        },
        "time": {"1.0.0": "2025-01-01T00:00:00.000Z"}
    });
    mock.with_package_metadata(package, "1.0.0", &tarball, metadata)
        .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--path",
            "src/copied",
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("integrity"));
    assert!(!project.file_exists("src/copied/index.js"));
}

#[tokio::test]
async fn add_rejects_target_path_outside_project() {
    let mock = MockRegistry::start().await;
    let package = "outside-target-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Safe.ts"}]}),
        &[("Safe.ts", b"export const safe = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let outside_name = format!(
        "outside-target-source-{}",
        project.path().file_name().unwrap().to_string_lossy()
    );
    let outside = project.path().parent().unwrap().join(&outside_name);
    let outside_argument = format!("../{outside_name}");

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--path",
            &outside_argument,
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!outside.exists());
}

#[tokio::test]
async fn add_dry_run_rejects_destination_parent_reference() {
    let mock = MockRegistry::start().await;
    let package = "dry-run-traversal-source";
    let tarball = make_traversal_tarball(package, "1.0.0", "../../escaped.txt");
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--dry-run",
            "--json",
            "--path",
            "src/copied",
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
}

#[tokio::test]
async fn add_dry_run_rejects_an_existing_file_as_the_target_directory() {
    let mock = MockRegistry::start().await;
    let package = "dry-run-file-target-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("occupied", "not a directory\n");

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--path",
            "occupied",
            "--yes",
            "--dry-run",
            "--json",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .failure();

    assert_eq!(project.read_file("occupied"), "not a directory\n");
}

#[cfg(unix)]
#[tokio::test]
async fn add_dry_run_rejects_a_destination_link_outside_the_target_directory() {
    let mock = MockRegistry::start().await;
    let package = "dry-run-linked-parent-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "files": [{"src": "Source.ts", "dest": "linked/Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.path().join("target")).unwrap();
    std::fs::create_dir_all(project.path().join("elsewhere")).unwrap();
    std::os::unix::fs::symlink("../elsewhere", project.path().join("target/linked")).unwrap();

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--path",
            "target",
            "--yes",
            "--dry-run",
            "--json",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .failure();

    assert!(!project.file_exists("elsewhere/Source.ts"));
}

#[tokio::test]
async fn add_dry_run_no_install_deps_reports_zero_planned_dependencies() {
    let mock = MockRegistry::start().await;
    let package = "dry-run-no-deps-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
            "dependencies": {"enabled": {"true": ["dep@1.0.0"]}},
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--dry-run",
            "--json",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["dependencies_count"], 0);
}

#[tokio::test]
async fn add_dry_run_simple_package_reports_no_automatic_dependencies() {
    let mock = MockRegistry::start().await;
    let package = "dry-run-simple-source";
    let tarball = make_tarball_from_pkg_json(
        json!({
            "name": package,
            "version": "1.0.0",
            "dependencies": {"runtime-leaf": "1.0.0"}
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--dry-run",
            "--json",
            "--path",
            "src/copied",
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["dependencies_count"], 0);
}

#[tokio::test]
async fn add_dry_run_rejects_declared_dependencies_without_project_manifest() {
    let mock = MockRegistry::start().await;
    let package = "dry-run-needs-manifest";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
            "dependencies": {"enabled": {"true": ["runtime-leaf@1.0.0"]}},
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty("");
    std::fs::remove_file(project.path().join("package.json")).unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--dry-run",
            "--json",
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!project.file_exists("components/Source.ts"));
}

#[tokio::test]
async fn add_json_with_declared_dependency_emits_one_document() {
    let mock = MockRegistry::start().await;
    let package = "json-dependency-source";
    let dependency = "json-source-dependency";
    let source_tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
            "dependencies": {"enabled": {"true": [format!("{dependency}@1.0.0")] }},
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &source_tarball).await;
    let dep_tarball =
        make_tarball_from_pkg_json(json!({"name": dependency, "version": "1.0.0"}), &[]);
    let dep_metadata = mock.package_metadata(dependency, "1.0.0", &dep_tarball);
    mock.with_package(dependency, "1.0.0", &dep_tarball).await;
    mock.with_batch_metadata(vec![dep_metadata]).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--json",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("stdout must contain one JSON document: {error}"));
    assert_eq!(json["dependencies_installed"], 1);
}

#[tokio::test]
async fn add_noninteractive_required_config_without_default_fails() {
    let mock = MockRegistry::start().await;
    let package = "missing-required-config-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {"variant": {"type": "string", "required": true}},
            "files": [{"src": "Source.ts", "include": "when", "condition": {"variant": "a"}}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["add", package, "--json", "--no-skills"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("variant"),
        "unexpected output: {combined}"
    );
    assert!(!project.file_exists("components/Source.ts"));
}

#[tokio::test]
async fn add_rejects_inline_config_values_outside_the_package_schema_before_mutation() {
    let mock = MockRegistry::start().await;
    let package = "invalid-inline-config-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {
                "enabled": {"type": "boolean"},
                "variant": {"type": "select", "options": ["a", "b"]},
                "features": {"type": "select", "multiSelect": true, "options": ["x", "y"]}
            },
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;

    for query in [
        "enabled=maybe",
        "variant=unknown",
        "features=x,unknown",
        "undeclared=value",
    ] {
        let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
        lpm_with_registry(&project, &mock.url())
            .args([
                "add",
                &format!("{package}?{query}"),
                "--yes",
                "--no-install-deps",
                "--no-skills",
            ])
            .assert()
            .failure();
        assert!(!project.file_exists("components/Source.ts"));
        assert!(!project.file_exists(".lpm/added-sources.json"));
    }
}

#[tokio::test]
async fn add_noninteractive_optional_defaults_select_only_the_authored_outputs() {
    let mock = MockRegistry::start().await;
    let package = "optional-default-config-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {
                "variant": {"type": "select", "required": false, "options": ["a", "b"], "default": "a"}
            },
            "files": [
                {"src": "A.ts", "include": "when", "condition": {"variant": "a"}},
                {"src": "B.ts", "include": "when", "condition": {"variant": "b"}}
            ]
        }),
        &[
            ("A.ts", b"export const variant = 'a';\n"),
            ("B.ts", b"export const variant = 'b';\n"),
        ],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    lpm_with_registry(&project, &mock.url())
        .args(["add", package, "--yes", "--no-install-deps", "--no-skills"])
        .assert()
        .success();

    assert!(project.file_exists("components/A.ts"));
    assert!(!project.file_exists("components/B.ts"));
}

#[tokio::test]
async fn add_top_level_package_respects_minimum_release_age() {
    let mock = MockRegistry::start().await;
    let package = "release-age-top-level-source";
    let mature = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Version.ts"}]}),
        &[("Version.ts", b"export const version = 'mature';\n")],
    );
    let fresh = make_source_pkg_tarball(
        package,
        "1.1.0",
        json!({"ecosystem": "js", "files": [{"src": "Version.ts"}]}),
        &[("Version.ts", b"export const version = 'fresh';\n")],
    );
    let metadata = json!({
        "name": package,
        "dist-tags": {"latest": "1.1.0"},
        "versions": {
            "1.0.0": {"name": package, "version": "1.0.0", "dist": {"tarball": mock.tarball_url(package, "1.0.0"), "integrity": compute_integrity(&mature)}},
            "1.1.0": {"name": package, "version": "1.1.0", "dist": {"tarball": mock.tarball_url(package, "1.1.0"), "integrity": compute_integrity(&fresh)}}
        },
        "time": {
            "1.0.0": iso8601_n_secs_ago(3 * 86_400),
            "1.1.0": iso8601_n_secs_ago(3_600)
        }
    });
    mock.with_package_metadata_and_tarballs(
        package,
        metadata,
        &[("1.0.0", mature), ("1.1.0", fresh)],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"host","version":"1.0.0","lpm":{"minimumReleaseAge":86400}}"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["add", package, "--yes", "--no-skills"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        project.read_file("components/Version.ts"),
        "export const version = 'mature';\n"
    );
}

#[tokio::test]
async fn add_does_not_duplicate_dependency_declared_in_dev_dependencies() {
    let mock = MockRegistry::start().await;
    let package = "cross-section-source";
    let dependency = "cross-section-dependency";
    let source_tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
            "dependencies": {"enabled": {"true": [format!("{dependency}@1.0.0")] }},
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &source_tarball).await;
    let dep_tarball =
        make_tarball_from_pkg_json(json!({"name": dependency, "version": "1.0.0"}), &[]);
    let dep_metadata = mock.package_metadata(dependency, "1.0.0", &dep_tarball);
    mock.with_package(dependency, "1.0.0", &dep_tarball).await;
    mock.with_batch_metadata(vec![dep_metadata]).await;
    let project = TempProject::empty(&format!(
        r#"{{"name":"host","version":"1.0.0","dependencies":{{}},"devDependencies":{{"{dependency}":"1.0.0"}}}}"#
    ));

    let output = lpm_with_registry(&project, &mock.url())
        .args(["add", package, "--yes", "--no-skills", "--no-editor-setup"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(manifest["dependencies"].get(dependency).is_none());
    assert_eq!(manifest["devDependencies"][dependency], "1.0.0");
}

#[tokio::test]
async fn add_package_skill_fetch_failure_is_nonfatal_and_json_stays_valid() {
    let mock = MockRegistry::start().await;
    let package = "@lpm.dev/owner.widget";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Widget.ts"}]}),
        &[("Widget.ts", b"export const widget = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    mock.with_package_skills_error_for_version("owner.widget", "1.0.0", 500)
        .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["add", package, "--yes", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["success"], true);
    assert!(
        json["warnings"]
            .as_array()
            .is_some_and(|warnings| !warnings.is_empty())
    );
    assert!(project.file_exists("components/Widget.ts"));
}

#[tokio::test]
async fn add_records_installed_digest_and_original_backup_for_forced_overwrite() {
    use sha2::{Digest, Sha256};

    let mock = MockRegistry::start().await;
    let package = "overwrite-provenance-source";
    let installed = b"export const value = 'installed';\n";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", installed)],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("components/Source.ts", "original project bytes\n");

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--force",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .success();

    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let file = &state["packages"][package]["files"]["components/Source.ts"];
    assert_eq!(state["schema_version"], 2);
    assert_eq!(file["action"], "overwrite");
    assert_eq!(
        file["installed_digest"],
        format!("sha256-{}", hex::encode(Sha256::digest(installed)))
    );
    let backup_path = file["backup_path"].as_str().expect("overwrite backup path");
    assert_eq!(project.read_file(backup_path), "original project bytes\n");
    assert_eq!(
        file["backup_digest"],
        format!(
            "sha256-{}",
            hex::encode(Sha256::digest(b"original project bytes\n"))
        )
    );
}

#[tokio::test]
async fn add_repeat_after_installed_file_deletion_preserves_original_backup() {
    let mock = MockRegistry::start().await;
    let package = "missing-repeat-overwrite-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"export const installed = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("components/Source.ts", "original project bytes\n");

    for run in 0..2 {
        if run == 1 {
            std::fs::remove_file(project.path().join("components/Source.ts")).unwrap();
        }
        lpm_with_registry(&project, &mock.url())
            .args([
                "add",
                package,
                "--yes",
                "--force",
                "--no-install-deps",
                "--no-skills",
            ])
            .assert()
            .success();
    }

    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let file = &state["packages"][package]["files"]["components/Source.ts"];
    assert_eq!(file["action"], "overwrite");
    let backup_path = file["backup_path"].as_str().expect("overwrite backup path");
    assert_eq!(project.read_file(backup_path), "original project bytes\n");
}

#[tokio::test]
async fn add_new_version_replaces_unchanged_created_and_overwritten_outputs() {
    let mock = MockRegistry::start().await;
    let package = "managed-output-update-source";
    let first = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"export const version = 1;\n")],
    );
    let second = make_source_pkg_tarball(
        package,
        "2.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"export const version = 2;\n")],
    );
    mock.mount_full_package_metadata_routes(
        package,
        "2.0.0",
        &[
            ("1.0.0", json!({}), Some(first)),
            ("2.0.0", json!({}), Some(second)),
        ],
    )
    .await;
    let created_project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let overwritten_project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    overwritten_project.write_file("components/Source.ts", "original project bytes\n");

    lpm_with_registry(&created_project, &mock.url())
        .args([
            "add",
            &format!("{package}@1.0.0"),
            "--yes",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .success();
    lpm_with_registry(&overwritten_project, &mock.url())
        .args([
            "add",
            &format!("{package}@1.0.0"),
            "--yes",
            "--force",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .success();

    for project in [&created_project, &overwritten_project] {
        lpm_with_registry(project, &mock.url())
            .args([
                "add",
                &format!("{package}@2.0.0"),
                "--yes",
                "--no-install-deps",
                "--no-skills",
            ])
            .assert()
            .success();
        assert_eq!(
            project.read_file("components/Source.ts"),
            "export const version = 2;\n"
        );
    }

    let overwritten_state: serde_json::Value =
        serde_json::from_str(&overwritten_project.read_file(".lpm/added-sources.json")).unwrap();
    let overwritten_file = &overwritten_state["packages"][package]["files"]["components/Source.ts"];
    assert_eq!(overwritten_file["action"], "overwrite");
    let backup_path = overwritten_file["backup_path"]
        .as_str()
        .expect("overwrite backup path");
    assert_eq!(
        overwritten_project.read_file(backup_path),
        "original project bytes\n"
    );
}

#[tokio::test]
async fn add_new_version_restores_original_when_a_dropped_overwrite_is_missing() {
    let mock = MockRegistry::start().await;
    let package = "missing-dropped-overwrite-source";
    let first = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Old.ts"}]}),
        &[("Old.ts", b"export const installed = true;\n")],
    );
    let second = make_source_pkg_tarball(
        package,
        "2.0.0",
        json!({"ecosystem": "js", "files": [{"src": "New.ts"}]}),
        &[("New.ts", b"export const next = true;\n")],
    );
    mock.mount_full_package_metadata_routes(
        package,
        "2.0.0",
        &[
            ("1.0.0", json!({}), Some(first)),
            ("2.0.0", json!({}), Some(second)),
        ],
    )
    .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("components/Old.ts", "original project bytes\n");

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            &format!("{package}@1.0.0"),
            "--yes",
            "--force",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .success();
    let first_state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let backup_path = first_state["packages"][package]["files"]["components/Old.ts"]["backup_path"]
        .as_str()
        .unwrap()
        .to_string();
    std::fs::remove_file(project.path().join("components/Old.ts")).unwrap();

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            &format!("{package}@2.0.0"),
            "--yes",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .success();

    assert_eq!(
        project.read_file("components/Old.ts"),
        "original project bytes\n"
    );
    assert!(!project.file_exists(&backup_path));
    let final_state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    assert!(
        final_state["packages"][package]["files"]
            .get("components/Old.ts")
            .is_none()
    );
}

#[tokio::test]
async fn add_rejects_a_tampered_backup_before_restoring_a_dropped_overwrite() {
    let mock = MockRegistry::start().await;
    let package = "tampered-backup-source";
    let first = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Old.ts"}]}),
        &[("Old.ts", b"export const installed = true;\n")],
    );
    let second = make_source_pkg_tarball(
        package,
        "2.0.0",
        json!({"ecosystem": "js", "files": [{"src": "New.ts"}]}),
        &[("New.ts", b"export const next = true;\n")],
    );
    mock.mount_full_package_metadata_routes(
        package,
        "2.0.0",
        &[
            ("1.0.0", json!({}), Some(first)),
            ("2.0.0", json!({}), Some(second)),
        ],
    )
    .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("components/Old.ts", "original project bytes\n");

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            &format!("{package}@1.0.0"),
            "--yes",
            "--force",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .success();
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let backup_path = state["packages"][package]["files"]["components/Old.ts"]["backup_path"]
        .as_str()
        .unwrap()
        .to_string();
    project.write_file(&backup_path, "tampered backup bytes\n");

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            &format!("{package}@2.0.0"),
            "--yes",
            "--no-install-deps",
            "--no-skills",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("backup integrity"));

    assert_eq!(
        project.read_file("components/Old.ts"),
        "export const installed = true;\n"
    );
    assert_eq!(project.read_file(&backup_path), "tampered backup bytes\n");
    assert!(!project.file_exists("components/New.ts"));
}

#[tokio::test]
async fn add_new_version_removes_unchanged_outputs_dropped_by_the_package() {
    let mock = MockRegistry::start().await;
    let package = "versioned-output-source";
    let first = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Old.ts"}]}),
        &[("Old.ts", b"export const old = true;\n")],
    );
    let second = make_source_pkg_tarball(
        package,
        "2.0.0",
        json!({"ecosystem": "js", "files": [{"src": "New.ts"}]}),
        &[("New.ts", b"export const new = true;\n")],
    );
    let metadata = json!({
        "name": package,
        "dist-tags": {"latest": "2.0.0"},
        "versions": {
            "1.0.0": {"name": package, "version": "1.0.0", "dist": {"tarball": mock.tarball_url(package, "1.0.0"), "integrity": compute_integrity(&first)}},
            "2.0.0": {"name": package, "version": "2.0.0", "dist": {"tarball": mock.tarball_url(package, "2.0.0"), "integrity": compute_integrity(&second)}}
        }
    });
    mock.with_package_metadata_and_tarballs(
        package,
        metadata,
        &[("1.0.0", first), ("2.0.0", second)],
    )
    .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    for spec in [format!("{package}@1.0.0"), format!("{package}@2.0.0")] {
        lpm_with_registry(&project, &mock.url())
            .args(["add", &spec, "--yes", "--no-install-deps", "--no-skills"])
            .assert()
            .success();
    }

    assert!(!project.file_exists("components/Old.ts"));
    assert!(project.file_exists("components/New.ts"));
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let files = state["packages"][package]["files"].as_object().unwrap();
    assert!(!files.contains_key("components/Old.ts"));
    assert!(files.contains_key("components/New.ts"));
}

#[tokio::test]
async fn add_new_version_removes_unchanged_dependency_dropped_by_the_package() {
    let mock = MockRegistry::start().await;
    let package = "versioned-dependency-source";
    let dependency = "versioned-dependency-leaf";
    let first = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
            "dependencies": {"enabled": {"true": [format!("{dependency}@1.0.0")] }},
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    let second = make_source_pkg_tarball(
        package,
        "2.0.0",
        json!({
            "ecosystem": "js",
            "dependencies": {},
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    let source_metadata = mock
        .mount_full_package_metadata_routes(
            package,
            "2.0.0",
            &[
                ("1.0.0", json!({}), Some(first)),
                ("2.0.0", json!({}), Some(second)),
            ],
        )
        .await;
    let dependency_tarball =
        make_tarball_from_pkg_json(json!({"name": dependency, "version": "1.0.0"}), &[]);
    let dependency_metadata = mock.package_metadata(dependency, "1.0.0", &dependency_tarball);
    mock.with_package(dependency, "1.0.0", &dependency_tarball)
        .await;
    mock.with_batch_metadata(vec![source_metadata, dependency_metadata])
        .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    for spec in [format!("{package}@1.0.0"), format!("{package}@2.0.0")] {
        lpm_with_registry(&project, &mock.url())
            .args(["add", &spec, "--yes", "--no-skills", "--no-editor-setup"])
            .assert()
            .success();
    }

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(manifest["dependencies"].get(dependency).is_none());
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    assert!(
        state["packages"][package]["dependencies"]
            .get(dependency)
            .is_none()
    );
    assert!(!project.read_file("lpm.lock").contains(dependency));
}

#[tokio::test]
async fn add_new_version_updates_an_unchanged_dependency_owned_by_the_package() {
    let mock = MockRegistry::start().await;
    let package = "updated-dependency-source";
    let dependency = "updated-dependency-leaf";
    let source_tarball = |version: &str, dependency_version: &str| {
        make_source_pkg_tarball(
            package,
            version,
            json!({
                "ecosystem": "js",
                "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
                "dependencies": {"enabled": {"true": [format!("{dependency}@{dependency_version}")] }},
                "files": [{"src": "Source.ts"}]
            }),
            &[("Source.ts", b"export const source = true;\n")],
        )
    };
    let first = source_tarball("1.0.0", "1.0.0");
    let second = source_tarball("2.0.0", "2.0.0");
    let source_metadata = json!({
        "name": package,
        "dist-tags": {"latest": "2.0.0"},
        "versions": {
            "1.0.0": {"name": package, "version": "1.0.0", "dist": {"tarball": mock.tarball_url(package, "1.0.0"), "integrity": compute_integrity(&first)}},
            "2.0.0": {"name": package, "version": "2.0.0", "dist": {"tarball": mock.tarball_url(package, "2.0.0"), "integrity": compute_integrity(&second)}}
        }
    });
    mock.with_package_metadata_and_tarballs(
        package,
        source_metadata.clone(),
        &[("1.0.0", first), ("2.0.0", second)],
    )
    .await;
    let dependency_v1 =
        make_tarball_from_pkg_json(json!({"name": dependency, "version": "1.0.0"}), &[]);
    let dependency_v2 =
        make_tarball_from_pkg_json(json!({"name": dependency, "version": "2.0.0"}), &[]);
    let dependency_metadata = mock
        .mount_full_package_metadata_routes(
            dependency,
            "2.0.0",
            &[
                ("1.0.0", json!({}), Some(dependency_v1)),
                ("2.0.0", json!({}), Some(dependency_v2)),
            ],
        )
        .await;
    mock.with_batch_metadata(vec![source_metadata, dependency_metadata])
        .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    for spec in [format!("{package}@1.0.0"), format!("{package}@2.0.0")] {
        lpm_with_registry(&project, &mock.url())
            .args(["add", &spec, "--yes", "--no-skills", "--no-editor-setup"])
            .assert()
            .success();
    }

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(manifest["dependencies"][dependency], "2.0.0");
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let ownership = &state["packages"][package]["dependencies"][dependency];
    assert_eq!(ownership["spec"], "2.0.0");
    assert_eq!(ownership["inserted"], true);
    assert!(project.read_file("lpm.lock").contains("2.0.0"));
}

#[tokio::test]
async fn add_transfers_dependency_cleanup_ownership_until_the_last_source_drops_it() {
    let mock = MockRegistry::start().await;
    let first_package = "first-shared-dependency-source";
    let second_package = "second-shared-dependency-source";
    let dependency = "shared-dependency-leaf";
    let source_tarball = |package: &str, version: &str, include_dependency: bool| {
        let config = if include_dependency {
            json!({
                "ecosystem": "js",
                "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
                "dependencies": {"enabled": {"true": [format!("{dependency}@1.0.0")] }},
                "files": [{"src": "Source.ts", "dest": format!("{package}.ts")}]
            })
        } else {
            json!({
                "ecosystem": "js",
                "dependencies": {},
                "files": [{"src": "Source.ts", "dest": format!("{package}.ts")}]
            })
        };
        make_source_pkg_tarball(
            package,
            version,
            config,
            &[("Source.ts", b"export const source = true;\n")],
        )
    };

    let first_v1 = source_tarball(first_package, "1.0.0", true);
    let first_v2 = source_tarball(first_package, "2.0.0", false);
    let second_v1 = source_tarball(second_package, "1.0.0", true);
    let second_v2 = source_tarball(second_package, "2.0.0", false);
    let first_metadata = mock
        .mount_full_package_metadata_routes(
            first_package,
            "2.0.0",
            &[
                ("1.0.0", json!({}), Some(first_v1)),
                ("2.0.0", json!({}), Some(first_v2)),
            ],
        )
        .await;
    let second_metadata = mock
        .mount_full_package_metadata_routes(
            second_package,
            "2.0.0",
            &[
                ("1.0.0", json!({}), Some(second_v1)),
                ("2.0.0", json!({}), Some(second_v2)),
            ],
        )
        .await;
    let dependency_tarball =
        make_tarball_from_pkg_json(json!({"name": dependency, "version": "1.0.0"}), &[]);
    let dependency_metadata = mock
        .mount_full_package_metadata_routes(
            dependency,
            "1.0.0",
            &[("1.0.0", json!({}), Some(dependency_tarball))],
        )
        .await;
    mock.with_batch_metadata(vec![first_metadata, second_metadata, dependency_metadata])
        .await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    for spec in [
        format!("{first_package}@1.0.0"),
        format!("{second_package}@1.0.0"),
        format!("{first_package}@2.0.0"),
    ] {
        lpm_with_registry(&project, &mock.url())
            .args(["add", &spec, "--yes", "--no-skills", "--no-editor-setup"])
            .assert()
            .success();
    }

    let manifest_after_first_drop: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(
        manifest_after_first_drop["dependencies"][dependency],
        "1.0.0"
    );
    let state_after_first_drop: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    assert_eq!(
        state_after_first_drop["packages"][second_package]["dependencies"][dependency]["inserted"],
        true
    );

    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            &format!("{second_package}@2.0.0"),
            "--yes",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();

    let final_manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(final_manifest["dependencies"].get(dependency).is_none());
    assert!(!project.read_file("lpm.lock").contains(dependency));
}

#[tokio::test]
async fn add_records_dependency_requirement_and_insertion_ownership() {
    let mock = MockRegistry::start().await;
    let package = "dependency-provenance-source";
    let dependency = "dependency-provenance-leaf";
    let source_tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
            "dependencies": {"enabled": {"true": [format!("{dependency}@1.0.0")] }},
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &source_tarball).await;
    let dependency_tarball =
        make_tarball_from_pkg_json(json!({"name": dependency, "version": "1.0.0"}), &[]);
    let dependency_metadata = mock.package_metadata(dependency, "1.0.0", &dependency_tarball);
    mock.with_package(dependency, "1.0.0", &dependency_tarball)
        .await;
    mock.with_batch_metadata(vec![dependency_metadata]).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    lpm_with_registry(&project, &mock.url())
        .args(["add", package, "--yes", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();

    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let requirement = &state["packages"][package]["dependencies"][dependency];
    assert_eq!(requirement["spec"], "1.0.0");
    assert_eq!(requirement["section"], "dependencies");
    assert_eq!(requirement["inserted"], true);
}

#[tokio::test]
async fn add_repeat_preserves_dependency_insertion_ownership() {
    let mock = MockRegistry::start().await;
    let package = "repeat-dependency-owner";
    let dependency = "repeat-dependency-leaf";
    let source_tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "configSchema": {"enabled": {"type": "boolean", "required": true, "default": true}},
            "dependencies": {"enabled": {"true": [format!("{dependency}@1.0.0")] }},
            "files": [{"src": "Source.ts"}]
        }),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &source_tarball).await;
    let dependency_tarball =
        make_tarball_from_pkg_json(json!({"name": dependency, "version": "1.0.0"}), &[]);
    let dependency_metadata = mock.package_metadata(dependency, "1.0.0", &dependency_tarball);
    mock.with_package(dependency, "1.0.0", &dependency_tarball)
        .await;
    mock.with_batch_metadata(vec![dependency_metadata]).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{}}"#);

    for _ in 0..2 {
        lpm_with_registry(&project, &mock.url())
            .args(["add", package, "--yes", "--no-skills", "--no-editor-setup"])
            .assert()
            .success();
    }

    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    assert_eq!(
        state["packages"][package]["dependencies"][dependency]["inserted"],
        true
    );
}

#[tokio::test]
async fn add_waits_for_the_project_install_lock_before_mutating_source_state() {
    let mock = MockRegistry::start().await;
    let package = "add-lock-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let transaction_lock =
        lpm_common::acquire_exclusive_lock(lpm_common::project_install_lock(project.path()))
            .expect("hold the project install lock");
    let lock_path = lpm_common::project_install_lock(project.path());
    let marker_path = project.home().join("add-lock-contention");
    let mut command = lpm_spawnable_with_registry(&project, &mock.url());
    command.env(LOCK_CONTENTION_MARKER_ENV, &marker_path);
    command.args(["add", package, "--yes", "--no-install-deps", "--no-skills"]);
    let mut child = command.spawn().expect("spawn contending add");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    assert!(
        child.try_wait().expect("inspect contending add").is_none(),
        "add must wait while another transaction owns the project install lock"
    );
    assert!(!project.file_exists("components/Source.ts"));
    assert!(!project.file_exists(".lpm/added-sources.json"));
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish contending add");
    assert!(
        output.status.success(),
        "add failed after lock release\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn add_rejects_a_workspace_that_appears_while_waiting_for_the_lock() {
    let mock = MockRegistry::start().await;
    let package = "workspace-appeared-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let transaction_lock =
        lpm_common::acquire_exclusive_lock(lpm_common::project_install_lock(project.path()))
            .expect("hold the project install lock");
    let lock_path = lpm_common::project_install_lock(project.path());
    let marker_path = project.home().join("add-workspace-appeared");
    let mut command = lpm_spawnable_with_registry(&project, &mock.url());
    command.env(LOCK_CONTENTION_MARKER_ENV, &marker_path);
    command.args(["add", package, "--yes", "--no-install-deps", "--no-skills"]);
    let mut child = command.spawn().expect("spawn contending add");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    project.write_file(
        "package.json",
        r#"{"name":"host","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish contending add");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("appeared while waiting"));
    assert!(!project.file_exists("components/Source.ts"));
    assert!(!project.file_exists(".lpm/added-sources.json"));
}

#[tokio::test]
async fn add_refuses_a_forged_backup_path_before_deleting_outside_files() {
    let mock = MockRegistry::start().await;
    let package = "forged-backup-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"outside sentinel").unwrap();
    project.write_file(
        ".lpm/added-sources.json",
        &serde_json::to_string_pretty(&json!({
            "schema_version": 2,
            "packages": {
                package: {
                    "files": {
                        "components/Source.ts": {
                            "source": "Source.ts",
                            "installed_digest": "sha256-stale",
                            "action": "overwrite",
                            "backup_path": outside.path(),
                        }
                    }
                }
            }
        }))
        .unwrap(),
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--force",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(std::fs::read(outside.path()).unwrap(), b"outside sentinel");
    assert!(!project.file_exists("components/Source.ts"));
}

#[tokio::test]
async fn add_rejects_semantically_duplicate_destinations_before_copying() {
    let mock = MockRegistry::start().await;
    let package = "duplicate-destination-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "files": [
                {"src": "One.ts", "dest": "Alias.ts"},
                {"src": "Two.ts", "dest": "./Alias.ts"}
            ]
        }),
        &[
            ("One.ts", b"export const one = true;\n"),
            ("Two.ts", b"export const two = true;\n"),
        ],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--yes",
            "--force",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!project.file_exists("components/Alias.ts"));
}

#[tokio::test]
async fn add_reserves_project_lpm_state_namespace_from_source_delivery() {
    let mock = MockRegistry::start().await;
    let package = "reserved-state-destination-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "files": [{"src": "Payload.txt", "dest": ".lpm/managed.txt"}]
        }),
        &[("Payload.txt", b"package controlled")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--path",
            ".",
            "--yes",
            "--force",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!project.file_exists(".lpm/managed.txt"));
}

#[cfg(unix)]
#[tokio::test]
async fn add_reserves_project_lpm_state_namespace_through_a_symlink_alias() {
    let mock = MockRegistry::start().await;
    let package = "linked-reserved-state-destination-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({
            "ecosystem": "js",
            "files": [{"src": "Payload.txt", "dest": "state-link/managed.txt"}]
        }),
        &[("Payload.txt", b"package controlled")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
    std::os::unix::fs::symlink(".lpm", project.path().join("state-link")).unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            package,
            "--path",
            ".",
            "--yes",
            "--force",
            "--no-install-deps",
            "--no-skills",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!project.file_exists(".lpm/managed.txt"));
}

#[cfg(unix)]
#[tokio::test]
async fn add_refuses_a_linked_project_lpm_directory() {
    let mock = MockRegistry::start().await;
    let package = "linked-lpm-source";
    let tarball = make_source_pkg_tarball(
        package,
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"export const source = true;\n")],
    );
    mock.with_package(package, "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), project.path().join(".lpm")).unwrap();

    let output = lpm_with_registry(&project, &mock.url())
        .args(["add", package, "--yes", "--no-install-deps", "--no-skills"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!project.file_exists("components/Source.ts"));
    assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
}
