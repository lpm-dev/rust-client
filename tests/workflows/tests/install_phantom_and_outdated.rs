//! Workflow tests for the install pipeline's source-import intelligence
//! and `+`-list outdated-version annotation.
//!
//! Pinned behaviors:
//!   * Phantom-dep scanner stops at nested `package.json` boundaries.
//!   * Phantom-dep scanner skips imports resolved by user-declared TS / JS
//!     path aliases (`tsconfig.json` `compilerOptions.paths`,
//!     `lpm.config.json` `importAlias`).
//!   * Phantom-dep `Fix:` suggestion stays `lpm install <pkg>` for real
//!     npm phantoms — only the false positives that triggered the
//!     nonsense suggestions get filtered out.
//!   * The post-install `+` list annotates a direct dep with
//!     `(vX.Y.Z available)` when the resolver's metadata cache has a
//!     newer stable release than the version that was installed.

mod support;

use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

// ─── Phantom scanner: nested package.json boundary ───────────────

#[tokio::test]
async fn phantom_scanner_stops_at_nested_package_json() {
    let mock = MockRegistry::start().await;

    // Root project declares `ms`. A nested `child/` has its own
    // package.json declaring `lodash`, with source files importing
    // `lodash`. The phantom scanner must NOT flag `lodash` against the
    // root's manifest — the child is its own package.
    let pkg_json_ms = serde_json::json!({
        "name": "ms",
        "version": "2.1.3",
        "main": "index.js"
    });
    let tarball = make_tarball_from_pkg_json(pkg_json_ms, &[]);
    mock.with_full_package_metadata(
        "ms",
        "2.1.3",
        &[("2.1.3", serde_json::json!({}), Some(tarball))],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "root-with-nested",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );

    // Nested child package — its imports must not pollute the parent.
    project.write_file(
        "child/package.json",
        r#"{"name":"child","version":"0.1.0"}"#,
    );
    project.write_file(
        "child/src/index.js",
        r#"import _ from "lodash";\nexport default _;\n"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install must succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("lodash") && !stdout.contains("lodash"),
        "phantom scanner must not cross into child/ package boundary — `lodash` is the child's, \
         not the root's:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("phantom dependency import"),
        "no phantoms should be reported for this project:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// ─── Phantom scanner: tsconfig path aliases skipped ──────────────

#[tokio::test]
async fn phantom_scanner_skips_tsconfig_path_aliases() {
    let mock = MockRegistry::start().await;
    let pkg_json_ms = serde_json::json!({
        "name": "ms",
        "version": "2.1.3",
        "main": "index.js"
    });
    let tarball = make_tarball_from_pkg_json(pkg_json_ms, &[]);
    mock.with_full_package_metadata(
        "ms",
        "2.1.3",
        &[("2.1.3", serde_json::json!({}), Some(tarball))],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "ts-alias-project",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );

    project.write_file(
        "tsconfig.json",
        r#"{
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {
                    "@/*": ["./*"],
                    "internal/*": ["./internal/*"]
                }
            }
        }"#,
    );

    project.write_file(
        "src/app.js",
        r#"
        import { Button } from "@/components/Button";
        import { Tools } from "internal/tools";
        import ms from "ms";
        "#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install must succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    // Neither alias should produce a bogus "Fix: lpm install @/components"
    // line — those alias prefixes are local files, not packages.
    assert!(
        !stdout.contains("lpm install @/components")
            && !stderr.contains("lpm install @/components"),
        "`@/components` is a TS path alias, never a package; phantom scanner \
         must not suggest `lpm install @/components`:\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("lpm install internal/tools")
            && !stderr.contains("lpm install internal/tools"),
        "`internal/tools` is a user-declared tsconfig alias, not a package:\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

// ─── Phantom scanner: real phantom still gets a Fix line ─────────

#[tokio::test]
async fn phantom_scanner_still_reports_real_phantoms_with_install_fix() {
    let mock = MockRegistry::start().await;
    let pkg_json_ms = serde_json::json!({
        "name": "ms",
        "version": "2.1.3",
        "main": "index.js"
    });
    let tarball = make_tarball_from_pkg_json(pkg_json_ms, &[]);
    mock.with_full_package_metadata(
        "ms",
        "2.1.3",
        &[("2.1.3", serde_json::json!({}), Some(tarball))],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "real-phantom",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );

    // `react` is imported but not declared — a real phantom.
    project.write_file(
        "src/index.js",
        r#"import React from "react";
           export default React;"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install must succeed (phantom is a warning, not an error):\nstdout: {stdout}\nstderr: {stderr}"
    );
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("phantom dependency import"),
        "real phantom (`react`) must be reported:\n{combined}"
    );
    assert!(
        combined.contains("lpm install react"),
        "Fix suggestion for a real npm-style phantom must read `lpm install react`:\n{combined}"
    );
}

// ─── + list: (vX.Y.Z available) annotation ───────────────────────

#[tokio::test]
async fn plus_list_annotates_outdated_direct_dep_with_latest_available() {
    let mock = MockRegistry::start().await;

    // Mount `lodash` with TWO versions: an older 1.0.0 (which our range
    // pins) and a newer 2.0.0 (the registry's `latest`). The `+` list
    // should annotate `+ lodash@1.0.0 (v2.0.0 available)`.
    let pkg_v1 = serde_json::json!({ "name": "lodash", "version": "1.0.0" });
    let pkg_v2 = serde_json::json!({ "name": "lodash", "version": "2.0.0" });
    let tar_v1 = make_tarball_from_pkg_json(pkg_v1, &[]);
    let tar_v2 = make_tarball_from_pkg_json(pkg_v2, &[]);

    mock.with_full_package_metadata(
        "lodash",
        "2.0.0",
        &[
            ("1.0.0", serde_json::json!({}), Some(tar_v1.clone())),
            ("2.0.0", serde_json::json!({}), Some(tar_v2.clone())),
        ],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "outdated-direct",
            "version": "1.0.0",
            "dependencies": { "lodash": "^1.0.0" }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install must succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("+ lodash") && combined.contains("(v2.0.0 available)"),
        "`+` list must annotate the older direct dep with the newer registry latest:\n{combined}"
    );
}

#[tokio::test]
async fn plus_list_omits_annotation_when_already_on_latest() {
    let mock = MockRegistry::start().await;

    let pkg = serde_json::json!({ "name": "ms", "version": "2.1.3" });
    let tarball = make_tarball_from_pkg_json(pkg, &[]);
    mock.with_full_package_metadata(
        "ms",
        "2.1.3",
        &[("2.1.3", serde_json::json!({}), Some(tarball))],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "on-latest",
            "version": "1.0.0",
            "dependencies": { "ms": "^2.1.3" }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install must succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("+ ms@2.1.3"),
        "`+` line for the direct dep must be present:\n{combined}"
    );
    assert!(
        !combined.contains("available)"),
        "no `(vX available)` hint when resolved version equals the registry's `latest`:\n{combined}"
    );
}

#[tokio::test]
async fn plus_list_omits_annotation_when_latest_is_prerelease() {
    let mock = MockRegistry::start().await;

    // Newest version in the registry is a pre-release. Stable users
    // shouldn't be nagged toward it.
    let pkg_stable = serde_json::json!({ "name": "react", "version": "1.0.0" });
    let pkg_pre = serde_json::json!({ "name": "react", "version": "2.0.0-rc.1" });
    let tar_stable = make_tarball_from_pkg_json(pkg_stable, &[]);
    let tar_pre = make_tarball_from_pkg_json(pkg_pre, &[]);

    mock.with_full_package_metadata(
        "react",
        "1.0.0",
        &[
            ("1.0.0", serde_json::json!({}), Some(tar_stable)),
            ("2.0.0-rc.1", serde_json::json!({}), Some(tar_pre)),
        ],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "pre-release-only-newer",
            "version": "1.0.0",
            "dependencies": { "react": "^1.0.0" }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "install must succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("+ react@1.0.0"),
        "`+ react@1.0.0` must appear:\n{combined}"
    );
    assert!(
        !combined.contains("available)"),
        "pre-release newest must not surface as `(vX available)`:\n{combined}"
    );
}
