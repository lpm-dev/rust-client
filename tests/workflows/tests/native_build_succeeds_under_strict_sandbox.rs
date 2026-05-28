//! Native-rebuild positive control under Strict-sandbox.
//!
//! Pins the vcvarsall capture fix at the workflow tier. A
//! regression that drops the MSVC env injection or breaks the
//! vcvarsall parse fails this test deterministically (the
//! AppContainer'd `node-gyp rebuild` can't reach `cl.exe` /
//! `link.exe` / SDK headers without it).
//!
//! ## File naming
//!
//! This test was originally named
//! `install_native_package_succeeds_under_strict_sandbox`; we
//! dropped the leading `install_` to side-step Windows's Installer
//! Detection Technology heuristic, which auto-elevates any
//! executable whose name contains `install` / `setup` / `update`
//! and breaks `cargo test` on Windows hosts running under a
//! non-elevated shell. The behavior under test is unchanged.
//!
//! ## Gating
//!
//! The test soft-skips on every host except Windows with
//! `LPM_TEST_WINDOWS_TOOLCHAIN_AVAILABLE=1`. Reasons:
//!
//! - **Linux / macOS**: AppContainer is Windows-only; this test
//!   exercises the Windows backend specifically.
//! - **Windows without BuildTools**: vcvarsall isn't installed, so
//!   the capture would (correctly) fail and `node-gyp rebuild`
//!   wouldn't have the toolchain regardless. Skip is the honest
//!   outcome.
//! - **`LPM_TEST_WINDOWS_TOOLCHAIN_AVAILABLE` is the explicit
//!   opt-in** so CI can choose which Windows runners pay the cost
//!   of provisioning BuildTools.
//!
//! ## What this test pins
//!
//! 1. `node-gyp rebuild` runs INSIDE the AppContainer (Strict
//!    mode — no outbound network, but COM is also denied → the
//!    capture path is exercised end-to-end).
//! 2. The MSVC env from `vcvarsall.bat` reaches the child via the
//!    helper's `--env` argv plumbing.
//! 3. The synthetic `binding.gyp` build produces a
//!    `build/Release/*.node` output.
//!
//! Without the vcvarsall capture fix, the build fails at "cl.exe not found"
//! and the marker assertion below trips.

#![cfg(target_os = "windows")]

mod support;

use std::path::PathBuf;
use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry};

/// `package.json` for the synthetic native dep. Postinstall runs
/// `node-gyp rebuild` (the cross-platform native-build entry point
/// every native npm package uses).
const NATIVE_DEP_NAME: &str = "synthetic-native-build-under-strict";
const NATIVE_DEP_VERSION: &str = "1.0.0";

/// Minimal binding.gyp — a single C++ source compiled into a Node
/// addon. No actual Node binding (we don't load the .node file);
/// we only need the *.node output to prove the toolchain ran.
const BINDING_GYP: &str = r#"{
    "targets": [
        {
            "target_name": "lpm_native_smoke",
            "sources": [ "addon.cc" ]
        }
    ]
}
"#;

const ADDON_CC: &str = r#"
#include <stddef.h>
extern "C" {
    void lpm_helper_native_smoke_marker(void) {}
}
"#;

fn helper_available() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Some(target_profile) = exe.parent().and_then(|p| p.parent()) else {
        return false;
    };
    target_profile.join("lpm-sandbox-helper.exe").exists()
}

fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn toolchain_explicitly_enabled() -> bool {
    std::env::var("LPM_TEST_WINDOWS_TOOLCHAIN_AVAILABLE").is_ok_and(|v| v == "1")
}

/// `true` when the test runner opted in to hard-fail-on-skip for
/// the AppContainer / native-build paths via
/// `LPM_TEST_REQUIRE_APPCONTAINER=1`. Same shape + intent as the
/// sibling helper in `sandbox_network_denial.rs`.
fn require_appcontainer_coverage() -> bool {
    std::env::var("LPM_TEST_REQUIRE_APPCONTAINER").is_ok_and(|v| v == "1")
}

fn project_manifest() -> String {
    format!(
        r#"{{
    "name": "sandbox-native-build-fixture",
    "version": "1.0.0",
    "dependencies": {{
        "{NATIVE_DEP_NAME}": "^{NATIVE_DEP_VERSION}"
    }}
}}
"#
    )
}

fn build_native_tarball() -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": NATIVE_DEP_NAME,
        "version": NATIVE_DEP_VERSION,
        "scripts": {
            "postinstall": "node-gyp rebuild",
        }
    });
    make_tarball_from_pkg_json(
        pkg_json,
        &[
            ("binding.gyp", BINDING_GYP.as_bytes()),
            ("addon.cc", ADDON_CC.as_bytes()),
        ],
    )
}

async fn mount_native_dep(mock: &MockRegistry, tarball: &[u8]) {
    mock.with_package(NATIVE_DEP_NAME, NATIVE_DEP_VERSION, tarball)
        .await;
    let tarball_url = format!(
        "{}/tarballs/{NATIVE_DEP_NAME}/-/{NATIVE_DEP_NAME}-{NATIVE_DEP_VERSION}.tgz",
        mock.url()
    );
    let integrity = support::mock_registry::compute_integrity(tarball);
    let mut versions = serde_json::Map::new();
    versions.insert(
        NATIVE_DEP_VERSION.to_string(),
        serde_json::json!({
            "name": NATIVE_DEP_NAME,
            "version": NATIVE_DEP_VERSION,
            "dist": {
                "tarball": tarball_url,
                "integrity": integrity,
            },
            "dependencies": {}
        }),
    );
    let mut time = serde_json::Map::new();
    time.insert(
        NATIVE_DEP_VERSION.to_string(),
        serde_json::Value::String("2024-01-01T00:00:00.000Z".to_string()),
    );
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": NATIVE_DEP_NAME,
        "dist-tags": { "latest": NATIVE_DEP_VERSION },
        "versions": serde_json::Value::Object(versions),
        "time": serde_json::Value::Object(time),
    })])
    .await;
}

/// Path the build pipeline writes when a postinstall succeeds.
/// Absence proves the build failed; presence is one half of the
/// success contract (the other half is the `.node` output below).
fn lpm_built_marker(project: &TempProject) -> PathBuf {
    let safe = NATIVE_DEP_NAME.replace(['/', '\\'], "+");
    project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{NATIVE_DEP_VERSION}"))
        .join(".lpm-built")
}

#[tokio::test]
async fn native_rebuild_succeeds_under_appcontainer_strict_with_vcvarsall_capture() {
    if !node_available() {
        let msg = "node not on PATH (need node + node-gyp on PATH for this test)";
        if require_appcontainer_coverage() {
            panic!("LPM_TEST_REQUIRE_APPCONTAINER=1 is set, but {msg}");
        }
        eprintln!("skipping: {msg}");
        return;
    }
    if !helper_available() {
        let msg = "lpm-sandbox-helper.exe not built";
        if require_appcontainer_coverage() {
            panic!("LPM_TEST_REQUIRE_APPCONTAINER=1 is set, but {msg}");
        }
        eprintln!("skipping: {msg}");
        return;
    }
    if !toolchain_explicitly_enabled() {
        let msg = "LPM_TEST_WINDOWS_TOOLCHAIN_AVAILABLE not set to `1`. \
             This test needs a Windows host with Visual Studio / BuildTools \
             installed so vcvarsall.bat can render the MSVC env. CI runners \
             that provision BuildTools should set the env var explicitly \
             before running this test.";
        if require_appcontainer_coverage() {
            panic!("LPM_TEST_REQUIRE_APPCONTAINER=1 is set, but {msg}");
        }
        eprintln!("skipping: {msg}");
        return;
    }

    let mock = MockRegistry::start().await;
    let tarball = build_native_tarball();
    mount_native_dep(&mock, &tarball).await;

    let project = TempProject::empty(&project_manifest());

    let out = lpm_with_registry(&project, &mock.url())
        // `--policy=allow` bypasses the triage gate so the
        // postinstall runs unconditionally.
        .args(["install", "--policy=allow"])
        // Pin Strict mode so the AppContainer Default-deny posture
        // fires; the vcvarsall capture is the only way the child sees
        // an MSVC env under that posture (`vswhere`/COM is denied
        // inside the AppContainer).
        .env("LPM_STRICT_SANDBOX", "1")
        .output()
        .expect("spawn lpm install");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        out.status.success(),
        "install must succeed (soft-fail contract); status: {:?}\n\
         stdout:\n{stdout}\nstderr:\n{stderr}",
        out.status,
    );
    let marker = lpm_built_marker(&project);
    assert!(
        marker.exists(),
        "`.lpm-built` marker must be present after a successful native rebuild — \
         absence means `node-gyp rebuild` failed inside the AppContainer. \
         A common failure mode is missing MSVC env (regression in the vcvarsall capture: 
         vcvarsall capture). Marker path: {}\nstderr:\n{stderr}",
        marker.display(),
    );

    // The .node output proves cl.exe + link.exe actually ran with
    // the right INCLUDE/LIB env. Without the vcvarsall capture this
    // file isn't produced.
    let safe = NATIVE_DEP_NAME.replace(['/', '\\'], "+");
    let build_release = project
        .store_dir()
        .join("v1")
        .join(format!("{safe}@{NATIVE_DEP_VERSION}"))
        .join("build")
        .join("Release");
    let any_node = std::fs::read_dir(&build_release).is_ok_and(|it| {
        it.flatten().any(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("node"))
        })
    });
    assert!(
        any_node,
        "expected a `.node` artifact under {} after a successful node-gyp rebuild; \
         without one the MSVC toolchain didn't actually produce output. \
         stderr:\n{stderr}",
        build_release.display(),
    );
}
