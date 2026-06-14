mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};

struct FrameworkBinCase {
    label: &'static str,
    package_name: &'static str,
    bin_name: &'static str,
    script: &'static str,
}

const FRAMEWORK_BIN_CASES: &[FrameworkBinCase] = &[
    FrameworkBinCase {
        label: "next",
        package_name: "next",
        bin_name: "next",
        script: "next dev",
    },
    FrameworkBinCase {
        label: "vite",
        package_name: "vite",
        bin_name: "vite",
        script: "vite --host 127.0.0.1",
    },
    FrameworkBinCase {
        label: "astro",
        package_name: "astro",
        bin_name: "astro",
        script: "astro dev",
    },
    FrameworkBinCase {
        label: "webpack",
        package_name: "webpack-cli",
        bin_name: "webpack",
        script: "webpack serve",
    },
    FrameworkBinCase {
        label: "remix",
        package_name: "@remix-run/dev",
        bin_name: "remix",
        script: "remix dev",
    },
    FrameworkBinCase {
        label: "react-router",
        package_name: "@react-router/dev",
        bin_name: "react-router",
        script: "react-router dev",
    },
    FrameworkBinCase {
        label: "nuxt",
        package_name: "@nuxt/cli",
        bin_name: "nuxt",
        script: "nuxt dev",
    },
    FrameworkBinCase {
        label: "sveltekit",
        package_name: "@sveltejs/kit",
        bin_name: "svelte-kit",
        script: "svelte-kit dev",
    },
    FrameworkBinCase {
        label: "storybook",
        package_name: "storybook",
        bin_name: "storybook",
        script: "storybook dev",
    },
];

#[test]
fn dev_passes_selected_port_to_single_service_script() {
    let project = TempProject::empty(
        r#"{"name":"dev-port","version":"1.0.0","scripts":{"dev":"node check-port.js"}}"#,
    );
    project.write_file(
        "check-port.js",
        r#"
if (process.env.PORT !== '4567') {
  console.error(`expected PORT=4567, got ${process.env.PORT || '<unset>'}`);
  process.exit(42);
}
"#,
    );

    let output = lpm(&project)
        .args([
            "dev",
            "--no-install",
            "--no-open",
            "--no-dashboard",
            "--port",
            "4567",
        ])
        .output()
        .expect("failed to run lpm dev");

    assert!(
        output.status.success(),
        "lpm dev should pass the selected port into single-service scripts\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn dev_auto_compat_materializes_project_local_entrypoint_for_framework_bins() {
    for case in FRAMEWORK_BIN_CASES {
        let project = project_for_framework_case(case);
        let mock = MockRegistry::start().await;
        mount_framework_case(&mock, case).await;

        let output = lpm_with_registry(&project, &mock.url())
            .env("LPM_STORE_VERSION", "v2")
            .args(["dev", "--no-open", "--no-dashboard", "--port", "4567"])
            .output()
            .unwrap_or_else(|e| panic!("failed to run lpm dev for {}: {e}", case.label));

        assert!(
            output.status.success(),
            "lpm dev should auto-materialize compat for {} ({})\nstdout:\n{}\nstderr:\n{}",
            case.label,
            case.script,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        let compat_root = project
            .path()
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .canonicalize()
            .unwrap_or_else(|e| panic!("{} compat root should exist: {e}", case.label));
        let bin_real = project
            .path()
            .join("node_modules")
            .join(".bin")
            .join(case.bin_name)
            .canonicalize()
            .unwrap_or_else(|e| panic!("{} bin shim should resolve: {e}", case.label));
        assert!(
            bin_real.starts_with(&compat_root),
            "{} bin shim should execute from project-local compat, got {}",
            case.label,
            bin_real.display(),
        );
    }
}

#[tokio::test]
async fn dev_auto_compat_relinks_when_install_is_fresh_but_compat_is_missing() {
    let case = FRAMEWORK_BIN_CASES
        .iter()
        .find(|case| case.label == "webpack")
        .expect("webpack fixture should exist");
    let project = project_for_framework_case(case);
    let mock = MockRegistry::start().await;
    mount_framework_case(&mock, case).await;

    let first = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["dev", "--no-open", "--no-dashboard", "--port", "4567"])
        .output()
        .expect("failed to run initial lpm dev");
    assert!(
        first.status.success(),
        "initial lpm dev should create compat\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    std::fs::remove_dir_all(
        project
            .path()
            .join("node_modules")
            .join(".lpm")
            .join("compat"),
    )
    .expect("compat root should be removable");

    let second = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["dev", "--no-open", "--no-dashboard", "--port", "4567"])
        .output()
        .expect("failed to rerun lpm dev");
    assert!(
        second.status.success(),
        "lpm dev should relink compat even when the install hash is fresh\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
}

fn project_for_framework_case(case: &FrameworkBinCase) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name":"dev-compat-{label}",
            "version":"1.0.0",
            "scripts":{{"dev":{script:?}}},
            "dependencies":{{"{package_name}":"1.0.0"}}
        }}"#,
        label = case.label,
        script = case.script,
        package_name = case.package_name,
    ))
}

async fn mount_framework_case(mock: &MockRegistry, case: &FrameworkBinCase) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": "compat-helper",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": case.package_name,
            "version": "1.0.0",
            "bin": {
                case.bin_name: "bin/dev-tool.js"
            },
            "dependencies": {
                "compat-helper": "1.0.0"
            }
        }),
        &[("bin/dev-tool.js", framework_bin_script())],
    )
    .await;
}

fn framework_bin_script() -> &'static [u8] {
    br#"#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const project = fs.realpathSync(process.cwd());
const compatRoot = path.join(project, 'node_modules', '.lpm', 'compat') + path.sep;
const ownRealpath = fs.realpathSync(__filename);
if (!ownRealpath.startsWith(compatRoot)) {
  console.error(`entrypoint realpath outside compat: ${ownRealpath}`);
  process.exit(41);
}

const helperPackageJson = require.resolve('compat-helper/package.json');
const helperRealpath = fs.realpathSync(helperPackageJson);
if (!helperRealpath.startsWith(compatRoot)) {
  console.error(`helper realpath outside compat: ${helperRealpath}`);
  process.exit(42);
}

console.log(`compat-ok ${path.basename(process.argv[1])}`);
"#
}
