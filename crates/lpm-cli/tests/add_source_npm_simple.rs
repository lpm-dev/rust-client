//! Phase 60 end-to-end — `lpm add` simple-path source delivery from npm.
//!
//! Proves the full new-flow pipeline:
//! 1. `AddTarget::Npm` resolves correctly (no @lpm.dev rewrite).
//! 2. Routed metadata fetch via `RouteTable` (.npmrc registry).
//! 3. File-spool tarball download (Phase 60 D1) + integrity check.
//! 4. Extraction + `validate_extracted_paths` (extraction side).
//! 5. Simple path: `lpm.config.json` absent → no schema prompts,
//!    files copied verbatim under `target_dir`, no auto-nest.
//! 6. Bare-imports notice (D4) lists external imports.
//! 7. Dep gate (60.1): no auto-install, no `package.json` mutation.
//! 8. `--json` output includes `external_imports` array.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha512};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PACKAGE_NAME: &str = "phase60-simple-fixture";
const VERSION: &str = "1.0.0";

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn make_simple_tarball() -> Vec<u8> {
    // No lpm.config.json → forces the simple path.
    // Source files reference external bare imports so the bare-imports
    // notice has something to print.
    let mut builder = tar::Builder::new(Vec::new());

    let pkg_json = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": VERSION,
        "main": "index.js",
        // Note: dependencies present in the tarball's package.json
        // but the simple-path dep gate (60.1) must NOT auto-install
        // them.
        "dependencies": { "react": "^18.0.0" }
    });
    let pkg_bytes = serde_json::to_vec_pretty(&pkg_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(pkg_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &pkg_bytes[..]).unwrap();

    let index_js = br#"import { useState } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cn } from "./utils";
export const Foo = () => useState();
"#;
    let mut header = tar::Header::new_gnu();
    header.set_path("package/index.js").unwrap();
    header.set_size(index_js.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &index_js[..]).unwrap();

    let utils_js = b"export const cn = (...s) => s.join(' ');\n";
    let mut header = tar::Header::new_gnu();
    header.set_path("package/utils.js").unwrap();
    header.set_size(utils_js.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &utils_js[..]).unwrap();

    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

fn integrity(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    format!("sha512-{}", BASE64.encode(digest))
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-phase60-simple-e2e")
        .join(format!("{name}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "host", "version": "1.0.0", "dependencies": {} }"#,
    )
    .unwrap();
    dir
}

fn write_npmrc(dir: &Path, server_url: &str) {
    fs::write(dir.join(".npmrc"), format!("registry={server_url}/\n")).unwrap();
}

fn run_lpm_add(cwd: &Path, args: &[&str]) -> CommandOutput {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    fs::create_dir_all(&home).unwrap();

    let mut command = Command::new(exe);
    let mut full_args = vec!["add"];
    full_args.extend_from_slice(args);
    command
        .args(&full_args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env_remove("LPM_TOKEN")
        .env_remove("RUST_LOG")
        .env("LPM_REGISTRY_URL", "http://127.0.0.1:1");

    let output = command.output().expect("failed to spawn lpm-rs");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

async fn mount_npm_metadata_and_tarball(server: &MockServer, tarball: &[u8]) {
    let server_url = server.uri();
    let tarball_url = format!("{server_url}/{PACKAGE_NAME}/-/{PACKAGE_NAME}-{VERSION}.tgz");

    let metadata = serde_json::json!({
        "name": PACKAGE_NAME,
        "dist-tags": { "latest": VERSION },
        "versions": {
            VERSION: {
                "name": PACKAGE_NAME,
                "version": VERSION,
                "dist": {
                    "tarball": tarball_url,
                    "integrity": integrity(tarball),
                },
            }
        },
        "time": { VERSION: chrono::Utc::now().to_rfc3339() },
    });

    Mock::given(method("GET"))
        .and(path(format!("/{PACKAGE_NAME}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/{PACKAGE_NAME}/-/{PACKAGE_NAME}-{VERSION}.tgz"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/octet-stream")
                .set_body_bytes(tarball.to_vec()),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn simple_path_e2e_with_path_yes_no_install_deps() {
    let server = MockServer::start().await;
    let tarball = make_simple_tarball();
    mount_npm_metadata_and_tarball(&server, &tarball).await;

    let dir = project_dir("e2e_yes_no_install");
    write_npmrc(&dir, &server.uri());

    let out = run_lpm_add(
        &dir,
        &[
            PACKAGE_NAME,
            "--yes",
            "--path",
            "src/copied",
            "--no-install-deps",
            "--no-skills",
        ],
    );
    assert!(
        out.status.success(),
        "expected success\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // 1. Files copied directly under target — no auto-nest under
    //    package-name subdirectory (Phase 60 simple-path contract).
    assert!(
        dir.join("src/copied/index.js").exists(),
        "expected src/copied/index.js"
    );
    assert!(
        dir.join("src/copied/utils.js").exists(),
        "expected src/copied/utils.js"
    );
    assert!(
        !dir.join("src/copied").join(PACKAGE_NAME).exists(),
        "simple path must NOT auto-nest under package-name subdirectory"
    );

    // 2. Bare-imports notice surfaced. The actual specifiers depend on
    //    whether import rewriting altered the literal `"react"` /
    //    `"@radix-ui/react-slot"` strings (it doesn't — these are
    //    bare/external).
    assert!(
        out.stderr.contains("Source uses external imports")
            && out.stderr.contains("react")
            && out.stderr.contains("@radix-ui/react-slot"),
        "expected bare-imports notice listing react + @radix-ui/react-slot\nstderr:\n{}",
        out.stderr,
    );

    // 3. package.json NOT mutated — simple path doesn't auto-install
    //    the tarball's `dependencies`/`peerDependencies` (60.1 dep gate).
    let manifest = fs::read_to_string(dir.join("package.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let deps = parsed
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|o| o.len())
        .unwrap_or(0);
    assert_eq!(
        deps, 0,
        "simple path must not auto-install deps; got {deps} entries in dependencies"
    );

    // 4. .lpm/skills/ NOT created — npm packages don't get skills
    //    extracted (60.2 scope gate).
    assert!(
        !dir.join(".lpm").join("skills").exists(),
        "skills directory must not be created for non-@lpm.dev packages"
    );
}

#[tokio::test]
async fn simple_path_e2e_json_output_includes_external_imports() {
    let server = MockServer::start().await;
    let tarball = make_simple_tarball();
    mount_npm_metadata_and_tarball(&server, &tarball).await;

    let dir = project_dir("e2e_json_external");
    write_npmrc(&dir, &server.uri());

    let out = run_lpm_add(
        &dir,
        &[
            PACKAGE_NAME,
            "--json",
            "--path",
            "src/copied",
            "--no-install-deps",
            "--no-skills",
        ],
    );
    assert!(
        out.status.success(),
        "expected success\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // The JSON document goes to stdout. Parse it and assert the new
    // Phase 60 fields are present and well-shaped.
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "expected valid JSON on stdout, got: {e}\nstdout:\n{}",
            out.stdout
        )
    });
    assert_eq!(parsed["success"], serde_json::Value::Bool(true));

    // package.name is the npm-style identity, NOT the @lpm.dev/ form
    // (regression check for Phase 60.0.a — the JSON formerly always
    // used `name.scoped()` which would mis-render any non-LPM target).
    assert_eq!(
        parsed["package"]["name"].as_str(),
        Some(PACKAGE_NAME),
        "json package.name should be the verbatim npm spec, not @lpm.dev/-prefixed"
    );

    // external_imports array sorted, contains the bare specifiers.
    let externals = parsed["external_imports"]
        .as_array()
        .expect("external_imports must be an array");
    let names: Vec<&str> = externals.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        names.contains(&"react"),
        "expected 'react' in external_imports; got {names:?}"
    );
    assert!(
        names.contains(&"@radix-ui/react-slot"),
        "expected '@radix-ui/react-slot' in external_imports; got {names:?}"
    );
    // Relative imports MUST NOT appear.
    assert!(
        !names.contains(&"./utils"),
        "relative imports must not be in external_imports"
    );
}
