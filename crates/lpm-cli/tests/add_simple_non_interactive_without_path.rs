//! Phase 60.1.5 regression — non-interactive simple-path guard.
//!
//! `lpm add <pkg>` against a package without `lpm.config.json` (the
//! "simple path" — Phase 60's new arbitrary-npm flow) must REFUSE
//! when invoked non-interactively without `--path`. Heuristically
//! defaulting to `components/` for arbitrary 3rd-party source under
//! `--yes`/`--json`/non-TTY is a CI/automation footgun: there's no
//! human in the loop to confirm where the source landed.
//!
//! Three sub-cases:
//! 1. `--yes` without `--path` → error
//! 2. `--json` without `--path` → error
//! 3. non-TTY stdin (redirected from `/dev/null`) → error
//!
//! All three: assert exit code non-zero, no `package.json` mutation.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha512};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PACKAGE_NAME: &str = "phase60-simple-no-path-fixture";
const VERSION: &str = "1.0.0";

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn make_tarball() -> Vec<u8> {
    // Minimal source-shape package with NO lpm.config.json — forces
    // the simple path inside `lpm add`.
    let mut builder = tar::Builder::new(Vec::new());

    let pkg = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": VERSION,
    });
    let pkg_bytes = serde_json::to_vec_pretty(&pkg).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(pkg_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &pkg_bytes[..]).unwrap();

    let index_js = b"export const x = 42;\n";
    let mut header = tar::Header::new_gnu();
    header.set_path("package/index.js").unwrap();
    header.set_size(index_js.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &index_js[..]).unwrap();

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
        .join("lpm-phase60-simple-noninteractive")
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

/// Run `lpm-rs add <args>` in `cwd`. `force_no_tty` redirects stdin
/// from `/dev/null` so `IsTerminal::is_terminal` returns false even
/// when the test harness happens to inherit a TTY.
fn run_lpm_add(cwd: &Path, args: &[&str], force_no_tty: bool) -> CommandOutput {
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

    if force_no_tty {
        command.stdin(Stdio::null());
    }

    let output = command.output().expect("failed to spawn lpm-rs");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

async fn mount_npm_metadata_and_tarball(server: &MockServer) {
    let server_url = server.uri();
    let tarball = make_tarball();
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
                    "integrity": integrity(&tarball),
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
                .set_body_bytes(tarball.clone()),
        )
        .mount(server)
        .await;
}

fn assert_guard_error(out: &CommandOutput, scenario: &str) {
    assert!(
        !out.status.success(),
        "[{scenario}] expected non-zero exit, got {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        out.stdout,
        out.stderr,
    );
    let combined = format!("{}{}", out.stdout, out.stderr);
    // miette boxes errors across multiple lines, so substrings within
    // the message can be split. Check for fragments that survive the
    // line wrap rather than the joined string.
    assert!(
        combined.contains("non-interactive mode") && combined.contains("lpm.config.json"),
        "[{scenario}] expected guard message, got:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );
}

fn assert_package_json_unchanged(dir: &Path) {
    let manifest = fs::read_to_string(dir.join("package.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let deps = parsed
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|o| o.len())
        .unwrap_or(0);
    assert_eq!(
        deps, 0,
        "guard should fire BEFORE any package.json mutation; got {deps} deps"
    );
}

#[tokio::test]
async fn add_simple_path_yes_without_path_errors() {
    let server = MockServer::start().await;
    mount_npm_metadata_and_tarball(&server).await;

    let dir = project_dir("yes_no_path");
    write_npmrc(&dir, &server.uri());

    let out = run_lpm_add(&dir, &[PACKAGE_NAME, "--yes"], false);
    assert_guard_error(&out, "--yes without --path");
    assert_package_json_unchanged(&dir);
}

#[tokio::test]
async fn add_simple_path_json_without_path_errors() {
    let server = MockServer::start().await;
    mount_npm_metadata_and_tarball(&server).await;

    let dir = project_dir("json_no_path");
    write_npmrc(&dir, &server.uri());

    let out = run_lpm_add(&dir, &[PACKAGE_NAME, "--json"], false);
    assert_guard_error(&out, "--json without --path");
    assert_package_json_unchanged(&dir);
}

#[tokio::test]
async fn add_simple_path_no_tty_without_path_errors() {
    let server = MockServer::start().await;
    mount_npm_metadata_and_tarball(&server).await;

    let dir = project_dir("notty_no_path");
    write_npmrc(&dir, &server.uri());

    // Force non-TTY by redirecting stdin from /dev/null.
    let out = run_lpm_add(&dir, &[PACKAGE_NAME], true);
    assert_guard_error(&out, "non-TTY without --path");
    assert_package_json_unchanged(&dir);
}

#[tokio::test]
async fn add_simple_path_yes_with_path_succeeds() {
    // Sanity check: `--path` provided → guard does NOT fire.
    // Combined with `--no-install-deps` so we don't try to spawn
    // a downstream `lpm install` (which would try to network out).
    let server = MockServer::start().await;
    mount_npm_metadata_and_tarball(&server).await;

    let dir = project_dir("yes_with_path");
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
        false,
    );
    assert!(
        out.status.success(),
        "expected success when --path provided\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );
    // Source files copied directly under target (no auto-nest under
    // package-name subdirectory — Phase 60 simple-path contract).
    assert!(
        dir.join("src/copied/index.js").exists(),
        "expected src/copied/index.js to exist; tree:\n{}",
        list_tree(&dir),
    );
    // No package-name nesting.
    assert!(
        !dir.join("src/copied").join(PACKAGE_NAME).exists(),
        "simple path must NOT auto-nest under package-name subdirectory"
    );
}

fn list_tree(dir: &Path) -> String {
    fn walk(dir: &Path, prefix: &str, out: &mut String) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                out.push_str(&format!("{prefix}{}\n", entry.path().display()));
                if entry.path().is_dir() && entry.file_name() != ".home" {
                    walk(&entry.path(), &format!("{prefix}  "), out);
                }
            }
        }
    }
    let mut out = String::new();
    walk(dir, "", &mut out);
    out
}
