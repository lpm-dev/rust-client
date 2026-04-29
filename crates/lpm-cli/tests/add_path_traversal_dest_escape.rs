//! Phase 60.0.f / D6 regression — destination-side path containment.
//!
//! `lpm add` against an arbitrary npm tarball whose `lpm.config.json`
//! `files[0].dest` resolves outside `target_dir` MUST refuse with a
//! containment violation, not silently write outside the target.
//!
//! Pre-Phase-60 the only path-traversal check ran at extraction
//! against the temp dir; the user-side write at `target_dir.join(dest_rel)`
//! had no second containment check. For arbitrary npm publishers
//! (Phase 60's whole new threat model), a malicious or buggy
//! `dest_rel = "../../etc/evil"` would have written outside the
//! target. `resolve_safe_dest` is the wire-up that catches this.
//!
//! Unit tests cover `resolve_safe_dest` in isolation; this integration
//! test proves it's wired into the actual `lpm add` write loop.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha512};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PACKAGE_NAME: &str = "phase60-traversal-fixture";
const VERSION: &str = "1.0.0";

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

/// Build a tarball that ships an `lpm.config.json` whose `files[]`
/// rewrites a benign source file to a destination that resolves
/// OUTSIDE the user's target directory via `..`.
///
/// Note: the file source path itself stays inside the tarball
/// (so `validate_extracted_paths` extraction-side check passes); the
/// attack vector is the AUTHOR-SUPPLIED `dest`, which the buyer's
/// `resolve_safe_dest` must catch.
fn make_traversal_tarball() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let pkg_json = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": VERSION,
    });
    let pkg_bytes = serde_json::to_vec_pretty(&pkg_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(pkg_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &pkg_bytes[..]).unwrap();

    let lpm_config = serde_json::json!({
        "files": [
            {
                "src": "src/evil.txt",
                "dest": "../../escaped/evil.txt"
            }
        ]
    });
    let lpm_bytes = serde_json::to_vec_pretty(&lpm_config).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/lpm.config.json").unwrap();
    header.set_size(lpm_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &lpm_bytes[..]).unwrap();

    let evil_content = b"benign content but malicious dest\n";
    let mut header = tar::Header::new_gnu();
    header.set_path("package/src/evil.txt").unwrap();
    header.set_size(evil_content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &evil_content[..]).unwrap();

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
        .join("lpm-phase60-traversal")
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
async fn dest_escape_via_dotdot_is_refused() {
    let server = MockServer::start().await;
    let tarball = make_traversal_tarball();
    mount_npm_metadata_and_tarball(&server, &tarball).await;

    let dir = project_dir("dest_escape");
    write_npmrc(&dir, &server.uri());

    // Run with `--path src/copied` so the install dir is well-known
    // and predictable. The malicious `dest = "../../escaped/evil.txt"`
    // would, without containment, write to `src/escaped/evil.txt`
    // (because `../../` from `src/copied` lands at `src/`'s parent's
    // parent — which is `dir`).
    let would_have_escaped_to = dir.join("escaped").join("evil.txt");

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
        !out.status.success(),
        "expected non-zero exit on traversal attempt\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    let combined = format!("{}{}", out.stdout, out.stderr);
    assert!(
        combined.contains("path containment violation"),
        "expected containment-violation error message\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    // No file written outside target_dir at the would-be escape path.
    assert!(
        !would_have_escaped_to.exists(),
        "file written outside target_dir at {} — containment failed",
        would_have_escaped_to.display(),
    );
    // Also: no file at any reasonable interpretation of the escape.
    assert!(
        !dir.parent()
            .unwrap()
            .join("escaped")
            .join("evil.txt")
            .exists(),
        "file written outside dir entirely — containment failed",
    );
}
