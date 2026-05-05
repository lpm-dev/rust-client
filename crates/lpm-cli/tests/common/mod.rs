//! Shared support helpers for the `lpm-cli` direct-binary test tier.
//!
//! These are the canonical implementations of:
//!
//! - [`run_lpm`] / [`run_lpm_with_env`] — spawn the real `lpm-rs`
//!   binary with HOME / `LPM_HOME` / `PATH` / `LPM_REGISTRY_URL` /
//!   `NO_COLOR` / telemetry env isolation.
//! - [`strip_ansi`] — best-effort ANSI escape stripping for
//!   assertions over CLI stdout/stderr.
//! - [`parse_json_stdout`] — strip ANSI then parse stdout as JSON.
//! - Mock npm-style registry mounting ([`mount_mock_registry`] +
//!   [`MockPackage`] / [`MockPackageVersion`] and the lower-level
//!   [`make_mock_tarball`], [`sri_for`], [`tarball_route`] builders).
//!
//! Per `rust-client/CLAUDE.md` `# Testing Tier Discipline`, every
//! cli-binary file must use these helpers — never reinvent
//! `CommandOutput`, `run_lpm`, or a mock-registry mounter from
//! scratch. Drift between hand-rolled subprocess helpers is what
//! produced the phase-named regression-dump files Phase 65 cleaned
//! up; the canonical-helper rule is what stops it from coming back.
//!
//! New cli-binary files should:
//!
//! 1. Add `mod common;` at the top of the test file.
//! 2. Call `common::run_lpm`, `common::mount_mock_registry`, etc.
//! 3. Add file-local helpers only for genuinely test-specific state
//!    (e.g., global-install manifest seeding in
//!    `global_install_state_mutation.rs`).
//!
//! Different cli-binary tests use different subsets of this module,
//! so unused-helper warnings are expected and silenced with
//! `#![allow(dead_code)]`.

#![allow(dead_code)]

use base64::Engine;
use lpm_registry::{DistInfo, PackageMetadata, VersionMetadata};
use sha2::Digest;
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, ExitStatus};
use wiremock::matchers::{method, path as match_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone)]
pub struct MockPackageVersion {
    pub version: &'static str,
    pub dependencies: Vec<(&'static str, &'static str)>,
    pub bins: Vec<(&'static str, &'static str)>,
}

#[derive(Clone)]
pub struct MockPackage {
    pub name: &'static str,
    pub versions: Vec<MockPackageVersion>,
}

/// Spawn `lpm-rs` with the standard isolated env (HOME, LPM_HOME,
/// `PATH` prefixed with `lpm_home/bin`, `NO_COLOR`, telemetry off,
/// `RUST_LOG` removed). Returns `(status, stdout, stderr)`.
pub fn run_lpm(
    cwd: &Path,
    lpm_home: &Path,
    registry_url: Option<&str>,
    args: &[&str],
) -> (ExitStatus, String, String) {
    run_lpm_with_env(cwd, lpm_home, registry_url, &[], args)
}

/// Same as [`run_lpm`] but accepts additional env-var pairs to set
/// after the standard isolation env is applied.
pub fn run_lpm_with_env(
    cwd: &Path,
    lpm_home: &Path,
    registry_url: Option<&str>,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> (ExitStatus, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let mut path_entries = vec![lpm_home.join("bin")];
    path_entries.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let joined_path = std::env::join_paths(path_entries).unwrap();

    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", cwd)
        .env("LPM_HOME", lpm_home)
        .env("PATH", joined_path)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env_remove("RUST_LOG");
    match registry_url {
        Some(url) => {
            command.env("LPM_REGISTRY_URL", url);
        }
        None => {
            command.env_remove("LPM_REGISTRY_URL");
        }
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }

    let output = command.output().expect("failed to spawn lpm-rs");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stdout, stderr)
}

/// Best-effort ANSI escape stripping for stdout/stderr assertions.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && index + 1 < bytes.len() && bytes[index + 1] == b'[' {
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        } else {
            out.push(bytes[index] as char);
            index += 1;
        }
    }
    out
}

/// Strip ANSI escapes then parse stdout as JSON; panics with the raw
/// stdout in the message if parsing fails.
pub fn parse_json_stdout(stdout: &str) -> serde_json::Value {
    let stripped = strip_ansi(stdout);
    let trimmed = stripped.trim();
    serde_json::from_str(trimmed).unwrap_or_else(|error| {
        panic!("failed to parse JSON stdout: {error}; raw stdout={trimmed:?}")
    })
}

/// Path component for the mock-registry tarball route.
pub fn tarball_route(name: &str, version: &str) -> String {
    let sanitized = name.trim_start_matches('@').replace('/', "-");
    format!("/tarballs/{sanitized}-{version}.tgz")
}

fn append_tar_entry(
    builder: &mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>,
    path: &str,
    bytes: &[u8],
    mode: u32,
) {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    builder.append_data(&mut header, path, bytes).unwrap();
}

/// Build a minimal gzipped tarball with `package/package.json`
/// (name, version, optional `bin` map) plus a node-shebang stub
/// script for each declared bin entry.
pub fn make_mock_tarball(
    package_name: &str,
    version: &str,
    bin_entries: &[(&str, &str)],
) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    let mut package_json = serde_json::json!({
        "name": package_name,
        "version": version,
    });
    if !bin_entries.is_empty() {
        let bin_map = bin_entries
            .iter()
            .map(|(command, path)| {
                (
                    (*command).to_string(),
                    serde_json::Value::String((*path).to_string()),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>();
        package_json
            .as_object_mut()
            .unwrap()
            .insert("bin".into(), serde_json::Value::Object(bin_map));
    }

    let package_json_bytes = serde_json::to_vec(&package_json).unwrap();
    append_tar_entry(
        &mut builder,
        "package/package.json",
        &package_json_bytes,
        0o644,
    );

    for (_, path) in bin_entries {
        append_tar_entry(
            &mut builder,
            &format!("package/{path}"),
            b"#!/usr/bin/env node\nconsole.log('ok')\n",
            0o755,
        );
    }

    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap()
}

/// SRI integrity string (`sha512-<base64>`) for the given bytes.
pub fn sri_for(bytes: &[u8]) -> String {
    let digest = sha2::Sha512::digest(bytes);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn make_version_metadata(
    name: &str,
    version: &str,
    dependencies: &[(&str, &str)],
    tarball_url: String,
    integrity: String,
) -> VersionMetadata {
    VersionMetadata {
        name: name.to_string(),
        version: version.to_string(),
        dependencies: dependencies
            .iter()
            .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
            .collect(),
        dist: Some(DistInfo {
            tarball: Some(tarball_url),
            integrity: Some(integrity),
            shasum: None,
            ..Default::default()
        }),
        ..VersionMetadata::default()
    }
}

fn make_package_metadata(name: &str, versions: Vec<VersionMetadata>) -> PackageMetadata {
    let latest = versions
        .last()
        .map(|version| version.version.clone())
        .expect("mock package metadata must include at least one version");

    PackageMetadata {
        name: name.to_string(),
        description: None,
        dist_tags: HashMap::from([("latest".to_string(), latest.clone())]),
        versions: versions
            .into_iter()
            .map(|version| (version.version.clone(), version))
            .collect(),
        time: Default::default(),
        downloads: None,
        distribution_mode: None,
        package_type: None,
        latest_version: Some(latest),
        ecosystem: None,
    }
}

/// Mount per-package metadata GET routes, the batch-metadata POST,
/// and tarball GETs on `server` for each [`MockPackage`] (each with
/// one or more [`MockPackageVersion`]s). The integrity field is
/// computed against the tarball bytes via [`sri_for`].
pub async fn mount_mock_registry(server: &MockServer, packages: &[MockPackage]) {
    let mut tarballs: HashMap<(String, String), Vec<u8>> = HashMap::new();
    let mut metadata_map: HashMap<String, PackageMetadata> = HashMap::new();

    for package in packages {
        let mut versions = Vec::new();
        for version in &package.versions {
            let tarball = make_mock_tarball(package.name, version.version, &version.bins);
            let tarball_key = (package.name.to_string(), version.version.to_string());
            let tarball_url = format!(
                "{}{}",
                server.uri(),
                tarball_route(package.name, version.version)
            );
            let integrity = sri_for(&tarball);
            tarballs.insert(tarball_key, tarball);
            versions.push(make_version_metadata(
                package.name,
                version.version,
                &version.dependencies,
                tarball_url,
                integrity,
            ));
        }
        metadata_map.insert(
            package.name.to_string(),
            make_package_metadata(package.name, versions),
        );
    }

    for ((name, version), tarball) in &tarballs {
        Mock::given(method("GET"))
            .and(match_path(tarball_route(name, version)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
            .mount(server)
            .await;
    }

    for (name, metadata) in &metadata_map {
        Mock::given(method("GET"))
            .and(match_path(format!("/api/registry/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(server)
            .await;
    }

    Mock::given(method("POST"))
        .and(match_path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": metadata_map,
        })))
        .mount(server)
        .await;
}
