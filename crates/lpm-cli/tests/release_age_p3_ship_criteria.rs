//! Phase 46 P3 ship-criteria end-to-end tests.
//!
//! Exercises the full `lpm install` pipeline against a wiremock-backed
//! mock registry to verify the four §11 P3 ship criteria land correctly
//! at the cooldown gate in [`lpm_cli::commands::install::run_with_options`]
//! (install.rs:1646):
//!
//! 1. `--min-release-age=72h` blocks a fresh test package.
//! 2. `--allow-new` unblocks (independent bypass, orthogonal to the new flag).
//! 3. `~/.lpm/config.toml` key `minimum-release-age-secs` overrides the 24h default.
//! 4. `package.json > lpm > minimumReleaseAge` overrides the global config.
//!
//! Plus the §12.3 pin-bypass regression: an explicit version pin
//! (`@lpm.dev/acme.widget@1.0.0`) must still block during the cooldown
//! window. The v1 plan proposed pin-bypass; v2 rejected it per D7 in
//! the plan's decision log. This test guards that the rejected
//! behaviour never re-lands.
//!
//! Harness pattern is lifted verbatim from
//! `crates/lpm-cli/tests/upgrade_phase7_regression.rs`: start a
//! `wiremock::MockServer`, mount the single-package metadata endpoint
//! plus the batch-metadata endpoint, serve a real tarball, spawn the
//! `lpm-rs` binary with `LPM_REGISTRY_URL` pointing at the mock and
//! `HOME` scoped to a per-test temp dir (so the test doesn't read the
//! developer's `~/.lpm/config.toml`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{SecondsFormat, Utc};
use sha2::{Digest, Sha512};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PACKAGE_NAME: &str = "@lpm.dev/acme.widget";
const VERSION: &str = "1.0.0";

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

struct MockRegistry {
    server: MockServer,
}

impl MockRegistry {
    async fn start() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    fn url(&self) -> String {
        self.server.uri()
    }

    /// Mount a single-version package whose `time[VERSION]` is
    /// `published_at`. The tarball is real (gzipped tar with a
    /// minimal `package.json` + `index.js`) so the install pipeline
    /// can complete past the cooldown gate in the bypass tests.
    async fn mount_single_version(&self, published_at: &str) {
        let tarball = make_minimal_tarball();
        let metadata = package_metadata(&self.url(), published_at, &tarball);

        // Single-package GET (used by the cooldown gate's metadata lookup).
        Mock::given(method("GET"))
            .and(path(format!("/api/registry/{PACKAGE_NAME}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;

        // Batch-metadata POST (used by the resolver during fresh resolution).
        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut packages = serde_json::Map::new();
                packages.insert(PACKAGE_NAME.to_string(), metadata.clone());
                serde_json::json!({ "packages": packages })
            }))
            .mount(&self.server)
            .await;

        // Tarball GET (used by the fetch stage — only reached when the
        // cooldown gate allows the install to proceed).
        Mock::given(method("GET"))
            .and(path(tarball_path()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball.clone())
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(&self.server)
            .await;
    }
}

/// ISO-8601 UTC string representing `n_secs` seconds before now. The
/// LPM cooldown parser accepts `2025-01-01T00:00:00.000Z`-style ISO
/// strings (see [`lpm_security::parse_timestamp`]).
fn iso8601_n_secs_ago(n_secs: i64) -> String {
    let dt = Utc::now() - chrono::Duration::seconds(n_secs);
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn tarball_path() -> String {
    let slug = PACKAGE_NAME
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    format!("/tarballs/{slug}-{VERSION}.tgz")
}

fn package_metadata(registry_url: &str, published_at: &str, tarball: &[u8]) -> serde_json::Value {
    let tarball_url = format!("{registry_url}{}", tarball_path());
    let integrity = compute_integrity(tarball);

    let version_obj = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": VERSION,
        "dist": {
            "tarball": tarball_url,
            "integrity": integrity,
        },
        "dependencies": {},
    });

    serde_json::json!({
        "name": PACKAGE_NAME,
        "dist-tags": { "latest": VERSION },
        "versions": { VERSION: version_obj },
        "time": { VERSION: published_at },
    })
}

fn compute_integrity(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    format!("sha512-{}", BASE64.encode(digest))
}

fn make_minimal_tarball() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let package_json = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": VERSION,
        "main": "index.js",
    });
    let package_json_bytes = serde_json::to_vec_pretty(&package_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(package_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &package_json_bytes[..]).unwrap();

    let index_js = b"module.exports = {};\n";
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

/// Per-test project dir under a pid-namespaced tempdir so parallel
/// test runs don't collide.
fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-release-age-p3-ship-criteria")
        .join(format!("{name}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_manifest(dir: &Path, min_release_age: Option<u64>) {
    let mut lpm = serde_json::Map::new();
    if let Some(secs) = min_release_age {
        lpm.insert(
            "minimumReleaseAge".to_string(),
            serde_json::Value::Number(secs.into()),
        );
    }

    let mut manifest = serde_json::json!({
        "name": "release-age-p3-ship-test",
        "version": "1.0.0",
        "dependencies": {
            PACKAGE_NAME: VERSION,
        },
    });
    if !lpm.is_empty() {
        manifest["lpm"] = serde_json::Value::Object(lpm);
    }

    fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// Write `~/.lpm/config.toml` into the scoped HOME. `None` skips.
fn write_global_config(home: &Path, min_release_age_secs: Option<u64>) {
    let Some(secs) = min_release_age_secs else {
        return;
    };
    let lpm_dir = home.join(".lpm");
    fs::create_dir_all(&lpm_dir).unwrap();
    fs::write(
        lpm_dir.join("config.toml"),
        format!("minimum-release-age-secs = {secs}\n"),
    )
    .unwrap();
}

/// Run `lpm-rs` as a subprocess, scoped to `cwd` with a fresh
/// per-test HOME (so the developer's `~/.lpm/config.toml` never leaks
/// into the test; we write our own into the scoped HOME when needed).
fn run_lpm(cwd: &Path, args: &[&str], registry_url: &str) -> CommandOutput {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    fs::create_dir_all(&home).unwrap();

    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env("LPM_REGISTRY_URL", registry_url)
        .env_remove("LPM_TOKEN")
        .env_remove("RUST_LOG");

    let output = command.output().expect("failed to spawn lpm-rs");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Shared setup: fresh project, mock registry serving a package published
/// `n_secs` ago. The caller supplies the manifest's `minimumReleaseAge`
/// (usually `None`) and an optional global-config seconds value, then
/// asserts on the subprocess output.
struct Fixture {
    dir: PathBuf,
    home: PathBuf,
    mock: MockRegistry,
}

/// Assertion helper: panic messages always include BOTH stdout and
/// stderr plus the exit status, so a failing assertion on a subprocess
/// test never leaves the author guessing which channel the output
/// landed on.
fn fail_with_context(out: &CommandOutput, what_failed: &str) -> ! {
    panic!(
        "{what_failed}\n  exit: {:?}\n  stdout:\n{}\n  stderr:\n{}",
        out.status.code(),
        out.stdout,
        out.stderr,
    );
}

fn assert_cooldown_blocked(out: &CommandOutput) {
    if out.status.success() {
        fail_with_context(out, "install must fail with a cooldown block");
    }
    let combined = format!("{}{}", out.stdout, out.stderr);
    if !(combined.contains("blocked by minimumReleaseAge")
        || combined.contains("published too recently"))
    {
        fail_with_context(out, "output must name the cooldown block");
    }
}

fn assert_cooldown_not_blocked(out: &CommandOutput) {
    let combined = format!("{}{}", out.stdout, out.stderr);
    if combined.contains("blocked by minimumReleaseAge")
        || combined.contains("published too recently")
    {
        fail_with_context(out, "cooldown must not fire but the block message appeared");
    }
}

impl Fixture {
    async fn build(
        test_name: &str,
        published_n_secs_ago: i64,
        manifest_min_release_age: Option<u64>,
        global_min_release_age_secs: Option<u64>,
    ) -> Self {
        let dir = project_dir(test_name);
        let home = dir.join(".home");
        fs::create_dir_all(&home).unwrap();

        write_manifest(&dir, manifest_min_release_age);
        write_global_config(&home, global_min_release_age_secs);

        let mock = MockRegistry::start().await;
        mock.mount_single_version(&iso8601_n_secs_ago(published_n_secs_ago))
            .await;

        Self { dir, home, mock }
    }

    fn run(&self, args: &[&str]) -> CommandOutput {
        // `run_lpm` recomputes `home` from `cwd.join(".home")`, which
        // matches our `self.home` by construction.
        let _ = &self.home;
        run_lpm(&self.dir, args, &self.mock.url())
    }
}

// ── §11 P3 ship criteria ──────────────────────────────────────

/// Ship criterion 1: `lpm install --min-release-age=72h` blocks a
/// package published inside the 72h window. Without the flag the
/// default 24h already blocks a ~1h-old package, so we shorten the
/// manifest-side value to prove the CLI flag is what took effect.
#[tokio::test]
async fn cli_override_72h_blocks_fresh_package() {
    // Publish time: 1h ago. Manifest disables the default (0 would
    // short-circuit the check); CLI override re-enables it at 72h.
    let fx = Fixture::build(
        "cli_override_72h_blocks_fresh_package",
        3_600,
        Some(0),
        None,
    )
    .await;

    let out = fx.run(&["install", "--min-release-age=72h"]);

    assert_cooldown_blocked(&out);
    // The effective window value should be rendered — 72h = 259200s.
    let combined = format!("{}{}", out.stdout, out.stderr);
    if !combined.contains("259200") {
        fail_with_context(&out, "output must render the effective 72h=259200s window");
    }
}

/// Ship criterion 2: `--allow-new` bypasses the cooldown even when
/// `--min-release-age` is also set, because the two are orthogonal
/// per §8.3 / D16 — `--allow-new` short-circuits the gate at
/// install.rs:1641 BEFORE the resolver runs.
///
/// The install may still fail for downstream reasons (no linker setup
/// in the scoped HOME, etc.); we only assert that the cooldown block
/// message is absent. The exit code is not asserted here — the
/// contract under test is "cooldown does not fire," nothing more.
#[tokio::test]
async fn allow_new_bypasses_cli_override() {
    let fx = Fixture::build("allow_new_bypasses_cli_override", 3_600, Some(0), None).await;

    let out = fx.run(&["install", "--allow-new", "--min-release-age=72h"]);

    assert_cooldown_not_blocked(&out);
}

/// Ship criterion 3: `~/.lpm/config.toml` key
/// `minimum-release-age-secs` overrides the 24h default when no CLI
/// flag and no `package.json` key are present. Package is published
/// 30 min ago; global = 3600s (1h); the default (86400) would also
/// block, so we assert the rendered policy value in stderr names
/// 3600 — proving the global layer is what took effect.
#[tokio::test]
async fn global_config_overrides_default() {
    let fx = Fixture::build("global_config_overrides_default", 1_800, None, Some(3_600)).await;

    let out = fx.run(&["install"]);

    assert_cooldown_blocked(&out);
    let combined = format!("{}{}", out.stdout, out.stderr);
    if !combined.contains("3600") {
        fail_with_context(&out, "output must render the global config's 3600s window");
    }
    if combined.contains("86400") {
        fail_with_context(
            &out,
            "86400 (default) must NOT appear — global config takes precedence",
        );
    }
}

/// Ship criterion 4: `package.json > lpm > minimumReleaseAge`
/// overrides the global config. Package is 30 min old; global = 3600
/// (1h, would block); package.json = 60 (1min, would allow). The
/// manifest layer wins → install proceeds (no cooldown message).
#[tokio::test]
async fn package_json_overrides_global() {
    let fx = Fixture::build(
        "package_json_overrides_global",
        1_800,
        Some(60),
        Some(3_600),
    )
    .await;

    let out = fx.run(&["install"]);

    assert_cooldown_not_blocked(&out);
}

// ── §12.3 pin-bypass regression ──────────────────────────────

/// §12.3 pin-bypass regression: `lpm install @lpm.dev/acme.widget@1.0.0`
/// with an explicit version pin must still block during the cooldown
/// window without `--allow-new`. v1 of the plan proposed pin-bypass
/// ("explicit pins bypass cooldown"); walking through the axios
/// attack showed that would be strictly less secure — renovate /
/// dependabot auto-pin PRs would then land compromised versions
/// during the detection window. v2 (this plan) explicitly rejects it
/// per D7 in §15.
///
/// This test is the structural guard: if a future change introduces
/// a pin-specific bypass at the install gate, this test fails.
/// Package is 1h old, default 24h window applies, user types an
/// explicit exact-version spec — cooldown must still fire.
#[tokio::test]
async fn pin_does_not_bypass_cooldown() {
    let fx = Fixture::build("pin_does_not_bypass_cooldown", 3_600, None, None).await;

    // Explicit exact-version pin on the command line. The resolver
    // normalizes this to the same `packages` entry the cooldown gate
    // would see for any other spec form, so the gate treats it
    // identically. The plan's D7 analysis (§8.2) spells out why this
    // is the intended behaviour.
    let pinned_spec = format!("{PACKAGE_NAME}@{VERSION}");
    let out = fx.run(&["install", &pinned_spec]);

    assert_cooldown_blocked(&out);
}
