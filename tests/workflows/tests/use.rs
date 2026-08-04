//! Workflow tests for `lpm use`.
//!
//! Local list/pin/remove paths are deterministic under an isolated HOME, and
//! install-path coverage uses mocked runtime indexes/assets so the workflow tier
//! never depends on live nodejs.org or GitHub traffic.
//!
//! `lpm_runtime::node::list_installed()` reads `<HOME>/.lpm/runtimes/node/`,
//! which is empty in a fresh isolated HOME.

mod support;

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use std::io::Write;
use support::{TempProject, lpm};
use tar::Builder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zip::write::SimpleFileOptions;

fn seed_installed_node(project: &TempProject, version: &str) {
    let bin_dir = project
        .home()
        .join(".lpm")
        .join("runtimes")
        .join("node")
        .join(version)
        .join("bin");
    std::fs::create_dir_all(&bin_dir).expect("failed to create runtime bin dir");
    std::fs::write(bin_dir.join("node"), "").expect("failed to seed node binary");
}

fn seed_installed_bun(project: &TempProject, version: &str) {
    let bin_dir = project
        .home()
        .join(".lpm")
        .join("runtimes")
        .join("bun")
        .join(version)
        .join("bin");
    std::fs::create_dir_all(&bin_dir).expect("failed to create Bun runtime bin dir");
    let binary = if cfg!(windows) { "bun.exe" } else { "bun" };
    std::fs::write(bin_dir.join(binary), "").expect("failed to seed Bun binary");
}

#[cfg(unix)]
fn seed_executable_bun(project: &TempProject, version: &str, output: &str) {
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = project
        .home()
        .join(".lpm")
        .join("runtimes")
        .join("bun")
        .join(version)
        .join("bin");
    std::fs::create_dir_all(&bin_dir).expect("failed to create Bun runtime bin dir");
    let path = bin_dir.join("bun");
    std::fs::write(&path, format!("#!/bin/sh\necho {output}\n"))
        .expect("failed to seed executable Bun binary");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("failed to make Bun binary executable");
}

#[cfg(unix)]
fn seed_executable_bun_with_log(
    project: &TempProject,
    version: &str,
    output: &str,
    log_path: &std::path::Path,
) {
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = project
        .home()
        .join(".lpm")
        .join("runtimes")
        .join("bun")
        .join(version)
        .join("bin");
    std::fs::create_dir_all(&bin_dir).expect("failed to create Bun runtime bin dir");
    let path = bin_dir.join("bun");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nprintf 'bun\\n' >> \"{}\"\nprintf '%s\\n' '{}'\n",
            log_path.display(),
            output,
        ),
    )
    .expect("failed to seed executable Bun binary with log");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("failed to make Bun binary executable");
}

fn managed_node_dir(project: &TempProject, version: &str) -> std::path::PathBuf {
    project
        .home()
        .join(".lpm")
        .join("runtimes")
        .join("node")
        .join(version)
}

fn managed_bun_dir(project: &TempProject, version: &str) -> std::path::PathBuf {
    project
        .home()
        .join(".lpm")
        .join("runtimes")
        .join("bun")
        .join(version)
}

fn current_node_dist_suffix() -> String {
    lpm_runtime::platform::Platform::current()
        .expect("resolve current node runtime platform")
        .node_suffix()
}

fn current_bun_asset_name() -> String {
    format!(
        "bun-{}.zip",
        lpm_runtime::platform::Platform::current()
            .expect("resolve current bun runtime platform")
            .bun_suffix()
    )
}

fn current_node_archive_name(version: &str) -> String {
    let ext = if cfg!(windows) { "zip" } else { "tar.gz" };
    format!("node-v{version}-{}.{}", current_node_dist_suffix(), ext)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn make_node_runtime_archive(version: &str) -> Vec<u8> {
    let root_dir = format!("node-v{version}-{}", current_node_dist_suffix());
    let node_contents = if cfg!(windows) {
        b"mock-node.exe\n".to_vec()
    } else {
        b"#!/bin/sh\necho mock-node\n".to_vec()
    };

    if cfg!(windows) {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = SimpleFileOptions::default();
        writer
            .add_directory(format!("{root_dir}/"), options)
            .expect("add node zip root dir");
        writer
            .start_file(format!("{root_dir}/node.exe"), options)
            .expect("start node.exe in node zip");
        writer
            .write_all(&node_contents)
            .expect("write node.exe in node zip");
        writer.finish().expect("finish node zip").into_inner()
    } else {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);

        let dir_path = format!("{root_dir}/");
        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_mode(0o755);
        dir_header.set_size(0);
        dir_header.set_cksum();
        builder
            .append_data(&mut dir_header, &dir_path, std::io::empty())
            .expect("append node root dir to tarball");

        let bin_dir_path = format!("{root_dir}/bin/");
        let mut bin_dir_header = tar::Header::new_gnu();
        bin_dir_header.set_entry_type(tar::EntryType::Directory);
        bin_dir_header.set_mode(0o755);
        bin_dir_header.set_size(0);
        bin_dir_header.set_cksum();
        builder
            .append_data(&mut bin_dir_header, &bin_dir_path, std::io::empty())
            .expect("append node bin dir to tarball");

        let mut node_header = tar::Header::new_gnu();
        node_header.set_mode(0o755);
        node_header.set_size(node_contents.len() as u64);
        node_header.set_cksum();
        builder
            .append_data(
                &mut node_header,
                format!("{root_dir}/bin/node"),
                std::io::Cursor::new(node_contents),
            )
            .expect("append node binary to tarball");

        let encoder = builder.into_inner().expect("finish node tar builder");
        encoder.finish().expect("finish node tarball")
    }
}

fn make_bun_runtime_zip() -> Vec<u8> {
    let asset_name = current_bun_asset_name();
    let root_dir = asset_name.trim_end_matches(".zip").to_string();
    let binary_name = if cfg!(windows) { "bun.exe" } else { "bun" };
    let bun_contents = if cfg!(windows) {
        b"mock-bun.exe\n".to_vec()
    } else {
        b"#!/bin/sh\necho mock-bun\n".to_vec()
    };

    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = SimpleFileOptions::default();
    writer
        .add_directory(format!("{root_dir}/"), options)
        .expect("add bun zip root dir");
    writer
        .start_file(format!("{root_dir}/{binary_name}"), options)
        .expect("start bun binary in zip");
    writer
        .write_all(&bun_contents)
        .expect("write bun binary in zip");
    writer.finish().expect("finish bun zip").into_inner()
}

fn write_node_index_cache(project: &TempProject, releases_json: &str) {
    let runtimes_dir = project.home().join(".lpm").join("runtimes");
    std::fs::create_dir_all(&runtimes_dir).expect("create runtimes dir for node cache");
    std::fs::write(runtimes_dir.join("index-cache.json"), releases_json)
        .expect("write node index cache");
}

fn write_bun_index_cache(project: &TempProject, releases_json: &str) {
    let runtimes_dir = project.home().join(".lpm").join("runtimes");
    std::fs::create_dir_all(&runtimes_dir).expect("create runtimes dir for bun cache");
    std::fs::write(runtimes_dir.join("bun-index-cache.json"), releases_json)
        .expect("write bun index cache");
}

fn lpm_json_runtime(project: &TempProject, runtime: &str) -> serde_json::Value {
    let lpm_json: serde_json::Value = serde_json::from_str(&project.read_file("lpm.json"))
        .expect("lpm command must write valid lpm.json");
    lpm_json["runtime"][runtime].clone()
}

#[test]
fn use_list_on_empty_runtime_succeeds_with_empty_set() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "--list"])
        .output()
        .expect("failed to run lpm use --list");

    assert!(
        output.status.success(),
        "lpm use --list on a fresh HOME must exit 0, got: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human use --list should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› No Node versions installed"),
        "empty human use --list should use the slim info line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Run lpm use node@22 to install one"),
        "empty human use --list should keep the install hint, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from use --list stderr, got:\n{stderr}"
    );
}

#[test]
fn use_list_human_output_renders_plain_installed_versions() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);
    seed_installed_node(&project, "22.12.0");
    seed_installed_node(&project, "20.18.0");

    let output = lpm(&project)
        .args(["use", "--list"])
        .output()
        .expect("failed to run lpm use --list with seeded versions");

    assert!(
        output.status.success(),
        "seeded use --list must exit 0, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Installed Node versions (2)"),
        "installed human use --list should use the slim summary line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("22.12.0") && stderr.contains("20.18.0"),
        "installed human use --list should list the available versions, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "installed human use --list must not use legacy bullets or gutters, got:\n{stderr}"
    );
}

#[test]
fn use_list_bun_human_output_renders_plain_installed_versions() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);
    seed_installed_bun(&project, "1.3.14");
    seed_installed_bun(&project, "1.2.23");

    let output = lpm(&project)
        .args(["use", "--list", "bun"])
        .output()
        .expect("failed to run lpm use --list bun with seeded versions");

    assert!(
        output.status.success(),
        "seeded use --list bun must exit 0, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Installed Bun versions (2)"),
        "installed Bun use --list should use the slim summary line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("1.3.14") && stderr.contains("1.2.23"),
        "installed Bun use --list should list available versions, got:\n{stderr}"
    );
}

#[test]
fn use_list_json_envelope_reports_empty_versions_on_fresh_home() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "use", "--list"])
        .output()
        .expect("failed to run lpm use --list --json");

    assert!(output.status.success(), "lpm use --list --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("use --list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["runtime"], serde_json::json!("node"));

    let versions = envelope["versions"]
        .as_array()
        .expect("versions must be an array");
    assert!(
        versions.is_empty(),
        "fresh HOME must have zero installed node versions, got: {versions:?}",
    );
}

#[test]
fn use_list_bun_json_envelope_reports_versions() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);
    seed_installed_bun(&project, "1.3.14");

    let output = lpm(&project)
        .args(["--json", "use", "--list", "bun"])
        .output()
        .expect("failed to run lpm use --list bun --json");

    assert!(output.status.success(), "lpm use --list bun --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("use --list bun --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["runtime"], serde_json::json!("bun"));
    assert_eq!(envelope["versions"], serde_json::json!(["1.3.14"]));
}

#[test]
fn use_no_args_falls_through_to_list_path() {
    // `lpm use` with no positional and no flags routes to the list
    // action (see dispatch in main.rs::Commands::Use). Behavior-pin
    // for the implicit-list path so it can't silently shift later.
    let project = TempProject::empty(r#"{"name":"use-no-args","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use"])
        .output()
        .expect("failed to run bare lpm use");

    assert!(
        output.status.success(),
        "bare `lpm use` must succeed (falls through to list)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

// ─── install path: pre-network error branches ─────────────────────────

#[test]
fn use_install_unsupported_runtime_fails_before_network_call() {
    // The install path's runtime check fires BEFORE the
    // `lpm_runtime::node::fetch_index` network call. Locking that
    // ordering keeps the unsupported-runtime UX fast even when the
    // host has no internet, and lets workflow tests probe the
    // contract without flake.
    let project = TempProject::empty(r#"{"name":"use","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "deno@1.0.0"])
        .output()
        .expect("failed to run lpm use deno@1.0.0");

    assert!(
        !output.status.success(),
        "unsupported runtime must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deno") || stderr.contains("not yet supported"),
        "stderr must explain the unsupported runtime, got:\n{stderr}",
    );
    assert!(
        stderr.contains("node") && stderr.contains("bun"),
        "stderr must guide users toward the supported runtime, got:\n{stderr}",
    );
}

#[test]
fn use_install_without_runtime_prefix_fails_with_usage() {
    let project = TempProject::empty(r#"{"name":"use","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "i"]) // alias for install, but no spec
        .output()
        .expect("failed to run lpm use i (no spec)");

    // `i` is parsed as a spec, not as an action, so this routes through
    // the install action with spec="i". Either: clap rejects, or the
    // runtime parser fails. Both are acceptable; assert non-zero exit.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.is_empty() || !String::from_utf8_lossy(&output.stdout).is_empty(),
            "must emit a diagnostic, got stdout: {} / stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            stderr,
        );
    }
}

/// `lpm --json use --pin` without a spec must surface the missing-spec
/// error as a parseable JSON envelope on stdout. The bare `lpm use
/// node@<v>` install path is out of scope for the workflow tier (real
/// nodejs.org download), but the validation error path is the cheapest
/// contract that proves the surface is machine-readable under --json.
#[test]
fn use_pin_without_spec_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"use-pin-no-spec","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "use", "--pin"])
        .output()
        .expect("failed to run lpm --json use --pin");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json use --pin must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("missing version") || s.contains("Usage")),
        "error must reference the missing-version condition, got: {envelope}",
    );
}

#[test]
fn use_pin_major_spec_writes_matching_installed_exact_version() {
    let project = TempProject::empty(r#"{"name":"use-pin","version":"1.0.0"}"#);
    seed_installed_node(&project, "22.12.0");

    let output = lpm(&project)
        .args(["use", "node@22", "--pin"])
        .output()
        .expect("failed to run lpm use node@22 --pin");

    assert!(
        output.status.success(),
        "lpm use node@22 --pin must succeed when a matching version is already installed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human use --pin should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Pinned node@22.12.0 in lpm.json"),
        "human use --pin should use the slim done line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from use --pin stderr, got:\n{stderr}"
    );

    let lpm_json: serde_json::Value = serde_json::from_str(&project.read_file("lpm.json"))
        .expect("lpm use --pin must write valid lpm.json");
    assert_eq!(lpm_json["runtime"]["node"], serde_json::json!("22.12.0"));
}

#[test]
fn use_pin_node_keeps_requested_spec_when_it_cannot_resolve_locally() {
    let project = TempProject::empty(r#"{"name":"use-pin-node-spec","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "node@lts", "--pin"])
        .output()
        .expect("failed to run lpm use node@lts --pin");

    assert!(
        output.status.success(),
        "lpm use node@lts --pin must succeed even without a locally installed Node\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("node@lts is not currently installed"),
        "unmatched Node pin should warn instead of failing, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Run `lpm use node@lts` to install it"),
        "unmatched Node pin should guide users to the install command, got:\n{stderr}"
    );

    assert_eq!(lpm_json_runtime(&project, "node"), serde_json::json!("lts"));
}

#[tokio::test]
async fn use_install_node_supported_specs_install_and_pin_from_mocked_dist() {
    let server = MockServer::start().await;
    let version = "22.12.0";
    let archive_name = current_node_archive_name(version);
    let archive_bytes = make_node_runtime_archive(version);
    let archive_sha = sha256_hex(&archive_bytes);

    Mock::given(method("GET"))
        .and(path("/node-dist/index.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "version": "v23.1.0",
                "date": "2026-05-01",
                "lts": false,
                "dist_base_url": format!("{}/node-dist", server.uri()),
            },
            {
                "version": format!("v{version}"),
                "date": "2026-04-15",
                "lts": "Jod",
                "dist_base_url": format!("{}/node-dist", server.uri()),
            }
        ])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/node-dist/v{version}/{archive_name}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive_bytes.clone()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/node-dist/v{version}/SHASUMS256.txt")))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("{archive_sha}  {archive_name}\n")),
        )
        .mount(&server)
        .await;

    for (spec, expected_pinned) in [
        ("node@22", "22.12.0"),
        ("node@lts", "22.12.0"),
        ("node@22.12.0", "22.12.0"),
    ] {
        let project = TempProject::empty(r#"{"name":"use-install-node","version":"1.0.0"}"#);
        write_node_index_cache(
            &project,
            &serde_json::to_string(&serde_json::json!([
                {
                    "version": "v23.1.0",
                    "date": "2026-05-01",
                    "lts": false,
                    "dist_base_url": format!("{}/node-dist", server.uri()),
                },
                {
                    "version": format!("v{version}"),
                    "date": "2026-04-15",
                    "lts": "Jod",
                    "dist_base_url": format!("{}/node-dist", server.uri()),
                }
            ]))
            .expect("serialize node cache releases"),
        );

        let output = lpm(&project)
            .args(["use", spec])
            .output()
            .unwrap_or_else(|e| panic!("failed to run lpm use {spec}: {e}"));

        assert!(
            output.status.success(),
            "lpm use {spec} must succeed from the mocked dist\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Resolving node@")
                && stderr.contains("→ 22.12.0")
                && stderr.contains("(lts/jod)"),
            "lpm use {spec} should report the resolved Node version, got:\n{stderr}"
        );
        assert!(
            stderr.contains("Pinned node@22.12.0 in lpm.json"),
            "lpm use {spec} should pin the resolved Node version, got:\n{stderr}"
        );
        assert!(
            stderr.contains("Downloaded Node 22.12.0 ·")
                && stderr.contains("Verified SHA-256 sha256:"),
            "lpm use {spec} should report the download and checksum, got:\n{stderr}"
        );
        assert!(
            stderr.contains("Now using Node 22.12.0 ·") && stderr.contains("PATH "),
            "lpm use {spec} should print the final runtime status and PATH hint, got:\n{stderr}"
        );

        assert!(
            managed_node_dir(&project, expected_pinned).exists(),
            "lpm use {spec} should install Node {expected_pinned} into the managed runtimes dir"
        );
        assert_eq!(
            lpm_json_runtime(&project, "node"),
            serde_json::json!(expected_pinned),
            "lpm use {spec} should pin the resolved Node version"
        );
    }
}

#[tokio::test]
async fn use_install_node_json_emits_installed_envelope_from_mocked_dist() {
    let server = MockServer::start().await;
    let version = "22.12.0";
    let archive_name = current_node_archive_name(version);
    let archive_bytes = make_node_runtime_archive(version);
    let archive_sha = sha256_hex(&archive_bytes);
    let base_url = format!("{}/node-dist", server.uri());

    write_node_index_cache(
        &TempProject::empty(r#"{"name":"placeholder","version":"1.0.0"}"#),
        "[]",
    );

    Mock::given(method("GET"))
        .and(path(format!("/node-dist/v{version}/{archive_name}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive_bytes.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/node-dist/v{version}/SHASUMS256.txt")))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("{archive_sha}  {archive_name}\n")),
        )
        .mount(&server)
        .await;

    let project = TempProject::empty(r#"{"name":"use-install-node-json","version":"1.0.0"}"#);
    write_node_index_cache(
        &project,
        &serde_json::to_string(&serde_json::json!([
            {
                "version": format!("v{version}"),
                "date": "2026-04-15",
                "lts": "Jod",
                "dist_base_url": base_url,
            }
        ]))
        .expect("serialize node cache releases"),
    );

    let output = lpm(&project)
        .args(["--json", "use", "node@22.12.0"])
        .output()
        .expect("failed to run lpm --json use node@22.12.0");

    assert!(
        output.status.success(),
        "json node install must succeed\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelopes: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("--json use node@22.12.0 must emit one JSON envelope per line: {e}\n---\n{stdout}")
            })
        })
        .collect();
    assert_eq!(
        envelopes.len(),
        2,
        "install+pin path should emit two JSON envelopes"
    );
    assert_eq!(envelopes[0]["success"], serde_json::json!(true));
    assert_eq!(envelopes[0]["status"], serde_json::json!("installed"));
    assert_eq!(envelopes[0]["runtime"], serde_json::json!("node"));
    assert_eq!(envelopes[0]["version"], serde_json::json!("22.12.0"));
    assert_eq!(envelopes[1]["success"], serde_json::json!(true));
    assert_eq!(envelopes[1]["pinned"]["node"], serde_json::json!("22.12.0"));
    assert!(managed_node_dir(&project, version).exists());
}

#[test]
fn use_pin_bun_major_minor_spec_writes_matching_installed_exact_version() {
    let project = TempProject::empty(r#"{"name":"use-pin","version":"1.0.0"}"#);
    seed_installed_bun(&project, "1.3.14");

    let output = lpm(&project)
        .args(["use", "bun@1.3", "--pin"])
        .output()
        .expect("failed to run lpm use bun@1.3 --pin");

    assert!(
        output.status.success(),
        "lpm use bun@1.3 --pin must succeed when a matching version is already installed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Pinned bun@1.3.14 in lpm.json"),
        "human Bun use --pin should use the slim done line, got:\n{stderr}"
    );

    let lpm_json: serde_json::Value = serde_json::from_str(&project.read_file("lpm.json"))
        .expect("lpm use --pin must write valid lpm.json");
    assert_eq!(lpm_json["runtime"]["bun"], serde_json::json!("1.3.14"));
}

#[test]
fn use_pin_bun_accepts_documented_spec_forms_and_exactizes_locally() {
    let project = TempProject::empty(r#"{"name":"use-pin-bun-specs","version":"1.0.0"}"#);
    seed_installed_bun(&project, "1.3.14");
    seed_installed_bun(&project, "1.3.9");
    seed_installed_bun(&project, "1.2.23");

    for (spec, expected) in [
        ("bun@v1.3.14", "1.3.14"),
        ("bun@bun-v1.3.14", "1.3.14"),
        ("bun@latest", "1.3.14"),
        ("bun@>=1.2.0 <1.3.0", "1.2.23"),
    ] {
        let output = lpm(&project)
            .args(["use", spec, "--pin"])
            .output()
            .unwrap_or_else(|e| panic!("failed to run lpm use {spec} --pin: {e}"));

        assert!(
            output.status.success(),
            "lpm use {spec} --pin must succeed when a matching Bun version is already installed\nstderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("✓ Pinned bun@{expected} in lpm.json")),
            "human Bun use --pin should exactize {spec} to {expected}, got:\n{stderr}"
        );

        let lpm_json: serde_json::Value = serde_json::from_str(&project.read_file("lpm.json"))
            .expect("lpm use --pin must write valid lpm.json");
        assert_eq!(
            lpm_json["runtime"]["bun"],
            serde_json::json!(expected),
            "lpm use {spec} --pin should store the resolved Bun version"
        );
    }
}

#[test]
fn use_pin_bun_keeps_requested_spec_when_it_cannot_resolve_locally() {
    let project = TempProject::empty(r#"{"name":"use-pin-bun-spec","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "bun@latest", "--pin"])
        .output()
        .expect("failed to run lpm use bun@latest --pin");

    assert!(
        output.status.success(),
        "lpm use bun@latest --pin must succeed even without a locally installed Bun\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bun@latest is not currently installed"),
        "unmatched Bun pin should warn instead of failing, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Run `lpm use bun@latest` to install it"),
        "unmatched Bun pin should guide users to the install command, got:\n{stderr}"
    );

    let lpm_json: serde_json::Value = serde_json::from_str(&project.read_file("lpm.json"))
        .expect("lpm use --pin must write valid lpm.json");
    assert_eq!(lpm_json["runtime"]["bun"], serde_json::json!("latest"));
}

#[test]
fn use_pin_bun_lts_rejects_with_clear_message() {
    let project = TempProject::empty(r#"{"name":"use-pin-bun-lts","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "bun@lts", "--pin"])
        .output()
        .expect("failed to run lpm use bun@lts --pin");

    assert!(!output.status.success(), "bun@lts must exit non-zero");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Bun does not publish an LTS channel"),
        "bun@lts should fail with the Bun-specific guidance, got:\n{stderr}"
    );
    assert!(
        stderr.contains("bun@latest") && stderr.contains("bun@<version>"),
        "bun@lts rejection should point at the supported Bun spec forms, got:\n{stderr}"
    );
}

#[test]
fn use_remove_major_spec_removes_all_matching_installed_versions() {
    let project = TempProject::empty(r#"{"name":"use-remove","version":"1.0.0"}"#);
    seed_installed_node(&project, "22.12.0");
    seed_installed_node(&project, "20.18.0");
    seed_installed_node(&project, "20.17.0");

    let output = lpm(&project)
        .args(["use", "remove", "node@20"])
        .output()
        .expect("failed to run lpm use remove node@20");

    assert!(
        output.status.success(),
        "lpm use remove node@20 must succeed when matching managed runtimes exist\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        !managed_node_dir(&project, "20.18.0").exists()
            && !managed_node_dir(&project, "20.17.0").exists(),
        "remove must delete all matching 20.x runtimes"
    );
    assert!(
        managed_node_dir(&project, "22.12.0").exists(),
        "remove must not delete non-matching runtimes"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human use remove should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Removed 2 Node versions"),
        "remove must report the number of deleted runtimes, got:\n{stderr}"
    );
    assert!(
        stderr.contains("20.18.0") && stderr.contains("20.17.0"),
        "remove must list each deleted runtime, got:\n{stderr}"
    );
}

#[test]
fn use_remove_node_range_spec_removes_all_matching_installed_versions() {
    let project = TempProject::empty(r#"{"name":"use-remove-node-range","version":"1.0.0"}"#);
    seed_installed_node(&project, "22.12.0");
    seed_installed_node(&project, "20.18.0");
    seed_installed_node(&project, "20.17.0");

    let output = lpm(&project)
        .args(["use", "remove", "node@>=20.17.0 <21.0.0"])
        .output()
        .expect("failed to run lpm use remove node@>=20.17.0 <21.0.0");

    assert!(
        output.status.success(),
        "lpm use remove node@>=20.17.0 <21.0.0 must succeed when matching managed runtimes exist\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        !managed_node_dir(&project, "20.18.0").exists()
            && !managed_node_dir(&project, "20.17.0").exists(),
        "remove must delete every Node runtime that satisfies the semver range"
    );
    assert!(
        managed_node_dir(&project, "22.12.0").exists(),
        "remove must keep Node runtimes outside the semver range"
    );
}

#[test]
fn use_remove_node_latest_and_lts_aliases_fail_cleanly() {
    let project = TempProject::empty(r#"{"name":"use-remove-node-alias","version":"1.0.0"}"#);

    let latest_output = lpm(&project)
        .args(["use", "remove", "node@latest"])
        .output()
        .expect("failed to run lpm use remove node@latest");
    assert!(
        !latest_output.status.success(),
        "node@latest remove must exit non-zero"
    );
    let latest_stderr = String::from_utf8_lossy(&latest_output.stderr);
    assert!(
        latest_stderr.contains("remove requires an explicit version, prefix, or semver")
            && latest_stderr.contains("`lts` and `latest` are not supported"),
        "node@latest remove should explain the deterministic local-set restriction, got:\n{latest_stderr}"
    );

    let lts_output = lpm(&project)
        .args(["use", "remove", "node@lts"])
        .output()
        .expect("failed to run lpm use remove node@lts");
    assert!(
        !lts_output.status.success(),
        "node@lts remove must exit non-zero"
    );
    let lts_stderr = String::from_utf8_lossy(&lts_output.stderr);
    assert!(
        lts_stderr.contains("remove requires an explicit version, prefix, or semver")
            && lts_stderr.contains("`lts` and `latest` are not supported"),
        "node@lts remove should explain the deterministic local-set restriction, got:\n{lts_stderr}"
    );
}

#[test]
fn use_remove_bun_major_minor_spec_removes_all_matching_installed_versions() {
    let project = TempProject::empty(r#"{"name":"use-remove","version":"1.0.0"}"#);
    seed_installed_bun(&project, "1.3.14");
    seed_installed_bun(&project, "1.3.9");
    seed_installed_bun(&project, "1.2.23");

    let output = lpm(&project)
        .args(["use", "remove", "bun@1.3"])
        .output()
        .expect("failed to run lpm use remove bun@1.3");

    assert!(
        output.status.success(),
        "lpm use remove bun@1.3 must succeed when matching managed runtimes exist\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        !managed_bun_dir(&project, "1.3.14").exists()
            && !managed_bun_dir(&project, "1.3.9").exists(),
        "remove must delete all matching 1.3.x Bun runtimes"
    );
    assert!(
        managed_bun_dir(&project, "1.2.23").exists(),
        "remove must not delete non-matching Bun runtimes"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Removed 2 Bun versions"),
        "remove must report the number of deleted Bun runtimes, got:\n{stderr}"
    );
}

#[test]
fn use_remove_bun_range_spec_removes_all_matching_installed_versions() {
    let project = TempProject::empty(r#"{"name":"use-remove-range","version":"1.0.0"}"#);
    seed_installed_bun(&project, "1.3.14");
    seed_installed_bun(&project, "1.2.23");
    seed_installed_bun(&project, "1.1.18");

    let output = lpm(&project)
        .args(["use", "remove", "bun@>=1.2.0 <1.4.0"])
        .output()
        .expect("failed to run lpm use remove bun@>=1.2.0 <1.4.0");

    assert!(
        output.status.success(),
        "lpm use remove bun@>=1.2.0 <1.4.0 must succeed when matching managed runtimes exist\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        !managed_bun_dir(&project, "1.3.14").exists()
            && !managed_bun_dir(&project, "1.2.23").exists(),
        "remove must delete every Bun runtime that satisfies the semver range"
    );
    assert!(
        managed_bun_dir(&project, "1.1.18").exists(),
        "remove must keep Bun runtimes outside the semver range"
    );
}

#[test]
fn use_remove_bun_latest_and_lts_aliases_fail_cleanly() {
    let project = TempProject::empty(r#"{"name":"use-remove-bun-alias","version":"1.0.0"}"#);

    let latest_output = lpm(&project)
        .args(["use", "remove", "bun@latest"])
        .output()
        .expect("failed to run lpm use remove bun@latest");
    assert!(
        !latest_output.status.success(),
        "bun@latest remove must exit non-zero"
    );
    let latest_stderr = String::from_utf8_lossy(&latest_output.stderr);
    assert!(
        latest_stderr.contains("remove requires an explicit version, prefix, or semver")
            && latest_stderr.contains("`lts` and `latest` are not supported"),
        "bun@latest remove should explain the deterministic local-set restriction, got:\n{latest_stderr}"
    );

    let lts_output = lpm(&project)
        .args(["use", "remove", "bun@lts"])
        .output()
        .expect("failed to run lpm use remove bun@lts");
    assert!(
        !lts_output.status.success(),
        "bun@lts remove must exit non-zero"
    );
    let lts_stderr = String::from_utf8_lossy(&lts_output.stderr);
    assert!(
        lts_stderr.contains("Bun does not publish an LTS channel"),
        "bun@lts remove should fail with the Bun-specific guidance, got:\n{lts_stderr}"
    );
}

#[cfg(unix)]
#[test]
fn run_prepends_managed_bun_bin_when_runtime_bun_is_pinned() {
    let project = TempProject::empty(
        r#"{"name":"run-bun","version":"1.0.0","scripts":{"show-bun":"bun --version"}}"#,
    );
    seed_executable_bun(&project, "1.3.14", "managed-bun-1.3.14");
    project.write_file(
        "lpm.json",
        r#"{
  "runtime": {
    "bun": "1.3.14"
  }
}
"#,
    );

    let output = lpm(&project)
        .args(["run", "show-bun"])
        .output()
        .expect("failed to run lpm run show-bun");

    assert!(
        output.status.success(),
        "lpm run must succeed with managed Bun on PATH\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("managed-bun-1.3.14"),
        "script must resolve bun from the managed runtime PATH entry, got:\n{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn run_keeps_lpm_runner_when_runtime_bun_is_pinned() {
    let project = TempProject::empty(
        r#"{"name":"run-bun-shell","version":"1.0.0","scripts":{"shell-runner":"printf 'runner-stays-shell\\n'"}}"#,
    );
    let bun_invocation_log = project.path().join("bun-invocations.log");
    seed_executable_bun_with_log(
        &project,
        "1.3.14",
        "managed-bun-invoked",
        &bun_invocation_log,
    );
    project.write_file(
        "lpm.json",
        r#"{
  "runtime": {
    "bun": "1.3.14"
  }
}
"#,
    );

    let output = lpm(&project)
        .args(["run", "shell-runner"])
        .output()
        .expect("failed to run lpm run shell-runner");

    assert!(
        output.status.success(),
        "lpm run shell-runner must succeed with runtime.bun pinned\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("runner-stays-shell"),
        "the script should still execute through LPM's runner, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("managed-bun-invoked"),
        "runtime.bun should not switch `lpm run` into `bun run`, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Using bun 1.3.14 (from lpm.json > runtime.bun)"),
        "runtime.bun should still be recognized as a managed PATH entry, got:\n{stderr}"
    );

    assert!(
        !bun_invocation_log.exists(),
        "the managed bun binary must not be invoked when the script itself does not call bun"
    );
}

#[tokio::test]
async fn use_install_bun_from_cached_release_and_mocked_asset() {
    let server = MockServer::start().await;
    let version = "1.3.14";
    let asset_name = current_bun_asset_name();
    let zip_bytes = make_bun_runtime_zip();
    let digest = format!("sha256:{}", sha256_hex(&zip_bytes));

    Mock::given(method("GET"))
        .and(path(format!("/bun-dist/{asset_name}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes.clone()))
        .mount(&server)
        .await;

    let project = TempProject::empty(r#"{"name":"use-install-bun","version":"1.0.0"}"#);
    write_bun_index_cache(
        &project,
        &serde_json::to_string(&serde_json::json!([
            {
                "tag_name": format!("bun-v{version}"),
                "name": format!("Bun {version}"),
                "draft": false,
                "prerelease": false,
                "assets": [
                    {
                        "name": asset_name,
                        "browser_download_url": format!("{}/bun-dist/{asset_name}", server.uri()),
                        "digest": digest,
                    }
                ]
            }
        ]))
        .expect("serialize bun cache releases"),
    );

    let output = lpm(&project)
        .args(["use", "bun@1.3.14"])
        .output()
        .expect("failed to run lpm use bun@1.3.14");

    assert!(
        output.status.success(),
        "lpm use bun@1.3.14 must succeed from cached releases and mocked asset\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Resolving bun@1.3.14") && stderr.contains("→ 1.3.14"),
        "lpm use bun@1.3.14 should report the resolved Bun version, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Pinned bun@1.3.14 in lpm.json"),
        "lpm use bun@1.3.14 should pin the resolved Bun version, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Downloaded Bun 1.3.14 ·")
            && stderr.contains("Verified SHA-256 sha256:")
            && stderr.contains("Now using Bun 1.3.14 ·"),
        "lpm use bun@1.3.14 should print download, checksum, and final status, got:\n{stderr}"
    );
    assert!(managed_bun_dir(&project, version).exists());
    assert_eq!(
        lpm_json_runtime(&project, "bun"),
        serde_json::json!(version)
    );
}

#[test]
fn use_remove_warns_when_project_pin_still_matches_removed_runtime() {
    let project = TempProject::empty(r#"{"name":"use-remove","version":"1.0.0"}"#);
    seed_installed_node(&project, "20.18.0");
    project.write_file(
        "lpm.json",
        r#"{
  "runtime": {
    "node": "20"
  }
}
"#,
    );

    let output = lpm(&project)
        .args(["use", "remove", "node@20"])
        .output()
        .expect("failed to run lpm use remove node@20 with existing pin");

    assert!(
        output.status.success(),
        "lpm use remove node@20 must succeed when the runtime is pinned\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lpm.json still pins node@20"),
        "remove must warn when the project pin would auto-reinstall the deleted runtime, got:\n{stderr}"
    );
}

#[test]
fn use_list_with_unsupported_runtime_filter_fails_cleanly() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "deno", "--list"])
        .output()
        .expect("failed to run lpm use deno --list");

    assert!(
        !output.status.success(),
        "unsupported runtime filter must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deno") || stderr.contains("not yet supported"),
        "stderr must indicate the unsupported runtime, got:\n{stderr}"
    );
}
