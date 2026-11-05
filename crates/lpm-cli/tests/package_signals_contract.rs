//! **Tier placement: cli-binary.** Justification class: **intentionally
//! minimal binary-surface repro**. `lpm internal-package-signals` is a hidden
//! helper a registry runs as a subprocess, feeding a release's tarball on
//! stdin and reading one JSON document from stdout. These tests pin that
//! stdin / stdout / exit-code contract, and that the helper writes nothing,
//! which the workflow harness's project setup would hide.

mod common;

use std::io::Write as _;
use std::process::{Output, Stdio};
use tempfile::TempDir;

fn release_tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    for (path, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        builder
            .append_data(&mut header, format!("package/{path}"), *content)
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// Runs the helper in empty directories, feeding `input` on stdin, and
/// checks it left both empty. The update check and telemetry stay enabled,
/// so a write from either would show.
fn package_signals(args: &[&str], input: &[u8]) -> Output {
    let project = TempDir::new().unwrap();
    let lpm_home = TempDir::new().unwrap();
    let mut command_args = vec!["internal-package-signals"];
    command_args.extend_from_slice(args);
    let mut child = common::lpm_command(project.path(), lpm_home.path(), None, &command_args)
        .env_remove("LPM_NO_UPDATE_CHECK")
        .env_remove("LPM_DISABLE_TELEMETRY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lpm-rs");
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    for directory in [project.path(), lpm_home.path()] {
        let written: Vec<_> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert!(written.is_empty(), "the helper wrote {written:?}");
    }
    output
}

#[test]
fn prints_the_release_signals_as_one_json_document() {
    let tarball = release_tarball(&[
        (
            "package.json",
            br#"{"name":"kit","version":"1.0.0","license":"MIT","main":"lib/index.js","dependencies":{"left":"*"}}"#,
        ),
        (
            "lib/index.js",
            b"const url = \"https://api.example.com/v1\"\nmodule.exports = input => eval(input)\n",
        ),
        (
            "test/run.test.js",
            br#"require("child_process").spawn("node")"#,
        ),
        ("binding.gyp", br#"{"targets":[]}"#),
    ]);

    let output = package_signals(&[], &tarball);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    let mut document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        document["lpmVersion"]
            .as_str()
            .is_some_and(|version| !version.is_empty())
    );
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["tags"]["eval"], true);
    assert_eq!(document["tags"]["childProcess"], true);
    assert_eq!(
        document["testOnlyTags"],
        serde_json::json!(["childProcess"])
    );
    assert_eq!(document["tagFiles"]["childProcess"]["testsOnly"], true);
    assert_eq!(document["evalCalls"], 1);
    assert_eq!(document["coverage"]["complete"], true);
    document["lpmVersion"] = serde_json::json!("[version]");
    insta::assert_json_snapshot!("release_signals", document);
}

#[test]
fn reads_the_sources_of_the_ecosystem_it_is_given() {
    let tarball = release_tarball(&[
        ("Sources/Kit/Kit.swift", b"let kit = 1"),
        ("scripts/build.js", b"eval(code)"),
    ]);

    let output = package_signals(&["--ecosystem", "swift"], &tarball);

    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["tags"]["eval"], false);
    assert_eq!(document["coverage"]["sourceFiles"], 1);
    assert_eq!(document["coverage"]["manifest"], false);
}

#[test]
fn reads_a_source_nested_deeper_than_any_stack_without_aborting() {
    let nested = format!("x={}eval(y){};", "[".repeat(20_000), "]".repeat(20_000));
    let tarball = release_tarball(&[
        ("package.json", br#"{"name":"kit","license":"MIT"}"#),
        ("index.js", nested.as_bytes()),
    ]);

    let output = package_signals(&[], &tarball);

    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["tags"]["eval"], true);
    assert_eq!(document["coverage"]["sourceFiles"], 1);
}

#[test]
fn reads_files_past_the_first_gzip_member() {
    let first = release_tarball(&[("package.json", br#"{"name":"kit","license":"MIT"}"#)]);
    let second = release_tarball(&[("lib/run.js", br#"require("child_process").exec(cmd)"#)]);

    let output = package_signals(&[], &[first, second].concat());

    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["tags"]["childProcess"], true);
    assert_eq!(document["coverage"]["manifest"], true);
}

#[test]
fn reports_input_that_is_not_a_release_tarball_as_a_json_error() {
    let output = package_signals(&[], b"not a tarball");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["success"], false);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );
}

#[test]
fn reports_a_usage_error_as_the_json_usage_envelope() {
    let output = package_signals(&["--ecosystem", "go"], b"");

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let error: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|parse| panic!("usage error must be JSON ({parse}): {output:?}"));
    assert_eq!(error["success"], false);
    assert_eq!(error["error_code"], "usage");
    assert_eq!(error["value"], "go");
    assert_eq!(
        error["valid_values"],
        serde_json::json!(["js", "swift", "rust", "python"])
    );
}

#[test]
fn stays_out_of_help() {
    let project = TempDir::new().unwrap();
    let lpm_home = TempDir::new().unwrap();
    let (status, stdout, _) = common::run_lpm(project.path(), lpm_home.path(), None, &["--help"]);

    assert!(status.success());
    assert!(!stdout.contains("internal-package-signals"));
}
