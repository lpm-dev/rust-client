//! **Phase 59.1 audit response — round 3 fresh-binary regression.**
//!
//! Reproduces the auditor's HIGH finding: a `workspace:` spec inside a
//! local file/link source's transitive `package.json` would crash the
//! resolver with `invalid version range: invalid range 'workspace:'`
//! because `extract_workspace_protocol_deps` only ran on the top-level
//! manifest, while `recurse_local_source_deps` appended raw transitive
//! specs to the consumer's deps map AFTER that pass.
//!
//! Post-fix, the install must fail BEFORE the resolver — at the
//! `recurse_local_source_deps` boundary — with a typed
//! `LpmError::Workspace` carrying the dep name, raw spec, source dir,
//! and an explanation of why no member matched.
//!
//! Mirrors the round-2 `phase59_transitive_non_registry_e2e.rs`
//! pattern: spawn the real `lpm-rs` binary, normalize wrapped miette
//! output for substring matching, assert positive markers AND the
//! negative "invalid range" assertion.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-phase59-workspace-transitive-e2e")
        .join(format!("{name}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_manifest(dir: &Path, body: &str) {
    fs::write(dir.join("package.json"), body).unwrap();
}

fn run_lpm(cwd: &Path, args: &[&str]) -> CommandOutput {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    fs::create_dir_all(&home).unwrap();

    let output = Command::new(exe)
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env("LPM_REGISTRY_URL", "http://127.0.0.1:1")
        .env_remove("LPM_TOKEN")
        .env_remove("NPM_TOKEN")
        .output()
        .expect("failed to spawn lpm-rs");

    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

#[test]
fn transitive_workspace_protocol_is_rejected_before_resolver() {
    let project = project_dir("transitive-workspace");

    // Non-workspace consumer project — no `workspaces` field — that
    // depends on a local file: source. The local source's manifest
    // declares a `workspace:*` transitive. Pre-fix the workspace
    // protocol extractor would have run only on the top-level manifest
    // (which has no workspace: deps), the walker would have appended
    // `bar=workspace:*` to the consumer deps map, and the resolver
    // would have crashed.
    write_manifest(
        &project,
        r#"{
  "name": "phase59-r3-workspace-transitive",
  "version": "1.0.0",
  "dependencies": {
    "foo": "file:./packages/foo"
  }
}"#,
    );

    let source_dir = project.join("packages").join("foo");
    fs::create_dir_all(&source_dir).unwrap();
    write_manifest(
        &source_dir,
        r#"{
  "name": "foo",
  "version": "1.0.0",
  "dependencies": {
    "bar": "workspace:^1.0.0"
  }
}"#,
    );

    let out = run_lpm(
        &project,
        &[
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ],
    );
    let stderr_compact: String = out
        .stderr
        .chars()
        .filter(|c| c.is_ascii() && !c.is_whitespace())
        .collect();

    assert!(
        !out.status.success(),
        "install must fail for unsupported transitive workspace: dep:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    let source_dir = source_dir.canonicalize().unwrap();
    assert!(
        out.stderr.contains("transitive `workspace:` dep `bar`"),
        "stderr must categorize the transitive workspace: failure and name the dep:\n{}",
        out.stderr,
    );
    assert!(
        stderr_compact.contains("workspace:^1.0.0"),
        "stderr must include the raw workspace: spec, got:\n{}",
        out.stderr,
    );
    assert!(
        out.stderr.contains("not a workspace"),
        "stderr must explain that the consumer project isn't a workspace, got:\n{}",
        out.stderr,
    );
    assert!(
        stderr_compact.contains(
            &source_dir
                .display()
                .to_string()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        ),
        "stderr must point at the local source directory, got:\n{}",
        out.stderr,
    );
    assert!(
        !out.stderr.contains("invalid range") && !out.stderr.contains("invalid version range"),
        "failure must happen BEFORE resolver range parsing — the auditor's exact \
         repro was a resolver crash on `invalid range 'workspace:'`. Got:\n{}",
        out.stderr,
    );
}
