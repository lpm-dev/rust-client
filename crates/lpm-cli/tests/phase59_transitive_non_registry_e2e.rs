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
        .join("lpm-phase59-transitive-non-registry-e2e")
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
fn transitive_tarball_url_is_rejected_before_resolver() {
    let project = project_dir("transitive-tarball-url");

    write_manifest(
        &project,
        r#"{
  "name": "phase59-transitive-tarball-url",
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
    "bar": "https://example.com/bar.tgz"
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
        "install should fail for unsupported transitive tarball URL:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr,
    );

    let source_dir = source_dir.canonicalize().unwrap();
    assert!(
        out.stderr.contains("transitive non-registry dep `bar`"),
        "stderr must mention the offending dep name, got:\n{}",
        out.stderr,
    );
    assert!(
        stderr_compact.contains("https://example.com/bar.tgz"),
        "stderr must include the raw offending spec, got:\n{}",
        out.stderr,
    );
    assert!(
        out.stderr.contains("tarball URL"),
        "stderr must categorize the unsupported shape, got:\n{}",
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
        stderr_compact.contains("hoistthedeptoyourproject'spackage.json"),
        "stderr must include the workaround hint, got:\n{}",
        out.stderr,
    );
    assert!(
        !out.stderr.contains("invalid semver range"),
        "failure must happen before resolver range parsing, got:\n{}",
        out.stderr,
    );
}
