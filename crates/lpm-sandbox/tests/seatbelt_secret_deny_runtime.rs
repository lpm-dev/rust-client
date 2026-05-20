//! Backend runtime gate: under the default Seatbelt sandbox, a
//! lifecycle script reading `<project>/.env`, `<project>/.npmrc`,
//! or any `*.pem` file fails — even though the broader
//! `project_dir` read allow rule would otherwise permit those
//! reads. Pins SBPL last-match-wins semantics for the
//! `(deny file-read* ...)` block emitted by
//! [`seatbelt::render_secret_denies`].
//! Sibling of [`seccomp_socket_deny.rs`] — runs the sandbox
//! backend end-to-end (real `sandbox-exec` invocation) rather
//! than asserting profile-string shape. Catches a regression
//! where the rendered profile parses cleanly but doesn't fire
//! at enforcement time (Apple SBPL `#"..."` regex semantics,
//! literal canonicalisation, etc.).
//! macOS-only: Linux has no `sandbox-exec` analogue; the Linux
//! equivalent of this contract lives in
//! [`secret_overlay_bind_mount.rs`].

#![cfg(target_os = "macos")]

use lpm_sandbox::{
    SandboxMode, SandboxOptions, SandboxSpec, SandboxStdio, SandboxedCommand,
    new_for_platform_with_options,
};
use std::path::{Path, PathBuf};

/// Build a SandboxSpec rooted at `project_dir`. Mirrors the
/// `seccomp_socket_deny.rs` realistic-spec shape — uses real
/// `dirs::home_dir()` and `$TMPDIR` so the macOS Seatbelt
/// profile canonicalisation (which calls
/// `std::fs::canonicalize` on every base path) doesn't fail at
/// render time.
fn fixture_spec(project_dir: &Path) -> SandboxSpec {
    let home = dirs::home_dir().expect("home dir for test");
    let tmp = std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    SandboxSpec {
        package_dir: home.join(".lpm/store/testpkg@0.1.0"),
        project_dir: project_dir.to_path_buf(),
        package_name: "testpkg".into(),
        package_version: "0.1.0".into(),
        store_root: home.join(".lpm/store"),
        home_dir: home,
        tmpdir: tmp,
        secret_read_allow: Vec::new(),
        extra_write_dirs: Vec::new(),
    }
}

/// Spawn `/bin/cat <path>` through the default-mode Seatbelt
/// sandbox and return `(exit_code, stdout, stderr)`. The sandbox
/// is constructed per call so individual tests get isolated state.
fn cat_through_sandbox(project_dir: &Path, path_to_cat: &Path) -> (i32, Vec<u8>, Vec<u8>) {
    let spec = fixture_spec(project_dir);
    let options = SandboxOptions {
        allow_degraded: false,
        deny_outbound_network: false,
    };
    let sandbox = new_for_platform_with_options(spec, SandboxMode::Enforce, options)
        .expect("sandbox construction");

    let mut cmd = SandboxedCommand::new("/bin/cat");
    cmd.args.push(path_to_cat.into());
    cmd.stdout = SandboxStdio::Piped;
    cmd.stderr = SandboxStdio::Piped;

    let child = sandbox.spawn(cmd).expect("sandbox-exec spawn for /bin/cat");
    let output = child.wait_with_output().expect("collect /bin/cat output");

    (
        output.status.code().unwrap_or(-1),
        output.stdout,
        output.stderr,
    )
}

/// `<project>/.env` is on the literal deny list. `/bin/cat` must
/// fail (non-zero exit) and produce no stdout. Apple's SBPL
/// last-match-wins gates this — the deny block emitted after the
/// project_dir allow overrides the allow for the named path.
#[test]
fn seatbelt_denies_dotenv_at_project_root_at_runtime() {
    let project = tempfile::tempdir().expect("project tempdir");
    let env_path = project.path().join(".env");
    std::fs::write(&env_path, "API_KEY=actually-secret\n").expect("write .env");

    let (code, stdout, stderr) = cat_through_sandbox(project.path(), &env_path);

    assert_ne!(
        code,
        0,
        "/bin/cat must fail when reading project-rooted .env;\n\
         stdout = {:?}\n\
         stderr = {:?}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert!(
        stdout.is_empty(),
        "no stdout — the deny fired before read:\n{:?}",
        String::from_utf8_lossy(&stdout),
    );
}

/// `<project>/.npmrc` is on the literal deny list — pins the
/// auth-file convention beyond just `.env`.
#[test]
fn seatbelt_denies_npmrc_at_project_root_at_runtime() {
    let project = tempfile::tempdir().expect("project tempdir");
    let npmrc_path = project.path().join(".npmrc");
    std::fs::write(&npmrc_path, "//registry.npmjs.org/:_authToken=secret\n").expect("write .npmrc");

    let (code, stdout, _stderr) = cat_through_sandbox(project.path(), &npmrc_path);

    assert_ne!(code, 0, ".npmrc read must be denied by the sandbox");
    assert!(stdout.is_empty(), "no .npmrc bytes leak past the deny");
}

/// `*.pem` at any depth is denied via the derived-regex rule.
/// This is the load-bearing assertion that Apple SBPL's
/// `#"..."` regex literal parses `\.` as a literal dot (not as
/// an unescaped wildcard); a regression that interprets `\` as a
/// Scheme escape would turn the rule into `/.pem$` which still
/// denies but for the wrong reason. The non-secret assertion
/// below pins the opposite direction.
#[test]
fn seatbelt_denies_pem_files_via_regex_at_runtime() {
    let project = tempfile::tempdir().expect("project tempdir");
    let pem_path = project.path().join("cert.pem");
    std::fs::write(
        &pem_path,
        "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
    )
    .expect("write cert.pem");

    let (code, stdout, _stderr) = cat_through_sandbox(project.path(), &pem_path);

    assert_ne!(code, 0, "*.pem read must be denied by the regex rule");
    assert!(stdout.is_empty(), "no .pem bytes leak past the deny");
}

/// Nested `*.pem` — exercises the `^...<project>/.*\.pem$`
/// anchored regex's `.*` consuming intermediate path components.
#[test]
fn seatbelt_denies_pem_at_nested_depth_via_regex_at_runtime() {
    let project = tempfile::tempdir().expect("project tempdir");
    let nested = project.path().join("infra").join("certs");
    std::fs::create_dir_all(&nested).expect("create nested dir");
    let pem_path = nested.join("prod.pem");
    std::fs::write(&pem_path, "fake-cert").expect("write nested .pem");

    let (code, stdout, _stderr) = cat_through_sandbox(project.path(), &pem_path);

    assert_ne!(
        code, 0,
        "*.pem must be denied even when nested several directories deep"
    );
    assert!(stdout.is_empty());
}

/// `<project>/.aws/credentials` is denied via the subpath rule
/// for `.aws/`. Pins the subpath-style deny for credential dirs.
#[test]
fn seatbelt_denies_aws_credentials_via_subpath_at_runtime() {
    let project = tempfile::tempdir().expect("project tempdir");
    let aws_dir = project.path().join(".aws");
    std::fs::create_dir(&aws_dir).expect("create .aws/");
    let creds = aws_dir.join("credentials");
    std::fs::write(&creds, "[default]\naws_access_key_id=...").expect("write creds");

    let (code, stdout, _stderr) = cat_through_sandbox(project.path(), &creds);

    assert_ne!(
        code, 0,
        ".aws/ subpath deny must cover every file inside (credentials, config, ...)"
    );
    assert!(stdout.is_empty());
}

/// Symmetry: a non-secret project file (`hello.txt`) is NOT
/// denied — `/bin/cat` succeeds and emits the file contents.
/// Pins the negative side of the contract — the deny block
/// scopes only to the known secret conventions, not to every
/// project file. A regression that broadens the deny to
/// arbitrary project paths would fail this assertion.
#[test]
fn seatbelt_does_not_deny_non_secret_project_files_at_runtime() {
    let project = tempfile::tempdir().expect("project tempdir");
    let src_path = project.path().join("hello.txt");
    let expected = "hello, world\n";
    std::fs::write(&src_path, expected).expect("write hello.txt");

    let (code, stdout, stderr) = cat_through_sandbox(project.path(), &src_path);

    assert_eq!(
        code,
        0,
        "non-secret project file must remain readable; stderr = {:?}",
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        expected,
        "full contents of hello.txt must reach stdout — the deny block must not over-match"
    );
}

/// opt-in: when the user lists `.env` in
/// `secret_read_allow`, the allow-override block emitted after
/// the deny restores read access. End-to-end gate that the
/// override mechanism actually works at the kernel layer (not
/// just at profile-render time).
#[test]
fn seatbelt_secret_read_allow_restores_dotenv_at_runtime() {
    let project = tempfile::tempdir().expect("project tempdir");
    let env_path = project.path().join(".env");
    let expected = "DATABASE_URL=postgres://example\n";
    std::fs::write(&env_path, expected).expect("write .env");

    // Build a spec that exempts `.env` via secret_read_allow.
    // The canonicalized path must match what the kernel sees at
    // enforcement time — Seatbelt's tempdir on macOS resolves
    // through /private, so use `canonicalize` to mirror the
    // backend's own canonicalisation.
    let mut spec = fixture_spec(project.path());
    spec.secret_read_allow =
        vec![std::fs::canonicalize(&env_path).expect("canonicalize allowed .env")];

    let options = SandboxOptions {
        allow_degraded: false,
        deny_outbound_network: false,
    };
    let sandbox = new_for_platform_with_options(spec, SandboxMode::Enforce, options)
        .expect("sandbox construction");

    let mut cmd = SandboxedCommand::new("/bin/cat");
    cmd.args.push(env_path.into());
    cmd.stdout = SandboxStdio::Piped;
    cmd.stderr = SandboxStdio::Piped;
    let child = sandbox.spawn(cmd).expect("spawn");
    let output = child.wait_with_output().expect("collect");

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "the secret_read_allow override must restore read access; stderr = {:?}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected,
        "full .env contents must reach stdout when the file is on the override list"
    );
}
