//! End-to-end coverage for the unknown-protocol parser guard
//! (defaults-fixes #2).
//!
//! Pre-fix, a `package.json` dependency entry with an unknown protocol
//! (`magic:bar`, `filee:./foo`, ...) silently slipped through
//! `Specifier::parse` as a SemverRange. The resolver then tried to
//! resolve it as a dist-tag and failed with "no version found for tag
//! 'magic:bar'" — the user couldn't tell that the actual problem was a
//! malformed protocol prefix.
//!
//! Post-fix, the install preflight surfaces a helpful error naming the
//! supported protocols and (when applicable) suggesting the
//! Levenshtein-nearest known prefix.

mod support;

use support::{TempProject, lpm};

fn manifest_with_dep(name: &str, spec: &str) -> String {
    format!(r#"{{"name":"specifier-test","version":"1.0.0","dependencies":{{"{name}":"{spec}"}}}}"#)
}

#[test]
fn install_rejects_unknown_protocol_with_supported_list() {
    let project = TempProject::empty(&manifest_with_dep("badpkg", "magic:bar"));

    let output = lpm(&project)
        .arg("install")
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "install must fail on unknown protocol; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("magic:"),
        "error must surface the offending prefix, got:\n{combined}"
    );
    assert!(
        combined.contains("unknown package specifier protocol"),
        "error must use the canonical phrasing, got:\n{combined}"
    );
    // No "did you mean" suggestion — `magic` is too far from any known
    // protocol prefix.
    assert!(
        !combined.to_lowercase().contains("did you mean"),
        "must omit 'did you mean' when no close match, got:\n{combined}"
    );
}

#[test]
fn install_suggests_file_for_filee_typo() {
    let project = TempProject::empty(&manifest_with_dep("local", "filee:./pkg"));

    let output = lpm(&project)
        .arg("install")
        .output()
        .expect("failed to run lpm install");

    assert!(!output.status.success(), "install must fail on filee:");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("filee:"),
        "error must surface the typo, got:\n{combined}"
    );
    assert!(
        combined.contains("Did you mean 'file:'"),
        "Levenshtein suggestion must point to 'file:', got:\n{combined}"
    );
}

// ─── CLI argv path (GPT-audit follow-up) ─────────────────────────────────────
//
// Pre-fix the manifest-side parser guard didn't cover the explicit-token CLI
// path: `lpm install foo@magic:bar` ran through `save_spec::classify_version_token`
// which fell through to `UserSaveIntent::DistTag("magic:bar")`. The resolver
// then silently installed `foo@latest` and rewrote `package.json` to
// `"foo": "^1.0.0"` — silent corruption worse than the original confusing error.

#[test]
fn cli_install_argv_rejects_unknown_protocol_token() {
    let project = TempProject::empty(r#"{"name":"cli-protocol-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["install", "foo@magic:bar"])
        .output()
        .expect("failed to run lpm install foo@magic:bar");

    assert!(
        !output.status.success(),
        "install must fail on argv token `foo@magic:bar`, not silently install with placeholder; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("magic:"),
        "error must surface the offending prefix, got:\n{combined}"
    );
    assert!(
        combined.contains("unknown package specifier protocol"),
        "error must use the canonical phrasing, got:\n{combined}"
    );

    // Critical: package.json must NOT be mutated. Pre-fix this got
    // rewritten to `"foo": "^1.0.0"` (silent corruption).
    let pkg = project.read_file("package.json");
    assert!(
        !pkg.contains("\"foo\""),
        "package.json must NOT add 'foo' on a rejected protocol input, got: {pkg}"
    );
}

#[test]
fn cli_install_argv_suggests_file_for_filee_typo() {
    let project = TempProject::empty(r#"{"name":"cli-protocol-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["install", "foo@filee:./pkg"])
        .output()
        .expect("failed to run lpm install foo@filee:./pkg");

    assert!(
        !output.status.success(),
        "install must fail on `foo@filee:./pkg`"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("filee:"),
        "error must surface the typo, got:\n{combined}"
    );
    assert!(
        combined.contains("Did you mean 'file:'"),
        "Levenshtein suggestion must point to `file:`, got:\n{combined}"
    );
    let pkg = project.read_file("package.json");
    assert!(
        !pkg.contains("\"foo\""),
        "package.json must NOT add 'foo' on a rejected protocol typo, got: {pkg}"
    );
}

// Regression guard for `foo@latest` / `foo@beta` / `foo@next` lives at
// the unit-test layer:
// * `Specifier::parse` test arms confirm `latest`/`beta`/`next` resolve
//   to `SemverRange` (no `:` → protocol guard never fires).
// * `parse_user_save_intent("zod@latest")` test arm pins the
//   `DistTag` classification.
// Re-asserting here from a workflow test would either hit the registry
// or duplicate the unit coverage.

#[test]
fn install_rejects_windows_drive_letter_path_with_file_hint() {
    let project = TempProject::empty(&manifest_with_dep("badpath", r"C:\\path\\to\\dir"));

    let output = lpm(&project)
        .arg("install")
        .output()
        .expect("failed to run lpm install");

    assert!(
        !output.status.success(),
        "install must fail on bare drive letter"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("Windows drive-letter path"),
        "error must classify as Windows drive-letter, got:\n{combined}"
    );
    assert!(
        combined.contains("file:"),
        "error must hint at the `file:` prefix, got:\n{combined}"
    );
}
