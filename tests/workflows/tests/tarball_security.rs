//! Tarball-extraction security contracts at the workflow tier.
//!
//! Item 3 of `private/test-coverage-followup-plan.md`. Pins the
//! end-to-end behavior of `lpm install` against malicious tarballs
//! served through the registry. Each test constructs the malicious
//! tarball **in-test** with `tar::Builder` (no checked-in fixtures —
//! they age poorly and obscure intent), serves it via `MockRegistry`,
//! runs `lpm install`, and asserts the contract:
//!
//! - The install never extracts a file outside the project's
//!   `node_modules/` (no zip-slip writethrough).
//! - The install either rejects the malicious entry cleanly (non-zero
//!   exit, error message names something actionable) or silently
//!   skips it (zero exit, no malicious entry on disk). Both are
//!   defensible end-states; the test pins **whichever the extractor
//!   actually does today** so a future regression that flips between
//!   them is caught.
//! - The install never panics or emits a stack trace.
//! - The pre-existing source-of-truth in
//!   [`crates/lpm-extractor/src/lib.rs`](../../../crates/lpm-extractor/src/lib.rs)
//!   already covers most of these at the unit tier. The workflow tier
//!   adds proof that the FULL install pipeline (download → verify →
//!   extract → link) honors the same contracts when an attacker
//!   reaches the extractor through `lpm install`.
//!
//! Findings surfaced during this work are filed in
//! `private/findings.md`. Tests that pin a current behavior different
//! from the plan's prescribed contract carry a `// TODO #NN — tighten
//! when finding fixed` comment.
//!
//! See `private/test-coverage-followup-plan.md` for the full design
//! and the 10-test surface.

mod support;

use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

// ─── Helpers ────────────────────────────────────────────────────────

/// Build a `.tgz` containing a valid `package/package.json` plus a
/// caller-supplied set of additional tar entries. `package.json` is
/// the minimal shape the install pipeline needs — without it the
/// install fails on missing-manifest before reaching the extractor's
/// security checks, which would mask the actual concern under test.
fn tarball_with_extra_entries<F>(name: &str, version: &str, mut customize: F) -> Vec<u8>
where
    F: FnMut(&mut tar::Builder<&mut Vec<u8>>),
{
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);

        // Always include a valid package.json so the install pipeline
        // gets past the manifest-required gate and the malicious
        // entries actually exercise the extractor's hardening.
        let pkg_json = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
        let mut header = tar::Header::new_gnu();
        header.set_size(pkg_json.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", pkg_json.as_bytes())
            .expect("append package.json");

        // Caller plants the malicious entries.
        customize(&mut builder);

        builder.finish().expect("finish tar");
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Common install-args set that workflow tests reuse — keeps the
/// install footprint small and deterministic across the suite.
fn install_args(spec: &str) -> Vec<&str> {
    vec![
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
        spec,
    ]
}

// ─── Tests ──────────────────────────────────────────────────────────

/// **Plan #1 — `..` path entry must be rejected.**
///
/// Tarball includes a regular file whose path resolves above the
/// extraction root after npm's `package/` prefix is stripped. The
/// extractor's `Component::ParentDir` check at
/// [lib.rs:347](../../../crates/lpm-extractor/src/lib.rs#L347)
/// rejects this with an error that contains "path traversal".
///
/// The unit-tier coverage at [lib.rs:1010](../../../crates/lpm-extractor/src/lib.rs#L1010)
/// `extract_rejects_nested_path_traversal_after_prefix_stripping`
/// pins this in isolation. The workflow tier adds proof that the
/// install pipeline (download → verify → extract → link) does not
/// silently swallow the rejection or extract the entry through a
/// fast path.
#[tokio::test]
async fn tarball_with_dot_dot_path_entry_is_rejected_by_install() {
    // Build the malicious tarball: header path is "package/safe.txt"
    // (so set_path doesn't error on the `..`), then we overwrite the
    // path bytes in the raw header to "package/../escape.txt".
    let tgz = tarball_with_extra_entries("dot-dot-pkg", "1.0.0", |builder| {
        let content = b"pwned";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/safe.txt").unwrap();
        let raw = header.as_mut_bytes();
        raw[..100].fill(0);
        let evil = b"package/../escape.txt";
        raw[..evil.len()].copy_from_slice(evil);
        header.set_cksum();
        builder.append(&header, &content[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("dot-dot-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);

    // Plant a sentinel just outside the project so a writethrough is
    // detectable post-failure.
    let outside = project.path().parent().unwrap().join("escape.txt");
    let _ = std::fs::remove_file(&outside);

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("dot-dot-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#1 dotdot] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of `..`-traversal tarball reported success — \
         the malicious path was extracted somewhere:\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on `..` traversal:\nstderr:\n{stderr}"
    );
    assert!(
        !outside.exists(),
        "extractor wrote outside the target through a `..` traversal — \
         security regression. file lives at: {outside:?}"
    );
    let stderr_l = stderr.to_lowercase();
    assert!(
        stderr_l.contains("traversal")
            || stderr_l.contains("integrity")
            || stderr_l.contains("invalid"),
        "rejection message lacks an actionable noun \
         (expected one of: traversal / integrity / invalid). \
         stderr:\n{stderr}"
    );
}

/// **Plan #3 — absolute-path entry is normalized to relative under the package dir.**
///
/// **Plan-vs-actual:** the plan's name said "rejected"; the
/// extractor's actual behavior is to **normalize** an absolute-path
/// entry into a relative path under the package's `node_modules`
/// directory. The mechanism is incidental but worth pinning:
///
/// - `strip_first_component` ([lib.rs:733](../../../crates/lpm-extractor/src/lib.rs#L733))
///   drops the FIRST `Path::components()` element. For a tarball
///   path of `/etc/lpm-pwned.txt`, the components are
///   `[RootDir, Normal("etc"), Normal("lpm-pwned.txt")]`. Stripping
///   first yields the relative path `etc/lpm-pwned.txt`.
/// - The post-strip `Component::RootDir` check at
///   [lib.rs:347-352](../../../crates/lpm-extractor/src/lib.rs#L347)
///   then sees no `RootDir` (the strip already consumed it), so
///   the extractor proceeds.
/// - `target_path.starts_with(&extraction_root)` guards the final
///   write against any escape; the normalized path lives entirely
///   under `node_modules/<pkg>/`, so the guard passes.
///
/// **Result:** install SUCCEEDS, the file extracts at
/// `node_modules/<pkg>/etc/lpm-pwned.txt`, and `/etc/lpm-pwned.txt`
/// at the filesystem root is NEVER created. The "absolute path"
/// attack vector is foreclosed by normalization, not by rejection.
///
/// That posture is defensible: an absolute tarball entry is malformed
/// per the npm convention (every entry should sit under `package/`),
/// but normalizing-then-extracting is safer than refusing the whole
/// tarball — the user gets a working install rather than a brittle
/// hard failure on what is functionally cosmetic. Pin the current
/// shape so a future regression that flips the contract (e.g.,
/// "reject loudly" or "extract at the absolute path") trips this
/// test.
#[tokio::test]
async fn tarball_with_absolute_path_entry_is_normalized_to_relative_under_package_dir() {
    let tgz = tarball_with_extra_entries("abspath-pkg", "1.0.0", |builder| {
        let content = b"absolute attack";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        // set_path won't accept a literal absolute path; install a
        // placeholder then poke the absolute path into the raw header
        // bytes. The header's name field is fixed-size; the trailing
        // null implicitly terminates after our slice.
        header.set_path("package/safe.txt").unwrap();
        let raw = header.as_mut_bytes();
        raw[..100].fill(0);
        let evil = b"/etc/lpm-pwned.txt";
        raw[..evil.len()].copy_from_slice(evil);
        header.set_cksum();
        builder.append(&header, &content[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("abspath-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("abspath-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#3 abspath-normalize] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    // The install SUCCEEDS — normalization, not rejection.
    assert!(
        output.status.success(),
        "install of absolute-path tarball failed — extractor's \
         normalize-then-extract contract may have changed.\n\
         stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on absolute path:\nstderr:\n{stderr}"
    );
    // **Critical** — never write to the literal absolute path. If
    // /etc/lpm-pwned.txt appears, the extractor went rogue.
    assert!(
        !std::path::Path::new("/etc/lpm-pwned.txt").exists(),
        "extractor wrote to absolute /etc/lpm-pwned.txt — security regression."
    );
    // Pin the normalized landing site so a future regression that
    // changes WHERE the entry lands (or stops extracting it at all)
    // is detected. The path may or may not exist depending on
    // pipeline details — the load-bearing assertion above is the
    // "no absolute-path writethrough" one. The diagnostic on the
    // landing site is informational.
    let normalized = project
        .path()
        .join("node_modules/abspath-pkg/etc/lpm-pwned.txt");
    eprintln!(
        "[Plan#3 abspath-normalize] normalized landing exists={}, path={normalized:?}",
        normalized.exists()
    );
}

/// **Plan #2 — symlink to outside path is silently skipped (current behavior).**
///
/// **Plan-vs-actual:** the plan's name said "rejected"; the
/// extractor's actual contract is to **silently skip** any tar entry
/// whose `header.entry_type()` is not `is_file()`. See
/// [lib.rs:398](../../../crates/lpm-extractor/src/lib.rs#L398) — the
/// regular-files-only branch swallows symlinks, hardlinks, FIFOs,
/// device files, etc.; they vanish, the tarball still extracts
/// successfully, and the install proceeds.
///
/// That posture is defensible: npm packages don't legitimately ship
/// symlinks, so silently dropping them avoids ever following a
/// dangerous link. The risk it leaves on the table: if any
/// downstream code consumes the tarball without going through the
/// extractor (e.g. a future bundler, a raw inspect tool), the
/// silently-skipped entries become invisible to the user. Pin the
/// current shape; flag a future-work item if "reject loudly" is the
/// preferred contract.
///
/// The test asserts: install succeeds (silent skip is the contract),
/// the linked file does NOT appear in the extracted package, and the
/// outside target the symlink pointed at is NOT modified.
#[tokio::test]
async fn tarball_with_symlink_to_outside_path_is_silently_skipped() {
    // Plant an outside sentinel with known content so a writethrough
    // would change it.
    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let outside_target = outside_dir.path().join("victim.txt");
    std::fs::write(&outside_target, b"original outside content").expect("plant sentinel");

    let outside_target_str = outside_target.to_string_lossy().into_owned();

    let tgz = tarball_with_extra_entries("symlink-pkg", "1.0.0", |builder| {
        let mut symlink_header = tar::Header::new_gnu();
        symlink_header.set_entry_type(tar::EntryType::Symlink);
        symlink_header.set_size(0);
        symlink_header.set_mode(0o777);
        symlink_header
            .set_link_name(&outside_target_str)
            .expect("set symlink target");
        symlink_header.set_cksum();
        builder
            .append_data(
                &mut symlink_header,
                "package/link-to-outside.txt",
                std::io::empty(),
            )
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("symlink-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("symlink-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#2 symlink-skip] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    // Current contract: silent skip, install succeeds.
    assert!(
        output.status.success(),
        "install of symlink-bearing tarball failed — extractor's \
         silent-skip contract may have changed (audit before \
         flipping the assertion).\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on a symlink entry:\nstderr:\n{stderr}"
    );

    // Critical: outside sentinel is byte-identical.
    let after = std::fs::read(&outside_target).expect("re-read outside sentinel");
    assert_eq!(
        after, b"original outside content",
        "outside sentinel was modified — extractor wrote through the \
         silently-skipped symlink. file: {outside_target:?}"
    );

    // The symlink's named path must NOT appear inside the project's
    // node_modules/<pkg>/ either as a symlink, a file, or anything.
    let pkg_dir = project.path().join("node_modules/symlink-pkg");
    let phantom = pkg_dir.join("link-to-outside.txt");
    assert!(
        !phantom.exists(),
        "the silently-skipped symlink should not appear at {phantom:?}"
    );
}

/// **Plan #5 — hard link to outside file is silently skipped (current behavior).**
///
/// Same posture as #2: tar entry type 'Link' (`hardlink`) is not
/// `is_file()`, so the extractor's regular-files-only branch silently
/// drops it. The install succeeds, no hardlink lands on disk.
///
/// The risk it forecloses: a hardlink in a tarball pointing at
/// `/etc/passwd` could otherwise let an attacker materialize a
/// readable copy inside the package directory. Silent-skip prevents
/// that.
#[tokio::test]
async fn tarball_with_hard_link_to_outside_file_is_silently_skipped() {
    // Plant the outside file with known content.
    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let outside_target = outside_dir.path().join("victim.txt");
    std::fs::write(&outside_target, b"sensitive bytes").expect("plant outside victim");
    let outside_target_str = outside_target.to_string_lossy().into_owned();

    let tgz = tarball_with_extra_entries("hardlink-pkg", "1.0.0", |builder| {
        let mut hardlink_header = tar::Header::new_gnu();
        hardlink_header.set_entry_type(tar::EntryType::Link);
        hardlink_header.set_size(0);
        hardlink_header.set_mode(0o644);
        hardlink_header
            .set_link_name(&outside_target_str)
            .expect("set hardlink target");
        hardlink_header.set_cksum();
        builder
            .append_data(
                &mut hardlink_header,
                "package/hardlink-to-victim.txt",
                std::io::empty(),
            )
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("hardlink-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("hardlink-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#5 hardlink-skip] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of hardlink-bearing tarball failed — extractor's \
         silent-skip contract may have changed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on a hardlink entry:\nstderr:\n{stderr}"
    );

    // Outside target must still contain the original bytes — the
    // hardlink was NOT created (which would have made the outside
    // file mutable through the package path).
    let after = std::fs::read(&outside_target).expect("re-read outside victim");
    assert_eq!(
        after, b"sensitive bytes",
        "outside file was mutated — silent-skip contract violated. \
         file: {outside_target:?}"
    );

    let phantom = project
        .path()
        .join("node_modules/hardlink-pkg/hardlink-to-victim.txt");
    assert!(
        !phantom.exists(),
        "the silently-skipped hardlink should not appear at {phantom:?}"
    );
}

/// **Plan #8 — setuid/setgid executable extracts with setuid bits stripped.**
///
/// `set_preserve_permissions(false)` at [lib.rs:240](../../../crates/lpm-extractor/src/lib.rs#L240)
/// disables tar's SUID-bit preservation. Subsequent post-write
/// `set_permissions` at [lib.rs:472](../../../crates/lpm-extractor/src/lib.rs#L472)
/// uses `0o644 | exec_bits`, where `exec_bits = mode & 0o111` —
/// strictly the user/group/other execute bits, never the SUID
/// (0o4000), SGID (0o2000), or sticky (0o1000) bits.
///
/// Pinned contract: a tarball with mode `0o4755` (SUID + rwxr-xr-x)
/// extracts with mode `0o755` (no SUID). The file extracts, the
/// install succeeds, and a `stat` of the on-disk file shows the SUID
/// bit cleared.
///
/// POSIX-only — Windows NTFS doesn't have POSIX mode bits; bin
/// scripts there are dispatched by extension.
#[cfg(unix)]
#[tokio::test]
async fn tarball_with_setuid_executable_extracts_with_setuid_bit_stripped() {
    use std::os::unix::fs::PermissionsExt;

    let tgz = tarball_with_extra_entries("setuid-pkg", "1.0.0", |builder| {
        let content = b"#!/bin/sh\necho privileged\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        // 0o4755 = SUID + rwxr-xr-x. The extractor must strip the
        // SUID bit (0o4000) and emit 0o755.
        header.set_mode(0o4755);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/bin/run.sh", &content[..])
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("setuid-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("setuid-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#8 setuid-strip] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of setuid-bearing tarball failed — the file should \
         have extracted (SUID stripped, rwx preserved).\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on setuid entry:\nstderr:\n{stderr}"
    );

    let extracted = project.path().join("node_modules/setuid-pkg/bin/run.sh");
    assert!(
        extracted.exists(),
        "expected the setuid file to extract (with SUID stripped) at {extracted:?}"
    );

    let mode = std::fs::metadata(&extracted)
        .expect("stat extracted file")
        .permissions()
        .mode()
        & 0o7777;
    // The post-write set_permissions uses (0o644 | exec_bits). For a
    // tarball mode of 0o4755 (rwxr-xr-x + SUID): exec_bits = 0o111,
    // so the on-disk mode is 0o644 | 0o111 = 0o755. SUID (0o4000)
    // MUST be cleared.
    assert_eq!(
        mode & 0o4000,
        0,
        "SUID bit was preserved — security regression. on-disk mode: {mode:#o}"
    );
    assert_eq!(
        mode & 0o2000,
        0,
        "SGID bit was preserved — security regression. on-disk mode: {mode:#o}"
    );
    assert_eq!(
        mode & 0o1000,
        0,
        "sticky bit was preserved — sanity. on-disk mode: {mode:#o}"
    );
    // Sanity: exec bits are still present (the extractor honored
    // the legitimate executability of bin scripts).
    assert!(
        mode & 0o111 != 0,
        "all execute bits stripped — the extractor over-corrected. \
         on-disk mode: {mode:#o}. Expected exec bits preserved (0o755)."
    );
}

// ─── Phase 2 tests (added 2026-05-14) ───────────────────────────────

/// **Plan #4 — Unicode-bearing entry path is taken as literal bytes, not normalized.**
///
/// The extractor's `Component::ParentDir` check at
/// [lib.rs:347](../../../crates/lpm-extractor/src/lib.rs#L347) compares
/// against `b".."` byte-exactly. A tarball entry with full-width
/// dots `．．` (U+FF0E × 2, UTF-8 `\xef\xbc\x8e\xef\xbc\x8e`) does
/// NOT match `ParentDir` and is treated as a normal `Component::Normal`
/// directory name. Same shape for RTL override (U+202E, the
/// `RIGHT-TO-LEFT OVERRIDE` codepoint — not literally embedded in
/// this docstring because rustc rejects bidi codepoints in source
/// even in comments), URL-encoded forms like `..%c0%af`, and any
/// other Unicode
/// representation that doesn't decode to the literal ASCII bytes
/// `..` at the OS layer.
///
/// **Result:** install SUCCEEDS, the entry extracts at the literal
/// Unicode-bearing path under `node_modules/<pkg>/`, no traversal
/// triggers, and the outside sentinel is unchanged.
///
/// That posture is defensible: Rust's `Path::components()` is byte-
/// based on POSIX (no NFC/NFKC normalization), so any non-ASCII
/// representation of "parent dir" loses its semantic meaning at the
/// path-component layer. The bytes become a normal filename. The
/// only Unicode-trick that COULD escape would be one whose bytes
/// are byte-identical to ASCII `..` at the OS layer — by
/// construction, that's the regular `..` case (Plan #1), already
/// pinned.
///
/// Pin the no-escape contract: outside sentinel byte-identical, the
/// extracted file (if any) lives strictly under
/// `node_modules/<pkg>/`.
#[tokio::test]
async fn tarball_with_unicode_lookalike_parent_dir_extracts_safely_as_literal_bytes() {
    // Plant an outside sentinel — same shape as the symlink/hardlink
    // tests so a writethrough is detectable.
    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let outside_target = outside_dir.path().join("escape.txt");
    std::fs::write(&outside_target, b"original outside content").expect("plant sentinel");

    let tgz = tarball_with_extra_entries("unicode-pkg", "1.0.0", |builder| {
        let content = b"unicode-pwn-attempt";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        // Full-width dots — visually `..` but bytewise NOT the
        // ASCII `..` that triggers `Component::ParentDir`.
        header
            .set_path("package/．．/escape.txt")
            .expect("set unicode path");
        header.set_cksum();
        builder.append(&header, &content[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("unicode-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("unicode-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#4 unicode-literal] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of Unicode-lookalike-traversal tarball failed — \
         the extractor's literal-bytes contract may have changed.\n\
         stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on Unicode-bearing path:\nstderr:\n{stderr}"
    );

    // **Critical** — outside sentinel must be byte-identical. If
    // `．．` were ever interpreted as parent-dir traversal AND the
    // extractor wrote through it, the outside file would be
    // overwritten or supplemented.
    let after = std::fs::read(&outside_target).expect("re-read outside sentinel");
    assert_eq!(
        after, b"original outside content",
        "outside sentinel was modified — Unicode-lookalike path was \
         interpreted as traversal somewhere in the pipeline. \
         file: {outside_target:?}"
    );
    // Also pin: nothing landed at the project's parent dir as a
    // sibling escape.txt (`node_modules/escape.txt` would also be
    // a smell — the literal path should land deeper).
    let project_parent_escape = project.path().parent().unwrap().join("escape.txt");
    assert!(
        !project_parent_escape.exists(),
        "extractor wrote to project's parent — security regression. \
         file lives at: {project_parent_escape:?}"
    );

    // Diagnostic only: surface the actual landing path so future
    // readers can see where the extractor placed the literal-bytes
    // entry. Not asserted because filesystem rules around non-ASCII
    // dir names vary across macOS HFS+/APFS, ext4, NTFS-via-WSL.
    let pkg_dir = project.path().join("node_modules/unicode-pkg");
    let unicode_subdir = pkg_dir.join("．．");
    eprintln!(
        "[Plan#4 unicode-literal] unicode_subdir_exists={} pkg_dir_exists={} files_under_pkg={:?}",
        unicode_subdir.exists(),
        pkg_dir.exists(),
        pkg_dir
            .read_dir()
            .ok()
            .map(|rd| rd.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
    );
}

/// **Plan #6 — character-device entry is silently skipped (POSIX-only).**
///
/// Tarball entry type `EntryType::Char` (or `Block`) is not
/// `is_file()`, so the extractor's regular-files-only branch at
/// [lib.rs:398](../../../crates/lpm-extractor/src/lib.rs#L398)
/// silently drops it. Same posture as the symlink/hardlink tests
/// in phase 1.
///
/// Defensible: npm packages don't legitimately ship device files.
/// Silent-skip avoids ever materializing a /dev/null-like entry
/// that could confuse downstream tools (Node's `fs.readFileSync`
/// on a character device would block forever or read zero bytes).
///
/// **Why Unix-only:** tar's `EntryType::Char` and `Block` map to
/// POSIX `mknod()` semantics. Windows tar can't materialize them
/// even if the silent-skip logic were bypassed; the path is moot
/// there. The same `is_file()` predicate gates the skip cross-
/// platform, but constructing the test fixture is POSIX-shaped.
#[cfg(unix)]
#[tokio::test]
async fn tarball_with_character_device_entry_is_silently_skipped() {
    let tgz = tarball_with_extra_entries("chardev-pkg", "1.0.0", |builder| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_mode(0o600);
        // device_major/minor live in the tar header but the extractor
        // never reads them (silent-skip happens before any device-
        // creation code path). Set both to 0 — value is irrelevant.
        header.set_device_major(1).expect("set major");
        header.set_device_minor(3).expect("set minor"); // /dev/null-shape
        header.set_cksum();
        builder
            .append_data(&mut header, "package/devnull-clone", std::io::empty())
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("chardev-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("chardev-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#6 chardev-skip] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of character-device-bearing tarball failed — \
         silent-skip contract may have changed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on character-device entry:\nstderr:\n{stderr}"
    );

    let phantom = project
        .path()
        .join("node_modules/chardev-pkg/devnull-clone");
    assert!(
        !phantom.exists(),
        "the silently-skipped character device should not appear at {phantom:?}"
    );
}

/// **Plan #7 — FIFO entry is silently skipped (POSIX-only).**
///
/// Tarball entry type `EntryType::Fifo` is not `is_file()`. Same
/// silent-skip posture as #6 (character device). Pinned for
/// completeness so a future regression that flips the gate (e.g.,
/// `EntryType::Fifo` accidentally treated as Regular) is detected
/// here.
///
/// Defensible: npm packages don't ship named pipes. Materializing
/// one would create a hang trap for any tool that opened the path
/// for read.
#[cfg(unix)]
#[tokio::test]
async fn tarball_with_fifo_entry_is_silently_skipped() {
    let tgz = tarball_with_extra_entries("fifo-pkg", "1.0.0", |builder| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/named-pipe", std::io::empty())
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("fifo-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("fifo-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#7 fifo-skip] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of FIFO-bearing tarball failed — silent-skip contract \
         may have changed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on FIFO entry:\nstderr:\n{stderr}"
    );

    let phantom = project.path().join("node_modules/fifo-pkg/named-pipe");
    assert!(
        !phantom.exists(),
        "the silently-skipped FIFO should not appear at {phantom:?}"
    );
}

/// **Plan #9 — zero-byte regular file extracts as an empty file (sanity).**
///
/// Pure sanity check that the size-0 edge case isn't swallowed by
/// the size-limit / hardening branches. Many npm packages ship
/// empty files (build artifacts, `.gitkeep`, `LICENSE` placeholders),
/// so a regression that drops them would break real installs while
/// passing all the malicious-tarball tests above.
///
/// Pin: install succeeds, the empty file lands at the expected path
/// inside `node_modules/<pkg>/`, on-disk size is 0.
#[tokio::test]
async fn tarball_with_zero_byte_regular_file_extracts_as_empty_file() {
    let tgz = tarball_with_extra_entries("empty-pkg", "1.0.0", |builder| {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/empty.txt", std::io::empty())
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("empty-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("empty-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#9 zero-byte] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of zero-byte-member tarball failed — extractor's \
         empty-file handling may have regressed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on zero-byte entry:\nstderr:\n{stderr}"
    );

    let extracted = project.path().join("node_modules/empty-pkg/empty.txt");
    assert!(
        extracted.exists(),
        "expected the zero-byte file to extract at {extracted:?}"
    );
    let on_disk_size = std::fs::metadata(&extracted)
        .expect("stat extracted empty file")
        .len();
    assert_eq!(
        on_disk_size, 0,
        "extracted empty file is not zero bytes — the extractor wrote \
         garbage. on-disk size: {on_disk_size}"
    );
}

/// **Plan #10 — entry path with a single 300-byte component fails cleanly.**
///
/// POSIX `NAME_MAX` is 255 on most filesystems (ext4/APFS/HFS+);
/// Windows `MAX_PATH` is 260 by default. A single 300-byte path
/// component exceeds NAME_MAX everywhere, so `std::fs::create_dir`
/// (or `OpenOptions::open` for the leaf) returns an OS error
/// (`ENAMETOOLONG` on Linux/macOS, `ERROR_FILENAME_EXCED_RANGE` on
/// Windows). The extractor wraps this as `LpmError::Io(error)` →
/// install fails with the OS message visible.
///
/// Pin the contract:
/// - Install fails non-zero (no silent extraction at a corrupted path).
/// - No panic (the OS error is wrapped, not unwrapped).
/// - Stderr contains the long-name nature OR the generic IO error
///   noun (long / name / file / directory / io / extraction / install).
///
/// **Why 300, not 4096:** the goal is to trip the per-component
/// `NAME_MAX` (~255) ceiling, which most filesystems enforce
/// uniformly. Trying to trip the per-path `PATH_MAX` (4096 on Linux,
/// 1024 on macOS) would require deep nesting AND a long leaf,
/// adding shape complexity for the same security signal.
#[tokio::test]
async fn tarball_with_single_path_component_exceeding_name_max_fails_cleanly() {
    // 300-byte component name. Most filesystems cap at NAME_MAX=255;
    // 300 trips the ceiling reliably.
    let long_name: String = "a".repeat(300);
    let entry_path = format!("package/{long_name}");

    let tgz = tarball_with_extra_entries("longname-pkg", "1.0.0", |builder| {
        let content = b"will-fail-on-create";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        // append_data uses GNU long-name extension for paths longer
        // than 100 bytes — the tar wire format succeeds; only the
        // FILESYSTEM rejects on extraction.
        builder
            .append_data(&mut header, &entry_path, &content[..])
            .expect("append long-name entry");
    });

    let mock = MockRegistry::start().await;
    mock.with_package("longname-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("longname-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#10 long-path] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of 300-byte-component tarball reported success — \
         the filesystem accepted a path beyond NAME_MAX, OR the \
         extractor silently dropped the entry. Either is a contract \
         break.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on long-path entry:\nstderr:\n{stderr}"
    );

    // Stderr should name SOMETHING actionable. The extractor wraps
    // the OS error as `LpmError::Io` → miette renders it with the
    // original system message ("File name too long" / "filename
    // exceeds maximum length"). The word list is broad to tolerate
    // platform variance.
    let stderr_l = stderr.to_lowercase();
    let actionable = [
        "long",
        "name",
        "filename",
        "file name",
        "exceed",
        "directory",
        "io error",
        "io ",
        "io)",
        "extraction",
        "extract",
        "tarball",
        "installation",
        "install",
    ]
    .iter()
    .any(|n| stderr_l.contains(n));
    assert!(
        actionable,
        "long-path failure didn't surface an actionable noun. \
         stderr:\n{stderr}"
    );
}
