//! Backend runtime gate: spawn the `socket-probe` test bin under
//! a Strict-posture landlock sandbox and assert the seccomp filter
//! denies the `socket(AF_INET, SOCK_DGRAM)` syscall.
//!
//! Sibling of the lib-side `tests` mod inside
//! [`crates/lpm-sandbox/src/linux.rs`], but lifted to the
//! integration-test layer because the `socket-probe` bin path is
//! only injected into the build env (`CARGO_BIN_EXE_socket-probe`)
//! for integration tests — not for `src/lib.rs::tests`. Same
//! pattern the existing `helper_filesystem.rs` /
//! `helper_network.rs` tests use for `lpm-sandbox-helper`.
//!
//! Linux-only: macOS Seatbelt already denies UDP unconditionally
//! via `(deny default)`; this test gates the Linux seccomp layer.

#![cfg(target_os = "linux")]

use lpm_sandbox::{
    SandboxError, SandboxMode, SandboxOptions, SandboxPosture, SandboxSpec, SandboxedCommand,
    new_for_platform_with_options,
};
use std::path::PathBuf;

/// Returns the directory the test should stage `socket-probe`
/// into for exec under the sandbox. This must be both (a) in
/// landlock's RW allow-list — see
/// [`crates/lpm-sandbox/src/landlock_rules.rs::describe_rules`]
/// — and (b) on an exec-capable mount so the kernel doesn't
/// deny execve at the mount layer before the seccomp filter is
/// exercised.
///
/// Prefers `$TMPDIR` over `/tmp` (the env var is what
/// `realistic_spec()` reads to populate `spec.tmpdir`, which
/// IS in the allow-list). Falls back to `/tmp` when `TMPDIR`
/// is unset. The returned path is what `tempfile::tempdir_in`
/// is called on.
fn allowlisted_exec_dir() -> std::path::PathBuf {
    std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// True iff the most-specific `/proc/mounts` entry covering
/// `path` has the `noexec` option. On hardened Linux hosts
/// (some Docker images, security-hardened distros), the kernel
/// denies `execve` on any file under such a mount regardless
/// of file permissions or sandbox state. This test copies
/// `socket-probe` into the allow-listed exec dir (see
/// [`allowlisted_exec_dir`]) and then exec-spawns it; if the
/// chosen dir is on a noexec mount, that exec fails with
/// EACCES at the kernel-mount layer BEFORE the seccomp filter
/// ever runs, producing a false-fail.
///
/// Returns false on any parse failure — better to surface a
/// clear failure from the actual exec than to silently skip
/// on a misread.
fn path_is_noexec(path: &std::path::Path) -> bool {
    let target = path.to_string_lossy();
    let mounts = match std::fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut best_len: usize = 0;
    let mut best_noexec = false;
    for line in mounts.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let mountpoint = parts[1];
        let options = parts[3];
        // A mount covers `target` when target == mountpoint or
        // target lives under the mountpoint as a directory
        // descendant. The "/" mount covers everything; deeper
        // mounts override via the longest-match wins logic.
        let covers = target == mountpoint
            || target.starts_with(&format!("{mountpoint}/"))
            || mountpoint == "/";
        if covers && mountpoint.len() > best_len {
            best_len = mountpoint.len();
            best_noexec = options.split(',').any(|o| o == "noexec");
        }
    }
    best_noexec
}

fn realistic_spec() -> SandboxSpec {
    let home = dirs::home_dir().expect("home dir for test");
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    SandboxSpec {
        package_dir: home.join(".lpm/store/testpkg@0.1.0"),
        project_dir: home.join("lpm-sandbox-test-project"),
        package_name: "testpkg".into(),
        package_version: "0.1.0".into(),
        store_root: home.join(".lpm/store"),
        home_dir: home,
        tmpdir: tmp,
        extra_write_dirs: Vec::new(),
    }
}

/// Strict-posture sandbox must deny `socket(AF_INET, SOCK_DGRAM,
/// 0)` from the spawned `socket-probe` bin. The bin exits 0 iff
/// `errno == EACCES`, so `status.success()` proves the kernel
/// returned the deny-matrix outcome.
///
/// Skipped on hosts where the kernel can't deliver Strict (V4
/// landlock unreachable). Mirrors the early-return pattern the
/// existing `linux::tests::new_strict_*` tests use.
#[test]
fn denies_udp_socket_under_strict() {
    let exec_dir = allowlisted_exec_dir();
    if path_is_noexec(&exec_dir) {
        eprintln!(
            "skipping: chosen exec staging dir {} is on a noexec mount. \
             The test copies socket-probe there and execs it under the \
             sandbox; noexec masks seccomp denial with a kernel-mount EACCES. \
             To run: set TMPDIR to a directory on an exec-capable mount \
             (the test reads TMPDIR), or remount the underlying filesystem \
             without `noexec`.",
            exec_dir.display(),
        );
        return;
    }

    let options = SandboxOptions {
        deny_outbound_network: true,
        allow_degraded: false,
    };
    let sb = match new_for_platform_with_options(realistic_spec(), SandboxMode::Enforce, options) {
        Ok(sb) => sb,
        // Kernel < 6.7 or landlock LSM disabled: no Strict
        // path available, so the seccomp filter wouldn't
        // install either. Skip rather than fail.
        Err(SandboxError::KernelTooOld { .. }) => {
            eprintln!("skipping: kernel < 6.7 or landlock LSM disabled");
            return;
        }
        Err(e) => panic!("new_for_platform_with_options (Strict) failed: {e:?}"),
    };
    assert_eq!(sb.posture(), SandboxPosture::Strict);

    // `cargo_bin!` is a compile-time macro that expands to the
    // value of `CARGO_BIN_EXE_socket-probe` — set by cargo when
    // building integration tests. The macro path also matches
    // how `helper_filesystem.rs` locates `lpm-sandbox-helper`.
    let src_probe = PathBuf::from(assert_cmd::cargo_bin!("socket-probe"));

    // Landlock's default rule set (see
    // `crates/lpm-sandbox/src/landlock_rules.rs::describe_rules`)
    // allows read on a narrow list of paths under `home_dir` (.nvm,
    // .cache, .node-gyp, .npm), on `/tmp`, and on `spec.tmpdir`
    // — but NOT on arbitrary cargo target dirs. If the test runs
    // with `CARGO_TARGET_DIR` pointed outside the allow-list,
    // `execve` on the probe path returns `EACCES` before the
    // child's pre_exec ever runs. Copy the bin into the
    // allow-listed exec dir chosen by `allowlisted_exec_dir()`
    // (TMPDIR if set, else /tmp — matches what `realistic_spec()`
    // reads for `spec.tmpdir`) so the test pins seccomp denial of
    // `socket(2)` — the actual contract — not landlock denial of
    // exec on the test bin's path.
    let probe_tmpdir = tempfile::tempdir_in(&exec_dir)
        .unwrap_or_else(|e| panic!("tempdir under {}: {e}", exec_dir.display()));
    let probe = probe_tmpdir.path().join("socket-probe");
    std::fs::copy(&src_probe, &probe).expect("copy socket-probe into /tmp");
    // Preserve the executable bit. `std::fs::copy` carries
    // permissions on Unix per the stdlib contract, but be
    // defensive — a future stdlib change shouldn't silently
    // break this test.
    use std::os::unix::fs::PermissionsExt as _;
    let mut perm = std::fs::metadata(&probe).expect("metadata").permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&probe, perm).expect("chmod 0755");

    // libc constants are stable on Linux: AF_INET=2,
    // SOCK_DGRAM=2. Pass as ints to socket-probe via argv.
    let cmd = SandboxedCommand::new(&probe)
        .arg(libc::AF_INET.to_string())
        .arg(libc::SOCK_DGRAM.to_string())
        .arg("0")
        .envs_cleared([("PATH", "/usr/bin:/bin")]);
    let mut child = sb.spawn(cmd).expect("spawn socket-probe under strict");
    let status = child.wait().expect("wait socket-probe");
    assert!(
        status.success(),
        "seccomp filter must deny socket(AF_INET, SOCK_DGRAM, 0): \
         `socket-probe` exits 0 iff errno=EACCES, got {status:?}. A non-zero \
         exit means the filter is NOT installed (probe returned an fd, exit 1) \
         or the host returned a different errno (EAFNOSUPPORT / ENOSYS / etc., \
         exit 2)."
    );
}
