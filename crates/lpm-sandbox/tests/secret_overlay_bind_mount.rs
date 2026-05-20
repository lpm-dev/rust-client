//! Backend runtime gate: under the default Landlock sandbox, the
//! Linux secret-file overlay bind-mounts `/dev/null` over project
//! `.env`. The lifecycle-script-equivalent (`/bin/cat <project>/.env`)
//! spawned through the sandbox must therefore observe an empty
//! file, even though the parent process sees the real bytes.
//!
//! Sibling of [`seccomp_socket_deny.rs`] — both live at the
//! integration-test layer rather than `src/lib.rs::tests` because
//! the spawned binary path (`/bin/cat`) is a system path that's
//! always available on Linux but spawning it through the sandbox
//! requires the full backend construction, not just the
//! rule-description layer.
//!
//! Linux-only: macOS Seatbelt achieves the same denial via the
//! `(deny file-read* ...)` block in `seatbelt::render_profile`
//! (covered by the `secret_deny_block_*` lib tests). Windows
//! AppContainer has no equivalent overlay layer (filed as a
//! follow-up).

#![cfg(target_os = "linux")]

use lpm_sandbox::{
    SandboxMode, SandboxOptions, SandboxSpec, SandboxStdio, SandboxedCommand,
    new_for_platform_with_options,
};
use std::path::PathBuf;

/// Returns true iff the FULL overlay sequence — `unshare` + the
/// uid/gid map dance + bind-mount of `/dev/null` over a probe file
/// — succeeds from THIS process's binary identity. The probe runs
/// the same syscalls in the same order as the production
/// `apply_secret_overlay_in_child`, so every host condition the
/// real overlay needs is exercised.
///
/// Why probe the full sequence and not just `unshare`:
///
/// - **Hardened distros** (Debian with
///   `kernel.unprivileged_userns_clone=0`, container runtimes
///   without `--privileged`) refuse `unshare(CLONE_NEWUSER)`
///   outright. Stopping at unshare is enough on those hosts.
/// - **Ubuntu 24.04 GitHub Actions runners** ship an AppArmor
///   `unprivileged_userns` profile that permits `unshare` but
///   does NOT permit `mount(2)` on arbitrary targets — the
///   profile's allow-list grants `userns` capability and not
///   `mount` capability. An `unshare`-only probe reports
///   "supported" but the workload's silent `mount(2)` failure
///   leaves `/bin/cat` reading the real `.env`. Probing the
///   bind-mount itself catches this asymmetric host posture.
/// - Probing via `/usr/bin/unshare` (the obvious shell shortcut)
///   is also wrong: the shell binary has its own AppArmor allow,
///   the cargo test binary doesn't — different binary identities
///   produce different decisions.
///
/// When this returns false the overlay layer is a documented
/// no-op; skipping the runtime assertion is the correct behavior
/// — a "shouldn't be empty" pass would mask the overlay's silent-
/// degrade design.
fn unshare_userns_supported() -> bool {
    // mount(2) needs a target file that exists on the host fs; the
    // bind-mount itself only takes effect in the new mount
    // namespace. NamedTempFile drops at end-of-scope (after the
    // child has exited), so the leak window is the test method.
    let probe_target = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => return false,
    };
    let probe_cstring = match probe_target
        .path()
        .to_str()
        .and_then(|s| std::ffi::CString::new(s).ok())
    {
        Some(c) => c,
        None => return false,
    };

    // Pre-format uid_map / gid_map strings in the parent. We don't
    // need full AS-safety here — the probe is plain test code, not
    // pre_exec — but doing the format parent-side avoids an
    // allocator call inside the forked child, which is cheap
    // insurance.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let uid_map = format!("0 {uid} 1\n").into_bytes();
    let gid_map = format!("0 {gid} 1\n").into_bytes();

    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                libc::_exit(11);
            }
            if !write_proc_file(b"/proc/self/setgroups\0", b"deny") {
                libc::_exit(12);
            }
            if !write_proc_file(b"/proc/self/uid_map\0", &uid_map) {
                libc::_exit(13);
            }
            if !write_proc_file(b"/proc/self/gid_map\0", &gid_map) {
                libc::_exit(14);
            }
            let rc = libc::mount(
                c"/dev/null".as_ptr(),
                probe_cstring.as_ptr(),
                c"none".as_ptr(),
                libc::MS_BIND,
                std::ptr::null(),
            );
            libc::_exit(if rc == 0 { 0 } else { 15 });
        }
        let mut status: libc::c_int = 0;
        if libc::waitpid(pid, &mut status, 0) < 0 {
            return false;
        }
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

/// In-child helper for the probe — write `bytes` to the
/// NUL-terminated `path` under `/proc/self/*`. Returns true on a
/// successful full write. Mirrors `write_proc_file_assafe` in
/// `linux_secret_overlay.rs` but as a free function so this test
/// crate doesn't depend on private items.
unsafe fn write_proc_file(path: &[u8], bytes: &[u8]) -> bool {
    unsafe {
        let fd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_WRONLY);
        if fd < 0 {
            return false;
        }
        let mut written = 0usize;
        while written < bytes.len() {
            let n = libc::write(
                fd,
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            );
            if n <= 0 {
                libc::close(fd);
                return false;
            }
            written += n as usize;
        }
        libc::close(fd);
        true
    }
}

fn fixture_spec(project_dir: &std::path::Path) -> SandboxSpec {
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

/// Default-mode sandbox: a script reading `<project>/.env` sees
/// zero bytes because the overlay bind-mounted `/dev/null` over
/// the path. End-to-end behavioral gate.
#[test]
fn default_mode_bind_mounts_dotenv_to_empty() {
    if !unshare_userns_supported() {
        eprintln!(
            "skipping: unprivileged user namespaces unavailable on this host. \
             check `kernel.unprivileged_userns_clone`, AppArmor / SELinux \
             confinement, or container runtime privileges. \
             The secret overlay is documented to silently no-op when unshare \
             fails — running this assertion would mask that design."
        );
        return;
    }

    let project = tempfile::tempdir().expect("project tempdir");
    let env_path = project.path().join(".env");
    std::fs::write(&env_path, "API_KEY=actually-secret\nDB_URL=postgres://x\n")
        .expect("write .env");

    let spec = fixture_spec(project.path());
    let options = SandboxOptions {
        allow_degraded: false,
        deny_outbound_network: false,
    };
    let sandbox = new_for_platform_with_options(spec, SandboxMode::Enforce, options)
        .expect("sandbox construction");

    let mut cmd = SandboxedCommand::new("/bin/cat");
    cmd.args.push(env_path.clone().into_os_string());
    cmd.stdout = SandboxStdio::Piped;
    cmd.stderr = SandboxStdio::Piped;

    let child = sandbox.spawn(cmd).expect("spawn /bin/cat under sandbox");
    let output = child.wait_with_output().expect("collect /bin/cat output");

    assert!(
        output.stdout.is_empty(),
        "bind-mount overlay must replace .env with /dev/null in the child's view;\n\
         got stdout = {:?}\n\
         stderr = {:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Symmetry: a non-secret file in the same project tree must NOT
/// be overlaid. Pins the negative side of the contract — overlay
/// only covers the named secret conventions, not arbitrary
/// project files.
#[test]
fn default_mode_does_not_overlay_source_files() {
    if !unshare_userns_supported() {
        eprintln!("skipping: unprivileged user namespaces unavailable");
        return;
    }

    let project = tempfile::tempdir().expect("project tempdir");
    let src_path = project.path().join("hello.txt");
    let expected = "hello, world\n";
    std::fs::write(&src_path, expected).expect("write hello.txt");

    let spec = fixture_spec(project.path());
    let options = SandboxOptions {
        allow_degraded: false,
        deny_outbound_network: false,
    };
    let sandbox = new_for_platform_with_options(spec, SandboxMode::Enforce, options)
        .expect("sandbox construction");

    let mut cmd = SandboxedCommand::new("/bin/cat");
    cmd.args.push(src_path.clone().into_os_string());
    cmd.stdout = SandboxStdio::Piped;
    cmd.stderr = SandboxStdio::Piped;

    let child = sandbox.spawn(cmd).expect("spawn /bin/cat under sandbox");
    let output = child.wait_with_output().expect("collect output");

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected,
        "non-secret file must remain readable; stderr = {:?}",
        String::from_utf8_lossy(&output.stderr),
    );
}
