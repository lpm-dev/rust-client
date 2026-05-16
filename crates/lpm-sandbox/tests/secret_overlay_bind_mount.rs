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

/// Returns true iff `unshare(CLONE_NEWUSER)` succeeds on this
/// host. Hardened distros (Debian with
/// `kernel.unprivileged_userns_clone=0`, AppArmor profiles
/// blocking unprivileged user namespaces, container runtimes
/// without `--privileged`) refuse the syscall. When this returns
/// false the overlay layer is a documented no-op; skipping the
/// runtime assertion is the correct behavior — a "shouldn't be
/// empty" pass would mask the overlay's silent-degrade design.
fn unshare_userns_supported() -> bool {
    std::process::Command::new("unshare")
        .args(["-U", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn fixture_spec(project_dir: &std::path::Path) -> SandboxSpec {
    let home = dirs::home_dir().expect("home dir for test");
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
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
    let output = child
        .wait_with_output()
        .expect("collect /bin/cat output");

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
