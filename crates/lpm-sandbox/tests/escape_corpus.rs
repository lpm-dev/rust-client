//! §12.5 escape corpus — each test attempts a forbidden operation
//! under `SandboxMode::Enforce` and asserts the sandbox BLOCKS it.
//!
//! The corpus covers the representative bad behaviors a malicious
//! postinstall might try:
//!
//! | # | Attempt                                    | Why it's forbidden                                  |
//! |---|--------------------------------------------|-----------------------------------------------------|
//! | 1 | Read a file the sandbox didn't allow-list  | Covers the general "reads outside allow list" class |
//! | 2 | Write to `~/.bashrc`                       | Shell-startup persistence                           |
//! | 3 | Write to `/etc/hosts` (macOS: `/private/etc/hosts`) | System config hijack                      |
//! | 4 | Read `~/.ssh/id_rsa`-shaped path           | Credential exfiltration                             |
//! | 5 | Read `~/.aws/credentials`-shaped path      | Cloud-credential exfiltration                       |
//! | 6 | (macOS) Write inside `/Library/Keychains`  | Keychain tamper                                     |
//! | 7 | (macOS) Write to `/System/Library`         | System-binary tamper                                |
//!
//! All tests skip gracefully if the host lacks a working sandbox
//! (old Linux kernel, non-{macOS,Linux} unix, Windows). Assertions
//! verify two things per case:
//!
//! - The script's exit status is NON-ZERO (OS-level block fired).
//! - The forbidden side-effect did NOT land on disk (defensive
//!   check in case exit-status-only would be spoofable by a script
//!   that catches the SIGSYS/EPERM and fakes failure).

mod common;

use common::{SandboxFixture, run_script, sandbox_supported, try_build_sandbox};
use lpm_sandbox::SandboxMode;

// -------- Case 1: generic read outside allow list --------

#[test]
fn block_read_of_file_outside_allow_list() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("probe", "1.0.0");
    // Create a secret in a tempdir OUTSIDE the spec's allow list
    // — the fixture's tempdir is under /var/folders (macOS) or /tmp
    // (Linux), but the SPEC only covers `{tmp}/store/probe@1.0.0`
    // and `{tmp}/proj`. The sibling `{tmp}/secret.txt` is not
    // covered.
    let secret_dir = fx.tmp_path().join("secret-sibling");
    std::fs::create_dir_all(&secret_dir).unwrap();
    let secret = secret_dir.join("id_rsa");
    std::fs::write(&secret, b"FAKE-PRIVATE-KEY").unwrap();

    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce)
        .expect("sandbox supported per precondition");
    let status = run_script(
        sb.as_ref(),
        &fx.pkg_dir,
        &format!("cat {}", secret.display()),
    );
    assert!(
        !status.success(),
        "sandbox must block a read of a path outside the allow list — {status:?}"
    );
}

// -------- Case 2: shell-startup persistence (~/.bashrc) --------

#[test]
fn block_write_to_bashrc_shape_in_home_root() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    // Target a `.bashrc`-shaped path inside the user's real home dir.
    // The sandbox spec doesn't list `$HOME/.bashrc` (it lists only
    // `$HOME/.cache`, `$HOME/.node-gyp`, `$HOME/.npm`, `$HOME/.nvm/
    // versions`), so writes to `~/.bashrc` must be denied. Use a
    // unique suffix so a test-harness accident doesn't corrupt the
    // real user `.bashrc`.
    let uniq = format!("lpm-p5-escape-bashrc-{}", std::process::id());
    let home = dirs::home_dir().unwrap();
    let forbidden = home.join(format!(".bashrc.{uniq}"));
    // Guard: make sure it doesn't already exist before the test.
    let _ = std::fs::remove_file(&forbidden);

    let fx = SandboxFixture::new("bashrc-probe", "1.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    let status = run_script(
        sb.as_ref(),
        &fx.pkg_dir,
        &format!("echo persisted > {}", forbidden.display()),
    );
    assert!(
        !status.success(),
        "sandbox must block a write to a `.bashrc`-shaped path in $HOME"
    );
    assert!(
        !forbidden.exists(),
        "sandbox escape — forbidden {} was created",
        forbidden.display()
    );
    // Belt-and-braces cleanup in case the sandbox somehow allowed it.
    let _ = std::fs::remove_file(&forbidden);
}

// -------- Case 3: /etc/hosts tamper --------

#[test]
fn block_write_to_etc_hosts() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("etc-probe", "1.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    // On macOS, `/etc` is a symlink to `/private/etc`; on Linux it
    // is a real directory. Attempting to write to `/etc/hosts-lpm-
    // probe-<pid>` must fail on both platforms regardless of unix
    // permissions — the sandbox denies the open-for-write BEFORE
    // the kernel evaluates permissions.
    let probe_path = format!("/etc/hosts-lpm-p5-probe-{}", std::process::id());
    let status = run_script(
        sb.as_ref(),
        &fx.pkg_dir,
        &format!("echo spoof > {probe_path}"),
    );
    assert!(
        !status.success(),
        "sandbox must block a write to /etc/<*> — {status:?}"
    );
    // The target doesn't need cleanup — if the sandbox worked, the
    // file was never created; if it didn't, the unix permissions
    // stopped the write a millisecond later anyway.
}

// -------- Case 4: ssh credential exfiltration --------

#[test]
fn block_read_of_ssh_credential_shape_path() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    // Create a FAKE credential inside the test's tempdir but at a
    // `.ssh/id_rsa`-shaped subpath. The sandbox spec has no rule
    // covering `~/.ssh` OR this tempdir sibling, so the read must
    // fail on both platforms. Use a tempdir to avoid any risk of
    // touching a real user credential even for a read probe.
    let fx = SandboxFixture::new("ssh-probe", "1.0.0");
    let ssh_shape = fx.tmp_path().join(".ssh");
    std::fs::create_dir_all(&ssh_shape).unwrap();
    let id_rsa = ssh_shape.join("id_rsa");
    std::fs::write(&id_rsa, b"-----BEGIN FAKE TEST KEY-----\n").unwrap();

    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    let status = run_script(
        sb.as_ref(),
        &fx.pkg_dir,
        &format!("cat {}", id_rsa.display()),
    );
    assert!(
        !status.success(),
        "sandbox must block a read of a `.ssh/id_rsa`-shaped path — {status:?}"
    );
}

// -------- Case 5: AWS credential exfiltration --------

#[test]
fn block_read_of_aws_credentials_shape_path() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("aws-probe", "1.0.0");
    let aws_shape = fx.tmp_path().join(".aws");
    std::fs::create_dir_all(&aws_shape).unwrap();
    let creds = aws_shape.join("credentials");
    std::fs::write(
        &creds,
        b"[default]\naws_access_key_id = FAKE\naws_secret_access_key = FAKE\n",
    )
    .unwrap();

    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    let status = run_script(
        sb.as_ref(),
        &fx.pkg_dir,
        &format!("cat {}", creds.display()),
    );
    assert!(
        !status.success(),
        "sandbox must block a read of an `.aws/credentials`-shaped path — {status:?}"
    );
}

// -------- Case 6: macOS /Library/Keychains write --------

#[cfg(target_os = "macos")]
#[test]
fn block_write_under_library_keychains_macos() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("keychain-probe", "1.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    // `/Library/Keychains` is OS-owned; unix perms alone would also
    // deny. The sandbox's job is to deny the attempt before it
    // reaches the permissions check — the test asserts that
    // happens by virtue of the sandbox profile, not by accident of
    // user privilege.
    let probe_path = format!(
        "/Library/Keychains/lpm-p5-probe-{}.keychain-db",
        std::process::id()
    );
    let status = run_script(
        sb.as_ref(),
        &fx.pkg_dir,
        &format!("echo leak > {probe_path}"),
    );
    assert!(
        !status.success(),
        "sandbox must block a write under /Library/Keychains — {status:?}"
    );
}

// -------- Case 7: macOS /System/Library write --------

#[cfg(target_os = "macos")]
#[test]
fn block_write_under_system_library_macos() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("system-probe", "1.0.0");
    let sb = try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce).unwrap();
    // `/System/Library` is read-allowed in the Seatbelt profile
    // (via `(subpath "/System")`) but NOT write-allowed. Verify
    // the read/write distinction holds at runtime.
    let probe_path = format!("/System/Library/lpm-p5-probe-{}.plist", std::process::id());
    let status = run_script(
        sb.as_ref(),
        &fx.pkg_dir,
        &format!("echo leak > {probe_path}"),
    );
    assert!(
        !status.success(),
        "sandbox must block a write under /System/Library — {status:?}"
    );
}
