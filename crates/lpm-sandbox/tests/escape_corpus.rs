//! §12.5 escape corpus — each test attempts a forbidden operation
//! and asserts the SANDBOX (specifically) blocked it.
//!
//! # Discrimination via positive control
//!
//! Each test uses a paired-control pattern: the same script runs
//! twice, once under [`SandboxMode::Disabled`] (positive control —
//! must SUCCEED, proving the target is reachable with ambient OS
//! permissions) and once under [`SandboxMode::Enforce`] (negative
//! test — must FAIL, proving the sandbox is the differentiator).
//! If the positive control ever fails on a given platform, the
//! test panics with a message naming the issue — a target path
//! that's already blocked by the OS cannot be used to demonstrate
//! sandbox effectiveness.
//!
//! This pattern directly addresses the Chunk 5 review finding:
//! earlier versions of this file used `/etc/hosts`,
//! `/Library/Keychains`, and `/System/Library` as targets — all
//! blocked by SIP / unix perms / TCC for unprivileged processes
//! regardless of the sandbox. `!status.success()` on those was a
//! vacuous pass. The current tests target user-writable paths that
//! SHOULD succeed under Disabled and fail under Enforce.
//!
//! # Threat categories covered (user-writable equivalents)
//!
//! | # | Threat                 | User-writable probe target                           |
//! |---|------------------------|------------------------------------------------------|
//! | 1 | Read outside allow list| Tempdir sibling with fake secret contents            |
//! | 2 | Shell-startup persist  | `$HOME/.bashrc.<pid>`                                |
//! | 3 | Home-root config hijack| `$HOME/.lpmrc-probe-<pid>`                           |
//! | 4 | SSH credential exfil   | Tempdir `.ssh/id_rsa`-shape                          |
//! | 5 | AWS credential exfil   | Tempdir `.aws/credentials`-shape                     |
//! | 6 | LaunchAgents persist   | `$HOME/Library/LaunchAgents/lpm-probe-<pid>.plist`   |
//! | 7 | Preferences tamper     | `$HOME/Library/Preferences/lpm-probe-<pid>.plist`    |
//!
//! Every target is under the user's own home, writable via normal
//! unix permissions. The sandbox is the ONLY reason Enforce blocks.

mod common;

use common::{SandboxFixture, run_script, sandbox_supported, try_build_sandbox};
use lpm_sandbox::SandboxMode;
use std::path::Path;

/// Paired-control write test. Runs `script` under Disabled first
/// (must succeed — positive control) then under Enforce (must fail —
/// negative test). Asserts the sandbox mode is the single variable
/// that flipped the outcome. Cleans up `target` between runs.
fn assert_sandbox_blocks_write(fx: &SandboxFixture, target: &Path, script: &str) {
    // Pre-clean any leftover from a previous run.
    let _ = std::fs::remove_file(target);
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Positive control: under Disabled the write must succeed. If
    // it doesn't, the target isn't actually reachable and the test
    // is incapable of discriminating sandbox denial from ambient
    // denial — panic loudly so a confused reviewer sees WHY.
    let noop = try_build_sandbox(fx.spec.clone(), SandboxMode::Disabled)
        .expect("NoopSandbox must always succeed");
    let control_status = run_script(noop.as_ref(), &fx.pkg_dir, script);
    assert!(
        control_status.success(),
        "positive control failed: writing to {} under SandboxMode::Disabled \
         returned {control_status:?}. The target path is already blocked by \
         something other than the sandbox (unix perms, SIP, TCC). Pick a \
         target the user can actually write to so this test can \
         discriminate sandbox denial from ambient denial.",
        target.display()
    );
    assert!(
        target.exists(),
        "positive control incomplete: Disabled run reported success but \
         {} wasn't created. Either the script is silently failing or the \
         target path was interpreted unexpectedly.",
        target.display()
    );
    std::fs::remove_file(target).expect("clean up positive-control artifact");

    // Negative test: under Enforce the same write must be blocked.
    let enforce = match try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce) {
        Some(sb) => sb,
        None => return, // platform lacks an enforcing backend — skip
    };
    let status = run_script(enforce.as_ref(), &fx.pkg_dir, script);
    assert!(
        !status.success(),
        "sandbox regression: Enforce allowed a write that Disabled also \
         allowed — the sandbox's deny-default is not covering {}. \
         Exit was {status:?}.",
        target.display()
    );
    assert!(
        !target.exists(),
        "sandbox escape: forbidden file {} was created under Enforce",
        target.display()
    );
    // Belt-and-braces cleanup in case the sandbox somehow allowed the
    // write despite the above assertion (panicking wouldn't run the
    // remaining cleanup).
    let _ = std::fs::remove_file(target);
}

/// Paired-control read test. Runs `script` under Disabled first
/// (must succeed — reading the file) then under Enforce (must
/// fail — reading blocked). `target` must already contain the
/// fake-sensitive bytes when this is called.
fn assert_sandbox_blocks_read(fx: &SandboxFixture, target: &Path, script: &str) {
    assert!(
        target.exists(),
        "test setup bug: read-probe target {} doesn't exist",
        target.display()
    );

    let noop = try_build_sandbox(fx.spec.clone(), SandboxMode::Disabled)
        .expect("NoopSandbox must always succeed");
    let control_status = run_script(noop.as_ref(), &fx.pkg_dir, script);
    assert!(
        control_status.success(),
        "positive control failed: reading {} under SandboxMode::Disabled \
         returned {control_status:?}. Target isn't user-readable — pick a \
         different path so the test can discriminate sandbox denial from \
         ambient denial.",
        target.display()
    );

    let enforce = match try_build_sandbox(fx.spec.clone(), SandboxMode::Enforce) {
        Some(sb) => sb,
        None => return,
    };
    let status = run_script(enforce.as_ref(), &fx.pkg_dir, script);
    assert!(
        !status.success(),
        "sandbox regression: Enforce allowed a read that Disabled also \
         allowed — the sandbox's deny-default is not covering {}. \
         Exit was {status:?}.",
        target.display()
    );
}

// -------- Case 1: generic read outside allow list --------

#[test]
fn block_read_of_file_outside_allow_list() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("probe", "1.0.0");
    // Secret MUST sit at a path no sandbox rule covers. The fixture's
    // own tempdir root (`fx.tmp_path()`) happens to sit under
    // `/var/folders/.../T/` on macOS (outside the allow list) but
    // under `/tmp/.tmpXXX/` on Linux (INSIDE the `/tmp` allow rule —
    // see describe_rules); earlier revisions used it here, producing
    // a silent Linux pass on macOS and a Linux-CI failure that
    // looked like a sandbox bug. Use `/var/tmp/lpm-probe-<pid>/`
    // instead — it's a standard POSIX scratch directory, user-writable
    // on both platforms, and explicitly not referenced by any rule.
    let secret_dir = std::path::PathBuf::from("/var/tmp")
        .join(format!("lpm-sandbox-escape-sibling-{}", std::process::id()));
    std::fs::create_dir_all(&secret_dir).unwrap();
    let secret = secret_dir.join("id_rsa");
    std::fs::write(&secret, b"FAKE-PRIVATE-KEY").unwrap();

    assert_sandbox_blocks_read(&fx, &secret, &format!("cat {}", secret.display()));
    let _ = std::fs::remove_dir_all(&secret_dir);
}

// -------- Case 2: shell-startup persistence (~/.bashrc-shape) --------

#[test]
fn block_write_to_bashrc_shape_in_home_root() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let home = dirs::home_dir().unwrap();
    let target = home.join(format!(".bashrc.lpm-escape-{}", std::process::id()));
    let fx = SandboxFixture::new("bashrc-probe", "1.0.0");
    assert_sandbox_blocks_write(
        &fx,
        &target,
        &format!("echo persisted > {}", target.display()),
    );
}

// -------- Case 3: home-root config hijack --------

#[test]
fn block_write_to_home_root_config_file() {
    // Replaces the earlier `/etc/hosts` probe, which was a vacuous
    // pass on macOS + Linux — unprivileged users can't write to
    // `/etc` regardless of the sandbox. Target a user-writable
    // `$HOME/.lpmrc-probe-<pid>` instead; threat model is analogous
    // (tool picks up a config file from home root on next run).
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let home = dirs::home_dir().unwrap();
    let target = home.join(format!(".lpmrc-lpm-escape-{}", std::process::id()));
    let fx = SandboxFixture::new("config-probe", "1.0.0");
    assert_sandbox_blocks_write(
        &fx,
        &target,
        &format!("echo '[tool] malicious=true' > {}", target.display()),
    );
}

// -------- Case 4: ssh credential exfiltration --------

#[test]
fn block_read_of_ssh_credential_shape_path() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("ssh-probe", "1.0.0");
    // See `block_read_of_file_outside_allow_list` for why `/var/tmp`
    // (not `fx.tmp_path()`) is the right probe root on Linux.
    let ssh_shape = std::path::PathBuf::from("/var/tmp")
        .join(format!("lpm-sandbox-escape-ssh-{}/.ssh", std::process::id()));
    std::fs::create_dir_all(&ssh_shape).unwrap();
    let id_rsa = ssh_shape.join("id_rsa");
    std::fs::write(&id_rsa, b"-----BEGIN FAKE TEST KEY-----\n").unwrap();

    assert_sandbox_blocks_read(&fx, &id_rsa, &format!("cat {}", id_rsa.display()));
    if let Some(p) = ssh_shape.parent() {
        let _ = std::fs::remove_dir_all(p);
    }
}

// -------- Case 5: AWS credential exfiltration --------

#[test]
fn block_read_of_aws_credentials_shape_path() {
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let fx = SandboxFixture::new("aws-probe", "1.0.0");
    // See `block_read_of_file_outside_allow_list` for why `/var/tmp`
    // (not `fx.tmp_path()`) is the right probe root on Linux.
    let aws_shape = std::path::PathBuf::from("/var/tmp")
        .join(format!("lpm-sandbox-escape-aws-{}/.aws", std::process::id()));
    std::fs::create_dir_all(&aws_shape).unwrap();
    let creds = aws_shape.join("credentials");
    std::fs::write(
        &creds,
        b"[default]\naws_access_key_id = FAKE\naws_secret_access_key = FAKE\n",
    )
    .unwrap();

    assert_sandbox_blocks_read(&fx, &creds, &format!("cat {}", creds.display()));
    if let Some(p) = aws_shape.parent() {
        let _ = std::fs::remove_dir_all(p);
    }
}

// -------- Case 6: LaunchAgents persistence (macOS) --------

#[cfg(target_os = "macos")]
#[test]
fn block_write_to_user_launchagents_macos() {
    // Replaces the earlier `/Library/Keychains` probe, which was a
    // vacuous pass on macOS — SIP + TCC block that for unprivileged
    // processes regardless of the sandbox. Target the USER's
    // `$HOME/Library/LaunchAgents/` directory instead. Users can
    // write there normally (it's how launchd persistence works);
    // the sandbox should block it because `$HOME/Library/
    // LaunchAgents` is NOT in the §9.3 allow list.
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let home = dirs::home_dir().unwrap();
    let launchagents = home.join("Library").join("LaunchAgents");
    let _ = std::fs::create_dir_all(&launchagents); // usually already exists
    let target = launchagents.join(format!("lpm-escape-probe-{}.plist", std::process::id()));
    let fx = SandboxFixture::new("launchagent-probe", "1.0.0");
    assert_sandbox_blocks_write(
        &fx,
        &target,
        &format!("echo '<plist/>' > {}", target.display()),
    );
}

// -------- Case 7: Preferences tamper (macOS) --------

#[cfg(target_os = "macos")]
#[test]
fn block_write_to_user_preferences_macos() {
    // Replaces the earlier `/System/Library` probe, which was a
    // vacuous pass — SIP blocks it regardless of the sandbox.
    // Target the USER's `$HOME/Library/Preferences/` directory.
    // Users write there constantly (it's where user-level apps
    // store preferences); the sandbox should block writes because
    // the subpath isn't in the §9.3 allow list. Threat: tampering
    // with another app's preferences.
    //
    // `Preferences` has no spaces (unlike `Application Support`)
    // so shell-interpolated paths in the test script work without
    // extra quoting — more robust across sh implementations.
    if !sandbox_supported(SandboxMode::Enforce) {
        return;
    }
    let home = dirs::home_dir().unwrap();
    let prefs = home.join("Library").join("Preferences");
    let _ = std::fs::create_dir_all(&prefs); // usually already exists
    let target = prefs.join(format!("lpm-escape-probe-{}.plist", std::process::id()));
    let fx = SandboxFixture::new("prefs-probe", "1.0.0");
    assert_sandbox_blocks_write(
        &fx,
        &target,
        &format!("echo '<plist/>' > {}", target.display()),
    );
}
