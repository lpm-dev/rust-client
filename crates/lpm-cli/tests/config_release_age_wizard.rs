//! Cli-binary tier — TTY interaction and machine-readable contracts for
//! release-age configuration.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior and an
//! intentionally minimal binary-surface contract. Inline tests pin the parser,
//! editor state, canonical-seconds persistence, and rendering helpers. This
//! file covers the real guided editor plus the `--json` success envelope that
//! automation reads.

mod common;

use common::{parse_json_stdout, run_lpm};
use tempfile::TempDir;

fn isolated_project() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp LPM_HOME");

    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"release-age-wizard-test","version":"1.0.0"}"#,
    )
    .expect("seed package.json");

    (project, lpm_home)
}

fn lpm_config_path(lpm_home: &TempDir) -> std::path::PathBuf {
    lpm_home.path().join("config.toml")
}

fn read_lpm_config(lpm_home: &TempDir) -> String {
    let path = lpm_config_path(lpm_home);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("config.toml at {} not readable: {e}", path.display()))
}

/// The public machine-readable contract for the wizard is the
/// canonical-seconds envelope, not the human duration the operator
/// typed. This keeps CLI UX human-friendly while preserving a stable
/// config/storage API for downstream automation.
#[test]
fn release_age_wizard_set_duration_with_json_announces_canonical_seconds() {
    let (project, lpm_home) = isolated_project();

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "--json", "release-age", "--set", "3d"],
    );

    assert!(
        status.success(),
        "lpm config --json release-age --set 3d must succeed;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(
        envelope["success"],
        serde_json::json!(true),
        "envelope must report success; got: {envelope}",
    );
    assert_eq!(
        envelope["minimum-release-age-secs"],
        serde_json::json!(259200),
        "envelope must announce canonical seconds, not the raw duration; got: {envelope}",
    );

    let cfg = read_lpm_config(&lpm_home);
    assert!(
        cfg.contains("minimum-release-age-secs = \"259200\""),
        "config.toml must persist canonical seconds after --set 3d; got:\n{cfg}",
    );
}

/// `default` is not a synonym for writing the current built-in value.
/// It means "remove the operator override entirely" so a future
/// product-default change can flow through without another CLI write.
#[test]
fn release_age_wizard_set_default_with_json_deletes_override_and_announces_null() {
    let (project, lpm_home) = isolated_project();
    let config_path = lpm_config_path(&lpm_home);
    std::fs::create_dir_all(config_path.parent().expect("config dir"))
        .expect("create LPM_HOME dir");
    std::fs::write(&config_path, "minimum-release-age-secs = \"259200\"\n")
        .expect("seed release-age override");

    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["config", "--json", "release-age", "--set", "default"],
    );

    assert!(
        status.success(),
        "lpm config --json release-age --set default must succeed;\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(
        envelope["success"],
        serde_json::json!(true),
        "envelope must report success; got: {envelope}",
    );
    assert_eq!(
        envelope["minimum-release-age-secs"],
        serde_json::Value::Null,
        "default must announce that the override is absent; got: {envelope}",
    );

    let cfg = read_lpm_config(&lpm_home);
    assert!(
        !cfg.contains("minimum-release-age-secs"),
        "default must delete the explicit override from config.toml; got:\n{cfg}",
    );
}

#[cfg(unix)]
mod tty {
    use super::*;

    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt as _;
    use std::process::{ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    fn grouped_release_age_input() -> Vec<u8> {
        let mut input = Vec::with_capacity(96);
        for _ in 0..9 {
            input.extend_from_slice(b"\x1b[B");
        }
        input.push(b'\r');
        input.extend_from_slice(b"\x1b[C\x1b[B\x1b[C\r");
        for _ in 0..12 {
            input.extend_from_slice(b"\x1b[B");
        }
        input.push(b'\r');
        input
    }

    fn run_guided_config_in_pty(
        project: &TempDir,
        lpm_home: &TempDir,
        input: &[u8],
    ) -> (ExitStatus, String) {
        let mut master_fd = -1;
        let mut slave_fd = -1;
        // SAFETY: `openpty` initializes both owned descriptors when it returns zero.
        let open_result = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(open_result, 0, "create PTY pair");

        // SAFETY: `openpty` returned unique owned descriptors for these files.
        let mut master = unsafe { File::from_raw_fd(master_fd) };
        // SAFETY: `openpty` returned unique owned descriptors for these files.
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        // SAFETY: `master` owns a valid descriptor, and these calls only update its flags.
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "read PTY flags");
        // SAFETY: `flags | O_NONBLOCK` is valid for this descriptor.
        let set_flags =
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert_eq!(set_flags, 0, "set PTY nonblocking mode");

        let mut command = common::lpm_command(project.path(), lpm_home.path(), None, &["config"]);
        command
            .stdin(Stdio::from(slave.try_clone().expect("clone PTY stdin")))
            .stdout(Stdio::from(slave.try_clone().expect("clone PTY stdout")))
            .stderr(Stdio::from(slave));
        // SAFETY: The closure calls only async-signal-safe session and terminal syscalls.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as libc::c_ulong, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("spawn guided config in PTY");

        let prompt = b"What do you want to configure?";
        let mut transcript = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut input_sent = false;
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            loop {
                match master.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => transcript.extend_from_slice(&buffer[..read]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => panic!("read PTY transcript: {error}"),
                }
            }

            if !input_sent
                && transcript
                    .windows(prompt.len())
                    .any(|window| window == prompt)
            {
                master.write_all(input).expect("write guided editor input");
                master.flush().expect("flush guided editor input");
                input_sent = true;
            }

            if let Some(status) = child.try_wait().expect("poll guided config") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out guided config");
                child.wait().expect("reap timed-out guided config");
                panic!(
                    "guided config did not finish within 20 seconds:\n{}",
                    String::from_utf8_lossy(&transcript)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => transcript.extend_from_slice(&buffer[..read]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::EIO) =>
                {
                    break;
                }
                Err(error) => panic!("read final PTY transcript: {error}"),
            }
        }

        assert!(
            input_sent,
            "guided config exited before showing its menu:\n{}",
            String::from_utf8_lossy(&transcript)
        );
        (status, String::from_utf8_lossy(&transcript).into_owned())
    }

    #[test]
    fn guided_config_edits_release_age_scope_and_minimum_age_on_one_screen() {
        let (project, lpm_home) = isolated_project();
        let input = grouped_release_age_input();

        let (status, transcript) = run_guided_config_in_pty(&project, &lpm_home, &input);

        assert!(status.success(), "guided config failed:\n{transcript}");
        assert!(
            transcript.contains("◆  Release age configuration"),
            "grouped editor header is missing:\n{transcript}"
        );
        assert!(
            transcript.contains("Release-age scope") && transcript.contains("Minimum release age"),
            "both release-age controls must appear in the grouped editor:\n{transcript}"
        );
        assert!(
            transcript.contains("Saved release age configuration: scope = strict, minimum = 3d"),
            "grouped save summary is missing:\n{transcript}"
        );
        let cfg = read_lpm_config(&lpm_home);
        assert!(
            cfg.contains("minimum-release-age-secs = \"259200\"")
                && cfg.contains("release-age-policy = \"strict\""),
            "grouped editor must persist both release-age settings:\n{cfg}"
        );
    }
}
