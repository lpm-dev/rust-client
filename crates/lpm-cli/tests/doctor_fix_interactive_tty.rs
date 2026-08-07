//! Cli-binary coverage for the `lpm doctor --fix` confirmation prompt.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior.
//! The workflow tier covers non-interactive refusal and `--yes`. These
//! tests use a real PTY to cover prompt acceptance and rejection.

mod common;

#[cfg(unix)]
mod tty {
    use crate::common;

    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt as _;
    use std::path::Path;
    use std::process::{ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    fn seed_fixable_project(project: &Path) {
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"doctor-confirm-tty","version":"1.0.0"}"#,
        )
        .expect("seed package.json");
        std::fs::create_dir_all(project.join("node_modules")).expect("seed node_modules");
        std::fs::create_dir_all(project.join(".lpm/hoisted")).expect("seed hoisted state");
        std::fs::write(
            project.join(".lpm/hoisted/metadata.json"),
            r#"{"version":1,"members":{},"packages":{}}"#,
        )
        .expect("seed hoisted metadata");
        std::fs::write(
            project.join("lpm.lock"),
            "[metadata]\nlockfile-version = 1\n",
        )
        .expect("seed lpm.lock");
    }

    fn run_doctor_fix_in_pty(
        project: &Path,
        lpm_home: &Path,
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
        // SAFETY: `master` owns a valid descriptor, and `flags | O_NONBLOCK` is valid.
        let set_flags =
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert_eq!(set_flags, 0, "set PTY nonblocking mode");

        let mut command = common::lpm_command(project, lpm_home, None, &["doctor", "--fix"]);
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
        let mut child = command.spawn().expect("spawn doctor in PTY");
        drop(command);

        let mut transcript = Vec::new();
        let mut buffer = [0_u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut response_sent = false;
        let mut prompt_checked_through = 0;
        let prompt = b"Apply these automatic fixes?";
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

            if !response_sent && prompt_checked_through != transcript.len() {
                let scan_start = prompt_checked_through.saturating_sub(prompt.len() - 1);
                prompt_checked_through = transcript.len();
                if transcript[scan_start..]
                    .windows(prompt.len())
                    .any(|window| window == prompt)
                {
                    master.write_all(input).expect("write prompt response");
                    master.flush().expect("flush prompt response");
                    response_sent = true;
                }
            }

            if let Some(status) = child.try_wait().expect("poll doctor") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out doctor");
                child.wait().expect("reap timed-out doctor");
                let transcript = String::from_utf8_lossy(&transcript);
                panic!("doctor prompt did not finish within 15 seconds:\n{transcript}");
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
                Err(error) => panic!("read PTY transcript: {error}"),
            }
        }

        let transcript = String::from_utf8_lossy(&transcript).into_owned();
        assert!(
            response_sent,
            "doctor exited before it displayed the confirmation prompt:\n{transcript}"
        );

        (status, transcript)
    }

    #[test]
    fn accepting_doctor_fix_confirmation_applies_the_planned_fix() {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        seed_fixable_project(project.path());

        let (status, transcript) = run_doctor_fix_in_pty(project.path(), lpm_home.path(), b"y\r");
        let transcript = common::strip_ansi(&transcript);

        assert!(status.success(), "doctor failed:\n{transcript}");
        assert!(
            project.path().join("lpm.lockb").exists(),
            "accepted confirmation must apply the planned fix\n{transcript}"
        );
        assert!(
            transcript.contains("reconcile lpm.lockb"),
            "the plan must list the lockfile action\n{transcript}"
        );
        assert!(
            transcript.contains("Apply these automatic fixes?"),
            "doctor must show the confirmation\n{transcript}"
        );
    }

    #[test]
    fn declining_doctor_fix_confirmation_leaves_the_project_unchanged() {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        seed_fixable_project(project.path());

        let (status, transcript) = run_doctor_fix_in_pty(project.path(), lpm_home.path(), b"n\r");
        let transcript = common::strip_ansi(&transcript);

        assert!(!status.success(), "declined doctor unexpectedly succeeded");
        assert!(
            !project.path().join("lpm.lockb").exists(),
            "declined confirmation must not apply the planned fix\n{transcript}"
        );
        assert!(
            transcript.contains("Automatic fixes were declined. No changes were made."),
            "the decline error must state that no changes were made\n{transcript}"
        );
        assert!(
            transcript.contains("Apply these automatic fixes?"),
            "doctor must show the confirmation\n{transcript}"
        );
    }
}
