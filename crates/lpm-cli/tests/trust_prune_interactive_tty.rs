//! CLI-binary coverage for the `lpm trust prune` confirmation contract.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior.
//! Workflow tests cover explicit `--yes` and non-interactive dry runs. These
//! tests use a real PTY to verify the input-terminal and JSON prompt rules.

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

    use serde_json::json;
    use tempfile::TempDir;

    fn seed_project(project: &Path) {
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec_pretty(&json!({
                "name": "trust-prune-tty",
                "version": "1.0.0",
                "lpm": {
                    "trustedDependencies": {
                        "removed-pkg@1.0.0": { "integrity": "sha512-r" }
                    }
                }
            }))
            .unwrap(),
        )
        .expect("seed package.json");
        std::fs::write(
            project.join("lpm.lock"),
            "[metadata]\nlockfile-version = 1\n",
        )
        .expect("seed lpm.lock");
    }

    fn open_pty() -> (File, File) {
        let mut master_fd = -1;
        let mut slave_fd = -1;
        // SAFETY: `openpty` initializes both owned descriptors when it returns zero.
        let result = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0, "create PTY pair");
        // SAFETY: `openpty` returned unique owned descriptors for these files.
        let master = unsafe { File::from_raw_fd(master_fd) };
        // SAFETY: `openpty` returned unique owned descriptors for these files.
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        (master, slave)
    }

    fn configure_nonblocking(file: &File) {
        // SAFETY: `file` owns a valid descriptor, and these calls only update its flags.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "read PTY flags");
        // SAFETY: `flags | O_NONBLOCK` is valid for this descriptor.
        let result =
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert_eq!(result, 0, "set PTY nonblocking mode");
    }

    fn attach_controlling_terminal(command: &mut std::process::Command) {
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
    }

    fn collect_until_exit(
        child: &mut std::process::Child,
        master: &mut File,
        response: Option<(&[u8], &[u8])>,
    ) -> (ExitStatus, String, bool) {
        configure_nonblocking(master);
        let mut transcript = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut response_sent = false;
        let mut prompt_checked_through = 0;
        let deadline = Instant::now() + Duration::from_secs(15);

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

            if let Some((prompt, input)) = response
                && !response_sent
                && prompt_checked_through != transcript.len()
            {
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

            if let Some(status) = child.try_wait().expect("poll trust prune") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out trust prune");
                child.wait().expect("reap timed-out trust prune");
                panic!(
                    "trust prune did not finish within 15 seconds:\n{}",
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
                Err(error) => panic!("read PTY transcript: {error}"),
            }
        }

        (
            status,
            String::from_utf8_lossy(&transcript).into_owned(),
            response_sent,
        )
    }

    #[test]
    fn trust_prune_json_requires_yes_even_when_attached_to_a_terminal() {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        seed_project(project.path());
        let manifest_before = std::fs::read(project.path().join("package.json")).unwrap();
        let (mut master, slave) = open_pty();
        let mut command = common::lpm_command(
            project.path(),
            lpm_home.path(),
            None,
            &["trust", "prune", "--json"],
        );
        command
            .stdin(Stdio::from(slave.try_clone().expect("clone PTY stdin")))
            .stdout(Stdio::from(slave.try_clone().expect("clone PTY stdout")))
            .stderr(Stdio::from(slave));
        attach_controlling_terminal(&mut command);
        let mut child = command.spawn().expect("spawn JSON trust prune in PTY");
        let (status, transcript, _) = collect_until_exit(&mut child, &mut master, None);
        let transcript = common::strip_ansi(&transcript);

        assert!(
            !status.success(),
            "JSON prune unexpectedly succeeded:\n{transcript}"
        );
        assert!(
            transcript.contains("--yes"),
            "the refusal must require explicit --yes:\n{transcript}"
        );
        assert_eq!(
            std::fs::read(project.path().join("package.json")).unwrap(),
            manifest_before,
            "JSON mode without --yes must not mutate package.json"
        );
    }

    #[test]
    fn trust_prune_prompts_when_stdin_is_a_terminal_and_stdout_is_redirected() {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        seed_project(project.path());
        let (mut master, slave) = open_pty();
        let mut command =
            common::lpm_command(project.path(), lpm_home.path(), None, &["trust", "prune"]);
        command
            .stdin(Stdio::from(slave.try_clone().expect("clone PTY stdin")))
            .stdout(Stdio::piped())
            .stderr(Stdio::from(slave));
        attach_controlling_terminal(&mut command);
        let mut child = command
            .spawn()
            .expect("spawn human trust prune with redirected stdout");
        let (status, transcript, response_sent) = collect_until_exit(
            &mut child,
            &mut master,
            Some((b"Remove 1 stale entry/entries from package.json?", b"y\r")),
        );
        let transcript = common::strip_ansi(&transcript);

        assert!(response_sent, "trust prune did not prompt:\n{transcript}");
        assert!(status.success(), "trust prune failed:\n{transcript}");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(project.path().join("package.json")).unwrap())
                .unwrap();
        assert!(
            manifest["lpm"]["trustedDependencies"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty),
            "accepted confirmation must prune the stale entry: {manifest}"
        );
    }
}
