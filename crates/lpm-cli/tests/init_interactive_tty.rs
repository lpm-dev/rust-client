//! Cli-binary tier: real TTY prompts, unavailable in the ordinary workflow harness.
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

    fn run_init(
        project: &Path,
        lpm_home: &Path,
        args: &[&str],
        replies: &[(&str, &[u8])],
        before_reply: impl FnOnce(),
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

        let mut command = common::lpm_command(project, lpm_home, None, args);
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
        let mut child = command.spawn().expect("spawn init in PTY");
        drop(command);

        let mut transcript = Vec::new();
        let mut buffer = [0_u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut step = 0;
        let mut scanned = 0;
        let mut before_reply = Some(before_reply);
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

            if let Some((prompt, input)) = replies.get(step)
                && transcript[scanned..]
                    .windows(prompt.len())
                    .any(|part| part == prompt.as_bytes())
            {
                if let Some(callback) = before_reply.take() {
                    callback();
                }
                master.write_all(input).unwrap();
                master.flush().unwrap();
                scanned = transcript.len();
                step += 1;
            }

            if let Some(status) = child.try_wait().expect("poll init") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out init");
                child.wait().expect("reap timed-out init");
                let transcript = String::from_utf8_lossy(&transcript);
                panic!("init prompt did not finish within 5 seconds:\n{transcript}");
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
        (status, transcript)
    }

    #[test]
    fn init_json_never_prompts_even_with_a_terminal() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let (status, output) = run_init(
            project.path(),
            home.path(),
            &["init", "--npm", "--name", "widget", "--json"],
            &[],
            || {},
        );
        assert!(!status.success());
        let json: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert!(json["error"].as_str().unwrap().contains("--yes"), "{json}");
    }

    #[test]
    fn init_rejects_invalid_interactive_versions_before_writes() {
        for version in ["banana", "1.2", "01.2.3", "1.2.3-01"] {
            let project = tempfile::tempdir().unwrap();
            let home = tempfile::tempdir().unwrap();
            let input = format!("{version}\r");
            let (status, output) = run_init(
                project.path(),
                home.path(),
                &["init", "--npm", "--name", "widget"],
                &[("Version", input.as_bytes()), ("Description", b"\r")],
                || {},
            );
            assert!(!status.success(), "accepted {version}: {output}");
            assert!(!project.path().join("package.json").exists());
        }
    }

    #[test]
    fn init_interactive_npm_selection_rejects_owner() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let (status, output) = run_init(
            project.path(),
            home.path(),
            &["init", "--owner", "acme", "--name", "widget"],
            &[
                ("Package target?", b"\x1b[B\r"),
                ("Version", b"\r"),
                ("Description", b"\r"),
            ],
            || {},
        );
        assert!(!status.success(), "ignored owner: {output}");
        assert!(output.contains("--owner"), "{output}");
        assert!(!project.path().join("package.json").exists());
    }

    #[test]
    fn init_preserves_a_manifest_created_during_the_prompts() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let manifest = "{\"name\":\"another-writer\"}\n";
        let (status, output) = run_init(
            project.path(),
            home.path(),
            &["init", "--npm", "--name", "widget"],
            &[("Version", b"\r"), ("Description", b"\r")],
            || {
                std::fs::write(project.path().join("package.json"), manifest).unwrap();
            },
        );
        assert!(!status.success(), "overwrote concurrent manifest: {output}");
        assert_eq!(
            std::fs::read_to_string(project.path().join("package.json")).unwrap(),
            manifest
        );
        assert!(!project.path().join("lpm.json").exists());
    }
}
