//! Cli-binary coverage for the `lpm token-rotate` OTP prompt.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior.
//! The workflow tier covers explicit OTP input and non-interactive errors.
//! This test uses a real PTY to cover the challenge prompt and retry.

mod common;

#[cfg(unix)]
mod tty {
    use crate::common;

    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt as _;
    use std::process::{ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, Request, Respond, ResponseTemplate};

    const OTP: &str = "123456";

    struct OtpChallengeResponder;

    impl Respond for OtpChallengeResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            match request
                .headers
                .get("x-otp")
                .and_then(|value| value.to_str().ok())
            {
                None => ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "error": "Two-factor authentication code required to rotate this token.",
                    "code": "OTP_REQUIRED",
                })),
                Some(OTP) => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "token": "replacement-session-token",
                    "expiresAt": "2032-01-03T04:05:06Z",
                })),
                Some(_) => ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "error": "Invalid two-factor authentication code.",
                    "code": "OTP_INVALID",
                })),
            }
        }
    }

    fn terminal_echo_is_disabled(file: &File) -> bool {
        let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `file` owns a valid PTY descriptor and `tcgetattr` initializes
        // `attributes` when it returns zero.
        let result = unsafe { libc::tcgetattr(file.as_raw_fd(), attributes.as_mut_ptr()) };
        assert_eq!(result, 0, "read PTY terminal attributes");
        // SAFETY: The successful `tcgetattr` call initialized `attributes`.
        let attributes = unsafe { attributes.assume_init() };
        attributes.c_lflag & libc::ECHO == 0
    }

    fn run_token_rotate_in_pty(
        project: &std::path::Path,
        lpm_home: &std::path::Path,
        registry_url: &str,
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

        let mut command =
            common::lpm_command(project, lpm_home, Some(registry_url), &["token-rotate"]);
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
        let mut child = command.spawn().expect("spawn token rotation in PTY");
        drop(command);

        let prompt = b"Authenticator code (6 digits)";
        let mut transcript = Vec::new();
        let mut buffer = [0_u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut response_sent = false;
        let mut prompt_seen = false;
        let mut prompt_checked_through = 0;
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

            if !prompt_seen && prompt_checked_through != transcript.len() {
                let scan_start = prompt_checked_through.saturating_sub(prompt.len() - 1);
                prompt_checked_through = transcript.len();
                if transcript[scan_start..]
                    .windows(prompt.len())
                    .any(|window| window == prompt)
                {
                    prompt_seen = true;
                }
            }

            if prompt_seen && !response_sent && terminal_echo_is_disabled(&master) {
                master
                    .write_all(format!("{OTP}\r").as_bytes())
                    .expect("write OTP response");
                master.flush().expect("flush OTP response");
                response_sent = true;
            }

            if let Some(status) = child.try_wait().expect("poll token rotation") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out token rotation");
                child.wait().expect("reap timed-out token rotation");
                let transcript = String::from_utf8_lossy(&transcript);
                panic!("OTP prompt did not finish within 15 seconds:\n{transcript}");
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
            "token rotation exited before it displayed the OTP prompt:\n{transcript}"
        );
        (status, transcript)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_rotate_prompts_after_otp_challenge_and_retries_once() {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"token-rotate-tty","version":"1.0.0"}"#,
        )
        .expect("write package.json");

        let server = wiremock::MockServer::start().await;
        common::seed_lpm_token(project.path(), &server.uri(), "old-session-token");
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/rotate"))
            .respond_with(OtpChallengeResponder)
            .expect(2)
            .mount(&server)
            .await;

        let (status, transcript) =
            run_token_rotate_in_pty(project.path(), lpm_home.path(), &server.uri());
        let transcript = common::strip_ansi(&transcript);

        assert!(status.success(), "token rotation failed:\n{transcript}");
        assert!(transcript.contains("Authenticator code (6 digits)"));
        assert!(transcript.contains("session token rotated successfully"));
        assert!(!transcript.contains(OTP));
        assert!(!transcript.contains("old-session-token"));
        assert!(!transcript.contains("replacement-session-token"));

        let requests = server.received_requests().await.expect("record requests");
        assert_eq!(requests.len(), 2, "challenge must cause exactly one retry");
        assert!(requests[0].headers.get("x-otp").is_none());
        assert_eq!(
            requests[1]
                .headers
                .get("x-otp")
                .and_then(|value| value.to_str().ok()),
            Some(OTP)
        );
    }
}
