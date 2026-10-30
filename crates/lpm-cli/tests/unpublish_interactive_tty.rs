//! CLI-binary coverage for the `lpm unpublish` prompts.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior.
//! The workflow tier covers `--yes`, `--json`, and runs without a terminal.
//! These tests use a real PTY to cover the confirmation and the
//! authenticator code asked for after the registry's challenge.

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
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const UNPUBLISH_PATH: &str = "/api/registry/-/package/unpublish";
    const CONFIRMATION: &[u8] = b"This can't be undone.";
    const OTP: &str = "123456";

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

    /// Runs `lpm unpublish` in a PTY, answering each prompt in turn once it
    /// shows and the terminal reads keys.
    fn run_unpublish_in_pty(
        project: &std::path::Path,
        lpm_home: &std::path::Path,
        registry_url: &str,
        answers: &[(&[u8], &[u8])],
    ) -> (ExitStatus, String, usize) {
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

        let mut command = common::lpm_command(
            project,
            lpm_home,
            Some(registry_url),
            &["unpublish", "@lpm.dev/acme.kit@1.2.3"],
        );
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
        let mut child = command.spawn().expect("spawn unpublish in PTY");
        drop(command);

        let mut transcript = Vec::new();
        let mut buffer = [0_u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut answered = 0;
        let mut scanned_from = 0;
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

            if let Some((prompt, answer)) = answers.get(answered)
                && transcript[scanned_from..]
                    .windows(prompt.len())
                    .any(|window| window == *prompt)
                && terminal_echo_is_disabled(&master)
            {
                master.write_all(answer).expect("answer the prompt");
                master.flush().expect("flush the answer");
                answered += 1;
                scanned_from = transcript.len();
            }

            if let Some(status) = child.try_wait().expect("poll unpublish") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out unpublish");
                child.wait().expect("reap timed-out unpublish");
                let transcript = String::from_utf8_lossy(&transcript);
                panic!("unpublish did not finish within 15 seconds:\n{transcript}");
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
            common::strip_ansi(&String::from_utf8_lossy(&transcript)),
            answered,
        )
    }

    struct Fixture {
        project: TempDir,
        lpm_home: TempDir,
        server: MockServer,
    }

    async fn fixture() -> Fixture {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"unpublish-tty","version":"1.0.0"}"#,
        )
        .expect("write package.json");
        let server = MockServer::start().await;
        common::seed_lpm_token(lpm_home.path(), &server.uri(), "session-token");
        Fixture {
            project,
            lpm_home,
            server,
        }
    }

    fn unpublished() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "package": "@lpm.dev/acme.kit",
            "version": "1.2.3",
        }))
    }

    async fn unpublish_requests(server: &MockServer) -> Vec<Request> {
        server
            .received_requests()
            .await
            .expect("record requests")
            .into_iter()
            .filter(|request| request.url.path() == UNPUBLISH_PATH)
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unpublish_asks_first_and_unpublishes_once_confirmed() {
        let fixture = fixture().await;
        Mock::given(method("POST"))
            .and(path(UNPUBLISH_PATH))
            .respond_with(unpublished())
            .mount(&fixture.server)
            .await;

        let (status, transcript, answered) = run_unpublish_in_pty(
            fixture.project.path(),
            fixture.lpm_home.path(),
            &fixture.server.uri(),
            &[(CONFIRMATION, b"y")],
        );

        assert!(status.success(), "unpublish failed:\n{transcript}");
        assert_eq!(answered, 1, "{transcript}");
        assert!(
            transcript.contains("Unpublish @lpm.dev/acme.kit@1.2.3?"),
            "{transcript}"
        );
        assert!(
            transcript.contains("unpublished @lpm.dev/acme.kit@1.2.3"),
            "{transcript}"
        );
        assert_eq!(unpublish_requests(&fixture.server).await.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unpublish_defaults_to_no_and_sends_nothing() {
        let fixture = fixture().await;
        Mock::given(method("POST"))
            .and(path(UNPUBLISH_PATH))
            .respond_with(unpublished())
            .mount(&fixture.server)
            .await;

        let (status, transcript, answered) = run_unpublish_in_pty(
            fixture.project.path(),
            fixture.lpm_home.path(),
            &fixture.server.uri(),
            &[(CONFIRMATION, b"\r")],
        );

        assert!(
            status.success(),
            "a declined unpublish isn't an error:\n{transcript}"
        );
        assert_eq!(answered, 1, "{transcript}");
        assert!(transcript.contains("Unpublish cancelled"), "{transcript}");
        assert!(unpublish_requests(&fixture.server).await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unpublish_asks_an_authenticator_account_for_its_code_and_retries_once() {
        let fixture = fixture().await;
        let base = fixture.server.uri();
        Mock::given(method("POST"))
            .and(path(UNPUBLISH_PATH))
            .respond_with(move |request: &Request| {
                match request
                    .headers
                    .get("x-otp")
                    .and_then(|value| value.to_str().ok())
                {
                    Some(OTP) => unpublished(),
                    _ => ResponseTemplate::new(401).set_body_json(serde_json::json!({
                        "error": "Approve this unpublish in your browser, or send an authenticator code.",
                        "code": "OTP_REQUIRED",
                        "otp": true,
                        "passkey": false,
                        "authUrl": format!("{base}/cli/approve/approval-1"),
                        "doneUrl": format!("{base}/api/auth/cli-approvals/approval-1/poll"),
                    })),
                }
            })
            .mount(&fixture.server)
            .await;

        let code = format!("{OTP}\r");
        let (status, transcript, answered) = run_unpublish_in_pty(
            fixture.project.path(),
            fixture.lpm_home.path(),
            &fixture.server.uri(),
            &[
                (CONFIRMATION, b"y"),
                (b"Authenticator code (6 digits)", code.as_bytes()),
            ],
        );

        assert!(status.success(), "unpublish failed:\n{transcript}");
        assert_eq!(answered, 2, "{transcript}");
        assert!(!transcript.contains(OTP), "{transcript}");
        assert!(!transcript.contains("cli/approve"), "{transcript}");
        let requests = unpublish_requests(&fixture.server).await;
        assert_eq!(requests.len(), 2, "the challenge causes exactly one retry");
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
