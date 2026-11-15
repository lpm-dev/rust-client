//! Cli-binary coverage for the confirmation `lpm env oidc allow --org` asks for.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior.
//! The workflow tier covers the refusal without a terminal. These tests use
//! a real PTY to cover what the command shows before it asks, the password
//! prompt, the browser approval, and the write it repeats with the proof.

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
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const ORG_ID: &str = "00000000-0000-4000-8000-000000000001";
    const POLICY_ID: &str = "11111111-1111-4111-8111-111111111111";
    const PROOF: &str = "step-up-proof-jwt";
    const PASSWORD: &str = "correct horse battery staple";
    const APPROVAL_TOKEN: &str = "one-time-approval-token";
    const PROOF_HEADER: &str = "x-lpm-step-up-proof";

    fn scope() -> String {
        format!(
            "vault:oidc-policy:3f2b8c1e-9a4d-4c6b-8e21-5d7f0a9b1c23:{}",
            "ab".repeat(32)
        )
    }

    /// The policy write as the Registry answers it: a confirmation is
    /// required until the request carries the proof.
    struct PolicyWrite;

    impl Respond for PolicyWrite {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            match request
                .headers
                .get(PROOF_HEADER)
                .and_then(|value| value.to_str().ok())
            {
                Some(PROOF) => ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "status": "ok", "policyId": POLICY_ID })),
                _ => ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "error": "Confirm it's you to give CI access to this env project.",
                    "code": "step_up_required",
                    "requiredScope": scope(),
                })),
            }
        }
    }

    /// `POST /api/auth/cli-step-up` for an account that confirms in the
    /// browser: the request for an approval, then the mint with its token.
    struct ApprovalStepUp {
        registry_url: String,
    }

    impl Respond for ApprovalStepUp {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body: serde_json::Value = request.body_json().expect("step-up body");
            if body["approvalToken"] == APPROVAL_TOKEN {
                return ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "ok": true, "proof": PROOF }));
            }
            ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "ok": false,
                "code": "approval_required",
                "authUrl": format!("{}/cli/approve/approval-1", self.registry_url),
                "doneUrl": format!("{}/api/auth/cli-approvals/approval-1/secret", self.registry_url),
            }))
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

    /// Runs `lpm env oidc allow` for an organization's GitLab project in a
    /// PTY. `typed` is a prompt to wait for and what to type at it.
    fn run_allow_in_pty(
        project: &std::path::Path,
        lpm_home: &std::path::Path,
        registry_url: &str,
        typed: Option<(&[u8], &[u8])>,
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

        // `BROWSER=true` stands in for the browser a terminal would open.
        let mut command = common::lpm_command_with_env(
            project,
            lpm_home,
            Some(registry_url),
            &[("BROWSER", "true")],
            &[
                "env",
                "oidc",
                "allow",
                "--org=acme",
                "--allow-server-decryption",
                "--provider=gitlab",
                "--project-id=123",
                "--branch=main",
                "--env=production",
            ],
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
        let mut child = command.spawn().expect("spawn env oidc allow in PTY");
        drop(command);

        let mut transcript = Vec::new();
        let mut buffer = [0_u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut response_sent = false;
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

            if let Some((prompt, response)) = typed
                && !response_sent
                && transcript
                    .windows(prompt.len())
                    .any(|window| window == prompt)
                && terminal_echo_is_disabled(&master)
            {
                master.write_all(response).expect("write prompt response");
                master.flush().expect("flush prompt response");
                response_sent = true;
            }

            if let Some(status) = child.try_wait().expect("poll env oidc allow") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out env oidc allow");
                child.wait().expect("reap timed-out env oidc allow");
                let transcript = String::from_utf8_lossy(&transcript);
                panic!("env oidc allow did not finish within 30 seconds:\n{transcript}");
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
            typed.is_none() || response_sent,
            "env oidc allow exited before it displayed its prompt:\n{transcript}"
        );
        (status, common::strip_ansi(&transcript))
    }

    /// An organization env project this checkout has pulled, a signed-in
    /// CLI, and a Registry that asks for a confirmation of the policy write.
    async fn organization_project() -> (TempDir, TempDir, MockServer) {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"env-oidc-allow-tty","version":"1.0.0"}"#,
        )
        .expect("write package.json");
        std::fs::write(
            project.path().join("lpm.json"),
            r#"{"vault":"org-ci-project"}"#,
        )
        .expect("write lpm.json");

        let server = MockServer::start().await;
        lpm_vault::vault_id::write_org_sync_version_for_principal(
            project.path(),
            "acme",
            7,
            lpm_vault::vault_id::SyncPrincipal {
                registry_url: &server.uri(),
                principal_id: ORG_ID,
            },
        )
        .expect("record the organization binding");
        common::seed_lpm_session(lpm_home.path(), &server.uri(), "session-access-token");
        Mock::given(method("POST"))
            .and(path("/api/vault/oidc/policies"))
            .respond_with(PolicyWrite)
            .mount(&server)
            .await;
        (project, lpm_home, server)
    }

    fn requests_to<'a>(requests: &'a [Request], method: &str, path: &str) -> Vec<&'a Request> {
        requests
            .iter()
            .filter(|request| request.method.as_str() == method && request.url.path() == path)
            .collect()
    }

    /// The transcript lists the policy before anything is asked.
    fn assert_policy_is_listed_before(transcript: &str, asked: &str) {
        let listed = [
            "Giving CI access to this env project needs a confirmation that it's you.",
            "acme",
            "org-ci-project",
            "123",
            "main",
            "production",
        ];
        let asked_at = transcript
            .find(asked)
            .unwrap_or_else(|| panic!("`{asked}` is never shown:\n{transcript}"));
        for text in listed {
            assert!(
                transcript[..asked_at].contains(text),
                "`{text}` isn't shown before `{asked}`:\n{transcript}"
            );
        }
    }

    /// The two policy writes: the first without a proof, the second the
    /// same policy with it.
    fn assert_policy_is_written_again_with_the_proof(requests: &[Request]) -> serde_json::Value {
        let writes = requests_to(requests, "POST", "/api/vault/oidc/policies");
        assert_eq!(writes.len(), 2, "one refused write, one with the proof");
        assert!(writes[0].headers.get(PROOF_HEADER).is_none());
        assert_eq!(
            writes[1]
                .headers
                .get(PROOF_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(PROOF)
        );
        let first: serde_json::Value = writes[0].body_json().expect("policy body");
        let second: serde_json::Value = writes[1].body_json().expect("policy body");
        assert_eq!(first, second, "the confirmed policy is the one first sent");
        first
    }

    /// This Registry signs no vault responses, so the key upload that
    /// follows a saved policy is refused: the command got past the
    /// confirmation and says what state CI access is in.
    fn assert_stopped_after_the_confirmed_write(status: ExitStatus, transcript: &str) {
        assert!(!status.success(), "{transcript}");
        assert!(
            transcript.contains("The OIDC policy may already be saved")
                && transcript.contains("lpm env oidc disable --org=acme"),
            "{transcript}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn allow_lists_the_policy_asks_for_the_password_and_writes_again_with_the_proof() {
        let (project, lpm_home, server) = organization_project().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "password",
                "methods": ["password"],
                "ttlSeconds": 300,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "ok": true, "proof": PROOF })),
            )
            .mount(&server)
            .await;

        let typed = format!("{PASSWORD}\r");
        let (status, transcript) = run_allow_in_pty(
            project.path(),
            lpm_home.path(),
            &server.uri(),
            Some((b"Password", typed.as_bytes())),
        );

        assert_stopped_after_the_confirmed_write(status, &transcript);
        assert_policy_is_listed_before(&transcript, "Password");
        assert!(!transcript.contains(PASSWORD), "{transcript}");
        assert!(!transcript.contains(PROOF), "{transcript}");

        let requests = server.received_requests().await.expect("record requests");
        assert_policy_is_written_again_with_the_proof(&requests);
        let mints = requests_to(&requests, "POST", "/api/auth/cli-step-up");
        assert_eq!(mints.len(), 1, "{transcript}");
        assert_eq!(
            mints[0]
                .body_json::<serde_json::Value>()
                .expect("mint body"),
            serde_json::json!({ "scope": scope(), "method": "password", "password": PASSWORD })
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn allow_sends_the_policy_it_writes_to_the_browser_approval() {
        let (project, lpm_home, server) = organization_project().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "approval",
                "methods": ["approval"],
                "ttlSeconds": 300,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ApprovalStepUp {
                registry_url: server.uri(),
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-approvals/approval-1/secret"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "token": APPROVAL_TOKEN })),
            )
            .mount(&server)
            .await;

        let (status, transcript) =
            run_allow_in_pty(project.path(), lpm_home.path(), &server.uri(), None);

        assert_stopped_after_the_confirmed_write(status, &transcript);
        let approval_url = format!("{}/cli/approve/approval-1", server.uri());
        assert_policy_is_listed_before(&transcript, &approval_url);
        assert!(!transcript.contains(APPROVAL_TOKEN), "{transcript}");
        assert!(!transcript.contains(PROOF), "{transcript}");

        let requests = server.received_requests().await.expect("record requests");
        let mut written = assert_policy_is_written_again_with_the_proof(&requests);
        let step_ups = requests_to(&requests, "POST", "/api/auth/cli-step-up");
        assert_eq!(step_ups.len(), 2, "{transcript}");

        // The scope's digest covers the policy without the fields that say
        // where the write goes, and the approval page is told the same.
        let fields = written.as_object_mut().expect("policy object");
        assert_eq!(fields.remove("org"), Some(serde_json::json!("acme")));
        assert_eq!(
            fields.remove("expectedPrincipalId"),
            Some(serde_json::json!(ORG_ID))
        );
        assert_eq!(
            step_ups[0]
                .body_json::<serde_json::Value>()
                .expect("approval request"),
            serde_json::json!({ "scope": scope(), "method": "approval", "policy": written })
        );
        assert_eq!(
            step_ups[1]
                .body_json::<serde_json::Value>()
                .expect("mint body"),
            serde_json::json!({
                "scope": scope(),
                "method": "approval",
                "approvalToken": APPROVAL_TOKEN,
            })
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn allow_cancelled_at_the_password_prompt_writes_nothing_more() {
        let (project, lpm_home, server) = organization_project().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "password",
                "methods": ["password"],
            })))
            .mount(&server)
            .await;

        let (status, transcript) = run_allow_in_pty(
            project.path(),
            lpm_home.path(),
            &server.uri(),
            Some((b"Password", b"\x03")),
        );

        assert_eq!(
            status.code(),
            Some(130),
            "a cancelled confirmation exits with the interrupt status:\n{transcript}"
        );
        let requests = server.received_requests().await.expect("record requests");
        assert_eq!(
            requests_to(&requests, "POST", "/api/vault/oidc/policies").len(),
            1,
            "the policy isn't sent again without a proof"
        );
        assert!(requests_to(&requests, "POST", "/api/auth/cli-step-up").is_empty());
    }
}
