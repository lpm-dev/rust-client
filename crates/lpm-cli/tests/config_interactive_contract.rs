//! CLI-binary tier: terminal-backed JSON refusal and configuration-editor cancellation.

mod common;

#[cfg(unix)]
mod unix {
    use super::common;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn run_in_terminal(mut command: Command, prompts: &[(&str, &[u8])]) -> (ExitStatus, String) {
        let mut master_fd = -1;
        let mut slave_fd = -1;
        // SAFETY: openpty initializes two distinct owned descriptors on success.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: Each descriptor was returned by openpty and is owned exactly once.
        let mut master = unsafe { File::from_raw_fd(master_fd) };
        // SAFETY: The slave is distinct from the master descriptor.
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        // SAFETY: The master descriptor is live, and O_NONBLOCK is a valid flag.
        unsafe {
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(
                libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
                0
            );
        }
        command
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        let mut child = command.spawn().unwrap();
        drop(command);
        let mut transcript = Vec::new();
        let mut buffer = [0u8; 4096];
        let mut next = 0;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            loop {
                match master.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => transcript.extend_from_slice(&buffer[..n]),
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.raw_os_error() == Some(libc::EIO) =>
                    {
                        break;
                    }
                    Err(error) => panic!("read terminal: {error}"),
                }
            }
            if next < prompts.len()
                && String::from_utf8_lossy(&transcript).contains(prompts[next].0)
            {
                master.write_all(prompts[next].1).unwrap();
                next += 1;
            }
            if let Some(status) = child.try_wait().unwrap() {
                return (
                    status,
                    common::strip_ansi(&String::from_utf8_lossy(&transcript)),
                );
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!(
                    "command did not exit without more input: {}",
                    String::from_utf8_lossy(&transcript)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn focused_json_config_requires_set_even_with_terminal_input() {
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        for setting in [
            "scripts",
            "triage",
            "sandbox",
            "sigstore",
            "signatures",
            "trust-policy",
            "typosquat",
            "firewall",
            "integrity",
            "release-age",
            "release-age-policy",
            "source-analysis",
            "lpm-skills",
            "lpm-insights",
        ] {
            let command = common::lpm_command(
                project.path(),
                home.path(),
                None,
                &["config", setting, "--json"],
            );
            let (status, output) = run_in_terminal(command, &[]);
            assert!(!status.success(), "{setting}: {output}");
            let json: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
            assert_eq!(json["success"], false);
            assert!(json["error"].as_str().unwrap().contains("--set"));
            assert!(!home.path().join("config.toml").exists());
        }
    }

    #[test]
    fn cancelling_triage_selection_preserves_the_original_script_policy() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let project = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let before = "script-policy = \"allow\"\n";
        std::fs::write(home.path().join("config.toml"), before).unwrap();
        let security = home.path().join("security");
        std::fs::create_dir(&security).unwrap();
        let secret = [42u8; 32];
        std::fs::write(security.join("signing-secret.hex"), hex::encode(secret)).unwrap();
        let payload = serde_json::json!({"schema_version":1,"updated_at":chrono::Utc::now().to_rfc3339(),"script_policy":"allow","minimum_release_age_secs":0,"sandbox_mode":"default","sandbox_allow_degraded":false,"sigstore_verify":"deny"});
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        mac.update(&serde_json::to_vec(&payload).unwrap());
        let envelope = serde_json::json!({"payload":payload,"signature":hex::encode(mac.finalize().into_bytes())});
        std::fs::write(
            security.join("approved-posture.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        let bin = home.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let provider = bin.join("claude");
        std::fs::write(&provider, "#!/bin/sh\nexit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut command =
            common::lpm_command(project.path(), home.path(), None, &["config", "triage"]);
        command.env("PATH", &bin);
        let (_, transcript) = run_in_terminal(
            command,
            &[
                ("Switch script-policy", b"y"),
                ("Pick a triage advisor", b"\x1b"),
            ],
        );
        assert!(transcript.contains("Pick a triage advisor"), "{transcript}");
        assert_eq!(
            std::fs::read_to_string(home.path().join("config.toml")).unwrap(),
            before,
            "{transcript}"
        );
    }
}
