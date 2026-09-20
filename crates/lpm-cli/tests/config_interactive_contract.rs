//! CLI-binary tier: terminal-backed JSON refusal and configuration-editor cancellation and source-package selection defaults.

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn source_package_optional_select_preserves_unset_and_explicit_defaults() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for default in [None, Some("b")] {
            let server = MockServer::start().await;
            let project = TempDir::new().unwrap();
            let home = TempDir::new().unwrap();
            std::fs::write(
                project.path().join("package.json"),
                r#"{"name":"host","version":"1.0.0"}"#,
            )
            .unwrap();
            let mut field =
                serde_json::json!({"type":"select","label":"Select variant","options":["a","b"]});
            if let Some(default) = default {
                field["default"] = serde_json::json!(default);
            }
            let config = serde_json::json!({
                "configSchema":{"variant":field},
                "files":[
                    {"src":"a.txt","include":"when","condition":{"variant":"a"}},
                    {"src":"b.txt","include":"when","condition":{"variant":"b"}}
                ]
            });
            let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            ));
            for (name, bytes) in [
                (
                    "package.json",
                    br#"{"name":"optional-select-source","version":"1.0.0"}"#.to_vec(),
                ),
                ("lpm.config.json", serde_json::to_vec(&config).unwrap()),
                ("a.txt", b"variant a".to_vec()),
                ("b.txt", b"variant b".to_vec()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, format!("package/{name}"), bytes.as_slice())
                    .unwrap();
            }
            let tarball = tar.into_inner().unwrap().finish().unwrap();
            let metadata = serde_json::json!({
                "name":"optional-select-source", "dist-tags":{"latest":"1.0.0"},
                "versions":{"1.0.0":{"name":"optional-select-source","version":"1.0.0",
                    "dist":{"tarball":format!("{}/source.tgz",server.uri()),"integrity":common::sri_for(&tarball)}}},
                "time":{"1.0.0":"2020-01-01T00:00:00.000Z"}
            });
            for endpoint in [
                "/optional-select-source",
                "/api/registry/optional-select-source",
            ] {
                Mock::given(method("GET"))
                    .and(path(endpoint))
                    .respond_with(ResponseTemplate::new(200).set_body_json(&metadata))
                    .mount(&server)
                    .await;
            }
            Mock::given(method("GET"))
                .and(path("/source.tgz"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
                .mount(&server)
                .await;
            let command = common::lpm_command(
                project.path(),
                home.path(),
                Some(&server.uri()),
                &[
                    "add",
                    "optional-select-source",
                    "--path",
                    "vendor",
                    "--alias",
                    "@/vendor",
                    "--no-install-deps",
                    "--no-skills",
                ],
            );
            let (status, output) = run_in_terminal(command, &[("Select variant", b"\r")]);
            assert!(status.success(), "{output}");
            assert!(
                project.path().join("vendor/b.txt").exists(),
                "Enter lost the unset or explicit default: {output}"
            );
            assert_eq!(
                project.path().join("vendor/a.txt").exists(),
                default.is_none(),
                "{output}"
            );
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
