//! Cli-binary tier: real-terminal certificate consent and interactive dev hooks.
mod common;

#[cfg(all(unix, debug_assertions))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dev_certificate_consent_stays_visible_before_dependency_installation() {
    use std::time::Duration;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("package.json"), r#"{"name":"consent-visibility","version":"1.0.0","scripts":{"dev":"node server.js"},"dependencies":{"delayed-dependency":"1.0.0"}}"#).unwrap();
    let (visible, _, transcript) = run_dev_tty(
        project.path(),
        home.path(),
        Some(&server.uri()),
        &["dev", "--https", "--no-open"],
        &["Fingerprint:", "Install now?"],
        b"n\r",
    );
    assert!(
        visible,
        "certificate consent disappeared during startup:\n{transcript}"
    );
}

#[cfg(all(unix, debug_assertions))]
fn run_dev_tty(
    project: &std::path::Path,
    home: &std::path::Path,
    registry: Option<&str>,
    args: &[&str],
    prompts: &[&str],
    reply: &[u8],
) -> (bool, Option<std::process::ExitStatus>, String) {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let mut master_fd = -1;
    let mut slave_fd = -1;
    // SAFETY: openpty initializes both owned descriptors on success.
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
    // SAFETY: each descriptor is uniquely owned after successful openpty.
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    // SAFETY: each descriptor is uniquely owned after successful openpty.
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    // SAFETY: the descriptor is valid; fcntl only changes its read mode.
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    // SAFETY: the descriptor and flags are valid.
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let mut command = common::lpm_command(project, home, registry, args);
    command
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", home.join("test-trust"))
        .env("LPM_CERT_AUDIT_DIR", home.join("cert-audit"))
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    // SAFETY: only async-signal-safe terminal/session syscalls run after fork.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1
                || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as libc::c_ulong, 0) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut transcript = Vec::new();
    let mut buffer = [0u8; 4096];
    let visible = loop {
        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => transcript.extend_from_slice(&buffer[..count]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::EIO) =>
                {
                    break;
                }
                Err(error) => panic!("read consent transcript: {error}"),
            }
        }
        let text = String::from_utf8_lossy(&transcript);
        if prompts.iter().all(|prompt| text.contains(prompt)) {
            break true;
        }
        if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = master.write_all(reply);
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            if let Ok(pid) = std::fs::read_to_string(project.join("hook.pid"))
                && let Ok(pid) = pid.parse::<i32>()
            {
                // SAFETY: this PID belongs to the hook recorded by this fixture.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            // SAFETY: this process group was created for the fixture above.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(master);
    let deadline = Instant::now() + Duration::from_secs(1);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    (
        visible,
        status,
        String::from_utf8_lossy(&transcript).into_owned(),
    )
}

#[cfg(all(unix, debug_assertions))]
#[test]
fn dev_hooks_can_read_from_the_foreground_terminal() {
    for phase in ["predev", "postdev"] {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("package.json"),
            serde_json::json!({
                "name":"interactive-hook", "version":"1.0.0",
                "scripts":{"dev":"node -e \"\"",phase:"node hook.js"}
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            project.path().join("hook.js"),
            r#"
const fs=require('fs');
fs.writeFileSync('hook.pid',String(process.pid));
console.log('Hook input:');
const buffer=Buffer.alloc(32);
const count=fs.readSync(0,buffer,0,buffer.length,null);
fs.writeFileSync('reply.txt',buffer.subarray(0,count));
"#,
        )
        .unwrap();
        let (visible, status, transcript) = run_dev_tty(
            project.path(),
            home.path(),
            None,
            &["dev", "--no-install", "--no-open"],
            &["Hook input:"],
            b"yes\r",
        );
        if !status.is_some_and(|status| status.success())
            && let Ok(pid) = std::fs::read_to_string(project.path().join("hook.pid"))
            && let Ok(pid) = pid.parse::<i32>()
        {
            // SAFETY: the PID belongs to the hook launched in this fixture.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert!(
            visible && status.is_some_and(|status| status.success()),
            "{phase} could not read terminal input: {status:?}\n{transcript}"
        );
        assert_eq!(
            std::fs::read_to_string(project.path().join("reply.txt"))
                .unwrap()
                .trim(),
            "yes"
        );
    }
}
