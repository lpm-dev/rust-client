//! Cli-binary tier: benchmark defaults depend on a real terminal, which the workflow output harness does not provide.
#![cfg(unix)]
mod common;

fn run_bench_terminal(args: &[&str], watch: bool) {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("package.json"), r#"{"name":"bench-terminal","private":true,"workspaces":["packages/*"],"devDependencies":{"vitest":"4.1.9"}}"#).unwrap();
    for name in ["a", "b"] {
        let member = project.path().join("packages").join(name);
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            member.join("package.json"),
            serde_json::json!({"name":name,"version":"1.0.0","devDependencies":{"vitest":"4.1.9"}})
                .to_string(),
        )
        .unwrap();
    }
    let bins = project.path().join("node_modules/.bin");
    std::fs::create_dir_all(&bins).unwrap();
    let executable = bins.join("vitest");
    std::fs::write(&executable, "#!/usr/bin/env node\nif(!process.stdout.isTTY)process.exit(21);const run=process.argv.includes('--run');console.log(run?'BENCH_FINISHED':'BENCH_WATCHING');if(!run)setInterval(()=>{},1000);\n").unwrap();
    std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut master_fd = -1;
    let mut slave_fd = -1;
    // SAFETY: openpty initializes two uniquely owned descriptors on success.
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
    // SAFETY: successful openpty transferred ownership of these descriptors.
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    // SAFETY: successful openpty transferred ownership of these descriptors.
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    // SAFETY: master owns a valid descriptor; only its read flags change.
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    // SAFETY: master owns a valid descriptor and flags are valid.
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let mut command = common::lpm_command(project.path(), home.path(), None, args);
    command
        .process_group(0)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    let mut child = command.spawn().unwrap();
    drop(command);
    let group = child.id() as i32;
    let mut transcript = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut read_available = |transcript: &mut Vec<u8>| loop {
        match master.read(&mut buffer) {
            Ok(0) => return,
            Ok(count) => transcript.extend_from_slice(&buffer[..count]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(libc::EIO) =>
            {
                return;
            }
            Err(error) => panic!("terminal read failed: {error}"),
        }
    };
    // A loaded macOS runner can take seconds just to launch the debug binary, so the deadline
    // only bounds a hung benchmark; the expected outcomes end the wait as soon as they occur.
    let deadline = Instant::now() + BENCH_TERMINAL_TIMEOUT;
    let outcome = loop {
        read_available(&mut transcript);
        if let Some(status) = child.try_wait().unwrap() {
            read_available(&mut transcript);
            break BenchOutcome::Exited(status);
        }
        if String::from_utf8_lossy(&transcript).contains("BENCH_WATCHING") {
            break BenchOutcome::Watching;
        }
        if Instant::now() >= deadline {
            break BenchOutcome::TimedOut;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // SAFETY: only the fixture's isolated process group receives cleanup.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    let transcript = String::from_utf8_lossy(&transcript);
    match (watch, outcome) {
        (true, BenchOutcome::Watching) => {}
        (false, BenchOutcome::Exited(status)) if status.success() => {
            assert!(transcript.contains("BENCH_FINISHED"), "{transcript}");
        }
        (true, outcome) => panic!("explicit watch did not stay active ({outcome:?}): {transcript}"),
        (false, BenchOutcome::Watching) => {
            panic!("default benchmark entered watch mode: {transcript}")
        }
        (false, outcome) => panic!("default benchmark did not finish ({outcome:?}): {transcript}"),
    }
}

const BENCH_TERMINAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug)]
enum BenchOutcome {
    Exited(std::process::ExitStatus),
    Watching,
    TimedOut,
}

#[test]
fn bench_finishes_in_a_terminal_by_default() {
    run_bench_terminal(&["bench"], false);
}

#[test]
fn workspace_bench_finishes_in_a_terminal_by_default() {
    run_bench_terminal(&["bench", "--all"], false);
}

#[test]
fn single_member_bench_watch_stays_active_in_a_terminal() {
    run_bench_terminal(&["bench", "--filter", "a", "--", "--watch"], true);
}
