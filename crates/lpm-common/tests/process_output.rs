use lpm_common::process_output::output_capped;
use std::io;
use std::process::Command;
use std::time::{Duration, Instant};

fn shell(_unix: &str, _windows: &str) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new("cmd");
        command.args(["/D", "/S", "/C"]).raw_arg(_windows);
        command
    }
    #[cfg(not(windows))]
    {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", _unix]);
        command
    }
}

#[test]
fn exact_stdout_limit_preserves_all_bytes_and_rejects_one_more() {
    for (limit, success) in [(6, true), (5, false)] {
        let result = output_capped(
            &mut shell("printf 123456", "<nul set /p =123456"),
            Duration::from_secs(5),
            limit,
        );
        if success {
            assert_eq!(result.unwrap().stdout, b"123456");
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }
}

#[cfg(unix)]
#[test]
fn probe_drains_output_larger_than_a_pipe_buffer() {
    let output = output_capped(
        &mut shell("head -c 300000 /dev/zero", ""),
        Duration::from_secs(5),
        300_000,
    )
    .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 300_000);
}

#[test]
fn probe_closes_stdin_discards_stderr_and_preserves_failure_status() {
    let output = output_capped(
        &mut shell(
            "read ignored; printf error >&2; printf output; exit 23",
            r#"set /p "ignored=" & echo error >&2 & <nul set /p "=output" & exit /b 23"#,
        ),
        Duration::from_secs(5),
        100,
    )
    .unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"output");
    assert!(output.stderr.is_empty());
}

#[test]
fn probe_times_out_after_a_valid_prefix_when_the_child_hangs() {
    let started = Instant::now();
    let error = output_capped(
        &mut shell(
            "printf v22.18.0; sleep 20",
            "echo v22.18.0 & ping -n 21 127.0.0.1 >nul",
        ),
        Duration::from_millis(200),
        4096,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn probe_times_out_when_an_exited_root_leaves_stdout_with_a_descendant() {
    let started = Instant::now();
    let error = output_capped(
        &mut shell("sleep 20 & printf v22.18.0; exit 0", ""),
        Duration::from_millis(200),
        4096,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
#[ignore = "subprocess fixture for escaped probe cleanup"]
fn probe_group_escape_fixture() {
    assert_eq!(
        std::env::var("LPM_PROBE_ESCAPE_FIXTURE").as_deref(),
        Ok("1")
    );
    // SAFETY: this subprocess changes only its own process group within its session.
    assert_eq!(
        unsafe { libc::setpgid(0, libc::getpgid(libc::getppid())) },
        0
    );
    std::thread::sleep(Duration::from_secs(20));
}

#[cfg(unix)]
#[test]
fn probe_deadline_still_kills_an_owned_root_that_changes_its_group() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "probe_group_escape_fixture", "--ignored"])
        .env("LPM_PROBE_ESCAPE_FIXTURE", "1");
    let started = Instant::now();
    let error = output_capped(&mut command, Duration::from_millis(200), 4096).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "probe root outlived the deadline"
    );
}
