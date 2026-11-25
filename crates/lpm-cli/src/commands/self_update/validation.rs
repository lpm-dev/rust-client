use lpm_common::LpmError;
use std::ffi::OsStr;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 1024 * 1024;

/// The only environment a validation program gets, so none of the caller's
/// variables can change what a system tool does or prints.
const VALIDATION_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

pub(super) fn run(
    program: &str,
    arguments: &[&OsStr],
    description: &str,
    timeout: Duration,
) -> Result<Output, LpmError> {
    let started = Instant::now();
    let mut timed_out = false;
    let mut session = lpm_common::process_output::CaptureSession::default();
    let output = session
        .capture_output(
            Command::new(program)
                .args(arguments)
                .env_clear()
                .env("PATH", VALIDATION_PATH),
            OUTPUT_LIMIT + 1,
            |_| {
                if started.elapsed() >= timeout {
                    timed_out = true;
                    Some(libc::SIGKILL)
                } else {
                    None
                }
            },
        )
        .map_err(|error| LpmError::SelfUpdate(format!("could not run {description}: {error}")))?;
    if timed_out {
        return Err(LpmError::SelfUpdate(format!(
            "{description} exceeded its {}-second deadline",
            timeout.as_secs()
        )));
    }
    if output.stdout.len() > OUTPUT_LIMIT || output.stderr.len() > OUTPUT_LIMIT {
        return Err(LpmError::SelfUpdate(format!(
            "{description} output exceeded {OUTPUT_LIMIT} bytes"
        )));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_deadline_terminates_the_process_and_releases_its_scope() {
        let root = tempfile::tempdir().unwrap();
        let lock_path = root.path().join("update.lock");
        let started = Instant::now();
        let result = lpm_common::with_exclusive_lock(&lock_path, || {
            run(
                "/bin/sleep",
                &[OsStr::new("30")],
                "sleeping fixture",
                Duration::from_millis(50),
            )
        });
        assert!(result.unwrap_err().to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(3));
        lpm_common::with_exclusive_lock(&lock_path, || Ok::<_, LpmError>(())).unwrap();
    }

    #[test]
    fn macos_validation_refuses_excessive_output() {
        let result = run(
            "/bin/sh",
            &[
                OsStr::new("-c"),
                OsStr::new("/usr/bin/head -c 2097152 /dev/zero"),
            ],
            "noisy validation fixture",
            Duration::from_secs(60),
        );
        assert!(result.is_err(), "validation output must be bounded");
    }

    #[test]
    fn macos_validation_does_not_wait_for_inherited_output_after_parent_exit() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("child-pid");
        let script = format!("/bin/sleep 5 & echo $! > '{}'; exit 0", pid_file.display());
        let started = Instant::now();
        let result = run(
            "/bin/sh",
            &[OsStr::new("-c"), OsStr::new(&script)],
            "detached output fixture",
            Duration::from_secs(60),
        );
        let elapsed = started.elapsed();
        if let Ok(pid) = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
        {
            // SAFETY: the PID belongs to the disposable child created by this test.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        result.unwrap();
        assert!(
            elapsed < Duration::from_secs(3),
            "inherited pipe delayed completion: {elapsed:?}"
        );
    }

    #[test]
    fn validation_programs_see_only_the_system_path() {
        let output = run(
            "/usr/bin/env",
            &[],
            "environment fixture",
            Duration::from_secs(60),
        )
        .unwrap();

        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("PATH={VALIDATION_PATH}\n")
        );
    }
}
