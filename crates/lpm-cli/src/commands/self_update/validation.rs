use lpm_common::LpmError;
use std::ffi::OsStr;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 1024 * 1024;

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
            Command::new(program).args(arguments),
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
}
