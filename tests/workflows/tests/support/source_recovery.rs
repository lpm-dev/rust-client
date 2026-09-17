use std::io::{Read as _, Seek as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn interrupt(mut command: Command, marker: &Path, stage: &str, source_path: Option<&str>) {
    let _ = std::fs::remove_file(marker);
    let mut output = tempfile::tempfile().unwrap();
    command
        .env("LPM_TEST_SOURCE_RECOVERY_STAGE", stage)
        .env("LPM_TEST_SOURCE_RECOVERY_MARKER", marker)
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output.try_clone().unwrap()));
    if let Some(path) = source_path {
        command.env("LPM_TEST_SOURCE_RECOVERY_PATH", path);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            output.rewind().unwrap();
            let mut text = String::new();
            output.read_to_string(&mut text).unwrap();
            panic!("command finished with {status} before {stage}: {text}");
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("command did not reach {stage}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.kill().unwrap();
    child.wait().unwrap();
}
