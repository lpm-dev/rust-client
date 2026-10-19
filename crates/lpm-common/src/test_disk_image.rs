//! Disk images that macOS tests attach to run on a filesystem of their own.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const HDIUTIL: &str = "/usr/bin/hdiutil";

/// A disk image attached for a test, detached when dropped.
pub struct AttachedImage {
    mount_point: PathBuf,
}

impl AttachedImage {
    /// Creates the image `image` with `create` arguments (size, filesystem,
    /// volume name) and attaches it at `mount_point`, an existing empty
    /// directory, with `attach` arguments, such as `-owners off`.
    ///
    /// # Panics
    ///
    /// When `hdiutil` keeps failing, with what it reported each time.
    #[must_use]
    pub fn new(image: &Path, mount_point: &Path, create: &[&str], attach: &[&str]) -> Self {
        let mut arguments: Vec<&OsStr> = vec!["create".as_ref()];
        arguments.extend(create.iter().map(OsStr::new));
        arguments.push(image.as_os_str());
        hdiutil(&arguments, || {
            let _ = std::fs::remove_file(image);
        });

        let mut arguments: Vec<&OsStr> = vec![
            "attach".as_ref(),
            "-nobrowse".as_ref(),
            "-noautoopen".as_ref(),
        ];
        arguments.extend(attach.iter().map(OsStr::new));
        arguments.extend([
            "-mountpoint".as_ref(),
            mount_point.as_os_str(),
            image.as_os_str(),
        ]);
        hdiutil(&arguments, || detach(mount_point));

        Self {
            mount_point: mount_point.to_owned(),
        }
    }

    /// Where the image's volume is mounted.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.mount_point
    }
}

impl Drop for AttachedImage {
    fn drop(&mut self) {
        detach(&self.mount_point);
    }
}

fn detach(mount_point: &Path) {
    let _ = Command::new(HDIUTIL)
        .args(["detach", "-force", "-quiet"])
        .arg(mount_point)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Runs `hdiutil` with `arguments`, again after a failure: on a loaded
/// machine, as CI runners are, `create` and `attach` sometimes fail once and
/// then succeed. `reset` undoes what a failed run left behind. Never pass
/// `-quiet`, which closes stderr and hides why a run failed.
fn hdiutil(arguments: &[&OsStr], reset: impl Fn()) {
    const ATTEMPTS: u64 = 4;
    let mut failures = Vec::new();
    for attempt in 1..=ATTEMPTS {
        let output = Command::new(HDIUTIL)
            .args(arguments)
            .output()
            .expect("run hdiutil");
        if output.status.success() {
            return;
        }
        failures.push(format!(
            "attempt {attempt}, {}: {} {}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
        reset();
        if attempt < ATTEMPTS {
            std::thread::sleep(Duration::from_millis(500 * attempt));
        }
    }
    panic!("hdiutil {arguments:?} failed:\n{}", failures.join("\n"));
}
