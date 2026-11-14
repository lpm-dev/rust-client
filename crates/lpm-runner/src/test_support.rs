use std::path::Path;
use std::process::Child;

/// A script that succeeds only where each variable holds its value, written
/// for the shell lpm runs scripts with: `sh` on Unix, `cmd.exe` on Windows.
pub(crate) fn script_expecting_env(expected: &[(&str, &str)]) -> String {
    let checks = expected.iter().map(|(name, value)| {
        if cfg!(windows) {
            // Parenthesized, so that `exit` doesn't take the next check as
            // part of its own command.
            format!(r#"(if not "%{name}%"=="{value}" exit 1)"#)
        } else {
            format!(r#"test "${name}" = "{value}""#)
        }
    });
    let separator = if cfg!(windows) { " & " } else { " && " };
    checks.collect::<Vec<_>>().join(separator)
}

/// A script that creates an empty file at `path`, written for the shell lpm
/// runs scripts with.
pub(crate) fn script_creating_file(path: &Path) -> String {
    if cfg!(windows) {
        format!(r#"type nul > "{}""#, path.display())
    } else {
        format!("touch '{}'", path.display())
    }
}

pub(crate) struct KillOnDropChild(Child);

impl KillOnDropChild {
    pub(crate) fn new(child: Child) -> Self {
        Self(child)
    }

    pub(crate) fn id(&self) -> u32 {
        self.0.id()
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for KillOnDropChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn child_is_reaped_when_the_fixture_body_panics() {
    let mut pid = None;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let child = KillOnDropChild::new(
            std::process::Command::new("node")
                .args(["-e", "setInterval(()=>{},1000)"])
                .spawn()
                .unwrap(),
        );
        pid = Some(child.id());
        panic!("injected fixture panic");
    }));
    assert!(panic.is_err());
    assert!(!crate::ports::process_is_running(pid.unwrap()));
}

#[cfg(unix)]
pub(crate) struct ProcessSpawners {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl ProcessSpawners {
    pub(crate) fn new() -> Self {
        let mut spawners = Self {
            stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            threads: Vec::with_capacity(4),
        };
        for _ in 0..4 {
            let stop = std::sync::Arc::clone(&spawners.stop);
            spawners.threads.push(std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = std::process::Command::new("true").status();
                }
            }));
        }
        spawners
    }
}

#[cfg(unix)]
impl Drop for ProcessSpawners {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut worker_panicked = false;
        for thread in self.threads.drain(..) {
            worker_panicked |= thread.join().is_err();
        }
        if !std::thread::panicking() {
            assert!(!worker_panicked, "process-spawning worker panicked");
        }
    }
}

#[cfg(unix)]
#[test]
fn process_spawners_stop_and_join_when_the_body_panics() {
    let mut shutdown = None;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let spawners = ProcessSpawners::new();
        shutdown = Some(std::sync::Arc::downgrade(&spawners.stop));
        panic!("injected body panic");
    }));
    assert!(panic.is_err());
    let shutdown = shutdown.unwrap();
    let stopped = shutdown.upgrade().is_none();
    if let Some(stop) = shutdown.upgrade() {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    assert!(stopped, "process-spawning workers survived the body panic");
}

#[test]
fn scripts_expecting_env_succeed_only_where_every_value_matches() {
    let path = std::env::var("PATH").unwrap_or_default();
    let run = |command: &str, envs: &[(&str, &str)]| {
        let envs = envs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        crate::shell::spawn_shell(&crate::shell::ShellCommand {
            command,
            cwd: Path::new("."),
            path: &path,
            envs: &envs,
        })
        .unwrap()
        .success()
    };
    let script = script_expecting_env(&[("LPM_FIRST", "one"), ("LPM_SECOND", "two")]);

    assert!(run(&script, &[("LPM_FIRST", "one"), ("LPM_SECOND", "two")]));
    assert!(!run(
        &script,
        &[("LPM_FIRST", "one"), ("LPM_SECOND", "other")]
    ));
    assert!(!run(
        &script,
        &[("LPM_FIRST", "other"), ("LPM_SECOND", "two")]
    ));
    assert!(!run(&script, &[("LPM_FIRST", "one")]));
}

#[test]
fn a_script_creating_a_file_creates_it_under_a_path_with_spaces() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("with space").join("marker");
    std::fs::create_dir(marker.parent().unwrap()).unwrap();
    let path = std::env::var("PATH").unwrap_or_default();

    let status = crate::shell::spawn_shell(&crate::shell::ShellCommand {
        command: &script_creating_file(&marker),
        cwd: directory.path(),
        path: &path,
        envs: &std::collections::HashMap::new(),
    })
    .unwrap();

    assert!(status.success());
    assert!(marker.is_file());
}
