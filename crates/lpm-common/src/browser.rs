//! Opening a URL or a file in the user's browser.

use std::ffi::{OsStr, OsString};
use std::io;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long a `BROWSER` command has to fail before it counts as opened. A
/// browser started in the foreground keeps running, so its exit can't be
/// waited for.
const BROWSER_COMMAND_GRACE: Duration = Duration::from_secs(2);

#[cfg(windows)]
const BROWSER_SEPARATOR: char = ';';
#[cfg(not(windows))]
const BROWSER_SEPARATOR: char = ':';

/// Opens `target`, a URL or a file, in the user's browser.
///
/// When `BROWSER` is set, it decides on every platform, as with xdg-open's
/// generic mode and Python's `webbrowser`: a list of commands separated by
/// `:` (`;` on Windows), tried in order. A command's `%s` is replaced by the
/// target; a command without one gets the target as its last argument. A
/// command that can't start, or exits with an error within two seconds,
/// fails, so `BROWSER=false` opens nothing and the caller can show the
/// target instead. Without `BROWSER`, the platform's opener runs.
pub fn open(target: impl AsRef<OsStr>) -> io::Result<()> {
    open_with(
        std::env::var_os("BROWSER").as_deref(),
        target.as_ref(),
        BROWSER_COMMAND_GRACE,
    )
}

fn open_with(browser: Option<&OsStr>, target: &OsStr, grace: Duration) -> io::Result<()> {
    let Some(browser) = browser.filter(|value| !value.is_empty()) else {
        return open::that(target);
    };
    let browser = browser
        .to_str()
        .ok_or_else(|| io::Error::other("BROWSER is not valid UTF-8"))?;
    let mut failure = io::Error::other("BROWSER names no command");
    for entry in browser.split(BROWSER_SEPARATOR) {
        let Some(command) = browser_command(entry, target) else {
            continue;
        };
        match run_browser_command(command, grace) {
            Ok(()) => return Ok(()),
            Err(error) => failure = error,
        }
    }
    Err(failure)
}

/// One `BROWSER` entry as a command for `target`, or None when the entry is
/// empty or its quoting is unbalanced.
fn browser_command(entry: &str, target: &OsStr) -> Option<Command> {
    let words = shlex::split(entry.trim())?;
    let (program, arguments) = words.split_first()?;
    let mut command = Command::new(program);
    let mut substituted = false;
    for argument in arguments {
        if argument.contains("%s") {
            substituted = true;
            let mut replaced = OsString::new();
            for (index, part) in argument.split("%s").enumerate() {
                if index > 0 {
                    replaced.push(target);
                }
                replaced.push(part);
            }
            command.arg(replaced);
        } else {
            command.arg(argument);
        }
    }
    if !substituted {
        command.arg(target);
    }
    Some(command)
}

fn run_browser_command(mut command: Command, grace: Duration) -> io::Result<()> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Its own process group, so Ctrl-C in the terminal doesn't close the
    // browser it starts.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn()?;
    let deadline = Instant::now() + grace;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "the BROWSER command exited with {status}"
                )))
            };
        }
        if Instant::now() >= deadline {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const GRACE: Duration = Duration::from_secs(2);

    fn recorder(directory: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let script = directory.join("record browser");
        let log = directory.join("arguments");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nfor argument in \"$@\"; do printf '%s\\n' \"$argument\"; done > '{}'\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        (script, log)
    }

    #[test]
    fn a_failing_browser_command_fails_so_the_caller_shows_the_target() {
        let error = open_with(
            Some(OsStr::new("false")),
            OsStr::new("https://lpm.dev"),
            GRACE,
        )
        .unwrap_err();
        assert!(error.to_string().contains("exited with"), "{error}");
    }

    #[test]
    fn the_next_browser_command_runs_when_one_fails() {
        let directory = tempfile::tempdir().unwrap();
        let (script, log) = recorder(directory.path());
        let browser = format!("false:'{}'", script.display());

        open_with(
            Some(OsStr::new(&browser)),
            OsStr::new("https://lpm.dev/a b"),
            GRACE,
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            "https://lpm.dev/a b\n"
        );
    }

    #[test]
    fn a_browser_command_gets_the_target_in_place_of_each_percent_s() {
        let directory = tempfile::tempdir().unwrap();
        let (script, log) = recorder(directory.path());
        let browser = format!("'{}' --new-tab url=%s %s", script.display());

        open_with(
            Some(OsStr::new(&browser)),
            OsStr::new("https://lpm.dev"),
            GRACE,
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(log).unwrap(),
            "--new-tab\nurl=https://lpm.dev\nhttps://lpm.dev\n"
        );
    }

    #[test]
    fn a_browser_that_keeps_running_counts_as_opened_without_waiting_for_it() {
        let started = Instant::now();

        open_with(
            Some(OsStr::new("sh -c 'sleep 3' %s")),
            OsStr::new("https://lpm.dev"),
            Duration::from_millis(200),
        )
        .unwrap();

        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_browser_command_that_cant_start_fails() {
        assert!(
            open_with(
                Some(OsStr::new("/nonexistent/lpm-browser")),
                OsStr::new("https://lpm.dev"),
                GRACE
            )
            .is_err()
        );
        assert!(open_with(Some(OsStr::new(":'unbalanced")), OsStr::new("x"), GRACE).is_err());
    }
}
