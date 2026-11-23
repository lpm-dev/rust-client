//! Running `lpm-rs` in a pseudo-terminal, for the TTY/stdin interactive
//! cases the workflow tier can't reach: prompts, echo and Ctrl+C.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Whether the terminal behind `file` echoes what's typed.
pub fn terminal_echo_is_disabled(file: &File) -> bool {
    let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `file` owns a valid PTY descriptor and `tcgetattr` initializes
    // `attributes` when it returns zero.
    let result = unsafe { libc::tcgetattr(file.as_raw_fd(), attributes.as_mut_ptr()) };
    assert_eq!(result, 0, "read PTY terminal attributes");
    // SAFETY: The successful `tcgetattr` call initialized `attributes`.
    let attributes = unsafe { attributes.assume_init() };
    attributes.c_lflag & libc::ECHO == 0
}

/// How a command run in a PTY ended.
pub struct PtySession {
    pub status: ExitStatus,
    /// Everything the command wrote, escapes included.
    pub raw: Vec<u8>,
    /// What the command wrote, without ANSI escapes.
    pub transcript: String,
    /// The terminal echoes again once the command exited.
    pub echo_restored: bool,
    /// Input bytes still waiting in the terminal once the command exited:
    /// what the shell would read next.
    pub left_unread: usize,
}

/// Bytes waiting to be read from the terminal behind `file`.
fn unread_input(file: &File) -> usize {
    let mut waiting: libc::c_int = 0;
    // SAFETY: `file` owns a valid PTY descriptor and `FIONREAD` writes one int.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::FIONREAD, &mut waiting) };
    assert_eq!(result, 0, "read the PTY's pending input");
    usize::try_from(waiting).unwrap_or_default()
}

/// How [`run_in_pty_with`] runs `lpm`.
pub struct PtyOptions {
    /// The pause between the writes of one response.
    pub pause: Duration,
    /// Capture lpm's standard output rather than give it the terminal.
    pub capture_stdout: bool,
    /// Leave the terminal's descriptor non-blocking, as an earlier program
    /// can.
    pub nonblocking_stdin: bool,
    /// `TERM` for lpm; `None` leaves it unset.
    pub term: Option<&'static str>,
    /// Signals lpm starts out ignoring, as under `nohup`.
    pub ignored_signals: &'static [libc::c_int],
}

impl Default for PtyOptions {
    fn default() -> Self {
        Self {
            pause: Duration::ZERO,
            capture_stdout: false,
            nonblocking_stdin: false,
            term: Some("xterm-256color"),
            ignored_signals: &[],
        }
    }
}

/// Each step's response as one write.
fn whole<'a>(steps: &[(&'a [u8], &'a [u8])]) -> Vec<(&'a [u8], Vec<&'a [u8]>)> {
    steps
        .iter()
        .map(|(prompt, response)| (*prompt, vec![*response]))
        .collect()
}

/// Run `lpm` with `args` in a PTY as `cwd`'s command, isolated as
/// [`crate::common::lpm_command`] isolates it. Each step is a prompt to wait
/// for and the bytes to send once it shows with echo off, in order; the
/// command must show every one within 30 seconds.
pub fn run_in_pty(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], &[u8])],
) -> PtySession {
    run_in_pty_with(cwd, lpm_home, args, &whole(steps), &PtyOptions::default()).0
}

/// [`run_in_pty`], sending each response as several writes with `pause`
/// between them, the way a terminal delivers a long paste in pieces.
pub fn run_in_pty_chunked(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], Vec<&[u8]>)],
    pause: Duration,
) -> PtySession {
    let options = PtyOptions {
        pause,
        ..PtyOptions::default()
    };
    run_in_pty_with(cwd, lpm_home, args, steps, &options).0
}

/// [`run_in_pty`] with lpm's standard output captured rather than the
/// terminal, as `$(lpm ...)` captures it; returns what it wrote there.
pub fn run_in_pty_with_stdout_captured(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], &[u8])],
) -> (PtySession, String) {
    let options = PtyOptions {
        capture_stdout: true,
        ..PtyOptions::default()
    };
    let (session, stdout) = run_in_pty_with(cwd, lpm_home, args, &whole(steps), &options);
    (session, stdout.unwrap_or_default())
}

/// [`run_in_pty`] with `options`, calling `before_answer` with each step's
/// index and lpm's process ID once its prompt shows and before it's
/// answered, such as to change what the command is asking about or to send
/// it a signal.
pub fn run_in_pty_answering(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], &[u8])],
    options: &PtyOptions,
    before_answer: &mut dyn FnMut(usize, u32),
) -> PtySession {
    run(
        cwd,
        lpm_home,
        args,
        &whole(steps),
        options,
        &mut |answering: &Answering<'_>| before_answer(answering.index, answering.pid),
    )
    .0
}

/// A step whose prompt shows, before it's answered.
pub struct Answering<'pty> {
    pub index: usize,
    pub pid: u32,
    master: &'pty File,
}

impl Answering<'_> {
    /// Whether the terminal hides what's typed.
    pub fn echo_is_disabled(&self) -> bool {
        terminal_echo_is_disabled(self.master)
    }

    /// Fill what the terminal holds of lpm's output until it's read, so
    /// lpm's next write to the terminal waits. The run reads it all after
    /// the step.
    pub fn fill_output(&self) {
        // SAFETY: `master` is a valid PTY master, whose slave `ptsname`
        // names in a buffer the call returns.
        let name = unsafe { libc::ptsname(self.master.as_raw_fd()) };
        assert!(!name.is_null(), "name the PTY slave");
        // SAFETY: `ptsname` returned a valid C string.
        let name = unsafe { std::ffi::CStr::from_ptr(name) }.to_owned();
        // SAFETY: `name` is a valid C string, and the call opens a new
        // descriptor of the slave, whose flags lpm's don't share.
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0, "open the PTY slave to fill its output");
        // SAFETY: `open` returned a descriptor owned here alone.
        let mut slave = unsafe { File::from_raw_fd(fd) };
        let chunk = [b'.'; 1024];
        loop {
            match slave.write(&chunk) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill the PTY's output: {error}"),
            }
        }
    }
}

/// [`run_in_pty`] with `options`, calling `control` once each step's prompt
/// shows and before it's answered.
pub fn run_in_pty_controlled(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], &[u8])],
    options: &PtyOptions,
    control: &mut dyn FnMut(&Answering<'_>),
) -> PtySession {
    run(cwd, lpm_home, args, &whole(steps), options, control).0
}

/// [`run_in_pty`] with `options`, returning what lpm wrote to its standard
/// output when it was captured.
pub fn run_in_pty_with(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], Vec<&[u8]>)],
    options: &PtyOptions,
) -> (PtySession, Option<String>) {
    run(cwd, lpm_home, args, steps, options, &mut |_: &Answering<
        '_,
    >| {})
}

fn run(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], Vec<&[u8]>)],
    options: &PtyOptions,
    before_answer: &mut dyn FnMut(&Answering<'_>),
) -> (PtySession, Option<String>) {
    let mut master_fd = -1;
    let mut slave_fd = -1;
    // SAFETY: `openpty` initializes both owned descriptors when it returns zero.
    let open_result = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(open_result, 0, "create PTY pair");
    // SAFETY: `openpty` returned unique owned descriptors for these files.
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    // SAFETY: `openpty` returned unique owned descriptors for these files.
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    let slave_probe = slave
        .try_clone()
        .expect("keep a PTY handle to probe its input");
    // SAFETY: `master` owns a valid descriptor, and these calls only update its flags.
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0, "read PTY flags");
    // SAFETY: `master` owns a valid descriptor, and `flags | O_NONBLOCK` is valid.
    let set_flags =
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert_eq!(set_flags, 0, "set PTY nonblocking mode");

    // The PTY is lpm's standard streams but not its controlling terminal:
    // a session leader's exit revokes its terminal on macOS, which would
    // discard the input lpm left unread instead of keeping it for whatever
    // reads the terminal next, as a shell's foreground job does.
    if options.nonblocking_stdin {
        // SAFETY: `slave` owns a valid descriptor, and these calls only update
        // the flags of the open file description lpm's streams share.
        unsafe {
            let flags = libc::fcntl(slave.as_raw_fd(), libc::F_GETFL);
            assert!(flags >= 0, "read PTY slave flags");
            assert_eq!(
                libc::fcntl(slave.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
                0,
                "set PTY slave nonblocking mode"
            );
        }
    }
    let mut command = super::lpm_command(cwd, lpm_home, None, args);
    match options.term {
        Some(term) => command.env("TERM", term),
        None => command.env_remove("TERM"),
    };
    let ignored_signals = options.ignored_signals;
    if !ignored_signals.is_empty() {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: between fork and exec the closure makes only `signal`
        // calls, which are async-signal-safe, and an ignored signal stays
        // ignored across exec.
        unsafe {
            command.pre_exec(move || {
                for &signal in ignored_signals {
                    if libc::signal(signal, libc::SIG_IGN) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    command
        .stdin(Stdio::from(slave.try_clone().expect("clone PTY stdin")))
        .stdout(if options.capture_stdout {
            Stdio::piped()
        } else {
            Stdio::from(slave.try_clone().expect("clone PTY stdout"))
        })
        .stderr(Stdio::from(slave));
    let mut child = command.spawn().expect("spawn lpm in PTY");
    drop(command);

    let mut transcript = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut answered = 0;
    let mut searched_from = 0;
    let drain = |master: &mut File, transcript: &mut Vec<u8>, buffer: &mut [u8]| loop {
        match master.read(buffer) {
            Ok(0) => break,
            Ok(read) => transcript.extend_from_slice(&buffer[..read]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(libc::EIO) =>
            {
                break;
            }
            Err(error) => panic!("read PTY transcript: {error}"),
        }
    };
    let status = loop {
        drain(&mut master, &mut transcript, &mut buffer);
        if let Some((prompt, response)) = steps.get(answered)
            && let Some(found) = transcript[searched_from..]
                .windows(prompt.len())
                .position(|window| window == *prompt)
            && terminal_echo_is_disabled(&master)
        {
            before_answer(&Answering {
                index: answered,
                pid: child.id(),
                master: &master,
            });
            for (index, chunk) in response.iter().enumerate() {
                if index > 0 {
                    std::thread::sleep(options.pause);
                }
                let mut rest: &[u8] = chunk;
                while !rest.is_empty() {
                    match master.write(rest) {
                        Ok(written) => rest = &rest[written..],
                        // The terminal's input buffer is full until lpm reads.
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            drain(&mut master, &mut transcript, &mut buffer);
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("write prompt response: {error}"),
                    }
                }
            }
            searched_from += found + prompt.len();
            answered += 1;
        }
        if let Some(status) = child.try_wait().expect("poll lpm") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out lpm");
            child.wait().expect("reap timed-out lpm");
            panic!(
                "lpm did not finish within 30 seconds:\n{}",
                String::from_utf8_lossy(&transcript)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drain(&mut master, &mut transcript, &mut buffer);
    let stdout = child.stdout.take().map(|mut piped| {
        let mut captured = String::new();
        piped
            .read_to_string(&mut captured)
            .expect("read lpm's standard output");
        captured
    });
    let text = String::from_utf8_lossy(&transcript).into_owned();
    assert_eq!(
        answered,
        steps.len(),
        "lpm exited before it showed every prompt:\n{text}"
    );
    let session = PtySession {
        status,
        transcript: super::strip_ansi(&text),
        echo_restored: !terminal_echo_is_disabled(&master),
        left_unread: unread_input(&slave_probe),
        raw: transcript,
    };
    (session, stdout)
}
