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
    let chunked: Vec<(&[u8], Vec<&[u8]>)> = steps
        .iter()
        .map(|(prompt, response)| (*prompt, vec![*response]))
        .collect();
    run_in_pty_chunked(cwd, lpm_home, args, &chunked, Duration::ZERO)
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
    run(cwd, lpm_home, args, steps, pause, false).0
}

/// [`run_in_pty`] with lpm's standard output captured rather than the
/// terminal, as `$(lpm ...)` captures it; returns what it wrote there.
pub fn run_in_pty_with_stdout_captured(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], &[u8])],
) -> (PtySession, String) {
    let chunked: Vec<(&[u8], Vec<&[u8]>)> = steps
        .iter()
        .map(|(prompt, response)| (*prompt, vec![*response]))
        .collect();
    let (session, stdout) = run(cwd, lpm_home, args, &chunked, Duration::ZERO, true);
    (session, stdout.unwrap_or_default())
}

fn run(
    cwd: &Path,
    lpm_home: &Path,
    args: &[&str],
    steps: &[(&[u8], Vec<&[u8]>)],
    pause: Duration,
    capture_stdout: bool,
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
    let mut command = super::lpm_command(cwd, lpm_home, None, args);
    command
        .stdin(Stdio::from(slave.try_clone().expect("clone PTY stdin")))
        .stdout(if capture_stdout {
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
            for (index, chunk) in response.iter().enumerate() {
                if index > 0 {
                    std::thread::sleep(pause);
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
