//! Running `lpm-rs` in a pseudo-terminal, for the TTY/stdin interactive
//! cases the workflow tier can't reach: prompts, echo and Ctrl+C.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt as _;
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
    // SAFETY: `master` owns a valid descriptor, and these calls only update its flags.
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0, "read PTY flags");
    // SAFETY: `master` owns a valid descriptor, and `flags | O_NONBLOCK` is valid.
    let set_flags =
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert_eq!(set_flags, 0, "set PTY nonblocking mode");

    let mut command = super::lpm_command(cwd, lpm_home, None, args);
    command
        .stdin(Stdio::from(slave.try_clone().expect("clone PTY stdin")))
        .stdout(Stdio::from(slave.try_clone().expect("clone PTY stdout")))
        .stderr(Stdio::from(slave));
    // SAFETY: The closure calls only async-signal-safe session and terminal syscalls.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as libc::c_ulong, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
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
            master.write_all(response).expect("write prompt response");
            master.flush().expect("flush prompt response");
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
    let text = String::from_utf8_lossy(&transcript).into_owned();
    assert_eq!(
        answered,
        steps.len(),
        "lpm exited before it showed every prompt:\n{text}"
    );
    PtySession {
        status,
        transcript: super::strip_ansi(&text),
        echo_restored: !terminal_echo_is_disabled(&master),
        raw: transcript,
    }
}
