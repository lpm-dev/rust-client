//! The terminal on Unix: standard input in raw mode, with bracketed paste.

use std::io;
use std::mem::MaybeUninit;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::decode::Bytes;
use super::{Event, Keyboard, Output};

const BRACKETED_PASTE_ON: &[u8] = b"\x1b[?2004h";
const BRACKETED_PASTE_OFF: &[u8] = b"\x1b[?2004l";

/// How long an escape waits for the rest of a sequence before it's taken to
/// be the Escape key, as long as readline's: a sequence can arrive in pieces
/// over a slow connection.
const ESCAPE_KEY_WAIT: Duration = Duration::from_millis(500);

/// How long a read that may wait `wait` and has spent `elapsed` waits for
/// the rest of a sequence after its escape: never past the read's own wait,
/// so a bounded wait stays bounded.
fn escape_budget(wait: Option<Duration>, elapsed: Duration) -> Duration {
    wait.map_or(ESCAPE_KEY_WAIT, |wait| {
        wait.saturating_sub(elapsed).min(ESCAPE_KEY_WAIT)
    })
}

/// Whether the terminal can hide what's typed: a Unix terminal can, but
/// not inside Emacs's shell (comint), which shows what's typed in its own
/// buffer, whatever the terminal's echo.
pub(super) fn can_hide_input() -> bool {
    hides_typed_input(std::env::var_os("INSIDE_EMACS").as_deref())
}

/// [`can_hide_input`] for the `INSIDE_EMACS` an Emacs front end sets, such
/// as `29.4,comint` for `M-x shell`; vterm and other terminal emulators
/// inside Emacs hide what's typed as any terminal does.
fn hides_typed_input(inside_emacs: Option<&std::ffi::OsStr>) -> bool {
    !inside_emacs.is_some_and(|front_end| {
        front_end
            .to_string_lossy()
            .split(',')
            .any(|part| part == "comint")
    })
}

/// Whether the terminal takes escape sequences, such as the one that turns
/// on bracketed paste: not without `TERM`, or with `TERM=dumb`.
fn takes_escape_sequences() -> bool {
    std::env::var_os("TERM").is_some_and(|term| !term.is_empty() && term != "dumb")
}

/// Raw mode and bracketed paste for as long as it lives.
pub(super) struct Terminal {
    original: libc::termios,
    output: Output,
    paste_marked: bool,
    bytes: Bytes,
}

impl Terminal {
    pub(super) fn enter(output: Output, _limit: usize) -> io::Result<Self> {
        let mut original = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: standard input is open, and `tcgetattr` initializes
        // `original` when it returns zero.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful `tcgetattr` initialized it.
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        // SAFETY: `raw` is a valid termios that the call only changes.
        unsafe { libc::cfmakeraw(&mut raw) };
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: standard input is open and `raw` is a valid termios.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut terminal = Self {
            original,
            output,
            paste_marked: false,
            bytes: Bytes::default(),
        };
        terminal.paste_marked =
            takes_escape_sequences() && output.write(BRACKETED_PASTE_ON).is_ok();
        Ok(terminal)
    }
}

impl Keyboard for Terminal {
    fn read(&mut self, wait: Option<Duration>, each: &mut dyn FnMut(Event)) -> io::Result<bool> {
        let started = Instant::now();
        let deadline = wait.map(|wait| started + wait);
        if deadline.is_some() && !input_by(deadline)? {
            return Ok(false);
        }
        let mut buffer = Zeroizing::new([0_u8; 1024]);
        let read = loop {
            // SAFETY: `buffer` is valid for writes of its whole length.
            let read =
                unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
            if let Ok(read) = usize::try_from(read) {
                break read;
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => {}
                // An earlier program can leave the terminal non-blocking.
                io::ErrorKind::WouldBlock => {
                    if !input_by(deadline)? {
                        return Ok(false);
                    }
                }
                _ => return Err(error),
            }
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the terminal closed",
            ));
        }
        self.bytes.next_read();
        for &byte in &buffer[..read] {
            self.bytes.feed(byte, each);
        }
        self.bytes.end_of_read(each);
        // A terminal sends the rest of a sequence with the escape that
        // starts it; one nothing follows soon was the Escape key.
        if self.bytes.after_escape()
            && !input_by(Some(
                Instant::now() + escape_budget(wait, started.elapsed()),
            ))?
        {
            self.bytes.escape_key();
        }
        Ok(true)
    }

    fn unfinished(&self) -> bool {
        self.bytes.unfinished()
    }

    fn end_unfinished(&mut self, each: &mut dyn FnMut(Event)) {
        self.bytes.end_unfinished(each);
    }
}

/// Whether input arrives by `deadline`, or at all when `None`.
fn input_by(deadline: Option<Instant>) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // A poll a signal interrupts waits only for what's left.
        let timeout = poll_timeout(deadline, Instant::now());
        // SAFETY: `descriptor` is one valid pollfd for the call's duration.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if ready >= 0 {
            return Ok(ready > 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// The milliseconds `poll` waits at `now` for `deadline`; -1 for none.
fn poll_timeout(deadline: Option<Instant>, now: Instant) -> libc::c_int {
    deadline.map_or(-1, |deadline| {
        let left = deadline.saturating_duration_since(now);
        libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX)
    })
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if self.paste_marked {
            let _ = self.output.write(BRACKETED_PASTE_OFF);
        }
        // Input that arrived since the last read is discarded rather than
        // left for the shell, or shown once echo returns.
        // SAFETY: standard input is open and `original` is the termios read
        // from it.
        unsafe {
            libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emacs_s_shell_buffer_shows_what_s_typed_and_its_terminals_hide_it() {
        use std::ffi::OsStr;
        assert!(hides_typed_input(None));
        assert!(!hides_typed_input(Some(OsStr::new("29.4,comint"))));
        assert!(hides_typed_input(Some(OsStr::new("vterm"))));
        assert!(hides_typed_input(Some(OsStr::new("29.4,eat"))));
    }

    #[test]
    fn the_wait_for_the_rest_of_a_sequence_stays_within_what_the_read_has_left() {
        let ms = Duration::from_millis;
        assert_eq!(escape_budget(None, ms(900)), ESCAPE_KEY_WAIT);
        assert_eq!(escape_budget(Some(ms(40)), Duration::ZERO), ms(40));
        assert_eq!(
            escape_budget(Some(Duration::from_secs(2)), ms(10)),
            ESCAPE_KEY_WAIT
        );
        assert_eq!(
            escape_budget(Some(ms(100)), ms(80)),
            ms(20),
            "the poll before it already spent most of the read's wait"
        );
        assert_eq!(escape_budget(Some(ms(100)), ms(150)), Duration::ZERO);
    }

    #[test]
    fn a_poll_waits_only_for_what_its_deadline_leaves() {
        let now = Instant::now();
        assert_eq!(poll_timeout(None, now), -1);
        assert_eq!(
            poll_timeout(Some(now + Duration::from_millis(250)), now),
            250
        );
        assert_eq!(
            poll_timeout(
                Some(now + Duration::from_millis(250)),
                now + Duration::from_millis(200)
            ),
            50,
            "after an interruption, only what's left"
        );
        assert_eq!(poll_timeout(Some(now), now + Duration::from_secs(1)), 0);
    }
}
